"""Tests for the user-activity extractors (ShellBags / LNK / Jump Lists /
Browser history / Registry file-access).

Import-safe on a box without fastmcp: tests target the disk.py functions and
the FK vendored-YAML fallback directly, mocking the EZ runner where needed.
Uses NON-ROCBA synthetic fixtures only - no case specifics anywhere.
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk


# ---------------------------------------------------------------------------
# Fake EZ runner - records calls, writes synthetic CSVs, status matrix support
# ---------------------------------------------------------------------------

class _FakeRunner(SafeRunner):
    def __init__(self, *, audit_logger, case_id, state_manager):
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="disk.fake",
            state_manager=state_manager,
        )
        # per-tool behavior: map call -> "rows" | "empty" | "fail"
        self.sbe_behavior = "rows"
        self.le_behavior = "rows"
        self.jle_behavior = "rows"
        self.recmd_behavior = "rows"
        self.calls: list[str] = []

    def _emit(self, csv_dir, csv_filename, header, row):
        p = Path(csv_dir) / (csv_filename or "out.csv")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(header + "\n" + row + "\n", encoding="utf-8")

    def _fake_result(self, ok: bool, params, tool_name):
        cmd = ["printf", "ok"] if ok else ["false"]
        return self.run(cmd, parameters=params, tool_name=tool_name, timeout=30)

    def classify_error(self, result):  # mirror EZToolsRunner API
        if getattr(result, "timed_out", False):
            return "timeout"
        return "unknown"

    def run_sbecmd(self, *, hive_dir, csv_dir, csv_filename=None, tool_name=None, timeout=1800):
        self.calls.append(f"sbe:{hive_dir}")
        if self.sbe_behavior == "rows":
            self._emit(csv_dir, "UsrClass_shellbags.csv",
                       "BagPath,AbsolutePath,LastWriteTime",
                       "1\\2,C:\\Synthetic\\Folder,2024-01-02 03:04:05")
            return self._fake_result(True, {"hive_dir": hive_dir}, tool_name)
        if self.sbe_behavior == "empty":
            return self._fake_result(True, {"hive_dir": hive_dir}, tool_name)
        return self._fake_result(False, {"hive_dir": hive_dir}, tool_name)

    def run_lecmd(self, *, target_dir, csv_dir, csv_filename, tool_name=None, timeout=1800):
        self.calls.append(f"le:{target_dir}")
        if self.le_behavior == "rows":
            self._emit(csv_dir, csv_filename,
                       "SourceFile,TargetIDAbsolutePath,LastModified",
                       "a.lnk,C:\\Synthetic\\target.txt,2024-01-02 03:04:05")
            return self._fake_result(True, {"target_dir": target_dir}, tool_name)
        if self.le_behavior == "empty":
            return self._fake_result(True, {"target_dir": target_dir}, tool_name)
        return self._fake_result(False, {"target_dir": target_dir}, tool_name)

    def run_jlecmd(self, *, target_dir, csv_dir, csv_filename, tool_name=None, timeout=1800):
        self.calls.append(f"jle:{target_dir}")
        if self.jle_behavior == "rows":
            self._emit(csv_dir, csv_filename,
                       "SourceFile,AppId,Path,LastModified",
                       "auto.dat,abc123,C:\\Synthetic\\doc.docx,2024-01-02 03:04:05")
            return self._fake_result(True, {"target_dir": target_dir}, tool_name)
        if self.jle_behavior == "empty":
            return self._fake_result(True, {"target_dir": target_dir}, tool_name)
        return self._fake_result(False, {"target_dir": target_dir}, tool_name)

    def run_recmd(self, *, hive_dir, csv_dir, csv_filename, batch_file=None,
                  sync_batch=False, tool_name=None, timeout=1800):
        self.calls.append(f"recmd:{hive_dir}")
        if self.recmd_behavior == "rows":
            # One UserAssist row (file-access fragment) + one unrelated row.
            self._emit(
                csv_dir, csv_filename,
                "HivePath,HiveType,Description,Category,KeyPath,ValueName,LastWriteTimestamp",
                "ROOT,NtUser,UserAssist,Program Execution,"
                "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist,"
                "synthetic.exe,2024-01-02 03:04:05",
            )
            return self._fake_result(True, {"hive_dir": hive_dir}, tool_name)
        if self.recmd_behavior == "empty":
            self._emit(csv_dir, csv_filename,
                       "HivePath,HiveType,Description,Category,KeyPath,ValueName,LastWriteTimestamp",
                       "ROOT,Software,Run,Autoruns,ROOT\\...\\Run,synthetic,2024-01-02 03:04:05")
            return self._fake_result(True, {"hive_dir": hive_dir}, tool_name)
        return self._fake_result(False, {"hive_dir": hive_dir}, tool_name)


def _no_replay(hive_path, label):
    """Mock _replay_hive_with_rla: pretend the hive is already clean."""
    return Path(hive_path), None, None


class _Base(unittest.TestCase):
    def _init(self, tmp_dir, case_id="CASE-UA"):
        audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
        state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
        state.load(case_id)
        runner = _FakeRunner(audit_logger=audit, case_id=case_id, state_manager=state)
        disk.init_tools(state, audit, ez_runner=runner)
        return runner, audit, state

    def _make_profiles(self, root: Path, names):
        """Create Users/<name> profile dirs with the artifact layout."""
        for name in names:
            base = root / "Users" / name
            # ShellBag hives
            uc = base / "AppData" / "Local" / "Microsoft" / "Windows"
            uc.mkdir(parents=True, exist_ok=True)
            (uc / "UsrClass.dat").write_text("x", encoding="utf-8")
            (base / "NTUSER.DAT").write_text("x", encoding="utf-8")
            # Recent (LNK) + Jump Lists
            recent = base / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            recent.mkdir(parents=True, exist_ok=True)
            (recent / "AutomaticDestinations").mkdir(exist_ok=True)
        (root / "Windows").mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# FK vendored fallback
# ---------------------------------------------------------------------------

class FkFallbackTests(unittest.TestCase):
    def _load_fk(self, artifact):
        external = Path("/opt/valhuntir-knowledge/packages/forensic-knowledge/data")
        vendored = Path(__file__).resolve().parent.parent / "data" / "forensic-knowledge"
        for base in (external, vendored):
            for platform in ("windows", "linux"):
                p = base / "artifacts" / platform / f"{artifact}.yaml"
                if p.exists():
                    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return {}

    def test_new_artifact_loads_from_vendored(self):
        for art in ("shellbags", "lnk_files", "jump_lists", "browser", "registry_fileaccess"):
            fk = self._load_fk(art)
            self.assertTrue(fk.get("does_not_prove"), art)
            self.assertTrue(fk.get("corroborate_with"), art)

    def test_existing_artifact_loads_from_vendored(self):
        for art in ("mft", "prefetch", "amcache", "shimcache", "srum",
                    "registry_run_keys", "event_logs_security", "recycle_bin",
                    "volume_shadow_copies", "volatility_memory", "hayabusa_alerts"):
            fk = self._load_fk(art)
            self.assertTrue(fk.get("does_not_prove"), art)
            self.assertTrue(fk.get("corroborate_with"), art)


# ---------------------------------------------------------------------------
# Agnostic grep gate over new code + YAMLs
# ---------------------------------------------------------------------------

class AgnosticGateTests(unittest.TestCase):
    def test_no_case_specifics_in_new_yamls(self):
        pat = re.compile(r"rocba|fred|pegasus|cobra|2020-11|stark", re.IGNORECASE)
        repo = Path(__file__).resolve().parent.parent
        for f in (repo / "data" / "forensic-knowledge").rglob("*.yaml"):
            self.assertIsNone(pat.search(f.read_text(encoding="utf-8")), str(f))

    def test_no_case_specifics_in_new_disk_section(self):
        pat = re.compile(r"rocba|fred|pegasus|cobra|2020-11|stark", re.IGNORECASE)
        repo = Path(__file__).resolve().parent.parent
        text = (repo / "sift_mcp" / "tools" / "disk.py").read_text(encoding="utf-8")
        marker = "User-activity extractors (ShellBags / LNK / Jump Lists"
        idx = text.find(marker)
        self.assertGreater(idx, -1)
        self.assertIsNone(pat.search(text[idx:]))


# ---------------------------------------------------------------------------
# Discovery + multi-profile
# ---------------------------------------------------------------------------

class DiscoveryTests(_Base):
    def test_multi_profile_discovery_both_user_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha", "bravo"])
            # legacy profile dir
            legacy = root / "Documents and Settings" / "charlie"
            legacy.mkdir(parents=True, exist_ok=True)
            (legacy / "NTUSER.DAT").write_text("x", encoding="utf-8")
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]):
                profiles = {n for n, _ in disk._iter_user_profile_dirs(str(root))}
            self.assertIn("alpha", profiles)
            self.assertIn("bravo", profiles)
            self.assertIn("charlie", profiles)

    def test_non_user_profiles_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["realuser"])
            for skip in ("Public", "Default", "All Users"):
                (root / "Users" / skip).mkdir(parents=True, exist_ok=True)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]):
                names = {n for n, _ in disk._iter_user_profile_dirs(str(root))}
            self.assertEqual(names, {"realuser"})

    def test_discover_user_hives_finds_usrclass_and_ntuser(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]):
                hives = disk._discover_user_hives(
                    str(root),
                    ("AppData/Local/Microsoft/Windows/UsrClass.dat", "NTUSER.DAT"),
                )
            names = sorted(h[1].name for h in hives)
            self.assertEqual(names, ["NTUSER.DAT", "UsrClass.dat"])


# ---------------------------------------------------------------------------
# Per-tool: response contract, multi-profile merge, artifact_absent, status matrix
# ---------------------------------------------------------------------------

class ShellbagsTests(_Base):
    def test_success_response_contract_and_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha", "bravo"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_shellbags(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            for key in ("execution_id", "csv_path", "records_count", "total_rows",
                        "truncated", "profiles_checked", "profiles_with_data",
                        "parser_failures", "findings_created", "preview"):
                self.assertIn(key, r)
            self.assertGreaterEqual(r["total_rows"], 2)  # one row per profile hive set
            self.assertIn("alpha", r["profiles_checked"])
            self.assertIn("bravo", r["profiles_checked"])
            # provenance columns present in persisted CSV
            rows = disk._read_csv(r["csv_path"])
            self.assertTrue(rows)
            for col in disk._PROVENANCE_COLUMNS:
                self.assertIn(col, rows[0])

    def test_truncation_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha", "bravo"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_shellbags(image_path=str(root), case_id="CASE-UA", max_entries=1)
            self.assertTrue(r["truncated"])

    def test_artifact_absent_when_no_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_shellbags(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "artifact_absent")
            self.assertEqual(r["total_rows"], 0)
            # audit log_result outputs_summary contains the literal marker
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertTrue(any("status=artifact_absent" in ln for ln in lines))

    def test_parser_failure_is_collection_failed_not_absent(self):
        """Consensus-signed 4-way taxonomy: a discovered hive whose parse FAILS
        and yields zero rows must report ``collection_failed`` (exit_code=1),
        NEVER ``artifact_absent`` - a failed collection is not evidence that no
        evidence exists (false-negative bug)."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            runner.sbe_behavior = "fail"
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_shellbags(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "collection_failed")
            self.assertTrue(r["parser_failures"])
            self.assertTrue(any("parser_error" in pf["status"] for pf in r["parser_failures"]))
            # audit row: exit_code=1 AND summary must NOT contain artifact_absent.
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            import json
            results = [json.loads(ln) for ln in lines]
            cf = [e for e in results
                  if e.get("event_type") == "completed"
                  and "status=collection_failed" in (e.get("outputs_summary") or "")]
            self.assertTrue(cf, "expected a collection_failed audit result row")
            self.assertEqual(cf[-1]["exit_code"], 1)
            self.assertNotIn("artifact_absent", cf[-1]["outputs_summary"])

    def test_no_data_when_discovered_but_zero_rows(self):
        """Discovered hive + clean parse + zero rows -> ``no_data`` (exit_code=0),
        distinct from both artifact_absent (nothing discovered) and
        collection_failed (parse failed)."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            runner.sbe_behavior = "empty"  # parser succeeds, emits no CSV rows
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_shellbags(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "no_data")
            self.assertEqual(r["total_rows"], 0)
            self.assertFalse(r["parser_failures"])
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertTrue(any("status=no_data" in ln for ln in lines))
            self.assertFalse(any("status=artifact_absent" in ln for ln in lines))


class LnkTests(_Base):
    def test_success_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_lnk_files(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertIn("alpha", r["profiles_with_data"])
            rows = disk._read_csv(r["csv_path"])
            self.assertEqual(rows[0]["parser_command"], "LECmd")

    def test_artifact_absent_no_recent_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Users" / "alpha").mkdir(parents=True, exist_ok=True)
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_lnk_files(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "artifact_absent")


class JumpListTests(_Base):
    def test_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_jump_lists(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            rows = disk._read_csv(r["csv_path"])
            self.assertEqual(rows[0]["parser_command"], "JLECmd")


class BrowserTests(_Base):
    def _make_chromium_db(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INT, last_visit_time INT)")
        # WebKit micros: 13300000000000000 ~ a plausible 2022 date
        conn.execute("INSERT INTO urls VALUES (?,?,?,?)",
                     ("https://synthetic.example/", "Synthetic", 3, 13300000000000000))
        conn.execute("CREATE TABLE downloads (target_path TEXT, total_bytes INT, start_time INT, tab_url TEXT)")
        conn.execute("INSERT INTO downloads VALUES (?,?,?,?)",
                     ("C:\\Synthetic\\file.zip", 12345, 13300000000000000, "https://synthetic.example/dl"))
        conn.commit()
        conn.close()

    def test_chromium_history_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            prof = root / "Users" / "alpha"
            db = prof / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
            self._make_chromium_db(db)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_browser_history(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertGreaterEqual(r["total_rows"], 2)  # one visit + one download
            rows = disk._read_csv(r["csv_path"])
            self.assertTrue(any(row.get("record_type") == "download" for row in rows))
            self.assertTrue(all(row.get("source_artifact_path") for row in rows))
            # timestamp normalized to ISO UTC
            self.assertTrue(any("T" in (row.get("timestamp_utc") or "") for row in rows))

    def test_corrupt_db_does_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            prof = root / "Users" / "alpha"
            # good firefox DB
            ff = prof / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "p1.default" / "places.sqlite"
            ff.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(ff))
            conn.execute("CREATE TABLE moz_places (id INT, url TEXT, title TEXT, visit_count INT, last_visit_date INT)")
            conn.execute("INSERT INTO moz_places VALUES (1,'https://synthetic.example/','S',2,1640000000000000)")
            conn.commit(); conn.close()
            # corrupt chromium DB
            bad = prof / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "History"
            bad.parent.mkdir(parents=True, exist_ok=True)
            bad.write_text("not a sqlite db", encoding="utf-8")
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_browser_history(image_path=str(root), case_id="CASE-UA")
            # firefox rows survive even though the edge DB is unreadable -
            # one corrupt DB must NOT abort the whole tool.
            self.assertEqual(r["status"], "success")
            self.assertGreaterEqual(r["total_rows"], 1)
            self.assertIn("alpha", r["profiles_with_data"])

    def test_artifact_absent_no_browsers(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Users" / "alpha").mkdir(parents=True, exist_ok=True)
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_browser_history(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "artifact_absent")

    def test_incompatible_db_is_collection_failed_not_absent(self):
        """A discovered DB that CONNECTS but whose queries fail (schema drift /
        incompatible / encrypted History) yields zero rows AND populated
        parser_failures -> ``collection_failed``, NEVER artifact_absent. This is
        the consensus-signed false-negative guard for the browser path."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            prof = root / "Users" / "alpha"
            # A valid sqlite DB that connects fine but lacks the urls/downloads
            # tables Chromium history expects -> every query raises sqlite3.Error.
            db = prof / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
            db.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db))
            conn.execute("CREATE TABLE unrelated (x INT)")
            conn.execute("INSERT INTO unrelated VALUES (1)")
            conn.commit(); conn.close()
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_browser_history(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "collection_failed")
            self.assertTrue(r["parser_failures"])
            self.assertTrue(any("query_error" in pf["status"] for pf in r["parser_failures"]))
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertFalse(any("status=artifact_absent" in ln for ln in lines))

    def test_query_helper_signatures_return_errors(self):
        """The browser query helpers must RETURN (rows..., query_errors) so a
        failed query is observable - the old swallow-and-pass hid collection
        failures behind an empty row set."""
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.sqlite"
            conn = sqlite3.connect(str(bad))
            conn.execute("CREATE TABLE noop (x INT)")
            conn.commit(); conn.close()
            visits, downloads, q_errs = disk._query_chromium_history(bad)
            self.assertEqual(visits, [])
            self.assertEqual(downloads, [])
            self.assertTrue(q_errs)  # both chromium queries failed
            ff = Path(tmp) / "places.sqlite"
            conn = sqlite3.connect(str(ff))
            conn.execute("CREATE TABLE noop (x INT)")
            conn.commit(); conn.close()
            rows, ff_errs = disk._query_firefox_history(ff)
            self.assertEqual(rows, [])
            self.assertTrue(ff_errs)


_FILEACCESS_CSV = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,LastWriteTimestamp\n"
    "ROOT,NtUser,UserAssist,Program Execution,"
    "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist,"
    "synthetic.exe,2024-01-02 03:04:05\n"
    "ROOT,Software,Run,Autoruns,ROOT\\...\\Run,unrelated,2024-01-02 03:04:05\n"
)


class RegistryFileAccessTests(_Base):
    def _seed_run_keys_cache(
        self, state, image_path, *, csv_path, source_execution_id,
        user_hives, cache_image_path=None,
    ):
        """Seed the state cache EXACTLY as extract_registry_run_keys would.

        Mirrors the real cache write path: build the key via
        ``disk._registry_run_keys_cache_params`` (key incl. image_path) and
        persist metadata with csv_path + source_execution_id + image_path +
        user_hives_scanned. ``cache_image_path`` lets a test seed a DIFFERENT
        image into the metadata to exercise the mismatch guard.
        """
        resolved_hive_dir = disk._resolved_path_str(
            disk._resolve_registry_hive_dir_input(image_path, None)
        )
        batch_file = None
        for candidate in disk.DFIR_BATCH_PATHS:
            if os.path.isfile(candidate):
                batch_file = candidate
                break
        key = disk.build_cache_key(
            "disk.extract_registry_run_keys",
            disk._registry_run_keys_cache_params(
                resolved_hive_dir=resolved_hive_dir,
                batch_mode=True,
                batch_file_used=batch_file,
                user_hives_found=user_hives,
                sync_batch=False,
                image_path=image_path,
            ),
        )
        meta_image = cache_image_path if cache_image_path is not None else image_path
        state.cache_artifact(
            key,
            {
                "source_execution_id": source_execution_id,
                "csv_path": str(csv_path),
                "image_path": disk._resolved_path_str(meta_image),
                "user_hives_scanned": list(user_hives),
                "total_records": 2,
            },
        )
        return key

    def test_reuse_combined_csv(self):
        """Provenance-MATCHED reuse: the state cache holds a run-keys entry whose
        image_path equals THIS image and whose csv_path exists on disk. RECmd must
        NOT run; the audit/raw_command must cite the cached source_execution_id."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                # durable run-keys CSV on disk (OUTPUT_BASE now points at tmp)
                combined = disk._artifact_output_dir("registry") / "registry_combined.csv"
                combined.parent.mkdir(parents=True, exist_ok=True)
                combined.write_text(_FILEACCESS_CSV, encoding="utf-8")
                user_hives = disk._discover_run_keys_user_hives(str(root))
                self._seed_run_keys_cache(
                    state, str(root), csv_path=combined,
                    source_execution_id="E-RK-001", user_hives=user_hives,
                )
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertTrue(r["reused_combined_csv"])
            self.assertTrue(r["cache_hit"])
            self.assertEqual(r["cache_source_execution_id"], "E-RK-001")
            self.assertEqual(r["total_rows"], 1)  # only the UserAssist row matches
            self.assertIn("userassist", r["fragment_counts"])
            # RECmd was NOT invoked (cache-keyed reuse path)
            self.assertFalse(any(c.startswith("recmd:") for c in runner.calls))
            # audit raw_command cites the cached source_execution_id
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8")
            self.assertIn("E-RK-001", lines)
            self.assertIn("CACHE_HIT", lines)
            # profiles_checked reflects the CACHED hive metadata (alpha profile dir)
            self.assertIn("alpha", r["profiles_checked"])

    def test_orphan_csv_no_cache_runs_recmd(self):
        """ORPHAN CSV: registry_combined.csv on disk but NO matching cache entry.
        Must NOT silently reuse - RECmd runs and an orphan-ignored warning is set."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            # NO cache seeded.
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                combined = disk._artifact_output_dir("registry") / "registry_combined.csv"
                combined.parent.mkdir(parents=True, exist_ok=True)
                combined.write_text(_FILEACCESS_CSV, encoding="utf-8")
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertFalse(r["reused_combined_csv"])
            self.assertFalse(r["cache_hit"])
            self.assertTrue(any(c.startswith("recmd:") for c in runner.calls))
            self.assertIn("orphan_csv_warning", r)

    def test_image_mismatch_no_reuse(self):
        """IMAGE MISMATCH: cache+CSV seeded for image A; calling with image B must
        NOT reuse A's data - RECmd runs for B."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            other_image = str(Path(tmp) / "mnt" / "OTHER_IMAGE")
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                combined = disk._artifact_output_dir("registry") / "registry_combined.csv"
                combined.parent.mkdir(parents=True, exist_ok=True)
                combined.write_text(_FILEACCESS_CSV, encoding="utf-8")
                user_hives = disk._discover_run_keys_user_hives(str(root))
                # Seed cache keyed/metadata for a DIFFERENT image (other_image).
                self._seed_run_keys_cache(
                    state, other_image, csv_path=combined,
                    source_execution_id="E-RK-OTHER", user_hives=user_hives,
                )
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertFalse(r["reused_combined_csv"])
            self.assertFalse(r["cache_hit"])
            self.assertTrue(any(c.startswith("recmd:") for c in runner.calls))

    def test_metadata_image_mismatch_no_reuse(self):
        """Even if the cache KEY happened to match, a metadata image_path that
        differs from the call image must block reuse (defense in depth)."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                combined = disk._artifact_output_dir("registry") / "registry_combined.csv"
                combined.parent.mkdir(parents=True, exist_ok=True)
                combined.write_text(_FILEACCESS_CSV, encoding="utf-8")
                user_hives = disk._discover_run_keys_user_hives(str(root))
                # KEY built for THIS image, but metadata image_path points elsewhere.
                self._seed_run_keys_cache(
                    state, str(root), csv_path=combined,
                    source_execution_id="E-RK-BAD", user_hives=user_hives,
                    cache_image_path=str(Path(tmp) / "mnt" / "WRONG"),
                )
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertFalse(r["reused_combined_csv"])
            self.assertTrue(any(c.startswith("recmd:") for c in runner.calls))

    def test_run_recmd_when_no_combined_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertFalse(r["reused_combined_csv"])
            self.assertTrue(any(c.startswith("recmd:") for c in runner.calls))
            self.assertIn("userassist", r["fragment_counts"])

    def test_no_data_when_discovered_but_no_fileaccess_rows(self):
        """RECmd ran cleanly over a discovered NTUSER hive but no row matched the
        file-access fragment set -> ``no_data`` (discovered=True, no failures),
        NOT artifact_absent (which would falsely claim no evidence existed)."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            runner.recmd_behavior = "empty"  # produces only non-fileaccess rows
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "no_data")
            self.assertFalse(r["parser_failures"])

    def test_artifact_absent_when_nothing_discovered(self):
        """No reuse CSV and no NTUSER hive discovered -> true ``artifact_absent``
        (discovered=False). This is the only path that legitimately reports
        absence for the registry file-access tool."""
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            # profile dir exists but carries NO NTUSER.DAT hive
            (root / "Users" / "alpha").mkdir(parents=True, exist_ok=True)
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "artifact_absent")
            self.assertFalse(any(c.startswith("recmd:") for c in runner.calls))


if __name__ == "__main__":
    unittest.main()
