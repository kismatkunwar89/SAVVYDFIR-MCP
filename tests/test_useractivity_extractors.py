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

    def test_parser_failure_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            runner.sbe_behavior = "fail"
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_shellbags(image_path=str(root), case_id="CASE-UA")
            # no rows produced -> artifact_absent with parser_failures populated
            self.assertEqual(r["status"], "artifact_absent")
            self.assertTrue(r["parser_failures"])
            self.assertTrue(any("parser_error" in pf["status"] for pf in r["parser_failures"]))


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


class RegistryFileAccessTests(_Base):
    def test_reuse_combined_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            (root / "Users" / "alpha").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                # seed a durable registry_combined.csv with a UserAssist row
                combined = disk._artifact_output_dir("registry") / "registry_combined.csv"
                combined.parent.mkdir(parents=True, exist_ok=True)
                combined.write_text(
                    "HivePath,HiveType,Description,Category,KeyPath,ValueName,LastWriteTimestamp\n"
                    "ROOT,NtUser,UserAssist,Program Execution,"
                    "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist,"
                    "synthetic.exe,2024-01-02 03:04:05\n"
                    "ROOT,Software,Run,Autoruns,ROOT\\...\\Run,unrelated,2024-01-02 03:04:05\n",
                    encoding="utf-8",
                )
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "success")
            self.assertTrue(r["reused_combined_csv"])
            self.assertEqual(r["total_rows"], 1)  # only the UserAssist row matches
            self.assertIn("userassist", r["fragment_counts"])
            # runner was NOT invoked (reuse path)
            self.assertFalse(any(c.startswith("recmd:") for c in runner.calls))

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

    def test_artifact_absent_when_no_fileaccess_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, audit, state = self._init(tmp)
            runner.recmd_behavior = "empty"  # produces only non-fileaccess rows
            root = Path(tmp) / "mnt" / "C"
            self._make_profiles(root, ["alpha"])
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[root]), \
                 mock.patch.object(disk, "_replay_hive_with_rla", _no_replay), \
                 mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_registry_fileaccess(image_path=str(root), case_id="CASE-UA")
            self.assertEqual(r["status"], "artifact_absent")


if __name__ == "__main__":
    unittest.main()
