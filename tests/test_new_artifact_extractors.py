"""Tests for the three new FK-only OPTIONAL extractors:

    extract_recycle_bin        - native $I parser, per-SID
    extract_powershell_history - native PSReadline text read, per-user
    extract_scheduled_tasks    - native Task XML parse, system-path

Mirrors tests/test_useractivity_extractors.py: synthetic fixtures only, no case
specifics. Real $I blobs, ConsoleHost_history.txt, and Task XML are crafted so
the native parsers are genuinely exercised.
"""

from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk


_FILETIME_EPOCH_DELTA = 116444736000000000


def _iso_to_filetime(year, month, day, hour, minute, second) -> int:
    from datetime import datetime, timezone
    dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    secs = int((dt - epoch).total_seconds())
    return secs * 10_000_000 + _FILETIME_EPOCH_DELTA


def _make_i_v1(path: str, size: int, filetime: int) -> bytes:
    """Craft a v1 $I blob: header + fixed 260 UTF-16LE char path region."""
    blob = struct.pack("<q", 1) + struct.pack("<q", size) + struct.pack("<q", filetime)
    raw = path.encode("utf-16-le")
    raw += b"\x00\x00"  # NUL terminator
    raw = raw.ljust(520, b"\x00")[:520]
    return blob + raw


def _make_i_v2(path: str, size: int, filetime: int) -> bytes:
    """Craft a v2 $I blob: header + 4-byte char count + UTF-16LE path."""
    encoded = (path + "\x00")
    n_chars = len(encoded)
    blob = struct.pack("<q", 2) + struct.pack("<q", size) + struct.pack("<q", filetime)
    blob += struct.pack("<I", n_chars)
    blob += encoded.encode("utf-16-le")
    return blob


_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-02T03:04:05</Date>
    <Author>SYNTHETIC\\author</Author>
    <URI>\\SyntheticTask</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Users\\Public\\evil.exe</Command>
      <Arguments>-enc QQBBAA==</Arguments>
    </Exec>
  </Actions>
</Task>
"""

_TASK_XML_BENIGN = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Microsoft</Author></RegistrationInfo>
  <Actions Context="Author">
    <Exec><Command>C:\\Windows\\System32\\defrag.exe</Command></Exec>
  </Actions>
</Task>
"""


class _Base(unittest.TestCase):
    def _init(self, tmp_dir, case_id="CASE-NEW"):
        audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
        state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
        state.load(case_id)
        disk.init_tools(state, audit, ez_runner=None)
        return audit, state


# ---------------------------------------------------------------------------
# Documented-absence: non-Windows / mount-less input -> status=error
# ---------------------------------------------------------------------------

class HardFailTests(_Base):
    def _check(self, fn):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            non_volume = Path(tmp) / "not_a_volume"
            non_volume.mkdir(parents=True, exist_ok=True)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = fn(image_path=str(non_volume), case_id="CASE-NEW")
            self.assertEqual(r["status"], "error")
            self.assertEqual(r["reason"], "no_windows_volume_at_image_path")
            self.assertIsNone(r["csv_path"])
            # audit summary must NOT read as a clean negative
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertFalse(any("status=artifact_absent" in ln for ln in lines))

    def test_recycle_bin_hard_fail(self):
        self._check(disk.extract_recycle_bin)

    def test_powershell_history_hard_fail(self):
        self._check(disk.extract_powershell_history)

    def test_scheduled_tasks_hard_fail(self):
        self._check(disk.extract_scheduled_tasks)


# ---------------------------------------------------------------------------
# Documented-absence: present-but-empty Windows root -> artifact_absent
# ---------------------------------------------------------------------------

class ArtifactAbsentTests(_Base):
    def _root(self, tmp):
        root = Path(tmp) / "mnt" / "C"
        (root / "Windows").mkdir(parents=True, exist_ok=True)
        (root / "Users" / "alpha").mkdir(parents=True, exist_ok=True)
        return root

    def test_recycle_bin_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = self._root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "artifact_absent")
            self.assertIsNone(r["csv_path"])

    def test_powershell_history_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = self._root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_powershell_history(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "artifact_absent")

    def test_scheduled_tasks_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = self._root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "artifact_absent")


# ---------------------------------------------------------------------------
# Recycle Bin: per-SID discovery, v1 + v2 parse, schema, provenance
# ---------------------------------------------------------------------------

class RecycleBinTests(_Base):
    def test_per_sid_v1_and_v2_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            bin_dir = root / "$Recycle.Bin"
            sid1 = bin_dir / "S-1-5-21-1111-2222-3333-1001"
            sid2 = bin_dir / "S-1-5-21-1111-2222-3333-1002"
            sid1.mkdir(parents=True)
            sid2.mkdir(parents=True)
            ft = _iso_to_filetime(2024, 1, 2, 3, 4, 5)
            # v1 pair (with $R) under sid1
            (sid1 / "$IAAAAAA.txt").write_bytes(
                _make_i_v1("C:\\Users\\alpha\\secret.txt", 1234, ft))
            (sid1 / "$RAAAAAA.txt").write_bytes(b"content")
            # v2 orphan (no $R) under sid2
            (sid2 / "$IBBBBBB.zip").write_bytes(
                _make_i_v2("C:\\staging\\archive.zip", 999999, ft))
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "success")
            self.assertEqual(r["total_rows"], 2)
            rows = disk._read_csv(r["csv_path"])
            by_path = {row["original_path"]: row for row in rows}
            self.assertIn("C:\\Users\\alpha\\secret.txt", by_path)
            self.assertIn("C:\\staging\\archive.zip", by_path)
            v1 = by_path["C:\\Users\\alpha\\secret.txt"]
            self.assertEqual(v1["i_format_version"], "1")
            self.assertEqual(v1["original_size_bytes"], "1234")
            self.assertEqual(v1["deletion_time_utc"], "2024-01-02T03:04:05")
            self.assertEqual(v1["content_present"], "True")
            self.assertEqual(v1["original_extension"], "txt")
            v2 = by_path["C:\\staging\\archive.zip"]
            self.assertEqual(v2["i_format_version"], "2")
            self.assertEqual(v2["content_present"], "False")
            # per-SID provenance + the 5 provenance columns present
            sids = {row["sid"] for row in rows}
            self.assertEqual(len(sids), 2)
            for col in disk._PROVENANCE_COLUMNS:
                self.assertIn(col, rows[0])
            self.assertTrue(all(row["parser_command"] == "native_i_parser" for row in rows))

    def test_malformed_i_is_collection_failed_not_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            sid = root / "$Recycle.Bin" / "S-1-5-21-9-9-9-1001"
            sid.mkdir(parents=True)
            (sid / "$ICORRUPT.txt").write_bytes(b"\x00\x01")  # too short
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "collection_failed")
            self.assertTrue(r["parser_failures"])
            lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertFalse(any("status=artifact_absent" in ln for ln in lines))


# ---------------------------------------------------------------------------
# PowerShell history: per-user discovery, one row per line, high_signal, schema
# ---------------------------------------------------------------------------

class PowerShellHistoryTests(_Base):
    def _make_psr(self, root, user, filename, lines):
        psr = (root / "Users" / user / "AppData" / "Roaming" / "Microsoft"
               / "Windows" / "PowerShell" / "PSReadLine")
        psr.mkdir(parents=True, exist_ok=True)
        (psr / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_per_user_discovery_and_high_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            self._make_psr(root, "alpha", "ConsoleHost_history.txt",
                           ["Get-Process", "IEX (New-Object Net.WebClient).DownloadString('x')"])
            self._make_psr(root, "beta", "VSCode_history.txt",
                           ["whoami"])
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_powershell_history(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "success")
            self.assertEqual(r["total_rows"], 3)
            rows = disk._read_csv(r["csv_path"])
            profiles = {row["source_profile"] for row in rows}
            self.assertEqual(profiles, {"alpha", "beta"})
            # line numbering is 1-based per file
            line_nos = {row["line_no"] for row in rows if row["source_profile"] == "alpha"}
            self.assertEqual(line_nos, {"1", "2"})
            # high_signal flags the IEX/DownloadString line, not Get-Process
            high = {row["command"]: row["high_signal"] for row in rows}
            self.assertEqual(high["Get-Process"], "False")
            self.assertEqual(
                high["IEX (New-Object Net.WebClient).DownloadString('x')"], "True")
            # source_history_file provenance distinguishes host variants
            files = {row["source_history_file"] for row in rows}
            self.assertEqual(files, {"ConsoleHost_history.txt", "VSCode_history.txt"})
            for col in disk._PROVENANCE_COLUMNS:
                self.assertIn(col, rows[0])


# ---------------------------------------------------------------------------
# Scheduled tasks: recursive discovery, XML fields, flags, hardlink dedup
# ---------------------------------------------------------------------------

class ScheduledTasksTests(_Base):
    def _tasks_root(self, root):
        t = root / "Windows" / "System32" / "Tasks"
        t.mkdir(parents=True, exist_ok=True)
        return t

    def test_recursive_parse_flags_and_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            tasks = self._tasks_root(root)
            # off-baseline root task
            (tasks / "SyntheticTask").write_text(_TASK_XML, encoding="utf-8")
            # nested built-in
            nested = tasks / "Microsoft" / "Windows" / "Defrag"
            nested.mkdir(parents=True)
            (nested / "ScheduledDefrag").write_text(_TASK_XML_BENIGN, encoding="utf-8")
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "success")
            self.assertEqual(r["total_rows"], 2)
            rows = disk._read_csv(r["csv_path"])
            by_name = {row["task_name"]: row for row in rows}
            evil = by_name["SyntheticTask"]
            self.assertEqual(evil["command"], "C:\\Users\\Public\\evil.exe")
            self.assertEqual(evil["arguments"], "-enc QQBBAA==")
            self.assertEqual(evil["principal_userid"], "S-1-5-18")
            self.assertEqual(evil["run_level"], "HighestAvailable")
            self.assertEqual(evil["registration_date"], "2024-01-02T03:04:05")
            self.assertEqual(evil["builtin_baseline"], "False")
            self.assertEqual(evil["off_path_command"], "True")
            builtin = by_name["ScheduledDefrag"]
            self.assertEqual(builtin["builtin_baseline"], "True")
            self.assertEqual(builtin["off_path_command"], "False")
            self.assertTrue(all(row["source_profile"] == "system" for row in rows))
            for col in disk._PROVENANCE_COLUMNS:
                self.assertIn(col, rows[0])

    def test_hardlink_deduped_single_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            tasks = self._tasks_root(root)
            original = tasks / "SyntheticTask"
            original.write_text(_TASK_XML, encoding="utf-8")
            link = tasks / "HardlinkAlias"
            try:
                os.link(str(original), str(link))
            except OSError:
                self.skipTest("hardlinks unsupported on this filesystem")
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "success")
            self.assertEqual(r["total_rows"], 1)

    def test_malformed_xml_is_collection_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            tasks = self._tasks_root(root)
            (tasks / "BadTask").write_text("<not valid xml", encoding="utf-8")
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "collection_failed")
            self.assertTrue(r["parser_failures"])


# ---------------------------------------------------------------------------
# State mirror / debt accrual
# ---------------------------------------------------------------------------

class StateMirrorTests(_Base):
    def test_recycle_bin_execution_mirrored_and_accrues_debt(self):
        from sift_mcp import analysis_debt
        with tempfile.TemporaryDirectory() as tmp:
            audit, state = self._init(tmp)
            root = Path(tmp) / "mnt" / "C"
            (root / "Windows").mkdir(parents=True, exist_ok=True)
            sid = root / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
            sid.mkdir(parents=True)
            ft = _iso_to_filetime(2024, 1, 2, 3, 4, 5)
            (sid / "$IAAAAAA.txt").write_bytes(_make_i_v1("C:\\x.txt", 5, ft))
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-NEW")
            self.assertEqual(r["status"], "success")
            # state.executions row exists for the canonical tool name + csv_path
            mine = state.get_executions("disk.extract_recycle_bin")
            self.assertTrue(mine)
            # the catalog entry exists and is an extraction that accrues debt
            entry = analysis_debt._CATALOG_BY_SUFFIX.get("extract_recycle_bin")
            self.assertIsNotNone(entry)
            self.assertEqual(entry.taxonomy_group, "extended")
            self.assertFalse(entry.report_block_when_required)


# ---------------------------------------------------------------------------
# FK completeness: new YAML stems load + are reachable from _FK_MAP
# ---------------------------------------------------------------------------

class FkCompletenessTests(unittest.TestCase):
    def _load_fk(self, artifact):
        vendored = (Path(__file__).resolve().parent.parent
                    / "data" / "forensic-knowledge")
        for platform in ("windows", "analysis_outputs", "linux", "macos"):
            p = vendored / "artifacts" / platform / f"{artifact}.yaml"
            if p.exists():
                return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return {}

    def test_new_yamls_load_and_have_required_sections(self):
        for art in ("recycle_bin", "powershell_history", "scheduled_tasks"):
            fk = self._load_fk(art)
            self.assertEqual(fk.get("artifact"), art)
            self.assertTrue(fk.get("does_not_prove"), art)
            self.assertTrue(fk.get("corroborate_with"), art)
            self.assertTrue(fk.get("discipline_reminder"), art)

    def test_corroboration_recycle_bin_names_tool(self):
        from sift_mcp import corroboration
        self.assertEqual(
            corroboration.SOURCE_CLASS_TO_FK_YAML.get("recycle_bin"),
            "recycle_bin",
        )


if __name__ == "__main__":
    unittest.main()
