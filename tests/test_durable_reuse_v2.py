"""Durable-reuse v2: consistent cache-hit reuse across ALL artifact extractors.

A SECOND run on the same evidence + staged artifacts must SKIP re-parsing
(cache-hit reuse) when a valid v2 sidecar matches the source-set + parameters +
parser signature. Any change -> re-parse. v1 sidecars ignored. Partial outcomes
never write a sidecar. Case B never reuses case A.

Synthetic fixtures only - no case specifics. Reuses the fake EZ runner +
fixture helpers from tests.test_useractivity_extractors.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import _cache as c
from sift_mcp.tools import disk

from tests.test_useractivity_extractors import _FakeRunner, _no_replay


# ===========================================================================
# Phase 0 - v2 fingerprint framework (unit-level)
# ===========================================================================

class V2FingerprintFrameworkTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())

    def _mk(self, name, content=b"x"):
        p = self.base / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def test_source_set_manifest_matches_when_unchanged(self):
        a = self._mk("a"); b = self._mk("b")
        fp1 = c.build_source_set_fingerprint([str(a), str(b)])
        fp2 = c.build_source_set_fingerprint([str(b), str(a)])  # order-independent
        self.assertEqual(fp1["manifest_sha256"], fp2["manifest_sha256"])

    def test_source_set_invalidates_on_any_change(self):
        a = self._mk("a"); b = self._mk("b")
        fp1 = c.build_source_set_fingerprint([str(a), str(b)])
        b.write_bytes(b"CHANGED-BIGGER")
        fp2 = c.build_source_set_fingerprint([str(a), str(b)])
        self.assertNotEqual(fp1["manifest_sha256"], fp2["manifest_sha256"])

    def test_source_set_invalidates_on_removed_input(self):
        a = self._mk("a"); b = self._mk("b")
        fp1 = c.build_source_set_fingerprint([str(a), str(b)])
        fp2 = c.build_source_set_fingerprint([str(a)])
        self.assertNotEqual(fp1["manifest_sha256"], fp2["manifest_sha256"])

    def test_parameter_fingerprint_changes_on_param_change(self):
        p1 = c.build_parameter_fingerprint({"channel": "Security"})
        p2 = c.build_parameter_fingerprint({"channel": "System"})
        self.assertNotEqual(p1, p2)
        self.assertEqual(p1, c.build_parameter_fingerprint({"channel": "Security"}))


class _ReuseHarness(unittest.TestCase):
    """Probe try_durable_reuse_v2 against a written sidecar + durable CSV."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.src = self.base / "raw" / "$MFT"
        self.src.parent.mkdir(parents=True)
        self.src.write_bytes(b"RAWMFT")
        self.out = self.base / "CASE" / "artifacts" / "mft"
        self.out.mkdir(parents=True)
        self.csv = self.out / "mft_timeline.csv"
        self.csv.write_text("a,b\n1,2\n")
        from tests.test_durable_reuse_helper import FakeAudit, FakeState
        self.a, self.s = FakeAudit(), FakeState()

    def _write(self, *, sig="MFTECmd/mft_timeline_v1", params=None, sources=None):
        c.write_reuse_sidecar_v2(
            str(self.csv), tool_name="disk.extract_mft_timeline",
            parser_signature=sig, source_paths=sources or [str(self.src)],
            parameters=params or {"mft_path": str(self.src)},
        )

    def _reuse(self, **over):
        kw = dict(
            tool_name="disk.extract_mft_timeline",
            parser_signature="MFTECmd/mft_timeline_v1",
            source_paths=[str(self.src)],
            parameters={"mft_path": str(self.src)},
            output_base=str(self.base), case_id="CASE", subtype="mft",
            canonical_filename="mft_timeline.csv",
        )
        kw.update(over)
        return c.try_durable_reuse_v2(self.a, self.s, **kw)


class V2ReuseTests(_ReuseHarness):
    def test_t1_reuse_hit_on_identical_inputs(self):
        self._write()
        r = self._reuse()
        self.assertIsNotNone(r)
        self.assertTrue(r["reused_output"])
        self.assertEqual(r["reuse_confidence"], "fingerprint_verified")

    def test_t2_invalidate_on_source_change(self):
        self._write()
        self.src.write_bytes(b"CHANGED-BIGGER")
        self.assertIsNone(self._reuse(), "changed source must reparse")

    def test_t3_invalidate_on_param_change(self):
        # EVTX-style param staleness: sidecar written for channel=Security,
        # probe with channel=System -> NO reuse.
        self._write(params={"channel": "Security"})
        r = self._reuse(parameters={"channel": "System"})
        self.assertIsNone(r, "param change must reparse (EVTX bug fix)")

    def test_t4_invalidate_on_parser_version_change(self):
        self._write(sig="MFTECmd/mft_timeline_v1")
        self.assertIsNone(
            self._reuse(parser_signature="MFTECmd/mft_timeline_v2"),
            "parser-version bump must reparse",
        )

    def test_t5_cache_hit_execution_satisfies_report_gate(self):
        self._write()
        r = self._reuse()
        row = self.s.rows[0]
        # mirrors reporting._execution_was_successful
        self.assertEqual(int(row["exit_code"]), 0)
        self.assertGreater(float(row["duration_seconds"]), 0)
        self.assertTrue(row["audit_completed_entry_hash"])
        self.assertEqual(r["execution_id"], row["execution_id"])

    def test_t8_no_sidecar_means_no_reuse(self):
        # No sidecar at all -> strict v2 refuses reuse (re-parse).
        self.assertIsNone(self._reuse())

    def test_t9_v1_sidecar_is_ignored(self):
        # Write a legacy v1 sidecar; v2 probe must ignore it (no reuse).
        c.write_reuse_sidecar(
            str(self.csv), tool_name="disk.extract_mft_timeline",
            source_path=str(self.src),
        )
        self.assertIsNone(self._reuse(), "v1 sidecar must be ignored under v2")

    def test_t7_case_isolation(self):
        # Case B has its own (empty) artifacts dir -> never reuses case A's CSV.
        self._write()
        outB = self.base / "CASE-B" / "artifacts" / "mft"
        outB.mkdir(parents=True)
        self.assertIsNone(self._reuse(case_id="CASE-B"))

    def test_force_reparse_invalidates(self):
        self._write()
        self.assertIsNone(self._reuse(force_reparse=True))
        self.assertFalse(c._sidecar_path(str(self.csv)).exists())


# ===========================================================================
# Phase 1/3 - end-to-end double-call reuse across the extractors
# ===========================================================================

_FILETIME_EPOCH_DELTA = 116444736000000000


def _make_i_v2(path: str, size: int, filetime: int) -> bytes:
    encoded = path + "\x00"
    blob = struct.pack("<q", 2) + struct.pack("<q", size) + struct.pack("<q", filetime)
    blob += struct.pack("<I", len(encoded))
    blob += encoded.encode("utf-16-le")
    return blob


_TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>\n'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
    "  <RegistrationInfo><Author>SYN\\author</Author></RegistrationInfo>\n"
    '  <Actions Context="Author"><Exec>'
    "<Command>C:\\Users\\Public\\evil.exe</Command></Exec></Actions>\n"
    "</Task>\n"
)


class _E2EBase(unittest.TestCase):
    def _init(self, tmp, case_id="CASE-V2", fake_ez=False):
        audit = AuditLogger(str(Path(tmp) / f"audit_{case_id}.jsonl"))
        state = CaseStateManager(str(Path(tmp) / f"state_{case_id}.json"))
        state.load(case_id)
        runner = None
        if fake_ez:
            runner = _FakeRunner(audit_logger=audit, case_id=case_id, state_manager=state)
        disk.init_tools(state, audit, ez_runner=runner)
        return audit, state, runner

    def _count_parse_calls(self, runner):
        return list(runner.calls) if runner else []


class NativeReuseE2ETests(_E2EBase):
    """recycle / psreadline / scheduled_tasks: parse#1 -> reuse#2."""

    def _recycle_root(self, tmp):
        root = Path(tmp) / "mnt" / "C"
        (root / "Windows").mkdir(parents=True, exist_ok=True)
        sid = root / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
        sid.mkdir(parents=True, exist_ok=True)
        ft = 130000000000000000
        (sid / "$IAAA").write_bytes(_make_i_v2("C:\\Users\\x\\secret.docx", 99, ft))
        (sid / "$RAAA").write_bytes(b"content")
        return root

    def test_recycle_bin_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            _a, _s, _r = self._init(tmp)
            root = self._recycle_root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r1 = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-V2")
                self.assertEqual(r1["status"], "success")
                self.assertNotIn("reused_output", r1)
                sidecar = c._sidecar_path(r1["csv_path"])
                self.assertTrue(sidecar.exists(), "sidecar written on success")

                r2 = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-V2")
            self.assertTrue(r2.get("reused_output"), "2nd call must reuse")
            self.assertEqual(r2["status"], "success")
            self.assertTrue(r2["findings_created"], "finding recreated on reuse")
            self.assertNotEqual(r1["execution_id"], r2["execution_id"], "fresh exec id")
            self.assertEqual(r1["total_rows"], r2["total_rows"])

    def test_recycle_bin_invalidate_on_input_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = self._recycle_root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                disk.extract_recycle_bin(image_path=str(root), case_id="CASE-V2")
                # add a new $I -> source-set changes -> re-parse (no reuse)
                sid = root / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
                (sid / "$IBBB").write_bytes(
                    _make_i_v2("C:\\Users\\x\\other.txt", 5, 130000000000000001))
                r2 = disk.extract_recycle_bin(image_path=str(root), case_id="CASE-V2")
            self.assertFalse(r2.get("reused_output"), "added input must reparse")

    def _psr_root(self, tmp):
        root = Path(tmp) / "mnt" / "C"
        (root / "Windows").mkdir(parents=True, exist_ok=True)
        psr = (root / "Users" / "alpha" / "AppData" / "Roaming" / "Microsoft"
               / "Windows" / "PowerShell" / "PSReadLine")
        psr.mkdir(parents=True, exist_ok=True)
        (psr / "ConsoleHost_history.txt").write_text(
            "whoami\nIEX (New-Object Net.WebClient).DownloadString('h')\n",
            encoding="utf-8")
        return root

    def test_powershell_history_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = self._psr_root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r1 = disk.extract_powershell_history(image_path=str(root), case_id="CASE-V2")
                self.assertEqual(r1["status"], "success")
                r2 = disk.extract_powershell_history(image_path=str(root), case_id="CASE-V2")
            self.assertTrue(r2.get("reused_output"))
            self.assertTrue(r2["findings_created"])

    def _task_root(self, tmp):
        root = Path(tmp) / "mnt" / "C"
        t = root / "Windows" / "System32" / "Tasks"
        t.mkdir(parents=True, exist_ok=True)
        (t / "SyntheticTask").write_text(_TASK_XML, encoding="utf-8")
        return root

    def test_scheduled_tasks_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp)
            root = self._task_root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                r1 = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-V2")
                self.assertEqual(r1["status"], "success")
                r2 = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-V2")
            self.assertTrue(r2.get("reused_output"))
            self.assertTrue(r2["findings_created"])

    def test_scheduled_tasks_case_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init(tmp, case_id="CASE-A")
            root = self._task_root(tmp)
            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-A")
                # switch to a fresh case in the SAME image -> must NOT reuse A's CSV
                _a, _s, _r = self._init(tmp, case_id="CASE-B")
                r2 = disk.extract_scheduled_tasks(image_path=str(root), case_id="CASE-B")
            self.assertFalse(r2.get("reused_output"), "case B must not reuse case A")


class FileAccessReuseE2ETests(_E2EBase):
    """ShellBags (dotnet) parse#1 -> reuse#2 via the fake EZ runner."""

    def _profiles(self, root):
        base = root / "Users" / "alpha"
        uc = base / "AppData" / "Local" / "Microsoft" / "Windows"
        uc.mkdir(parents=True, exist_ok=True)
        (uc / "UsrClass.dat").write_text("x", encoding="utf-8")
        (base / "NTUSER.DAT").write_text("x", encoding="utf-8")
        (root / "Windows").mkdir(parents=True, exist_ok=True)

    def test_shellbags_reuse_skips_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            _a, _s, runner = self._init(tmp, fake_ez=True)
            root = Path(tmp) / "mnt" / "C"
            self._profiles(root)
            with mock.patch.object(disk, "_replay_hive_with_rla", _no_replay):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                    r1 = disk.extract_shellbags(image_path=str(root), case_id="CASE-V2")
                    self.assertEqual(r1["status"], "success")
                    calls_after_1 = len(runner.calls)
                    self.assertGreater(calls_after_1, 0, "1st call parses (SBECmd invoked)")

                    r2 = disk.extract_shellbags(image_path=str(root), case_id="CASE-V2")
            self.assertTrue(r2.get("reused_output"), "2nd call reuses")
            self.assertEqual(len(runner.calls), calls_after_1,
                             "2nd call must NOT invoke SBECmd (parse skipped)")
            self.assertTrue(r2["findings_created"], "finding recreated on reuse")

    def test_shellbags_invalidate_on_hive_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            _a, _s, runner = self._init(tmp, fake_ez=True)
            root = Path(tmp) / "mnt" / "C"
            self._profiles(root)
            with mock.patch.object(disk, "_replay_hive_with_rla", _no_replay):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                    disk.extract_shellbags(image_path=str(root), case_id="CASE-V2")
                    calls_after_1 = len(runner.calls)
                    # mutate the hive -> source-set changes -> reparse
                    (root / "Users" / "alpha" / "NTUSER.DAT").write_text(
                        "CHANGED-BIGGER", encoding="utf-8")
                    r2 = disk.extract_shellbags(image_path=str(root), case_id="CASE-V2")
            self.assertFalse(r2.get("reused_output"), "changed hive must reparse")
            self.assertGreater(len(runner.calls), calls_after_1, "SBECmd re-invoked")


class NoPoisonedCacheTests(_E2EBase):
    """A failed parse must NOT write a sidecar -> next run re-parses."""

    def _profiles(self, root):
        base = root / "Users" / "alpha"
        uc = base / "AppData" / "Local" / "Microsoft" / "Windows"
        uc.mkdir(parents=True, exist_ok=True)
        (uc / "UsrClass.dat").write_text("x", encoding="utf-8")
        (base / "NTUSER.DAT").write_text("x", encoding="utf-8")
        (root / "Windows").mkdir(parents=True, exist_ok=True)

    def test_partial_collection_writes_no_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            _a, _s, runner = self._init(tmp, fake_ez=True)
            runner.sbe_behavior = "fail"  # parser non-ok -> partial_collection
            root = Path(tmp) / "mnt" / "C"
            self._profiles(root)
            with mock.patch.object(disk, "_replay_hive_with_rla", _no_replay):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp}, clear=False):
                    r1 = disk.extract_shellbags(image_path=str(root), case_id="CASE-V2")
                    self.assertNotEqual(r1["status"], "success")
                    csv_path = r1.get("csv_path")
                    if csv_path:
                        self.assertFalse(
                            c._sidecar_path(csv_path).exists(),
                            "no sidecar on partial_collection",
                        )
                    # fix the parser; 2nd call must RE-PARSE (no poisoned reuse)
                    runner.sbe_behavior = "rows"
                    calls_before = len(runner.calls)
                    r2 = disk.extract_shellbags(image_path=str(root), case_id="CASE-V2")
            self.assertFalse(r2.get("reused_output"))
            self.assertGreater(len(runner.calls), calls_before)


if __name__ == "__main__":
    unittest.main()
