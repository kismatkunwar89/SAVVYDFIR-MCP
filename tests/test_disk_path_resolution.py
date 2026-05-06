import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class _PathAwareRunner(SafeRunner):
    def __init__(self, *, audit_logger: AuditLogger, case_id: str, state_manager: CaseStateManager) -> None:
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="disk.path-aware",
            state_manager=state_manager,
        )
        self.last_evtx_dir: str | None = None
        self.last_hive_dir: str | None = None
        self.hive_dirs: list[str] = []
        self.last_hive_path: str | None = None
        self.last_mft_path: str | None = None

    def run_evtxecmd(
        self,
        *,
        evtx_dir: str,
        csv_dir: str,
        csv_filename: str,
        start_date=None,
        end_date=None,
        event_ids=None,
        tool_name=None,
        timeout=1800,
    ):
        self.last_evtx_dir = evtx_dir
        _write_text(
            Path(csv_dir) / csv_filename,
            "EventId,Channel,Provider,TimeCreated,Level,Computer,UserId,Message\n"
            "4688,Security,Microsoft-Windows-Security-Auditing,2026-04-17T00:00:00+00:00,Information,WKSTN01,S-1-5-18,Process created\n",
        )
        return self.run(["printf", "Completed EVTX parsing"], parameters={"evtx_dir": evtx_dir}, tool_name=tool_name, timeout=timeout)

    def run_recmd(
        self,
        *,
        hive_dir: str,
        csv_dir: str,
        csv_filename: str,
        batch_file=None,
        sync_batch=False,
        tool_name=None,
        timeout=1800,
    ):
        self.last_hive_dir = hive_dir
        self.hive_dirs.append(hive_dir)
        _write_text(
            Path(csv_dir) / csv_filename,
            "HiveType,KeyPath,ValueName,ValueData,LastWriteTimestamp\n"
            "NTUSER.DAT,NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,Malware,C:\\Users\\Alice\\AppData\\Roaming\\evil.exe,2026-04-14 09:00:00\n",
        )
        return self.run(["printf", "Completed registry parsing"], parameters={"hive_dir": hive_dir}, tool_name=tool_name, timeout=timeout)

    def run_amcacheparser(
        self,
        *,
        hive_path: str,
        csv_dir: str,
        csv_filename: str,
        tool_name=None,
        timeout=1800,
    ):
        self.last_hive_path = hive_path
        _write_text(
            Path(csv_dir) / "amcache_UnassociatedFileEntries.csv",
            "FullPath,SHA1,FileSize,Publisher\n"
            "C:\\Temp\\evil.exe,0123456789abcdef0123456789abcdef01234567,1337,Acme\n",
        )
        return self.run(["printf", "Completed amcache parsing"], parameters={"hive_path": hive_path}, tool_name=tool_name, timeout=timeout)

    def run_mftecmd(
        self,
        *,
        mft_path: str,
        csv_dir: str,
        csv_filename: str,
        tool_name=None,
        timeout=1800,
    ):
        self.last_mft_path = mft_path
        _write_text(
            Path(csv_dir) / csv_filename,
            "EntryNumber,SequenceNumber,FileName,Created0x10,Created0x30,InUse,IsDirectory,FileSize,ParentEntryNumber\n"
            "42,1,C:\\Temp\\evil.exe,2026-04-14 09:00:00,2026-04-14 10:00:00,true,false,1337,5\n",
        )
        return self.run(["printf", "Completed mft parsing"], parameters={"mft_path": mft_path}, tool_name=tool_name, timeout=timeout)


class DiskPathResolutionTests(unittest.TestCase):
    def _init_tools(self, tmp_dir: str, case_id: str = "CASE-PATHS") -> _PathAwareRunner:
        audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
        state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
        state.load(case_id)
        runner = _PathAwareRunner(audit_logger=audit, case_id=case_id, state_manager=state)
        disk.init_tools(state, audit, ez_runner=runner)
        return runner

    def test_helper_resolvers_cover_direct_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_file = root / "Security.evtx"
            evtx_file.write_text("x", encoding="utf-8")
            hive_file = root / "NTUSER.DAT"
            hive_file.write_text("x", encoding="utf-8")
            amcache_file = root / "Amcache.hve"
            amcache_file.write_text("x", encoding="utf-8")
            mft_file = root / "$MFT"
            mft_file.write_text("x", encoding="utf-8")
            prefetch_dir = root / "Prefetch"
            prefetch_dir.mkdir()
            (prefetch_dir / "EVIL.EXE-12345678.pf").write_text("x", encoding="utf-8")

            self.assertEqual(disk._resolve_evtx_dir_input(str(evtx_file), None), str(evtx_file.parent))
            self.assertEqual(disk._resolve_registry_hive_dir_input(str(hive_file), None), str(hive_file.parent))
            self.assertEqual(disk._resolve_amcache_hive_input(str(amcache_file), None), str(amcache_file))
            self.assertEqual(disk._resolve_mft_path_input(str(mft_file), None), str(mft_file))
            self.assertEqual(disk._resolve_prefetch_dir_input(str(prefetch_dir), None), str(prefetch_dir))

    def test_summarize_evtx_uses_shared_windows_root_for_tsk_direct_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            runner = self._init_tools(tmp_dir, "CASE-EVTX-PATH")
            image_root = Path(tmp_dir) / "mnt" / "evidence" / "ewf1"
            image_root.mkdir(parents=True, exist_ok=True)
            shared_root = Path(tmp_dir) / "mnt" / "disk"
            evtx_dir = shared_root / "Windows" / "System32" / "winevt" / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[shared_root]):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                    result = disk.summarize_evtx(image_path=str(image_root), channel="Security")

            self.assertEqual(result["status"], "success")
            self.assertEqual(runner.last_evtx_dir, str(evtx_dir))

    def test_extract_registry_uses_shared_windows_root_and_discovers_user_hives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            runner = self._init_tools(tmp_dir, "CASE-REG-PATH")
            image_root = Path(tmp_dir) / "mnt" / "evidence" / "ewf1"
            image_root.mkdir(parents=True, exist_ok=True)
            shared_root = Path(tmp_dir) / "mnt" / "disk"
            hive_dir = shared_root / "Windows" / "System32" / "config"
            hive_dir.mkdir(parents=True, exist_ok=True)
            user_hive = shared_root / "Users" / "alice" / "NTUSER.DAT"
            user_hive.parent.mkdir(parents=True, exist_ok=True)
            user_hive.write_text("hive", encoding="utf-8")

            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[shared_root]):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                    result = disk.extract_registry_run_keys(image_path=str(image_root), batch_mode=False)

            self.assertEqual(result["status"], "success")
            self.assertIn(str(hive_dir), runner.hive_dirs)
            self.assertIn(str(user_hive), result["user_hives_scanned"])

    def test_get_amcache_uses_shared_windows_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            runner = self._init_tools(tmp_dir, "CASE-AMCACHE-PATH")
            image_root = Path(tmp_dir) / "mnt" / "evidence" / "ewf1"
            image_root.mkdir(parents=True, exist_ok=True)
            shared_root = Path(tmp_dir) / "mnt" / "disk"
            hive_path = shared_root / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
            hive_path.parent.mkdir(parents=True, exist_ok=True)
            hive_path.write_text("hive", encoding="utf-8")

            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[shared_root]):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                    result = disk.get_amcache(image_path=str(image_root))

            self.assertEqual(result["status"], "success")
            self.assertEqual(runner.last_hive_path, str(hive_path))

    def test_extract_mft_uses_shared_windows_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            runner = self._init_tools(tmp_dir, "CASE-MFT-PATH")
            image_root = Path(tmp_dir) / "mnt" / "evidence" / "ewf1"
            image_root.mkdir(parents=True, exist_ok=True)
            shared_root = Path(tmp_dir) / "mnt" / "disk"
            mft_path = shared_root / "$MFT"
            mft_path.parent.mkdir(parents=True, exist_ok=True)
            mft_path.write_text("mft", encoding="utf-8")

            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[shared_root]):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                    result = disk.extract_mft_timeline(image_path=str(image_root))

            self.assertEqual(result["status"], "success")
            self.assertEqual(runner.last_mft_path, str(mft_path))

    def test_extract_prefetch_uses_shared_windows_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            self._init_tools(tmp_dir, "CASE-PREFETCH-PATH")
            image_root = Path(tmp_dir) / "mnt" / "evidence" / "ewf1"
            image_root.mkdir(parents=True, exist_ok=True)
            shared_root = Path(tmp_dir) / "mnt" / "disk"
            prefetch_dir = shared_root / "Windows" / "Prefetch"
            prefetch_dir.mkdir(parents=True, exist_ok=True)
            (prefetch_dir / "EVIL.EXE-12345678.pf").write_text("placeholder", encoding="utf-8")

            class _FakePrefetchFile:
                executable_filename = "EVIL.EXE"
                run_count = 1
                number_of_filenames = 1

                def get_last_run_time(self, index: int):
                    if index == 0:
                        return datetime(2026, 4, 14, 10, 0, tzinfo=timezone.utc)
                    raise IndexError

                def get_filename(self, index: int):
                    return r"C:\Temp\evil.exe"

            fake_pyscca = types.SimpleNamespace(open=lambda _: _FakePrefetchFile())
            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[shared_root]):
                with mock.patch.dict(sys.modules, {"pyscca": fake_pyscca}, clear=False):
                    with mock.patch.object(disk, "_prefetch_metadata_from_stat", return_value=None):
                        with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                            result = disk.extract_prefetch(image_path=str(image_root))

            self.assertEqual(result["status"], "success")
            self.assertTrue(result["normalized_observations"][0]["prefetch_path"].startswith(str(prefetch_dir)))

    def test_tools_error_when_resolved_path_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            runner = self._init_tools(tmp_dir, "CASE-MISSING-PATH")
            image_root = Path(tmp_dir) / "mnt" / "evidence" / "ewf1"
            image_root.mkdir(parents=True, exist_ok=True)
            shared_root = Path(tmp_dir) / "mnt" / "disk"

            with mock.patch.object(disk, "_shared_windows_root_candidates", return_value=[shared_root]):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                    evtx = disk.summarize_evtx(image_path=str(image_root), channel="Security")
                    registry = disk.extract_registry_run_keys(image_path=str(image_root), batch_mode=False)
                    amcache = disk.get_amcache(image_path=str(image_root))
                    mft = disk.extract_mft_timeline(image_path=str(image_root))
                    prefetch = disk.extract_prefetch(image_path=str(image_root))

            for result, field in (
                (evtx, "evtx_dir"),
                (registry, "hive_dir"),
                (amcache, "hive_path"),
                (mft, "mft_path"),
                (prefetch, "prefetch_dir"),
            ):
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["input_name"], field)
            self.assertIsNone(runner.last_evtx_dir)


if __name__ == "__main__":
    unittest.main()
