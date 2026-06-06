import csv
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk, timeline


def _write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


class FakeEZRunner(SafeRunner):
    def __init__(self, *, audit_logger: AuditLogger, case_id: str, state_manager: CaseStateManager) -> None:
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="disk.fake",
            state_manager=state_manager,
        )
        self.evtx_calls = 0
        self.recmd_calls = 0

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
        self.evtx_calls += 1
        rows = [
            {
                "EventId": "4624",
                "Channel": "Security",
                "TimeCreated": f"2026-04-14 10:{idx % 60:02d}:00",
                "Provider": "Microsoft-Windows-Security-Auditing",
                "Computer": "WKSTN01",
                "UserSID": "S-1-5-18",
                "Message": f"Successful logon #{idx}",
            }
            for idx in range(120)
        ]
        _write_rows(Path(csv_dir) / csv_filename, rows)
        return self.run(
            ["printf", "Completed 120 events"],
            parameters={
                "evtx_dir": evtx_dir,
                "start_date": start_date,
                "end_date": end_date,
                "event_ids": list(event_ids or []),
            },
            tool_name=tool_name,
            timeout=timeout,
        )

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
        self.recmd_calls += 1
        rows = [
            {
                "HiveType": "NTUSER.DAT",
                "KeyPath": r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run",
                "ValueName": "Malware",
                "ValueData": r"C:\Users\Alice\AppData\Roaming\evil.exe",
                "LastWriteTimestamp": "2026-04-14 09:00:00",
            }
        ]
        _write_rows(Path(csv_dir) / csv_filename, rows)
        return self.run(
            ["printf", "Processed registry"],
            parameters={
                "hive_dir": hive_dir,
                "batch_file": batch_file,
                "sync_batch": sync_batch,
            },
            tool_name=tool_name,
            timeout=timeout,
        )


class FakePlasoRunner(SafeRunner):
    def __init__(self, *, audit_logger: AuditLogger, case_id: str, state_manager: CaseStateManager) -> None:
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="timeline.fake",
            state_manager=state_manager,
        )
        self.timeline_calls = 0

    def log2timeline(
        self,
        *,
        source_path: str,
        storage_file: str,
        parsers: str,
        tool_name=None,
        timeout=7200,
    ):
        self.timeline_calls += 1
        Path(storage_file).parent.mkdir(parents=True, exist_ok=True)
        Path(storage_file).write_text("plaso-storage", encoding="utf-8")
        return self.run(
            ["printf", "Completed processing 123 events"],
            parameters={"source_path": source_path, "storage_file": storage_file, "parsers": parsers},
            tool_name=tool_name,
            timeout=timeout,
        )


class Batch2ToolTests(unittest.TestCase):
    def test_summarize_evtx_reuses_cached_csv_and_records_cache_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-B2-EVTX")
            runner = FakeEZRunner(audit_logger=audit, case_id="CASE-B2-EVTX", state_manager=state)
            disk.init_tools(state, audit, ez_runner=runner)

            evtx_dir = Path(tmp_dir) / "evidence" / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                first = disk.summarize_evtx(
                    image_path=str(Path(tmp_dir) / "evidence"),
                    evtx_dir=str(evtx_dir),
                )
                second = disk.summarize_evtx(
                    image_path=str(Path(tmp_dir) / "evidence"),
                    evtx_dir=str(evtx_dir),
                )

            self.assertFalse(first["cache_hit"])
            self.assertTrue(second["cache_hit"])
            self.assertEqual(runner.evtx_calls, 1)

            persisted = json.loads(Path(tmp_dir, "state.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["executions_count"], 2)

            entries = [
                json.loads(line)
                for line in Path(tmp_dir, "audit.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            # W1.7 (Run 2 review): _finalize_tool_response now also writes
            # context_bundle audit rows. Filter to durable execution-lifecycle
            # events so this assertion stays stable.
            lifecycle = [e for e in entries if e.get("event_type") in {"started", "completed", "linked"}]
            self.assertEqual(len(lifecycle), 4)

    def test_summarize_evtx_reruns_when_cached_csv_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-B2-EVTX-MISS")
            runner = FakeEZRunner(audit_logger=audit, case_id="CASE-B2-EVTX-MISS", state_manager=state)
            disk.init_tools(state, audit, ez_runner=runner)

            evtx_dir = Path(tmp_dir) / "evidence" / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                first = disk.summarize_evtx(
                    image_path=str(Path(tmp_dir) / "evidence"),
                    evtx_dir=str(evtx_dir),
                )
                Path(first["csv_path"]).unlink()
                second = disk.summarize_evtx(
                    image_path=str(Path(tmp_dir) / "evidence"),
                    evtx_dir=str(evtx_dir),
                )

            self.assertEqual(runner.evtx_calls, 2)
            self.assertFalse(second["cache_hit"])

    def test_registry_sync_batch_bypasses_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-B2-REG")
            runner = FakeEZRunner(audit_logger=audit, case_id="CASE-B2-REG", state_manager=state)
            disk.init_tools(state, audit, ez_runner=runner)

            image_path = Path(tmp_dir) / "image"
            hive_dir = Path(tmp_dir) / "hives"
            image_path.mkdir(parents=True, exist_ok=True)
            hive_dir.mkdir(parents=True, exist_ok=True)

            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                first = disk.extract_registry_run_keys(
                    image_path=str(image_path),
                    hive_dir=str(hive_dir),
                    batch_mode=False,
                    sync_batch=False,
                )
                second = disk.extract_registry_run_keys(
                    image_path=str(image_path),
                    hive_dir=str(hive_dir),
                    batch_mode=False,
                    sync_batch=True,
                )

            self.assertFalse(first["cache_hit"])
            self.assertFalse(second["cache_hit"])
            self.assertEqual(runner.recmd_calls, 2)

    def test_replay_hive_with_rla_uses_temp_cleaned_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hive_path = Path(tmp_dir) / "NTUSER.DAT"
            hive_path.write_text("hive", encoding="utf-8")
            (Path(tmp_dir) / "NTUSER.DAT.LOG1").write_text("log1", encoding="utf-8")
            (Path(tmp_dir) / "NTUSER.DAT.LOG2").write_text("log2", encoding="utf-8")

            def fake_run(cmd, **kwargs):
                out_dir = Path(cmd[cmd.index("--out") + 1])
                (out_dir / "cleaned_NTUSER.DAT").write_text("cleaned", encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with mock.patch("sift_mcp.tools.disk.subprocess.run", side_effect=fake_run):
                cleaned_hive, tmp_in, tmp_out = disk._replay_hive_with_rla(hive_path, "alice")

            try:
                self.assertNotEqual(cleaned_hive, hive_path)
                self.assertTrue(cleaned_hive.exists())
                self.assertTrue(str(cleaned_hive).startswith(str(tmp_out)))
                self.assertTrue((tmp_in / "NTUSER.DAT").exists())
            finally:
                shutil.rmtree(tmp_in, ignore_errors=True)
                shutil.rmtree(tmp_out, ignore_errors=True)

    def test_build_timeline_reuses_cached_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-B2-TL")
            runner = FakePlasoRunner(audit_logger=audit, case_id="CASE-B2-TL", state_manager=state)
            timeline.init_tools(audit, state)
            timeline._runner = runner  # type: ignore[attr-defined]

            source_path = Path(tmp_dir) / "evidence" / "disk.E01"
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("dummy", encoding="utf-8")

            old_cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                first = timeline.build_timeline(str(source_path), "CASE-B2-TL", parsers="win10")
                second = timeline.build_timeline(str(source_path), "CASE-B2-TL", parsers="win10")
            finally:
                os.chdir(old_cwd)

            self.assertFalse(first["cache_hit"])
            self.assertTrue(second["cache_hit"])
            self.assertEqual(runner.timeline_calls, 1)


if __name__ == "__main__":
    unittest.main()
