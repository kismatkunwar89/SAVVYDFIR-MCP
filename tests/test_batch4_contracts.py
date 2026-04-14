import csv
import json
import os
import tempfile
import unittest
from pathlib import Path

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk


def _write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


class FakeBatch4EZRunner(SafeRunner):
    def __init__(self, *, audit_logger: AuditLogger, case_id: str, state_manager: CaseStateManager) -> None:
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="disk.fake",
            state_manager=state_manager,
        )
        self.evtx_calls = 0
        self.mft_calls = 0
        self.registry_calls = 0

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
        _write_rows(
            Path(csv_dir) / csv_filename,
            [
                {
                    "EventId": "4688",
                    "Channel": "Security",
                    "TimeCreated": "2026-04-14 10:00:00",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "Computer": "WKSTN01",
                    "UserSID": "S-1-5-18",
                    "Message": r"A new process has been created. New Process Name: C:\Temp\evil.exe",
                },
                {
                    "EventId": "4624",
                    "Channel": "Security",
                    "TimeCreated": "2026-04-14 10:01:00",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "Computer": "WKSTN01",
                    "UserSID": "S-1-5-18",
                    "Message": "An account was successfully logged on.",
                },
            ],
        )
        return self.run(
            ["printf", "Completed EVTX parsing"],
            parameters={"evtx_dir": evtx_dir, "event_ids": list(event_ids or [])},
            tool_name=tool_name,
            timeout=timeout,
        )

    def run_mftecmd(
        self,
        *,
        mft_path: str,
        csv_dir: str,
        csv_filename: str,
        tool_name=None,
        timeout=1800,
    ):
        self.mft_calls += 1
        _write_rows(
            Path(csv_dir) / csv_filename,
            [
                {
                    "EntryNumber": "42",
                    "SequenceNumber": "1",
                    "FileName": r"C:\Temp\evil.exe",
                    "Created0x10": "2026-04-14 09:00:00",
                    "Created0x30": "2026-04-14 10:00:00",
                    "InUse": "true",
                    "IsDirectory": "false",
                    "FileSize": "1337",
                    "ParentEntryNumber": "5",
                }
            ],
        )
        return self.run(
            ["printf", "Completed MFTECmd parsing"],
            parameters={"mft_path": mft_path},
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
        self.registry_calls += 1
        _write_rows(
            Path(csv_dir) / csv_filename,
            [
                {
                    "HiveType": "NTUSER.DAT",
                    "KeyPath": r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run",
                    "ValueName": "Malware",
                    "ValueData": r"C:\Users\Alice\AppData\Roaming\evil.exe",
                    "LastWriteTimestamp": "2026-04-14 09:00:00",
                }
            ],
        )
        return self.run(
            ["printf", "Completed RECmd parsing"],
            parameters={"hive_dir": hive_dir, "batch_file": batch_file, "sync_batch": sync_batch},
            tool_name=tool_name,
            timeout=timeout,
        )


class Batch4ContractTests(unittest.TestCase):
    def _init_disk_tools(self, tmp_dir: str):
        audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
        state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
        state.load("CASE-B4")
        runner = FakeBatch4EZRunner(audit_logger=audit, case_id="CASE-B4", state_manager=state)
        disk.init_tools(state, audit, ez_runner=runner)
        return state, runner

    def test_default_summary_mode_omits_data_for_heavy_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            self._init_disk_tools(tmp_dir)
            evidence_root = Path(tmp_dir) / "evidence"
            evtx_dir = evidence_root / "Logs"
            hive_dir = evidence_root / "config"
            mft_path = evidence_root / "$MFT"
            evtx_dir.mkdir(parents=True, exist_ok=True)
            hive_dir.mkdir(parents=True, exist_ok=True)
            mft_path.write_text("placeholder", encoding="utf-8")

            with unittest.mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                mft = disk.extract_mft_timeline(image_path=str(evidence_root), mft_path=str(mft_path))
                evtx = disk.summarize_evtx(image_path=str(evidence_root), evtx_dir=str(evtx_dir))
                registry = disk.extract_registry_run_keys(image_path=str(evidence_root), hive_dir=str(hive_dir))

            for result in (mft, evtx, registry):
                self.assertEqual(result["status"], "success")
                self.assertNotIn("data", result)
                self.assertIn("csv_path", result)
                self.assertIn("findings_created", result)
                self.assertIn("records_count", result)

    def test_detailed_mode_returns_data_for_heavy_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            self._init_disk_tools(tmp_dir)
            evidence_root = Path(tmp_dir) / "evidence"
            evtx_dir = evidence_root / "Logs"
            hive_dir = evidence_root / "config"
            mft_path = evidence_root / "$MFT"
            evtx_dir.mkdir(parents=True, exist_ok=True)
            hive_dir.mkdir(parents=True, exist_ok=True)
            mft_path.write_text("placeholder", encoding="utf-8")

            with unittest.mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                mft = disk.extract_mft_timeline(
                    image_path=str(evidence_root),
                    mft_path=str(mft_path),
                    response_format="detailed",
                )
                evtx = disk.summarize_evtx(
                    image_path=str(evidence_root),
                    evtx_dir=str(evtx_dir),
                    response_format="detailed",
                )
                registry = disk.extract_registry_run_keys(
                    image_path=str(evidence_root),
                    hive_dir=str(hive_dir),
                    response_format="detailed",
                )

            for result in (mft, evtx, registry):
                self.assertEqual(result["status"], "success")
                self.assertIn("data", result)
                self.assertGreater(len(result["data"]), 0)

    def test_cache_hit_still_works_between_summary_and_detailed_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state, runner = self._init_disk_tools(tmp_dir)
            evidence_root = Path(tmp_dir) / "evidence"
            evtx_dir = evidence_root / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            with unittest.mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                first = disk.summarize_evtx(
                    image_path=str(evidence_root),
                    evtx_dir=str(evtx_dir),
                )
                second = disk.summarize_evtx(
                    image_path=str(evidence_root),
                    evtx_dir=str(evtx_dir),
                    response_format="detailed",
                )

            self.assertFalse(first["cache_hit"])
            self.assertTrue(second["cache_hit"])
            self.assertIn("data", second)
            self.assertEqual(runner.evtx_calls, 1)
            persisted = json.loads(Path(tmp_dir, "state.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["executions_count"], 2)

    def test_invalid_response_format_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            self._init_disk_tools(tmp_dir)
            evidence_root = Path(tmp_dir) / "evidence"
            evtx_dir = evidence_root / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            result = disk.summarize_evtx(
                image_path=str(evidence_root),
                evtx_dir=str(evtx_dir),
                response_format="invalid",
            )
            self.assertEqual(result["status"], "error")
            self.assertIn("response_format", result["error_message"])


if __name__ == "__main__":
    unittest.main()
