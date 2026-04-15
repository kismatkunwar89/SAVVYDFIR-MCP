import csv
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.semantics import adaptive_eids_from_findings, compute_coverage_from_findings
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk


def _write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


class FakeAdaptiveEZRunner(SafeRunner):
    def __init__(self, *, audit_logger: AuditLogger, case_id: str, state_manager: CaseStateManager) -> None:
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="disk.fake",
            state_manager=state_manager,
        )
        self.last_event_ids = None

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
        self.last_event_ids = list(event_ids or [])
        rows = [
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
        ]
        _write_rows(Path(csv_dir) / csv_filename, rows)
        return self.run(
            ["printf", "Completed EVTX parsing"],
            parameters={
                "evtx_dir": evtx_dir,
                "start_date": start_date,
                "end_date": end_date,
                "event_ids": list(event_ids or []),
            },
            tool_name=tool_name,
            timeout=timeout,
        )


class EvtxAdaptiveTests(unittest.TestCase):
    def test_adaptive_eids_from_findings_expands_from_attack_techniques(self) -> None:
        finding_set = [
            {"mitre_technique": "T1078"},
            {"mitre_technique": "T1059.001"},
            {"mitre_technique": "T1547.001"},
        ]
        eids = adaptive_eids_from_findings(finding_set)
        for event_id in (4624, 4625, 4648, 4688, 4689, 4672, 4104, 4698):
            self.assertIn(event_id, eids)

    def test_coverage_computation_returns_suggestions_for_uncovered_tactics(self) -> None:
        coverage = compute_coverage_from_findings(
            [
                {"mitre_tactic": "TA0003"},
                {"mitre_tactic": "TA0005"},
            ]
        )
        self.assertGreater(len(coverage["covered_tactics"]), 0)
        self.assertGreater(len(coverage["uncovered_tactics"]), 0)
        self.assertIn("TA0006", coverage["suggested_next_tools"])

    def test_summarize_evtx_marks_default_adaptive_and_explicit_strategies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-EVTX-ADAPT")
            runner = FakeAdaptiveEZRunner(
                audit_logger=audit,
                case_id="CASE-EVTX-ADAPT",
                state_manager=state,
            )
            disk.init_tools(state, audit, ez_runner=runner)

            evidence_root = Path(tmp_dir) / "evidence"
            evtx_dir = evidence_root / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            default_result = disk.summarize_evtx(
                image_path=str(evidence_root),
                evtx_dir=str(evtx_dir),
            )
            self.assertEqual(default_result["event_id_strategy"], "default")
            self.assertIn(4688, runner.last_event_ids)

            state.add_finding(
                {
                    "case_id": "CASE-EVTX-ADAPT",
                    "finding_type": "other",
                    "artifact_type": "disk",
                    "artifact_path": str(evtx_dir / "Security.evtx"),
                    "tool_name": "disk.extract_registry_run_keys",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "ACTIVE",
                    "confidence": 0.9,
                    "description": "Credential access activity was observed.",
                    "mitre_tactic": "TA0006",
                    "mitre_technique": "T1003",
                }
            )

            adaptive_result = disk.summarize_evtx(
                image_path=str(evidence_root),
                evtx_dir=str(evtx_dir),
                start_date="2026-04-14",
            )
            self.assertEqual(adaptive_result["event_id_strategy"], "adaptive")
            self.assertIn(4663, runner.last_event_ids)

            explicit_result = disk.summarize_evtx(
                image_path=str(evidence_root),
                evtx_dir=str(evtx_dir),
                event_ids=[1, 11],
                end_date="2026-04-15",
            )
            self.assertEqual(explicit_result["event_id_strategy"], "explicit")
            self.assertEqual(runner.last_event_ids, [1, 11])

    def test_summarize_evtx_cache_hit_despite_growing_findings(self) -> None:
        """Repeated no-arg EVTX calls must cache-hit even when findings grow
        (which changes the adaptive EID set).  This is the Layer B evtx_started=30 fix.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-EVTX-IDEM")
            runner = FakeAdaptiveEZRunner(
                audit_logger=audit,
                case_id="CASE-EVTX-IDEM",
                state_manager=state,
            )
            disk.init_tools(state, audit, ez_runner=runner)

            evidence_root = Path(tmp_dir) / "evidence"
            evtx_dir = evidence_root / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                # Call 1: no findings → default EIDs
                first = disk.summarize_evtx(
                    image_path=str(evidence_root),
                    evtx_dir=str(evtx_dir),
                )
            self.assertFalse(first.get("cache_hit", False))

            # Add findings that change what adaptive_eids_from_findings returns
            state.add_finding({
                "case_id": "CASE-EVTX-IDEM",
                "finding_type": "other",
                "artifact_type": "disk",
                "artifact_path": str(evtx_dir / "Security.evtx"),
                "tool_name": "disk.extract_registry_run_keys",
                "execution_id": "E-001",
                "iteration": 1,
                "evidence_kind": "observation",
                "finding_status": "ACTIVE",
                "confidence": 0.9,
                "description": "Credential access.",
                "mitre_tactic": "TA0006",
                "mitre_technique": "T1003",
            })

            with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                # Call 2: findings exist → adaptive EIDs differ from call 1
                # But MUST be a cache hit (same base params, no explicit EIDs)
                second = disk.summarize_evtx(
                    image_path=str(evidence_root),
                    evtx_dir=str(evtx_dir),
                )

            self.assertTrue(second.get("cache_hit", False),
                            "Second no-arg EVTX call should be cache hit despite adaptive EID drift")
            # EvtxECmd subprocess should only have been called once
            evtx_run_count = sum(
                1 for line in Path(tmp_dir, "audit.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip() and '"event_type": "started"' in line
                and "disk.summarize_evtx" in line
                and "CACHE_HIT" not in line
            )
            # One real run + one cache-hit = we want only 1 real EvtxECmd start
            self.assertLessEqual(evtx_run_count, 2,
                                 f"Expected at most 2 audit started entries (1 real + 1 cache), got {evtx_run_count}")


if __name__ == "__main__":
    unittest.main()
