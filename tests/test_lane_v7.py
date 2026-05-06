import tempfile
import unittest
from pathlib import Path

from sift_mcp.reporting import (
    EXPECTED_LANE_AGENTS,
    classify_missing_artifact_record,
    generate_report_payload,
)
from sift_mcp.state import CaseStateManager


class LaneV7Tests(unittest.TestCase):
    def test_expected_lane_agents_cover_all_configured_specialists(self) -> None:
        expected_agents = {
            agent
            for agents in EXPECTED_LANE_AGENTS.values()
            for agent in agents
        }
        for required_agent in {
            "amcache-analyst",
            "browser-analyst",
            "corroboration-analyst",
            "evtx-analyst",
            "memory-analyst",
            "mft-analyst",
            "prefetch-analyst",
            "registry-analyst",
            "sigma-analyst",
            "srum-analyst",
            "timeline-analyst",
        }:
            self.assertIn(required_agent, expected_agents)

    def test_classify_missing_artifact_splits_empty_from_wiped(self) -> None:
        empty = classify_missing_artifact_record(
            artifact_family="Security.evtx",
            is_mandatory=True,
            exists=True,
            parser_succeeded=True,
            record_count=0,
            file_size_bytes=68 * 1024,
            corroborating_signals=[],
            lane_id="event_auth",
        )
        wiped = classify_missing_artifact_record(
            artifact_family="Security.evtx",
            is_mandatory=True,
            exists=True,
            parser_succeeded=True,
            record_count=0,
            file_size_bytes=68 * 1024,
            corroborating_signals=["event:1102"],
            lane_id="event_auth",
        )
        self.assertEqual(empty["classification"], "empty")
        self.assertEqual(wiped["classification"], "wiped")

    def test_legacy_lane_synthesis_supports_bare_tool_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V7-LEGACY")
            manager.add_execution(
                {
                    "case_id": "CASE-V7-LEGACY",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "disk.analyze_vss",
                    "command_line": "analyze_vss()",
                }
            )
            manager.add_finding(
                {
                    "case_id": "CASE-V7-LEGACY",
                    "finding_type": "anti_forensics_recovery",
                    "artifact_type": "disk",
                    "artifact_path": "/evidence/disk/image.E01",
                    "tool_name": "analyze_vss",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "ACTIVE",
                    "confidence": 0.9,
                    "description": "Shadow copies exist but structured log classification is still missing.",
                }
            )

            result = generate_report_payload(
                case_id="CASE-V7-LEGACY",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            anti_lane = next(
                lane for lane in result["analysis_lanes"]
                if lane["lane_id"] == "anti_forensics_recovery"
            )
            self.assertTrue(anti_lane["legacy_inferred"])
            self.assertIn("E-001", anti_lane["execution_ids"])
            self.assertTrue(anti_lane["finding_ids"])
            self.assertEqual(result["triage_status"], "COMPLETE_WITH_GAPS")
            self.assertFalse(result["status_flags"]["anti_forensics_warning"])
            self.assertTrue(result["data_gaps"])

    def test_required_pending_lanes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V7-PENDING")
            for lane_id in (
                "memory",
                "disk_execution_persistence",
                "event_auth",
                "anti_forensics_recovery",
                "timeline_correlation",
            ):
                manager.upsert_analysis_lane(lane_id, status="PENDING", required=True)

            result = generate_report_payload(
                case_id="CASE-V7-PENDING",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            self.assertEqual(result["triage_status"], "COMPLETE_WITH_GAPS")
            self.assertTrue(any(lane["status"] == "FAILED" for lane in result["analysis_lanes"] if lane["required"]))

    def test_subagent_lane_with_hallucinated_ids_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V7-SUBAGENT")
            manager.upsert_analysis_lane(
                "memory",
                status="COMPLETE",
                required=True,
                assigned_agent="memory-analyst",
                execution_ids=["E-999"],
                finding_ids=["F-999"],
            )

            result = generate_report_payload(
                case_id="CASE-V7-SUBAGENT",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            memory_lane = next(
                lane for lane in result["analysis_lanes"]
                if lane["lane_id"] == "memory"
            )
            self.assertEqual(memory_lane["status"], "FAILED")
            self.assertEqual(result["triage_status"], "COMPLETE_WITH_GAPS")
            self.assertTrue(
                any(
                    gap["classification"] == "subagent_return_invalid"
                    for gap in result["data_gaps"]
                )
            )

    def test_report_warns_on_inferred_only_specialist_lanes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V7-INFERRED")
            manager.add_execution(
                {
                    "case_id": "CASE-V7-INFERRED",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "memory.list_processes",
                    "command_line": "list_processes()",
                }
            )

            result = generate_report_payload(
                case_id="CASE-V7-INFERRED",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            warnings = result["orchestration_warnings"]
            self.assertTrue(
                any(
                    warning["type"] == "specialist_lane_not_recorded"
                    and warning["lane_id"] == "memory"
                    for warning in warnings
                )
            )

    def test_inferred_specialist_lane_blocks_triage_complete(self) -> None:
        """v7.1 hard gate: a required lane with executions but no owning agent
        must force COMPLETE_WITH_GAPS, surface specialist_lanes_inferred=True,
        and emit a lane_not_owned_by_subagent data gap.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V71-GATE")
            manager.add_execution(
                {
                    "case_id": "CASE-V71-GATE",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "memory.list_processes",
                    "command_line": "list_processes()",
                }
            )

            result = generate_report_payload(
                case_id="CASE-V71-GATE",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            self.assertEqual(result["triage_status"], "COMPLETE_WITH_GAPS")
            self.assertTrue(result["status_flags"]["specialist_lanes_inferred"])
            self.assertTrue(
                any(
                    gap.get("classification") == "lane_not_owned_by_subagent"
                    and gap.get("lane_id") == "memory"
                    for gap in result["data_gaps"]
                ),
                f"Expected lane_not_owned_by_subagent gap; got {result['data_gaps']!r}",
            )

    def test_owned_specialist_lane_can_still_complete(self) -> None:
        """Regression: a lane that IS owned by a specialist must not trigger
        the new gate, and triage_status must remain TRIAGE_COMPLETE when no
        other gap signals exist.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V71-OK")
            report_dir = Path(tmp_dir) / "CASE-V71-OK"
            report_dir.mkdir(parents=True)
            (report_dir / "graph.html").write_text("<html>graph</html>", encoding="utf-8")
            manager.add_execution(
                {
                    "case_id": "CASE-V71-OK",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "memory.list_processes",
                    "command_line": "list_processes()",
                }
            )
            finding_id = manager.add_finding(
                {
                    "case_id": "CASE-V71-OK",
                    "finding_type": "memory_anomaly",
                    "artifact_type": "memory",
                    "artifact_path": "/evidence/memory/dump.raw",
                    "tool_name": "memory.list_processes",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "CONFIRMED",
                    "confidence": 0.9,
                    "description": "Owned by memory-analyst.",
                }
            )
            for lane_id, agent in (
                ("memory", "memory-analyst"),
                ("disk_execution_persistence", "main-agent"),
                ("event_auth", "main-agent"),
                ("anti_forensics_recovery", "main-agent"),
                ("timeline_correlation", "main-agent"),
            ):
                manager.upsert_analysis_lane(
                    lane_id,
                    status="COMPLETE",
                    required=True,
                    assigned_agent=agent,
                    execution_ids=["E-001"] if lane_id == "memory" else [],
                    finding_ids=[finding_id] if lane_id == "memory" else [],
                )

            result = generate_report_payload(
                case_id="CASE-V71-OK",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            self.assertEqual(result["triage_status"], "TRIAGE_COMPLETE")
            self.assertEqual(result["finding_quality_summary"]["raw_persisted_findings"], 1)
            self.assertEqual(result["finding_quality_summary"]["reportable_findings"], 1)
            self.assertIn("not a de-duplicated incident count", result["finding_quality_summary"]["semantics"])
            self.assertFalse(result["status_flags"]["specialist_lanes_inferred"])
            self.assertFalse(
                any(
                    gap.get("classification") == "lane_not_owned_by_subagent"
                    for gap in result["data_gaps"]
                )
            )


if __name__ == "__main__":
    unittest.main()
