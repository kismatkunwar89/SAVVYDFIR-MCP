import json
import tempfile
import unittest
from pathlib import Path

from sift_mcp.reporting import generate_report_payload
from sift_mcp.state import CaseStateManager

try:
    from ir_baseline import add_windows_ir_baseline_executions
except ModuleNotFoundError:
    from tests.ir_baseline import add_windows_ir_baseline_executions


class ReportingHtmlTests(unittest.TestCase):
    def test_generate_report_payload_writes_html_and_marks_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-REPORT-OK")
            add_windows_ir_baseline_executions(manager, "CASE-REPORT-OK")
            manager.add_finding(
                {
                    "case_id": "CASE-REPORT-OK",
                    "finding_type": "persistence",
                    "artifact_type": "disk",
                    "artifact_path": r"C:\Users\Alice\AppData\Roaming\evil.exe",
                    "tool_name": "disk.extract_registry_run_keys",
                    "execution_id": "E-006",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "ACTIVE",
                    "confidence": 0.9,
                    "description": "Registry Run persistence points to an AppData executable.",
                    "supporting_indicators": [
                        r"C:\Users\Alice\AppData\Roaming\evil.exe"
                    ],
                    "mitre_tactic": "TA0003",
                    "mitre_technique": "T1547.001",
                }
            )
            report_dir = Path(tmp_dir) / "CASE-REPORT-OK"
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "graph.json").write_text("{}", encoding="utf-8")

            result = generate_report_payload(
                case_id="CASE-REPORT-OK",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 3,
                    "critical_count": 1,
                    "high_count": 1,
                    "summary_markdown": "## Sigma summary",
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [{"id": "TA0003", "name": "Persistence"}],
                    "uncovered_tactics": [{"id": "TA0006", "name": "Credential Access"}],
                    "coverage_percent": 7.1,
                    "suggested_next_tools": {"TA0006": ["disk.summarize_evtx"]},
                },
                reports_root=tmp_dir,
                delegate_path=str(Path(tmp_dir) / "no_delegate.json"),
            )

            self.assertEqual(result["status"], "ok")
            self.assertIn("coverage", result)
            self.assertIn("sigma_scan", result)
            report_path = Path(result["report_path"])
            self.assertTrue(report_path.exists())
            self.assertTrue(report_path.samefile(Path(tmp_dir) / "CASE-REPORT-OK" / "report.html"))

            html_text = report_path.read_text(encoding="utf-8")
            self.assertIn("Executive Summary", html_text)
            self.assertIn("Analysis Lanes", html_text)
            self.assertIn("ATT&amp;CK Coverage", html_text)
            self.assertIn("Sigma Anomaly Summary", html_text)
            self.assertIn("Top Confirmed Findings", html_text)

            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["status"], "COMPLETE")

    def test_generate_report_payload_does_not_complete_case_on_sigma_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-REPORT-ERR")

            result = generate_report_payload(
                case_id="CASE-REPORT-ERR",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "error",
                    "error": "sigma engine unavailable",
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [],
                    "uncovered_tactics": [],
                    "coverage_percent": 0.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
                delegate_path=str(Path(tmp_dir) / "no_delegate.json"),
            )

            self.assertEqual(result["status"], "needs_graph")
            self.assertEqual(result["next_required_tool"], "generate_graph")
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["status"], "IN_PROGRESS")

    def test_generate_report_payload_refuses_pending_delegate_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-DELEGATE")
            delegate_path = Path(tmp_dir) / "delegate.json"
            delegate_path.write_text(
                json.dumps({"processed": False, "subagent_type": "sigma-analyst"}),
                encoding="utf-8",
            )

            result = generate_report_payload(
                case_id="CASE-DELEGATE",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {"status": "ok"},
                coverage_fn=lambda case_id: {"covered_tactics": [], "uncovered_tactics": []},
                reports_root=tmp_dir,
                delegate_path=str(delegate_path),
            )

            self.assertEqual(result["status"], "needs_delegate")
            self.assertEqual(result["next_required_tool"], "record_analysis_lane")
            self.assertFalse((Path(tmp_dir) / "CASE-DELEGATE" / "report.json").exists())

    def test_generate_report_payload_ignores_pending_delegate_for_other_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-ONE")
            delegate_path = Path(tmp_dir) / "delegate.json"
            delegate_path.write_text(
                json.dumps(
                    {
                        "processed": False,
                        "subagent_type": "evtx-analyst",
                        "case_id": "CASE-TWO",
                        "created_at": "2026-05-09T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )

            result = generate_report_payload(
                case_id="CASE-ONE",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {"status": "ok"},
                coverage_fn=lambda case_id: {"covered_tactics": [], "uncovered_tactics": []},
                reports_root=tmp_dir,
                delegate_path=str(delegate_path),
            )

            self.assertNotEqual(result["status"], "needs_delegate")

    def test_generate_report_payload_processes_stale_delegate_for_completed_lanes(self) -> None:
        lane_agents = {
            "memory": "memory-analyst",
            "event_auth": "evtx-analyst",
            "timeline_correlation": "mft-analyst",
            "disk_execution_persistence": "prefetch-analyst",
        }
        for lane_id, agent in lane_agents.items():
            with self.subTest(lane_id=lane_id), tempfile.TemporaryDirectory() as tmp_dir:
                state_path = Path(tmp_dir) / "state.json"
                manager = CaseStateManager(str(state_path))
                manager.load("CASE-DELEGATE-DONE")
                manager.upsert_analysis_lane(
                    lane_id,
                    status="COMPLETE",
                    assigned_agent=agent,
                    summary=f"{lane_id} lane complete.",
                )
                delegate_path = Path(tmp_dir) / "delegate.json"
                delegate_path.write_text(
                    json.dumps(
                        {
                            "processed": False,
                            "subagent_type": agent,
                            "lane_id": lane_id,
                            "case_id": "CASE-DELEGATE-DONE",
                        }
                    ),
                    encoding="utf-8",
                )

                result = generate_report_payload(
                    case_id="CASE-DELEGATE-DONE",
                    state_manager=manager,
                    sigma_scan_fn=lambda case_id: {"status": "ok"},
                    coverage_fn=lambda case_id: {"covered_tactics": [], "uncovered_tactics": []},
                    reports_root=tmp_dir,
                    delegate_path=str(delegate_path),
                )

                self.assertNotEqual(result["status"], "needs_delegate")
                payload = json.loads(delegate_path.read_text(encoding="utf-8"))
                self.assertTrue(payload["processed"])
                self.assertEqual(payload["processed_reason"], "lane_already_completed")

    def test_generate_report_payload_unresolved_count_matches_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-UNRESOLVED")
            add_windows_ir_baseline_executions(manager, "CASE-UNRESOLVED")
            manager.add_finding(
                {
                    "case_id": "CASE-UNRESOLVED",
                    "finding_type": "other",
                    "artifact_type": "memory",
                    "artifact_path": "/evidence/memory.raw",
                    "tool_name": "memory.list_processes",
                    "execution_id": "E-002",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "ACTIVE",
                    "confidence": 0.7,
                    "description": "Unresolved contradiction test finding.",
                    "contradicted_by": ["F-XYZ"],
                }
            )
            report_dir = Path(tmp_dir) / "CASE-UNRESOLVED"
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "graph.json").write_text("{}", encoding="utf-8")

            result = generate_report_payload(
                case_id="CASE-UNRESOLVED",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "none",
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [{"id": "TA0003", "name": "Persistence"}],
                    "uncovered_tactics": [],
                    "coverage_percent": 100.0,
                    "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
                delegate_path=str(Path(tmp_dir) / "no_delegate.json"),
            )

            self.assertEqual(result["status"], "ok")
            self.assertIn("unresolved_discrepancies", result)
            self.assertEqual(result["unresolved_count"], len(result["unresolved_discrepancies"]))


class HypothesisValidationRenderTests(unittest.TestCase):
    """Closes the hunting loop: the report surfaces each recorded hypothesis
    with its resolved verdict + linked findings (consensus 2026-05-30)."""

    def test_empty_renders_graceful_message(self) -> None:
        from sift_mcp.reporting import _render_hypothesis_validation
        html_out = _render_hypothesis_validation([])
        self.assertIn("No hunting hypotheses recorded", html_out)

    def test_verdicts_render_badges_and_linked_findings(self) -> None:
        from sift_mcp.reporting import _render_hypothesis_validation
        hyps = [
            {"hypothesis_id": "H-AAA", "attack_class": "rdp_intrusion", "rank": 1,
             "status": "CONFIRMED", "related_finding_ids": ["F-088", "F-089"],
             "mitre_techniques": ["T1021.001"]},
            {"hypothesis_id": "H-BBB", "attack_class": "insider_threat", "rank": 2,
             "status": "REFUTED", "related_finding_ids": []},
            {"hypothesis_id": "H-CCC", "attack_class": "malware", "rank": 3,
             "status": "SUSPENDED", "related_finding_ids": ["F-040"]},
            {"hypothesis_id": "H-DDD", "attack_class": "lateral", "rank": 4,
             "status": "ACTIVE", "related_finding_ids": []},
        ]
        html_out = _render_hypothesis_validation(hyps)
        # full id preserved, verdict labels present, linked findings rendered
        for token in ("H-AAA", "H-BBB", "H-CCC", "H-DDD",
                      "CONFIRMED — proven", "REFUTED — disproven",
                      "SUSPENDED — inconclusive", "ACTIVE — unresolved",
                      "F-088", "F-089", "F-040", "T1021.001"):
            self.assertIn(token, html_out)
        # verdict tag classes
        self.assertIn("tag covered", html_out)
        self.assertIn("tag refuted", html_out)
        self.assertIn("tag uncovered", html_out)
        self.assertIn("tag muted", html_out)

    def test_defensive_against_malformed_entries(self) -> None:
        from sift_mcp.reporting import _render_hypothesis_validation
        # non-list related_finding_ids / mitre, missing fields, a non-dict entry
        hyps = [
            "not-a-dict",
            {"hypothesis_id": "H-X", "status": "confirmed",
             "related_finding_ids": "F-001", "mitre_technique": "T1059"},
            {"hypothesis_id": "H-Y"},  # bare; defaults to ACTIVE
        ]
        html_out = _render_hypothesis_validation(hyps)  # must not raise
        self.assertIn("F-001", html_out)         # singleton string normalized
        self.assertIn("T1059", html_out)
        self.assertIn("CONFIRMED — proven", html_out)  # case-insensitive status
        self.assertIn("ACTIVE — unresolved", html_out)  # bare entry default

    def test_payload_includes_hypotheses_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-HYP-PAYLOAD")
            add_windows_ir_baseline_executions(manager, "CASE-HYP-PAYLOAD")
            report_dir = Path(tmp_dir) / "CASE-HYP-PAYLOAD"
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "graph.json").write_text("{}", encoding="utf-8")  # pass graph gate
            result = generate_report_payload(
                case_id="CASE-HYP-PAYLOAD",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {"status": "ok", "total_hits": 0,
                                               "critical_count": 0, "high_count": 0,
                                               "summary_markdown": "none"},
                coverage_fn=lambda case_id: {"covered_tactics": [], "uncovered_tactics": [],
                                             "coverage_percent": 0.0, "suggested_next_tools": {}},
                reports_root=tmp_dir,
                delegate_path=str(Path(tmp_dir) / "no_delegate.json"),
                allow_partial=True,  # bypass specialist-contribution gate to reach full payload
            )
            self.assertIn("hypotheses", result)
            self.assertIsInstance(result["hypotheses"], list)


if __name__ == "__main__":
    unittest.main()
