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
                      "CONFIRMED - proven", "REFUTED - disproven",
                      "SUSPENDED - inconclusive", "ACTIVE - unresolved",
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
        self.assertIn("CONFIRMED - proven", html_out)  # case-insensitive status
        self.assertIn("ACTIVE - unresolved", html_out)  # bare entry default

    def test_unresolved_counter(self) -> None:
        from sift_mcp.reporting import _count_unresolved_hypotheses
        hyps = [
            {"status": "CONFIRMED"}, {"status": "REFUTED"}, {"status": "SUSPENDED"},
            {"status": "ACTIVE"}, {"status": "INVESTIGATING"}, {}, "bad",
        ]
        # ACTIVE + INVESTIGATING + bare(default ACTIVE) = 3 unresolved; non-dict ignored
        self.assertEqual(_count_unresolved_hypotheses(hyps), 3)
        self.assertEqual(_count_unresolved_hypotheses([]), 0)
        self.assertEqual(
            _count_unresolved_hypotheses([{"status": "confirmed"}]), 0  # case-insensitive
        )

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


class ReportStructureRenderTests(unittest.TestCase):
    """Golden structure checks for the rebuilt render_report_html: executive-
    first layout, self-contained (no JS/CDN/Mermaid), color-coded sections, and
    deterministic narrative assembled from agent-authored fields."""

    def _payload(self) -> dict:
        return {
            "case_id": "CASE-STRUCT-1",
            "report_generated_at": "2026-05-31T00:00:00+00:00",
            "summary": {"status": "COMPLETE", "findings_count": 4,
                        "confirmed_count": 1, "unresolved_discrepancies": 2},
            "triage_status": "COMPLETE_WITH_GAPS",
            "status_breakdown": {"CONFIRMED": 1, "ACTIVE": 3},
            "sigma_scan": {"total_hits": 5, "critical_count": 0, "high_count": 2,
                           "summary_markdown": "2 HIGH anomalies"},
            "coverage": {"coverage_percent": 41.7,
                         "covered_tactics": [{"id": "TA0010", "name": "Exfiltration"}],
                         "uncovered_tactics": [{"id": "TA0001", "name": "Initial Access"}],
                         "suggested_next_tools": {"TA0001": ["extract_evtx"]}},
            "top_findings": [
                {"finding_id": "F-001", "finding_status": "CONFIRMED", "confidence": 0.95,
                 "mitre_tactic": "TA0010", "mitre_technique": "T1041",
                 "description": "Exfiltration over C2 channel observed in SRUM and memory.",
                 "corroborated_by": ["F-004", "F-005"], "timestamp_observed": None,
                 "supporting_indicators": ["10.0.0.9 (peer)", "evil.exe C:\\\\Temp\\\\evil.exe"]},
                {"finding_id": "F-002", "finding_status": "ACTIVE", "confidence": 0.6,
                 "mitre_tactic": "TA0010", "mitre_technique": "T1048",
                 "description": "Possible secondary channel.", "corroborated_by": [],
                 "timestamp_observed": None, "supporting_indicators": ["TCP :8080"]},
            ],
            "top_confirmed_findings": [
                {"finding_id": "F-001", "finding_status": "CONFIRMED", "confidence": 0.95,
                 "mitre_tactic": "TA0010", "mitre_technique": "T1041",
                 "description": "Exfiltration over C2 channel observed in SRUM and memory.",
                 "corroborated_by": ["F-004", "F-005"],
                 "supporting_indicators": ["10.0.0.9 (peer)"]},
            ],
            "actionable_leads": [], "anti_forensics_warnings": [], "data_gaps": [],
            "analysis_lanes": [{"lane_id": "synthesis_corroboration", "status": "COMPLETE",
                                "summary": "Phase 6 synthesis confirmed 1 exfil finding."}],
            "orchestration_warnings": [], "open_questions": [], "hypotheses": [],
            "status_flags": {}, "evidence_kind_breakdown": {},
        }

    def test_structure_and_self_contained(self) -> None:
        from sift_mcp.reporting import render_report_html
        out = render_report_html(self._payload())
        # self-contained: no scripts, no CDN, no Mermaid, no dark gradient
        self.assertNotIn("<script", out)
        self.assertNotIn("cdn.jsdelivr", out)
        self.assertNotIn("graph LR", out)
        self.assertNotIn('class="mermaid"', out)
        self.assertNotIn("radial-gradient", out)
        # new components present
        self.assertIn('id="executive-brief"', out)
        self.assertIn('class="killchain"', out)
        self.assertIn("Indicators of Compromise", out)
        self.assertIn("Technical Appendix", out)
        self.assertIn('class="finding"', out)
        self.assertIn("@media print", out)
        # narrative is assembled from agent findings, not a bare count line
        self.assertIn("structurally confirmed finding", out)
        self.assertIn("F-001", out)

    def test_executive_first_ordering(self) -> None:
        from sift_mcp.reporting import render_report_html
        out = render_report_html(self._payload())
        i_exec = out.find('id="executive-brief"')
        i_appendix = out.find("Technical Appendix")
        i_sigma = out.find("Sigma Anomaly Summary")
        self.assertTrue(0 < i_exec < i_appendix, "exec brief must precede appendix")
        self.assertTrue(i_appendix < i_sigma, "Sigma summary must be inside the appendix")

    def test_zero_confirmed_branch(self) -> None:
        from sift_mcp.reporting import render_report_html, _render_executive_summary
        p = self._payload()
        p["status_breakdown"] = {"ACTIVE": 4}
        p["summary"]["confirmed_count"] = 0
        p["top_confirmed_findings"] = []
        narrative = _render_executive_summary(p)
        self.assertIn("No structurally confirmed findings", narrative)
        # must not raise and must render full document
        self.assertIn("Executive Summary", render_report_html(p))

    def test_indicator_classifier_conservative(self) -> None:
        from sift_mcp.reporting import _classify_indicator
        self.assertEqual(_classify_indicator("10.0.0.9 (peer)"), "ip")
        self.assertEqual(_classify_indicator("evil.exe C:\\Temp\\evil.exe"), "path/file")
        self.assertEqual(_classify_indicator("TCP :8080 controller"), "port")
        self.assertEqual(_classify_indicator("something opaque"), "indicator")
        # invalid IPv4 octets and out-of-range ports must degrade to neutral
        self.assertEqual(_classify_indicator("999.999.999.999"), "indicator")
        self.assertEqual(_classify_indicator("TCP :99999"), "indicator")
        self.assertEqual(_classify_indicator("256.1.1.1 host"), "indicator")

    def test_exec_summary_no_overstated_corroboration(self) -> None:
        """A CONFIRMED finding with empty corroborated_by must not yield a
        report-level claim of multi-source corroboration (peer reviewer adversarial)."""
        from sift_mcp.reporting import _render_executive_summary
        p = self._payload()
        p["status_breakdown"] = {"CONFIRMED": 1, "ACTIVE": 1}
        p["top_confirmed_findings"] = [
            {"finding_id": "F-001", "finding_status": "CONFIRMED", "confidence": 0.9,
             "description": "single-source confirmed item", "corroborated_by": []},
        ]
        out = _render_executive_summary(p)
        self.assertNotIn("multiple independent artifact sources", out)
        self.assertIn("without recorded multi-source corroboration", out)
        # with >=2 corroborators the multi-source claim is permitted
        p["top_confirmed_findings"][0]["corroborated_by"] = ["F-2", "F-3"]
        out2 = _render_executive_summary(p)
        self.assertIn("corroborated by multiple independent artifact sources", out2)

    def test_no_template_emdash_only_evidence(self) -> None:
        """Template prose has no em-dashes; evidence-derived text keeps them."""
        from sift_mcp.reporting import render_report_html
        p = self._payload()
        p["top_findings"][0]["supporting_indicators"] = ["1.2.3.4 (host - evidence)"]
        out = render_report_html(p)
        # the only em-dash, if any, must be inside evidence content, never a heading
        import re as _re
        for m in _re.finditer("—", out):
            seg = out[max(0, m.start() - 100):m.start()]
            tag = seg[seg.rfind("<"):]
            self.assertFalse(
                any(x in tag for x in ("<h2", "<th", "<title", 'class="k"')),
                f"template-label em-dash near: {tag}",
            )


if __name__ == "__main__":
    unittest.main()
