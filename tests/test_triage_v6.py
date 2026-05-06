import json
import tempfile
import unittest
from pathlib import Path

from sift_mcp.detectors import normalize_enabled_detectors, run_two_phase_scan
from sift_mcp.models.execution import Execution
from sift_mcp.models.finding import Finding
from sift_mcp.reporting import generate_report_payload
from sift_mcp.state import CaseStateManager


def _base_finding(**overrides):
    payload = {
        "case_id": "CASE-V6",
        "finding_type": "other",
        "artifact_type": "disk",
        "artifact_path": "artifact",
        "tool_name": "disk.extract_mft_timeline",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "finding_status": "active",
        "confidence": 0.8,
        "description": "A sufficiently detailed generic finding description.",
    }
    payload.update(overrides)
    return payload


class TriageV6Tests(unittest.TestCase):
    def test_models_do_not_allocate_ids(self):
        finding = Finding(**_base_finding())
        execution = Execution(
            case_id="CASE-V6",
            iteration=1,
            tool_name="disk.extract_mft_timeline",
            command_line="tool()",
        )
        self.assertIsNone(finding.finding_id)
        self.assertIsNone(execution.execution_id)

    def test_state_allocates_and_migrates_duplicate_finding_ids(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            legacy = {
                "case_id": "CASE-V6",
                "status": "IN_PROGRESS",
                "created_at": "2026-01-01T00:00:00.000Z",
                "updated_at": "2026-01-01T00:00:00.000Z",
                "_finding_counter": 1,
                "_execution_counter": 1,
                "findings": [
                    _base_finding(finding_id="F-001", description="First legacy duplicate finding."),
                    _base_finding(finding_id="F-001", description="Second legacy duplicate finding."),
                ],
                "executions": [],
                "open_questions": [],
                "findings_count": 2,
                "executions_count": 0,
            }
            state_path.write_text(json.dumps(legacy), encoding="utf-8")
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-V6")

            ids = [finding["finding_id"] for finding in manager.get_findings()]
            self.assertEqual(ids[0], "F-001")
            self.assertNotEqual(ids[0], ids[1])
            self.assertGreaterEqual(manager.to_summary()["findings_count"], 2)
            self.assertTrue(manager.to_summary()["migration_warnings"])

            new_id = manager.add_finding(_base_finding(description="Brand new semantic finding."))
            self.assertNotIn(new_id, ids)

    def test_enabled_detectors_semantics(self):
        self.assertIn("log_clear", normalize_enabled_detectors(None))
        self.assertEqual(normalize_enabled_detectors(["log_clear"]), {"log_clear"})
        with self.assertRaises(ValueError):
            normalize_enabled_detectors([])

    def test_pinned_correlators_and_structured_pivots(self):
        findings = [
            _base_finding(
                artifact_subtype="mft",
                description="MFT copied binary.",
                LastModified0x10="2026-01-01T00:00:00Z",
                Created0x30="2026-01-01T00:00:02Z",
                parent_reference="42",
                sequence_number=1,
            ),
            _base_finding(
                artifact_subtype="mft",
                description="Sibling one.",
                parent_reference="42",
                sequence_number=100,
            ),
            _base_finding(
                artifact_subtype="mft",
                description="Sibling two.",
                parent_reference="42",
                sequence_number=101,
            ),
            _base_finding(
                artifact_subtype="mft",
                description="Sibling three.",
                parent_reference="42",
                sequence_number=102,
            ),
            _base_finding(
                artifact_subtype="mft",
                description="Outlier sibling.",
                parent_reference="42",
                sequence_number=5000,
            ),
            _base_finding(
                artifact_subtype="evtx",
                description="Explicit credentials.",
                event_id=4648,
                timestamp_observed="2026-01-01T01:00:00Z",
                source_ip="10.0.0.5",
                user="alice",
            ),
            _base_finding(
                artifact_subtype="evtx",
                description="SMB share access.",
                event_id=5145,
                timestamp_observed="2026-01-01T01:00:30Z",
                source_ip="10.0.0.5",
                user="alice",
            ),
        ]
        result = run_two_phase_scan(findings)
        detectors = {hit.detector for hit in result["hits"]}
        self.assertIn("m_before_c_copy", detectors)
        self.assertIn("mft_sequence_anomaly", detectors)
        self.assertIn("explicit_logon_smb_correlation", detectors)
        self.assertTrue(all(isinstance(lead["next_pivot"], dict) for lead in result["actionable_leads"]))

    def test_report_json_and_gap_status(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-V6")
            result = generate_report_payload(
                case_id="CASE-V6",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok",
                    "total_hits": 1,
                    "critical_count": 1,
                    "high_count": 0,
                    "summary_markdown": "log clear",
                    "actionable_leads": [
                        {
                            "detector": "log_clear",
                            "severity": "CRITICAL",
                            "confidence": 0.95,
                            "description": "Security log cleared.",
                            "next_pivot": {
                                "tool": "detection.analyze_vss",
                                "args": {},
                                "human_readable": "Recover logs from VSS.",
                            },
                        }
                    ],
                    "anti_forensics_warnings": [{"detector": "log_clear", "description": "Security 1102"}],
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
            report_json = Path(result["report_json_path"])
            self.assertTrue(report_json.exists())
            payload = json.loads(report_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["triage_status"], "COMPLETE_WITH_GAPS")
            self.assertTrue(payload["status_flags"]["anti_forensics_warning"])


if __name__ == "__main__":
    unittest.main()
