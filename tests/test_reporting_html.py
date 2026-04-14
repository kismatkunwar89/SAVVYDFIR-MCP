import json
import tempfile
import unittest
from pathlib import Path

from sift_mcp.reporting import generate_report_payload
from sift_mcp.state import CaseStateManager


class ReportingHtmlTests(unittest.TestCase):
    def test_generate_report_payload_writes_html_and_marks_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-REPORT-OK")
            manager.add_finding(
                {
                    "case_id": "CASE-REPORT-OK",
                    "finding_type": "persistence",
                    "artifact_type": "disk",
                    "artifact_path": r"C:\Users\Alice\AppData\Roaming\evil.exe",
                    "tool_name": "disk.extract_registry_run_keys",
                    "execution_id": "E-001",
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
            )

            self.assertEqual(result["status"], "ok")
            self.assertIn("coverage", result)
            self.assertIn("sigma_scan", result)
            report_path = Path(result["report_path"])
            self.assertTrue(report_path.exists())
            self.assertTrue(report_path.samefile(Path(tmp_dir) / "CASE-REPORT-OK" / "report.html"))

            html_text = report_path.read_text(encoding="utf-8")
            self.assertIn("Executive Summary", html_text)
            self.assertIn("ATT&amp;CK Coverage", html_text)
            self.assertIn("Sigma Anomaly Summary", html_text)
            self.assertIn("Top Findings", html_text)

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
            )

            self.assertEqual(result["status"], "error")
            self.assertIn("sigma_scan", result)
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["status"], "IN_PROGRESS")


if __name__ == "__main__":
    unittest.main()
