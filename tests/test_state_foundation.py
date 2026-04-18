import json
import tempfile
import unittest
from pathlib import Path

from sift_mcp.state import CaseStateManager


class StateFoundationTests(unittest.TestCase):
    def test_load_migrates_legacy_finding_status_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            legacy_state = {
                "case_id": "CASE-001",
                "status": "IN_PROGRESS",
                "created_at": "2026-04-14T00:00:00.000Z",
                "updated_at": "2026-04-14T00:00:00.000Z",
                "_finding_counter": 4,
                "_execution_counter": 0,
                "findings": [
                    {
                        "finding_id": "F-001",
                        "artifact_type": "disk",
                        "evidence_kind": "OBSERVATION",
                        "status": "CONFIRMED",
                    },
                    {
                        "finding_id": "F-002",
                        "artifact_type": "memory",
                        "evidence_kind": "HYPOTHESIS",
                        "contradicted_by": ["F-001"],
                    },
                    {
                        "finding_id": "F-003",
                        "artifact_type": "memory",
                        "evidence_kind": "OBSERVATION",
                        "status": "",
                    },
                    {
                        "finding_id": "F-004",
                        "artifact_type": "memory",
                        "evidence_kind": "OBSERVATION",
                        "status": "REJECTED",
                        "contradicted_by": ["F-001"],
                    },
                ],
                "executions": [],
                "open_questions": [],
                "findings_count": 4,
                "executions_count": 0,
            }
            state_path.write_text(json.dumps(legacy_state), encoding="utf-8")

            manager = CaseStateManager(str(state_path))
            loaded = manager.load("CASE-001")

            self.assertIn("cached_artifacts", loaded)

            findings = manager.get_findings()
            self.assertEqual(
                [f["finding_status"] for f in findings],
                ["CONFIRMED", "ACTIVE", "ACTIVE", "REJECTED"],
            )
            self.assertTrue(all("status" not in finding for finding in findings))
            self.assertEqual(findings[1]["evidence_kind"], "hypothesis")
            self.assertEqual(findings[0]["tool_name"], "legacy.migrated")
            self.assertEqual(findings[0]["execution_id"], "E-000")
            self.assertIn("supporting_tool_families", findings[0])
            self.assertIn("confidence_support_inputs", findings[0])

            self.assertEqual(
                [f["finding_id"] for f in manager.get_findings(finding_status="confirmed")],
                ["F-001"],
            )
            self.assertEqual(
                [f["finding_id"] for f in manager.get_findings(status="rejected")],
                ["F-004"],
            )

            unresolved = manager.get_unresolved_discrepancies()
            self.assertEqual([f["finding_id"] for f in unresolved], ["F-002"])

            summary = manager.to_summary()
            self.assertEqual(summary["confirmed_count"], 1)
            self.assertEqual(summary["hypothesis_count"], 1)
            self.assertEqual(summary["rejected_count"], 1)
            self.assertEqual(summary["unresolved_discrepancies"], 1)

    def test_cache_artifact_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-002")

            manager.cache_artifact(
                "disk.summarize_evtx:security",
                {
                    "execution_id": "E-001",
                    "csv_path": "./analysis/CASE-002/evtx/security.csv",
                },
            )

            cached = manager.get_artifact_cache("disk.summarize_evtx:security")
            self.assertIsNotNone(cached)
            self.assertEqual(cached["execution_id"], "E-001")
            self.assertEqual(cached["csv_path"], "./analysis/CASE-002/evtx/security.csv")
            self.assertIn("timestamp", cached)


if __name__ == "__main__":
    unittest.main()
