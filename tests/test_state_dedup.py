import tempfile
import unittest
from pathlib import Path

from sift_mcp.state import CaseStateManager


def _finding_payload(*, description: str, timestamp_observed: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "case_id": "CASE-DEDUP",
        "finding_type": "persistence",
        "artifact_type": "disk",
        "artifact_path": r"C:\Users\Alice\AppData\Roaming\evil.exe",
        "tool_name": "disk.extract_registry_run_keys",
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "finding_status": "ACTIVE",
        "confidence": 0.9,
        "description": description,
        "mitre_technique": "T1547.001",
        "supporting_indicators": [r"C:\Users\Alice\AppData\Roaming\evil.exe"],
    }
    if timestamp_observed is not None:
        payload["timestamp_observed"] = timestamp_observed
    return payload


class StateDedupTests(unittest.TestCase):
    def test_same_semantic_finding_returns_same_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-DEDUP")

            first_id = manager.add_finding(
                _finding_payload(
                    description="Registry Run persistence points to evil.exe in AppData."
                )
            )
            second_id = manager.add_finding(
                _finding_payload(
                    description="Registry Run persistence points to evil.exe in AppData."
                )
            )

            self.assertEqual(first_id, second_id)
            self.assertEqual(len(manager.get_findings()), 1)

    def test_different_timestamp_or_description_creates_new_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-DEDUP-2")

            first_id = manager.add_finding(
                _finding_payload(
                    description="Registry Run persistence points to evil.exe in AppData."
                )
            )
            second_id = manager.add_finding(
                _finding_payload(
                    description="Registry Run persistence points to evil.exe in ProgramData."
                )
            )
            third_id = manager.add_finding(
                _finding_payload(
                    description="Registry Run persistence points to evil.exe in AppData.",
                    timestamp_observed="2026-04-14T12:00:00Z",
                )
            )

            self.assertNotEqual(first_id, second_id)
            self.assertNotEqual(first_id, third_id)
            self.assertEqual(len(manager.get_findings()), 3)

    def test_subtype_aliases_are_queryable_via_artifact_type_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-DEDUP-3")

            finding_id = manager.add_finding(
                {
                    "case_id": "CASE-DEDUP-3",
                    "finding_type": "threat_detection",
                    "artifact_type": "evtx",
                    "artifact_path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
                    "tool_name": "disk.summarize_evtx",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "evidence_kind": "DISK_ARTIFACT",
                    "finding_status": "ACTIVE",
                    "confidence": 0.8,
                    "description": "Security.evtx shows a suspicious process creation event.",
                    "supporting_indicators": ["EID 4688"],
                }
            )

            finding = manager.get_finding(finding_id)
            assert finding is not None
            self.assertEqual(finding["artifact_type"], "disk")
            self.assertEqual(finding["artifact_subtype"], "evtx")
            self.assertEqual(
                [item["finding_id"] for item in manager.get_findings(artifact_type="evtx")],
                [finding_id],
            )


if __name__ == "__main__":
    unittest.main()
