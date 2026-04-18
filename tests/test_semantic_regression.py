import tempfile
import unittest
from pathlib import Path

from sift_mcp.semantics import normalize_finding_for_storage, promote_corroborated_findings
from sift_mcp.state import CaseStateManager


def _base_finding(*, tool_name: str, description: str, artifact_path: str, confidence: float = 0.9):
    return {
        "case_id": "CASE-SEM",
        "finding_type": "other",
        "artifact_type": "disk",
        "artifact_path": artifact_path,
        "tool_name": tool_name,
        "execution_id": "E-001",
        "iteration": 1,
        "evidence_kind": "observation",
        "finding_status": "ACTIVE",
        "confidence": confidence,
        "description": description,
        "supporting_indicators": [artifact_path],
    }


class SemanticRegressionTests(unittest.TestCase):
    def test_fk_confidence_multipliers_are_deterministic(self) -> None:
        cases = [
            ("disk.extract_shimcache", "ShimCache indicates execution.", r"C:\Temp\evil.exe", 0.63),
            ("disk.get_amcache", "Amcache captured a suspicious hash.", r"C:\Temp\evil.exe", 0.675),
            ("disk.extract_prefetch", "Prefetch confirms execution history.", r"C:\Windows\Prefetch\EVIL.EXE-1234ABCD.pf", 0.9),
            ("disk.extract_registry_run_keys", "Registry Run key references startup malware.", r"HKCU\\...\\Run", 0.765),
            ("disk.summarize_evtx", "Security event 4688 process creation for evil.exe.", r"C:\Windows\System32\winevt\Logs\Security.evtx", 0.9),
        ]
        for tool_name, description, artifact_path, expected in cases:
            with self.subTest(tool_name=tool_name):
                finding = normalize_finding_for_storage(
                    _base_finding(
                        tool_name=tool_name,
                        description=description,
                        artifact_path=artifact_path,
                    )
                )
                self.assertAlmostEqual(finding["confidence"], expected, places=3)
                self.assertIn("content_key", finding)
                self.assertIn("supporting_tool_families", finding)
                self.assertIn("supporting_artifact_families", finding)
                self.assertIn("confidence_support_inputs", finding)

    def test_catalog_backed_family_derivation_adds_secondary_artifact_context(self) -> None:
        cases = [
            ("disk.get_amcache", r"C:\Temp\evil.exe", {"disk", "registry", "file_system"}),
            ("memory.scan_network", r"memory.raw", {"memory", "network"}),
        ]
        for tool_name, artifact_path, expected_families in cases:
            with self.subTest(tool_name=tool_name):
                finding = normalize_finding_for_storage(
                    _base_finding(
                        tool_name=tool_name,
                        description="Catalog-backed family derivation test.",
                        artifact_path=artifact_path,
                    )
                )
                self.assertTrue(
                    expected_families.issubset(set(finding["supporting_artifact_families"]))
                )

    def test_corroboration_promotion_upgrades_active_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            manager.load("CASE-SEM-PROMOTE")
            finding_id = manager.add_finding(
                {
                    "case_id": "CASE-SEM-PROMOTE",
                    "finding_type": "other",
                    "artifact_type": "disk",
                    "artifact_path": r"C:\Users\Alice\AppData\Roaming\evil.exe",
                    "tool_name": "disk.extract_shimcache",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "ACTIVE",
                    "confidence": 0.9,
                    "description": "ShimCache shows execution of evil.exe from AppData.",
                    "supporting_indicators": [r"C:\Users\Alice\AppData\Roaming\evil.exe"],
                }
            )

            promoted = promote_corroborated_findings(
                manager,
                "prefetch",
                [r"C:\Users\Alice\AppData\Roaming\evil.exe"],
            )

            self.assertEqual(promoted, [finding_id])
            finding = manager.get_finding(finding_id)
            assert finding is not None
            self.assertEqual(finding["finding_status"], "CONFIRMED")
            self.assertIn("prefetch", finding["corroborated_by"])
            self.assertEqual(finding["corroboration_completed_by"], "prefetch")
            self.assertAlmostEqual(finding["confidence"], 0.78, places=3)
            self.assertEqual(finding["promotion_eligibility"], "confirmed")
            self.assertIn("disk", finding["supporting_tool_families"])
            self.assertIn("disk", finding["supporting_artifact_families"])
            self.assertEqual(
                finding["confidence_support_inputs"]["completed_corroboration"],
                ["prefetch"],
            )


if __name__ == "__main__":
    unittest.main()
