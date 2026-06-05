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
            # peer reviewer provenance gate (A1): the finding's cited execution_id
            # must resolve to a real execution row before promotion to
            # CONFIRMED can survive validation. Record the audit row that
            # this finding will reference.
            manager.add_execution(
                {
                    "execution_id": "E-001",
                    "tool_name": "disk.extract_shimcache",
                    "event_type": "completed",
                    "iteration": 1,
                }
            )
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
                    # peer reviewer alternative-hypothesis gate (A2): the
                    # promotion path requires structured alt-hypothesis
                    # disposition to keep CONFIRMED status.
                    "alternative_hypothesis": "Legitimate user-installed utility from AppData",
                    "evidence_against_it": [
                        "evil.exe is not present in any vendor catalog",
                        "AppData\\Roaming is not a standard install location for trusted software",
                    ],
                    "disposition": "ruled_out",
                }
            )

            ipath = r"C:\Users\Alice\AppData\Roaming\evil.exe"
            # INTEGRITY FIX (2026-06-05): CONFIRMED carries weight — it requires
            # ALL of the FK class's corroboration sources cleared, not one. shimcache
            # requires [prefetch, amcache, evtx_process_creation]. Partial
            # corroboration keeps the finding ACTIVE (not promoted); only when the
            # LAST required source clears does it become CONFIRMED.
            # 1 of 3 -> still ACTIVE, NOT promoted
            self.assertEqual(promote_corroborated_findings(manager, "prefetch", [ipath]), [])
            self.assertEqual(manager.get_finding(finding_id)["finding_status"], "ACTIVE")
            # 2 of 3 -> still ACTIVE
            self.assertEqual(promote_corroborated_findings(manager, "amcache", [ipath]), [])
            self.assertEqual(manager.get_finding(finding_id)["finding_status"], "ACTIVE")
            # 3 of 3 (all required cleared) -> CONFIRMED
            promoted = promote_corroborated_findings(manager, "evtx_process_creation", [ipath])

            self.assertEqual(promoted, [finding_id])
            finding = manager.get_finding(finding_id)
            assert finding is not None
            self.assertEqual(finding["finding_status"], "CONFIRMED")
            self.assertEqual(finding.get("corroboration_outstanding"), [])
            for src in ("prefetch", "amcache", "evtx_process_creation"):
                self.assertIn(src, finding["corroborated_by"])
            # All 3 execution sources cleared -> definitive execution (1.0)
            self.assertAlmostEqual(finding["confidence"], 1.0, places=3)
            self.assertEqual(finding["promotion_eligibility"], "confirmed")
            self.assertIn("disk", finding["supporting_tool_families"])
            self.assertIn("disk", finding["supporting_artifact_families"])
            # completed_corroboration reflects the LAST corroboration event (the
            # one that cleared the final required source -> CONFIRMED).
            self.assertEqual(
                finding["confidence_support_inputs"]["completed_corroboration"],
                ["evtx_process_creation"],
            )


if __name__ == "__main__":
    unittest.main()
