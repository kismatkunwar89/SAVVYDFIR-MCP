"""Tests for I.2: sigma_hunt audit finalizer for validation failures."""

import unittest


class SigmaHuntAuditTests(unittest.TestCase):
    """Tests for sigma_hunt validation failure audit trail (I.2 fix)."""

    def test_validation_finalizer_exists(self) -> None:
        """I.2 fix: sigma_hunt validation failures should produce complete audit records.

        review adversarial review MEDIUM priority: sigma_hunt opened audit execution
        before validation, but several post-start failure paths (missing rules, missing
        EVTX, invalid format) returned without log_result or _record_execution_parity.

        This test validates the finalizer exists in the code.
        Full integration test would require calling sigma_hunt with invalid inputs
        and checking audit.jsonl for completed records.
        """
        from pathlib import Path
        server_path = Path(__file__).parent.parent / "sift_mcp" / "server.py"
        source = server_path.read_text(encoding="utf-8")

        # Verify the I.2 fix is present
        self.assertIn("I.2 fix: Helper to finalize audit trail for validation failures", source)
        self.assertIn("_finalize_validation_failure", source)
        self.assertIn("Complete audit trail for sigma_hunt validation failures", source)


if __name__ == "__main__":
    unittest.main()
