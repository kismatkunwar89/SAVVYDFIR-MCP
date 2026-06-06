"""Regression tests for review adversarial review boundary fixes."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sift_mcp.state import CaseStateManager


class ReviewBoundaryTests(unittest.TestCase):
    """Tests for issues found in review adversarial review."""

    def test_corroboration_dispatch_atomic_write_then_claim(self) -> None:
        """review fix: delegate write must complete BEFORE flag claim.
        
        If delegate write fails, flag must NOT be claimed (allows retry).
        Original bug: claimed flag first, then wrote delegate. Transient
        write failures left flag claimed with no delegate file.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            state_mgr = CaseStateManager(str(state_path))
            state_mgr.load("CASE-ATOMIC-TEST")
            
            # Simulate successful dispatch flow
            from sift_mcp.server import _dispatch_corroboration_if_ready
            
            # Mock readiness: all prereq lanes complete
            state_mgr.upsert_analysis_lane("event_auth", status="COMPLETE", findings_added=3)
            state_mgr.upsert_analysis_lane("disk_auth", status="COMPLETE", findings_added=2)
            state_mgr.upsert_analysis_lane("memory_auth", status="COMPLETE", findings_added=1)
            
            delegate_path = Path(tmp_dir) / "delegate.json"
            os.environ["SAVVYDFIR_DELEGATE_PATH"] = str(delegate_path)
            
            try:
                # First call: should write delegate AND claim flag
                result = _dispatch_corroboration_if_ready("CASE-ATOMIC-TEST")
                self.assertTrue(result, "First dispatch should succeed")
                self.assertTrue(delegate_path.exists(), "Delegate file must exist after successful dispatch")

                # Verify flag was claimed
                state = state_mgr._state
                self.assertTrue(state["status_flags"].get("corroboration_dispatched"))

                # Second call: flag already claimed, should return False
                result2 = _dispatch_corroboration_if_ready("CASE-ATOMIC-TEST")
                self.assertFalse(result2, "Second dispatch should return False (already claimed)")
            finally:
                os.environ.pop("SAVVYDFIR_DELEGATE_PATH", None)

    def test_corroboration_dispatch_write_failure_no_claim(self) -> None:
        """review fix: if delegate write fails, flag must NOT be claimed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            state_mgr = CaseStateManager(str(state_path))
            state_mgr.load("CASE-WRITE-FAIL")
            
            from sift_mcp.server import _dispatch_corroboration_if_ready
            
            # Mock readiness
            state_mgr.upsert_analysis_lane("event_auth", status="COMPLETE", findings_added=1)
            state_mgr.upsert_analysis_lane("disk_auth", status="COMPLETE", findings_added=1)
            state_mgr.upsert_analysis_lane("memory_auth", status="COMPLETE", findings_added=1)
            
            # Point to unwritable directory to force failure
            unwritable = Path(tmp_dir) / "readonly"
            unwritable.mkdir()
            unwritable.chmod(0o444)  # read-only
            delegate_path = unwritable / "delegate.json"
            os.environ["SAVVYDFIR_DELEGATE_PATH"] = str(delegate_path)
            
            try:
                result = _dispatch_corroboration_if_ready("CASE-WRITE-FAIL")
                self.assertFalse(result, "Dispatch should return False on write failure")
                
                # Verify flag was NOT claimed (allows retry)
                state = state_mgr._state
                self.assertFalse(
                    state["status_flags"].get("corroboration_dispatched", False),
                    "Flag must NOT be claimed if delegate write failed"
                )
            finally:
                os.environ.pop("SAVVYDFIR_DELEGATE_PATH", None)
                unwritable.chmod(0o755)  # restore for cleanup

    def test_stop_hook_blocks_on_missing_audit_for_active_investigation(self) -> None:
        """review fix: Stop hook must block if audit.jsonl is missing for in-progress investigation."""
        import sys
        import io
        from contextlib import redirect_stdout

        # Import the stop hook module
        sys.path.insert(0, str(Path(__file__).parent.parent / ".claude" / "hooks"))
        import stop as stop_hook

        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)

            # Create state.json showing COMPLETE investigation with case_id and executions
            (analysis_dir / "state.json").write_text(
                json.dumps({
                    "case_id": "CASE-MISSING-AUDIT",
                    "status": "COMPLETE",
                    "executions": [{"execution_id": "E-001", "tool_name": "sigma_hunt"}],
                }),
                encoding="utf-8"
            )
            # DO NOT create audit.jsonl — this is the bug condition

            # Run stop hook with this analysis dir
            payload = {"stop_reason": "session_end"}
            stdout = io.StringIO()
            with patch.dict(os.environ, {"SAVVYDFIR_ANALYSIS_DIR": str(analysis_dir)}):
                with patch("sys.stdin", io.StringIO(json.dumps(payload))):
                    with redirect_stdout(stdout):
                        stop_hook.main()

            result = json.loads(stdout.getvalue())

            # Should BLOCK because audit.jsonl is missing
            self.assertEqual(result["decision"], "block", "Must block on missing audit.jsonl")
            self.assertIn("audit.jsonl not found", result["reason"], "Error must mention missing audit")

    # TODO: Add test for corroboration lane recording not rewriting delegate
    # Requires full server initialization with fastmcp, better tested via integration test


if __name__ == "__main__":
    unittest.main()
