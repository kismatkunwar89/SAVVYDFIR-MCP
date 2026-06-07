"""Wave 3 (3a) tests for the retry-required lane-completion guard.

A parser staging failure (status=error + needs_extract_windows_artifacts=true) is
a RETRYABLE signal, not a terminal gap. Before Wave 3 an agent could falsely close
the lane as COMPLETE_WITH_GAPS ("extraction failed"). These tests pin:

  T1  bug-blocked       - a persisted retry_required execution with no later
                          successful re-run blocks lane completion; lane unchanged.
  T2  terminal-gap-ok   - a successful extraction + a USN-rollover-style data_gap
                          (NO retry_state) is still accepted COMPLETE_WITH_GAPS
                          (the CORE-FLOW-SAFETY invariant).
  T3  retry-then-close  - E-fail -> extract_windows_artifacts -> E-retry (parser
                          exit 0, csv_path) -> lane completion accepted.
  T5  persistence       - driving the mft error+needs_extract path yields a
                          response with execution_id and the stored execution
                          carries retry_state.retry_required True.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from test_mcp_retrieval import _load_server_for_test
except ModuleNotFoundError:
    from tests.test_mcp_retrieval import _load_server_for_test


def _retry_execution(execution_id, parser_tool="disk.extract_mft_timeline",
                     artifact_family="mft", case_id="CASE-RETRY"):
    return {
        "case_id": case_id,
        "execution_id": execution_id,
        "iteration": 1,
        "tool_name": parser_tool,
        "command_line": f"{parser_tool}() -> retry_required",
        "exit_code": 1,
        "retry_state": {
            "retry_required": True,
            "recovery_tool": "extract_windows_artifacts",
            "required_tool_name": "disk.extract_windows_artifacts",
            "artifact_family": artifact_family,
            "parser_tool": parser_tool,
            "input_name": "mft_path",
            "input_path": "/tmp/$MFT",
        },
    }


class RetryRequiredLaneGuardTests(unittest.TestCase):
    # -- T1 -----------------------------------------------------------------
    def test_t1_retry_required_blocks_lane_completion_and_leaves_lane_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-RETRY")
            server._state_manager.add_execution(_retry_execution("E-001"))

            lanes_before = server._state_manager.get_analysis_lanes()

            for status in ("COMPLETE", "COMPLETE_WITH_GAPS"):
                result = server.record_analysis_lane(
                    case_id="CASE-RETRY",
                    lane_id="timeline_correlation",
                    status=status,
                    assigned_agent="main-agent",
                    execution_ids=["E-001"],
                    finding_ids=[],
                    summary="Attempted closure on a retryable parser failure.",
                )

                self.assertEqual(result["status"], "error")
                self.assertEqual(result["error"], "retry_required_execution_unresolved")
                self.assertTrue(result["lane_completion_blocked"])
                self.assertTrue(result["retry_required"])
                self.assertIn("E-001", result["blocking_execution_ids"])
                self.assertIn("mft", result["artifact_families"])
                self.assertEqual(result["next_required_tool"], "extract_windows_artifacts")
                self.assertEqual(result["required_tool_name"], "disk.extract_windows_artifacts")
                self.assertIn("disk.extract_mft_timeline", result["retry_parser_tools"])
                self.assertNotIn("status_downgrade_required", result)

            # Lane must remain UNCHANGED (the reject must not upsert it).
            lanes_after = server._state_manager.get_analysis_lanes()
            self.assertEqual(lanes_before, lanes_after)
            self.assertNotIn(
                "timeline_correlation",
                {lane.get("lane_id") for lane in lanes_after if isinstance(lane, dict)},
            )

    def test_t1b_omitting_bad_eid_still_blocked_via_lane_sweep(self) -> None:
        # The guard sweeps lane-family executions, so dropping the failed E-id
        # from execution_ids cannot bypass it.
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-RETRY")
            server._state_manager.add_execution(_retry_execution("E-001"))

            result = server.record_analysis_lane(
                case_id="CASE-RETRY",
                lane_id="timeline_correlation",
                status="COMPLETE_WITH_GAPS",
                assigned_agent="main-agent",
                execution_ids=[],  # bad E-id omitted on purpose
                finding_ids=[],
                summary="Tried to bypass by omitting the failed execution id.",
            )

            self.assertEqual(result["status"], "error")
            self.assertEqual(result["error"], "retry_required_execution_unresolved")
            self.assertIn("E-001", result["blocking_execution_ids"])

    # -- T2 -----------------------------------------------------------------
    def test_t2_terminal_usn_rollover_gap_without_retry_state_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-RETRY")
            # A genuine SUCCESSFUL extraction - exit 0, NO retry_state.
            server._state_manager.add_execution(
                {
                    "case_id": "CASE-RETRY",
                    "execution_id": "E-005",
                    "iteration": 1,
                    "tool_name": "disk.extract_mft_timeline",
                    "command_line": "extract_mft_timeline()",
                    "exit_code": 0,
                    "outputs_summary": "rows=12345 csv=/cases/CASE-RETRY/mft.csv",
                }
            )

            result = server.record_analysis_lane(
                case_id="CASE-RETRY",
                lane_id="timeline_correlation",
                status="COMPLETE_WITH_GAPS",
                assigned_agent="main-agent",
                execution_ids=["E-005"],
                finding_ids=[],
                data_gaps=[
                    {
                        "artifact_family": "usn",
                        "classification": "time_window_exhausted",
                        "reason": (
                            "USN Journal rolled over before the incident window; "
                            "earliest retained record post-dates the attack."
                        ),
                    }
                ],
                summary="Timeline lane closed with a documented USN rollover gap.",
            )

            self.assertNotEqual(result["status"], "error")
            self.assertEqual(result["lane"]["lane_id"], "timeline_correlation")
            self.assertEqual(result["lane"]["status"], "COMPLETE_WITH_GAPS")

    # -- T3 -----------------------------------------------------------------
    def test_t3_retry_then_successful_rerun_allows_lane_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-RETRY")
            # Original failure.
            server._state_manager.add_execution(_retry_execution("E-001"))
            # Recovery: extract_windows_artifacts.
            server._state_manager.add_execution(
                {
                    "case_id": "CASE-RETRY",
                    "execution_id": "E-002",
                    "iteration": 1,
                    "tool_name": "disk.extract_windows_artifacts",
                    "command_line": "extract_windows_artifacts()",
                    "exit_code": 0,
                }
            )
            # Re-run of the SAME parser, now succeeding (exit 0, csv produced,
            # NO retry_state).
            server._state_manager.add_execution(
                {
                    "case_id": "CASE-RETRY",
                    "execution_id": "E-003",
                    "iteration": 1,
                    "tool_name": "disk.extract_mft_timeline",
                    "command_line": "extract_mft_timeline(mft_path=/cases/.../raw/mft/$MFT)",
                    "exit_code": 0,
                    "outputs_summary": "rows=4242 csv=/cases/CASE-RETRY/mft.csv",
                }
            )

            result = server.record_analysis_lane(
                case_id="CASE-RETRY",
                lane_id="timeline_correlation",
                status="COMPLETE_WITH_GAPS",
                assigned_agent="main-agent",
                execution_ids=["E-001", "E-002", "E-003"],
                finding_ids=[],
                summary="Parser re-run after staging recovery; lane closed.",
            )

            self.assertNotEqual(result["status"], "error")
            self.assertEqual(result["lane"]["lane_id"], "timeline_correlation")
            self.assertIn(result["lane"]["status"], {"COMPLETE", "COMPLETE_WITH_GAPS"})

    # -- T5 -----------------------------------------------------------------
    def test_t5_mft_needs_extract_error_persists_retry_state_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-RETRY")

            error_payload = {
                "tool_name": "extract_mft_timeline",
                "status": "error",
                "error_message": "Resolved mft_path does not exist: /tmp/$MFT.",
                "data": [],
                "findings_created": [],
                "execution_id": None,
                "input_name": "mft_path",
                "resolved_path": "/tmp/$MFT",
                "image_path": "/evidence/disk/image.E01",
                "needs_extract_windows_artifacts": True,
            }

            with mock.patch.object(server, "_extract_mft_timeline", return_value=dict(error_payload)):
                response = server.extract_mft_timeline(
                    image_path="/evidence/disk/image.E01",
                    case_id="CASE-RETRY",
                )

            self.assertEqual(response["status"], "error")
            self.assertTrue(response.get("needs_extract_windows_artifacts"))
            eid = response.get("execution_id")
            self.assertTrue(eid, "needs_extract error must carry a persisted execution_id")

            stored = server._state_manager.get_execution(eid)
            self.assertIsNotNone(stored)
            self.assertIsInstance(stored.get("retry_state"), dict)
            self.assertTrue(stored["retry_state"]["retry_required"])
            self.assertEqual(stored["retry_state"]["artifact_family"], "mft")
            self.assertEqual(stored["retry_state"]["parser_tool"], "disk.extract_mft_timeline")
            self.assertEqual(stored["retry_state"]["recovery_tool"], "extract_windows_artifacts")

            # And the persisted retry now blocks lane completion (end-to-end).
            blocked = server.record_analysis_lane(
                case_id="CASE-RETRY",
                lane_id="timeline_correlation",
                status="COMPLETE_WITH_GAPS",
                assigned_agent="main-agent",
                execution_ids=[eid],
                finding_ids=[],
                summary="Should be blocked by the freshly-persisted retry_state.",
            )
            self.assertEqual(blocked["status"], "error")
            self.assertEqual(blocked["error"], "retry_required_execution_unresolved")


if __name__ == "__main__":
    unittest.main()
