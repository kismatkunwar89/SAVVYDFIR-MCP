import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "savvydfir_agent_trigger",
    ROOT / "scripts" / "agent_trigger.py",
)
assert SPEC is not None and SPEC.loader is not None
agent_trigger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent_trigger)


class AgentTriggerTests(unittest.TestCase):
    def _nested_event(
        self,
        tool_name: str,
        payload: dict,
        *,
        tool_input: Optional[dict[str, Any]] = None,
    ) -> dict:
        ev: dict = {
            "tool_name": tool_name,
            "tool_result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(payload),
                    }
                ]
            },
        }
        if tool_input is not None:
            ev["tool_input"] = tool_input
        return ev

    def _read_queue_delegate(self, trigger_path: Path, lane_id: Optional[str] = None, index: int = 0) -> Optional[dict]:
        """Read a delegate from the queue file structure.

        Args:
            trigger_path: Path to queue JSON file
            lane_id: Lane identifier (e.g., "event_auth"). If None, returns first delegate from any lane.
            index: Index in lane's queue (0 = head)

        Returns:
            Delegate dict or None if not found
        """
        if not trigger_path.exists():
            return None
        queue = json.loads(trigger_path.read_text(encoding="utf-8"))

        if lane_id is None:
            # Return first delegate from any lane (for simple tests)
            for lane_queue in queue.values():
                if lane_queue and len(lane_queue) > 0:
                    return lane_queue[0]
            return None

        lane_queue = queue.get(lane_id, [])
        if index < len(lane_queue):
            return lane_queue[index]
        return None

    def test_namespaced_evtx_payload_dispatches_and_writes_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__summarize_evtx",
                {
                    "status": "success",
                    "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                    "total_records": 120,
                },
            )

            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))

            self.assertIsNotNone(result)
            self.assertEqual(result["decision"], "block")
            self.assertIn("@evtx-analyst", result["reason"])
            self.assertIn("Task SYNCHRONOUSLY", result["reason"])
            self.assertIn("PATH B", result["reason"])
            self.assertIn("main-agent", result["reason"])
            self.assertIn("record_analysis_lane", result["reason"])
            payload = self._read_queue_delegate(trigger_path, "event_auth")
            self.assertIsNotNone(payload, "Delegate should be queued in event_auth lane")
            self.assertEqual(payload["agent"], "@evtx-analyst")
            self.assertEqual(payload["subagent_type"], "evtx-analyst")
            self.assertEqual(payload["lane_id"], "event_auth")
            self.assertIn("@evtx-analyst", payload["agent_call"])
            self.assertIn("Context handle:", payload["prompt"])
            self.assertEqual(payload["tool"], "mcp__savvydfir__summarize_evtx")
            self.assertIn("CSV at:", payload["instruction"])

    def test_bare_evtx_payload_dispatches_and_writes_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "summarize_evtx",
                {
                    "status": "success",
                    "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                    "total_records": 120,
                },
            )

            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))

            self.assertIsNotNone(result)
            self.assertEqual(result["decision"], "block")
            self.assertIn("@evtx-analyst", result["reason"])
            payload = self._read_queue_delegate(trigger_path, "event_auth")
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertEqual(payload["subagent_type"], "evtx-analyst")
            self.assertEqual(payload["lane_id"], "event_auth")
            self.assertEqual(payload["tool"], "summarize_evtx")

    def test_requires_agent_metadata_takes_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__summarize_evtx",
                {
                    "status": "success",
                    "requires_agent": "@custom-analyst",
                    "agent_instruction": "Use the metadata-driven path.",
                    "csv_path": "/cases/CASE-2/artifacts/evtx/custom.csv",
                    "total_records": 42,
                },
            )

            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))

            self.assertEqual(result["decision"], "block")
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertEqual(payload["agent"], "@custom-analyst")
            self.assertEqual(payload["subagent_type"], "custom-analyst")
            self.assertIn("Use the metadata-driven path.", payload["instruction"])

    def test_build_timeline_storage_dispatches_to_timeline_analyst(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__build_timeline",
                {
                    "status": "ok",
                    "summary": "Timeline storage ready for case CASE-TL.",
                    "storage_path": "/cases/CASE-TL/analysis/case-tl.plaso",
                },
            )

            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))

            self.assertIsNotNone(result)
            self.assertEqual(result["decision"], "block")
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertEqual(payload["agent"], "@timeline-analyst")
            self.assertIn("@timeline-analyst", result["reason"])
            self.assertIn("storage handle", payload["instruction"])
            self.assertIn("Summary:", payload["instruction"])

    def test_sigma_hits_dispatch_to_sigma_analyst(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__sigma_scan",
                {
                    "status": "ok",
                    "total_hits": 5,
                    "critical_count": 2,
                    "high_count": 1,
                    "summary_markdown": "## Sigma summary",
                },
            )

            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))

            self.assertEqual(result["decision"], "block")
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertEqual(payload["agent"], "@sigma-analyst")
            self.assertEqual(payload["subagent_type"], "sigma-analyst")
            self.assertIn("2 CRITICAL", payload["instruction"])
            self.assertIn("1 HIGH", payload["instruction"])

    def test_all_specialist_hook_messages_use_main_style_delegation(self) -> None:
        cases = {
            "mcp__savvydfir__extract_mft_timeline": "mft-analyst",
            "mcp__savvydfir__summarize_evtx": "evtx-analyst",
            "mcp__savvydfir__extract_registry_run_keys": "registry-analyst",
            "mcp__savvydfir__get_amcache": "amcache-analyst",
            "mcp__savvydfir__extract_prefetch": "prefetch-analyst",
            "mcp__savvydfir__detect_injection": "memory-analyst",
            "mcp__savvydfir__sigma_hunt": "sigma-analyst",
            "mcp__savvydfir__build_timeline": "timeline-analyst",
        }
        for tool_name, subagent_type in cases.items():
            with self.subTest(tool_name=tool_name):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    trigger_path = Path(tmp_dir) / "delegate.json"
                    result = agent_trigger.process_event(
                        self._nested_event(
                            tool_name,
                            {
                                "status": "success",
                                "csv_path": f"/cases/CASE-1/artifacts/{subagent_type}.csv",
                                "total_records": 1,
                            },
                        ),
                        trigger_path=str(trigger_path),
                    )
                    self.assertIsNotNone(result)
                    self.assertEqual(result["decision"], "block")
                    self.assertIn(f"@{subagent_type}", result["reason"])
                    self.assertIn("record_analysis_lane", result["reason"])
                    payload = self._read_queue_delegate(trigger_path)
                    self.assertIsNotNone(payload, "Delegate should be queued")
                    self.assertEqual(payload["subagent_type"], subagent_type)
                    self.assertIn(f"@{subagent_type}", payload["delegation_text"])

    def test_pending_delegation_blocks_parent_follow_up_until_lane_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            first = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                ),
                trigger_path=str(trigger_path),
            )
            self.assertEqual(first["decision"], "block")

            follow_up = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__run_analysis",
                    {"status": "ok", "rows": []},
                ),
                trigger_path=str(trigger_path),
            )
            self.assertIsNone(follow_up)
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertEqual(payload["lane_id"], "event_auth")
            self.assertFalse(payload["processed"])

            lane_record = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__record_analysis_lane",
                    {"status": "ok", "lane_id": "event_auth"},
                    tool_input={"lane_id": "event_auth"},
                ),
                trigger_path=str(trigger_path),
            )
            self.assertIsNone(lane_record)
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertTrue(payload["processed"])

    def test_pending_delegation_blocks_report_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "case_id": "CASE-1",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                    tool_input={"case_id": "CASE-1"},
                ),
                trigger_path=str(trigger_path),
            )
            blocked = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__generate_report",
                    {"status": "ok"},
                    tool_input={"case_id": "CASE-1"},
                ),
                trigger_path=str(trigger_path),
            )
            self.assertIsNotNone(blocked)
            self.assertEqual(blocked["decision"], "block")
            self.assertIn("@evtx-analyst", blocked["reason"])

    def test_pending_delegation_does_not_block_unrelated_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                ),
                trigger_path=str(trigger_path),
            )

            unrelated = agent_trigger.process_event(
                self._nested_event(
                    "WebFetch",
                    {"status": "ok", "url": "https://example.com"},
                ),
                trigger_path=str(trigger_path),
            )
            self.assertIsNone(unrelated)
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertFalse(payload["processed"])

    def test_pending_delegation_does_not_block_other_lane_tool_or_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "case_id": "CASE-1",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                    tool_input={"case_id": "CASE-1"},
                ),
                trigger_path=str(trigger_path),
            )

            unrelated_lane = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__detect_injection",
                    {"status": "success", "case_id": "CASE-1", "records_count": 3},
                    tool_input={"case_id": "CASE-1"},
                ),
                trigger_path=str(trigger_path),
            )
            self.assertIsNone(unrelated_lane)
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertEqual(payload["lane_id"], "event_auth")
            self.assertFalse(payload["processed"])

    def test_pending_delegation_case_mismatch_marks_trigger_processed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            trigger_path.write_text(
                json.dumps(
                    {
                        "processed": False,
                        "lane_id": "event_auth",
                        "subagent_type": "evtx-analyst",
                        "case_id": "CASE-A",
                        "session_id": "SESSION-A",
                        "created_at": "2099-01-01T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            result = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__generate_report",
                    {"status": "ok"},
                    tool_input={"case_id": "CASE-B"},
                ),
                trigger_path=str(trigger_path),
            )
            self.assertIsNone(result)
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertTrue(payload["processed"])

    def test_legacy_stale_trigger_without_created_at_is_processed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            trigger_path.write_text(
                json.dumps(
                    {
                        "processed": False,
                        "lane_id": "event_auth",
                        "subagent_type": "evtx-analyst",
                    }
                ),
                encoding="utf-8",
            )
            os.utime(trigger_path, (0, 0))

            result = agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__generate_report",
                    {"status": "ok"},
                    tool_input={"case_id": "CASE-B"},
                ),
                trigger_path=str(trigger_path),
            )

            self.assertIsNone(result)
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertTrue(payload["processed"])

    def test_lane_match_strict_clears_trigger_when_lane_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                ),
                trigger_path=str(trigger_path),
            )
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__record_analysis_lane",
                    {"status": "ok", "lane_id": "event_auth"},
                    tool_input={"lane_id": "event_auth"},
                ),
                trigger_path=str(trigger_path),
            )
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertTrue(payload["processed"])

    def test_lane_match_uses_nested_lane_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                ),
                trigger_path=str(trigger_path),
            )
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__record_analysis_lane",
                    {
                        "status": "ok",
                        "lane": {"lane_id": "event_auth"},
                    },
                ),
                trigger_path=str(trigger_path),
            )
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertTrue(payload["processed"])

    def test_lane_match_parses_string_content_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__detect_injection",
                    {"status": "success", "records_count": 0},
                ),
                trigger_path=str(trigger_path),
            )
            event = {
                "tool_name": "mcp__savvydfir__record_analysis_lane",
                "tool_result": {
                    "content": json.dumps(
                        {
                            "status": "ok",
                            "tool": "record_analysis_lane",
                            "case_id": "CASE-1",
                            "lane": {"lane_id": "memory"},
                        }
                    )
                },
            }

            agent_trigger.process_event(event, trigger_path=str(trigger_path))

            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertTrue(payload["processed"])

    def test_lane_match_strict_blocks_wrong_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__summarize_evtx",
                    {
                        "status": "success",
                        "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                        "total_records": 100,
                    },
                ),
                trigger_path=str(trigger_path),
            )
            agent_trigger.process_event(
                self._nested_event(
                    "mcp__savvydfir__record_analysis_lane",
                    {"status": "ok", "lane_id": "memory"},
                    tool_input={"lane_id": "memory"},
                ),
                trigger_path=str(trigger_path),
            )
            payload = self._read_queue_delegate(trigger_path)
            self.assertIsNotNone(payload, "Delegate should be queued")
            self.assertFalse(payload["processed"])

    def test_zero_hit_sigma_does_not_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__sigma_scan",
                {
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                },
            )

            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))

            self.assertIsNone(result)
            self.assertFalse(trigger_path.exists())

    def test_clear_failure_patterns_block(self) -> None:
        event = self._nested_event(
            "mcp__savvydfir__extract_registry_run_keys",
            {
                "status": "error",
                "error_message": "Permission denied while opening hive",
            },
        )

        result = agent_trigger.process_event(event)

        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")
        self.assertIn("Permission denied", result["reason"])

    def test_error_status_does_not_spawn_specialist(self) -> None:
        """Run2 bug: failed summarize_evtx spawned evtx-analyst with no data,
        analyst burned 21k tokens then bailed. Hook must not dispatch on error."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__summarize_evtx",
                {
                    "status": "error",
                    "csv_path": "/cases/CASE-1/artifacts/evtx/evtx_timeline.csv",
                },
            )
            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))
            self.assertIsNone(result, f"error must not spawn specialist, got: {result}")
            self.assertFalse(trigger_path.exists())

    def test_not_initialised_status_does_not_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trigger_path = Path(tmp_dir) / "delegate.json"
            event = self._nested_event(
                "mcp__savvydfir__summarize_evtx",
                {"status": "not_initialised", "csv_path": "/tmp/x.csv"},
            )
            result = agent_trigger.process_event(event, trigger_path=str(trigger_path))
            self.assertIsNone(result)
            self.assertFalse(trigger_path.exists())

    def test_same_lane_different_tools_queue_concurrently(self) -> None:
        """H.1 fix: same-lane tools should NOT block each other.

        Old behavior: extract_mft_timeline and sigma_hunt (both in
        timeline_correlation lane) blocked each other due to lane_id match.
        New behavior: different tools in same lane can queue concurrently.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Use queue path instead of single trigger file
            queue_path = Path(tmp_dir) / "delegate_queue.json"
            os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = str(queue_path)

            try:
                # First tool in timeline_correlation lane: extract_mft_timeline
                result1 = agent_trigger.process_event(
                    self._nested_event(
                        "mcp__savvydfir__extract_mft_timeline",
                        {
                            "status": "success",
                            "csv_path": "/cases/CASE-1/mft_timeline.csv",
                            "total_rows": 301000,
                        },
                    ),
                    trigger_path=str(queue_path),
                )
                self.assertIsNotNone(result1)
                self.assertEqual(result1["decision"], "block")
                self.assertIn("@mft-analyst", result1["reason"])

                # Second tool in SAME lane: sigma_hunt
                # OLD: would block because lane_id == "timeline_correlation"
                # NEW: should queue because it's a DIFFERENT tool
                result2 = agent_trigger.process_event(
                    self._nested_event(
                        "mcp__savvydfir__sigma_hunt",
                        {
                            "status": "success",
                            "finding_ids_generated": ["F-001", "F-002"],
                            "detection_count": 42,
                        },
                    ),
                    trigger_path=str(queue_path),
                )

                # Should NOT be None (specialist should be queued)
                self.assertIsNotNone(result2, "Same-lane different tools should queue concurrently")
                self.assertEqual(result2["decision"], "block")
                self.assertIn("@sigma-analyst", result2["reason"])

                # Verify queue has both delegates
                with open(queue_path) as f:
                    queue = json.load(f)
                self.assertIn("timeline_correlation", queue)
                self.assertEqual(len(queue["timeline_correlation"]), 2)
                self.assertEqual(queue["timeline_correlation"][0]["tool"], "mcp__savvydfir__extract_mft_timeline")
                self.assertEqual(queue["timeline_correlation"][1]["tool"], "mcp__savvydfir__sigma_hunt")

            finally:
                os.environ.pop("SAVVYDFIR_DELEGATE_QUEUE_PATH", None)

    def test_same_lane_same_tool_blocks_duplicate(self) -> None:
        """H.1 fix: same tool already queued in same lane should block.

        Prevents duplicate delegates for the same tool in the same lane.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            queue_path = Path(tmp_dir) / "delegate_queue.json"
            os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = str(queue_path)

            try:
                # First sigma_hunt in timeline_correlation
                result1 = agent_trigger.process_event(
                    self._nested_event(
                        "mcp__savvydfir__sigma_hunt",
                        {
                            "status": "success",
                            "finding_ids_generated": ["F-001"],
                        },
                    ),
                    trigger_path=str(queue_path),
                )
                self.assertIsNotNone(result1)
                self.assertEqual(result1["decision"], "block")

                # Second sigma_hunt in SAME lane — should block (duplicate)
                result2 = agent_trigger.process_event(
                    self._nested_event(
                        "mcp__savvydfir__sigma_hunt",
                        {
                            "status": "success",
                            "finding_ids_generated": ["F-002"],
                        },
                    ),
                    trigger_path=str(queue_path),
                )

                # Should block with delegation reason
                self.assertIsNotNone(result2)
                self.assertEqual(result2["decision"], "block")
                self.assertIn("@sigma-analyst", result2["reason"])

                # Verify queue has only ONE sigma_hunt delegate (no duplicate)
                with open(queue_path) as f:
                    queue = json.load(f)
                sigma_count = sum(
                    1 for d in queue.get("timeline_correlation", [])
                    if "sigma_hunt" in d.get("tool", "")
                )
                self.assertEqual(sigma_count, 1, "Duplicate tool should not be queued twice")

            finally:
                os.environ.pop("SAVVYDFIR_DELEGATE_QUEUE_PATH", None)


if __name__ == "__main__":
    unittest.main()
