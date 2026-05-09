import importlib.util
import json
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
                    payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
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


if __name__ == "__main__":
    unittest.main()
