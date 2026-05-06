import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "savvydfir_agent_trigger",
    ROOT / "scripts" / "agent_trigger.py",
)
assert SPEC is not None and SPEC.loader is not None
agent_trigger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent_trigger)


class AgentTriggerTests(unittest.TestCase):
    def _nested_event(self, tool_name: str, payload: dict) -> dict:
        return {
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
            self.assertEqual(result["decision"], "allow")
            self.assertIn("@evtx-analyst", result["message"])
            self.assertIn("artifact handle", result["message"])
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["agent"], "@evtx-analyst")
            self.assertEqual(payload["subagent_type"], "evtx-analyst")
            self.assertEqual(payload["lane_id"], "event_auth")
            self.assertIn("@evtx-analyst", payload["agent_call"])
            self.assertIn("Context handle:", payload["prompt"])
            self.assertEqual(payload["tool"], "mcp__savvydfir__summarize_evtx")
            self.assertIn("CSV at:", payload["instruction"])

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

            self.assertEqual(result["decision"], "allow")
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
            self.assertEqual(result["decision"], "allow")
            payload = json.loads(trigger_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["agent"], "@timeline-analyst")
            self.assertIn("@timeline-analyst", result["message"])
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

            self.assertEqual(result["decision"], "allow")
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
                    self.assertIn(f"@{subagent_type}", result["message"])
                    self.assertIn("artifact handle", result["message"])
                    payload = json.loads(trigger_path.read_text(encoding="utf-8"))
                    self.assertEqual(payload["subagent_type"], subagent_type)
                    self.assertIn(f"@{subagent_type}", payload["delegation_text"])

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
