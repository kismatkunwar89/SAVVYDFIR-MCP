import json
import tempfile
import unittest
from pathlib import Path

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.state import CaseStateManager


class RunnerAuditParityTests(unittest.TestCase):
    def test_safe_runner_normalizes_completed_audit_fields_and_state_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_path = Path(tmp_dir) / "audit.jsonl"
            state_path = Path(tmp_dir) / "state.json"

            audit = AuditLogger(str(audit_path))
            state = CaseStateManager(str(state_path))
            state.load("CASE-003")

            runner = SafeRunner(
                audit_logger=audit,
                case_id="CASE-003",
                tool_name="runner.default",
                state_manager=state,
            )

            result = runner.run(
                ["printf", "hello"],
                parameters={"query": "hello"},
                agent_turn=7,
                tool_name="memory.list_processes",
            )

            self.assertTrue(result.ok)
            self.assertEqual(result.stdout, "hello")

            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(entries), 2)

            started = next(entry for entry in entries if entry["event_type"] == "started")
            completed = next(entry for entry in entries if entry["event_type"] == "completed")

            for entry in (started, completed):
                self.assertEqual(entry["tool"], "memory.list_processes")
                self.assertEqual(entry["parameters"], {"query": "hello"})
                self.assertEqual(entry["command_line"], "printf hello")
                self.assertEqual(entry["agent_turn"], 7)
                self.assertEqual(entry["execution_id"], result.execution_id)
                self.assertEqual(entry["schema_version"], 2)
                self.assertTrue(entry["entry_hash"])

            self.assertEqual(completed["exit_code"], 0)
            self.assertTrue(completed["outputs_summary"])
            self.assertEqual(completed["finding_ids_generated"], [])
            self.assertEqual(completed["prev_entry_hash"], started["entry_hash"])

            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["executions_count"], 1)
            self.assertEqual(len(persisted["executions"]), 1)
            execution = persisted["executions"][0]
            self.assertEqual(execution["execution_id"], result.execution_id)
            self.assertEqual(execution["tool_name"], "memory.list_processes")
            self.assertEqual(execution["command_line"], "printf hello")
            self.assertEqual(execution["parameters"], {"query": "hello"})
            self.assertEqual(execution["agent_turn"], 7)
            self.assertEqual(execution["exit_code"], 0)
            self.assertTrue(execution["outputs_summary"])
            self.assertEqual(execution["audit_started_entry_hash"], started["entry_hash"])
            self.assertEqual(execution["audit_completed_entry_hash"], completed["entry_hash"])
            self.assertEqual(execution["finding_ids_generated"], [])


if __name__ == "__main__":
    unittest.main()
