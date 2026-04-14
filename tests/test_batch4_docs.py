import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class Batch4DocTests(unittest.TestCase):
    def test_investigation_workflow_mentions_summary_first_and_full_finding_retrieval(self) -> None:
        workflow = (REPO_ROOT / ".claude" / "skills" / "investigation-workflow" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn('response_format="detailed"', workflow)
        self.assertIn("get_findings(case_id, finding_status=\"ACTIVE\")", workflow)

    def test_specialist_agents_that_use_read_state_also_advertise_get_findings(self) -> None:
        agent_dir = REPO_ROOT / ".claude" / "agents"
        for agent_path in sorted(agent_dir.glob("*.md")):
            text = agent_path.read_text(encoding="utf-8")
            if "mcp__savvydfir__read_state" not in text:
                continue
            with self.subTest(agent=agent_path.name):
                self.assertIn("mcp__savvydfir__get_findings", text)
                self.assertIn("get_findings()", text)


if __name__ == "__main__":
    unittest.main()
