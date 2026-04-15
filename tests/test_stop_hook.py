import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "savvydfir_stop_hook",
    ROOT / ".claude" / "hooks" / "stop.py",
)
assert SPEC is not None and SPEC.loader is not None
stop_hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stop_hook)


class StopHookTests(unittest.TestCase):
    def _run_stop_hook(self, analysis_dir: Path) -> dict:
        payload = {"stop_reason": "session_end"}
        stdout = io.StringIO()
        with patch.dict(os.environ, {"SAVVYDFIR_ANALYSIS_DIR": str(analysis_dir)}):
            with patch("sys.stdin", io.StringIO(json.dumps(payload))):
                with redirect_stdout(stdout):
                    stop_hook.main()
        return json.loads(stdout.getvalue())

    def test_complete_state_and_audit_returns_approve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)
            (analysis_dir / "state.json").write_text(
                json.dumps({"status": "COMPLETE"}),
                encoding="utf-8",
            )
            (analysis_dir / "audit.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event_type": "completed",
                                "tool": "detection.sigma_scan",
                            }
                        ),
                        json.dumps(
                            {
                                "event_type": "completed",
                                "tool": "correlation.compare_disk_and_memory",
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )

            result = self._run_stop_hook(analysis_dir)

            self.assertEqual(result["decision"], "approve")

    def test_missing_completed_entries_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)
            (analysis_dir / "state.json").write_text(
                json.dumps({"status": "COMPLETE"}),
                encoding="utf-8",
            )
            (analysis_dir / "audit.jsonl").write_text("", encoding="utf-8")

            result = self._run_stop_hook(analysis_dir)

            self.assertEqual(result["decision"], "block")
            self.assertIn("sigma_scan", result["reason"])


if __name__ == "__main__":
    unittest.main()
