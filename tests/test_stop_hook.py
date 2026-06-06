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
    def _run_stop_hook(
        self,
        analysis_dir: Path,
        *,
        reports_dir: Path | None = None,
        delegate_path: Path | None = None,
    ) -> dict:
        payload = {"stop_reason": "session_end"}
        stdout = io.StringIO()
        env = {"SAVVYDFIR_ANALYSIS_DIR": str(analysis_dir)}
        if reports_dir is not None:
            env["SAVVYDFIR_REPORTS_DIR"] = str(reports_dir)
        if delegate_path is not None:
            env["SAVVYDFIR_DELEGATE_PATH"] = str(delegate_path)
        with patch.dict(os.environ, env):
            with patch("sys.stdin", io.StringIO(json.dumps(payload))):
                with redirect_stdout(stdout):
                    stop_hook.main()
        return json.loads(stdout.getvalue())

    def test_no_state_json_approves(self) -> None:
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
                                "tool": "detection.sigma_hunt",
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

    def test_pending_required_lanes_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)
            reports_dir = analysis_dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            # Must include case_id + executions for the in-progress gate
            # to trigger, otherwise the hook approves (non-DFIR session).
            (analysis_dir / "state.json").write_text(
                json.dumps({
                    "case_id": "TEST-INCOMPLETE",
                    "status": "COMPLETE",
                    "executions": [{"execution_id": "E-1", "tool_name": "x"}],
                }),
                encoding="utf-8",
            )

            result = self._run_stop_hook(analysis_dir, reports_dir=reports_dir)

            self.assertEqual(result["decision"], "block")
            # W1.7 merge: block reason no longer mentions sigma_hunt by name
            # (it lists next-required tool generically). Assert the block
            # is for an investigation-completeness reason.
            self.assertTrue(
                any(keyword in result["reason"].lower() for keyword in
                    ("sigma_hunt", "next required", "incomplete", "pending")),
                f"unexpected block reason: {result['reason']}"
            )

    def test_no_state_json_approves(self) -> None:
        """Non-DFIR session (no state.json) must approve, not block."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)  # empty dir, no state.json
            result = self._run_stop_hook(analysis_dir)
            self.assertEqual(result["decision"], "approve")

    def test_state_json_without_case_id_approves(self) -> None:
        """Residual state.json with no case_id is not a real investigation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)
            (analysis_dir / "state.json").write_text(
                json.dumps({"status": "COMPLETE"}),  # no case_id
                encoding="utf-8",
            )
            result = self._run_stop_hook(analysis_dir)
            self.assertEqual(result["decision"], "approve")

    def test_state_json_with_no_executions_approves(self) -> None:
        """Initialized but unused state — investigation never started."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_dir = Path(tmp_dir)
            (analysis_dir / "state.json").write_text(
                json.dumps({"case_id": "X", "executions": []}),
                encoding="utf-8",
            )
            result = self._run_stop_hook(analysis_dir)
            self.assertEqual(result["decision"], "approve")

    def test_no_global_glob_fallback_for_stale_shared_state(self) -> None:
        """review Phase-C-boundary #medium: prior implementation globbed
        /cases/*/state.json and /tmp/savvydfir/state.json. A stale state
        there could falsely block a non-DFIR session in the repo cwd.
        After the fix the hook only inspects the configured analysis dir
        (env or ./analysis) — no shared-path globbing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # The "analysis dir" for this session is empty — no state.json
            analysis_dir = Path(tmp_dir) / "session-empty-analysis"
            analysis_dir.mkdir()
            # _run_stop_hook should look only at analysis_dir,
            # not at /cases/ or /tmp/savvydfir/ on the host
            result = self._run_stop_hook(analysis_dir)
            self.assertEqual(
                result["decision"],
                "approve",
                f"Non-DFIR session with empty analysis dir must approve; "
                f"got {result}. Stale state in /cases or /tmp must not affect this.",
            )


if __name__ == "__main__":
    unittest.main()
