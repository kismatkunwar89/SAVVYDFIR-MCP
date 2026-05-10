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
            analysis_dir = Path(tmp_dir) / "analysis"
            analysis_dir.mkdir()

            result = self._run_stop_hook(analysis_dir)

            self.assertEqual(result["decision"], "approve")

    def test_pending_required_lanes_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            analysis_dir = root / "analysis"
            reports_dir = root / "reports"
            analysis_dir.mkdir()
            reports_dir.mkdir()
            (analysis_dir / "state.json").write_text(
                json.dumps(
                    {
                        "case_id": "CASE-STOP-PENDING",
                        "status": "IN_PROGRESS",
                        "analysis_lanes": [
                            {"lane_id": "memory", "required": True, "status": "COMPLETE"},
                            {"lane_id": "timeline_correlation", "required": True, "status": "PENDING"},
                            {"lane_id": "anti_forensics_recovery", "required": True, "status": "IN_PROGRESS"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = self._run_stop_hook(analysis_dir, reports_dir=reports_dir)

            self.assertEqual(result["decision"], "block")
            self.assertIn("timeline_correlation", result["reason"])
            self.assertIn("anti_forensics_recovery", result["reason"])
            self.assertIn("get_investigation_gates", result["reason"])

    def test_complete_lanes_but_missing_final_artifacts_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            analysis_dir = root / "analysis"
            reports_dir = root / "reports"
            analysis_dir.mkdir()
            reports_dir.mkdir()
            (analysis_dir / "state.json").write_text(
                json.dumps(
                    {
                        "case_id": "CASE-STOP-MISSING",
                        "status": "IN_PROGRESS",
                        "analysis_lanes": [
                            {"lane_id": "memory", "required": True, "status": "COMPLETE"},
                            {"lane_id": "disk_execution_persistence", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "event_auth", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "anti_forensics_recovery", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "timeline_correlation", "required": True, "status": "COMPLETE"},
                        ],
                        "findings": [{"finding_id": "F-001"}],
                    }
                ),
                encoding="utf-8",
            )

            result = self._run_stop_hook(analysis_dir, reports_dir=reports_dir)

            self.assertEqual(result["decision"], "block")
            self.assertIn("report.json", result["reason"])
            self.assertIn("graph.html", result["reason"])
            self.assertIn("generate_graph", result["reason"])
            self.assertIn("generate_report", result["reason"])

    def test_complete_state_with_required_artifacts_approves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            analysis_dir = root / "analysis"
            reports_dir = root / "reports"
            report_dir = reports_dir / "CASE-STOP-OK"
            analysis_dir.mkdir()
            report_dir.mkdir(parents=True)
            (analysis_dir / "state.json").write_text(
                json.dumps(
                    {
                        "case_id": "CASE-STOP-OK",
                        "status": "COMPLETE",
                        "analysis_lanes": [
                            {"lane_id": "memory", "required": True, "status": "COMPLETE"},
                            {"lane_id": "disk_execution_persistence", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "event_auth", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "anti_forensics_recovery", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "timeline_correlation", "required": True, "status": "COMPLETE"},
                        ],
                        "executions": [{"execution_id": "E-001"}],
                    }
                ),
                encoding="utf-8",
            )
            for name in ("report.json", "report.html", "graph.json", "graph.html"):
                (report_dir / name).write_text("ok", encoding="utf-8")

            result = self._run_stop_hook(analysis_dir, reports_dir=reports_dir)

            self.assertEqual(result["decision"], "approve")

    def test_unprocessed_delegate_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            analysis_dir = root / "analysis"
            reports_dir = root / "reports"
            delegate_path = root / "delegate.json"
            analysis_dir.mkdir()
            reports_dir.mkdir()
            (analysis_dir / "state.json").write_text(
                json.dumps(
                    {
                        "case_id": "CASE-STOP-DELEGATE",
                        "status": "IN_PROGRESS",
                        "analysis_lanes": [
                            {"lane_id": "memory", "required": True, "status": "COMPLETE"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            delegate_path.write_text(
                json.dumps({"lane_id": "event_auth", "processed": False}),
                encoding="utf-8",
            )

            result = self._run_stop_hook(
                analysis_dir,
                reports_dir=reports_dir,
                delegate_path=delegate_path,
            )

            self.assertEqual(result["decision"], "block")
            self.assertIn("event_auth", result["reason"])

    def test_processed_delegate_does_not_block_by_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            analysis_dir = root / "analysis"
            reports_dir = root / "reports"
            report_dir = reports_dir / "CASE-STOP-PROCESSED"
            delegate_path = root / "delegate.json"
            analysis_dir.mkdir()
            report_dir.mkdir(parents=True)
            (analysis_dir / "state.json").write_text(
                json.dumps(
                    {
                        "case_id": "CASE-STOP-PROCESSED",
                        "status": "COMPLETE",
                        "analysis_lanes": [
                            {"lane_id": "memory", "required": True, "status": "COMPLETE"},
                            {"lane_id": "disk_execution_persistence", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "event_auth", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "anti_forensics_recovery", "required": True, "status": "COMPLETE_WITH_GAPS"},
                            {"lane_id": "timeline_correlation", "required": True, "status": "COMPLETE"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            delegate_path.write_text(
                json.dumps({"lane_id": "event_auth", "processed": True}),
                encoding="utf-8",
            )
            for name in ("report.json", "report.html", "graph.json", "graph.html"):
                (report_dir / name).write_text("ok", encoding="utf-8")

            result = self._run_stop_hook(
                analysis_dir,
                reports_dir=reports_dir,
                delegate_path=delegate_path,
            )

            self.assertEqual(result["decision"], "approve")


if __name__ == "__main__":
    unittest.main()
