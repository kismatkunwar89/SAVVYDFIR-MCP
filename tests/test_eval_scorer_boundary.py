import json
import tempfile
import unittest
from pathlib import Path

from scripts.eval.baseline_report_scorer import load_finalized_report, score_report


class EvalScorerBoundaryTests(unittest.TestCase):
    def test_scorer_accepts_only_finalized_report_json(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_dir = Path(tmp_dir) / "reports" / "CASE"
            report_dir.mkdir(parents=True)
            report_path = report_dir / "report.json"
            report_path.write_text(json.dumps({"status": "ok", "sigma_scan": {}}), encoding="utf-8")
            self.assertEqual(load_finalized_report(report_path)["status"], "ok")

            state_path = Path(tmp_dir) / "analysis" / "state.json"
            state_path.parent.mkdir()
            state_path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_finalized_report(state_path)

    def test_scorer_does_not_need_runtime_imports(self):
        report = {
            "status": "ok",
            "triage_status": "TRIAGE_COMPLETE",
            "artifact_coverage": {"coverage_percent": 10},
            "actionable_leads": [
                {
                    "detector": "log_clear",
                    "next_pivot": {
                        "tool": "detection.analyze_vss",
                        "args": {},
                        "human_readable": "Recover logs.",
                    },
                }
            ],
            "sigma_scan": {"detectors_run": ["log_clear"]},
        }
        score = score_report(report, "MFT Amcache Prefetch Defender")
        self.assertIn("log_clear", score["detectors_present"])
        self.assertTrue(score["sections"]["structured_pivots"])


if __name__ == "__main__":
    unittest.main()
