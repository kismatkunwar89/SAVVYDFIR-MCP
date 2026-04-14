import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sift_mcp.safe_analysis import SafeAnalysisError, blocked_pattern, run_safe_analysis, _build_interpreter


class RunAnalysisSafetyTests(unittest.TestCase):
    def test_safe_query_executes_without_pandas_module_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "data.csv"
            csv_path.write_text("name,value\nalice,1\nbob,3\n", encoding="utf-8")

            result = run_safe_analysis(
                str(csv_path),
                "df[df['value'] > 1][['name', 'value']]",
                output_format="json",
            )

            self.assertEqual(result["row_count"], 1)
            self.assertIn("bob", result["result_table"])

    def test_blocked_patterns_cover_pandas_io_and_reflection(self) -> None:
        cases = [
            "pd.read_csv('x.csv')",
            "df.to_csv('out.csv')",
            "open('/tmp/x', 'w')",
            "df.__class__",
            "getattr(df, 'head')",
        ]
        for query in cases:
            with self.subTest(query=query):
                self.assertIsNotNone(blocked_pattern(query))

    def test_run_safe_analysis_rejects_blocked_queries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "data.csv"
            csv_path.write_text("name,value\nalice,1\n", encoding="utf-8")

            with self.assertRaises(SafeAnalysisError):
                run_safe_analysis(str(csv_path), "pd.read_csv('other.csv')")

    def test_build_interpreter_fails_closed_when_asteval_unavailable(self) -> None:
        with mock.patch.dict(sys.modules, {"asteval": None}):
            with self.assertRaises(SafeAnalysisError):
                _build_interpreter({"len": len})


if __name__ == "__main__":
    unittest.main()
