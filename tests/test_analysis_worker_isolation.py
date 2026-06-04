"""F1: run_analysis memory-isolation worker (review 2026-06-04).

The worker runs pandas in a memory-capped CHILD process so a runaway query can
never OOM-kill the MCP server (the 15.3GB systemd-oomd crash). These tests run
the real worker via subprocess and assert: success path, blocked-query path, and
that an over-cap allocation fails CLEANLY (no hang, server-equivalent survives).
Skips gracefully if pandas isn't installed in the test env.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import pandas  # noqa: F401
    _HAVE_PANDAS = True
except Exception:
    _HAVE_PANDAS = False


def _run_worker(req: dict, timeout: int = 60):
    proc = subprocess.run(
        [sys.executable, "-m", "sift_mcp.analysis_worker"],
        input=json.dumps(req), capture_output=True, text=True, timeout=timeout,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    return proc


@unittest.skipUnless(_HAVE_PANDAS, "pandas not installed in this env")
class AnalysisWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.csv = Path(tempfile.mkdtemp()) / "t.csv"
        cls.csv.write_text("a,b\n1,x\n2,y\n3,z\n", encoding="utf-8")

    def test_success_returns_result(self):
        p = _run_worker({"data_path": str(self.csv), "query": "df.shape",
                         "output_format": "json", "mem_cap_bytes": 2 * 1024**3})
        self.assertEqual(p.returncode, 0)
        env = json.loads(p.stdout)
        self.assertTrue(env["ok"], env)
        self.assertEqual(env["result"]["row_count"], 1)

    def test_blocked_query_rejected(self):
        p = _run_worker({"data_path": str(self.csv), "query": "__import__('os')",
                         "mem_cap_bytes": 2 * 1024**3})
        env = json.loads(p.stdout)
        self.assertFalse(env["ok"])
        self.assertEqual(env["kind"], "safe_analysis")

    def test_over_cap_allocation_fails_clean_no_hang(self):
        # 512MB cap, ~1.5GB allocation -> must fail cleanly (not hang, not crash test)
        p = _run_worker({"data_path": str(self.csv), "query": "np.ones(200000000)",
                         "mem_cap_bytes": 512 * 1024**2}, timeout=45)
        # worker always exits 0 with an envelope (the OOM is contained); even if the
        # OS SIGKILLs it, returncode != 0 is still a clean parent-observable signal.
        if p.returncode == 0:
            env = json.loads(p.stdout)
            self.assertFalse(env["ok"], "over-cap allocation must not report success")
        else:
            self.assertNotEqual(p.returncode, 124, "must not hang")

    def test_missing_file_clean_error(self):
        p = _run_worker({"data_path": "/nonexistent/x.csv", "query": "df.shape",
                         "mem_cap_bytes": 2 * 1024**3})
        env = json.loads(p.stdout)
        self.assertFalse(env["ok"])


class ApplyMemoryCapUnitTests(unittest.TestCase):
    def test_apply_cap_no_crash(self):
        from sift_mcp.analysis_worker import _apply_memory_cap
        # must be best-effort: never raise even on odd inputs
        _apply_memory_cap(0)
        _apply_memory_cap(-1)


if __name__ == "__main__":
    unittest.main()
