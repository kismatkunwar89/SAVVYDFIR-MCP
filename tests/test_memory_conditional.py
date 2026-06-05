"""Memory-conditional coverage (review 2026-06-05).

A legitimately DISK-ONLY case (manifest memory_dumps == []) must complete instead
of bricking on unconditional memory-tool requirements. Default-True-on-absent keeps
every memory case (and all legacy state) unchanged.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import sift_mcp.reporting as reporting


class FakeState:
    """Minimal state_manager exposing only get_memory_present (for gate tests)."""
    def __init__(self, memory_present):
        self._mp = memory_present

    def get_memory_present(self):
        return self._mp


class CoverageGateMemoryConditionalTests(unittest.TestCase):
    def _missing_tools(self, memory_present):
        out = reporting.evaluate_ir_coverage_gate(
            findings=[],
            executions=[],
            sigma_result={},
            analysis_lanes=[],
            selector=None,
            memory_present=memory_present,
        )
        return {m["tool"] for m in out.get("missing", [])}

    def test_memory_required_when_present(self):
        missing = self._missing_tools(True)
        # default behavior: the 3 baseline memory tools are demanded
        self.assertIn("memory.list_processes", missing)
        self.assertIn("memory.scan_processes", missing)
        self.assertIn("memory.scan_network", missing)

    def test_memory_not_required_when_absent(self):
        missing = self._missing_tools(False)
        self.assertNotIn("memory.list_processes", missing)
        self.assertNotIn("memory.scan_processes", missing)
        self.assertNotIn("memory.scan_network", missing)
        self.assertNotIn("memory.detect_injection", missing)
        self.assertNotIn("memory.list_dlls", missing)
        # disk tools STILL required (memory absence doesn't relax disk coverage)
        self.assertIn("disk.extract_mft_timeline", missing)

    def test_default_param_is_true(self):
        # omitting memory_present must behave as memory-mandatory (backward-compat)
        out = reporting.evaluate_ir_coverage_gate(
            findings=[], executions=[], sigma_result={}, analysis_lanes=[], selector=None)
        missing = {m["tool"] for m in out.get("missing", [])}
        self.assertIn("memory.list_processes", missing)


class SuccessGateMemoryConditionalTests(unittest.TestCase):
    def test_memory_lane_skipped_when_absent(self):
        # success gate reads get_memory_present off the state_manager directly
        out = reporting.evaluate_investigation_success_gate("CASE-X", FakeState(False))
        contrib = out.get("lane_contributions", {})
        mem = contrib.get("memory", {})
        self.assertTrue(mem.get("passed"), f"memory lane must pass on disk-only: {mem}")
        self.assertEqual(mem.get("reason"), "memory_not_in_scope_disk_only_case")

    def test_memory_lane_audited_when_present(self):
        out = reporting.evaluate_investigation_success_gate("CASE-Y", FakeState(True))
        mem = out.get("lane_contributions", {}).get("memory", {})
        # when present, the memory lane is audited (not auto-passed via the skip path)
        self.assertNotEqual(mem.get("reason"), "memory_not_in_scope_disk_only_case")


class StopHookMemoryConditionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "stophook", str(Path(__file__).resolve().parent.parent / ".claude/hooks/stop.py"))
        cls.stop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.stop)

    def _missing(self, memory_present):
        st = {"memory_present": memory_present, "executions": []}
        sp = Path(tempfile.mktemp()); sp.write_text(json.dumps(st))
        ap = Path(tempfile.mktemp()); ap.write_text("")
        return set(self.stop._missing_tools_actionable(str(sp), str(ap)))

    def test_memory_tools_not_demanded_when_absent(self):
        missing = self._missing(False)
        for t in ("list_processes", "scan_processes", "scan_network",
                  "detect_injection", "list_dlls"):
            self.assertNotIn(t, missing, f"{t} must not be demanded on disk-only")
        # compare_disk_and_memory STAYS demanded (disk-primary checks)
        self.assertIn("compare_disk_and_memory", missing)

    def test_memory_tools_demanded_when_present(self):
        missing = self._missing(True)
        self.assertIn("list_processes", missing)
        self.assertIn("compare_disk_and_memory", missing)


class StateMemoryPresentTests(unittest.TestCase):
    def test_default_true_then_set_false(self):
        import sift_mcp.state as state
        sp = Path(tempfile.mkdtemp()) / "state.json"
        mgr = state.CaseStateManager(state_path=str(sp))
        mgr.load("CASE-MEM")
        self.assertTrue(mgr.get_memory_present(), "absent flag must default True")
        mgr.set_memory_present(False)
        self.assertFalse(mgr.get_memory_present())
        mgr.set_memory_present(True)
        self.assertTrue(mgr.get_memory_present())


if __name__ == "__main__":
    unittest.main()
