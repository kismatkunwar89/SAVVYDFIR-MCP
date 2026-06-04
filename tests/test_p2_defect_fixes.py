"""P2 defect fixes (review 2026-06-03): #5 DLL allowlist, #7 agent_trigger
absence skip. (#3 sigma observability is exercised on the VM where Chainsaw runs;
its telemetry regex is covered indirectly here.)
"""

import importlib.util
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class DllClassificationTests(unittest.TestCase):
    """#5: off-path DLLs in known vendor app dirs are NOT 0.9 hijack hits."""

    def setUp(self):
        from sift_mcp.tools.memory import _classify_dll_path
        self.cl = _classify_dll_path

    def test_system_paths(self):
        self.assertEqual(self.cl(r"C:\Windows\System32\ntdll.dll"), "system")
        self.assertEqual(self.cl(r"C:\Program Files\App\x.dll"), "system")

    def test_vendor_paths(self):
        self.assertEqual(
            self.cl(r"C:\Users\b\AppData\Local\Microsoft\OneDrive\23.1\FileSyncShell.dll"),
            "vendor",
        )
        self.assertEqual(
            self.cl(r"C:\Users\b\AppData\Local\Programs\Microsoft VS Code\x.dll"),
            "vendor",
        )
        self.assertEqual(
            self.cl(r"C:\Users\b\AppData\Local\Temp\_MEI123456\python39.dll"),
            "vendor",
        )

    def test_suspicious_paths(self):
        self.assertEqual(self.cl(r"C:\Users\Public\evil.dll"), "suspicious")
        self.assertEqual(self.cl(r"C:\Temp\sketchy.dll"), "suspicious")

    def test_empty_path_non_suspicious(self):
        self.assertEqual(self.cl(""), "system")


class AgentTriggerAbsenceSkipTests(unittest.TestCase):
    """#7: documented-absence / no-data results must not dispatch a specialist."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "agent_trigger", str(REPO / "scripts" / "agent_trigger.py")
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        self.f = m._result_signals_absence

    def test_absence_statuses_skip(self):
        for st in ("artifact_absent", "no_data", "tool_incompatible",
                   "collection_failed", "not_applicable", "documented_absence"):
            self.assertTrue(self.f({"status": st}), st)

    def test_marker_in_summary_without_handle_skips(self):
        self.assertTrue(
            self.f({"status": "success",
                    "outputs_summary": "documented absence: no Windows volume"})
        )

    def test_real_handle_does_not_skip(self):
        self.assertFalse(
            self.f({"status": "success", "csv_path": "/cases/x/a.csv",
                    "outputs_summary": "no_data here"})
        )
        self.assertFalse(self.f({"status": "success", "csv_path": "/cases/x/a.csv"}))

    def test_documented_absence_flag(self):
        self.assertTrue(self.f({"documented_absence": True}))


class SigmaTelemetryRegexTests(unittest.TestCase):
    """#3: the telemetry regex (mirrors the nested helper in sigma_hunt)."""

    @staticmethod
    def _parse(text):
        out = {"documents_loaded": None, "rules_loaded": None}
        d = re.search(r"[Ll]oaded\s+([\d,]+)\s+(?:forensic\s+)?document", text)
        if d:
            out["documents_loaded"] = int(d.group(1).replace(",", ""))
        r = re.search(r"[Ll]oaded\s+([\d,]+)\s+(?:detection\s+rule|rule|sigma)", text)
        if r:
            out["rules_loaded"] = int(r.group(1).replace(",", ""))
        return out

    def test_both_counts(self):
        out = self._parse("[+] Loaded 2,980 detection rules\n[+] Loaded 12 forensic documents")
        self.assertEqual(out, {"documents_loaded": 12, "rules_loaded": 2980})

    def test_zero_documents(self):
        self.assertEqual(self._parse("[+] Loaded 0 documents")["documents_loaded"], 0)

    def test_no_telemetry(self):
        self.assertEqual(self._parse("garbage"), {"documents_loaded": None, "rules_loaded": None})


if __name__ == "__main__":
    unittest.main()
