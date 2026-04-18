"""Tests for the One-Shot Findings Quality Recovery changes.

Covers:
  - Registry grouping / promotion (Change 1)
  - Summary-first response_format (Change 2)
  - Report truth tracking (Change 3)
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sift_mcp.reporting import (
    _count_by_key,
    _rank_findings,
    _split_findings_by_status,
    generate_report_payload,
    render_report_html,
)


# ---------------------------------------------------------------------------
# Change 1: Registry grouping / promotion
# ---------------------------------------------------------------------------


class TestRegistryGroupingHelpers(unittest.TestCase):
    """Unit tests for the registry promotion helpers in disk.py."""

    def _import_helpers(self):
        from sift_mcp.tools.disk import (
            _classify_promotion_reason,
            _extract_target_path,
            _is_interpreter_target,
            _is_system_path,
            _is_user_writable_path,
            _normalize_target_for_grouping,
        )
        return {
            "classify": _classify_promotion_reason,
            "extract": _extract_target_path,
            "interp": _is_interpreter_target,
            "system": _is_system_path,
            "user_wr": _is_user_writable_path,
            "normalize": _normalize_target_for_grouping,
        }

    def test_always_promote_classes(self):
        h = self._import_helpers()
        for cls in ("winlogon_shell", "appinit_dlls", "lsa_package",
                     "bootexecute", "ifeo", "active_setup", "print_monitor",
                     "credential_provider", "winlogon_userinit"):
            reason = h["classify"](cls, "\\windows\\system32\\svchost.exe", 1)
            self.assertIsNotNone(reason, f"{cls} should always promote")
            self.assertEqual(reason, "rare_autostart_class")

    def test_run_key_user_writable_promotes(self):
        h = self._import_helpers()
        reason = h["classify"]("run", "\\users\\bob\\appdata\\evil.exe", 1)
        self.assertEqual(reason, "user_writable_target")

    def test_run_key_system32_suppresses(self):
        h = self._import_helpers()
        reason = h["classify"]("run", "\\windows\\system32\\ctfmon.exe", 1)
        self.assertIsNone(reason)

    def test_run_key_interpreter_promotes(self):
        h = self._import_helpers()
        reason = h["classify"]("run", "\\windows\\system32\\cmd.exe", 1)
        self.assertEqual(reason, "interpreter_target")

    def test_service_system_path_single_suppresses(self):
        h = self._import_helpers()
        reason = h["classify"]("services", "\\windows\\system32\\svchost.exe", 1)
        self.assertIsNone(reason)

    def test_service_user_writable_promotes(self):
        h = self._import_helpers()
        reason = h["classify"]("services", "\\users\\public\\svc.exe", 1)
        self.assertEqual(reason, "user_writable_target")

    def test_normalize_target_strips_drive(self):
        h = self._import_helpers()
        result = h["normalize"]('C:\\Windows\\System32\\svchost.exe')
        self.assertEqual(result, "\\windows\\system32\\svchost.exe")

    def test_extract_target_path_with_args(self):
        h = self._import_helpers()
        result = h["extract"]('"C:\\Windows\\System32\\cmd.exe" /c evil.bat')
        self.assertEqual(result, "C:\\Windows\\System32\\cmd.exe")

    def test_is_user_writable(self):
        h = self._import_helpers()
        self.assertTrue(h["user_wr"]("\\Users\\Bob\\evil.exe"))
        self.assertTrue(h["user_wr"]("\\ProgramData\\malware.dll"))
        self.assertFalse(h["user_wr"]("\\Windows\\System32\\svchost.exe"))

    def test_is_system_path(self):
        h = self._import_helpers()
        self.assertTrue(h["system"]("\\Windows\\System32\\svchost.exe"))
        self.assertTrue(h["system"]("\\Program Files\\Chrome\\chrome.exe"))
        self.assertFalse(h["system"]("\\Users\\Bob\\evil.exe"))

    def test_is_interpreter(self):
        h = self._import_helpers()
        self.assertTrue(h["interp"]("cmd.exe"))
        self.assertTrue(h["interp"]("powershell.exe"))
        self.assertTrue(h["interp"]("mshta.exe"))
        self.assertFalse(h["interp"]("svchost.exe"))

    def test_other_persistence_class_does_not_promote(self):
        h = self._import_helpers()
        reason = h["classify"]("browser_helper", "\\anything\\path.dll", 5)
        self.assertIsNone(reason)


class TestRegistryGroupAndPromote(unittest.TestCase):
    """Integration test for _group_and_promote_registry."""

    def test_grouping_creates_fewer_findings_than_rows(self):
        from sift_mcp.models.artifacts import RegistryRunKey
        from sift_mcp.tools.disk import _group_and_promote_registry

        # Create 100 records: 90 system Run keys (should suppress), 10 user-writable (should promote)
        records = []
        for i in range(90):
            records.append(RegistryRunKey(
                hive="NTUSER.DAT",
                key_path=f"HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                value_name=f"SysApp{i}",
                value_data=f"C:\\Windows\\System32\\legitimate{i}.exe",
                persistence_type="run",
            ))
        for i in range(10):
            records.append(RegistryRunKey(
                hive="NTUSER.DAT",
                key_path=f"HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                value_name=f"Evil{i}",
                value_data=f"C:\\Users\\Bob\\AppData\\Roaming\\malware{i}.exe",
                persistence_type="run",
            ))

        finding_ids: list[str] = []
        meta = _group_and_promote_registry(
            records,
            tool="test",
            execution_id="E-TEST",
            create_findings=False,
            finding_ids_out=finding_ids,
        )

        self.assertEqual(len(finding_ids), 0)  # create_findings=False
        self.assertIn("suppression_summary", meta)
        self.assertIn("promoted_group_count", meta)
        self.assertIn("suppressed_group_count", meta)
        # Each unique target gets its own group — 10 user-writable should promote
        self.assertGreater(meta["promoted_group_count"], 0)
        # 90 system entries should suppress
        self.assertGreater(meta["suppressed_group_count"], 0)
        # Total groups should be much less than 100 rows
        total = meta["promoted_group_count"] + meta["suppressed_group_count"]
        self.assertLessEqual(total, 100)


# ---------------------------------------------------------------------------
# Change 2: Summary-first response_format (memory.py helpers)
# ---------------------------------------------------------------------------


class TestMemoryResponseFormatHelper(unittest.TestCase):
    def test_normalize_response_format(self):
        from sift_mcp.tools.memory import _normalize_response_format

        self.assertEqual(_normalize_response_format("summary"), "summary")
        self.assertEqual(_normalize_response_format("detailed"), "detailed")
        self.assertEqual(_normalize_response_format("SUMMARY"), "summary")
        self.assertEqual(_normalize_response_format(" Detailed "), "detailed")
        self.assertIsNone(_normalize_response_format("bogus"))
        # Empty string defaults to "summary" (safe default)
        self.assertEqual(_normalize_response_format(""), "summary")

    def test_normalize_response_format_disk(self):
        from sift_mcp.tools.disk import _normalize_response_format

        self.assertEqual(_normalize_response_format("summary"), "summary")
        self.assertEqual(_normalize_response_format("detailed"), "detailed")


# ---------------------------------------------------------------------------
# Change 3: Report truth tracking
# ---------------------------------------------------------------------------


class TestRankFindings(unittest.TestCase):
    """Verify that _rank_findings sorts by status precedence then confidence."""

    def test_confirmed_before_hypothesis(self):
        findings = [
            {"finding_status": "ACTIVE", "confidence": 0.95, "description": "hypo"},
            {"finding_status": "CONFIRMED", "confidence": 0.70, "description": "confirmed"},
        ]
        ranked = _rank_findings(findings)
        self.assertEqual(ranked[0]["description"], "confirmed")

    def test_within_same_status_sorts_by_confidence(self):
        findings = [
            {"finding_status": "ACTIVE", "confidence": 0.5},
            {"finding_status": "ACTIVE", "confidence": 0.9},
        ]
        ranked = _rank_findings(findings)
        self.assertAlmostEqual(ranked[0]["confidence"], 0.9)

    def test_rejected_sorted_last(self):
        findings = [
            {"finding_status": "REJECTED", "confidence": 0.99},
            {"finding_status": "OBSERVATION", "confidence": 0.1},
        ]
        ranked = _rank_findings(findings)
        self.assertEqual(ranked[0]["finding_status"], "OBSERVATION")
        self.assertEqual(ranked[1]["finding_status"], "REJECTED")


class TestSplitFindingsByStatus(unittest.TestCase):
    def test_buckets(self):
        findings = [
            {"finding_status": "ACTIVE"},
            {"finding_status": "CONFIRMED"},
            {"finding_status": "ACTIVE"},
        ]
        buckets = _split_findings_by_status(findings)
        self.assertEqual(len(buckets.get("ACTIVE", [])), 2)
        self.assertEqual(len(buckets.get("CONFIRMED", [])), 1)


class TestCountByKey(unittest.TestCase):
    def test_count_by_finding_status(self):
        findings = [
            {"finding_status": "ACTIVE"},
            {"finding_status": "CONFIRMED"},
            {"finding_status": "ACTIVE"},
            {"finding_status": "REJECTED"},
        ]
        counts = _count_by_key(findings, "finding_status")
        self.assertEqual(counts["ACTIVE"], 2)
        self.assertEqual(counts["CONFIRMED"], 1)
        self.assertEqual(counts["REJECTED"], 1)


class TestReportTruthTracking(unittest.TestCase):
    """Verify that generate_report_payload includes status and evidence_kind breakdowns."""

    def test_payload_includes_breakdowns(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            from sift_mcp.state import CaseStateManager
            state_path = Path(tmp_dir) / "state.json"
            manager = CaseStateManager(str(state_path))
            manager.load("CASE-TRUTH")
            manager.add_finding({
                "case_id": "CASE-TRUTH",
                "finding_type": "persistence",
                "artifact_type": "disk",
                "artifact_path": "/test",
                "tool_name": "test",
                "execution_id": "E-001",
                "iteration": 1,
                "evidence_kind": "observation",
                "finding_status": "ACTIVE",
                "confidence": 0.9,
                "description": "test finding",
            })

            result = generate_report_payload(
                case_id="CASE-TRUTH",
                state_manager=manager,
                sigma_scan_fn=lambda case_id: {
                    "status": "ok", "total_hits": 0,
                    "critical_count": 0, "high_count": 0,
                    "summary_markdown": "",
                },
                coverage_fn=lambda case_id: {
                    "covered_tactics": [], "uncovered_tactics": [],
                    "coverage_percent": 0.0, "suggested_next_tools": {},
                },
                reports_root=tmp_dir,
            )

            self.assertIn("status_breakdown", result)
            self.assertIn("evidence_kind_breakdown", result)
            self.assertEqual(result["status_breakdown"]["ACTIVE"], 1)
            self.assertEqual(result["evidence_kind_breakdown"]["OBSERVATION"], 1)

    def test_html_shows_no_confirmed_banner_when_none_confirmed(self):
        payload = {
            "case_id": "CASE-NONE",
            "summary": {"findings_count": 2, "unresolved_discrepancies": 0},
            "sigma_scan": {"total_hits": 0, "critical_count": 0, "high_count": 0, "summary_markdown": ""},
            "coverage": {"coverage_percent": 0, "covered_tactics": [], "uncovered_tactics": [], "suggested_next_tools": {}},
            "top_findings": [
                {"finding_id": "F-001", "finding_status": "ACTIVE", "confidence": 0.8, "tool_name": "test", "description": "lead"},
            ],
            "open_questions": [],
            "status_breakdown": {"ACTIVE": 2},
            "evidence_kind_breakdown": {"OBSERVATION": 2},
            "report_path": "/tmp/report.html",
        }
        html_text = render_report_html(payload)
        self.assertIn("No Structurally Confirmed Findings", html_text)
        self.assertIn("Top Active Leads", html_text)
        self.assertIn("Top Confirmed Findings", html_text)

    def test_html_shows_confirmed_section_when_present(self):
        payload = {
            "case_id": "CASE-CONF",
            "summary": {"findings_count": 2, "unresolved_discrepancies": 0},
            "sigma_scan": {"total_hits": 0, "critical_count": 0, "high_count": 0, "summary_markdown": ""},
            "coverage": {"coverage_percent": 50, "covered_tactics": [], "uncovered_tactics": [], "suggested_next_tools": {}},
            "top_findings": [
                {"finding_id": "F-001", "finding_status": "CONFIRMED", "confidence": 0.95, "tool_name": "test", "description": "confirmed finding"},
                {"finding_id": "F-002", "finding_status": "ACTIVE", "confidence": 0.7, "tool_name": "test", "description": "lead finding"},
            ],
            "open_questions": [],
            "status_breakdown": {"CONFIRMED": 1, "ACTIVE": 1},
            "evidence_kind_breakdown": {"HYPOTHESIS": 1, "OBSERVATION": 1},
            "report_path": "/tmp/report.html",
        }
        html_text = render_report_html(payload)
        self.assertNotIn("No Structurally Confirmed Findings", html_text)
        self.assertIn("Top Confirmed Findings", html_text)
        self.assertIn("Top Active Leads", html_text)
        self.assertIn("Findings Status Breakdown", html_text)


if __name__ == "__main__":
    unittest.main()
