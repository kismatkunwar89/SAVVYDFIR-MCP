"""Tests for the taxonomy-conditional file-access coverage gate (review 2026-06-03).

Proves the agnostic selector + the SEAM-2 overlay + escape A (documented-absence),
and the anti-hard-block guardrails (the whole point of the escapes):
  - selector keyed on dispute_type + Windows; unknown/non-Windows => overlay off.
  - gate ACCEPTS documented-absence (no_windows_volume / artifact_absent / no_data).
  - gate REJECTS real gaps (collection_failed / partial_collection) and
    failed-exec-without-token and audit-only-no-state-row.
  - successful collection satisfies.
"""

import unittest

from sift_mcp import reporting
from sift_mcp.reporting import (
    FILE_ACCESS_TOOL_SUFFIXES,
    build_file_access_selector_snapshot,
    evaluate_ir_coverage_gate,
    file_access_required,
    windows_in_scope,
)


def _exec(suffix, *, exit_code, summary, duration=1.0, hashed=True):
    return {
        "tool_name": f"disk.{suffix}",
        "exit_code": exit_code,
        "duration_seconds": duration,
        "outputs_summary": summary,
        "audit_completed_entry_hash": "abc123" if hashed else None,
    }


def _file_access_missing(result):
    return {
        m["tool"] for m in result["missing"]
        if m.get("classification") == "taxonomy_file_access"
    }


_REQUIRED = build_file_access_selector_snapshot(
    {"dispute_type": "intrusion_response", "os_in_scope": ["Windows 10/11"]}
)
_ALL5 = {f"disk.{s}" for s in FILE_ACCESS_TOOL_SUFFIXES}


class SelectorTest(unittest.TestCase):
    def test_predicate(self):
        self.assertTrue(file_access_required({"dispute_type": "intrusion_response", "os_in_scope": ["Windows 10/11"]}))
        self.assertTrue(file_access_required({"dispute_type": "ransomware", "os_in_scope": ["Windows Server 2019/2022"]}))
        self.assertFalse(file_access_required({"dispute_type": "credential_theft", "os_in_scope": ["Windows 10/11"]}))
        self.assertFalse(file_access_required({"dispute_type": "intrusion_response", "os_in_scope": ["Linux"]}))
        self.assertFalse(file_access_required({"dispute_type": "unknown", "os_in_scope": ["Windows 10/11"]}))
        self.assertFalse(file_access_required(None))

    def test_windows_predicate_guards(self):
        self.assertTrue(windows_in_scope("Windows 10/11"))
        self.assertTrue(windows_in_scope(["macOS", "Windows Server"]))
        self.assertFalse(windows_in_scope(None))
        self.assertFalse(windows_in_scope(123))
        self.assertFalse(windows_in_scope([None, 7]))


class GateOverlayTest(unittest.TestCase):
    def _gate(self, executions, selector=_REQUIRED):
        # sigma present so its own check doesn't matter; we only inspect file-access.
        return evaluate_ir_coverage_gate(
            findings=[], executions=executions,
            sigma_result={"status": "ok"}, selector=selector,
        )

    def test_overlay_off_when_not_required(self):
        # unknown dispute_type / legacy state -> no file-access entries at all
        for sel in (None, build_file_access_selector_snapshot({"dispute_type": "unknown", "os_in_scope": ["Windows 10/11"]})):
            res = self._gate([], selector=sel)
            self.assertEqual(_file_access_missing(res), set())

    def test_required_all_missing_when_none_ran(self):
        res = self._gate([])
        self.assertEqual(_file_access_missing(res), _ALL5)

    def test_documented_absence_satisfies(self):
        # each of the 3 documented-absence tokens satisfies (escape A -> no brick)
        execs = [
            _exec("extract_shellbags", exit_code=1, summary="status=error reason=no_windows_volume_at_image_path: ..."),
            _exec("extract_lnk_files", exit_code=0, summary="status=artifact_absent: nothing discovered"),
            _exec("extract_jump_lists", exit_code=0, summary="status=no_data: parsed clean, zero rows"),
            _exec("extract_browser_history", exit_code=0, summary="status=success merged 12 rows"),
            _exec("extract_registry_fileaccess", exit_code=0, summary="status=success merged 511 rows"),
        ]
        res = self._gate(execs)
        self.assertEqual(_file_access_missing(res), set())

    def test_real_gaps_still_block(self):
        # collection_failed / partial_collection are NOT documented-absence -> block
        execs = [
            _exec("extract_shellbags", exit_code=1, summary="status=collection_failed: parser failures"),
            _exec("extract_lnk_files", exit_code=1, summary="status=partial_collection: 2 parser failure(s)"),
            # failed exec with no whitelisted token -> still blocks
            _exec("extract_jump_lists", exit_code=1, summary="exit=1; JLECmd crashed"),
        ]
        res = self._gate(execs)
        miss = _file_access_missing(res)
        self.assertIn("disk.extract_shellbags", miss)
        self.assertIn("disk.extract_lnk_files", miss)
        self.assertIn("disk.extract_jump_lists", miss)

    def test_audit_only_no_state_row_blocks(self):
        # suffix never written to state.executions (parity failure) -> missing
        res = self._gate([_exec("extract_shellbags", exit_code=0, summary="status=success merged 5 rows")])
        miss = _file_access_missing(res)
        self.assertNotIn("disk.extract_shellbags", miss)   # the one with a row is satisfied
        self.assertIn("disk.extract_lnk_files", miss)       # the others (no row) still missing


if __name__ == "__main__":
    unittest.main()
