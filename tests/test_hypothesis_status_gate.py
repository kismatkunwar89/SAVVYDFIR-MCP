"""Integrity gate for hunting-hypothesis verdicts + clean executive summary.

review 2026-06-05 (peer reviewer + peer reviewer + DeepSeek, unanimous):
 - A CONFIRMED/REFUTED hypothesis verdict must be backed by its linked findings
   clearing the SAME multi-source bar findings face. Unsupported verdicts
   downgrade to SUSPENDED. Closes the relocated gaming hole (hypothesis verdict
   was pure agent judgment).
 - The executive summary must carry NO internal identifiers (finding IDs,
   execution/audit IDs, raw MITRE codes, hypothesis ULIDs) - plain narrative for
   decision-makers; IDs live in the appendix.
"""
import re
import unittest

from sift_mcp.semantics import apply_hypothesis_status_gate
from sift_mcp.reporting import _render_executive_summary, _strip_internal_tokens


_MULTISOURCE_CONFIRMED = {
    "finding_status": "confirmed",
    "corroborated_by": ["F-010", "F-011"],
    "corroboration_outstanding": [],
}
_SINGLE_SOURCE_ACTIVE = {
    "finding_status": "active",
    "corroborated_by": [],
}
_CONFIRMED_BUT_OUTSTANDING = {
    "finding_status": "confirmed",
    "corroborated_by": ["prefetch"],          # 1 source
    "corroboration_outstanding": ["amcache"],  # not cleared
}


class _FakeState:
    def __init__(self, findings):
        self._f = findings

    def get_finding(self, fid):
        return self._f.get(str(fid))


class HypothesisVerdictGateTests(unittest.TestCase):
    def setUp(self):
        self.state = _FakeState({
            "F-001": _MULTISOURCE_CONFIRMED,
            "F-002": _SINGLE_SOURCE_ACTIVE,
            "F-003": _CONFIRMED_BUT_OUTSTANDING,
        })

    def test_confirmed_with_multisource_finding_stays_confirmed(self):
        h = apply_hypothesis_status_gate(
            {"status": "CONFIRMED", "attack_class": "exfil", "related_finding_ids": ["F-001"]},
            self.state,
        )
        self.assertEqual(h["status"], "CONFIRMED")
        self.assertNotIn("status_gate_reason", h)

    def test_confirmed_with_single_source_downgrades(self):
        h = apply_hypothesis_status_gate(
            {"status": "CONFIRMED", "attack_class": "keylogger", "related_finding_ids": ["F-002"]},
            self.state,
        )
        self.assertEqual(h["status"], "SUSPENDED")
        self.assertIn("downgraded_from_CONFIRMED", h["status_gate_reason"])

    def test_confirmed_with_outstanding_corroboration_downgrades(self):
        h = apply_hypothesis_status_gate(
            {"status": "CONFIRMED", "attack_class": "persistence", "related_finding_ids": ["F-003"]},
            self.state,
        )
        self.assertEqual(h["status"], "SUSPENDED")

    def test_confirmed_with_no_linked_findings_downgrades(self):
        h = apply_hypothesis_status_gate(
            {"status": "CONFIRMED", "attack_class": "lateral", "related_finding_ids": []},
            self.state,
        )
        self.assertEqual(h["status"], "SUSPENDED")

    def test_refuted_contradicted_by_confirmed_finding_downgrades(self):
        # A REFUTED verdict linking to a multi-source CONFIRMED finding (attack
        # evidence IS present) is self-contradictory.
        h = apply_hypothesis_status_gate(
            {"status": "REFUTED", "attack_class": "exfil", "related_finding_ids": ["F-001"]},
            self.state,
        )
        self.assertEqual(h["status"], "SUSPENDED")
        self.assertIn("downgraded_from_REFUTED", h["status_gate_reason"])

    def test_refuted_absence_based_is_preserved(self):
        # Refutation with no supporting findings is legitimate.
        h = apply_hypothesis_status_gate(
            {"status": "REFUTED", "attack_class": "ransomware", "related_finding_ids": []},
            self.state,
        )
        self.assertEqual(h["status"], "REFUTED")

    def test_non_terminal_statuses_untouched(self):
        for st in ("ACTIVE", "INVESTIGATING", "SUSPENDED"):
            h = apply_hypothesis_status_gate(
                {"status": st, "attack_class": "x", "related_finding_ids": ["F-002"]},
                self.state,
            )
            self.assertEqual(h["status"], st)

    def test_gate_does_not_mutate_input(self):
        original = {"status": "CONFIRMED", "attack_class": "x", "related_finding_ids": ["F-002"]}
        apply_hypothesis_status_gate(original, self.state)
        self.assertEqual(original["status"], "CONFIRMED")


class ExecutiveSummaryTokenHygieneTests(unittest.TestCase):
    def _payload(self):
        return {
            "case_id": "CASE-EXEC",
            "triage_status": "COMPLETE_WITH_GAPS",
            "status_breakdown": {"CONFIRMED": 1, "ACTIVE": 5},
            "summary": {"confirmed_count": 1, "unresolved_discrepancies": 0},
            "sigma_scan": {},
            "coverage": {},
            "activity_thread": {},
            "analysis_lanes": [{"lane_id": "synthesis_corroboration", "status": "COMPLETE",
                                "summary": "Temporal cluster (E-158) and compare_disk_and_memory (E-143) produced F-088."}],
            "top_confirmed_findings": [
                {"finding_id": "F-088", "confidence": 0.97,
                 "mitre_tactic": "TA0010", "mitre_technique": "T1567.002",
                 "corroborated_by": ["F-1", "F-2", "F-3", "F-4", "F-5"],
                 "description": "Multi-cloud exfiltration corroborated by five sources (see F-088)."},
            ],
            "hypotheses": [
                {"hypothesis_id": "01KTD1GC8QN71AZ4GVBX5JH4R6", "status": "CONFIRMED",
                 "attack_class": "Multi-cloud data exfiltration"},
                {"hypothesis_id": "01KTD1GC8RRPQGW65Z8D0Q37CX", "status": "SUSPENDED",
                 "attack_class": "Keylogger surveillance"},
            ],
        }

    def test_exec_brief_contains_no_internal_tokens(self):
        out = _render_executive_summary(self._payload())
        self.assertFalse(re.search(r"\bF-\d+\b", out), "finding IDs leaked into exec summary")
        self.assertFalse(re.search(r"\bE-\d+\b", out), "execution IDs leaked into exec summary")
        self.assertFalse(re.search(r"\bTA\d{4}\b", out), "raw MITRE tactic code leaked")
        self.assertFalse(re.search(r"\bT\d{4}(?:\.\d{3})?\b", out), "raw MITRE technique code leaked")
        self.assertNotIn("01KTD1GC8QN71AZ4GVBX5JH4R6", out, "hypothesis ULID leaked")
        self.assertNotIn("compare_disk_and_memory", out, "internal tool name leaked")

    def test_hunt_closure_uses_attack_class_labels(self):
        out = _render_executive_summary(self._payload())
        self.assertIn("Hunt closed:", out)
        self.assertIn("Multi-cloud data exfiltration", out)
        self.assertIn("Keylogger surveillance", out)
        self.assertIn("1 confirmed", out)
        self.assertIn("1 suspended", out)
        self.assertNotIn("Hunt verdicts:", out)  # old ULID line is gone

    def test_strip_internal_tokens_tidies_punctuation(self):
        self.assertEqual(_strip_internal_tokens("ran (F-088) and E-143"), "ran and")
        self.assertEqual(_strip_internal_tokens("technique T1567.002 used"), "technique used")


if __name__ == "__main__":
    unittest.main()
