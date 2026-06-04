"""Regression: ATT&CK coverage resolves tactic from technique (P1 #9, 2026-06-03).

Before the fix, compute_coverage_from_findings only read the explicit
``mitre_tactic`` column. A finding that recorded only ``mitre_technique`` (e.g.
F-094 lateral movement T1021.*) with a null tactic left its tactic UNCOVERED,
understating the report's ATT&CK matrix. The resolver now derives the tactic
from the routing catalog when mitre_tactic is absent; explicit mitre_tactic wins.
"""

import unittest

from sift_mcp import semantics as s


class TechniqueToTacticTests(unittest.TestCase):
    def _covered(self, findings):
        out = s.compute_coverage_from_findings(findings)
        return {t["id"] for t in out["covered_tactics"]}

    def test_subtechnique_resolves(self):
        self.assertIn("TA0008", self._covered([{"mitre_technique": "T1021.001"}]))

    def test_base_technique_resolves(self):
        self.assertIn("TA0008", self._covered([{"mitre_technique": "T1021"}]))

    def test_technique_with_trailing_name(self):
        self.assertIn("TA0006", self._covered([{"mitre_technique": "T1003.001 (LSASS)"}]))

    def test_explicit_tactic_id_wins(self):
        self.assertIn("TA0005", self._covered([{"mitre_tactic": "TA0005"}]))

    def test_explicit_tactic_name_resolves(self):
        self.assertIn("TA0008", self._covered([{"mitre_tactic": "Lateral Movement"}]))

    def test_null_everything_covers_nothing(self):
        self.assertEqual(
            self._covered([{"mitre_tactic": None, "mitre_technique": None}]), set()
        )

    def test_unknown_technique_safe(self):
        # garbage technique must not raise and must cover nothing
        self.assertEqual(self._covered([{"mitre_technique": "ZZZZ"}]), set())

    def test_resolver_helpers_direct(self):
        self.assertEqual(s._normalize_tactic_ids("TA0008"), {"TA0008"})
        self.assertEqual(s._normalize_tactic_ids("lateral movement"), {"TA0008"})
        self.assertIn("TA0008", s._tactics_from_technique("T1021.002"))


if __name__ == "__main__":
    unittest.main()
