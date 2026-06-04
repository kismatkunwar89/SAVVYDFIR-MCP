"""Tests for the agnostic GT-match scorer (PART A, review 2026-06-04).

The defining requirement: a TP must rest on a DISTINCTIVE anchor (email / domain /
filename / CamelCase id / proper noun), never a generic DFIR/English/path word.
The scratch matcher's failure (GT "Natasha Romanoff" matched on "correlation")
must not recur.
"""
import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "gt_match_scorer", str(REPO / "scripts" / "eval" / "gt_match_scorer.py")
)
gms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gms)


class AnchorExtractionTests(unittest.TestCase):
    def test_generic_words_are_not_anchors(self):
        a = gms.distinctive_anchors("correlation activity evidence execution lateral movement file")
        self.assertEqual(a, set(), f"generic words must not anchor: {a}")

    def test_path_components_are_not_anchors(self):
        a = gms.distinctive_anchors(r"C:\Users\x\AppData\Roaming\Microsoft\Windows\CurrentVersion\Software")
        self.assertEqual(a, set(), f"ubiquitous path components must not anchor: {a}")

    def test_distinctive_tokens_extracted(self):
        a = gms.distinctive_anchors(
            "sdelete.exe ran; OpenSavePidlMRU and TypedPaths; "
            "crimsonguard@cobracommandcenter.com; Natasha Romanoff; T1021.001; EID 1102"
        )
        for expect in ("sdelete.exe", "sdelete", "opensavepidlmru", "typedpaths",
                       "crimsonguard@cobracommandcenter.com", "cobracommandcenter.com",
                       "romanoff", "natasha", "t1021.001", "eid1102"):
            self.assertIn(expect, a, f"missing distinctive anchor {expect!r} in {a}")

    def test_ubiquitous_apps_not_anchors(self):
        a = gms.distinctive_anchors("Firefox Edge Outlook iPhone OneDrive history default")
        self.assertEqual(a & {"firefox", "edge", "outlook", "iphone", "onedrive"}, set())


class ScoreTests(unittest.TestCase):
    GT = {
        "case_id": "T",
        "findings": [
            {"id": "G1", "finding_type": "defense_evasion",
             "value": "sdelete.exe run 7x", "location_key": "sdelete"},
            {"id": "G2", "finding_type": "attribution",
             "value": "Natasha Romanoff named", "location_key": "Natasha Romanoff"},
        ],
        "known_negatives": [
            {"artifact_type": "Browser",
             "value": "Firefox bookmark to asgardventurecapital.sharepoint.com"},
        ],
    }

    def test_strong_anchor_tp_and_generic_fn(self):
        findings = [
            # matches G1 on the distinctive filename
            {"finding_id": "F1", "evidence_kind": "OBSERVATION",
             "description": "Executed sdelete.exe wiping files"},
            # mentions 'correlation' only -> must NOT match G2 (Romanoff)
            {"finding_id": "F2", "evidence_kind": "INFERENCE",
             "description": "correlation across artifacts"},
        ]
        r = gms.score(self.GT, findings)
        verds = {x["gt_id"]: x["verdict"] for x in r["per_gt"]}
        self.assertEqual(verds["G1"], "TP")
        self.assertEqual(verds["G2"], "FN")  # 'correlation' is generic -> no match
        self.assertEqual(r["tp"], 1)
        self.assertEqual(r["fn"], 1)
        self.assertAlmostEqual(r["recall"], 0.5)

    def test_known_negative_hallucination_on_distinctive_anchor(self):
        findings = [
            {"finding_id": "F9", "evidence_kind": "OBSERVATION",
             "description": "User bookmarked asgardventurecapital.sharepoint.com as exfil"},
        ]
        r = gms.score(self.GT, findings)
        self.assertEqual(r["hallucination_count"], 1)

    def test_ubiquitous_does_not_trigger_hallucination(self):
        findings = [
            {"finding_id": "F9", "evidence_kind": "OBSERVATION",
             "description": "Firefox browser history reviewed"},  # 'firefox' ubiquitous
        ]
        r = gms.score(self.GT, findings)
        self.assertEqual(r["hallucination_count"], 0)

    def test_hypothesis_findings_not_scored(self):
        findings = [
            {"finding_id": "F1", "evidence_kind": "HYPOTHESIS",
             "description": "sdelete.exe maybe ran"},
        ]
        r = gms.score(self.GT, findings)
        self.assertEqual(r["tp"], 0, "HYPOTHESIS findings must not count as TP")


if __name__ == "__main__":
    unittest.main()
