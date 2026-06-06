# Accuracy Report

**SAVVYDFIR-MCP — FIND EVIL! Hackathon 2026**

This report documents the accuracy of SAVVYDFIR-MCP across five public DFIR cases,
each run **blind** (ground truth never on the workstation). Metrics follow the
definitions in [`eval-methodology.md`](eval-methodology.md). Per-run scores come
from `scripts/eval/baselines/*.json`; full run artifacts (report, graph,
hash-chained audit) are under [`agent-execution-logs/`](agent-execution-logs/).

---

## 1. Method (summary)

- **Blind evaluation.** Each case is investigated autonomously from a
  `manifest.json`. Ground-truth answer keys live only on the analyst side
  (`scripts/eval/ground_truth/`, gitignored — never on the SIFT workstation).
- **Scorer.** `scripts/eval/gt_match_scorer.py` matches the agent's findings to
  the ground-truth answer key on distinctive anchors (rejecting generic tokens),
  and reports recall, hallucinations, and investigative-question coverage.
- Definitions of TP / FP / FN / Hallucination are in `eval-methodology.md` §2.

---

## 2. Results — 5 blind public cases

| Case | Scenario / OS | Recall (TP/GT) | Hallucinations | Eval-target coverage | CONFIRMED |
|------|---------------|----------------|----------------|----------------------|-----------|
| ROCBA-2020-FREDS-LAPTOP | insider IP theft (Windows) | **90%** | 0 | — | 3 |
| LONEWOLF-2018-DESKTOP-PM6C56D | mass-shooting plot (Windows) | **91.7%** (11/12) | 0 | 1/6 | 2 |
| NIST-DATALEAK-2015-PC | insider data leak (Windows, disk-only) | **60%** (9/15) | 0 | 4/6 | 4 |
| ALI-WEBSERVER-WIN-L0ZZQ76PMUF | web-server breach (Win Server 2008) | **92.3%** (12/13) | 0 | 7/8 | 2 |
| NIST-HACKINGCASE-2004-MREVIL | war-driving / credential theft (Win XP) | **86.7%** (13/15) | 0 | 5/6 | 3 |

**Headline: ~84% mean recall, 0 hallucinations across all five cases.** Every
CONFIRMED finding is backed by ≥2 independent corroborating sources and a ruled-out
benign alternative (the evidence-provenance gate; see `eval-methodology.md` §3).

---

## 3. Per-case notes (honest coverage)

- **ROCBA / LONEWOLF / ALI (90–92%)** — Windows cases that align with the
  framework's filesystem/registry/memory extractors. LONEWOLF's low
  eval-target coverage (1/6) is an honest *intent-narrative* breadth gap
  (document/email content not extracted), recorded rather than hidden.
- **NIST Data-Leakage (60%, disk-only)** — first disk-only case; the
  memory-conditional gate held (no brick). False negatives cluster on email
  (OST), Google-Drive client DB, and CD-R UDF carving — artifact classes outside
  the current extractor set (a documented coverage gap, not a fabrication).
- **NIST Hacking Case (86.7%, Windows XP, 2004)** — validates the framework on a
  legacy image; carried by prefetch + registry + filesystem. The two FNs are
  capability gaps (pcap-content parsing, AV scanning), not XP-format failures.

---

## 4. Honesty properties

- **Zero hallucinations** by construction: a finding cannot be CONFIRMED without a
  resolvable `execution_id` (real `audit.jsonl` row) + ≥2 independent sources +
  a ruled-out alternative. Single-source findings stay ACTIVE leads.
- **Gaps are documented, never faked.** Missing artifacts are recorded as
  documented-absence; the coverage gate blocks reporting until the mandatory
  detectors actually ran.
- **Reproducible.** Re-score any run with
  `scripts/eval/gt_match_scorer.py <ground_truth>.yaml <report.json>`; structural
  integrity guards are exercised by `tests/` (e.g. `test_evidence_integrity_bypass.py`,
  `test_confirmed_integrity.py`).

*Recall = granular ground-truth coverage. ROCBA predates audit-log retention, so
its execution-log directory ships report/graph/json without `audit.jsonl`.*
