# Evaluation Methodology

**SAVVYDFIR-MCP — FIND EVIL! Hackathon 2026**

This document defines how accuracy is measured: what counts as a true positive,
false positive, false negative, and hallucination, and how runs are scored. Results
are in [`accuracy-report.md`](accuracy-report.md); datasets in
[`dataset-documentation.md`](dataset-documentation.md).

---

## 1. Blind evaluation protocol

1. Each case is investigated **autonomously** from a `manifest.json` (evidence paths
   + taxonomy) on the SANS SIFT workstation. Minimal human interaction.
2. The **ground-truth answer key** is authored without LLM involvement (from the
   dataset's official answer key, published walkthroughs, or forensic report) and
   stored **analyst-side only** at `scripts/eval/ground_truth/<case>.yaml`. This
   directory is gitignored and is **never present on the workstation** — the run is
   blind.
3. After the run, the produced `report.json` is scored against the answer key by
   `scripts/eval/gt_match_scorer.py`.

---

## 2. Definitions

| Term | Definition |
|------|------------|
| **True Positive (TP)** | A ground-truth finding the agent surfaced, matched on a *distinctive* anchor (case-specific token; generic tokens are rejected by the scorer). |
| **False Negative (FN)** | A ground-truth finding the agent did not surface. |
| **Hallucination** | An OBSERVATION-class finding whose cited artifact does not exist or does not support the claim, OR a finding matching a ground-truth **known-negative** (an asserted-absent fact). |
| **Recall** | TP / (TP + FN) — granular ground-truth coverage. |
| **Eval-target coverage** | Fraction of the case's high-level investigative questions answered (the "why/intent", distinct from granular recall). |

Precision is reported as N/A because the ground-truth keys are non-exhaustive (a
finding with no GT match is "unscored", not automatically a false positive).

---

## 3. Confidence / CONFIRMED gate

The framework promotes a finding to **CONFIRMED** only when it clears three
code-enforced invariants (see `README.md` → Investigation & Decision Flow):

1. **Provenance** — its `execution_id` resolves to a real `audit.jsonl` row.
2. **Corroboration** — ≥ 2 independent artifact sources agree (single source stays
   an ACTIVE lead).
3. **Alternative ruled out** — the strongest benign explanation is recorded with a
   specific refuting observation.

This is why the reported hallucination count is 0: a finding cannot be elevated to a
court-defensible claim without backing.

---

## 4. Reproducing a score

```bash
# After a run produces reports/<case>/report.json:
python3 scripts/eval/gt_match_scorer.py \
    scripts/eval/ground_truth/<case>.yaml \
    reports/<case>/report.json
```

Recorded per-run results are committed at `scripts/eval/baselines/<case>-<date>.json`,
and each run's full artifacts (report, graph, and — for 4/5 cases — the hash-chained `audit.jsonl`; ROCBA predates audit retention) are under
[`agent-execution-logs/`](agent-execution-logs/).

---

## 5. Structural integrity guards

Beyond accuracy, the test suite exercises the honesty invariants directly, e.g.:

- `tests/test_evidence_integrity_bypass.py` — a CONFIRMED finding cannot be created
  without resolvable provenance.
- `tests/test_confirmed_integrity.py` — the corroboration + alternative-hypothesis
  invariants.
- `tests/test_sigma_mapping_regression.py` + `scripts/eval/sigma_positive_control.sh`
  — the detection engine is validated against known-malicious input (a detector that
  silently matches nothing is caught, not trusted).

---

## 6. Scope note

A baseline-vs-baseline comparison against a no-MCP "raw tools" run, and a multi-host
enterprise corpus (SRL-2018), are supported by the framework but were **not executed**
for this submission. The reported numbers are the five independent blind cases only.
