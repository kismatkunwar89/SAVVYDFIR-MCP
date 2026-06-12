# Accuracy Report

**SAVVYDFIR-MCP - FIND EVIL! Hackathon 2026**

This report documents the accuracy of SAVVYDFIR-MCP across five independent blind cases,
each run **blind** (ground truth never on the workstation). Metrics follow the
definitions in [`eval-methodology.md`](eval-methodology.md). Per-run scores come
from `scripts/eval/baselines/*.json`; full run artifacts (report, graph,
hash-chained audit) are under [`agent-execution-logs/`](agent-execution-logs/).

> **When these numbers were measured (read this first).** The five blind-case runs,
> recall, and TP/FP baselines below were measured on the **judged `v1.1.1` engine** -
> *before* several core features shipped in `v1.2.0` (the native file-access extractors -
> Recycle Bin / PowerShell history / scheduled tasks - durable artifact reuse, the
> case-insensitive / UTF-16 mount fix, and experimental triage-layout detection). These
> scores therefore reflect the `v1.1.1` baseline and have **not** yet been re-scored against
> `v1.2.0`. The newer features are additive and backward-compatible; re-scoring on `v1.2.0`
> is expected to maintain or improve coverage, but until a fresh blind run is published, treat
> the figures here as the `v1.1.1` baseline, not a `v1.2.0` measurement.

---

## 1. Method (summary)

- **Blind evaluation - two inputs, two phases, they never touch.** Each case is
  investigated autonomously from a single `manifest.json` (disk/memory paths, taxonomy,
  keywords, incident date). `start_investigation(manifest_path)` (`server.py`) and every
  forensic tool read **only** the case evidence and that manifest. The investigation is
  *blind* because **the engine never reads any ground-truth file** - verified: `sift_mcp/`
  loads `attack_routing.yaml`, artifact-FK, and `anti_patterns.yaml`, but **never**
  `scripts/eval/ground_truth/`.
- **Ground truth is applied post-hoc, by the scorer only.** The answer keys
  (`scripts/eval/ground_truth/<CASE>.yaml`) are now **published in this repo for
  verifiability** - they are *not* hidden; blindness comes from the engine not reading them,
  not from concealment. Anyone can re-score a run:
  `python scripts/eval/gt_match_scorer.py scripts/eval/ground_truth/<CASE>.yaml <report.json>`.
- **Scorer.** `gt_match_scorer.py` matches the agent's findings to the answer key on
  distinctive anchors (rejecting generic tokens), and reports recall, *scored* hallucinations,
  and investigative-question coverage.
- Definitions of TP / FP / FN / Hallucination are in `eval-methodology.md` §2.

---

## 2. Results - 5 independent blind cases

> **Column legend.** **Recall** = ground-truth items the agent found ÷ total ground-truth items (coverage).
> **Hallucinations** = *scored* fabrications (reported findings with no support in the evidence).
> **CONFIRMED** = the gated subset of findings that cleared evidence-provenance (resolvable
> `execution_id` + ≥2 independent sources + ruled-out alternative) - **not** the finding total. Each case
> records hundreds of ACTIVE *leads*; CONFIRMED counts only the court-defensible conclusions, so a low
> CONFIRMED count next to high recall is expected and correct - they measure different things
> (evidentiary strength vs coverage).

| Case | Scenario / OS | Recall (TP/GT) | Hallucinations | Eval-target coverage | CONFIRMED |
|------|---------------|----------------|----------------|----------------------|-----------|
| ROCBA-2020-FREDS-LAPTOP | insider IP theft (Windows) | **90%** | 0 | - | 3 |
| LONEWOLF-2018-DESKTOP-PM6C56D | mass-shooting plot (Windows) | **91.7%** (11/12) | 0 | 1/6 | 2 |
| NIST-DATALEAK-2015-PC | insider data leak (Windows, disk-only) | **60%** (9/15) | 0 | 4/6 | 4 |
| ALI-WEBSERVER-WIN-L0ZZQ76PMUF | web-server breach (Win Server 2008) | **92.3%** (12/13) | 0 | 7/8 | 2 |
| NIST-HACKINGCASE-2004-MREVIL | war-driving / credential theft (Win XP) | **86.7%** (13/15) | 0 | 5/6 | 3 |

**Headline: ~84% mean recall, 0 *scored* hallucinations across all five cases.** A *scored
hallucination* is a reported finding that asserts an artifact or event with no support in the
evidence; across every finding the scorer matched against ground truth, none were fabrications.
This is measured on the **scored** output - it is **not** a claim that all of each case's hundreds of
ACTIVE leads were independently artifact-verified. CONFIRMED is the gated subset: every CONFIRMED
finding is backed by ≥2 independent corroborating sources and a ruled-out benign alternative (the
evidence-provenance gate; see `eval-methodology.md` §3). ACTIVE findings are reported as *leads*,
not assertions of fact.

**Measurement caveats (read this before trusting the headline).** These five blind evaluations are
Windows-only (Sonnet 4.6, judged `v1.1.1` engine), with recall from 60% to 92.3%. Ground-truth keys
are non-exhaustive, so **precision is not measured**: findings without a GT match stay *unscored*,
not false positives. "0 scored hallucinations" means **no scoreable finding shared a distinctive
anchor with a published known-negative** (~a few per case) - the automated scorer does **not**
independently verify every cited artifact or rebut every plausible-but-wrong inference. Most findings
remain **ACTIVE** leads for human review; only a small corroborated subset reaches **CONFIRMED** (the
CONFIRMED gate bounds *what is elevated to court-defensible claims*; the hallucination metric is a
separate, narrower bar). Matching uses project-authored distinctive-anchor rules and can over- or
under-credit when an identifier appears out of context. The scorer and keys are **published for
independent re-scoring**, but were developed by the project; the Ali Hadi key relies on reconciled
community sources, not an official answer key. These results describe **performance on this corpus -
not a general zero-error guarantee.**

---

## 3. Per-case notes (honest coverage)

- **ROCBA / LONEWOLF / ALI (90-92%)** - Windows cases that align with the
  framework's filesystem/registry/memory extractors. LONEWOLF's low
  eval-target coverage (1/6) is an honest *intent-narrative* breadth gap
  (document/email content not extracted), recorded rather than hidden.
- **NIST Data-Leakage (60%, disk-only)** - first disk-only case; the
  memory-conditional gate held (no brick). False negatives cluster on email
  (OST), Google-Drive client DB, and CD-R UDF carving - artifact classes outside
  the current extractor set (a documented coverage gap, not a fabrication).
- **NIST Hacking Case (86.7%, Windows XP, 2004)** - validates the framework on a
  legacy image; carried by prefetch + registry + filesystem. The two FNs are
  capability gaps (pcap-content parsing, AV scanning), not XP-format failures.

---

## 4. Honesty properties

- **Zero *scored* hallucinations.** Measured against ground truth, no reported finding
  asserted an artifact/event absent from the evidence. This is a property of the *scored*
  output, not an automatic guarantee for every ACTIVE lead. The CONFIRMED tier is what
  carries the hard gate: a finding cannot be CONFIRMED without a resolvable `execution_id`
  (real `audit.jsonl` row) + ≥2 independent sources + a ruled-out alternative. Single-source
  findings stay ACTIVE leads (reported as leads, not facts).
- **Gaps are documented, never faked.** Missing artifacts are recorded as
  documented-absence; the coverage gate blocks reporting until the mandatory
  detectors actually ran.
- **Reproducible.** Re-score any run with
  `scripts/eval/gt_match_scorer.py <ground_truth>.yaml <report.json>`; structural
  integrity guards are exercised by `tests/` (e.g. `test_evidence_integrity_bypass.py`,
  `test_confirmed_integrity.py`).

### Evidence integrity (architectural, not prompt-based)

Evidence is protected by code, not by asking the model to behave. Three mechanisms enforce it:

1. **Read-only enforcement.** `SafeRunner` validates every command against `DENY_PATHS`;
   any write/destructive operation targeting `/evidence/` or `/mnt/` is blocked before
   execution (`subprocess.run(shell=False)`, path validation + deny list). The model cannot
   prompt its way past this - it is a hard gate in the server, exercised by
   `tests/test_evidence_integrity_bypass.py`.
2. **Hash verification at start and end.** The investigation verifies evidence hashes when it
   begins and again when it ends; a mismatch raises a CRITICAL alert (see
   `docs/architecture.md` "Evidence Integrity Model"), so silent tampering or accidental
   modification surfaces in the audit trail rather than passing unnoticed.
3. **Provenance gate.** A CONFIRMED finding's `source_execution_id` must resolve to a real
   `audit.jsonl` row in the current ledger; inherited/placeholder/auto-generated IDs are
   auto-demoted (`tests/test_confirmed_integrity.py`). This ties every court-defensible claim
   back to a logged, hash-chained tool execution.

Net effect: source evidence is immutable to the agent, and every elevated conclusion is
traceable to a verifiable execution record - the integrity properties are guaranteed
structurally, independent of model behavior.

*Recall = granular ground-truth coverage. ROCBA predates audit-log retention, so
its execution-log directory ships report/graph/json without `audit.jsonl`.*
