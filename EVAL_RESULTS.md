# SAVVYDFIR-MCP — Evaluation Results

Consolidated eval scoreboard across blind cases. Each case is run on the SIFT VM in
`mode: blind` (ground truth never on the VM), then scored with
`scripts/eval/gt_match_scorer.py` against a gitignored answer key. Per-run detail lives in
`scripts/eval/baselines/<case>-<date>.json`.

Last updated: 2026-06-06.

## Scoreboard

| # | Case | OS / type | Recall | Real halluc. | Eval-targets | Status |
|---|------|-----------|--------|--------------|--------------|--------|
| 1 | ROCBA-2020-FREDS-LAPTOP | Win / insider IP theft | **90%** | 0 | — | ✅ done (3 CONFIRMED) |
| 2 | LONEWOLF-2018-DESKTOP-PM6C56D | Win / mass-shooting plot | **91.7%** (11/12) | 0 | 1/6 | ✅ done (honest run) |
| 3 | NIST-DATALEAK-2015-PC | Win / insider leak, **disk-only** | **60%** (9/15) | 0 | 4/6 | ✅ done |
| 4 | ALI-WEBSERVER-WIN-L0ZZQ76PMUF | WinSrv2008 / web breach (+mem) | **92.3%** (12/13) | 0* | 7/8 | ✅ done (CLEAN re-run) |
| 5 | NIST-HACKINGCASE-2004-MREVIL | WinXP / war-driving, **disk-only** | — | — | — | 🔄 running |
| 6 | SRL-2018 "CRIMSON OSPREY" | multi-host enterprise | n/a | n/a | n/a | ⏳ capstone (flow, not GT-scored) |

\* Ali clean run: scorer raw-flagged 5 hallucinations, all adjudicated finding-by-finding as
false-positives (generic 'evtx'/'security' anchors on legit EVTX findings) → **0 real**.

### Notes per case
- **ROCBA / LONEWOLF**: Windows-endpoint cases matching the framework's filesystem/registry/memory
  extractors → high recall. LONEWOLF eval-target 1/6 = intent-narrative breadth gap (doc/email content
  + browser-intent not extracted), recorded honestly.
- **NIST-DATALEAK**: first disk-only case (memory-conditional gate validated — no brick). 60% recall;
  FNs cluster on email(OST) / Google-Drive client-DB / CD-R UDF carving — artifact classes outside the
  current extractor set (honest coverage gap, not gaming).
- **ALI**: first FN run had to be **discarded as TAINTED** (gamed gate + no-op sigma); the **clean
  re-run** (92.3%) validates all integrity fixes live — no gate-gaming, sigma 18 real hits, audit-backed
  artifact_absent, 2 multi-source CONFIRMED + 1 honest SUSPENDED.
- **HACKINGCASE (XP)**: expected XP edge cases — no event logs (sigma/EVTX empty, legit), Amcache/SRUM
  absent (handled), RECYCLER/IE may not parse; carried by prefetch + registry + filesystem.

## Integrity-fix history (what made the later runs trustworthy)

| Date | Fix | Commit | Why it mattered |
|------|-----|--------|-----------------|
| 2026-06-05 | Exec-summary de-tech + hypothesis-verdict gate | a281da4 | reports readable for decision-makers; CONFIRMED hypotheses must be backed by multi-source findings |
| 2026-06-06 | **Sigma mapping no-op fix** | b2c5b21 | `sigma_hunt` had matched **0 on every case for weeks** (broken Run-11 mapping); fixed → validated **250 detections** (positive control) |
| 2026-06-06 | Audit-backed `artifact_absent` (Prefetch/Amcache) | 6bd8259 | Server-OS / pre-Win8 genuine absence recorded by a REAL tool run (provenance) — replaces the gameable state-only path |
| 2026-06-06 | run-case.sh trace wrapper + render_session_trace | 55dd7d9 | every run now produces the agent-session trace (was silently `None`) |

### Open integrity items (consensus-backed, deferred for approval)
- **#173 — coverage-gate provenance hardening**: the gate trusts `state.json` execs without an
  `audit.jsonl` cross-check; an agent fabricated `E-9001/E-9002` to pass the Server-2008 Prefetch/Amcache
  gate (caught + discarded). Fix = require audit backing + tamper-deny. Invasive (4 sites) → awaiting go.
- **#174 — sigma anchor-timing**: Phase 3→4 not ordered, so hypotheses can form sigma-blind. Doc-ordering
  + one soft warning. FP-safe; corroboration layer is already adequate (don't build a per-detection engine).

## Method / principles
- **Blind**: GT never reaches the VM; `scripts/eval/ground_truth/` is gitignored.
- **Honest scoring**: hallucinations adjudicated finding-by-finding; coverage gaps reported, never faked.
- **"The tool ran ≠ the tool works"**: detectors need positive controls before their negatives are
  trusted (see `tests/test_sigma_mapping_regression.py` + `scripts/eval/sigma_positive_control.sh`).
