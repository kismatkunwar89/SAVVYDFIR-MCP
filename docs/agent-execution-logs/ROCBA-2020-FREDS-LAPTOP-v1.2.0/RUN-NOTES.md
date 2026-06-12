# ROCBA-2020-FREDS-LAPTOP - v1.2.0 re-run (showcase)

Blind re-run of the Fred Rocba IP-theft case on the **`v1.2.0`** engine, to exercise the
new native file-access extractors (Recycle Bin / PowerShell history / scheduled tasks),
durable reuse, and the case-insensitive/UTF-16 mount handling. The **v1.1.1 judged baseline**
for this case remains under [`../ROCBA-2020-FREDS-LAPTOP/`](../ROCBA-2020-FREDS-LAPTOP/) - this
folder is an additional showcase run, **not** a replacement of the judged baseline.

## Inputs
- **Engine**: `v1.2.0` · **Mode**: blind · **Taxonomy**: `data_exfiltration` (victim, Windows 10)
- **Evidence**: `rocba-cdrive.e01` (23.6 GB disk) + `rocba-memory.raw` (5.68 GB)
- **Goal**: the case's 5 questions - what IP was accessible, what was stolen, where transferred, how, when.

## Run stats
| Metric | Value |
|---|---|
| Wall-clock (analysis) | 2026-06-07T23:32:23Z -> 2026-06-08T01:14:40Z (**~1h 42m**) |
| Tokens (total) | **63.3M** (output 523k · cache-write 2.39M · cache-read 60.4M) |
| Agent turns | 597 (context compacted multiple times; resumed from durable state) |
| Approx cost (Sonnet 4.6) | **~$35** (out $7.8 + cache-write $9.0 + cache-read $18.1) |
| Findings | **127** (2 CONFIRMED, 125 ACTIVE) |
| Executions | **166** tool-execution records (`report.json:executions_count`) |
| Hypotheses | **5 - 4 CONFIRMED, 1 SUSPENDED** (all resolved) |
| Heuristic CTX refs cited | 6 |

### How the cost is derived (reason behind the numbers)
Of the 63.3M total tokens, **~95% is cache-read** (60.4M). That is expected, not waste: the
investigation ran **597 turns**, and on every turn the model re-reads the cached conversation +
tool context. Anthropic prices those tiers very differently, which is why a 63M-token run is only
~$35, not hundreds:

| Tier | Tokens | Rate (Sonnet 4.6) | Cost |
|------|--------|-------------------|------|
| Output (generated) | 523k | $15 / M | $7.8 |
| Cache-write (new context cached) | 2.39M | $3.75 / M | $9.0 |
| Cache-read (re-read cached context) | 60.4M | $0.30 / M | $18.1 |
| Fresh input | ~0 | $3 / M | ~$0 |
| **Total** | **63.3M** | | **~$35** |

- **Cache-read dominates because the per-turn context is re-read, not re-sent fresh** - it is billed
  ~10x cheaper than fresh input ($0.30 vs $3 per M), so the bulk of the token count is the cheapest tier.
- **Context compaction (at least twice on this run) caps cache-read growth** - it trims the window so
  each turn does not re-read an ever-growing history; the framework resumes from durable `state.json`,
  so compaction loses no progress.
- **Output is the smallest tier (523k)** - the model writes findings/queries tersely; the expensive
  per-token tier is the least-used one.
- **Opus would be the same token shape but ~5x the price** (~$175), which is why the eval used Sonnet 4.6.

## Confirmed hypotheses (attack narrative)
- pre-planned physical intrusion via a staged account
- multi-channel exfiltration (USB + cloud + lateral movement)
- BitLocker recovery-key exfiltration
- multi-method anti-forensics / evidence destruction

## Tool coverage (v1.2.0 features verified live)
- New native extractors **all fired**: `extract_recycle_bin`, `extract_powershell_history`,
  `extract_scheduled_tasks`, plus `extract_registry_fileaccess`.
- Mandatory: `sigma_hunt` (x2), `compare_disk_and_memory` (10 checks), `detect_injection`.

## GT evaluation (honest)
Scored with `scripts/eval/gt_match_scorer.py` against `scripts/eval/ground_truth/ROCBA-2020-FREDS-LAPTOP.yaml`:

| | v1.1.1 baseline | **v1.2.0 (this run)** |
|---|---|---|
| Recall | 90% (9/10 TP) | **90% (9/10 TP)** |
| Miss (FN) | GT-007 (Edge browser-download specifics) | **GT-007 (same)** |
| Hallucinations | 0 | 0 |
| eval-target coverage | 3/6 | 3/6 |

**Measured GT recall did NOT improve - both are 90% with 0 hallucinations and both miss the
same GT-007** (browser-download specifics; the new artifacts don't touch that browser gap). The
v1.2.0 gain is **qualitative, not GT-scored**: 4 confirmed hypotheses vs 3, all hypotheses
resolved (vs 10 left open), a fuller exfil + anti-forensics narrative, and the new artifacts
exercised - at the same 90% / 0-hallucination bar.

## Output files (this folder)
`report.html` · `report.pdf` (8 pp) · `report.json` · `graph.html` · `graph.json` · `trace.html` · `audit.jsonl`

## Provenance & restoration (full disclosure)

So a reviewer can trust this folder without guessing how it was assembled:

- **The `audit.jsonl` is the genuine June-7/8 run ledger, restored from retained VM storage.**
  The hash-chained ledger was produced by this run on `2026-06-07/08`, retained on the
  workstation at `~/demo-assets/rocba-audit.jsonl`, and committed to the repo on
  **2026-06-12** (commit `cfd787a`). It was **restored, not regenerated** - the byte content
  is the original run output.
- **Integrity is independently verifiable.** The ledger has **483 rows**, the chain validates
  with **0 `entry_hash` recompute mismatches and 0 broken links** under the canonical algorithm
  in `sift_mcp/audit.py` (see the verifier in [`../README.md`](../README.md)), and it records
  **5 correction events**.
- **The committed `report.html` is cryptographically bound to the ledger.** Its SHA-256
  (`0f02f915…a376a8`) matches the `artifact_hashes` seal written by execution **E-219**.
- **Post-analysis report regeneration is disclosed, not hidden.** Analysis ended ~`01:14:40Z`
  (the ledger's first `generate_report`, E-217, sealed the original `report.html` =
  `dbd294…953ab3`). The committed report is from a **second** `generate_report` (E-219) at
  `02:00:22Z` that re-rendered the report after three review-approved presentation fixes
  (CONFIRMED-only provenance block, a Full Finding Index, and an "unconfirmed findings" metric
  relabel). The fixes changed **rendering only**, not the findings/state; the ledger records
  **both** generations, so the 46-minute gap between `01:14` analysis-end and the `02:00` final
  seal is accounted for in the log itself.
- **Count semantics (so the numbers reconcile).** The ledger contains **483 rows** and
  allocates **220 `execution_id`s** (`E-001`–`E-220`; a single tool call emits multiple rows -
  `started`/`completed`/`linked`/`context_bundle` - and a few warm-up IDs go unused). The
  **166** above is `report.json:executions_count` = the count of persisted tool-execution
  *records* in `state.json`. These three figures (483 / 220 / 166) measure different things and
  are not expected to be equal.
- **Scope limit, stated plainly.** Only artifacts whose SHA-256 the framework sealed into the
  ledger are cryptographically bound to it (here: the final `report.html`). `report.json`,
  `graph.*`, `trace.html`, and `report.pdf` are run outputs that are **not** independently
  hash-bound by this chain. For per-turn session timestamps and token usage, see `trace.html`,
  not the ledger.
