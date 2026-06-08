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
| Wall-clock | 2026-06-07T23:32:23Z -> 2026-06-08T01:14:40Z (**~1h 42m**) |
| Tokens (total) | **63.3M** (output 523k · cache-write 2.39M · cache-read 60.4M) |
| Agent turns | 597 (context compacted multiple times; resumed from durable state) |
| Approx cost (Sonnet 4.6) | **~$35** (out $7.8 + cache-write $9.0 + cache-read $18.1) |
| Findings | **127** (2 CONFIRMED, 125 ACTIVE) |
| Executions | 165 |
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
`report.html` · `report.pdf` (8 pp) · `report.json` · `graph.html` · `graph.json` · `trace.html`
