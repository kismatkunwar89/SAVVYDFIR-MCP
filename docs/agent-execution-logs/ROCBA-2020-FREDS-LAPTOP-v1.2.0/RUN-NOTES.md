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
| Approx cost (Sonnet 4.6) | ~$30 (out $7.8 + cache-w $9.0 + cache-r $18.1) |
| Findings | **127** (2 CONFIRMED, 125 ACTIVE) |
| Executions | 165 |
| Hypotheses | **5 - 4 CONFIRMED, 1 SUSPENDED** (all resolved) |
| Heuristic CTX refs cited | 6 |

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
