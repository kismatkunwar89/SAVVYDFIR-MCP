# Agent Execution Logs

This directory holds the complete, unedited artifacts the framework produced on
its blind benchmark investigations, so reviewers can inspect the agent's decision
trail and outputs without running the tool themselves.

## Blind benchmark cases

The five independent blind cases used to validate the framework each have their full run
artifacts under `docs/agent-execution-logs/<case>/`. All five were run **blind**
(the investigation engine never reads ground truth; keys are published for re-scoring) with **zero scored hallucinations**.

| Case | Scenario / OS | Recall | Findings | CONFIRMED | Artifacts |
|------|---------------|--------|----------|-----------|-----------|
| `ROCBA-2020-FREDS-LAPTOP` | insider IP theft (Windows) | 90% | 107 | 3 | report·graph·json |
| `LONEWOLF-2018-DESKTOP-PM6C56D` | mass-shooting plot (Windows) | 91.7% | 88 | 2 | + audit.jsonl |
| `NIST-DATALEAK-2015-PC` | insider data leak (Windows, disk-only) | 60% | 503 | 4 | + audit.jsonl + trace |
| `ALI-WEBSERVER-WIN-L0ZZQ76PMUF` | web-server breach (Win Server 2008) | 92.3% | 427 | 2 | + audit.jsonl + trace |
| `NIST-HACKINGCASE-2004-MREVIL` | war-driving / credential theft (Win XP) | 86.7% | 304 | 3 | + audit.jsonl + trace |

Recall = granular ground-truth coverage (see `docs/accuracy-report.md`). Per-run scores
are in `scripts/eval/baselines/*.json` (the ground-truth answer keys are published under
`scripts/eval/ground_truth/`; the investigation engine never reads them).

> **Where to find timestamps and token usage.** Per-tool-call **timestamps**, durations,
> exit codes, and the hash chain live in each case's **`audit.jsonl`** (`timestamp`,
> `duration_seconds`, `prev_entry_hash` / `entry_hash`). **Token usage** is recorded in the
> rendered session **`trace.html`** (the Claude Code session trace), not in `audit.jsonl` —
> see the cases that ship a `trace` artifact (e.g. the
> [`ROCBA-2020-FREDS-LAPTOP-v1.2.0`](ROCBA-2020-FREDS-LAPTOP-v1.2.0/) re-run and its
> `RUN-NOTES.md` token/cost breakdown).

> **ROCBA `v1.1.1` directory has no `audit.jsonl`** (it predates audit-log retention) — this
> is disclosed, not an omission. See [`ROCBA-2020-FREDS-LAPTOP/NOTE.md`](ROCBA-2020-FREDS-LAPTOP/NOTE.md);
> the full hash-chained trail for ROCBA is in the v1.2.0 re-run below.

> **Note on timing:** these five runs + their recall and TP/FP baselines were measured on the
> judged **`v1.1.1`** engine, *before* the `v1.2.0` core features shipped (native file-access
> extractors, durable reuse, case-insensitive/UTF-16 mount fix, triage detection). They are the
> `v1.1.1` baseline and have not yet been re-scored against `v1.2.0`. See `docs/accuracy-report.md`.

### v1.2.0 re-run (showcase)

| Case | Engine | Recall | Findings | CONFIRMED hyps | Artifacts |
|------|--------|--------|----------|----------------|-----------|
| [`ROCBA-2020-FREDS-LAPTOP-v1.2.0`](ROCBA-2020-FREDS-LAPTOP-v1.2.0/) | v1.2.0 | 90% (9/10, 0 halluc) | 127 | 4 of 5 | report·pdf·graph·trace·json·**audit** + [RUN-NOTES](ROCBA-2020-FREDS-LAPTOP-v1.2.0/RUN-NOTES.md) |

A blind re-run of ROCBA on `v1.2.0` exercising the new native artifacts. **GT recall is identical
to the v1.1.1 baseline (90%, same single FN GT-007, 0 hallucinations)** - the gain is qualitative
(4 confirmed hypotheses vs 3, all hypotheses resolved, fuller exfil/anti-forensics narrative), not a
measured recall improvement. Full breakdown in its `RUN-NOTES.md`. The v1.1.1 judged baseline for
this case is preserved at [`ROCBA-2020-FREDS-LAPTOP/`](ROCBA-2020-FREDS-LAPTOP/).

## Multi-host capstone

| Case | Scenario | Hosts | Artifacts |
|------|----------|-------|-----------|
| [`CRIMSON-OSPREY-ENTERPRISE`](CRIMSON-OSPREY-ENTERPRISE/) | SRL-2018 enterprise intrusion (lead-driven cross-host pivot) | 5 (DMZ-FTP → WKSTN-01 → RD-01 → FILE → DC) | per-host report·graph·trace·audit + **unified cross-host graph** |

A showcase of the multi-host pipeline (IOC pivot host→host + unified correlation graph),
not a GT-scored eval. See its [README](CRIMSON-OSPREY-ENTERPRISE/README.md) for the attack
chain and the unified graph. Methodology: `docs/multihost-pivot-methodology.md`.

## Integration / execution evidence (not GT-scored)

| Case | Scenario / OS | Findings | CONFIRMED | Artifacts |
|------|---------------|----------|-----------|-----------|
| [`VANKO-ZEBRAFISH-2016`](VANKO-ZEBRAFISH-2016/) | data-exfiltration triage (Windows 10, disk-only) | 130 | 3 | report·graph·json |

End-to-end execution evidence for the native file-access extractors
(`extract_recycle_bin`, `extract_powershell_history`, `extract_scheduled_tasks`) plus
`extract_registry_fileaccess`, run on a real Windows 10 image. This is an **integration
run, not a ground-truth-scored benchmark** (no published GT key) — it demonstrates the
new artifacts contributing live findings (Recycle Bin recovered deleted Dropbox-synced
files corroborating the confirmed cloud-exfiltration hypothesis; PowerShell history 216
commands; 174 scheduled-task definitions parsed). Completed in a single clean session.

## What each file is

| File | What it shows |
|---|---|
| `report.html` | The human-readable forensic report (open in a browser). |
| `graph.html` | The interactive investigation graph (open in a browser). |
| `report.json` | The same findings in machine-readable form. |
| `trace.html` | The agent's step-by-step session trace (where rendered). |
| `audit.jsonl` | The agent execution log — one JSON object per tool invocation, in order, with a tamper-evident hash chain. The primary "agent execution logs" artifact. |

## How to read `audit.jsonl`

Each row records a single agent action. Key fields:

| Field | Meaning |
|---|---|
| `timestamp` | UTC time the tool was invoked. |
| `tool` | Which forensic tool the agent called. |
| `command_line` | The exact command that ran (chain-of-custody evidence). |
| `parameters` | Arguments the agent chose. |
| `exit_code` | Tool result code. |
| `duration_seconds` | Wall-clock time. |
| `finding_ids_generated` | Findings produced by this step (e.g. `F-014`). |
| `correction_event` | Set when the agent detected a contradiction and self-corrected. |
| `execution_id` | Stable id every CONFIRMED finding cites for provenance. |
| `entry_hash` / `prev_entry_hash` | Tamper-evident hash chain — each row's `prev_entry_hash` equals the previous row's `entry_hash`. |

## Why the hash chain matters

The log is a linked hash chain: altering or deleting any row breaks the chain at
that point, which is detectable. This is what makes the execution trail defensible
rather than just a convenience log. Verify it with:

```python
import json
rows = [json.loads(line) for line in open("audit.jsonl")]
ok = all(rows[i]["prev_entry_hash"] == rows[i - 1]["entry_hash"]
         for i in range(1, len(rows)))
print("chain intact:", ok)
```

## Notes

- Paths in the artifacts reflect the standard SANS SIFT workstation layout (e.g.
  `/home/referenceensics/...`, the default SIFT user); the `audit.jsonl` hash chains
  are **unmodified** so they remain independently verifiable.
- `ROCBA-2020-FREDS-LAPTOP` predates audit-log retention, so it ships report/graph/json only.
- On a live run the framework writes the log to `analysis/audit.jsonl` alongside
  per-case state; these are copies of completed runs, committed for visibility.
