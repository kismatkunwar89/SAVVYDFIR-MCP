# Agent Execution Logs

This directory holds the complete, unedited artifacts the framework produced on
its blind benchmark investigations, so reviewers can inspect the agent's decision
trail and outputs without running the tool themselves.

## Blind benchmark cases

The five public DFIR cases used to validate the framework each have their full run
artifacts under `docs/agent-execution-logs/<case>/`. All five were run **blind**
(ground truth never on the workstation) with **zero hallucinations**.

| Case | Scenario / OS | Recall | Findings | CONFIRMED | Artifacts |
|------|---------------|--------|----------|-----------|-----------|
| `ROCBA-2020-FREDS-LAPTOP` | insider IP theft (Windows) | 90% | 107 | 3 | report·graph·json |
| `LONEWOLF-2018-DESKTOP-PM6C56D` | mass-shooting plot (Windows) | 91.7% | 88 | 2 | + audit.jsonl |
| `NIST-DATALEAK-2015-PC` | insider data leak (Windows, disk-only) | 60% | 503 | 4 | + audit.jsonl + trace |
| `ALI-WEBSERVER-WIN-L0ZZQ76PMUF` | web-server breach (Win Server 2008) | 92.3% | 427 | 2 | + audit.jsonl + trace |
| `NIST-HACKINGCASE-2004-MREVIL` | war-driving / credential theft (Win XP) | 86.7% | 304 | 3 | + audit.jsonl + trace |

Recall = granular ground-truth coverage (see `docs/accuracy-report.md`).

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
