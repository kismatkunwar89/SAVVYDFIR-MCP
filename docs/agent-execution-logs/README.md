# Agent Execution Logs (Sample Run)

This directory holds a complete, unedited sample of what the framework produces on
one autonomous investigation. It exists so reviewers can inspect the agent's
decision trail and outputs without having to run the tool themselves.

**Sample run:** `HACKATHON-2026-WKSTN01` (single Windows workstation host).
The run was selected because it is representative and contains no operator
infrastructure details. It produced 3 court-defensible CONFIRMED findings with
full corroboration and alternative-hypothesis disposition.

## What each file is

| File | What it shows |
|---|---|
| `audit.jsonl` | The agent execution log. One JSON object per tool invocation, in order. This is the primary "agent execution logs" artifact. |
| `report.html` | The human-readable forensic report the run produced (open in a browser). |
| `report.json` | The same findings in machine-readable form. |
| `graph.html` | The interactive investigation graph (open in a browser). |

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
| `entry_hash` / `prev_entry_hash` | Tamper-evident hash chain. Each row's `prev_entry_hash` equals the previous row's `entry_hash`. |

## Why the hash chain matters

The log is a linked hash chain: altering or deleting any row breaks the chain at
that point, which is detectable. This is what makes the execution trail
defensible rather than just a convenience log. You can verify the chain with:

```python
import json
rows = [json.loads(line) for line in open("audit.jsonl")]
ok = all(rows[i]["prev_entry_hash"] == rows[i - 1]["entry_hash"]
         for i in range(1, len(rows)))
print("chain intact:", ok)
```

## Where logs come from on a live run

On a real investigation the framework writes the live log to
`analysis/audit.jsonl` (and per-case copies alongside the state). The files here
are a copy of one completed run, committed so the artifact is visible in the
repository.
