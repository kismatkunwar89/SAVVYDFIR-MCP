# Note — ROCBA-2020-FREDS-LAPTOP (judged v1.1.1 baseline)

**Why there is no `audit.jsonl` in this directory.** This is the judged **`v1.1.1`**
baseline run for the ROCBA case, captured *before* hash-chained `audit.jsonl` retention was
wired into the run-export path. The run is therefore preserved here as its
`report.html` / `report.json` / `graph.html` deliverables — the tool sequence and findings
are reconstructable from `report.json` (each finding carries its `source_execution_id`), but
this specific run does **not** ship the hash-chained execution log.

**This is a disclosed gap, not an omission.** The other four blind cases
(`LONEWOLF`, `NIST-DATALEAK`, `ALI-WEBSERVER`, `NIST-HACKINGCASE`) each ship a full
hash-chained `audit.jsonl`; see those directories for the per-tool-call execution-log format
(`execution_id`, `command_line`, `exit_code`, `duration_seconds`, `prev_entry_hash` /
`entry_hash`).

**For the full ROCBA execution trail, see the v1.2.0 re-run.** A blind re-run of this same
case on the `v1.2.0` engine ships the richer artifact set — report, PDF, graph, session
**`trace.html`** (timestamps + token usage), and `RUN-NOTES.md`:

→ [`../ROCBA-2020-FREDS-LAPTOP-v1.2.0/`](../ROCBA-2020-FREDS-LAPTOP-v1.2.0/)

GT recall is identical across both (90%, same single FN GT-007, 0 scored hallucinations); the
v1.2.0 gain is qualitative (4 confirmed hypotheses vs 3, fuller exfil/anti-forensics
narrative). This `v1.1.1` directory is kept as the **judged baseline of record**.
