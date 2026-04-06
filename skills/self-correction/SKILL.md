# Self-Correction Protocol

**Skill file for:** Detecting, logging, and resolving contradictions between findings during an investigation.
**Load when:** A `DiscrepancyAlert` is received, a tool returns a non-zero exit code, or any new result contradicts a prior finding.

---

## Overview

The Self-Correction Protocol is a mandatory quality-control loop that runs after every tool call. It prevents the agent from building an investigation narrative on findings that have been invalidated by later evidence. All correction events are permanently recorded in the audit trail.

The protocol has three modes:
1. **Post-tool contradiction check** — runs after every single tool call.
2. **DiscrepancyAlert response** — triggered by `compare_disk_and_memory()`.
3. **Tool failure response** — triggered by any `exit_code != 0`.

---

## Trigger Conditions

Self-correction is triggered by any of the following:

| Trigger | Source | Action Required |
|---|---|---|
| `DiscrepancyAlert` in tool result | `correlation.compare_disk_and_memory()` | Full protocol (all 5 steps) |
| New finding contradicts prior OBSERVATION | Any tool | Full protocol (all 5 steps) |
| New finding contradicts prior INFERENCE | Any tool | Full protocol (all 5 steps) |
| `exit_code != 0` | Any tool | Error classification + retry |
| Amcache SHA1 does not match expected binary | `disk.get_amcache()` | Downgrade + follow-up |
| YARA hit on previously benign process | `yara.scan_memory()` | Downgrade + re-evaluate |
| Hidden process found (psscan but not pslist) | `memory.scan_processes()` | Downgrade all assumptions about process list completeness |

---

## Step 1 — Detect the Contradiction

After every tool call, perform this check **before** using the result to update any finding:

```
For each finding_id referenced in the new tool result:
  1. Read the current classification and supporting evidence from findings.json
  2. Ask: does the new result support, contradict, or have no bearing on this finding?
  3. If CONTRADICTS → proceed to Step 2
  4. If SUPPORTS → add new result as corroborating_source to the finding, keep classification
  5. If NO BEARING → no action required
```

### What Counts as a Contradiction

- A process listed as `exit_time = null` (running) in pslist but the same PID shows a binary that does not exist on disk → contradiction of "process is legitimate."
- An OBSERVATION classified as "svchost.exe is clean" invalidated by a VAD anomaly on that PID's memory space → contradiction.
- An INFERENCE that "no external network activity occurred" contradicted by a network connection found by `memory.scan_network()` → contradiction.
- A HYPOTHESIS that "binary was executed from C:\Windows\System32\" contradicted by Prefetch evidence showing execution from `C:\Users\Public\` → contradiction.

---

## Step 2 — Log CORRECTION_EVENT Immediately

A `CORRECTION_EVENT` must be logged **before** any finding is reclassified. The event is permanent and cannot be deleted.

### CORRECTION_EVENT Format

```json
{
  "event_type": "CORRECTION_EVENT",
  "timestamp": "<UTC ISO-8601>",
  "correction_id": "CE-<N>",
  "trigger": "<DiscrepancyAlert | contradiction | tool_failure | hash_mismatch | yara_hit>",
  "affected_finding_ids": ["F-<N>", "F-<N>"],
  "prior_claim": "<verbatim description of the prior finding as it was classified>",
  "contradiction_source": {
    "tool": "<tool_name>",
    "execution_id": "<E-N>",
    "result_excerpt": "<the specific output that contradicts the prior claim>"
  },
  "revised_claim": "<what is now believed to be true, or 'UNKNOWN — requires follow-up'>",
  "resolution_status": "PENDING | RESOLVED",
  "resolution_tool": "<tool to be called to resolve>",
  "resolution_finding_id": "<F-N of the finding that resolved this, once known>"
}
```

Write the CORRECTION_EVENT to `./analysis/audit.jsonl` as an additional JSONL entry.

---

## Step 3 — Downgrade Affected Findings

After logging the CORRECTION_EVENT, immediately downgrade all affected findings:

| Prior Classification | New Classification | Action |
|---|---|---|
| OBSERVATION | HYPOTHESIS | Remove the `offset` field from the provenance until re-confirmed. Add `correction_id` to the finding record. |
| INFERENCE | HYPOTHESIS | Remove all `supporting_observations` references that relied on the now-invalidated finding. Add `correction_id`. |
| HYPOTHESIS | HYPOTHESIS | No reclassification needed — already unconfirmed. Still add `correction_id` for traceability. |
| REJECTED | (re-open) | If new evidence contradicts a REJECTED finding, un-reject it and reclassify as HYPOTHESIS. Add `correction_id`. |

**Never delete a finding.** Only reclassify. All historical classifications are preserved in the audit trail.

---

## Step 4 — Run Follow-Up Tools

Execute the tool(s) needed to resolve the contradiction:

### For DiscrepancyAlert
Use the `recommended_followup` list from the alert:

```
DiscrepancyAlert.recommended_followup → run each tool in the list
```

### For Other Contradictions
Select the appropriate follow-up based on the contradiction type:

| Contradiction Type | Recommended Follow-Up |
|---|---|
| Process in memory but no disk binary | `disk.list_deleted_files()` (check for recent deletion) + `disk.extract_prefetch()` (check execution evidence) |
| Amcache SHA1 mismatch | `yara.scan_memory(pid=<affected_pid>)` + `disk.extract_mft_timeline()` (check file modification time) |
| VAD anomaly on legitimate process | `memory.list_dlls(pid=<affected_pid>)` + `yara.scan_memory(pid=<affected_pid>)` |
| Network connection with no disk artifact | `disk.extract_prefetch()` (check for cleaned binary) + `disk.extract_registry_run_keys()` (persistence) |
| Hidden process (psscan only) | `memory.list_dlls(pid=<hidden_pid>)` + `memory.detect_injection(dump_path)` |
| Registry persistence → missing binary | `disk.list_deleted_files()` + `disk.extract_mft_timeline()` |

---

## Step 5 — Re-Evaluate and Reclassify

After the follow-up tool returns its result:

### Promote to OBSERVATION (if confirmed)
Conditions:
- Follow-up tool returns `exit_code == 0`
- New result provides `artifact_path` + `offset` that directly support the revised claim
- No remaining contradictions exist for this finding

Actions:
- Set classification to OBSERVATION.
- Add `artifact_path` and `offset` from the confirming result.
- Set `CORRECTION_EVENT.resolution_status = "RESOLVED"`.
- Set `CORRECTION_EVENT.resolution_finding_id` to the new or updated finding ID.

### Promote to INFERENCE (if analytically supported)
Conditions:
- No single artifact provides direct OBSERVATION-level evidence.
- But ≥2 OBSERVATION findings together strongly support the revised claim.

Actions:
- Set classification to INFERENCE.
- List all supporting OBSERVATION `finding_id`s.
- Set `CORRECTION_EVENT.resolution_status = "RESOLVED"`.

### Reclassify as REJECTED (if follow-up disproves the original concern)
Conditions:
- Follow-up tool provides evidence that the contradiction was benign (e.g., legitimate system behavior, known-good binary).

Actions:
- Set classification to REJECTED.
- Document the rejection reason explicitly.
- Set `CORRECTION_EVENT.resolution_status = "RESOLVED"`.

### Leave as HYPOTHESIS (if follow-up is inconclusive)
Conditions:
- Follow-up tool fails, or returns ambiguous results.
- No additional tools are available to resolve the contradiction.

Actions:
- Leave classification as HYPOTHESIS.
- Add the unresolved question to `open_questions` in the case state.
- Set `CORRECTION_EVENT.resolution_status = "PENDING — requires additional evidence"`.
- **This is the only acceptable reason to leave a CORRECTION_EVENT unresolved at case close.**

---

## Special Case: Tool Failure (exit_code != 0)

When any tool returns a non-zero exit code:

1. **Log the failure** in `./analysis/audit.jsonl` (done automatically by MCP server).
2. **Do not use any output** from the failed tool call.
3. **Retry once** with identical parameters.
4. **If still failing:**
   - Attempt an alternative tool or raw CLI approach that covers the same operation.
   - Document the failure and alternative approach in `open_questions`.
   - Continue with remaining tools in the phase sequence.
5. **Do not reclassify existing findings** based on a failed tool call. A failure is the absence of evidence, not evidence of absence.

---

## Non-Negotiable Rules

1. **Never leave a CORRECTION_EVENT with `resolution_status = "PENDING"` at case close** unless `max_iterations` has been reached and the issue is documented in `open_questions`.
2. **Never delete or modify a finding record.** Only reclassify.
3. **Never use a prior OBSERVATION to support an INFERENCE** if that OBSERVATION has been downgraded to HYPOTHESIS.
4. **Every CORRECTION_EVENT must reference** the specific `execution_id` of the tool call that triggered it.
5. **The audit trail is immutable.** The MCP server writes it. Do not attempt to modify `./analysis/audit.jsonl`.

---

## CORRECTION_EVENT Example

Scenario: `compare_disk_and_memory()` returns a DiscrepancyAlert indicating that PID 1284 (`svchost.exe`) has a VAD region with `PAGE_EXECUTE_READWRITE` permissions, contradicting the prior OBSERVATION F-003 that classified this process as legitimate.

```json
{
  "event_type": "CORRECTION_EVENT",
  "timestamp": "2026-05-01T14:31:05.112Z",
  "correction_id": "CE-001",
  "trigger": "DiscrepancyAlert",
  "affected_finding_ids": ["F-003"],
  "prior_claim": "PID 1284 (svchost.exe) classified as OBSERVATION — legitimate Windows service host, no anomalies detected in pslist output.",
  "contradiction_source": {
    "tool": "correlation.compare_disk_and_memory",
    "execution_id": "E-012",
    "result_excerpt": "DiscrepancyAlert: PID 1284 has VAD region at 0x7f000000 with PAGE_EXECUTE_READWRITE — anomalous for svchost.exe. No corresponding section in PE header on disk binary."
  },
  "revised_claim": "UNKNOWN — PID 1284 may be injected. Requires DLL list and YARA scan to confirm.",
  "resolution_status": "PENDING",
  "resolution_tool": "memory.list_dlls + yara.scan_memory",
  "resolution_finding_id": null
}
```

After running `memory.list_dlls(pid=1284)` and `yara.scan_memory(pid=1284, rule_set="common_injectors")`:

- YARA returns hit: `Cobalt_Strike_Beacon` at offset `0x7f000050` in dump `/cases/SRL-2018/evidence/wkstn-01.raw`.
- Update: F-003 reclassified from HYPOTHESIS to OBSERVATION (with new `artifact_path` and `offset`).
- CE-001 updated: `resolution_status = "RESOLVED"`, `resolution_finding_id = "F-011"`.
