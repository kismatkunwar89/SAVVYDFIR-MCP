---
name: investigation-workflow
description: REQUIRED when the user says "start investigation", "investigate", "analyze case", "Read case-templates/manifest.json", references a manifest.json, or provides a SAVVYDFIR-MCP case_id. Defines the 5-phase DFIR methodology from evidence mounting through report generation, with mandatory tools, decision points, and quality gates that the report coverage gate enforces.
allowed-tools:
  - Bash
---

# Investigation Workflow - 5-Phase DFIR Methodology

This workflow is an investigation loop, not a checklist. The parent agent keeps the case hypothesis, decides pivots, and writes the narrative. Specialist analysts handle large artifact context through durable CSV/storage handles.

## MANDATORY TOOLS (gate-enforced - report will not finalize without these)

The `evaluate_ir_coverage_gate` enforces tool coverage before `generate_report`. Enforcement strength varies by tool:

| Tool | Enforcement | Why it's mandatory | Common skip-pattern that we explicitly reject |
|------|-------------|-------------------|----------------------------------------------|
| `list_processes`, `scan_processes`, `scan_network` | **Presence + opportunistic success** (failed retry triggers re-run) | Universal memory baseline | Skipping any breaks DKOM detection |
| `extract_mft_timeline`, `summarize_evtx`, `extract_registry_run_keys`, `get_amcache`, `extract_prefetch` | **Presence + opportunistic success** | Universal disk baseline | "Memory was enough" reasoning |
| **`sigma_hunt`** (Chainsaw rule engine) | **Hard success** - requires exit_code 0, duration > 0, audit completion hash, AND durable Chainsaw output (output_path or finding_ids_generated populated) | Rule-based EVTX detection. `sigma_scan` is an internal anomaly post-processor - NOT a substitute. Run2 evidence: calling only `sigma_scan` produces zero rule-based detections. | Calling `sigma_scan` and skipping `sigma_hunt` |
| Conditional `detect_injection`, `list_dlls`, `analyze_vss`, `extract_shimcache`, `extract_srum` | Triggered by psscan-only PIDs, network followup PIDs, anti-forensics signals | Same enforcement as their class above | Ignoring `next_required_tool` returned by earlier tools |

**Enforcement specifics**:
- **Hard success** (sigma_hunt): the gate's `_needs_sigma_hunt_run` rejects failed, timed-out, zero-duration, or output-less runs. There is no presence-only fallback.
- **Presence + opportunistic success** (everything else): the gate accepts the tool if its name appears in executions. BUT if any matching execution has populated success metadata (exit_code/duration_seconds) AND none of them succeeded, the gate demands a retry. This protects legacy fixtures while still catching new failures.

If the parent agent attempts `generate_report` before these are satisfied, the gate returns `next_required_tool` - call THAT tool, do not retry generate_report.

## Non-Negotiables
- Use MCP tools for forensic work. Shell fallback is only for classifying a tool gap.
- Keep large artifacts out of parent context. EVTX, MFT, Registry, Amcache, Prefetch, and timeline data must be delegated by handle (`csv_path`, `storage_path`, or raw artifact directory).
- Delegate immediately after large artifact tools: `@mft-analyst`, `@evtx-analyst`, `@registry-analyst`, `@prefetch-analyst`, `@amcache-analyst`, `@sigma-analyst`, `@srum-analyst`, `@browser-analyst`, `@timeline-analyst`, `@corroboration-analyst`.
- After a specialist returns, the parent calls `record_analysis_lane(...)` with validated execution and finding IDs. If a subagent is unavailable, the parent may record `assigned_agent="main-agent"` with an explicit reason.
- If a parser returns `needs_extract_windows_artifacts=true`, call `extract_windows_artifacts(...)` and rerun the parser on the durable `/cases/<case_id>/artifacts/raw/...` path.
- If `artifact_persistence.status="transient"` but `csv_path` exists, the CSV is still the data handle. Delegate on the handle; do not manually extract with `icat` or direct `dotnet`.
- Full integrity hashing is deferred in fast IR unless manifest hashes exist, evidence access is inconsistent, or the operator asks for it.

## Analysis Orchestration Contract (DO NOT STALL)

The hook system blocks the parent's next non-bypass tool call until the artifact's
lane is **recorded** via `record_analysis_lane(...)`. Main-agent inline analysis
is the **primary path** per W1.6.1 + W1.7 architecture; specialist Task spawn is
opt-in for cross-artifact isolation only (synthesis/corroboration). Always finish
with the recording step in the same turn.

### Primary path - Main-agent inline analysis

1. Read the **`applicable_heuristics`** block in the extraction tool's response.
   The W1.7 heuristic-injection layer delivers the relevant slice from
   `.claude/agents/<artifact>-analyst.md` directly in the payload, with a
   `ctx_id` (CTX-NNN) for provenance.
2. Read the durable handle (`csv_path`, `storage_path`, raw artifact directory).
3. Run focused `run_analysis(data_path=<handle>, query=...)` queries shaped by
   the heuristics. Each call gets an `execution_id` + audit row.
4. Persist evidence-backed conclusions via `submit_finding(...)` or
   `add_finding(...)`. Cite the heuristic via `heuristic_context_refs=["CTX-N"]`.
5. Call `record_analysis_lane(case_id=..., lane_id=<exact id from the hook>,
   status="COMPLETE" or "COMPLETE_WITH_GAPS", assigned_agent="main-agent",
   execution_ids=[...], finding_ids=[...], summary=<one sentence>)`.

For multi-artifact hypothesis formation: call `prepare_hypothesis_context(case_id)`
to receive a ranked bundle (volatile + detection + heuristic CTX-cited slices),
then `record_hypotheses(case_id, hypotheses=[...])` to persist your hypotheses
for audit. For pivot-loop depth, call `get_heuristic(artifact, topic)`.

### Synthesis SOP - main-agent inline (MANDATORY before generate_report)

Per W1.7 Run 2 consensus 2026-05-24 - delegate synthesis
is opt-in; do not wait for `@synthesis-analyst`. Run 2 produced 0 CONFIRMED
because the specialist Task hung and the operator was forced into
`allow_partial=True`, which previously bypassed quality gates.

After all 4 prereq lanes (`memory`, `disk_execution_persistence`, `event_auth`,
`timeline_correlation`) reach `COMPLETE` or `COMPLETE_WITH_GAPS`:

1. `compare_disk_and_memory(case_id)` - MANDATORY.
2. `find_temporal_clusters(case_id, window_seconds=300, min_sources=2, min_events=3)`.
3. For each 3+ source cluster, promote via `submit_finding(...)` with:
   `evidence_kind="inference"` (NOT `"corroborated"` - valid enum is
   `OBSERVATION` / `INFERENCE` / `HYPOTHESIS` / `REJECTED` only),
   `corroborated_by=[<F-NNN finding_ids>]`,
   `status="CONFIRMED"`,
   `source_execution_id=<resolved audit row>`,
   `alternative_hypothesis=<benign explanation>`,
   `evidence_against_it=[<specific observations>]`,
   `disposition="ruled_out"` (or `"not_applicable"` + reason).
   `not_resolved` / `partially_plausible` will NOT promote to CONFIRMED.
   Response includes `confirmed_eligibility: {eligible, missing, gate_blocks}`
   - read it; resubmit if `eligible: false` and you wanted CONFIRMED.
4. `record_analysis_lane(lane_id="synthesis_corroboration", assigned_agent="main-agent", status="COMPLETE", execution_ids=[...], finding_ids=[<promoted ids>], summary=...)`.

### Opt-in escape hatch - Task subagent spawn

ONLY for cross-artifact synthesis or corroboration that benefits from context
isolation:

1. Spawn `@synthesis-analyst`, `@corroboration-analyst`, or `@timeline-analyst`
   via `Task(...)` **synchronously** (`run_in_background=false`). When Task returns,
   the subagent has finished - there is no "still running" state.
2. Parse the subagent's JSON and call `record_analysis_lane(...,
   assigned_agent=<that-specialist>, ...)` in the same response.

Do NOT spawn artifact specialists (`@mft-analyst`, `@evtx-analyst`, etc.) -
they're retired from default orchestration per W1.6.1 (32K Task ceiling caused
truncation in 7/8 prior runs). Artifact analysis stays inline.

### Hard rules (apply to BOTH paths)

- **Strict lane match.** The hook clears the lane only when the recorded `lane_id`
  equals the pending `lane_id` exactly. Wrong lane = trigger unprocessed = next
  non-bypass tool call blocks again.
- **Same turn.** Run analysis + `record_analysis_lane` in the same response.
- **No artifact collection before recording.** Once a lane is pending, do not call
  `extract_*`, `summarize_*`, `get_amcache`, etc. until the lane is recorded.
- **Multiple lanes queue serially.** If after recording one lane another is pending
  (e.g. `summarize_evtx` triggers `event_auth`), handle that next.
- **Free-text "investigation summary" is not a completion.** Producing a chat
  summary instead of `generate_report(...)` leaves the case `IN_PROGRESS` with no
  `report.json`. The acceptance criterion is `reports/{case_id}/report.html`
  written by `generate_report`.

If you ever feel "I should wait for the user before checking" - you are wrong.
Run the analysis, record the lane, and continue.

## Specialist Contract
Specialists return compact JSON, not prose dumps. The `SubagentStop` hook enforces this contract when a delegate is pending.

```json
{
  "lane_id": "event_auth",
  "status": "COMPLETE_WITH_GAPS",
  "assigned_agent": "evtx-analyst",
  "execution_ids": ["E-004"],
  "finding_ids": ["F-012"],
  "data_gaps": [],
  "anti_forensics_warnings": [],
  "unresolved_discrepancies": [],
  "next_pivots": [],
  "summary": "One sentence lane summary.",
  "confidence_notes": []
}
```

The parent validates IDs with `read_state(case_id)` before `record_analysis_lane(...)`.

If a specialist cannot access the artifact, cannot create findings, or finds that the evidence is unavailable/unsupported, it still returns this JSON with `status="COMPLETE_WITH_GAPS"` and at least one `data_gaps` entry. Do not silently summarize unavailable evidence.

## Phase 1: Evidence Preparation
1. `start_investigation(manifest_path)`
2. `environment_preflight(case_id)`
3. `mount_image(image_path)` and note `mount_status`, `access_mode`, `tsk_device_path`, `mount_path`, and `next_tools`
4. `load_memory(dump_path)`
5. Gate: evidence is mounted/loaded, or the missing piece is honestly classified

## Phase 2: Artifact Collection
Heavy dotnet tools can saturate the 4-vCPU server. Use summaries and handles. Keep `response_format="summary"` by default; request `response_format="detailed"` only for narrow row drill-down after a specialist identifies the exact question.

Group A - run together when safe:
1. `list_processes(dump_path)`
2. `scan_processes(dump_path)`
3. `scan_network(dump_path)`

Delegate memory context:

```text
@memory-analyst
Analyze memory lane for <case_id>. Review list_processes, scan_processes, scan_network, detect_injection, and related CSV handles. Confirm suspicious processes/network/C2, add evidence-backed findings, and return the Specialist Contract with lane_id="memory".
```

Group B - run one at a time or in small safe batches:
1. `detect_injection(dump_path)`
2. `get_amcache(image_path)`
3. `extract_prefetch(image_path)`
4. `list_deleted_files(image_path)`
5. `extract_mft_timeline(image_path)` -> delegate to `@mft-analyst`
6. `summarize_evtx(image_path, channel="Security")` -> delegate to `@evtx-analyst`
7. `extract_registry_run_keys(image_path)` -> delegate to `@registry-analyst`
8. `get_amcache(image_path)` -> delegate to `@amcache-analyst`
9. `extract_prefetch(image_path)` -> delegate to `@prefetch-analyst`
10. `extract_srum(image_path)` when SRUM exists or exfil volume matters -> delegate to `@srum-analyst`

Use durable handles as context:

```text
@mft-analyst
Analyze the MFT CSV handle for <case_id>. Look for timestomping, M-before-C copy artifacts, sequence anomalies, deletion bursts, staging directories, and suspicious ADS. Use run_analysis for focused pivots. Return the Specialist Contract with lane_id="timeline_correlation".
```

```text
@evtx-analyst
Analyze EVTX CSV handles for <case_id>. Prioritize 1102/104 log clearing, 4648 to 5140/5145 lateral movement, RDP reconnects, Defender 1116/1117, Sysmon process/network chains, and event-log data gaps. Return the Specialist Contract with lane_id="event_auth".
```

```text
@registry-analyst
Analyze Registry, Amcache, Prefetch, ShimCache, and PCA handles for <case_id>. Confirm persistence, service installs, Run keys, execution inventory, suspicious hashes, and missing-artifact gaps. Return the Specialist Contract with lane_id="disk_execution_persistence".
```

```text
@amcache-analyst
Analyze the Amcache handle for <case_id>. Corroborate execution inventory, renamed binaries, first-run timestamps, SHA-1s, and missing binary gaps. Return the Specialist Contract with lane_id="disk_execution_persistence".
```

```text
@prefetch-analyst
Analyze Prefetch/PCA handles for <case_id>. Corroborate execution count, run times, multi-path execution, orphaned PF files, and deleted binaries. Return the Specialist Contract with lane_id="disk_execution_persistence".
```

```text
@srum-analyst
Analyze SRUM handles for <case_id>. Quantify network usage by application, spot deleted or unresolved executables, and support exfiltration/lateral-movement hypotheses. Return the Specialist Contract with lane_id="timeline_correlation".
```

```text
@browser-analyst
Analyze browser artifacts only when collected or relevant to the hypothesis. Look for download/referrer history, suspicious extensions, sync artifacts, and initial-access pivots. Return the Specialist Contract with lane_id="disk_execution_persistence".
```

Gate: major artifact lanes are either specialist-owned or explicitly recorded by the parent with a data gap.

## Phase 3: Detection and Corroboration
1. `sigma_scan(case_id)` and/or `sigma_hunt(...)`
2. Review CRITICAL/HIGH hits first and follow `pivot_suggestion`
3. `compare_disk_and_memory(case_id)`
4. Delegate Sigma results to `@sigma-analyst` when there are hits, log/data gaps, or anti-forensics context to adjudicate
5. Delegate to `@corroboration-analyst`

```text
@sigma-analyst
Analyze Sigma results for <case_id>. Triage false positives, explain zero-hit limitations when evidence was wiped, map confirmed detections to ATT&CK, and return the Specialist Contract with lane_id="timeline_correlation".
```

```text
@corroboration-analyst
Stress-test confirmed and active findings across disk, memory, event, and timeline evidence. Downgrade weak claims, flag contradictions with flag_discrepancy, and return the Specialist Contract with lane_id="timeline_correlation".
```

Gate: critical/high anomalies are investigated, and contradictions are resolved or documented as open leads.

## Phase 4: Deep Dive and Pivots
1. Follow pivots from anomalies and specialist summaries
2. `run_analysis(data_path, query)` for focused CSV questions
3. `build_timeline(source_path, case_id)` when timelines help answer a hypothesis
4. `query_timeline(plaso_path, start, end)` around key attacker windows
5. `flag_discrepancy(...)` when evidence contradicts a claim

## Phase 5: Report and Graph
1. `read_state(case_id)`
2. `get_findings(case_id, finding_status="ACTIVE")`
3. `get_investigation_gates(case_id)`
4. If urgent partial triage is acceptable, document gaps; otherwise finish missing specialist records
5. `generate_report(case_id)`
6. `generate_graph(case_id)`
7. If graph was generated after report, rerun `generate_report(case_id)` so `report.json` no longer says `graph_missing`

## Decision Points
- Blind mode: do not use known IOCs; discover independently.
- Seeded mode: use IOCs to prioritize while still collecting broadly.
- `sigma_scan` returns 0 hits: decide whether this is true negative, missing evidence, or detector limitation.
- Corroboration downgrades a finding: update the narrative and confidence.
- Anti-forensics warning: recommend recovery pivots such as `analyze_vss` and keep report status honest.
