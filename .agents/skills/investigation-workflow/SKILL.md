---
name: investigation-workflow
description: Load when starting a new investigation or when unsure what phase to execute next. Defines the 5-phase DFIR methodology from evidence mounting through report generation, with decision points and quality gates.
allowed-tools:
  - Bash
---

# Investigation Workflow - 5-Phase DFIR Methodology

## Non-Negotiables
- Use MCP tools for forensic work. Do not hand-run substitute shell commands unless an MCP tool explicitly fails and the fallback is needed to classify the gap.
- Spawn analyst subagents with the `Agent` tool when an artifact lane is ready. Prose references like `@mft-analyst` are not enough.
- Subagents may call SAVVYDFIR MCP tools, but they must not invent IDs. Finding IDs and execution IDs must come from persisted MCP state.
- After every subagent return, call `record_analysis_lane(...)` with the returned JSON. If `Agent` is unavailable, continue in the main context and call `record_analysis_lane(..., assigned_agent="main-agent")`. Do not leave the lane untracked.
- Before phase transitions and before reporting, call `get_investigation_gates(case_id)`. If gates are not report-ready, either spawn/record the missing lanes or explicitly mark the report as urgent partial.
- **Persistence-Failure Rule:** if an artifact tool returns `artifact_persistence.status = "transient"` but the response includes a `csv_path` (or `data_path`), the CSV is the data. Spawn the lane analyst directly on the `csv_path` and continue the workflow. Do NOT detour into manual `icat`, `dotnet`, or shell-based extraction. Manual extraction is an emergency fallback only when no `csv_path` is returned at all.
- Full integrity hashing is deferred in fast IR unless manifest hashes exist, the user asks for it, evidence behaves inconsistently, or final evidence-quality reporting requires it.
- The framework now refuses to mark `triage_status = TRIAGE_COMPLETE` if any required lane has executions or findings but no `assigned_agent`. Specialist-inferred lanes force `COMPLETE_WITH_GAPS` with reason `lane_not_owned_by_subagent`. The fix is always to spawn the specialist or call `record_analysis_lane(..., assigned_agent="main-agent")`, not to ignore the warning.

## Subagent Return Contract
Each analyst subagent must return JSON matching this shape:

```json
{
  "lane_id": "memory",
  "status": "COMPLETE_WITH_GAPS",
  "execution_ids": ["E-001"],
  "finding_ids": ["F-001"],
  "data_gaps": [],
  "anti_forensics_warnings": [],
  "unresolved_discrepancies": [],
  "next_pivots": [],
  "summary": "One sentence lane summary.",
  "confidence_notes": []
}
```

The parent must validate returned `execution_ids` and `finding_ids` against `read_state(case_id)`. If any returned ID is absent from state, treat that lane as failed or incomplete and document the gap.

## Phase 1: Evidence Preparation
1. Read manifest: `start_investigation(manifest_path)`
2. Run `environment_preflight(case_id)` once. Treat missing dependencies as warnings to route around, not a reason to stop fast IR unless the needed tool has no fallback.
3. Mount disk: `mount_image(image_path)` and record `mount_path`, `mount_status`, `access_mode`, `tsk_device_path`, and `next_tools`.
4. Load memory: `load_memory(dump_path)` and record `raw_dump_path`
5. Lightweight evidence check: record path, existence, size, and mount/load outcome.
6. Optional/deferred integrity: run `verify_integrity(image_path)` only when manifest hashes exist, the user requests it, evidence access is inconsistent, or the final report needs an evidence-quality note.
7. Gate: all evidence is mounted/loaded or the missing artifact is classified with `classify_missing_artifact`

## Phase 2: Artifact Collection
Heavy dotnet tools can saturate the 4-vCPU server. Follow the grouping.

Group A - run together when safe:
1. `list_processes(dump_path)`
2. `scan_processes(dump_path)`
3. `scan_network(dump_path)`

After Group A, spawn memory analysis:

```text
Agent(
  subagent_type="memory-analyst",
  description="Analyze memory lane for case <case_id>",
  prompt="Read state for <case_id>. Review memory executions and findings from list_processes, scan_processes, scan_network, detect_injection, and related run_analysis results. Add only evidence-backed findings via mcp__savvydfir__add_finding. Return only JSON using the Subagent Return Contract with lane_id='memory'."
)
```

After it returns, call:

```text
record_analysis_lane(
  case_id="<case_id>",
  lane_id="memory",
  assigned_agent="memory-analyst",
  status="<returned status>",
  execution_ids=<returned execution_ids>,
  finding_ids=<returned finding_ids>,
  data_gaps=<returned data_gaps>,
  anti_forensics_warnings=<returned anti_forensics_warnings>,
  next_pivots=<returned next_pivots>,
  summary="<returned summary>"
)
```

Group B - run one at a time:
1. `detect_injection(dump_path)` - memory intensive, run solo
2. `get_amcache(image_path)`
3. `extract_prefetch(image_path)`
4. `list_deleted_files(image_path)`
5. `extract_mft_timeline(image_path)` - summary-first by default; request `response_format="detailed"` only for row drill-down
6. `summarize_evtx(image_path, channel="Security")` - summary-first by default
7. `extract_registry_run_keys(image_path)` - summary-first by default

**Important:** every Group B tool may return `artifact_persistence.status = "transient"` with a populated `csv_path`. That is normal and not a failure. Spawn the corresponding lane analyst on the `csv_path` (it is the same data). Do not loop back and try `icat` / `dotnet` / shell extraction. Manual recovery is reserved for cases where the response has no `csv_path` at all.

Spawn disk and event analysts after their source tools complete:

```text
Agent(
  subagent_type="mft-analyst",
  description="Analyze MFT and filesystem timeline lane for case <case_id>",
  prompt="Read state for <case_id>. Review extract_mft_timeline, list_deleted_files, and related filesystem findings. Look for timestomp, M-before-C copy artifacts, sequence anomalies, deletion bursts, and data gaps. Add only persisted MCP findings. Return only JSON using the Subagent Return Contract with lane_id='timeline_correlation'."
)
```

After each disk/event subagent returns, call `record_analysis_lane(...)` with its exact returned IDs and `assigned_agent` set to the subagent type. Do not proceed to Phase 3 until `get_investigation_gates(case_id)` shows no blocking Phase 2 specialist gaps, unless this is explicitly an urgent partial report.

```text
Agent(
  subagent_type="evtx-analyst",
  description="Analyze Security/System/Sysmon event lane for case <case_id>",
  prompt="Read state for <case_id>. Review summarize_evtx outputs and event-backed findings. Prioritize 1102/104 anti-forensics, 4648 to 5140/5145 correlation, RDP reconnects, Defender 1116/1117, and event-log data gaps. Add only persisted MCP findings. Return only JSON using the Subagent Return Contract with lane_id='event_auth'."
)
```

```text
Agent(
  subagent_type="registry-analyst",
  description="Analyze registry persistence lane for case <case_id>",
  prompt="Read state for <case_id>. Review registry run keys, services, autoruns-style persistence, and related disk findings. Add only evidence-backed MCP findings. Return only JSON using the Subagent Return Contract with lane_id='disk_execution_persistence'."
)
```

```text
Agent(
  subagent_type="prefetch-analyst",
  description="Analyze Prefetch execution evidence for case <case_id>",
  prompt="Read state for <case_id>. Review Prefetch evidence, missing Prefetch classifications, execution timelines, SDelete/cipher traces, and suspicious binaries. Add only persisted MCP findings. Return only JSON using the Subagent Return Contract with lane_id='disk_execution_persistence'."
)
```

```text
Agent(
  subagent_type="amcache-analyst",
  description="Analyze Amcache execution inventory for case <case_id>",
  prompt="Read state for <case_id>. Review Amcache evidence, missing Amcache classifications, first-run metadata, hashes, and suspicious execution artifacts. Add only persisted MCP findings. Return only JSON using the Subagent Return Contract with lane_id='disk_execution_persistence'."
)
```

Gate: required lanes have executions/findings or explicit data-gap classifications before Phase 3.

## Phase 3: Anomaly Detection
1. `sigma_scan(case_id)` - universal anomaly detection across all findings
2. Review CRITICAL and HIGH hits first; follow each `pivot_suggestion`
3. `compare_disk_and_memory(case_id)` - cross-artifact correlation

Spawn detection and corroboration reviewers:

```text
Agent(
  subagent_type="sigma-analyst",
  description="Review anomaly detector results for case <case_id>",
  prompt="Read state for <case_id>. Review sigma_scan results, actionable leads, anti-forensics warnings, and detector gaps. Add only evidence-backed MCP findings. Return only JSON using the Subagent Return Contract with lane_id='timeline_correlation'."
)
```

After each detection/corroboration subagent returns, call `record_analysis_lane(...)` with validated IDs. If `sigma_scan` returns zero hits, still spawn `sigma-analyst` to decide whether that is expected data absence, detector limitation, or a true negative.

```text
Agent(
  subagent_type="corroboration-analyst",
  description="Stress-test cross-artifact findings for case <case_id>",
  prompt="Read state for <case_id>. Stress-test confirmed and active findings against disk, memory, event, and timeline evidence. Use mcp__savvydfir__flag_discrepancy for contradictions. Downgrade unsupported claims by reporting data_gaps or unresolved_discrepancies; do not invent IDs. Return only JSON using the Subagent Return Contract with lane_id='timeline_correlation'."
)
```

Gate: all CRITICAL/HIGH anomalies are investigated and corroboration review is complete.
Call `get_investigation_gates(case_id)` before Phase 4.

## Phase 4: Deep Dive and Correlation
1. Follow pivot chains from anomalies with the pivot-methodology skill
2. `run_analysis(data_path, query)` for focused data questions
3. `build_timeline(source_path, case_id)`
4. `query_timeline(plaso_path, start, end)`
5. `flag_discrepancy()` for confirmed contradictions

Use these optional specialists when the data exists:

```text
Agent(
  subagent_type="timeline-analyst",
  description="Build and query timeline pivots for case <case_id>",
  prompt="Read state for <case_id>. Review timeline artifacts and correlate key process, file, event, network, and persistence times. Add only evidence-backed MCP findings. Return only JSON using the Subagent Return Contract with lane_id='timeline_correlation'."
)
```

```text
Agent(
  subagent_type="srum-analyst",
  description="Analyze SRUM network/application activity for case <case_id>",
  prompt="Read state for <case_id>. Review SRUM evidence if present; if absent, classify the data gap honestly. Add only persisted MCP findings. Return only JSON using the Subagent Return Contract with lane_id='timeline_correlation'."
)
```

```text
Agent(
  subagent_type="browser-analyst",
  description="Analyze browser artifacts for case <case_id>",
  prompt="Read state for <case_id>. Review browser history, downloads, MotW-supporting context, and user-execution pivots if present; if absent, classify the data gap honestly. Add only persisted MCP findings. Return only JSON using the Subagent Return Contract with lane_id='disk_execution_persistence'."
)
```

Gate: all discrepancies are resolved or documented as open questions.
Call `get_investigation_gates(case_id)` before report generation.

## Phase 5: Report Generation
1. `read_state(case_id)` - verify case status, counts, lanes, gaps, and open questions
2. `get_findings(case_id, finding_status="ACTIVE")` - review active findings
3. `get_investigation_gates(case_id)` - verify lane/subagent readiness
4. `generate_report(case_id)` - produce `report.html` and `report.json`
5. `generate_graph(case_id)` - create investigation visualization
6. Gate: report status is honest. Do not claim `TRIAGE_COMPLETE` if required lanes failed, anti-forensics forced gaps, unresolved discrepancies remain, or specialist lanes are inferred-only.

## Decision Points
- Blind mode: do not reference known_iocs; discover independently.
- Seeded mode: use IOCs to prioritize but still run full collection.
- `sigma_scan` returns 0 hits: recheck evidence mounting and run appropriate detector pivots.
- Corroboration downgrades a finding: do not include it at original confidence.
- Correlation finds discrepancies: enter self-correction before report.
