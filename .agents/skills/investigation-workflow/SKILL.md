---
name: investigation-workflow
description: Load when starting a new investigation or when unsure what phase to execute next. Defines the 5-phase DFIR methodology from evidence mounting through report generation, with decision points and quality gates.
allowed-tools:
  - Bash
---

# Investigation Workflow - 5-Phase DFIR Methodology

This workflow is an investigation loop, not a checklist. The parent agent keeps the case hypothesis, decides pivots, and writes the narrative. Specialist analysts handle large artifact context through durable CSV/storage handles.

## Non-Negotiables
- Use MCP tools for forensic work. Shell fallback is only for classifying a tool gap.
- Keep large artifacts out of parent context. EVTX, MFT, Registry, Amcache, Prefetch, and timeline data must be delegated by handle (`csv_path`, `storage_path`, or raw artifact directory).
- Delegate immediately after large artifact tools: `@mft-analyst`, `@evtx-analyst`, `@registry-analyst`, `@prefetch-analyst`, `@amcache-analyst`, `@sigma-analyst`, `@srum-analyst`, `@browser-analyst`, `@timeline-analyst`, `@corroboration-analyst`.
- After a specialist returns, the parent calls `record_analysis_lane(...)` with validated execution and finding IDs. If a subagent is unavailable, the parent may record `assigned_agent="main-agent"` with an explicit reason.
- If a parser returns `needs_extract_windows_artifacts=true`, call `extract_windows_artifacts(...)` and rerun the parser on the durable `/cases/<case_id>/artifacts/raw/...` path.
- If `artifact_persistence.status="transient"` but `csv_path` exists, the CSV is still the data handle. Delegate on the handle; do not manually extract with `icat` or direct `dotnet`.
- Full integrity hashing is deferred in fast IR unless manifest hashes exist, evidence access is inconsistent, or the operator asks for it.

## Specialist Contract
Specialists return compact JSON, not prose dumps:

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
