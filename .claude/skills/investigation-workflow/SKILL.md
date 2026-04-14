---
name: investigation-workflow
description: Load when starting a new investigation or when unsure what phase to execute next. Defines the 5-phase DFIR methodology from evidence mounting through report generation, with decision points and quality gates.
allowed-tools:
  - Bash
---

# Investigation Workflow — 5-Phase DFIR Methodology

## Phase 1: Evidence Preparation
1. Read manifest: `start_investigation(manifest_path)`
2. Mount disk: `mount_image(image_path)` → note mount_path
3. Load memory: `load_memory(dump_path)` → note raw_dump_path
4. Verify integrity: `verify_integrity(image_path)` for each evidence file
5. **Gate:** All evidence mounted before proceeding

## Phase 2: Artifact Collection
**IMPORTANT: Follow this grouping. Heavy dotnet tools will saturate the 4-vCPU server if run in parallel.**

**Group A — run together (Volatility, fast ~1 min):**
1. `list_processes(dump_path)` + `scan_processes(dump_path)` + `scan_network(dump_path)`

**Group B — run ONE AT A TIME (dotnet, heavy):**
2. `detect_injection(dump_path)` — memory hog, run solo
3. `get_amcache(image_path)` + `extract_prefetch(image_path)` + `list_deleted_files(image_path)` — fast disk tools, can run together
4. `extract_mft_timeline(image_path)` — summary-first by default; request `response_format="detailed"` only for raw row drill-down → delegate to @mft-analyst immediately after
5. `summarize_evtx(image_path, channel="Security")` — summary-first by default; request `response_format="detailed"` only for raw row drill-down → delegate to @evtx-analyst immediately after
6. `extract_registry_run_keys(image_path)` — summary-first by default; request `response_format="detailed"` only for raw row drill-down → delegate to @registry-analyst immediately after

**Gate:** All tools complete and subagents have reported findings before Phase 3

## Phase 3: Anomaly Detection
1. `sigma_scan(case_id)` → universal anomaly detection across all findings
2. Review CRITICAL and HIGH hits first; follow each `pivot_suggestion`
3. `compare_disk_and_memory(case_id)` → cross-artifact correlation (6 checks)
4. Delegate to @corroboration-analyst → stress-tests all findings, eliminates false positives, applies stacked anomaly validation
5. **Gate:** All CRITICAL/HIGH anomalies investigated; corroboration review complete

## Phase 4: Deep Dive & Correlation
1. Follow pivot chains from anomalies (see /pivot-methodology)
2. `run_analysis(data_path, query)` for ad-hoc data questions
3. Build timeline: `build_timeline(source_path, case_id)`
4. Query timeline around key events: `query_timeline(plaso_path, start, end)`
5. `flag_discrepancy()` for confirmed contradictions
6. **Gate:** All discrepancies resolved or documented as open questions

## Phase 5: Report Generation
1. `read_state(case_id)` → verify case status, counts, and open questions
2. `get_findings(case_id, finding_status="ACTIVE")` → review the full finding corpus when you need all prior findings, not just the latest summary window
3. `generate_report(case_id)` → produce final summary
4. `generate_graph(case_id)` → create investigation visualization
4. **Gate:** Report generated

## Decision Points
- If blind mode: DO NOT reference known_iocs, discover everything independently
- If seeded mode: Use IOCs to prioritize but still run full collection
- If sigma_scan returns 0 hits: recheck evidence mounting, run YARA scans
- If corroboration-analyst downgrades a finding: do NOT include it in report at original confidence
- If correlation finds discrepancies: enter self-correction loop before report
