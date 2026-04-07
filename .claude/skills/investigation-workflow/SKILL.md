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
5. **Gate:** All evidence mounted and integrity verified before proceeding

## Phase 2: Artifact Collection
Run ALL of these — order matters for correlation:
1. `list_processes(dump_path)` → baseline running processes
2. `scan_processes(dump_path)` → find DKOM-hidden processes
3. `detect_injection(dump_path)` → VAD anomalies
4. `scan_network(dump_path)` → network connections
5. `extract_prefetch(image_path)` → execution history
6. `get_amcache(image_path)` → SHA-1 hashes of executed binaries
7. `extract_mft_timeline(image_path)` → filesystem timeline
8. `list_deleted_files(image_path)` → cleaned-up artifacts
9. `summarize_evtx(image_path, channel="Security")` → logon/process events
10. `extract_registry_run_keys(image_path)` → persistence mechanisms
11. **Gate:** Record ALL findings with `add_finding()` before Phase 3

## Phase 3: Anomaly Detection
1. `sigma_scan(case_id)` → universal anomaly detection across all findings
2. Review CRITICAL and HIGH hits first
3. For each hit, follow the `pivot_suggestion`
4. `compare_disk_and_memory(case_id)` → cross-artifact correlation (6 checks)
5. **Gate:** All CRITICAL/HIGH anomalies investigated

## Phase 4: Deep Dive & Correlation
1. Follow pivot chains from anomalies (see /pivot-methodology)
2. `run_analysis(data_path, query)` for ad-hoc data questions
3. Build timeline: `build_timeline(source_path, case_id)`
4. Query timeline around key events: `query_timeline(plaso_path, start, end)`
5. `flag_discrepancy()` for any manual contradictions found
6. **Gate:** All discrepancies resolved or documented as open questions

## Phase 5: Report Generation
1. `read_state(case_id)` → verify all findings are recorded
2. `generate_report(case_id)` → produce final summary
3. `generate_graph(case_id)` → create investigation visualization
4. **Gate:** Report generated, all findings have status != HYPOTHESIS

## Decision Points
- If blind mode: DO NOT reference known_iocs, discover everything independently
- If seeded mode: Use IOCs to prioritize but still run full collection
- If sigma_scan returns 0 hits: recheck evidence mounting, run YARA scans
- If correlation finds discrepancies: enter self-correction loop before report
