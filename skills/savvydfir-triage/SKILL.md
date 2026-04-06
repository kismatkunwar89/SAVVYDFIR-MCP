# SAVVYDFIR Triage Workflow

**Skill file for:** Phase-by-phase triage orchestration of a complete DFIR case.
**Load when:** Starting any new investigation case.

---

## Overview

A complete triage runs 7 sequential phases. Never skip a phase unless the relevant evidence type is unavailable — and always document skips. The agent must not advance to Phase 4 (Correlation) until Phases 2 and 3 are complete.

The most critical phase is **Phase 4 (Correlation)**. All DiscrepancyAlerts from `compare_disk_and_memory()` must be resolved before proceeding.

---

## Phase 1 — Integrity Verification

**Goal:** Confirm evidence has not been modified since acquisition.

### Steps
1. Read `manifest.json` to obtain all evidence file paths and their expected hashes.
2. Call `evidence.verify_integrity(path=<disk_image>)` for each disk image.
3. Call `evidence.verify_integrity(path=<memory_dump>)` for each memory dump.
4. Compare returned `sha256` against `manifest.json` `expected_sha256`.

### Decision Points
- **Hash matches all files** → proceed to Phase 2.
- **Hash mismatch on one file** → log OBSERVATION (artifact integrity failure), document in open_questions, continue with remaining evidence if operator has not restricted.
- **Hash mismatch on all files** → halt investigation, report integrity failure, do not proceed.
- **Tool error (non-zero exit_code)** → retry once; if still failing, document and proceed with caveat that integrity is unverified.

### Output
- OBSERVATION findings for each verified file: `integrity_verified: true/false`.
- Entry in `./analysis/audit.jsonl` for each `verify_integrity` call.

---

## Phase 2 — Disk Analysis

**Goal:** Enumerate all disk-resident artifacts that establish timeline and execution history.

### Tool Call Sequence

Run these tools in order. Each builds context for the next.

| Order | Tool | Purpose | Output artifact |
|---|---|---|---|
| 2.1 | `disk.extract_mft_timeline(image_path)` | Full MFT timeline — created/modified/accessed/changed timestamps for all files | `./analysis/mft_timeline.csv` |
| 2.2 | `disk.extract_prefetch(image_path)` | Prefetch entries — executable names, run counts, last run time, DLLs loaded | `./analysis/prefetch.csv` |
| 2.3 | `disk.get_amcache(image_path)` | Amcache — SHA1 hashes of executed binaries, install timestamps | `./analysis/amcache.csv` |
| 2.4 | `disk.list_deleted_files(image_path)` | Deleted file entries still in MFT or directory entries | `./analysis/deleted_files.csv` |
| 2.5 | `disk.summarize_evtx(image_path)` | Windows event logs — logon events (4624/4625), service installs (7045), process create (4688) | `./analysis/evtx_summary.csv` |
| 2.6 | `disk.extract_registry_run_keys(image_path)` | Run/RunOnce persistence keys from NTUSER.DAT, SOFTWARE, SYSTEM hives | `./analysis/registry_run_keys.csv` |

### When to Pivot
- **Prefetch entry for an executable with no matching disk binary** → flag immediately as HYPOTHESIS (execution + deletion). Do not wait for Phase 4 — mark it and continue.
- **Amcache SHA1 does not match a known-good hash** → flag as HYPOTHESIS (modified or replaced binary).
- **Registry persistence key points to a non-existent path** → flag as HYPOTHESIS (cleaned malware).
- **Deleted file with forensically relevant name** (e.g., `svch0st.exe`, `update.bat`) → flag as HYPOTHESIS.

### Stopping Criteria
All 6 tools must complete successfully OR be documented as failed/skipped before advancing to Phase 3.

---

## Phase 3 — Memory Analysis

**Goal:** Enumerate all memory-resident processes, network connections, and injection indicators.

### Tool Call Sequence

| Order | Tool | Purpose | Output artifact |
|---|---|---|---|
| 3.1 | `memory.detect_profile(dump_path)` | Identify OS version + Volatility profile | Required for all subsequent memory tools |
| 3.2 | `memory.list_processes(dump_path)` | Full process list — pslist + psscan combined | `./analysis/processes.json` |
| 3.3 | `memory.scan_processes(dump_path)` | Cross-validate pslist vs psscan to detect hidden processes | `./analysis/process_scan.json` |
| 3.4 | `memory.scan_network(dump_path)` | Active and recently-closed network connections | `./analysis/network_connections.json` |
| 3.5 | `memory.detect_injection(dump_path)` | VAD anomalies (PAGE_EXECUTE_READWRITE), malfind results | `./analysis/injection_candidates.json` |

### When to Pivot
- **Hidden process** (appears in psscan but not pslist) → immediately add to suspicious PID list.
- **Process with suspicious parent** (e.g., `cmd.exe` child of `word.exe`) → flag as HYPOTHESIS (malicious document macro).
- **Network connection to external IP with no disk binary** → flag as HYPOTHESIS (fileless C2).
- **VAD anomaly on a process with a legitimate name** (`svchost.exe`, `explorer.exe`) → flag as HYPOTHESIS (process injection or hollowing).

### Stopping Criteria
All 5 tools must complete (or be documented as failed) before advancing to Phase 4. Profile detection (3.1) must succeed — if it fails, all other memory tools will fail and the memory phase must be skipped with documentation.

---

## Phase 4 — Correlation (CRITICAL)

**Goal:** Cross-reference disk and memory findings to detect discrepancies that individually appear benign but together indicate compromise.

### Required Tool Call
```
correlation.compare_disk_and_memory(case_id=<case_id>)
```

This is the single most important tool call in the investigation. It runs all 6 correlation checks automatically (see `skills/correlation/SKILL.md` for full interpretation).

### Response to DiscrepancyAlert

A `DiscrepancyAlert` in the result is a mandatory trigger for the Self-Correction Protocol:

1. Load `skills/self-correction/SKILL.md` immediately.
2. Log a `CORRECTION_EVENT` for every finding referenced in `affected_finding_ids`.
3. Downgrade all referenced findings to HYPOTHESIS.
4. Execute every tool in `recommended_followup`.
5. Re-evaluate and reclassify.
6. **Do not proceed to Phase 5 until all DiscrepancyAlerts are resolved.**

### Severity Interpretation
- **1 discrepancy on a PID** → investigate thoroughly; may be benign (e.g., packed binary, temp file cleanup).
- **2+ discrepancies on the same PID** → strong compromise indicator; treat as INFERENCE of malicious activity.
- **Any discrepancy + YARA hit** → high-confidence finding; elevate to OBSERVATION if artifact_path + offset are present.

---

## Phase 5 — Enrichment

**Goal:** Deepen findings on confirmed suspicious indicators before writing the narrative.

### Trigger Conditions
Run enrichment on each PID or artifact that has been flagged as suspicious after Phase 4 correlation.

### Tool Call Sequence (per suspicious PID)

| Tool | Purpose |
|---|---|
| `memory.list_dlls(dump_path, pid=<pid>)` | Full DLL list for the process — identify suspicious or out-of-place modules |
| `yara.scan_memory(dump_path, pid=<pid>, rule_set=<applicable_rules>)` | Apply YARA rules to process memory — confirm known-bad signatures |
| `timeline.query_timeline(handle, start=<suspicious_time-5m>, end=<suspicious_time+5m>)` | Super-timeline slice around suspicious timestamps — find corroborating events |

### When to Stop Enrichment
- All suspicious PIDs and artifacts have been processed through at least one enrichment tool.
- Each enrichment result has been classified (OBSERVATION, INFERENCE, HYPOTHESIS, or REJECTED).

---

## Phase 6 — Completion Check

**Goal:** Verify that every promise made during triage has been kept before generating the final narrative.

### Checklist (must all be TRUE before proceeding)

- [ ] Every suspicious indicator has been checked against ≥1 corroborating artifact source.
- [ ] No unresolved contradictions exist at severity `medium` or higher.
- [ ] All `CORRECTION_EVENT` records have final disposition (no HYPOTHESIS left without a follow-up result).
- [ ] All tool failures are documented in `open_questions`.
- [ ] `max_iterations` has not been exceeded. If it has: document all open questions and proceed to Phase 7.

### If Not Complete
- Identify the specific unresolved item.
- Run the specific tool that would resolve it.
- Re-check this list.
- If `max_iterations` would be exceeded, document all remaining open questions and proceed.

---

## Phase 7 — Narrative + Export

**Goal:** Produce human-readable investigation output and export structured data.

### Steps

1. Call `state.generate_narrative(case_id)` → writes `./reports/narrative.md`
   - Structure: Executive Summary → Timeline of Events → Technical Findings → Open Questions → Recommendations
2. Call `state.export_findings(case_id)` → writes `./analysis/findings.json`
3. Call `state.export_trace(case_id)` → verifies `./analysis/audit.jsonl` is complete
4. (Optional) Call `python3 generate_pdf_report.py ./reports/narrative.md` → `./reports/report.pdf`

### Narrative Quality Standards
- Every claim in the narrative must be traceable to a `finding_id` in `findings.json`.
- Attack timeline must use UTC timestamps.
- Distinguish clearly between OBSERVATION (confirmed fact) and INFERENCE (analytical conclusion).
- List all HYPOTHESIS findings as "unconfirmed leads requiring further investigation."
- List all REJECTED findings in a brief appendix with rejection reasons.

---

## Pivoting Decision Tree

```
Tool result received
│
├── exit_code != 0 ──────────────────────────────────────────► Log failure, document in open_questions,
│                                                                try alternative CLI if no MCP tool available,
│                                                                continue with remaining tools
│
├── exit_code == 0, no new findings ──────────────────────────► Continue to next tool in phase sequence
│
├── exit_code == 0, new finding matches prior OBSERVATION ────► Reinforce prior finding (add corroborating_source)
│
├── exit_code == 0, new finding CONTRADICTS prior finding ────► SELF-CORRECTION PROTOCOL (load SKILL.md)
│
├── DiscrepancyAlert received ─────────────────────────────────► SELF-CORRECTION PROTOCOL (mandatory, load SKILL.md)
│
└── YARA hit on previously HYPOTHESIS process ─────────────────► Elevate to OBSERVATION if artifact_path + offset
                                                                  are available from YARA match
```

---

## Key Rules

1. Never advance from Phase 4 to Phase 5 with unresolved DiscrepancyAlerts.
2. Never write a finding as OBSERVATION without `artifact_path` + `offset`.
3. Never present an INFERENCE as an OBSERVATION.
4. Document every tool failure — do not silently skip.
5. `max_iterations` is a hard stop — document open questions and generate the narrative regardless of completeness.
