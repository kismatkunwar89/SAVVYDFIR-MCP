# SAVVYDFIR-MCP

> DFIR MCP server for SIFT Workstation that correlates disk and memory evidence, tracks provenance, and produces investigation reports.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: SIFT Workstation](https://img.shields.io/badge/Platform-SIFT%20Workstation-orange.svg)](https://github.com/teamdfir/protocol-sift)
[![Framework: Claude Code](https://img.shields.io/badge/Framework-Claude%20Code-purple.svg)](https://www.anthropic.com/claude-code)

---

## What It Does

SAVVYDFIR-MCP is a purpose-built MCP (Model Context Protocol) server that turns Claude Code into a DFIR investigation interface on SANS SIFT Workstation. It exposes 56 typed forensic tools over stdio transport (see `describe_tool_catalog`), supports cross-artifact correlation between disk and memory evidence via 10 anti-forensics detection checks, and keeps findings traceable through persisted artifacts, state, and audit logs with court-defensible provenance (Section 3-lite evidence schema + CTX heuristic provenance chain).

---

## Architecture

```
  Evidence Files                     SIFT CLI Tools              MCP Server
  ─────────────                     ──────────────              ──────────
  /evidence/disk/*.E01    ───>    ewfmount, fls, mmls     ───>  ┌──────────────┐
  /evidence/memory/*.zip  ───>    vol3, yara              ───>  │ savvydfir-mcp│
                                  MFTECmd, EvtxECmd       ───>  │ (FastMCP)    │
                                  log2timeline.py         ───>  │              │
                                  regripper, strings      ───>  │  SafeRunner  │
                                                                │  AuditLogger │
                                                                │  StateManager│
                                                                └──────┬───────┘
                                                                       │ stdio
                                                                       │ JSON-RPC
                                                                       v
                                                                ┌──────────────┐
                                                                │  Claude Code │
                                                                │  Agent Loop  │
                                                                │              │
                                                                │  Skill:      │
                                                                │ .agents/     │
                                                                │ skills/      │
                                                                │ workflow     │
                                                                └──────┬───────┘
                                                                       │
                                                                       v
                                                                ┌──────────────┐
                                                                │   Output     │
                                                                │              │
                                                                │ state.json   │
                                                                │ audit.jsonl  │
                                                                │ report.html  │
                                                                │ graph.html   │
                                                                └──────────────┘
```

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **SIFT Workstation** | Ubuntu 22.04 x86-64 with Volatility 3, EZ Tools, Sleuth Kit, Plaso, YARA pre-installed |
| **Claude Code** | Install via `curl -fsSL https://claude.ai/install.sh | bash` |
| **Claude authentication** | Run `claude` and complete browser login; `ANTHROPIC_API_KEY` is mainly for automation |
| **Python 3.10+** | Included with SIFT Workstation |
| **.NET Runtime** | Required for EZ Tools (MFTECmd, EvtxECmd, etc.) |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/kismatkunwar89/SAVVYDFIR-MCP.git
cd SAVVYDFIR-MCP

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Install to /opt (production deployment)
sudo cp -r . /opt/SAVVYDFIR-MCP/

# 4. Install Claude Code (recommended native installer)
curl -fsSL https://claude.ai/install.sh | bash

# 5. Verify the install
claude --version

# 6. Authenticate
claude
```

Notes:

- Anthropic now recommends the native Claude Code installer on macOS, Linux, and WSL. It auto-updates in the background.
- `npm install -g @anthropic-ai/claude-code` still exists, but Anthropic documents it as deprecated in favor of the native installer.
- For interactive use, the normal authentication flow is to run `claude` and complete the browser login. `ANTHROPIC_API_KEY` is still useful for API-key-based automation, but it is no longer the best default onboarding step for humans.

---

## Usage

### Single Host

```bash
cd /opt/SAVVYDFIR-MCP
claude --allowedTools "mcp__savvydfir__*" \
  -p "Read case-templates/manifest.json and start the investigation. Investigate fully, run compare_disk_and_memory(case_id), run sigma_scan(case_id), call generate_report(case_id), call generate_graph(case_id), and stop only after both report outputs are written."
```

Claude calls MCP tools → accumulates findings → writes `analysis/state.json` + `analysis/audit.jsonl` → calls `generate_report(case_id)` and `generate_graph(case_id)`.
Output: `reports/{case_id}/report.html` and `reports/{case_id}/graph.html`.

### Multi-host Enterprise Investigation

Run each host as a separate Claude session with its own analysis directory:

```bash
# Per host — set SAVVYDFIR_ANALYSIS_DIR to isolate state
SAVVYDFIR_ANALYSIS_DIR=/opt/SAVVYDFIR-MCP/investigations/SRL-2018-DC \
  claude --allowedTools "mcp__savvydfir__*" \
  -p "Read case-templates/manifest.json and investigate."

# After all hosts — merge into unified cross-host graph
claude --allowedTools "mcp__savvydfir__*" \
  -p "Call merge_host_graphs() then build_reports_index()."
```

Serve all reports:

```bash
cd /opt/SAVVYDFIR-MCP/reports && python3 -m http.server 8080
# Open: http://<server>:8080/index.html
```

---

## Validation Status

Validated in live remote SIFT-host runs:

- Single-host investigation flow against a published Windows intrusion dataset
- Audit-backed completion for `compare_disk_and_memory`, `sigma_scan`, and `generate_report`
- Summary-first MCP responses for heavy disk tools
- Report and graph generation to `reports/{case_id}/`
- EVTX cache/idempotency fix under repeated workflow use
- v7 lane orchestration hardening at commit `bdffba4`: all required lanes reached `COMPLETE`, specialist lane writeback cleared stale delegates, and final `report.json`, `report.html`, `graph.json`, and `graph.html` were produced on the remote SIFT host
- `COMPLETE_WITH_GAPS` remains an expected investigation outcome when unresolved forensic discrepancies are still documented; it is not treated as a report-generation failure

Still pending broader end-to-end validation:

- Multi-host merge flow: `merge_host_graphs()` and `build_reports_index()`
- MCP-hosted graph serving via `serve_graph()` as the primary operator path
- Deferred optimization work from the original plan: parallel RECmd execution and wider timeout tuning
- Full live coverage of less-used artifact tools such as `analyze_vss`, `extract_pca`, `extract_shimcache`, `extract_srum`, `coverage_report`, and YARA/timeline workflows

So the current repo is ready for single-host investigations and Batch 1-4 validation, with adjacent multi-host and less-used artifact workflows still marked as pending live validation rather than fully signed off.

---

## Skills Reference

Claude Code skills provide on-demand forensic expertise. Skills auto-discover at startup (only name + description load). Full content loads when invoked.

| Slash Command | Skill | What It Does |
|---|---|---|
| `/memory-forensics` | Memory Forensics | Volatility 3 plugins: pslist, psscan, netscan, malfind, dlllist, hashdump |
| `/disk-forensics` | Disk Forensics | ewfmount, mmls, fls, icat — E01 mounting and filesystem analysis |
| `/ez-tools` | EZ Tools | MFTECmd, EvtxECmd, PECmd, AppCompatCacheParser, LECmd, JLECmd, SBECmd, regripper |
| `/timeline` | Timeline | log2timeline.py + psort.py — super timeline creation and filtering |
| `/yara` | YARA | Signature scanning on disk files and memory dumps |

---

## Evidence Structure

```
/evidence/
  disk/
    base-wkstn-01-c-drive.E01     # Disk image (E01 format)
  memory/
    base-wkstn-01-mem.zip          # Memory dump (compressed)
```

Evidence directories are READ-ONLY. By default output goes to `analysis/` and `reports/`. Set `SAVVYDFIR_ANALYSIS_DIR` before launching Claude when you want per-host isolation.

---

## Manifest Fields

```json
{
  "case_id": "CASE-001",
  "mode": "blind",
  "investigation_goal": "Identify initial access, persistence, and lateral movement.",
  "disk_images": [
    {"path": "/evidence/disk/image.E01", "host": "wkstn-01", "image_type": "E01"}
  ],
  "memory_dumps": [
    {"path": "/evidence/memory/dump.zip", "host": "wkstn-01"}
  ],
  "known_iocs": [],
  "max_iterations": 4
}
```

| Field | Description |
|---|---|
| `case_id` | Unique case identifier |
| `mode` | `"blind"` (no IOC hints) or `"seeded"` (IOCs provided to agent) |
| `investigation_goal` | What the agent should determine |
| `disk_images` | Array of disk images with path, host, and format |
| `memory_dumps` | Array of memory dumps with path and host |
| `known_iocs` | IOC array (empty for blind mode) |
| `max_iterations` | Maximum triage iterations before forced completion |

---

## MCP Tools (41)

| Namespace | Tools | Description |
|---|---|---|
| evidence | `verify_integrity`, `get_provenance` | Hash verification and finding traceability |
| disk | `extract_prefetch`, `get_amcache`, `extract_mft_timeline`, `list_deleted_files`, `summarize_evtx`, `extract_registry_run_keys` | Windows disk artifact analysis |
| memory | `detect_profile`, `list_processes`, `scan_processes`, `scan_network`, `detect_injection`, `list_dlls` | Volatility 3 memory analysis |
| timeline | `build_timeline`, `query_timeline` | Plaso super timeline |
| yara | `scan_files`, `scan_memory` | YARA signature scanning |
| correlation | `compare_disk_and_memory`, `flag_discrepancy`, `find_temporal_clusters` | Cross-artifact correlation (10 anti-forensics checks) + temporal clustering for synthesis |
| state | `read_state`, `get_finding`, `get_findings`, `export_trace`, `describe_tool_catalog` | Case state summary, retrieval, trace export, and catalog metadata |
| lifecycle | `start_investigation`, `add_finding`, `coverage_report`, `generate_report` | Investigation lifecycle |
| mounting | `mount_image`, `load_memory` | Evidence preparation |
| graph | `generate_graph`, `serve_graph`, `merge_host_graphs`, `build_reports_index` | D3 investigation graph + multi-host unified view + reports dashboard |
| detection | `sigma_hunt`, `query_sigma_results`, `sigma_scan`, `analyze_vss`, `extract_pca`, `extract_shimcache`, `extract_srum` | Sigma/Chainsaw detection, read-only Sigma result paging, VSS recovery, PCA, ShimCache, SRUM |
| analysis | `run_analysis` | Targeted local Pandas analysis over CSV outputs |

### Retrieval and Response Contracts

- `read_state(case_id)` is the summary/resume surface. Use it for case status, counts, open questions, and the latest finding window.
- `get_findings(case_id, ...)` is the full finding-corpus retrieval surface. It supports `artifact_type`, `evidence_kind`, `finding_status`, `mitre_tactic`, `min_confidence`, `limit`, and `offset`.
- `get_finding(case_id, finding_id)` drills into a single `F-NNN` record.
- `extract_prefetch`, `get_amcache`, `extract_mft_timeline`, `summarize_evtx`, `extract_registry_run_keys`, and `generate_report` are summary-first by default. Pass `response_format="detailed"` only when you truly need raw `data` arrays.
- `extract_prefetch` separates exact Prefetch-native execution history from `.pf` file metadata: use `last_run_times` for run history, and treat `pf_created_time` / `pf_modified_time` as `.pf` file timestamps.
- `sigma_hunt(...)` creates findings and persists full hunt output. Use `query_sigma_results(output_path=..., ...)` for read-only filtering and paging over persisted Sigma JSON.
- Summary mode preserves the operational fields agents need, including `execution_id`, `records_count`, `total_records`, `csv_path`, `cache_hit`, and `findings_created`.

---

## Scoring (TP/FP/FN)

When evaluating against ground truth:

- **True Positive (TP):** Finding matches a known-bad artifact in ground truth
- **False Positive (FP):** Finding flagged as suspicious but is benign per ground truth
- **False Negative (FN):** Known-bad artifact in ground truth not detected by agent

The `compare_disk_and_memory()` correlation engine runs 6 specific checks:
1. Process in memory with no disk binary (fileless)
2. Execution evidence for deleted binary (cleanup)
3. VAD anomaly on legitimate process path (injection)
4. Network connection with no disk artifact (fileless C2)
5. Registry persistence key for missing binary (cleaned malware)
6. SI vs FN timestamp mismatch (timestomping)

---

## Self-Correction

When physical evidence contradicts itself, the agent:
1. Logs a `CORRECTION_EVENT` to `audit.jsonl`
2. Downgrades affected findings to HYPOTHESIS
3. Runs follow-up tools from the alert's `recommended_followup`
4. Re-promotes (OBSERVATION) or rejects (REJECTED) based on new evidence

This is evidence-triggered — it fires when disk and memory contradict, not when the LLM second-guesses itself.

---

## Project Structure

```
SAVVYDFIR-MCP/
├── CLAUDE.md                          # Business Brain (skills routing + rules)
├── README.md                          # This file
├── .mcp.json                          # MCP server connection config
├── requirements.txt                   # Python dependencies
├── .claude/
│   ├── settings.json                  # Claude Code MCP + hook config
│   ├── hooks/
│   │   ├── post-tool-use.py           # Non-blocking dispatcher + tool follow-up context
│   │   └── stop.py                    # Completion verification from state.json + audit.jsonl
│   ├── agents/                        # Specialist analysts (MFT, EVTX, registry, memory, etc.)
│   └── skills/
│       ├── investigation-workflow/    # Primary investigation sequencing guidance
│       ├── artifact-routing/          # Artifact-to-specialist routing
│       ├── pivot-methodology/         # Cross-artifact pivoting patterns
│       └── tools-reference/           # Tool contract reference
├── case-templates/
│   └── manifest.json                  # Example case manifest
├── sift_mcp/
│   ├── server.py                      # FastMCP entry point (all tools registered)
│   ├── audit.py                       # JSONL audit logger (fail-closed)
│   ├── state.py                       # Case state manager
│   ├── models/                        # Pydantic data models
│   ├── tools/                         # MCP tool implementations
│   └── runners/                       # SafeRunner subprocess wrappers
├── scripts/
│   ├── investigation_graph.py         # Per-case D3 graph builder (called by generate_graph)
│   ├── merge_graphs.py               # Cross-host IOC graph merger (called by merge_host_graphs)
│   └── build_index.py                # Reports index generator (called by build_reports_index)
├── analysis/                          # Default single-host working state
│   ├── state.json
│   └── audit.jsonl
├── investigations/                    # Optional per-host state roots via SAVVYDFIR_ANALYSIS_DIR
│   └── {SCENARIO}-{HOST}/
│       ├── manifest.json
│       ├── state.json
│       └── audit.jsonl
├── reports/                           # Investigation outputs (gitignored)
│   ├── index.html                     # Dashboard (build_reports_index)
│   ├── {case_id}/
│   │   ├── report.html                # Per-host report (generate_report)
│   │   ├── graph.html                 # Per-host graph (generate_graph)
│   │   └── graph.json
│   └── unified/
│       ├── graph.html                 # Cross-host graph (merge_host_graphs)
│       └── graph.json
└── docs/                              # Architecture and methodology docs
```

---

## License

MIT License — Copyright (c) 2026 Kismat Kunwar. See [LICENSE](LICENSE).
