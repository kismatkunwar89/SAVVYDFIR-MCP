# SAVVYDFIR-MCP

> Autonomous DFIR agent that correlates disk and memory evidence, self-corrects on contradiction, and produces fully traceable forensic findings — without human intervention.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: SIFT Workstation](https://img.shields.io/badge/Platform-SIFT%20Workstation-orange.svg)](https://github.com/teamdfir/protocol-sift)
[![Framework: Claude Code](https://img.shields.io/badge/Framework-Claude%20Code-purple.svg)](https://www.anthropic.com/claude-code)

---

## What It Does

SAVVYDFIR-MCP is a purpose-built MCP (Model Context Protocol) server that turns Claude Code into an autonomous DFIR investigator on SANS SIFT Workstation. It exposes 24+ typed forensic tools over stdio transport, runs cross-artifact correlation between disk and memory evidence, and produces fully traceable findings with evidence-triggered self-correction.

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
                                                                │  Skills:     │
                                                                │  /memory-    │
                                                                │   forensics  │
                                                                │  /disk-      │
                                                                │   forensics  │
                                                                │  /ez-tools   │
                                                                │  /timeline   │
                                                                │  /yara       │
                                                                └──────┬───────┘
                                                                       │
                                                                       v
                                                                ┌──────────────┐
                                                                │   Output     │
                                                                │              │
                                                                │ audit.jsonl  │
                                                                │ findings.json│
                                                                │ narrative.md │
                                                                │ report.pdf   │
                                                                └──────────────┘
```

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **SIFT Workstation** | Ubuntu 22.04 x86-64 with Volatility 3, EZ Tools, Sleuth Kit, Plaso, YARA pre-installed |
| **Claude Code** | `npm install -g @anthropic-ai/claude-code` |
| **Anthropic API key** | `export ANTHROPIC_API_KEY='sk-ant-...'` |
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

# 4. Install Claude Code CLI
npm install -g @anthropic-ai/claude-code

# 5. Authenticate
export ANTHROPIC_API_KEY='sk-ant-...'
```

---

## Usage

### Mode 1: Blind Investigation (no IOCs provided)

```bash
# Set up case manifest with mode: "blind"
cd /cases/CASE-001/
claude   # Agent investigates without IOC bias
```

### Mode 2: Seeded Validation (IOCs provided)

```bash
# Edit manifest.json: set mode: "seeded" and populate known_iocs
cd /cases/CASE-002/
claude   # Agent uses IOCs to prioritize analysis
```

### Mode 3: Single-Host Triage

```bash
# Quick triage on one workstation
claude "Read /opt/SAVVYDFIR-MCP/case-templates/manifest.json and run a full investigation"
```

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

Evidence directories are READ-ONLY. All output goes to `/cases/`.

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

## MCP Tools (24+)

| Namespace | Tools | Description |
|---|---|---|
| evidence | `verify_integrity`, `get_provenance` | Hash verification and finding traceability |
| disk | `extract_prefetch`, `get_amcache`, `extract_mft_timeline`, `list_deleted_files`, `summarize_evtx`, `extract_registry_run_keys` | Windows disk artifact analysis |
| memory | `detect_profile`, `list_processes`, `scan_processes`, `scan_network`, `detect_injection`, `list_dlls` | Volatility 3 memory analysis |
| timeline | `build_timeline`, `query_timeline` | Plaso super timeline |
| yara | `scan_files`, `scan_memory` | YARA signature scanning |
| correlation | `compare_disk_and_memory`, `flag_discrepancy` | Cross-artifact correlation (6 checks) |
| state | `read_state`, `export_trace` | Case state management |
| lifecycle | `start_investigation`, `add_finding`, `generate_report` | Investigation lifecycle |
| mounting | `mount_image`, `load_memory` | Evidence preparation |

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
│   ├── settings.json                  # Permission allow/deny lists
│   ├── hooks/
│   │   ├── post-tool-use.py           # Error detection + auto-fix suggestions
│   │   └── stop.py                    # Completion verification
│   └── skills/
│       ├── memory-forensics/SKILL.md  # Volatility 3 reference
│       ├── disk-forensics/SKILL.md    # Sleuth Kit + ewfmount
│       ├── ez-tools/SKILL.md          # Eric Zimmerman tools
│       ├── timeline/SKILL.md          # Plaso/log2timeline
│       └── yara/SKILL.md              # YARA scanning
├── case-templates/
│   └── manifest.json                  # Example case manifest
├── sift_mcp/
│   ├── server.py                      # FastMCP entry point (all tools registered)
│   ├── audit.py                       # JSONL audit logger (fail-closed)
│   ├── state.py                       # Case state manager
│   ├── models/                        # Pydantic data models
│   ├── tools/                         # MCP tool implementations
│   └── runners/                       # SafeRunner subprocess wrappers
├── scripts/                           # Utility scripts
└── docs/                              # Architecture and methodology docs
```

---

## License

MIT License — Copyright (c) 2026 Kismat Kunwar. See [LICENSE](LICENSE).
