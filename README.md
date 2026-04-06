# SAVVYDFIR-MCP

> Autonomous DFIR agent that correlates disk and memory evidence, self-corrects on contradiction, and produces fully traceable forensic findings — without human intervention.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: SIFT Workstation](https://img.shields.io/badge/Platform-SIFT%20Workstation-orange.svg)](https://github.com/teamdfir/protocol-sift)
[![Framework: Claude Code](https://img.shields.io/badge/Framework-Claude%20Code-purple.svg)](https://www.anthropic.com/claude-code)

---

## What It Does

- **Cross-artifact correlation** — `compare_disk_and_memory()` automatically identifies forensically significant discrepancies between disk and memory evidence on the same host across 6 specific checks (fileless processes, deleted-binary execution, VAD anomalies, network attribution, registry persistence gaps, and timestomping).
- **Evidence-triggered self-correction** — when physical evidence contradicts itself the agent logs a `CORRECTION_EVENT`, downgrades the affected finding, runs follow-up tools, and re-promotes or rejects the finding based on new evidence — not on LLM stylistic revision.
- **Traceable findings** — every finding carries an `execution_id`, `artifact_path`, and `artifact_offset` linking it to the exact subprocess call that produced it. `trace_finding.py` reconstructs the full provenance chain from finding ID to raw tool output.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          SIFT WORKSTATION                                │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                     CLAUDE CODE AGENT LOOP                         │  │
│  │                                                                    │  │
│  │  ~/.claude/CLAUDE.md (global rules)                               │  │
│  │  /cases/<ID>/CLAUDE.md (case context)                             │  │
│  │  /cases/<ID>/manifest.json (evidence paths, IOCs)                 │  │
│  │                                                                    │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │  │
│  │  │ Planning    │→ │ Execution    │→ │ Validation & Correction  │ │  │
│  │  │ Phase       │  │ Phase        │  │ Phase                    │ │  │
│  │  │(triage plan)│  │(tool calls)  │  │(self-correction loop)    │ │  │
│  │  └─────────────┘  └──────┬───────┘  └──────────┬───────────────┘ │  │
│  └───────────────────────────┼─────────────────────┼─────────────────┘  │
│                              │ stdio JSON-RPC 2.0   │                    │
│                              │ (MCP transport)      │                    │
│                              ▼                      │                    │
│  ┌────────────────────────────────────────────────┐ │                    │
│  │           SAVVYDFIR-MCP SERVER (FastMCP)       │ │                    │
│  │                                                │ │                    │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────────┐  │ │                    │
│  │  │evidence/ │ │ disk/    │ │ memory/       │  │ │                    │
│  │  │(2 tools) │ │(6 tools) │ │(6 tools)      │  │ │                    │
│  │  └──────────┘ └──────────┘ └───────────────┘  │ │                    │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────────┐  │ │                    │
│  │  │timeline/ │ │ yara/    │ │ correlation/  │  │ │                    │
│  │  │(2 tools) │ │(2 tools) │ │(2 tools)      │  │ │                    │
│  │  └──────────┘ └──────────┘ └───────────────┘  │ │                    │
│  │  ┌──────────┐ ┌──────────────────────────────┐ │ │                    │
│  │  │ state/   │ │ SafeRunner (read-only layer) │ │ │                    │
│  │  │(2 tools) │ │ + AuditLogger (JSONL)        │ │ │                    │
│  │  └──────────┘ └──────────────────────────────┘ │ │                    │
│  │            → Pydantic typed responses           │ │                    │
│  │            → subprocess.run(shell=False)        │ │                    │
│  │            → Path validation + deny list        │ │                    │
│  └──────────────────────┬─────────────────────────┘ │                    │
│                         │                           │                    │
│                         ▼                           │                    │
│  ┌─────────────────────────────────────────────┐    │                    │
│  │         SIFT WORKSTATION TOOLS              │    │                    │
│  │                                             │    │                    │
│  │  Volatility 3 (/opt/volatility3-2.20.0/)   │    │                    │
│  │  EZ Tools   (dotnet /opt/zimmermantools/)   │    │                    │
│  │  Sleuth Kit (fls, icat, mmls, ewfverify)    │    │                    │
│  │  Plaso      (log2timeline.py, psort.py)     │    │                    │
│  │  YARA       (yara CLI)                      │    │                    │
│  └─────────────────────────────────────────────┘    │                    │
│                         │                           │                    │
│                         ▼                           ▼                    │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                      OUTPUT LAYER                                │    │
│  │                                                                  │    │
│  │  audit.jsonl      → Per-tool-call structured execution log       │    │
│  │  findings.json    → Authoritative finding state (all F-IDs)      │    │
│  │  narrative.md     → Investigative narrative (timeline + analysis) │    │
│  │  report.pdf       → WeasyPrint PDF (Protocol SIFT generator)     │    │
│  │  graph.html       → D3.js investigation graph (stretch goal)     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start (For Judges)

```bash
# 1. Clone the repository
git clone https://github.com/kismatkunwar89/savvydfir-mcp.git
cd savvydfir-mcp

# 2. Run the installer (installs Protocol SIFT first, then SAVVYDFIR-MCP)
bash install.sh

# 3. Set your Anthropic API key
export ANTHROPIC_API_KEY='sk-ant-...'

# 4. Activate the virtual environment
source venv/bin/activate

# 5. Mount your evidence (read-only)
sudo ewfmount /path/to/base-wkstn-01-c-drive.E01 /mnt/disk
# Memory dump is referenced by path — no mount required for raw .mem files

# 6. Set up the demo case
cp -r examples/SRL-2018-WKSTN-01/ /cases/SRL-2018-WKSTN-01/
# Edit /cases/SRL-2018-WKSTN-01/manifest.json with your evidence paths

# 7. Launch the investigation
cd /cases/SRL-2018-WKSTN-01/
claude

# 8. Trace a specific finding
python3 /path/to/savvydfir-mcp/scripts/trace_finding.py F-004

# 9. (Optional) View the investigation graph
python3 /path/to/savvydfir-mcp/scripts/build_graph.py ./analysis/
python3 -m http.server 8080
# Open http://localhost:8080/graph/ in your browser
```

### Expected Output

After a complete triage run on a compromised workstation you should see:

- `analysis/audit.jsonl` — one JSONL line per tool call, with command lines and finding IDs
- `analysis/findings.json` — structured findings with `evidence_kind`, `confidence`, and provenance
- `analysis/narrative.md` — investigative narrative with OBSERVATION/INFERENCE/HYPOTHESIS labels
- `analysis/report.pdf` — PDF report (generated via Protocol SIFT's `generate_pdf_report.py`)

---

## How It Works

### Triage Flow

```
1. INTEGRITY    verify_integrity() on all evidence files → records SHA-256 in audit log
        ↓
2. DISK         extract_prefetch, get_amcache, extract_mft_timeline,
                list_deleted_files, summarize_evtx, extract_registry_run_keys
        ↓
3. MEMORY       detect_profile, list_processes, scan_processes,
                scan_network, detect_injection
        ↓
4. CORRELATION  compare_disk_and_memory() — runs all 6 checks
                → DiscrepancyAlerts trigger CORRECTION_EVENTs
        ↓
5. ENRICHMENT   list_dlls on suspicious PIDs, scan_memory with YARA rules,
                query_timeline around suspicious timestamps
        ↓
6. COMPLETION   All findings corroborated, open questions documented,
                narrative.md + report.pdf generated
```

### Self-Correction Loop

When `compare_disk_and_memory()` returns a `DiscrepancyAlert`:

1. The agent logs a `CORRECTION_EVENT` to `audit.jsonl` with `prior_claim`, `contradiction_source`, and `correction_type`.
2. Affected findings are downgraded from `OBSERVATION`/`INFERENCE` to `HYPOTHESIS`.
3. The agent runs the `recommended_followup` tools listed in the alert.
4. Based on follow-up results, findings are re-promoted to `OBSERVATION` (confirmed) or `REJECTED` (benign explanation found).
5. A `confidence_delta` is recorded in the `CorrectionEvent`.

This loop is evidence-triggered — it fires when physical evidence contradicts itself, not when the LLM second-guesses itself.

---

## MCP Tools (24 Total)

| # | Namespace | Tool | Description |
|---|---|---|---|
| 1 | evidence | `verify_integrity` | Run `ewfverify` on evidence image; record SHA-256 in audit log |
| 2 | evidence | `get_provenance` | Trace any finding ID to its exact tool execution via audit.jsonl |
| 3 | disk | `extract_prefetch` | Parse Prefetch files via PECmd; returns run count + last 8 timestamps |
| 4 | disk | `get_amcache` | Parse Amcache.hve via AmcacheParser; returns SHA1 hashes of executed binaries |
| 5 | disk | `extract_mft_timeline` | Parse $MFT via MFTECmd; detects timestomping ($SI vs $FN mismatch) |
| 6 | disk | `list_deleted_files` | Run `fls -rd`; recovers deleted file metadata from unallocated MFT entries |
| 7 | disk | `summarize_evtx` | Parse event logs via EvtxECmd; surfaces 4624/4688/4732/7045 events |
| 8 | disk | `extract_registry_run_keys` | Parse persistence keys via RECmd; Run/RunOnce/AppInit/Winlogon/Services |
| 9 | memory | `detect_profile` | Run `vol windows.info`; identifies OS version required for all other plugins |
| 10 | memory | `list_processes` | Run `vol windows.pslist`; linked-list walk (OS-visible processes) |
| 11 | memory | `scan_processes` | Run `vol windows.psscan`; pool tag scan (finds hidden/unlinked DKOM processes) |
| 12 | memory | `scan_network` | Run `vol windows.netscan`; active and recently closed connections with PIDs |
| 13 | memory | `detect_injection` | Run `vol windows.malfind`; flags `PAGE_EXECUTE_READWRITE` VADs with PE headers |
| 14 | memory | `list_dlls` | Run `vol windows.dlllist`; loaded DLLs per process (unexpected DLLs = injection) |
| 15 | timeline | `build_timeline` | Run `log2timeline.py`; generate Plaso super-timeline from all artifact sources |
| 16 | timeline | `query_timeline` | Run `psort.py`; filter super-timeline by time window and IOC string |
| 17 | yara | `scan_files` | Run `yara` against disk artifacts; signature-based detection |
| 18 | yara | `scan_memory` | Run `yara` against raw memory dump; catches packed/encrypted payloads |
| 19 | correlation | `compare_disk_and_memory` | Run all 6 correlation checks; returns `CorrelationReport` with `DiscrepancyAlerts` |
| 20 | correlation | `flag_discrepancy` | Manually flag a contradiction between two findings |
| 21 | state | `read_state` | Read current authoritative `CaseState` (all findings + executions) |
| 22 | state | `export_trace` | Export full execution trace as `list[AuditEntry]` |
| 23 | graph | `build_investigation_graph` | Generate node/edge data for D3.js graph from audit.jsonl + findings.json |
| 24 | graph | `get_finding_neighborhood` | Return the immediate graph neighborhood of a finding ID |

---

## Evidence Classification

Every finding is assigned one of four `evidence_kind` values:

| Kind | Meaning | Requirement |
|---|---|---|
| `OBSERVATION` | Directly supported by tool output | `artifact_path` + `artifact_offset` must be present |
| `INFERENCE` | Analytical conclusion supported by ≥2 observations | Must cite corroborating finding IDs |
| `HYPOTHESIS` | Candidate lead requiring confirmation | Used as default; promoted after corroboration |
| `REJECTED` | Considered and ruled out | Documented reason required |

The agent is prohibited from stating a finding as `OBSERVATION` without `artifact_path` and `artifact_offset` in the provenance record. This eliminates hallucinated observations at the data model level.

---

## Self-Correction

The self-correction mechanism is evidence-triggered, not stylistic. It fires under these conditions:

1. `compare_disk_and_memory()` returns a `DiscrepancyAlert`
2. A tool exits non-zero or returns an empty result set
3. A memory process has no disk-backed binary (correlation check 1)
4. A Prefetch/Amcache entry refers to a binary absent from disk (correlation check 2)
5. A new finding contradicts a prior `OBSERVATION` or `INFERENCE`

Each correction is logged as a `CorrectionEvent` in `audit.jsonl`:

```json
{
  "correction_event": {
    "prior_claim": "svchost.exe (PID 1832) appears legitimate based on pslist output",
    "contradiction_source": "correlation.compare_disk_and_memory: process_no_disk_binary",
    "revised_claim": "svchost.exe (PID 1832) binary absent from disk; VAD analysis confirms reflective DLL injection",
    "affected_finding_ids": ["F-003"],
    "confidence_delta": 0.6,
    "correction_type": "evidence_contradiction"
  }
}
```

---

## Project Structure

```
savvydfir-mcp/
│
├── LICENSE
├── README.md
├── install.sh                      # One-command setup
├── requirements.txt
│
├── sift_mcp/                       # MCP server (Python package)
│   ├── server.py                   # FastMCP entry point — registers all 24 tools
│   ├── audit.py                    # Synchronous JSONL audit logger (fail-closed)
│   ├── state.py                    # Authoritative case state manager
│   ├── models/                     # Pydantic data models
│   │   ├── case.py                 # CaseManifest, CaseState
│   │   ├── finding.py              # Finding, EvidenceKind enum
│   │   ├── execution.py            # Execution, CorrectionEvent
│   │   └── artifacts.py            # ProcessRecord, PrefetchRecord, AmcacheRecord, ...
│   ├── tools/                      # MCP tool implementations
│   │   ├── evidence.py             # verify_integrity, get_provenance
│   │   ├── disk.py                 # 6 disk tools
│   │   ├── memory.py               # 6 memory tools
│   │   ├── timeline.py             # build_timeline, query_timeline
│   │   ├── yara.py                 # scan_files, scan_memory
│   │   └── correlation.py          # compare_disk_and_memory, flag_discrepancy
│   ├── runners/                    # SafeRunner subprocess wrappers
│   │   ├── base.py                 # SafeRunner: read-only enforcement, path validation
│   │   ├── volatility.py           # Volatility 3 runner
│   │   ├── sleuthkit.py            # fls, icat, mmls, ewfverify
│   │   ├── plaso.py                # log2timeline, psort (with timeout + pagination)
│   │   ├── eztools.py              # MFTECmd, PECmd, AmcacheParser, EvtxECmd, RECmd
│   │   └── yara_runner.py          # yara CLI runner
│   └── parsers/                    # Raw text → Pydantic model parsers
│       ├── vol_parsers.py
│       ├── ez_parsers.py
│       ├── tsk_parsers.py
│       └── plaso_parsers.py
│
├── claude_config/                  # Claude Code configuration
│   ├── CLAUDE.md                   # Global system prompt (extends Protocol SIFT)
│   ├── settings.json               # Permissions (allow/deny lists + MCP server config)
│   └── hooks.json                  # PostToolUse + Stop hooks
│
├── skills/                         # Claude Code skill files
│   ├── savvydfir-triage/SKILL.md   # Full triage workflow (6 phases)
│   ├── self-correction/SKILL.md    # When and how to self-correct
│   └── correlation/SKILL.md        # Cross-artifact correlation methodology
│
├── case-templates/
│   ├── CLAUDE.md                   # Per-case template
│   └── manifest.json               # Case manifest template
│
├── examples/
│   └── SRL-2018-WKSTN-01/
│       ├── CLAUDE.md
│       ├── manifest.json
│       └── analysis/
│           ├── audit.jsonl         # Complete sample run
│           ├── findings.json       # Final finding state
│           └── narrative.md        # Generated investigative narrative
│
├── scripts/
│   ├── trace_finding.py            # CLI: trace finding_id → execution chain
│   ├── generate_accuracy_report.py # Auto-generate TP/FP/FN metrics from audit.jsonl
│   └── build_graph.py              # Generate investigation graph HTML
│
├── graph/                          # Investigation graph visualization (D3.js)
│   ├── index.html
│   ├── graph.js
│   └── style.css
│
├── tests/
│   ├── test_saferunner.py
│   ├── test_parsers.py
│   ├── test_models.py
│   ├── test_correlation.py
│   └── test_guardrails.py
│
└── docs/
    ├── novel-contribution.md
    ├── architecture.md
    ├── dataset-documentation.md
    ├── accuracy-report.md
    └── eval-methodology.md
```

---

## Requirements

| Requirement | Detail |
|---|---|
| **SIFT Workstation** | Ubuntu x86-64 with Volatility 3, EZ Tools, Sleuth Kit, Plaso, YARA pre-installed. Download from [SANS](https://www.sans.org/tools/sift-workstation/). |
| **Claude Code** | `npm install -g @anthropic-ai/claude-code` |
| **Anthropic API key** | `export ANTHROPIC_API_KEY='sk-ant-...'` |
| **Python 3.8+** | Included with SIFT Workstation |
| **Protocol SIFT** | Installed automatically by `install.sh` |

---

## Running Against Evidence

### Step 1: Prepare evidence

```bash
# Mount a disk image read-only
sudo ewfmount /evidence/base-wkstn-01-c-drive.E01 /mnt/disk

# Memory dumps are referenced by path — no mounting required
ls /evidence/base-wkstn-01-mem.raw
```

### Step 2: Create a case

```bash
cp -r case-templates/ /cases/MY-CASE-001/
cd /cases/MY-CASE-001/
```

Edit `manifest.json`:

```json
{
  "case_id": "MY-CASE-001",
  "disk_images": [
    {"path": "/mnt/disk", "host": "wkstn-01", "image_type": "E01"}
  ],
  "memory_dumps": [
    {"path": "/evidence/base-wkstn-01-mem.raw", "host": "wkstn-01"}
  ],
  "known_iocs": ["192.0.2.45", "malware.exe"],
  "investigation_goal": "Determine initial access vector, persistence mechanism, and lateral movement path.",
  "max_iterations": 4
}
```

### Step 3: Run the investigation

```bash
cd /cases/MY-CASE-001/
claude
# The agent reads manifest.json, runs the triage workflow, and writes results to ./analysis/
```

### Step 4: Monitor progress

In a separate terminal:

```bash
# Watch the audit log grow in real time
tail -f /cases/MY-CASE-001/analysis/audit.jsonl | python3 -m json.tool

# Check current findings
cat /cases/MY-CASE-001/analysis/findings.json | python3 -m json.tool
```

---

## Viewing Results

### Audit log (`analysis/audit.jsonl`)

One JSON line per tool call. Each line contains:

```json
{
  "timestamp": "2026-05-01T14:23:11.442Z",
  "execution_id": "E-007",
  "agent_turn": 7,
  "iteration": 1,
  "tool": "memory.detect_injection",
  "parameters": {"dump_path": "/evidence/wkstn-01.raw", "pid": null},
  "command_line": "python3 /opt/volatility3-2.20.0/vol.py -f /evidence/wkstn-01.raw windows.malfind",
  "exit_code": 0,
  "duration_seconds": 12.4,
  "stdout_lines": 47,
  "outputs_summary": "3 VAD regions with PAGE_EXECUTE_READWRITE flagged",
  "finding_ids_generated": ["F-004"],
  "correction_event": null,
  "agent_reason": "Scanning for injection indicators after pslist showed 47 processes"
}
```

### Findings (`analysis/findings.json`)

Array of `Finding` objects, each with:

- `finding_id` (F-001, F-002, ...)
- `evidence_kind` (OBSERVATION / INFERENCE / HYPOTHESIS / REJECTED)
- `confidence` (0.0–1.0)
- `artifact_path` and `artifact_offset`
- `execution_id` linking to the audit log
- `mitre_tactic` and `mitre_technique`
- `contradicted_by` and `corroborated_by` (list of finding IDs)

### Trace a finding

```bash
python3 scripts/trace_finding.py F-004
```

Output:

```
Finding: F-004
  Execution:   E-007
  Tool:        memory.detect_injection
  Command:     python3 /opt/volatility3-2.20.0/vol.py -f /evidence/wkstn-01.raw windows.malfind
  Time:        2026-05-01T14:23:11.442Z
  Duration:    12.4s
  Exit code:   0
  Summary:     3 VAD regions with PAGE_EXECUTE_READWRITE flagged
  Description: svchost.exe (PID 1832) — reflective DLL injection confirmed via malfind
  Corrections: 1
    CORRECTION:
      Prior:     svchost.exe (PID 1832) appears legitimate based on pslist output
      Source:    correlation.compare_disk_and_memory: process_no_disk_binary
      Revised:   Binary absent from disk; VAD confirms reflective DLL injection
      Conf Δ:    +0.60
```

### Graph visualization

```bash
python3 scripts/build_graph.py /cases/MY-CASE-001/analysis/
python3 -m http.server 8080
# Open http://localhost:8080/graph/
```

Node colors: green = OBSERVATION, yellow = INFERENCE, orange = HYPOTHESIS, red = REJECTED.
Red dashed edges are self-correction paths.

---

## Novel Contributions

SAVVYDFIR-MCP extends [Protocol SIFT](https://github.com/teamdfir/protocol-sift) with three capabilities absent from all existing published DFIR-LLM systems:

1. **Cross-artifact contradiction detection** — `compare_disk_and_memory()` runs 6 specific checks against paired disk and memory evidence. No existing Protocol SIFT extension, Valhuntir, or published LLM-DFIR pipeline (including DFIR-Chain) implements automated cross-source contradiction detection. Justified by SynthChain's finding that two-source fusion yields 1.6× coverage improvement over single-source analysis.

2. **Evidence-triggered self-correction** — corrections fire when physical evidence contradicts itself, not when the LLM self-doubts. The `CORRECTION_EVENT` format provides a structured audit trail of what changed, why, and by how much (confidence delta). Modeled on ProveRAG's self-critique mechanism, which achieves 99% accuracy for exploitation information vs. 6% for prompt-only approaches.

3. **Architectural read-only enforcement** — `SafeRunner` enforces zero-spoliation at the transport layer via backend-owned CLI construction, validated mount options, `subprocess.run(shell=False)`, and a deny-listed command list. Directly addresses the MCP Safety Audit finding that current MCP designs allow major security exploits through prompt-controlled command execution.

See [docs/novel-contribution.md](docs/novel-contribution.md) for the full statement with academic citations.

---

## Academic References

1. DFIR-Chain: "Integrating Memory Forensics, YARA Scanning, and LLM Summarization for Automated Triage," IEEE, August 2025. https://ieeexplore.ieee.org/document/11187513/
2. Lang & Schreck: "Leveraging LLMs for Memory Forensics: A Comparative Analysis of Malware Detection," ACM Digital Threats, December 2025. https://dl.acm.org/doi/10.1145/3748263
3. SynthChain: "A Synthetic Benchmark and Forensic Analysis of Advanced and Stealthy Software Supply Chain Attacks," arXiv, March 2026. https://arxiv.org/abs/2603.16694
4. PROV-AGENT: "Unified Provenance for Tracking AI Agent Interactions in Agentic Workflows," IEEE, 2025. https://ieeexplore.ieee.org/document/11181558/
5. ProveRAG: "Provenance-Driven Vulnerability Analysis with Automated Retrieval Augmented Generation," IEEE Access, December 2025. https://ieeexplore.ieee.org/document/11272947/
6. MCP Safety Audit: "LLMs with the Model Context Protocol Allow Major Security Exploits," arXiv, April 2025. https://arxiv.org/abs/2504.03767
7. DFIR-Metric: "A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response," arXiv, May 2025. https://arxiv.org/html/2505.19973v1
8. Unified Knowledge Graph for Digital Evidence: "A Unified Knowledge Graph to Permit Interoperability of Heterogeneous Digital Evidence," arXiv, February 2024. https://arxiv.org/abs/2402.13746

---

## Troubleshooting

### Volatility profile not detected

```bash
# Verify the memory dump is accessible
file /evidence/wkstn-01.raw

# Run detect_profile manually
python3 /opt/volatility3-2.20.0/vol.py -f /evidence/wkstn-01.raw windows.info
```

### Plaso timeout

`build_timeline` can take 10–30 minutes on large disk images. The tool has a configurable timeout (default 1800 seconds). If it times out, the agent will fall back to `query_timeline` on a pre-built timeline if one exists.

### MCP server not connecting

Check that the venv is activated and `settings.json` points to the correct Python path:

```bash
source venv/bin/activate
python3 -c "import fastmcp; print(fastmcp.__version__)"
# Should print 2.x.x
```

### EZ Tools error

```bash
dotnet /opt/zimmermantools/PECmd.dll --help
# If dotnet is missing: sudo apt-get install -y dotnet-sdk-8.0
```

### Audit log not growing

The audit logger is fail-closed — if `./analysis/` does not exist, tool calls will fail. Ensure the case directory has the `analysis/` subdirectory:

```bash
mkdir -p /cases/MY-CASE-001/analysis/
```

---

## License

MIT License — Copyright (c) 2026 Kismat Kunwar. See [LICENSE](LICENSE).
