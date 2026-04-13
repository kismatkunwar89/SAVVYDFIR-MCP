# Architecture

**SAVVYDFIR-MCP** is a purpose-built MCP server that layers cross-artifact correlation and evidence-triggered self-correction on top of Protocol SIFT. This document describes all architectural layers, their interfaces, and the design decisions behind each.

---

## Top-Level System Diagram

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

## Layer 1: Claude Code Agent Loop

Claude Code acts as the orchestration engine. It reads two configuration inputs:

- **`~/.claude/CLAUDE.md`** (global) — defines the agent's identity, tool routing priority, evidence classification rules, and self-correction protocol.
- **`/cases/<ID>/CLAUDE.md`** (per-case) — defines the specific investigation: evidence paths, known IOCs, target time window, and investigation goal.

The agent loop has three phases per iteration:

```
Planning Phase
  → Agent reads manifest.json and prior audit.jsonl (if any)
  → Agent generates a triage plan: ordered list of tools to call
  → No tool calls happen in this phase

Execution Phase
  → Agent calls MCP tools in the planned order
  → Each tool call: build JSON-RPC 2.0 request → MCP server → subprocess → Pydantic response
  → Agent incorporates typed responses into its reasoning context

Validation & Correction Phase
  → Agent calls compare_disk_and_memory()
  → If DiscrepancyAlerts exist: CORRECTION_EVENT loop fires
  → Agent re-runs follow-up tools for each alert
  → Iteration complete when no unresolved contradictions remain
```

Maximum 4 iterations per investigation (configurable). Maximum 60 tool calls total.

---

## Layer 2: SAVVYDFIR-MCP Server

The server is implemented with [FastMCP](https://github.com/jlowin/fastmcp) and communicates with Claude Code over stdio JSON-RPC 2.0 transport.

### Tool Namespaces

```
sift_mcp/
├── tools/
│   ├── evidence.py    → verify_integrity, get_provenance
│   ├── disk.py        → extract_prefetch, get_amcache, extract_mft_timeline,
│   │                     list_deleted_files, summarize_evtx, extract_registry_run_keys
│   ├── memory.py      → detect_profile, list_processes, scan_processes,
│   │                     scan_network, detect_injection, list_dlls
│   ├── timeline.py    → build_timeline, query_timeline
│   ├── yara.py        → scan_files, scan_memory
│   ├── correlation.py → compare_disk_and_memory, flag_discrepancy
│   └── state.py       → read_state, export_trace
│   (graph tools in graph.py)
```

### Data Flow

```
Claude Code
    │
    │ JSON-RPC 2.0 call: {"tool": "disk.extract_prefetch", "params": {"image_path": "..."}}
    ▼
FastMCP dispatcher
    │
    │ dispatches to tools/disk.py::extract_prefetch()
    ▼
Tool layer (business logic)
    │
    │ validates parameters (Pydantic input model)
    │ constructs subprocess args list
    ▼
SafeRunner.run(args=[...], tool_name=..., ...)
    │
    │ validate_command(): check deny list
    │ validate_path(): resolve + check deny paths
    │ generate execution_id
    │ log pre-execution to audit.jsonl
    ▼
subprocess.run(args, shell=False, capture_output=True)
    │
    │ raw stdout/stderr
    ▼
Parser layer (tools/parsers/)
    │
    │ e.g., ez_parsers.py::parse_pecmd_output() → list[PrefetchRecord]
    ▼
Pydantic response model
    │
    │ validate schema (raises ValidationError if malformed)
    ▼
AuditLogger.log_execution(execution)   ← writes to audit.jsonl
    │
    ▼
JSON-RPC 2.0 response → Claude Code
```

---

## Layer 3: SafeRunner and Audit Logger

### SafeRunner

The `SafeRunner` class is the enforcement layer for zero-spoliation and injection prevention.

```
SafeRunner
    │
    ├── DENY_COMMANDS: ["rm", "dd", "wget", "curl", "ssh", "scp",
    │                   "mkfs", "fdisk", "shred", "chmod"]
    │
    ├── DENY_PATHS:    ["/mnt/", "/cases/*/evidence/", "/dev/", "/proc/", "/sys/"]
    │
    └── WRITE_PATHS:   ["./analysis/", "./exports/", "./reports/"]
```

Enforcement sequence:

```
1. validate_command(args[0])
   → Path(args[0]).name must not be in DENY_COMMANDS
   → PermissionError if denied

2. validate_path(arg) for each arg containing os.path.sep
   → Path(arg).resolve() → absolute path
   → must not match any DENY_PATHS pattern
   → PermissionError if denied

3. subprocess.run(args, shell=False, capture_output=True, timeout=300)
   → shell=False: no shell string interpolation
   → timeout: prevents runaway Plaso jobs

4. AuditLogger.log_execution(execution)
   → synchronous write + flush (fail-closed)
```

### AuditLogger

The `AuditLogger` writes one JSONL line per tool execution to `./analysis/audit.jsonl`. Properties:

- **Synchronous + immediate flush** — every entry is flushed to disk before the tool call returns.
- **Fail-closed** — if the write fails (disk full, permissions), the tool call fails.
- **Monotonic IDs** — execution IDs (E-001, E-002, ...) and finding IDs (F-001, F-002, ...) are never reused within a case.
- **Immutable** — once written, entries are never modified; corrections append new entries.

---

## Layer 4: Pydantic Data Models

All tool inputs and outputs are typed via Pydantic v2 models. This eliminates the sub-20% precision problem identified by Lang & Schreck (ACM 2025) when LLMs interpret raw Volatility text output.

### Core Model Hierarchy

```
CaseManifest          ← defines the investigation
    │
    └── CaseState     ← authoritative investigation state
            │
            ├── list[Finding]       ← forensic findings
            │       ├── EvidenceKind (OBSERVATION|INFERENCE|HYPOTHESIS|REJECTED)
            │       ├── execution_id → links to Execution
            │       ├── artifact_path + artifact_offset
            │       ├── mitre_tactic + mitre_technique
            │       └── contradicted_by, corroborated_by
            │
            └── list[Execution]     ← tool call records
                    │
                    └── CorrectionEvent (optional)
                            ├── prior_claim
                            ├── contradiction_source
                            ├── revised_claim
                            └── confidence_delta
```

### Artifact Record Types

```
Evidence artifact types:
    ProcessRecord        ← pslist / psscan output
    PrefetchRecord       ← PECmd output
    AmcacheRecord        ← AmcacheParser output
    RegistryRunKey       ← RECmd output
    EventRecord          ← EvtxECmd output
    TimelineEvent        ← psort output
    NetworkArtifact      ← netscan output
    InjectionIndicator   ← malfind output
    DllRecord            ← dlllist output
    DeletedFile          ← fls -rd output
    MftEntry             ← MFTECmd output

Correlation types:
    DiscrepancyAlert     ← output of individual correlation checks
    CorrelationReport    ← output of compare_disk_and_memory()

Provenance types:
    IntegrityResult      ← ewfverify output
    ProvenanceRecord     ← audit.jsonl lookup for a finding_id
```

---

## Layer 5: Correlation Engine

The correlation engine is the core novel contribution. It reads the authoritative `CaseState` and executes 6 checks:

```
compare_disk_and_memory(case_id)
    │
    ├── Check 1: process_no_disk_binary
    │   memory: ProcessRecord.image_path
    │   disk:   MftEntry.full_path, DeletedFile.full_path
    │   → DiscrepancyAlert (severity: critical)
    │
    ├── Check 2: prefetch_deleted_binary
    │   disk:   PrefetchRecord.executable_name, AmcacheRecord.file_path
    │           vs DeletedFile.file_name
    │   → DiscrepancyAlert (severity: high)
    │
    ├── Check 3: vad_anomaly_legitimate_path
    │   memory: InjectionIndicator.pid, InjectionIndicator.has_pe_header
    │   disk:   MftEntry for process image path (exists, expected location)
    │   → DiscrepancyAlert (severity: critical)
    │
    ├── Check 4: network_no_disk_artifact
    │   memory: NetworkArtifact.pid → process name
    │   disk:   MftEntry, PrefetchRecord for process binary
    │   → DiscrepancyAlert (severity: high)
    │
    ├── Check 5: registry_missing_binary
    │   disk:   RegistryRunKey.value_data (target binary path)
    │           vs MftEntry, DeletedFile for that path
    │   → DiscrepancyAlert (severity: high)
    │
    └── Check 6: timestamp_mismatch
        disk:   MftEntry.si_created vs MftEntry.fn_created
                MftEntry.si_modified vs MftEntry.fn_modified
        → DiscrepancyAlert (severity: medium)
    │
    └── returns CorrelationReport(
            total_checks_run=N,
            discrepancies=[...],
            confirmed_consistencies=K,
            summary="..."
        )
```

---

## Layer 6: Output Layer

All outputs are written to `./analysis/` relative to the case directory:

| File | Format | Written by | Purpose |
|---|---|---|---|
| `audit.jsonl` | JSONL | AuditLogger (automatic) | Immutable execution record, one line per tool call |
| `findings.json` | JSON | `state.py` (on Stop hook) | Authoritative finding state |
| `narrative.md` | Markdown | Agent (via file write) | Investigative narrative with MITRE ATT&CK mapping |
| `report.pdf` | PDF | `generate_pdf_report.py` (Protocol SIFT) | Formatted report for evidence package |
| `graph_data.json` | JSON | `scripts/build_graph.py` | Node/edge data for D3.js graph visualization |

---

## Claude Code Configuration

### Permission Model

```
settings.json
    │
    ├── allow: [
    │       "mcp__savvydfir-mcp__*",     ← all MCP tools
    │       "python3 /opt/volatility3-2.20.0/vol.py *",
    │       "log2timeline.py *",
    │       "psort.py *",
    │       "fls *", "icat *", "mmls *", "fsstat *",
    │       "ewfmount *", "ewfverify *",
    │       "dotnet /opt/zimmermantools/*.dll *",
    │       "yara *",
    │       "sha256sum *", "md5sum *",
    │       "file *", "strings *", "grep *", "find *",
    │       "cat *", "head *", "tail *", "wc *",
    │       "python3 scripts/*.py *"
    │   ]
    │
    ├── deny: [
    │       "rm -rf *", "rm -r *", "dd *",
    │       "wget *", "curl *", "ssh *", "scp *",
    │       "mkfs *", "fdisk *", "shred *",
    │       "chmod 777 *", "WebFetch *"
    │   ]
    │
    ├── write_paths: ["./analysis/", "./exports/", "./reports/"]
    └── deny_paths:  ["/mnt/", "/cases/*/evidence/"]
```

### Hooks

```
PostToolUse hook (matcher: mcp__savvydfir-mcp__*)
    → Checks exit code of every MCP tool call
    → Classifies errors for retry logic

Stop hook
    → Exports final case state: python3 -c "from sift_mcp.state import export_final_state; export_final_state()"
    → Re-verifies evidence integrity
    → Closes audit.jsonl
```

---

## Evidence Integrity Model

```
Investigation start
    │
    └── verify_integrity(image_path)
            → ewfverify on disk image
            → sha256sum on memory dump
            → records computed_hash in audit.jsonl
            → stored as CaseState.integrity_hash_start

Investigation end (Stop hook)
    │
    └── verify_integrity(image_path) again
            → records computed_hash in audit.jsonl
            → stored as CaseState.integrity_hash_end
            → if hash_start != hash_end → CRITICAL alert
```

This provides a cryptographic guarantee that evidence was not modified during the investigation. Because all writes are blocked to `/mnt/` and evidence directories, the hashes should always match. A mismatch would indicate a filesystem-level violation outside the MCP server's control.

---

## Investigation Graph (Stretch Goal)

The investigation graph is a lightweight D3.js force-directed visualization that auto-populates from `audit.jsonl` and `findings.json`. It requires zero build dependencies and runs via `python3 -m http.server`.

```
Node types:
    Case         (large gray circle)
    EvidenceSource  (blue square)
    Finding/OBSERVATION   (green circle)
    Finding/INFERENCE     (yellow circle)
    Finding/HYPOTHESIS    (orange circle)
    Finding/REJECTED      (red circle)
    Execution    (gray diamond)
    Correction   (red triangle)

Edge types:
    contains         (solid gray)    Case → EvidenceSource
    produced_by      (solid blue)    Finding → Execution
    contradicts      (dashed red)    Finding → Finding
    corroborates     (solid green)   Finding → Finding
    corrected_to     (thick dashed red)  Prior finding → Revised finding
    triggered        (dotted orange) DiscrepancyAlert → Follow-up execution
```

Interactions: hover for tooltip, click for full provenance sidebar, filter by evidence_kind, zoom/pan, text search.
