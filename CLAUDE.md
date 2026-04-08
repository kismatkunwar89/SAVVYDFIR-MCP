# SAVVYDFIR-MCP — DFIR Investigation Framework

## What This Is
AI-driven Digital Forensics & Incident Response on SANS SIFT Workstation.
You are the investigator. All evidence is READ-ONLY. Chain of custody applies.

## Critical Rules
1. **NEVER write to `/evidence/` or `/mnt/`** — read-only evidence and mount paths
2. **Write output ONLY to `/cases/` or `/tmp/`** — RBAC-enforced in server.py
3. **Every finding must cite**: artifact path + exact command + timestamp
4. **Load skills on-demand** — do not preload all skills at once
5. **Case-agnostic**: no hardcoded IPs, usernames, or filenames — universal patterns only

## Available Skills
| Skill | When to load |
|-------|-------------|
| `/investigation-workflow` | Starting investigation or unsure what phase is next |
| `/artifact-routing` | Deciding which tool to use for a specific Windows artifact |
| `/tools-reference` | Need exact command syntax for SIFT tools |
| `/sigma-detection` | Running sigma_scan(), interpreting anomaly results, ATT&CK mapping |
| `/pivot-methodology` | Have a finding, need to determine what to investigate next |

## Investigation Entry Point
1. Read manifest: `start_investigation(manifest_path)`
2. Mount evidence: `mount_image()` and `load_memory()`
3. Collect artifacts: all disk + memory tools
4. Run anomaly detection: `sigma_scan(case_id)` — 5 universal detectors
5. Cross-correlate: `compare_disk_and_memory(case_id)` — 6 forensic checks
6. Deep dive: `run_analysis(data_path, query)` for ad-hoc Pandas queries
7. Record findings: `add_finding()` with evidence_kind, artifact_path, confidence
8. Generate report: `generate_report(case_id)`

## New Tools (v3)
- `sigma_scan(case_id)` — universal anomaly detection (process, network, MFT, EVTX, persistence)
- `run_analysis(data_path, query)` — safe Pandas interpreter for CSV/JSON forensic output
- `mount_image()` / `load_memory()` — now return ToolResult with RBAC validation

## RBAC Path Model
- **Read-only**: `/evidence/`, `/mnt/` — evidence and mount points
- **Read-write**: `/cases/`, `/tmp/` — analysis output
- **Blocked commands**: rm, dd, mkfs, shred, wget, curl, ssh, scp, fdisk, parted, nc

## Tool Paths (SIFT Workstation)
```
/usr/bin/fls  /usr/bin/mmls  /usr/bin/icat  /usr/bin/ewfmount
/usr/local/bin/vol3  /usr/bin/yara  /usr/bin/log2timeline.py
/usr/local/bin/MFTECmd  /usr/local/bin/EvtxECmd
/usr/local/bin/AppCompatCacheParser  /usr/local/bin/LECmd
/usr/bin/regripper  /usr/bin/7z
```

## Pydantic Models (v3)
- `ArtifactHit` — single anomaly from sigma_scan() with ATT&CK + pivot suggestion
- `ToolResult` — universal wrapper returned by mount_image/load_memory
- `SigmaScanResult` — sigma_scan() output with hits, counts, markdown summary
- `AnalysisResult` — run_analysis() output with table, insights, columns

## Output Locations
- Cases: `/cases/`
- Mounts: `/mnt/disk/` (disk) and `/mnt/memory/` (memory)
- Evidence: `/evidence/disk/` and `/evidence/memory/` (READ-ONLY)

## IMPORTANT: Your Role vs MCP's Role

**MCP Handles (The Hands):**
Tool execution, raw data extraction, RBAC, formatting token-efficient JSON/CSV responses,
and preserving the chain of custody. Do NOT ask the MCP server to analyze or reason about the data.

**You Handle (The Brain):**
Tool sequencing, programmatic data hunting (Pandas), multi-artifact correlation,
timeline reconstruction, and writing the forensic narrative.

**MANDATORY DATA RULES:**
1. NEVER try to read raw data outputs or massive logs directly in this chat.
2. ALWAYS treat large tool outputs as external databases.
3. When a tool response includes `csv_path` and `total_rows`, first run `run_analysis(data_path=csv_path, query="df.dtypes")` to learn the schema, then write targeted Pandas queries to hunt for anomalies — never read all rows into context.
4. Write Python/Pandas code, pass it to `run_analysis` to execute locally, and read ONLY the filtered anomalies back into your context.
5. After every finding, write one follow-up `run_analysis` query targeting that finding's artifact before moving to the next phase.

**MANDATORY TOOL SEQUENCING:**
- Run Volatility memory tools together (fast): `list_processes` + `scan_processes` + `scan_network`
- Run heavy dotnet disk tools ONE AT A TIME (slow): `summarize_evtx`, then `extract_mft_timeline`, then `extract_registry_run_keys`
- Never run two dotnet tools in parallel — this saturates the 4 vCPU server and kills the MCP connection.

## The Forensic Trinity
Every Windows investigation anchors on three pillars — never neglect any one:
- **Filesystem** ($MFT, $UsnJrnl, Prefetch, Amcache, ShimCache, Recycle Bin)
- **Memory** (processes, network connections, injected code, credentials, unflushed ShimCache)
- **Registry** (persistence ASEPs, user behavior, hardware history, credential stores)

## Forensic Investigator Mindset

**Navigation ≠ Access ≠ Execution** — respect artifact boundaries:
- ShellBag = shell rendered the folder, NOT that the user read files inside
- Amcache/ShimCache = file existed on disk, NOT that it executed
- UserAssist = key was written, NOT that a human clicked it (background tasks populate it)
- To prove execution: corroborate with Prefetch + EVTX EID 4688
- To prove file access: corroborate ShellBag with LNK files + Jump Lists + RecentDocs

**Negative space is evidence.** Absent artifact ≠ innocent. It means the attacker used a different mechanism:
- No ShellBags = used command line or script instead of Explorer
- No Prefetch = server OS, or Prefetch was wiped, or binary never ran
- No EVTX = logs were cleared, or audit policy was disabled
Always ask: *why is this expected artifact missing?*

**Timestamps are bounding information, not precise mouse-click records.**
Align timestamps with active logon sessions before drawing conclusions.
Registry key LastWriteTimestamp = when the KEY changed, not when a specific value changed.
Always standardise to UTC across all artifacts.

**Targeted corroboration** — ask the next logical question, not a general pile of data:
- Finding → What would I expect to see if this finding is real? → Look for that specific artifact.
- Stacking threshold: 1 source = UNCONFIRMED. 2+ independent sources = CONFIRMED.

**Defensible language** in findings:
- Write: "shell state indicates the directory was rendered through Explorer"
- Not: "the user accessed the directory"
- Write: "Prefetch and EVTX EID 4688 corroborate execution at 03:01:58 UTC"
- Not: "the attacker ran the binary"
