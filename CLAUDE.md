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

## Forensic Knowledge in Tool Responses
Every tool response now carries forensic_caveat, corroborate_with, and discipline_reminder
injected from Valhuntir forensic-knowledge YAMLs at the point of interpretation.
**Read these fields** — they tell you what this artifact does NOT prove and what to run next.
CLAUDE.md is for investigation structure. Tool responses carry the artifact-specific rules.

## Investigation Entry Point
1. Read manifest: `start_investigation(manifest_path)`
2. Mount evidence: `mount_image()` and `load_memory()`
3. Collect artifacts: all disk + memory tools
4. Run anomaly detection: `sigma_hunt(evtx_path, case_id)` — 2,278 Sigma rules via Chainsaw
5. Cross-correlate: `compare_disk_and_memory(case_id)` — 6 forensic checks
6. Deep dive: `run_analysis(data_path, query)` for ad-hoc Pandas queries
7. Record findings: `add_finding()` with evidence_kind, artifact_path, confidence
8. Generate report: `generate_report(case_id)`
9. Generate graph: `generate_graph(case_id)` — produces reports/{case_id}/graph.html + graph.json for visualization and Graph RAG embedding
10. After all hosts complete: `merge_host_graphs()` — unified cross-host graph (lateral movement edges from shared IOCs across hosts)
11. Refresh dashboard: `build_reports_index()` — regenerates reports/index.html with per-host investigation cards

## Additional Detection Tools (invoke as needed)
- `sigma_hunt(evtx_path, case_id)` — run 2,278 Sigma community rules via Chainsaw on EVTX files. Produces ATT&CK-mapped findings from deterministic rule-based detection. Use after `summarize_evtx` to validate LLM interpretations against community consensus. If EID 1102 (log cleared) is found → immediately call `analyze_vss`.
- `analyze_vss(disk_image_path, case_id)` — enumerate Volume Shadow Copies via libvshadow. Shadow copies pre-dating the incident may contain intact Security.evtx after attacker log clearing. Reports artifact presence (Security.evtx, System.evtx, registry hives) per shadow store with creation timestamps. Cross-reference store dates against the incident timeline to identify pre-attack snapshots for log recovery.
- `extract_pca(mount_point, case_id)` — parse Windows 11 22H2+ Program Compatibility Assistant execution artifacts (PcaAppLaunchDic.txt). Plain-text, pipe-delimited: {path}|{last_execution_UTC}. Corroborates Prefetch + Amcache. Not present on Windows 10 / Server.
- `extract_shimcache(mount_point, case_id)` — parse ShimCache (AppCompatCache) from SYSTEM hive via AppCompatCacheParser + rla.exe (transaction log replay). Records every executable path Windows observed. Does NOT record run count — cross-reference with Amcache/Prefetch to confirm execution. Absence of an expected entry → binary was timestomped or deleted post-compromise. Entries outside System32/Program Files/WinSxS are flagged as suspicious for analyst review.
- `extract_srum(mount_point, case_id)` — parse SRUM (System Resource Utilization Monitor) via esedbexport. Network table: bytes_sent / bytes_recv per process per 60-day window. App resource table: CPU/disk I/O per 30-day window. SRUM records deleted applications — critical for anti-forensics detection. Use to quantify exfiltration volume per process and identify processes no longer on disk (AppIds with no matching binary — key anti-forensics indicator). Cross-reference with EVTX network events and memory scan_network findings.

### rla.exe (Registry Transaction Log Replay)
SYSTEM / NTUSER.DAT / Amcache.hve parsed from offline images may have uncommitted
transaction logs (.LOG1/.LOG2). `extract_shimcache` and `extract_srum` automatically
run `rla.exe` before parsing to replay those logs and produce clean, accurate output.
Always ensure hives are clean before cross-referencing registry evidence.

## RBAC Path Model
- **Read-only**: `/evidence/`, `/mnt/` — evidence and mount points
- **Read-write**: `/cases/`, `/tmp/` — analysis output
- **Blocked commands**: rm, dd, mkfs, shred, wget, curl, ssh, scp, fdisk, parted, nc

## Tool Paths (SIFT Workstation)
```
EZ Tools:    dotnet /opt/zimmermantools/{Tool}.dll
Volatility:  python3 /opt/volatility3-*/vol.py
Chainsaw:    /usr/local/bin/chainsaw
fls/mmls:    /usr/bin/fls  /usr/bin/mmls  /usr/bin/icat
ewfmount:    /usr/bin/ewfmount
vshadow:     /usr/bin/vshadowinfo  /usr/bin/vshadowmount
esedbexport: /usr/bin/esedbexport
yara:        /usr/bin/yara
Plaso:       /usr/bin/log2timeline.py
```

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


---

## Multi-host Enterprise Investigation Pipeline

### MCP Tool Workflow (no external scripts)

**Per host** — run as separate Claude sessions, clear analysis/ between each:

```bash
rm -f analysis/state.json analysis/audit.jsonl
claude --allowedTools "mcp__savvydfir__*" -p "Read case-templates/manifest.json and investigate."
```

Claude calls: `start_investigation` → forensic tools → `generate_graph(case_id)`
Output: `reports/{case_id}/graph.html` + `reports/{case_id}/graph.json`

**After all hosts** — final session or same session:

```
merge_host_graphs()      # → reports/unified/graph.html (cross-host lateral movement)
build_reports_index()    # → reports/index.html (dashboard of all investigations)
```

### Directory Layout

```
investigations/{SCENARIO}-{HOST}/   ← per-host working state (gitignored)
    manifest.json
    state.json
    audit.jsonl
reports/
    index.html                       ← build_reports_index()
    {SCENARIO}-{HOST}/
        graph.html                   ← generate_graph(case_id)
        graph.json
    unified/
        graph.html                   ← merge_host_graphs()
        graph.json
```

### Cross-host Edge Types (merge_host_graphs)
- `lateral_movement`  — TA0008 finding shares IOC with finding on another host
- `shared_ioc`        — same IP / hash / domain in 2+ hosts' findings
- `shared_account`    — same domain\\user account seen on 2+ hosts

### Case ID Convention
`{SCENARIO}-{HOST}` — uppercased, spaces/slashes → hyphens.
Examples: `SRL-2018-WKSTN01`, `SRL-2018-DC`, `SRL-2018-MAIL`

### Per-host Isolation
`server.py` reads `SAVVYDFIR_ANALYSIS_DIR` at startup.
Set this env var before launching Claude to redirect all tool writes to that dir.
The MCP binary is unchanged between hosts — only the env var routes data.
