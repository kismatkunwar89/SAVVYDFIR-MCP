# SAVVYDFIR-MCP — DFIR Investigation Framework

## What This Is
AI-driven Digital Forensics & Incident Response on SANS SIFT Workstation.
You are the investigator. All evidence is READ-ONLY. Chain of custody applies.

## Critical Rules
1. **NEVER write to `/evidence/` or `/mnt/`** — read-only evidence and mount paths
2. **Write output ONLY to `analysis/`, `reports/`, `/cases/`, or `/tmp/`** — RBAC-enforced in server.py
3. **Every finding must cite**: artifact path + exact command + timestamp
4. **Load skills on-demand** — do not preload all skills at once
5. **Case-agnostic**: no hardcoded IPs, usernames, or filenames — universal patterns only

## Forensic Knowledge in Tool Responses
Every tool response now carries forensic_caveat, corroborate_with, and discipline_reminder
injected from Valhuntir forensic-knowledge YAMLs at the point of interpretation.
**Read these fields** — they tell you what this artifact does NOT prove and what to run next.
CLAUDE.md is for investigation structure. Tool responses carry the artifact-specific rules.

## Investigation Workflow (7 Phases)

### PHASE 1: Volatile Data — Memory First (5–10 min)
Run ALL in one batch (parallel-safe):
```
list_processes(case_id)
scan_processes(case_id)
detect_injection(case_id)          ← MANDATORY
scan_network(case_id)              ← captures every active socket
list_dlls(case_id, pid)            ← MANDATORY for each PID from scan_network
load_memory(memory_image_path)
```

### PHASE 2: Triage Baseline — Disk Artifacts (15–30 min)
**Run dotnet tools SEQUENTIALLY** — never parallel (saturates 4 vCPU):
```
mount_image()
extract_mft_timeline(case_id)
extract_usn_journal(case_id)       ← do NOT delay — USN rolls over
summarize_evtx(case_id)            ← 2-stage: channel inventory + extraction
extract_prefetch(case_id)
get_amcache(case_id)
extract_shimcache(mount_point, case_id)
extract_registry_run_keys(case_id)
extract_srum(mount_point, case_id)
extract_windows_artifacts(case_id) ← fallback if direct mount failed
```

### PHASE 3: Detection Engines (10–15 min)
```
sigma_hunt(evtx_path, case_id)     ← MANDATORY, 2,278 Chainsaw rules
analyze_vss(disk_image_path, case_id)  ← only if sigma finds EID 1102
```

### PHASE 4: AI Hypothesis Formation — Main-Agent Inline (5–10 min)

**W1.7 architecture (main-agent inline primary, opt-in specialist spawn):**
the missing brain step between detection anchors and the pivot loop. Main-agent
inline analysis is the **primary path**; specialist Task spawn remains opt-in
for cross-artifact isolation (synthesis/corroboration). Task subagents hit the
hardcoded 32K output-token ceiling (anthropics/claude-code#25569) — don't use
them for artifact-level analysis.

**Heuristic delivery is now deterministic via MCP injection (W1.7):**
- Every extraction tool returns `applicable_heuristics` in its payload —
  the relevant slice of `.claude/agents/<artifact>-analyst.md` (your
  forensic-heuristic knowledge base) travels WITH the data. Each slice
  carries a `ctx_id` (CTX-NNN) for court-defensible provenance.
- The hypothesis-formation MCP tools bundle additional heuristic context.
- On-demand depth available via `get_heuristic(artifact, topic)`.

For each artifact whose extraction returned `csv_path`:
1. **Read the `applicable_heuristics` block** in the extraction response.
   The relevant DFIR patterns are inline. Note the `ctx_id`.
2. **Run targeted queries** via `run_analysis(data_path=csv_path, query=...)`.
   Each call gets an `execution_id` and audit row (W1.5).
3. **Persist evidence-backed conclusions** via `submit_finding(...)` with
   Section 3-lite schema (W1.3). Cite the heuristic CTX(s) used via
   `heuristic_context_refs=["CTX-003"]` for court-grade provenance.
4. **Close the lane** via `record_analysis_lane(assigned_agent='main-agent',
   lane_id=..., status='COMPLETE' or 'COMPLETE_WITH_GAPS', execution_ids=[...],
   finding_ids=[...], summary=...)`.

**For multi-artifact hypothesis formation (the LLM brain step):**
```
prepare_hypothesis_context(case_id)   ← returns taxonomy + volatile_summary +
                                         detection_anchors (top-N) + execution
                                         anomalies + open_corrections +
                                         data_gaps + applicable_heuristics
                                         (CTX-cited slices, dedup-aware)
```
Use the bundle to form 2-5 ranked hypotheses with:
- `attack_class` (concise label)
- `initial_pivot` (first artifact/indicator to drill)
- `expected_evidence_chain` (Activity Thread phases that should appear if true)
- `source_context_refs` (CTX-NNN ids of heuristics consulted)

Then persist via:
```
record_hypotheses(case_id, hypotheses=[...])
```

**For pivot-loop depth (Tier-3 on-demand):**
```
get_heuristic(artifact="mft", topic="professional_patterns")
```
Topics: `forensic_ground_rules`, `what_to_hunt`, `critical_heuristics`,
`professional_patterns`, `query_pattern`, `systematic_coverage`.

Artifact-to-heuristic source mapping:
- `extract_mft_timeline` / `extract_usn_journal` → `.claude/agents/mft-analyst.md`
- `summarize_evtx` → `.claude/agents/evtx-analyst.md`
- `extract_prefetch` → `.claude/agents/prefetch-analyst.md`
- `get_amcache` → `.claude/agents/amcache-analyst.md`
- `extract_shimcache` / `extract_registry_run_keys` → `.claude/agents/registry-analyst.md`
- `extract_srum` → `.claude/agents/srum-analyst.md`
- `sigma_hunt` → `.claude/agents/sigma-analyst.md`
- Memory tools (`list_processes`, `scan_processes`, etc.) → `.claude/agents/memory-analyst.md`

**Opt-in escape hatch — Task subagent spawn:** if you need genuine context
isolation (synthesis or corroboration that benefits from a clean room), you
MAY spawn `@synthesis-analyst`, `@corroboration-analyst`, or
`@timeline-analyst` via Task. Do NOT spawn artifact specialists
(`@mft-analyst` etc.) — they're retired from default orchestration.

### PHASE 5: Cross-Artifact Correlation (5 min)
```
compare_disk_and_memory(case_id)               ← MANDATORY, 10 checks
find_temporal_clusters(case_id, window_seconds=300, min_sources=2, min_events=3)
```

Discrepancies detected here trigger **`CorrectionEvent`** writes to
`audit.jsonl` (W1.5) — the structural self-correction proof for hackathon
criterion #1 (Autonomous Execution Quality, the tiebreaker).

### PHASE 6: Cross-Artifact Synthesis (5 min)

**MANDATORY — main-agent inline. Delegate synthesis is opt-in.** Run 2
demonstrated the failure mode of waiting for `@synthesis-analyst`: the
specialist Task subagent never recorded its lane, `synthesis_corroboration`
was missing from state, `generate_report` blocked on `needs_delegate`, the
operator forced `allow_partial=True`, and the report shipped with 0 CONFIRMED
(no 3+ source stacking happened). Per W1.7 (Run 2 consensus 2026-05-24,
peer reviewer+peer reviewer signed): **do not rely on delegate synthesis as the only path.**

**Main-agent inline synthesis SOP (run BEFORE generate_report once all 4
prereq lanes are COMPLETE / COMPLETE_WITH_GAPS):**

1. `compare_disk_and_memory(case_id)` — MANDATORY (10 anti-forensics checks)
2. `find_temporal_clusters(case_id, window_seconds=300, min_sources=2, min_events=3)`
3. For each cluster with 3+ independent sources, promote via `submit_finding(...)`:
   - `evidence_kind="inference"` (synthesis = derived from multiple observations;
     `"corroborated"` is NOT a valid enum value — only OBSERVATION / INFERENCE /
     HYPOTHESIS / REJECTED exist)
   - `corroborated_by=["F-007", "F-014", "F-017"]` (≥2, preferably ≥3 source finding IDs)
   - `status="CONFIRMED"` + the A2 alternative-hypothesis bundle:
     `alternative_hypothesis` (strongest competing benign explanation) +
     `evidence_against_it` (≥1 specific observation that rules it out) +
     `disposition="ruled_out"` OR `disposition="not_applicable"` +
     `alternative_hypothesis_not_applicable_reason`
   - `disposition="not_resolved"` or `"partially_plausible"` will keep finding ACTIVE, not CONFIRMED
   - `source_execution_id` MUST resolve to a real audit row (typically the
     `compare_disk_and_memory` or `find_temporal_clusters` execution_id)
   - Response includes `confirmed_eligibility: {eligible, missing, gate_blocks}`
     so you can self-correct without waiting for the report gate. Re-submit if
     `eligible: false` and you wanted CONFIRMED.

   **Schema template (Phase 6 synthesis-to-CONFIRMED) — replace `<placeholders>`
   with case-specific values from your actual evidence. Do NOT copy literal values:**
   ```python
   submit_finding(
       case_id=<the active case_id from the manifest>,
       lane_id="synthesis_corroboration",
       assigned_agent="main-agent",
       finding_type=<persistence | execution | lateral_movement | credential_access |
                    exfiltration | defense_evasion | other>,
       artifact_type="correlation",
       evidence_kind="inference",   # synthesis = derived from multiple observations
       description=<one sentence: what the multi-source stack proves>,
       confidence=<0.85-1.00 for CONFIRMED>,
       status="CONFIRMED",
       source_execution_id=<execution_id of the compare_disk_and_memory or
                            find_temporal_clusters run that produced the evidence>,
       corroborated_by=<list of ≥2 (preferably ≥3) source F-NNN finding IDs>,
       alternative_hypothesis=<strongest competing benign explanation, one sentence>,
       evidence_against_it=<list of ≥1 specific observation that rules out the benign alternative>,
       disposition="ruled_out",       # or "not_applicable" + reason
       supporting_indicators=<list of IOCs this finding cites>,
       mitre_technique=<T-NNNN technique id derived from your evidence>,
   )
   ```

4. `record_analysis_lane(lane_id="synthesis_corroboration", assigned_agent="main-agent", status="COMPLETE", execution_ids=[...], finding_ids=[<promoted CONFIRMED ids>], summary=<one-sentence narrative>)`

5. **Close the hypothesis loop (PEAK/TaHiTI).** Before `generate_report`, resolve
   EVERY hypothesis you recorded in Phase 4. Re-call
   `record_hypotheses(case_id, hypotheses=[...])` passing back the **FULL**
   hypothesis object (preserve `attack_class`, `initial_pivot`,
   `expected_evidence_chain`, `rank`, `source_context_refs` — `record_hypotheses`
   REPLACES by `hypothesis_id`, so a partial object loses data), changing only:
   - `status` → `CONFIRMED` (proven — malicious activity confirmed),
     `REFUTED` (disproven — ruled out), or `SUSPENDED` (inconclusive —
     tested but insufficient evidence). Do NOT leave a tested hypothesis `ACTIVE`.
   - `related_finding_ids` → the F-NNN findings that proved, refuted, or
     materially informed the verdict (may be empty for SUSPENDED).
   The report's "Recorded Hunting Hypotheses" section renders each verdict +
   linked findings, so the report reads as a closed hunt: hypothesis → tested →
   verdict + evidence.

**Opt-in escape hatch (only when context isolation outweighs Task ceiling risk):**
Spawn `@synthesis-analyst` or `@corroboration-analyst` via Task. The Task path
has a hardcoded 32K output-token ceiling that truncated 7/8 specialists in
prior runs. Do not gate the report on it.

**The synthesis step waits for all 4 prereq lanes status=COMPLETE / COMPLETE_WITH_GAPS:**
`memory`, `disk_execution_persistence`, `event_auth`, `timeline_correlation`.
The post-Phase-5 hook nudges this transition.

### PHASE 7: Reporting (2 min)
```
generate_report(case_id)
generate_graph(case_id)
merge_host_graphs()        ← only after all hosts complete
build_reports_index()
```

**Total wall-clock per host**: ~60–90 min on 4 vCPU / 7.6 GB.

## EVTX Tier System

`summarize_evtx` now runs a 2-stage channel inventory before extraction:
- **Stage 1**: Enumerate all .evtx files, classify as present (>4 KB) or empty (≤4 KB)
- **Stage 2**: Extract baseline channels + any high-value channels that are present

**Always-extract baseline**: Security, System, Application, Windows Defender Operational

**High-value attack-surface (extracted IF present)**:
Sysmon, PowerShell, RDPClient, LocalSessionManager, TaskScheduler, WinRM,
WMI-Activity, SMBServer, SMBClient, Firewall

The inventory is persisted to `state.json:artifact_coverage.evtx_inventory`.
`coverage_debt` lists high-value channels that were present but empty — these represent
evidence of absence (logging disabled or no activity), not a tool failure.

## Investigation Entry Point (quick reference)
1. Read manifest: `start_investigation(manifest_path)`
2. Follow 7-phase workflow above
3. Generate report: `generate_report(case_id)` — mandatory coverage gate enforced

## Additional Detection Tools (invoke as needed)
- `sigma_hunt(evtx_path, case_id)` — run 2,278 Sigma community rules via Chainsaw on EVTX files. Produces ATT&CK-mapped findings from deterministic rule-based detection. Use after `summarize_evtx` to validate LLM interpretations against community consensus. If EID 1102 (log cleared) is found → immediately call `analyze_vss`.
- `analyze_vss(disk_image_path, case_id)` — enumerate Volume Shadow Copies via libvshadow. Shadow copies pre-dating the incident may contain intact Security.evtx after attacker log clearing. Reports artifact presence (Security.evtx, System.evtx, registry hives) per shadow store with creation timestamps. Cross-reference store dates against the incident timeline to identify pre-attack snapshots for log recovery.
- `extract_pca(mount_point, case_id)` — parse Windows 11 22H2+ Program Compatibility Assistant execution artifacts (PcaAppLaunchDic.txt). Plain-text, pipe-delimited: {path}|{last_execution_UTC}. Corroborates Prefetch + Amcache. Not present on Windows 10 / Server.
- `extract_shimcache(mount_point, case_id)` — parse ShimCache (AppCompatCache) from SYSTEM hive via AppCompatCacheParser + rla.exe (transaction log replay). Records every executable path Windows observed. Does NOT record run count — cross-reference with Amcache/Prefetch to confirm execution. Absence of an expected entry → binary was timestomped or deleted post-compromise. Entries outside System32/Program Files/WinSxS are flagged as suspicious for analyst review.
- `extract_srum(mount_point, case_id)` — parse SRUM (System Resource Utilization Monitor) via esedbexport. Network table: bytes_sent / bytes_recv per process per 60-day window. App resource table: CPU/disk I/O per 30-day window. SRUM records deleted applications — critical for anti-forensics detection. Use to quantify exfiltration volume per process and identify processes no longer on disk (AppIds with no matching binary — key anti-forensics indicator). Cross-reference with EVTX network events and memory scan_network findings.
- `read_state(case_id)` is summary-only. Use it to resume, inspect counts, and get the latest finding window.
- `get_findings(case_id, ...)` is the full finding retrieval surface. Use filters plus `limit`/`offset` when you need the full corpus.
- `get_finding(case_id, finding_id)` drills into a single `F-NNN` finding.
- `extract_mft_timeline`, `summarize_evtx`, and `extract_registry_run_keys` are summary-first by default. Request `response_format="detailed"` only for raw-record drill-down.

### rla.exe (Registry Transaction Log Replay)
SYSTEM / NTUSER.DAT / Amcache.hve parsed from offline images may have uncommitted
transaction logs (.LOG1/.LOG2). `extract_shimcache` and `extract_srum` automatically
run `rla.exe` before parsing to replay those logs and produce clean, accurate output.
Always ensure hives are clean before cross-referencing registry evidence.

**Per-user NTUSER staging:** when the raw-fallback extraction (`extract_windows_artifacts`)
stages per-user registry hives, the user slug is applied to ALL variants — the hive
itself stages as `{user}_NTUSER.DAT` and its transaction logs as
`{user}_NTUSER.DAT.LOG1` / `{user}_NTUSER.DAT.LOG2`. Downstream tools must discover
logs RELATIVE to the staged hive (`hive_path.parent / (hive_path.name + ".LOG1")`),
never hardcode `NTUSER.DAT.LOG1`. Hardcoding the generic name silently breaks
replay for the per-user prefixed staging path.

## Server Setup Requirements

### User Permissions
The MCP server and investigation tools run as the invoking user (the user who
starts the MCP server). This user must have:

1. **Read access** to evidence directories (`/evidence/`, `/mnt/`)
2. **Write access** to analysis directories (`analysis/`, `reports/`, `/cases/`)
3. **Write access** to `/tmp` for queue files and Plaso logs

### FUSE Mount Permissions
Evidence mounts via ewfmount/xmount are user-specific. The user who mounts
the evidence must be the same user running the MCP server:

```bash
# As investigation user (not root):
whoami  # Verify current user
ewfmount /evidence/disk/image.E01 /mnt/evidence
```

Root cannot access FUSE mounts created by other users due to FUSE security model.

### Troubleshooting Permission Issues
If investigation fails with permission errors:
1. Verify MCP server process owner: `ps aux | grep sift_mcp/server.py`
2. Verify evidence mount owner: `mount | grep evidence`
3. Ensure both are the same user
4. If different, remount evidence as the MCP server user

## RBAC Path Model
- **Read-only**: `/evidence/`, `/mnt/` — evidence and mount points
- **Read-write**: repo `analysis/`, `reports/`, `/cases/`, and `/tmp/` — analysis output
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
- Case state: `analysis/state.json` and `analysis/audit.jsonl` by default
- Reports: `reports/{case_id}/`
- Large ad hoc exports: `/cases/` when a tool explicitly writes there
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

## Analyst Methodology (peer reviewer consensus 2026-05-19)

### Tabular artifact discipline — bounds before filters

For any CSV / dataframe artifact (MFT, USN, EVTX, Prefetch, Amcache, ShimCache, SRUM, browser history, registry exports), the **FIRST query** must establish:

1. **row count**
2. **schema** — column names and dtypes
3. **timestamp column min/max bounds**

Filtering for case events BEFORE establishing bounds risks **misinterpretation of absence**:

- A clean filter result may mean *"no evidence of the attacker action"* OR *"the data was capped/cleared before our attack window."* These are very different conclusions.
- Common failure mode: Amcache CSV capped some days before the incident window. A clean filter on the case-relevant date range returns zero rows — but that does NOT mean "no attacker activity"; it may mean "no Amcache data covers the window." A single `df['FileKeyLastWriteTimestamp'].max()` would surface the cap immediately.

Always know the bounds before drawing conclusions about gaps.

### Suspicious-network-process disposition checklist

When `scan_network` reveals a process with an active connection to a suspicious peer — especially generic Windows binaries like `svchost.exe`, `rundll32.exe`, `dllhost.exe`, or browser-named processes — calling `list_dlls(pid)` alone is **not a disposition**. The analyst MUST close the loop with all of:

1. **Process identity + binary path** — legitimate System32 path or off-path (`C:\Users\Public\...`, `\AppData\Local\Temp\...`)?
2. **Parent process + command line** — for `svchost.exe`, the service group (`-k DcomLaunch`, `-k netsvcs`, `-k LocalServiceNetworkRestricted`). Mismatched parent/group is a strong injection indicator.
3. **Module/DLL abnormalities** — explicit list of any non-Microsoft, unsigned, or user-writable-path DLLs loaded into the process, OR an explicit "none found after enumeration of N modules" statement.
4. **Peer interpretation** — is the destination IP known-internal infrastructure (DC, proxy, file server), case-relevant host (attacker, victim, lateral target), or unknown? Cross-reference against the case manifest.
5. **Corroborating artifacts checked** — explicit list: EVTX EID 4688 process creation, Sysmon EID 1/3, Firewall, DNS query logs. "Found nothing" is rigorous only if the artifacts were searched.
6. **Final confidence rationale** — what specifically supports the chosen confidence level based on what was actually examined.

**"No corroboration found" is rigorous only when it follows documented enumeration.** A finding demoted to PROBABLE because "DLL analysis was incomplete" is not rigorous — finish the analysis or mark the finding with `requires_re_extraction=True` so the report layer can partition it correctly.

### CONFIRMED-status invariants (enforced by code)

Two invariants are now **enforced by the framework** — the agent cannot bypass them via the finding API; only `generate_report(allow_partial=True)` at the report layer can partition affected findings into a clearly-labeled non-defensible section:

1. **Provenance invariant** — A CONFIRMED finding's `execution_id` MUST resolve to a real audit record in the current evidence ledger. Inherited claims from prior compacted sessions, placeholder `E-000` IDs, and `state_autogenerated` IDs all fail this gate. The finding is auto-demoted to ACTIVE with `requires_re_extraction=True`.

2. **Alternative-hypothesis invariant** — A CONFIRMED finding MUST carry structured disposition fields:
   - `alternative_hypothesis` (the strongest competing benign explanation)
   - `evidence_against_it` (≥1 entry, what was actually observed that rules the alternative out)
   - `disposition` set to `"ruled_out"` (with the above) OR `"not_applicable"` (with `alternative_hypothesis_not_applicable_reason`)

   `disposition="not_resolved"` or `"partially_plausible"` MUST downgrade — peer reviewer sign-off requires unresolved alternatives to cause partitioning, not CONFIRMED labeling.

The `@corroboration-analyst` agent is the natural place to populate both invariants. See `.claude/agents/corroboration-analyst.md` Step 6 for the structured-field template.

## When `summarize_evtx` Fails

If `summarize_evtx(mount_point)` fails with "cannot resolve Windows partition", the tool cannot auto-locate EVTX files from the mount root. This happens when:
- Multi-partition images without clear Windows volume markers
- Non-standard partition layouts
- Mount points that are not partition roots

**Solution**: Always extract EVTX first using `extract_windows_artifacts()`:
```python
extract_windows_artifacts(mount_point="/mnt/disk", case_id="CASE-ID")
```

This writes EVTX files to `/cases/{case_id}/artifacts/raw/evtx/`. Then call:
```python
summarize_evtx(evtx_dir="/cases/CASE-ID/artifacts/raw/evtx", case_id="CASE-ID")
```

The tool's path resolution prefers durable artifact directories first, so subsequent calls will automatically use the extracted files.

## Mandatory Tools

These tools must run in every investigation before `generate_report()`. The coverage gate blocks report generation if these are missing:

| Tool | Why Mandatory | What It Detects | Enforced |
|------|---------------|-----------------|----------|
| `sigma_hunt(evtx_path, case_id)` | 2,278 community Sigma rules provide deterministic ATT&CK-mapped detection. Validates LLM interpretations against consensus. Rule-based detection catches patterns LLMs miss. | Lateral movement (PsExec, WinRM), credential theft (Mimikatz, LSASS dumps), persistence (scheduled tasks, services), defense evasion (log clearing, AV tampering). | ✅ YES |
| `hayabusa_hunt(evtx_path, case_id)` | 3,700+ Sigma rules (superset of Chainsaw). Emits MITRE ATT&CK matrix HTML. Critical for comprehensive threat hunting beyond Chainsaw's coverage. | Additional C2 patterns, rare LOLBin abuse, Windows Defender event correlation, timeline-aware threat scoring. | ❌ NO |
| `compare_disk_and_memory(case_id)` | 6 forensic contradiction checks. Detects anti-forensics: code injection, process hiding (DKOM), prefetch deletion, timestamp manipulation. Cross-artifact validation LLMs cannot perform. | Hidden processes (in memory but no disk artifact), injected code (memory-only malware), deleted Prefetch (anti-forensics), orphaned network connections (no matching process). | ✅ YES |
| `build_timeline(case_id)` | Plaso super-timeline reconstructs attacker activity across all artifact types simultaneously. Temporal proximity analysis reveals staged attacks that single-artifact analysis misses. **OPTIONAL** — specialists work from individual CSV extracts; comprehensive timeline enhances but is not required. | Multi-stage intrusions (reconnaissance → credential theft → lateral movement), dwell time quantification, exfiltration staging windows, cleanup activity timestamps. | ❌ NO (optional) |
| `detect_injection(case_id)` | Memory-only malware detection. Reflective PE injection and shellcode are invisible to disk forensics. Required for fileless attacks. | Cobalt Strike beacons, Metasploit payloads, process hollowing, thread injection, reflective DLL loading. | ✅ YES |
| `list_dlls(case_id, pid)` | Per-PID DLL enumeration for suspicious network processes. Unsigned DLLs, out-of-place paths, and missing-on-disk DLLs indicate compromise. | Malicious DLLs loaded into legitimate processes (svchost.exe, explorer.exe), DLL side-loading, missing DLLs (memory-only injection). | ✅ YES |

**Coverage Gate Enforcement**: The report gate (`evaluate_ir_coverage_gate()`) checks:
- `sigma_hunt` completed with exit_code=0 AND valid output (not just `sigma_scan`)
- `compare_disk_and_memory` completed
- `detect_injection` completed
- `list_dlls` completed for ALL PIDs flagged by `scan_network` (per-PID coverage)

**Note**: `build_timeline` is OPTIONAL (not enforced by gate). Specialists analyze individual CSV extracts (MFT, EVTX, Prefetch, Amcache, Registry) for fast response. Plaso super-timeline remains available for deep-dive analysis but does not block report generation.

If any mandatory tool is missing or failed, `generate_report()` blocks with a specific error listing the gaps.

---

## Professional Forensic Workflows

The framework implements professional analyst workflows from SANS DFIR, Prefetch Deep Dive, and Forensics-course1 training materials.

### Execution Validation Hierarchy

The correlation engine **automatically applies** professional execution confidence levels when promoting findings (implemented in `semantics.py`):

- **Observation (0.70)**: ShellBags, ShimCache, Amcache alone — proves file existed, NOT that it executed
- **Probable (0.85)**: Prefetch OR BAM/DAM — strong execution indicator but single source
- **Definitive (1.00)**: Prefetch + Event ID 4688 + MFT — all three forensic pillars confirm execution
- **Stacked (1.00)**: 3+ independent sources — defeats anti-forensics through layered evidence

**Framework Application**:
```python
# When promoting findings, execution hierarchy overrides flat FK multipliers
# Example: Prefetch (0.85) + EVTX 4688 (1.00) + MFT (present) → confidence=1.00 (definitive_execution_trinity)
# Recorded in confidence_support_inputs for audit trail
```

### Temporal Proximity Analysis

Time windows define attack phase correlation:

- **±10 seconds**: Causality window — Event A caused Event B
  - Example: EVTX 4688 process creation → network connection within 10s = C2 beacon
  
- **±5 minutes**: Attack phase window — reconnaissance, exploitation, cleanup
  - Example: MFT file drop → Prefetch execution → Registry persistence within 5 min = staged attack
  
- **Multi-source bursts**: FILE+REG+EVT at same second = confirmed attacker action
  - Example: 14:32:01 MFT create + 14:32:01 Prefetch + 14:32:01 Registry Run key = automation signature

**Framework Tool**: `find_temporal_clusters(case_id, window_seconds=300, min_sources=2, min_events=3)`
- Sliding window analysis across all timestamped findings
- Returns clusters with confidence 0.80-1.00 based on source diversity
- Tighter timing = higher confidence (10s window = 0.95, 300s window = 0.80)

### Anti-Forensics Detection

The correlation engine runs **10 automated checks** (6 original + 4 new professional patterns):

**Original Checks**:
1. **Process in memory with no disk binary** — fileless malware or post-execution deletion
2. **Prefetch/Amcache entry for deleted binary** — proves execution then cleanup
3. **VAD anomaly on legitimate-path process** — process injection into System32/Program Files binaries
4. **Network connection with no disk artifact** — injected shellcode or memory-resident malware
5. **Registry persistence for missing binary** — compromised then cleaned
6. **Timestomping detection** — $SI vs $FN mismatch (>1 hour difference)

**NEW Professional Checks** (from DFIR training):
7. **USN Journal validation** — authoritative timestamp source (cannot be forged)
   - MFT $SI timestamp differs from USN entry by >1 hour = timestomping confirmed
   - MFT shows file but no USN Journal entry = backdating or journal tampering
   
8. **ShimCache vs Amcache presence** — cache clearing detection
   - ShimCache entry but no Amcache = possible selective cache clearing
   - ShimCache buffers in memory, Amcache persists on disk
   
9. **Event log clearing** — Event ID 1102 + VSS recovery workflow
   - Security log cleared = attacker cleanup activity (CRITICAL severity)
   - If VSS available → recommend extracting Security.evtx from pre-clearing snapshot
   - If VSS unavailable → logs unrecoverable (document gap)
   
10. **SRUM exfiltration detection** — high-volume data transfer
    - >100MB bytes_sent per process = potential exfiltration
    - Correlate with memory network connections and EVTX
    - HIGH severity if network connection match, MEDIUM if no match

**Each discrepancy includes**:
- Severity: CRITICAL / HIGH / MEDIUM
- Recommended action: Next forensic step or validation check
- Cross-reference guidance: Which artifacts to correlate

### Stacked Evidence Principle

**1 source = POSSIBLE (0.70)** — insufficient for defensible conclusion
- Example: Only ShellBag shows folder navigation → observation, not proof of file access

**2 sources = PROBABLE (0.85)** — strong indicator, needs one more
- Example: Prefetch + MFT → probable execution, need EVTX 4688 or memory confirmation

**3+ sources = CONFIRMED (1.00)** — defensible in court
- Example: LNK + ShellBag + RecentDocs → confirmed file access
- Example: Prefetch + EVTX 4688 + MFT + Memory process → definitive execution

**Framework Application**:
- Corroboration-analyst applies stacking during final review
- Confidence automatically adjusted based on `corroborated_by` list length
- Findings promoted to CONFIRMED status when corroboration requirements met

### Reliability Hierarchy (What Each Artifact Proves)

**Definitive Execution**:
- Prefetch + EVTX 4688 + MFT = executable ran
- Memory process list + network connection + EVTX 5156 = C2 active

**Probable Execution**:
- Prefetch alone (run_count > 1) = high confidence execution
- BAM/DAM registry keys = scheduled or background execution

**Observation Only**:
- ShellBags = folder navigation, NOT file access
- ShimCache = file existed, NOT execution
- Amcache = compatibility check, NOT execution
- UserAssist = key written, NOT user action

**Cross-Validation Required**:
- Registry Run key = persistence attempt, need execution proof
- LNK file = user navigation, need ShellBag/RecentDocs for file access
- Zone.Identifier = internet download, need Prefetch for execution

### Defensible Forensic Language

**Write**:
- "Shell state indicates the directory was rendered through Explorer"
- "Prefetch and EVTX 4688 corroborate execution at 03:01:58 UTC"
- "3 independent sources confirm file access: LNK + ShellBag + RecentDocs"
- "USN Journal (authoritative) contradicts MFT $SI timestamp — timestomping confirmed"

**NOT**:
- "The user accessed the directory" (ShellBag alone doesn't prove user action)
- "The attacker ran the binary" (avoid attribution without 3+ sources)
- "Malware executed" (single source = not defensible in court)
- "File was modified" (specify $SI or $FN and acknowledge manipulation potential)

### Professional Correlation Patterns (Agnostic)

**Browser C2 Detection**:
- Memory network connections + SRUM bytes_sent + browser history = C2 vs legitimate
- Beaconing: fixed intervals, jitter, non-browser process on 80/443

**Phishing Chain**:
- Zone.Identifier ADS → LNK file → Prefetch FirstRun → EVTX 4688 → Network connection
- Patient zero: earliest email delivery + execution chain

**Ransomware Indicators**:
- USN Journal: DATA_OVERWRITE bursts (1000+/min)
- EVTX 4688: vssadmin.exe delete shadows /all
- SRUM: pre-encryption exfiltration spike (>10GB within 1 hour)

**Lateral Movement**:
- MFT: M timestamp < B timestamp = SMB file copy
- EVTX: 4624 Type 3 + 4672 + 5140 + 7045 = PsExec execution chain
- Within ±10 seconds = causality confirmed

**All patterns documented in**:
- `CORRELATION_METHODOLOGY.md` (980 lines) — professional workflows → framework implementation
- `FORENSIC_ARTIFACTS.md` (1060 lines) — artifact significance, limitations, corroboration needs

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

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
