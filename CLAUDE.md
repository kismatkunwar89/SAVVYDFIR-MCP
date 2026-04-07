# SAVVYDFIR-MCP

SAVVYDFIR-MCP is an autonomous DFIR triage system that exposes forensic tools via MCP for Claude Code on SIFT Workstation. It provides cross-artifact correlation and evidence-triggered self-correction across disk and memory forensics.

## CRITICAL: READ-ONLY EVIDENCE RULE

**NEVER write to /evidence/, /mnt/evidence/, or modify disk images/memory dumps.** All analysis output goes to /cases/. Evidence is sacred — any write corrupts chain of custody and invalidates the investigation.

## Chain of Custody

Every finding MUST cite:
- `artifact_path` — full path to the source evidence file
- `command` — exact command or MCP tool call that produced it
- `execution_id` — the E-NNN audit trail identifier

## Skill Packages (load on-demand)

| Skill | Load When |
|---|---|
| `skills/memory-forensics/SKILL.md` | Analyzing memory dumps (Volatility 3) |
| `skills/disk-forensics/SKILL.md` | Mounting/analyzing disk images (Sleuth Kit, ewfmount) |
| `skills/ez-tools/SKILL.md` | Windows artifact analysis (MFT, registry, prefetch, evtx) |
| `skills/timeline/SKILL.md` | Building super timelines (Plaso/log2timeline) |
| `skills/yara/SKILL.md` | Signature scanning (YARA rules) |
| `skills/self-correction/SKILL.md` | On any DiscrepancyAlert or contradiction |
| `skills/correlation/SKILL.md` | Before Phase 4 cross-artifact correlation |
| `skills/savvydfir-triage/SKILL.md` | Full triage orchestration |

## Investigation Entry Point

1. Read manifest: `/opt/SAVVYDFIR-MCP/case-templates/manifest.json`
2. Call `start_investigation` tool with manifest data
3. Mount evidence before analysis:
   - Disk: `mount_image` tool (runs ewfmount + mount automatically)
   - Memory: `load_memory` tool (extracts ZIP if needed, returns raw dump path)
4. Run triage phases (load `savvydfir-triage` skill)
5. Document ALL findings with `add_finding` tool
6. Call `generate_report` when investigation is complete

## Tool Paths

| Tool | Path |
|---|---|
| Volatility 3 | `/usr/local/bin/vol3` |
| MFTECmd | `/usr/local/bin/MFTECmd` |
| EvtxECmd | `/usr/local/bin/EvtxECmd` |
| AppCompatCacheParser | `/usr/local/bin/AppCompatCacheParser` |
| LECmd | `/usr/local/bin/LECmd` |
| JLECmd | `/usr/local/bin/JLECmd` |
| SBECmd | `/usr/local/bin/SBECmd` |
| regripper | `/usr/bin/regripper` |
| fls, mmls, icat, fsstat | `/usr/bin/` |
| ewfmount | `/usr/bin/ewfmount` |
| yara | `/usr/bin/yara` |
| log2timeline.py | `/usr/bin/log2timeline.py` |
| psort.py | `/usr/bin/psort.py` |
| 7z | `/usr/bin/7z` |
