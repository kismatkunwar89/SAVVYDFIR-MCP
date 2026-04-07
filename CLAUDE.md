# SAVVYDFIR-MCP — DFIR Investigation Framework

## What This Is
AI-driven Digital Forensics & Incident Response on SANS SIFT Workstation.
You are the investigator. All evidence is READ-ONLY. Chain of custody applies.

## Critical Rules
1. **NEVER write to `/evidence/`** — treat all disk images and memory dumps as read-only
2. **Every finding must cite**: artifact path + exact command used + timestamp
3. **Load skills on-demand** — do not preload all skills at once

## Available Skills
Load a skill when you need it — type `/skill-name` or let Claude auto-discover:

| Skill | When to load |
|-------|-------------|
| `/memory-forensics` | Analyzing memory dumps, processes, network connections, injection |
| `/disk-forensics` | Mounting E01/raw images, filesystem analysis, artifact extraction |
| `/ez-tools` | Windows artifacts: MFT, event logs, prefetch, LNK, registry |
| `/timeline` | Building super timelines with Plaso/log2timeline |
| `/yara` | Signature scanning on disk or memory |

## Investigation Entry Point
1. Read manifest: `/opt/SAVVYDFIR-MCP/case-templates/manifest.json`
2. Call MCP tool: `start_investigation` with the manifest path
3. Mount evidence first:
   - Disk: call `mount_image` tool — mounts E01 to `/mnt/disk/`
   - Memory: call `load_memory` tool — extracts ZIP, returns raw path
4. Load the appropriate skill for each analysis phase
5. Record ALL findings with `add_finding` tool (evidence_kind, artifact_path, confidence)
6. Call `generate_report` when investigation is complete

## Tool Paths (SIFT Workstation)
```
/usr/bin/fls  /usr/bin/mmls  /usr/bin/icat  /usr/bin/ewfmount
/usr/local/bin/vol3  /usr/bin/yara  /usr/bin/log2timeline.py
/usr/local/bin/MFTECmd  /usr/local/bin/EvtxECmd
/usr/local/bin/AppCompatCacheParser  /usr/local/bin/LECmd
/usr/bin/regripper  /usr/bin/7z
```

## Output Locations
- Cases: `/cases/`
- Mounts: `/mnt/disk/` (disk) and `/mnt/memory/` (memory)
- Evidence: `/evidence/disk/` and `/evidence/memory/` (READ-ONLY)
