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
