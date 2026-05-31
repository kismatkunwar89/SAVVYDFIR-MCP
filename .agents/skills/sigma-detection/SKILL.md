---
name: sigma-detection
description: Load when running sigma_scan(), interpreting anomaly results, or mapping findings to MITRE ATT&CK techniques. Covers all 5 universal detectors, severity levels, and pivot patterns from each detection type.
allowed-tools:
  - Bash
---

# Sigma Detection - Universal Anomaly Detection Guide

## How sigma_scan() Works
`sigma_scan(case_id)` reads ALL findings from the case state and runs 5 independent detectors. Each detector implements case-agnostic logic - no hardcoded IPs, usernames, or filenames.

## Detector 1: Process Anomalies
**What it checks:**
- svchost.exe not spawned by services.exe → masquerading (T1036.005)
- System processes (smss, csrss, lsass, etc.) from non-System32 paths → masquerading
- Orphan processes (PPID points to non-existent process) → possible DKOM or parent terminated

**When it fires CRITICAL:**
- svchost wrong parent
- System process wrong path

**Pivot from hit:**
1. `detect_injection(pid=FLAGGED_PID)` - check for code injection
2. `list_dlls(pid=FLAGGED_PID)` - check for suspicious DLLs
3. Hash the binary: `sha256sum <path>`

## Detector 2: Network Anomalies
**What it checks:**
- System processes (svchost, lsass, etc.) with external (non-RFC1918) connections → C2
- Outbound connections on non-standard ports (not 80/443/53/445/etc.) → covert channel
- Listening sockets owned by unexpected processes

**RFC1918 exclusion logic:**
- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 are IGNORED (normal internal traffic)
- Only external IPs trigger alerts

**Pivot from hit:**
1. YARA scan memory for C2 signatures
2. Check if the remote IP appears in other findings
3. Timeline query around the connection timestamp

## Detector 3: MFT Timestomping
**What it checks:**
- $STANDARD_INFORMATION Created vs $FILE_NAME Created
- If delta > 1 hour → timestomping detected (T1070.006)
- SI timestamps are user-modifiable; FN timestamps require kernel access

**Pivot from hit:**
1. Check prefetch for true first execution time
2. Check amcache for SHA-1 hash of the binary
3. `run_analysis()` on MFT CSV to find nearby file operations

## Detector 4: EVTX High-Value Events
**Auto-tagged events with ATT&CK mapping:**
| EventID | Meaning | Tactic | Technique |
|---------|---------|--------|-----------|
| 4624 | Logon success | TA0001 | T1078 |
| 4625 | Logon failure | TA0006 | T1110 |
| 4648 | Explicit logon | TA0008 | T1021 |
| 4672 | Special privileges | TA0004 | T1134 |
| 4688 | Process creation | TA0002 | T1059 |
| 4697 | Service installed | TA0003 | T1543 |
| 4698 | Scheduled task | TA0003 | T1053 |
| 4720 | User created | TA0003 | T1136 |
| 7045 | New service | TA0003 | T1543.003 |
| 1116 | Defender detection | TA0005 | T1562 |

## Detector 5: Persistence Anomalies
**What it checks:**
- Registry Run keys pointing to paths containing: \\Temp\\, \\Tmp\\, \\AppData\\, \\Downloads\\, \\Public\\
- These are non-standard locations for legitimate persistence

**Pivot from hit:**
1. Check if the binary exists: `fls -r | grep <filename>`
2. If binary exists: hash it and check amcache
3. If binary is deleted: check prefetch for execution evidence

## Interpreting Results
- **CRITICAL + HIGH first:** These indicate active compromise indicators
- **MEDIUM:** Suspicious but could be legitimate - investigate before concluding
- **Always follow pivot_suggestion:** Each hit includes the recommended next step
- **Cross-reference:** A single anomaly is a lead; corroborating anomalies across detectors confirm compromise
