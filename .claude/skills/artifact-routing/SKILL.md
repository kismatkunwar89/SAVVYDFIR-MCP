---
name: artifact-routing
description: Load when you need to determine which forensic tool to use for a specific Windows artifact type. Maps artifact categories to exact MCP tools and Bash commands using the Practical Windows Forensics taxonomy.
allowed-tools:
  - Bash
---

# Artifact Routing - Windows Forensics Mind Map

## Execution Evidence
| Artifact | MCP Tool | What It Proves |
|----------|----------|----------------|
| Prefetch (.pf) | `extract_prefetch()` | Binary executed, first/last 8 run times |
| Amcache.hve | `get_amcache()` | Binary existed + SHA-1 hash (survives deletion) |
| ShimCache | `run_analysis()` on AppCompatCache CSV | Binary existed on disk (not necessarily executed) |
| BAM/DAM | `run_analysis()` on registry export | Binary executed by specific user (Win10+) |
| UserAssist | `run_analysis()` on registry export | GUI program execution with count + timestamp |

## Filesystem Evidence
| Artifact | MCP Tool | What It Proves |
|----------|----------|----------------|
| $MFT | `extract_mft_timeline()` | All files that ever existed, SI vs FN timestamps |
| Deleted files | `list_deleted_files()` | Files removed during/after attack |
| $UsnJrnl | `run_analysis()` on MFTECmd $J output | File creation/deletion/rename journal |
| $LogFile | N/A (manual parsing) | NTFS transaction log |

## Persistence Evidence
| Artifact | MCP Tool | What It Proves |
|----------|----------|----------------|
| Run/RunOnce | `extract_registry_run_keys()` | Auto-start binaries |
| Services | `summarize_evtx(channel="System")` → Event 7045 | New service installation |
| Scheduled Tasks | `summarize_evtx(channel="Security")` → Event 4698 | Scheduled task creation |
| WMI | Manual: `strings` on OBJECTS.DATA | WMI event subscriptions |
| Startup Folder | `list_deleted_files()` + `extract_mft_timeline()` | LNK files in Startup |

## Network Evidence
| Artifact | MCP Tool | What It Proves |
|----------|----------|----------------|
| Active connections | `scan_network()` | C2 beacons, lateral movement, data exfil |
| DNS cache | `run_analysis()` on DNS cache export | Resolved domains |
| Browser history | `run_analysis()` on SQLite export | URLs visited |
| SRUM | `run_analysis()` on SRUM CSV | Network usage per application |

## Memory Evidence
| Artifact | MCP Tool | What It Proves |
|----------|----------|----------------|
| Process list | `list_processes()` | Running processes from PEB linked list |
| Hidden processes | `scan_processes()` | DKOM-hidden processes via pool tag scan |
| Code injection | `detect_injection()` | PAGE_EXECUTE_READWRITE VAD regions |
| DLL list | `list_dlls()` | Loaded DLLs per process |
| Credentials | Manual: `vol3 windows.hashdump` | SAM hashes, LSA secrets |

## Lateral Movement Evidence
| Artifact | MCP Tool | What It Proves |
|----------|----------|----------------|
| Event 4624 Type 3 | `summarize_evtx(channel="Security")` | Network logon from remote host |
| Event 4648 | `summarize_evtx(channel="Security")` | Explicit credential logon |
| Event 5140/5145 | `summarize_evtx(channel="Security")` | Network share access |
| PSExec | `extract_prefetch()` + Event 7045 | Remote execution via PsExec |
| WMI | Event 4688 with `wmiprvse.exe` parent | Remote WMI execution |

## Cross-Artifact Correlation
| Check | MCP Tool | What It Detects |
|-------|----------|-----------------|
| All 10 checks (6 core + 4 extended) | `compare_disk_and_memory()` | Fileless, cleanup, injection, C2, persistence, timestomping + USN-journal validation, ShimCache-vs-Amcache clearing, EID 1102 log clearing, SRUM exfiltration |
| Universal anomalies | `sigma_scan()` | Process masquerade, orphans, suspicious persistence, high-value events |
