---
name: pivot-methodology
description: Load when you have an initial finding and need to determine what to investigate next. Defines universal pivot chains from each artifact type to related evidence, enabling systematic investigation expansion.
allowed-tools:
  - Bash
---

# Pivot Methodology - Universal Investigation Chains

## From a Suspicious Process
```
Process (PID, name, path)
  ├── detect_injection(pid=PID)      → Check for code injection
  ├── list_dlls(pid=PID)             → Check loaded DLLs
  ├── scan_network(dump_path)        → Filter connections by PID
  ├── extract_prefetch()             → Find .PF file for execution proof
  ├── get_amcache()                  → Get SHA-1 hash of binary
  └── list_deleted_files()           → Check if binary was deleted after execution
```

## From a Network Connection
```
Connection (remote_ip, remote_port, PID)
  ├── Look up owning process via PID  → What binary is talking?
  ├── detect_injection(pid=PID)       → Is the process injected?
  ├── Timeline query around timestamp  → What else happened at this time?
  ├── YARA scan memory for C2 sigs    → Known malware family?
  └── Check other connections to same IP → How many hosts are beaconing?
```

## From a Prefetch Entry
```
Prefetch (executable_name, run_count, last_run_times)
  ├── Is the binary still on disk?    → fls or ls
  │   ├── YES → sha256sum + check VirusTotal
  │   └── NO  → Attacker cleaned up (check deleted files + amcache SHA-1)
  ├── What DLLs did it reference?     → referenced_files in prefetch
  ├── What user ran it?               → Correlate with Event 4688 at same timestamp
  └── Timeline around first_run_time  → What happened just before execution?
```

## From a Registry Persistence Key
```
Registry Key (path, value_data)
  ├── Does the binary in value_data exist on disk?
  │   ├── YES → Hash it, check amcache, check if it was timestomped
  │   └── NO  → Binary deleted but persistence remains (compromised + partial cleanup)
  ├── When was the key last written?  → Correlate with timeline
  ├── Who created it?                 → Check Event 4657 (registry audit) or 4688
  └── What type of persistence?       → Map to ATT&CK: T1547, T1053, T1543, etc.
```

## From a Deleted File
```
Deleted File (path, inode, size)
  ├── extract_prefetch()              → Was the deleted file ever executed?
  ├── get_amcache()                   → SHA-1 hash survived deletion?
  ├── extract_mft_timeline()          → When was it created? Modified? Deleted?
  ├── icat to extract content         → Recover the file for analysis
  └── YARA scan the extracted file    → Known malware signature?
```

## From a YARA Match
```
YARA Hit (rule_name, target_file/offset)
  ├── Which rule matched?             → Malware family identification
  ├── In disk or memory?
  │   ├── Disk → Hash the file, check prefetch, check amcache
  │   └── Memory → Which process owns this region? detect_injection()
  ├── Other hits from same rule set?  → Multiple implants?
  └── Timeline around file creation   → When did the malware arrive?
```

## From a Timestomping Detection
```
Timestomp (file_path, SI_created, FN_created)
  ├── What is the TRUE creation time? → FN_created is reliable
  ├── Prefetch first_run_time         → Independent execution timestamp
  ├── Amcache install_time            → Another independent timestamp
  ├── What else was created at the TRUE time? → Timeline query
  └── Why did the attacker backdate?  → Usually to blend with legitimate system files
```

## From a sigma_scan() Hit
```
ArtifactHit (detector, severity, description, pivot_suggestion)
  ├── Always follow pivot_suggestion first
  ├── Cross-reference with other hits from same detector
  ├── Check if the same artifact appears in compare_disk_and_memory() results
  └── Use run_analysis() on CSV output for ad-hoc queries
```

## Universal Rules
1. **Always pivot both directions:** disk → memory AND memory → disk
2. **Follow the timestamps:** earliest timestamp = closest to initial access
3. **Hash everything suspicious:** SHA-256 for disk, SHA-1 from amcache
4. **Check what was deleted:** attackers clean up - deleted evidence is evidence
5. **Map to ATT&CK:** every finding should map to at least one technique
