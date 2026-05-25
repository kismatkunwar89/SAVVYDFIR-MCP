# Forensic Artifacts Knowledge Base

**Purpose**: Specialist agent reference for artifact significance, analysis patterns, and corroboration requirements.

**Principle**: Individual artifacts are CLUES, not PROOF. Corroboration across multiple independent sources elevates confidence from POSSIBLE to CONFIRMED.

---

## 1. $MFT (Master File Table) - extract_mft_timeline

### What It Is
NTFS filesystem metadata. Every file/directory has an MFT entry with:
- File Reference Number (FRN) - unique identifier
- MACB timestamps (Modified, Accessed, Changed $SI, Birth $FN)
- Size, attributes, parent directory
- ADS (Alternate Data Streams)

### What It Proves ALONE
- File **existed** on disk at some point
- File size and location in directory tree
- Timestamp boundaries (when file was created/modified)

### What It CANNOT Prove Alone
- ❌ **Execution** - MFT shows existence, not execution
- ❌ **User access** - timestamps can be programmatic, not user-driven
- ❌ **Authenticity** - timestamps can be manipulated (timestomping)

### What It NEEDS for Corroboration
- **Prefetch or EVTX 4688** → proves execution
- **USN journal** → validates timestamp authenticity (shows manipulation sequence)
- **ShellBags or LNK** → proves user navigation
- **Amcache or ShimCache** → confirms execution artifact exists

### MFT-Analyst Patterns to Look For

#### 1. Timestomping Detection
```python
# Birth time in $FN vs Modified time in $SI should align
# If $SI Modified < $FN Birth → timestomping
df['timestomp_flag'] = df['$SI_Modified'] < df['$FN_Birth']
```

#### 2. Sequential File Drops (Staging)
```python
# Files created within seconds in same directory → staging
df['time_delta'] = df.groupby('ParentPath')['$FN_Birth'].diff()
staging = df[df['time_delta'] < pd.Timedelta(seconds=10)]
```

#### 3. Suspicious Paths
```python
# Execution from Temp/Downloads/Public → investigate
suspicious_paths = ['\\Temp\\', '\\Downloads\\', '\\Public\\', '\\AppData\\Local\\Temp\\']
df[df['Path'].str.contains('|'.join(suspicious_paths), case=False)]
```

#### 4. ADS (Alternate Data Streams)
```python
# Files with ADS → hidden content
df[df['ADS'].notna()]
```

### Cross-Reference With
- **USN journal** (`extract_usn_journal`) → file manipulation timeline
- **Prefetch** (`extract_prefetch`) → execution confirmation
- **Amcache** (`get_amcache`) → hash + compilation timestamp
- **EVTX** (`summarize_evtx` EID 4688) → process creation

---

## 2. $UsnJrnl (Update Sequence Number Journal) - extract_usn_journal

### What It Is
NTFS change journal. Records every filesystem operation:
- FILE_CREATE, FILE_DELETE, DATA_EXTEND, DATA_TRUNCATE
- RENAME_OLD_NAME, RENAME_NEW_NAME, BASIC_INFO_CHANGE
- References MFT entry by FRN (File Reference Number)
- More granular than MFT - shows operation SEQUENCE

### What It Proves ALONE
- **Change sequence** - what happened to files over time
- **File manipulation patterns** - create → modify → rename → delete
- **Deletion evidence** - even after MFT entry is purged

### What It CANNOT Prove Alone
- ❌ **WHO caused the change** - user vs process unknown
- ❌ **Execution** - shows file activity, not execution
- ❌ **Motive** - pattern recognition needs context

### What It NEEDS for Corroboration
- **MFT** → file metadata (size, path, timestamps)
- **EVTX 4688** → process that caused the change
- **SRUM** → network activity during file creation (exfiltration)
- **Prefetch** → execution after file creation

### USN-Analyst (MFT-Analyst) Patterns to Look For

#### 1. Ransomware Detection
```python
# Rename burst to .encrypted/.locked extensions within seconds
renames = df[df['Reason'].str.contains('RENAME_NEW_NAME')]
ransomware = renames[renames['FileName'].str.match(r'.*\.(encrypted|locked|crypt|enc)$', case=False)]
burst = ransomware.groupby(ransomware['Timestamp'].dt.floor('10S')).size()
if (burst > 50).any():  # 50+ files renamed in 10 seconds
    # CONFIRMED ransomware pattern
```

#### 2. Exfiltration Staging
```python
# Large file created → DATA_EXTEND → short lived → DELETE
staging_files = df[
    (df['Reason'].str.contains('FILE_CREATE')) &
    (df['FileSize'] > 10_000_000)  # >10MB
]
# Check if file extended then deleted within minutes
for fid in staging_files['FRN']:
    extends = df[(df['FRN'] == fid) & (df['Reason'].str.contains('DATA_EXTEND'))]
    deletes = df[(df['FRN'] == fid) & (df['Reason'].str.contains('FILE_DELETE'))]
    if not extends.empty and not deletes.empty:
        lifespan = deletes['Timestamp'].min() - staging_files['Timestamp'].min()
        if lifespan < pd.Timedelta(minutes=30):
            # POSSIBLE exfiltration staging
```

#### 3. Anti-Forensics (Prefetch Deletion)
```python
# Prefetch .pf file deleted → attacker cleanup
pf_deletes = df[
    (df['Reason'].str.contains('FILE_DELETE')) &
    (df['FileName'].str.endswith('.pf', case=False))
]
```

#### 4. Attacker Cleanup Sequence
```python
# Create → Execute → Delete within minutes → anti-forensics
# Group by FRN, look for CREATE → DELETE with short lifespan
for fid in df['FRN'].unique():
    ops = df[df['FRN'] == fid].sort_values('Timestamp')
    if 'FILE_CREATE' in ops['Reason'].values and 'FILE_DELETE' in ops['Reason'].values:
        lifespan = ops['Timestamp'].max() - ops['Timestamp'].min()
        if lifespan < pd.Timedelta(minutes=10):
            # POSSIBLE attacker cleanup
```

### Cross-Reference With
- **MFT** → file metadata (align FRN)
- **EVTX 4688** → process that triggered the file change
- **SRUM** → network activity during file operations
- **Sigma hunt** → file deletion + log clearing patterns

---

## 3. EVTX (Event Logs) - summarize_evtx

### What It Is
Windows event logging system. Records:
- **Security.evtx**: Authentication, logon, privilege use, audit policy changes
- **System.evtx**: Services, drivers, system events
- **Application.evtx**: Application errors/warnings
- **Sysmon**: Process creation, network, file creation (if installed)

### What It Proves ALONE
- **WHO** authenticated (account names, SIDs)
- **WHEN** processes executed (EID 4688)
- **WHERE** authentication originated (source IPs, workstation names)
- **WHAT** was accessed (object access auditing, EID 4663)

### What It CANNOT Prove Alone
- ❌ **File timestamps** - logs events, not file metadata
- ❌ **Complete timeline** - gaps if logs cleared or audit policy disabled
- ❌ **Process parentage** - 4688 records parent PID but not full chain

### What It NEEDS for Corroboration
- **MFT/Prefetch/Amcache** → file existence for executed processes
- **Memory** → validates running processes (EVTX can be forged post-incident)
- **USN** → file changes during process activity
- **SRUM** → network bytes vs EVTX 5156 connections

### EVTX-Analyst Patterns to Look For

#### 1. Lateral Movement (Pass-the-Hash)
```python
# EID 4624 Type 3 (network logon) from unusual source
lateral = evtx[
    (evtx['EventID'] == 4624) &
    (evtx['LogonType'] == 3) &
    (~evtx['SourceIP'].isin(['127.0.0.1', '-', '::1']))
]
# Cross-reference with 4672 (special privileges) within 1 second
for idx, row in lateral.iterrows():
    privs = evtx[
        (evtx['EventID'] == 4672) &
        (evtx['SubjectUserName'] == row['TargetUserName']) &
        (abs(evtx['Timestamp'] - row['Timestamp']) < pd.Timedelta(seconds=1))
    ]
    if not privs.empty:
        # CONFIRMED lateral movement with elevated privileges
```

#### 2. Credential Dumping (Mimikatz)
```python
# EID 4656 (object access) to lsass.exe process
lsass_access = evtx[
    (evtx['EventID'] == 4656) &
    (evtx['ObjectName'].str.contains('lsass.exe', case=False))
]
# Or EID 4663 (object access attempt) with PROCESS_VM_READ
```

#### 3. Persistence (Scheduled Tasks)
```python
# EID 4698 (scheduled task created)
tasks = evtx[evtx['EventID'] == 4698]
# Cross-reference with registry run keys from extract_registry_run_keys
```

#### 4. Defense Evasion (Log Clearing)
```python
# EID 1102 (Security log cleared) or 104 (System log cleared)
log_clear = evtx[evtx['EventID'].isin([1102, 104])]
# If found → trigger analyze_vss (shadow copy recovery)
```

#### 5. RDP Brute Force
```python
# EID 4625 (failed logon) Type 10 (RDP) burst
rdp_fails = evtx[
    (evtx['EventID'] == 4625) &
    (evtx['LogonType'] == 10)
]
burst = rdp_fails.groupby([rdp_fails['Timestamp'].dt.floor('60S'), 'SourceIP']).size()
if (burst > 5).any():  # 5+ failures per minute
    # CONFIRMED brute force attempt
```

### Cross-Reference With
- **Sigma hunt** (`sigma_hunt`) → rule-based validation of patterns
- **MFT/Prefetch** → executed binary exists on disk
- **Memory** → process still running or injection
- **SRUM** → network traffic during authentication

---

## 4. Registry (Persistence Keys) - extract_registry_run_keys

### What It Is
Windows Registry persistence Auto-Start Extension Points (ASEPs):
- Run/RunOnce keys (HKLM/HKCU)
- Services (HKLM\\System\\CurrentControlSet\\Services)
- Winlogon shell/userinit
- Scheduled tasks references
- LSA packages, AppInit_DLLs

### What It Proves ALONE
- **Persistence mechanism configured**
- **LastWriteTime of registry key** (when key was modified, not value)
- **Path to executable**

### What It CANNOT Prove Alone
- ❌ **Execution** - registry entry ≠ execution proof
- ❌ **When specific value was set** - only key LastWrite time
- ❌ **Whether binary exists** - path may be deleted

### What It NEEDS for Corroboration
- **MFT/Amcache/ShimCache** → binary existence
- **Prefetch** → binary executed
- **EVTX 4688 or 7045** → execution confirmation
- **Memory** → persistence payload currently running

### Registry-Analyst Patterns to Look For

#### 1. Suspicious Run Key Paths
```python
# Executables from Temp/Downloads/AppData/Public
suspicious = registry[
    (registry['RegistryKey'].str.contains('Run', case=False)) &
    (registry['Value'].str.contains('\\Temp\\|\\Downloads\\|\\AppData\\Local\\|\\Public\\', case=False))
]
```

#### 2. Service Persistence (Non-Standard Paths)
```python
# Services outside System32/Program Files
services = registry[registry['RegistryKey'].str.contains('\\Services\\', case=False)]
suspicious_services = services[
    ~services['ImagePath'].str.contains('System32|Program Files', case=False)
]
```

#### 3. Winlogon Hijacking
```python
# Shell/Userinit modified from default
winlogon = registry[
    (registry['RegistryKey'].str.contains('Winlogon', case=False)) &
    (registry['ValueName'].isin(['Shell', 'Userinit']))
]
# Default: Shell=explorer.exe, Userinit=C:\Windows\system32\userinit.exe
defaults = {
    'Shell': 'explorer.exe',
    'Userinit': 'C:\\Windows\\system32\\userinit.exe'
}
for idx, row in winlogon.iterrows():
    if row['Value'] != defaults.get(row['ValueName']):
        # POSSIBLE Winlogon hijacking
```

#### 4. LSA Package Injection
```python
# LSA packages (credential theft persistence)
lsa = registry[
    registry['RegistryKey'].str.contains('LSA|Authentication Packages', case=False)
]
# Non-default packages → investigate
```

### Cross-Reference With
- **ShimCache** (`extract_shimcache`) → executable was parsed by Windows
- **Prefetch** (`extract_prefetch`) → executable ran
- **EVTX 7045** (service installation) → service creation event
- **EVTX 4698** (scheduled task) → task creation event

---

## 5. Amcache.hve - get_amcache

### What It Is
Application Compatibility Cache. Records executables for Windows compatibility:
- SHA-1 hash of executable (CRITICAL for renamed malware)
- Full path where executed
- LinkDate (PE compilation timestamp from binary header)
- File size

### What It Proves ALONE
- **Binary existed on disk** at some point
- **SHA-1 hash** (survives rename/move)
- **Compilation date** (from PE header, hard to forge)

### What It CANNOT Prove Alone
- ❌ **Execution** - Amcache records observation, not execution
- ❌ **When it ran** - only when Windows first parsed it
- ❌ **Run count** - Amcache doesn't track frequency

### What It NEEDS for Corroboration
- **Prefetch** → execution proof (run count, last run time)
- **EVTX 4688** → process creation event
- **MFT** → file creation timestamp (compare with LinkDate for staging detection)
- **ShimCache** → broader execution context

### Amcache-Analyst Patterns to Look For

#### 1. Renamed Malware Detection (SHA-1)
```python
# Same SHA-1, different paths → binary was renamed/moved
hash_groups = amcache.groupby('SHA1')['Path'].apply(list)
renamed = hash_groups[hash_groups.apply(len) > 1]
for sha1, paths in renamed.items():
    # POSSIBLE renamed malware or legitimate update
    # Cross-reference SHA1 with VirusTotal, EVTX, Prefetch
```

#### 2. BYOVD (Bring Your Own Vulnerable Driver)
```python
# Drivers with old compilation dates (LinkDate)
drivers = amcache[amcache['Path'].str.contains('\\.sys$', case=False)]
old_drivers = drivers[drivers['LinkDate'] < '2015-01-01']
# Old drivers + recent first seen → BYOVD attack
```

#### 3. Staging Detection (LinkDate vs MFT Birth)
```python
# Binary compiled 1 year ago but first seen today → pre-compiled malware
# Merge with MFT on Path
merged = amcache.merge(mft, left_on='Path', right_on='Path')
staged = merged[
    (merged['LinkDate'] < merged['$FN_Birth'] - pd.Timedelta(days=30))
]
# Compiled 30+ days before first appearance → staged attack
```

#### 4. Loose Executables (Suspicious Paths)
```python
# Executables from non-standard locations
loose = amcache[
    amcache['Path'].str.contains('\\Temp\\|\\Downloads\\|\\Public\\|\\Recycle', case=False)
]
```

### Cross-Reference With
- **Prefetch** (`extract_prefetch`) → execution confirmation
- **MFT** (`extract_mft_timeline`) → file birth time vs LinkDate
- **ShimCache** (`extract_shimcache`) → broader context
- **EVTX 4688** → process creation

---

## 6. Prefetch - extract_prefetch

### What It Is
Windows execution artifact (C:\\Windows\\Prefetch\\*.pf):
- Created when executable runs (Windows optimizes future loads)
- Records last 8 run times (Windows 10+) or last 1 (Windows 7)
- Run count
- Files/directories accessed during execution

### What It Proves ALONE
- **Execution highly likely** (Prefetch = Windows prepared to run it)
- **Last run timestamp(s)**
- **Run count** (how many times executed)
- **Referenced files** (DLLs, data files accessed)

### What It CANNOT Prove Alone
- ❌ **Guaranteed execution** - Prefetch can be created by AV scan
- ❌ **User interaction** - automated task can create Prefetch
- ❌ **Process success** - Prefetch created even if process crashed

### What It NEEDS for Corroboration
- **EVTX 4688** → process creation event (definitive proof)
- **MFT** → binary existence
- **Amcache** → hash confirmation
- **ShimCache** → broader execution context

### Prefetch-Analyst Patterns to Look For

#### 1. Multi-Path Execution (Same EXE, Different Paths)
```python
# Same executable name from different paths → renamed or moved malware
exe_name_groups = prefetch.groupby('ExecutableName')['Path'].apply(list)
multi_path = exe_name_groups[exe_name_groups.apply(len) > 1]
for exe, paths in multi_path.items():
    # POSSIBLE renamed malware or legitimate update
```

#### 2. SysWOW64 LOLBin Abuse
```python
# 32-bit binaries on 64-bit system (living-off-the-land)
lolbins = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
syswow = prefetch[
    (prefetch['Path'].str.contains('SysWOW64', case=False)) &
    (prefetch['ExecutableName'].isin(lolbins))
]
# SysWOW64 + LOLBin → POSSIBLE attacker use
```

#### 3. Orphaned Prefetch (File Deleted)
```python
# Prefetch exists but executable missing from MFT
# Merge with MFT, find unmatched
orphaned = prefetch[~prefetch['Path'].isin(mft['Path'])]
# POSSIBLE anti-forensics (deleted after execution)
```

#### 4. Temporal Correlation (Run Time vs File Birth)
```python
# Prefetch last run within 1 minute of MFT file birth → immediate execution
merged = prefetch.merge(mft, left_on='Path', right_on='Path')
immediate_exec = merged[
    abs(merged['LastRunTime'] - merged['$FN_Birth']) < pd.Timedelta(minutes=1)
]
# Drop → execute within 60 seconds → malware pattern
```

### Cross-Reference With
- **EVTX 4688** (`summarize_evtx`) → process creation PROOF
- **Amcache** (`get_amcache`) → hash + compilation date
- **MFT** (`extract_mft_timeline`) → file birth time
- **ShimCache** (`extract_shimcache`) → execution context

---

## 7. ShimCache (AppCompatCache) - extract_shimcache

### What It Is
Application Compatibility Cache in SYSTEM hive:
- Records EVERY executable path Windows observed (broader than Amcache)
- Does NOT record run count or last run time
- Only records: path, file size, last modified time
- Can include executables that NEVER ran (just scanned)

### What It Proves ALONE
- **Binary existed on disk**
- **Windows parsed/observed it** (at least once)
- **File path and size**

### What It CANNOT Prove Alone
- ❌ **Execution** - observation ≠ execution
- ❌ **When it ran** - only modified time
- ❌ **Run count** - ShimCache doesn't track

### What It NEEDS for Corroboration
- **Prefetch** → execution confirmation
- **Amcache** → execution + hash
- **EVTX 4688** → definitive execution proof
- **MFT** → file existence validation

### ShimCache-Analyst Patterns to Look For

#### 1. Execution Confirmation (ShimCache + Prefetch)
```python
# Binary in ShimCache AND Prefetch → CONFIRMED execution
shimcache_paths = set(shimcache['Path'])
prefetch_paths = set(prefetch['Path'])
confirmed_execution = shimcache_paths & prefetch_paths
# Intersection = definitively executed
```

#### 2. Suspicious Paths (Executables Outside Standard Locations)
```python
# Executables outside System32/Program Files/WinSxS
standard_paths = ['System32', 'Program Files', 'WinSxS']
suspicious = shimcache[
    ~shimcache['Path'].str.contains('|'.join(standard_paths), case=False)
]
```

#### 3. Missing Amcache Entry (Anti-Forensics)
```python
# ShimCache entry but NO Amcache → Amcache was cleared
shimcache_paths = set(shimcache['Path'])
amcache_paths = set(amcache['Path'])
missing_amcache = shimcache_paths - amcache_paths
# Entries in ShimCache but not Amcache → POSSIBLE anti-forensics
```

#### 4. Recent Addition (Modified Time vs Current Time)
```python
# Executables added recently (within incident window)
incident_start = pd.Timestamp('2026-05-15 14:00:00')
incident_end = pd.Timestamp('2026-05-15 16:00:00')
incident_binaries = shimcache[
    shimcache['LastModified'].between(incident_start, incident_end)
]
```

### Cross-Reference With
- **Prefetch** (`extract_prefetch`) → execution proof
- **Amcache** (`get_amcache`) → hash + compilation date
- **EVTX 4688** → process creation
- **MFT** (`extract_mft_timeline`) → file existence

---

## 8. SRUM (System Resource Utilization Monitor) - extract_srum

### What It Is
Windows 8+ system resource tracking (ESE database):
- **Network Data Usage** table: bytes sent/received per process per hour (60-day retention)
- **App Resource Usage** table: CPU, disk I/O per 30-day window
- **Records DELETED applications** (AppId remains after binary deleted)

### What It Proves ALONE
- **Exfiltration quantification** (bytes sent per process)
- **Network activity per process** (even if process deleted)
- **Deleted applications** (anti-forensics indicator)

### What It CANNOT Prove Alone
- ❌ **Network destination** (IP addresses not recorded)
- ❌ **Execution proof** (SRUM records resource use, not execution)
- ❌ **Complete network timeline** (hourly aggregation)

### What It NEEDS for Corroboration
- **EVTX 5156** (network connections) → destination IPs
- **Memory scan_network** → active connections at time of capture
- **MFT/Amcache** → binary existence (or deletion)
- **USN** → file creation/deletion timeline

### SRUM-Analyst Patterns to Look For

#### 1. Exfiltration Volume Quantification
```python
# Processes with high bytes_sent
exfil = srum[srum['BytesSent'] > 100_000_000]  # >100MB sent
# Cross-reference with EVTX 5156 for destination IPs
```

#### 2. Deleted Applications (Anti-Forensics)
```python
# AppId with no matching binary in MFT/Amcache
srum_appids = set(srum['AppId'])
mft_paths = set(mft['Path'])
deleted_apps = srum[~srum['AppId'].isin(mft_paths)]
# SRUM records application but binary missing → anti-forensics
```

#### 3. Network Activity During Incident Window
```python
# Network usage during known compromise timeframe
incident_start = pd.Timestamp('2026-05-15 14:00:00')
incident_end = pd.Timestamp('2026-05-15 16:00:00')
incident_network = srum[
    srum['Timestamp'].between(incident_start, incident_end) &
    (srum['BytesSent'] > 0)
]
```

#### 4. Rogue Process Network Usage
```python
# Processes from suspicious paths with network activity
suspicious_paths = ['\\Temp\\', '\\Downloads\\', '\\Public\\', '\\AppData\\Local\\']
rogue = srum[
    (srum['AppId'].str.contains('|'.join(suspicious_paths), case=False)) &
    (srum['BytesSent'] > 0)
]
```

### Cross-Reference With
- **EVTX 5156** (`summarize_evtx`) → network connection IPs
- **Memory scan_network** → active connections
- **MFT** (`extract_mft_timeline`) → file existence
- **USN** (`extract_usn_journal`) → file creation/deletion

---

## Memory Artifacts

### 9. Process List - list_processes

**What It Proves**: Running processes at time of memory capture
**Corroborate With**: EVTX 4688 (process creation), Prefetch (execution history), MFT (binary existence)
**Pattern**: Processes from suspicious paths, processes with no parent (PPID=0 or orphaned)

### 10. Hidden Processes - scan_processes

**What It Proves**: DKOM (Direct Kernel Object Manipulation) hidden processes
**Corroborate With**: list_processes (what's visible), EVTX 4688 (was it created), detect_injection (code injection)
**Pattern**: Processes in scan_processes but NOT in list_processes → hidden by rootkit

### 11. Network Connections - scan_network

**What It Proves**: Active network connections at time of capture
**Corroborate With**: EVTX 5156 (connection history), SRUM (bytes sent), MFT/Prefetch (binary exists)
**Pattern**: Connections to non-RFC1918 IPs, connections from suspicious binaries, beaconing (regular intervals)

---

## 12. Browser Artifacts (Chrome/Firefox/Edge)

### What It Is
SQLite databases tracking browser activity:
- **History**: `places.sqlite` (Firefox), `History` (Chrome/Edge)
- **Downloads**: Download URLs, file paths, timestamps
- **Cookies**: Session tokens, authentication state
- **Cache**: `cache_data` files (Chromium), POST requests, binary downloads
- **Extensions**: Unpacked extensions in AppData, `manifest.json` permissions
- **Login Data**: Saved passwords (encrypted), auto-fill forms

### What It Proves ALONE
- **Web URLs visited** - timestamps, titles, visit counts
- **Downloads initiated** - source URL, destination path, bytes downloaded
- **Session activity** - cookies prove authentication, not necessarily user action
- **Extension installed** - presence of extension, permissions granted

### What It CANNOT Prove
- **User vs malware** - browser history doesn't distinguish human from automated
- **File access after download** - browser records download, not subsequent file opening
- **Credential theft** - Login Data SQLite proves storage, not exfiltration

### What It NEEDS for Corroboration
- **Network connections in memory** → proves browser actually communicated (not just history database manipulation)
- **Zone.Identifier ADS** → proves download from internet zone
- **LNK files** → proves downloaded file was opened
- **EVTX 5156** → proves network connection matching browser history timestamp

### Specialist Patterns to Look For

**C2 Beaconing Detection**:
```python
# Fixed interval connections in browser history
history_df = run_analysis(csv_path, """
df['time_delta'] = df.groupby('domain')['timestamp'].diff()
beaconing = df[df['time_delta'].between('50s', '70s')]  # ±10s jitter on 60s beacon
""")
```

**Private Browsing in Memory**:
```python
# InPrivate/Incognito sessions leave memory artifacts
# Look for browser processes with "private" command-line args
# Session restore files while active (deleted on normal exit)
```

**Extension Forensics**:
```python
# Parse manifest.json for suspicious permissions
# "tabs", "webRequest", "cookies" = credential theft capability
# "downloads" = exfiltration capability
# Unpacked extensions from C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions\
```

### Cross-Reference With
- **Memory network connections** → validate browser history is real (not planted)
- **SRUM bytes_sent** → quantify data transferred per browser process
- **Zone.Identifier** → prove downloads came from internet
- **LNK files** → prove downloaded files were opened
- **EVTX 5156** → network connection logs matching history timestamps

---

## 13. LNK Files and Jump Lists

### What It Is
Windows Shortcut files (.lnk) and Jump Lists (AutomaticDestinations/CustomDestinations):
- **LNK**: Created when user accesses file via Explorer, Desktop, or shortcut
- **Jump Lists**: Recent/pinned files per application (taskbar right-click)
- **Distributed Link Tracking (DLT)**: MAC address, NetBIOS hostname embedded in LNK
- **DestList stream**: Entry number, pin status, hostname, access count

### What It Proves ALONE
- **File was accessed via Explorer/Desktop** - NOT command-line access
- **Target metadata** - file size, timestamps, volume serial
- **Network file access** - UNC paths (\\server\share\file.doc) prove remote access
- **MAC address of target system** - DLT embeds originating machine's MAC

### What It CANNOT Prove
- **File contents were read** - LNK proves navigation, not file opening
- **Execution** - LNK to .exe proves double-click attempt, not successful execution
- **Timeline accuracy** - LNK created during first access, not updated on subsequent

### What It NEEDS for Corroboration
- **ShellBags** → proves folder navigation leading to file
- **RecentDocs registry** → proves file in recent documents list
- **Prefetch** → if LNK points to .exe, Prefetch proves execution
- **MFT** → proves target file exists on disk (or existed before deletion)

### Specialist Patterns to Look For

**Three-Source File Access Validation**:
```python
# LNK + ShellBag + RecentDocs = CONFIRMED file access
lnk_paths = set(get_findings(artifact_type="lnk_file")['target_path'])
shellbag_paths = set(get_findings(artifact_type="shellbag")['path'])
recent_paths = set(get_findings(artifact_type="registry_recent")['path'])

confirmed_access = lnk_paths & shellbag_paths & recent_paths
# 3 independent sources = 1.00 confidence
```

**UNC Path Network Access**:
```python
# LNK with UNC path = remote file access without local copy
unc_lnks = [lnk for lnk in lnk_findings if lnk['target_path'].startswith('\\\\')]
# Correlate with EVTX 5140 (share access) matching timestamp
```

**Missing LNK Anti-Forensics**:
```python
# Expected LNK for file access but missing = user deleted LNK
# ShellBag shows folder navigation but no LNK for file inside
```

**Jump Lists AppID Mapping**:
```python
# AutomaticDestinations filename = AppID hash
# e.g., 1b4dd67f29cb1962.automaticDestinations-ms = Microsoft Word
# Parse DestList stream for access frequency, pin status
```

### Cross-Reference With
- **ShellBags** → folder navigation timeline
- **RecentDocs** → recent file registry keys
- **Prefetch** → if .exe, proves execution
- **MFT** → target file timestamps, existence
- **EVTX 5140** → network share access for UNC paths

---

## 14. Zone.Identifier ADS (Mark of the Web)

### What It Is
Alternate Data Stream (ADS) attached to files downloaded from the internet:
- **ZoneId**: Internet zone (3=Internet, 4=Restricted Sites, 2=Trusted)
- **ReferrerUrl**: URL of the page that linked to the download
- **HostUrl**: Direct download URL (attacker staging server)
- **Created by**: Browser, email client, Office (when opening attachments)

### What It Proves ALONE
- **File was downloaded from internet** - not created locally or copied from USB
- **Download URL** - HostUrl = attacker infrastructure
- **Referring page** - ReferrerUrl = phishing page or compromised site
- **Download timestamp** - ADS creation = download completion

### What It CANNOT Prove
- **File was executed** - Zone.Identifier proves download, not opening
- **File contents were malicious** - proves origin, not payload
- **User intent** - Zone.Identifier doesn't distinguish malicious from legitimate download

### What It NEEDS for Corroboration
- **LNK file** → proves user opened the downloaded file
- **Prefetch** → if .exe, proves execution
- **EVTX 4688** → process creation matching filename
- **Browser history** → download URL in history matching HostUrl

### Specialist Patterns to Look For

**Phishing Infrastructure Attribution**:
```python
# Extract HostUrl and ReferrerUrl for IOC tracking
zone_id_findings = get_findings(artifact_type="zone_identifier")
for finding in zone_id_findings:
    host_url = finding.get('HostUrl', '')
    referrer_url = finding.get('ReferrerUrl', '')
    # HostUrl = attacker's file staging server
    # ReferrerUrl = compromised site or phishing page
```

**ZoneId=4 Bypass Detection**:
```python
# ZoneId=4 = Restricted Sites (should be blocked)
# If file with ZoneId=4 exists on disk = user bypassed security warning
restricted_downloads = [z for z in zone_id_findings if z.get('ZoneId') == '4']
```

**Correlation: Download → Execution Chain**:
```python
# Zone.Identifier timestamp → LNK creation → Prefetch FirstRun → EVTX 4688
download_time = zone_finding['timestamp']
matching_lnk = [l for l in lnk_findings if abs(l['timestamp'] - download_time) < 300]
matching_prefetch = [p for p in prefetch_findings if abs(p['FirstRun'] - download_time) < 300]
if matching_lnk and matching_prefetch:
    confidence = 1.00  # Three sources confirm execution chain
```

### Cross-Reference With
- **Browser history** → download URL validation
- **LNK files** → file opened after download
- **Prefetch** → execution after download
- **EVTX 4688** → process creation matching filename
- **MFT** → file creation timestamp matching ADS timestamp

---

## 15. Volume Shadow Snapshots (VSS)

### What It Is
Copy-on-write snapshots of the entire volume:
- **Catalog file**: `System Volume Information\{GUID}` - tracks active shadow copies
- **Store files**: `{GUID}{CATALOG-GUID}` - 16KB data chunks
- **Creation triggers**: Windows Update, app installs, System Restore, scheduled tasks
- **VSS Service**: Manages snapshot lifecycle, deletion

### What It Proves ALONE
- **System state at snapshot time** - complete filesystem view
- **Deleted artifacts** - files deleted after snapshot still exist in VSS
- **Pre-tampering logs** - Security.evtx before Event ID 1102 log clearing
- **Baseline comparison** - registry hives, Run keys before compromise

### What It CANNOT Prove
- **User activity inside VSS** - snapshots are read-only, no user interaction
- **Execution from VSS** - binaries in VSS cannot run directly
- **Timeline ordering** - VSS timestamp = creation, not artifact activity time

### What It NEEDS for Corroboration
- **Event ID 1102** → triggers VSS recovery for log clearing
- **MFT InUse=False** → file deleted on live system but exists in VSS
- **Registry comparison** → current Run keys vs VSS Run keys = new persistence
- **Incident timeline** → VSS created before/during/after attack window

### Specialist Patterns to Look For

**Post-1102 Log Recovery**:
```python
# Event ID 1102 detected → check VSS pre-dating clearance
log_cleared_time = evtx_finding['timestamp']
vss_snapshots = get_findings(artifact_type="vss_snapshot")
pre_clearing_vss = [v for v in vss_snapshots if v['created'] < log_cleared_time]

if pre_clearing_vss:
    # Extract Security.evtx from oldest VSS pre-dating clearance
    recommended_vss = pre_clearing_vss[0]['id']
```

**Baseline Comparison (Pre-Incident)**:
```python
# Compare current registry Run keys vs oldest VSS Run keys
current_run_keys = get_findings(artifact_type="registry_run")
vss_run_keys = extract_from_vss(oldest_vss_id, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")

new_persistence = set(current_run_keys) - set(vss_run_keys)
# Keys present now but not in VSS = added during compromise
```

**VSS Deletion as Anti-Forensics**:
```python
# EVTX 4688: vssadmin.exe delete shadows /all
# VSS Service events: Store deletion confirmations
# Registry: VSS key modifications
vss_deletion = [e for e in evtx_findings if '4688' in e['event_id'] and 'vssadmin' in e['command_line']]
if vss_deletion:
    add_finding("Attacker deleted Volume Shadow Snapshots - anti-forensics", confidence=1.00)
```

**Temporal Analysis**:
```python
# VSS created during attack window = may contain attacker artifacts
for vss in vss_snapshots:
    if incident_start < vss['created'] < incident_end:
        # Snapshot taken during compromise - check for staged malware
```

### Cross-Reference With
- **Event ID 1102** → log clearing detection triggers VSS recovery
- **MFT InUse=False** → deleted files may exist in VSS
- **Registry Run keys** → baseline comparison for new persistence
- **EVTX 4688 vssadmin** → VSS deletion as anti-forensics
- **Incident timeline** → determine if VSS pre/post-dates attack

---

## 16. Cloud Sync Artifacts (OneDrive/Dropbox/Google Drive)

### What It Is
Local sync client artifacts tracking cloud storage activity:
- **OneDrive**: `sync_diagnostics_*.log`, `SyncEngineDatabase.db` (SQLite)
- **Dropbox**: `.dropbox.cache`, `sync_history.db`, `filecache.db`
- **Google Drive**: `sync_config.db`, `snapshot.db`, `cloud_graph\*.db`
- **Upload logs**: File paths, timestamps, bytes transferred
- **Shared folder metadata**: External collaborators, public link creation

### What It Proves ALONE
- **Files uploaded to cloud** - local file path, upload timestamp
- **Download from cloud** - sync client retrieved file from cloud storage
- **Sync client installed** - presence proves user has cloud access
- **Folder sync configuration** - which local folders sync to cloud

### What It CANNOT Prove
- **User vs automated** - sync client uploads don't distinguish user-initiated from automatic
- **Data exfiltration intent** - legitimate backup vs attacker exfiltration
- **File access by others** - shared folder doesn't prove collaborators accessed files
- **Timeline precision** - upload timestamp may lag actual file modification

### What It NEEDS for Corroboration
- **SRUM bytes_sent** → quantify data volume uploaded
- **Browser history** → manual cloud web access correlates with uploads
- **Off-hours activity** → uploads at 2am = suspicious
- **Process network connections** → memory shows sync client connected to cloud domains

### Specialist Patterns to Look For

**High-Volume Exfiltration**:
```python
# SRUM: OneDrive/Dropbox process sent >10GB
srum_df = run_analysis(srum_csv, "df[df['ProcessName'].str.contains('onedrive|dropbox|googledrivesync', case=False)]")
high_volume = srum_df[srum_df['BytesSent'] > 10*1024**3]  # >10GB

# Correlate with cloud sync logs for file list
```

**Off-Hours Uploads**:
```python
# Flag uploads between 6pm-6am (outside business hours)
sync_logs = get_findings(artifact_type="cloud_sync")
off_hours = [s for s in sync_logs if s['timestamp'].hour < 6 or s['timestamp'].hour >= 18]
```

**Shared Folder Forensics**:
```python
# Detect external sharing (public links, external email addresses)
# OneDrive: SyncEngineDatabase.db - SharedFolders table
# Dropbox: shared_folders.json
```

**Selective Sync Patterns**:
```python
# User configured specific folders to sync (not entire cloud)
# Selective sync of sensitive directories (Finance/, HR/, Legal/) = targeted exfiltration
```

### Cross-Reference With
- **SRUM** → bytes_sent quantification
- **Browser history** → manual web access to cloud storage
- **Memory network connections** → sync client active connections
- **EVTX 5156** → network connections to cloud domains
- **MFT** → local file modification timestamps matching upload times

---

## Corroboration Decision Tree

```
Finding: malware.exe executed at 14:32:16

Step 1: Check Prefetch
  → Prefetch exists? YES → confidence = POSSIBLE (not definitive)

Step 2: Check EVTX 4688
  → Process creation event at 14:32:16? YES → confidence = PROBABLE (2 sources)

Step 3: Check MFT
  → File birth time = 14:32:15? YES → confidence = PROBABLE (3 sources, tight temporal)

Step 4: Check Amcache
  → SHA1 exists, LinkDate = 2024-03-15 (1 year old)? YES → confidence = CONFIRMED
  → Reason: 4 independent sources, staged malware pattern

Step 5: Check USN
  → FILE_CREATE at 14:32:15? YES → confidence = CONFIRMED
  → Reason: 5 independent sources, no timestomping (USN cannot be forged)

Step 6: Check EVTX 5156
  → Network connection from PID within 2 seconds? YES → confidence = CONFIRMED
  → Reason: Execution + immediate C2 beacon = automated malware

FINAL: CONFIRMED execution with C2 beacon, staged attack (pre-compiled binary)
```

---

## Agent Responsibilities

### MFT-Analyst
- Analyze MFT for timestomping, suspicious paths, ADS
- Cross-reference with USN for validation
- Identify staging patterns (sequential drops)

### EVTX-Analyst
- Analyze authentication anomalies, lateral movement
- Cross-reference with Sigma hunt for validation
- Identify log clearing → trigger VSS recovery

### Registry-Analyst
- Analyze persistence ASEPs
- Cross-reference with ShimCache/Amcache for binary existence
- Identify Winlogon/LSA hijacking

### Amcache-Analyst
- Analyze renamed malware (SHA-1 tracking)
- Cross-reference LinkDate with MFT birth for staging detection
- Identify BYOVD (old drivers)

### Prefetch-Analyst
- Analyze execution artifacts
- Cross-reference with EVTX 4688 for confirmation
- Identify orphaned prefetch (deleted binaries)

### ShimCache-Analyst (Registry-Analyst)
- Analyze broad executable observation
- Cross-reference with Prefetch for execution confirmation
- Identify suspicious paths

### SRUM-Analyst
- Quantify exfiltration volumes
- Identify deleted applications (anti-forensics)
- Cross-reference with EVTX 5156 for destination IPs

### Memory-Analyst
- Analyze hidden processes, code injection
- Cross-reference with EVTX/Prefetch for process provenance
- Identify memory-only malware

---

## Timeline-Analyst Role

**After all specialists complete**, timeline-analyst:
1. Receives unified timeline (all artifacts merged chronologically)
2. Finds temporal clusters (3+ sources mentioning same entity within 10 seconds)
3. Applies corroboration logic to upgrade confidence
4. Produces final attack narrative with defensible conclusions

**Does NOT use hardcoded rules** - reasons from evidence using forensic training.
