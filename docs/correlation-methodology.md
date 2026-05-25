# Professional Forensic Correlation Methodology

**Source**: Synthesized from DFIR, Windows Prefetch Deep Dive, and Forensics-course1 training materials via reference

**Purpose**: Translate professional analyst workflows into agnostic correlation logic for SAVVYDFIR-MCP

---

## Core Principles from Professional Practice

### 1. **Artifacts Never Exist in Isolation**
> "Recovering a single forensic artifact is akin to reading a single isolated word in a sentence—its true meaning is only revealed through surrounding context."
> — DFIR

**Implication for Our Framework**: Individual specialist agents (mft-analyst, evtx-analyst, etc.) produce CLUES, not CONCLUSIONS. Timeline-analyst must synthesize.

---

### 2. **Temporal Proximity Analysis** (±5 Minute Windows)

Professional workflow:
1. **Establish a pivot point** - known suspicious event (IDS alert, suspicious executable, anomalous logon)
2. **Extract time slice** - ±5 minutes around pivot
3. **Merge all artifacts chronologically** - MFT, USN, EVTX, Prefetch, Registry, Amcache, ShimCache
4. **Observe the sequence** - artifacts don't appear magically; causality reveals attack flow

**Example Attack Sequence** (from DFIR):
```
14:32:00 | EVTX 4624  | Network logon (Type 3) from 192.168.1.50
14:32:01 | MFT        | malware.exe created (Modified time < Created time = copied over SMB)
14:32:15 | USN        | malware.exe FILE_CREATE
14:32:16 | Prefetch   | malware.exe.pf first run (run_count=1)
14:32:16 | EVTX 4688  | Process created PID 4732 (malware.exe)
14:32:18 | EVTX 5156  | PID 4732 network connection → 192.168.1.50:443
14:32:20 | Amcache    | malware.exe SHA1=a3f2... (LinkDate=2024-03-15, 1 year old)
14:32:30 | Registry   | Run key created → malware.exe persistence
```

**Key Insight**: 6 independent artifacts within 30 seconds = CONFIRMED attack sequence

**Our Implementation**: 
- `find_temporal_clusters(window_seconds=300)` for ±5 minute windows
- But also check ±10s, ±30s, ±60s sub-windows for tight correlations
- Tighter window = higher confidence

---

### 3. **Cross-Validation to Defeat Anti-Forensics**

Professional analysts **layer anomalies** to overcome artifact manipulation:

| Anti-Forensic Technique | Primary Artifact Compromised | Cross-Validation Method |
|-------------------------|----------------------------|------------------------|
| **Delete malware + Prefetch** | Prefetch, MFT | Check **ShimCache** (buffers in memory until reboot), **Amcache** (SHA-1 survives deletion) |
| **Timestomping** (backdate timestamps) | MFT $SI timestamps | Compare **$FN timestamp** (hidden), check **fractional seconds** (zeroes = manipulation), validate **USN Journal** (cannot be forged), check **ShimCache** modification time |
| **Clear EVTX logs** | Event logs | Extract from **Volume Shadow Snapshots** (pre-incident logs), check **EVTX 1102** (log cleared event) |
| **Delete staged exfil data** | MFT, files | Check **USN Journal** (rolling log of creates/deletes), **SRUM** (network bytes sent survive file deletion) |
| **Wipe Amcache** | Amcache execution records | Check **ShimCache** (overlapping but different cache), **Prefetch** (independent execution proof) |

**Our Implementation**:
- When MFT shows file but no Prefetch → check ShimCache + Amcache for deletion evidence
- When $SI timestamps = round numbers (00:00:00.000) → flag timestomping, validate with USN
- When Amcache missing but ShimCache present → flag Amcache clearing
- When EVTX 1102 found → trigger `analyze_vss` for shadow copy recovery

---

### 4. **Reliability Hierarchy: What Each Artifact Proves Alone**

From Prefetch Deep Dive:

| Artifact | What It Proves ALONE | What It CANNOT Prove | Needs Corroboration From |
|----------|---------------------|----------------------|-------------------------|
| **MFT** | File existed on disk, size, timestamps | Execution, user access, authenticity (timestamps can be forged) | Prefetch/EVTX (execution), USN (timestamp validation) |
| **USN Journal** | File operations sequence (create→modify→delete) | WHO caused the change, WHY | EVTX 4688 (process that caused change), MFT (file metadata) |
| **Prefetch** | File was executed (Prefetch = OS prepared to run it), last 8 run times, run count | Guaranteed execution (AV scan can create), user interaction, process success | EVTX 4688 (definitive execution), Amcache (hash), MFT (file exists) |
| **Amcache** | Binary existed, SHA-1 hash, compilation date | Execution (only proves observation), when it ran, run count | Prefetch (execution), EVTX 4688 (process creation) |
| **ShimCache** | Binary observed by Windows, path, size | Execution (observation ≠ execution), run time, run count | Prefetch (execution confirmation), Amcache (hash) |
| **EVTX 4688** | Process created, PID, parent PID, user, timestamp | File timestamps, complete timeline (gaps if audit policy disabled) | MFT/Prefetch/Amcache (file existence), Memory (validates process) |
| **SRUM** | Network bytes sent/received per process, deleted apps | Network destination IPs, execution proof, complete timeline (hourly aggregation) | EVTX 5156 (destination IPs), MFT/Amcache (binary exists) |
| **Registry** | Persistence mechanism configured, key LastWrite time | Execution, when specific value was set, binary exists | MFT/Amcache (binary exists), Prefetch (executed), EVTX 7045/4698 (service/task creation) |

**Observation vs Execution Hierarchy** (from Prefetch guide):

```
Observation Only:
- ShellBags → User navigated folder (GUI rendering)
- ShimCache → Executable visible in Explorer window (visual observation)
- Amcache → File scanned by Compatibility Appraiser (automated inventory)

Probable Execution:
- Prefetch → OS prepared to run it (run count, last run times, referenced files)

Definitive Execution:
- Prefetch + EVTX 4688 → Process created with matching timestamp
- Prefetch + EVTX 4688 + MFT → File exists + process created + timeline aligns
```

**Our Implementation**:
- **1 source = POSSIBLE** (observation, not proof)
- **2 sources = PROBABLE** (corroboration emerging)
- **3+ sources = CONFIRMED** (layered evidence defeats anti-forensics)

---

### 5. **Stacked Evidence and Filtering Layers**

Professional methodology (from Forensics-course1):

**"Having more will never hurt"** - collect all traces, then filter:

```python
# Layer 1: Collect ALL executables from MFT
executables = mft[mft['Path'].str.endswith('.exe')]

# Layer 2: Remove core OS binaries (System32, WinSxS)
executables = executables[~executables['Path'].str.contains('System32|WinSxS', case=False)]

# Layer 3: Remove digitally signed by trusted vendors (Microsoft, Intel, Dell)
# (Requires signature validation - not yet implemented)

# Layer 4: Cross-reference with Prefetch for execution proof
prefetch_paths = set(prefetch['Path'])
executed = executables[executables['Path'].isin(prefetch_paths)]

# Layer 5: Cross-reference with EVTX 4688 for process creation
evtx_processes = set(evtx[evtx['EventID'] == 4688]['NewProcessName'])
definitive_execution = executed[executed['Path'].isin(evtx_processes)]

# Result: Short list of CONFIRMED executed, non-standard binaries
```

**Our Implementation**:
- Don't hardcode filters (agnostic)
- Let Claude reason about "what stands out" after seeing the data
- But provide the CONCEPT of layering: "After seeing 1000 executables, 800 are System32, 150 are signed by Microsoft. Focus on the remaining 50."

---

### 6. **Defensible Timeline Construction** (Anti-Forensics Aware)

From Forensics-course1 and DFIR:

**Problem**: Standard timestamps ($SI) are fully writable; attackers backdate files

**Solution**: Use manipulation-resistant artifacts as anchors

| Artifact | Manipulation Resistance | Use Case |
|----------|------------------------|----------|
| **USN Journal** | Cannot be forged (sequential log with system clock) | Validate MFT timestamps, detect timestomping, track deletion sequences |
| **$FN Timestamp** (MFT) | Hidden from standard tools, not updated by SetFileTime API | Compare against $SI to detect timestomping |
| **Amcache LinkDate** | Pulled from PE header compilation timestamp (hard to forge without recompiling) | Detect staged malware (compiled months ago, first seen today) |
| **EVTX Timestamps** | Centralized log, tampering requires admin + log clearing (leaves 1102 event) | Trusted when no 1102 events found |
| **ShimCache Modification Time** | Cached when file first observed, independent of MFT | Cross-validate against MFT to detect backdating |

**Timestomping Detection Workflow**:

```python
# 1. Compare $SI vs $FN timestamps
timestomped = mft[mft['$SI_Modified'] != mft['$FN_Modified']]

# 2. Check for round timestamps (fractional seconds = 0)
timestomped |= mft[mft['$SI_Modified'].dt.microsecond == 0]

# 3. Cross-reference with USN Journal
# If MFT shows file created 2024-01-01 but USN shows FILE_CREATE 2026-05-15 → timestomped
usn_creates = usn[usn['Reason'].str.contains('FILE_CREATE')]
merged = mft.merge(usn_creates, on='FRN')
timestomped |= merged[merged['$FN_Birth'] < merged['USN_Timestamp'] - pd.Timedelta(days=1)]

# 4. Compare Amcache LinkDate with MFT birth
# Compiled 1 year ago but first seen today → staged attack
amcache_merged = mft.merge(amcache, on='Path')
staged = amcache_merged[
    amcache_merged['LinkDate'] < amcache_merged['$FN_Birth'] - pd.Timedelta(days=30)
]
```

**Our Implementation**:
- Run these checks in mft-analyst and amcache-analyst
- Flag findings as "TIMESTOMPED" or "STAGED"
- timeline-analyst sees these flags and adjusts confidence

---

### 7. **Super Timeline Workflow** (Plaso Equivalent)

Professional practice:
1. Parse all artifacts with Plaso (`log2timeline.py`)
2. Normalize timestamps to UTC
3. Merge into single chronological view
4. Filter to incident window (pivot ±5 minutes)
5. Observe causality sequences
6. Cross-validate anomalies

**Our Current Implementation**:
- `build_timeline()` creates unified Plaso timeline
- `query_timeline()` filters to specific windows
- timeline-analyst receives CSV with all sources merged

**Gap**: We don't have focused time-window queries yet. Need to add:

```python
def query_timeline_window(
    timeline_csv: str,
    pivot_time: str,  # "2026-05-15 14:32:00"
    window_minutes: int = 5
) -> pd.DataFrame:
    """Extract ±N minute window around pivot for focused analysis."""
    df = pd.read_csv(timeline_csv)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    pivot = pd.to_datetime(pivot_time)
    start = pivot - pd.Timedelta(minutes=window_minutes)
    end = pivot + pd.Timedelta(minutes=window_minutes)
    return df[df['timestamp'].between(start, end)].sort_values('timestamp')
```

---

### 8. **Agnostic Correlation Rules** (Our Framework)

Based on professional practice, our agnostic approach should:

#### Rule 1: Temporal Clustering
```python
# Group events by entity + time proximity
# Professional practice: ±5 minutes for incident window, ±10 seconds for causality
def find_execution_clusters(timeline_df):
    """
    Find tight temporal clusters indicating execution sequence.
    
    Professional pattern:
    - File creation → Execution → Network activity within 30 seconds
    """
    clusters = []
    for entity in timeline_df['entity'].unique():
        entity_events = timeline_df[timeline_df['entity'] == entity].sort_values('timestamp')
        
        # Check for execution sequence within 30-second window
        creates = entity_events[entity_events['event_type'].str.contains('CREATE|FILE_CREATE')]
        executions = entity_events[entity_events['event_type'].str.contains('Prefetch|4688')]
        network = entity_events[entity_events['event_type'].str.contains('5156|network')]
        
        if not creates.empty and not executions.empty:
            time_delta = (executions['timestamp'].min() - creates['timestamp'].min()).total_seconds()
            if time_delta < 30:  # Execution within 30s of creation
                cluster = {
                    'entity': entity,
                    'pattern': 'drop_and_execute',
                    'time_delta': time_delta,
                    'sources': entity_events['source'].unique().tolist(),
                    'confidence': 'CONFIRMED' if len(entity_events['source'].unique()) >= 3 else 'PROBABLE'
                }
                if not network.empty:
                    network_delta = (network['timestamp'].min() - executions['timestamp'].min()).total_seconds()
                    if network_delta < 5:  # C2 beacon within 5s
                        cluster['pattern'] = 'drop_execute_beacon'
                        cluster['c2_delta'] = network_delta
                clusters.append(cluster)
    
    return clusters
```

#### Rule 2: Anti-Forensics Detection
```python
def detect_anti_forensics(mft_df, usn_df, prefetch_df, shimcache_df, amcache_df):
    """
    Cross-validate artifacts to detect anti-forensic manipulation.
    
    Professional patterns:
    - File deleted but execution artifacts remain → cleanup attempt
    - Timestamps manipulated but USN contradicts → timestomping
    - Amcache cleared but ShimCache has entries → selective clearing
    """
    anomalies = []
    
    # Pattern 1: Orphaned Prefetch (deleted binary)
    prefetch_paths = set(prefetch_df['Path'])
    mft_paths = set(mft_df['Path'])
    orphaned = prefetch_paths - mft_paths
    if orphaned:
        anomalies.append({
            'pattern': 'deleted_after_execution',
            'evidence': list(orphaned),
            'confidence': 'CONFIRMED',
            'anti_forensics': True
        })
    
    # Pattern 2: Timestomping (round timestamps)
    timestomped = mft_df[
        (mft_df['$SI_Modified'].dt.microsecond == 0) |
        (mft_df['$SI_Modified'] != mft_df['$FN_Modified'])
    ]
    if not timestomped.empty:
        # Cross-validate with USN
        for idx, row in timestomped.iterrows():
            usn_entry = usn_df[usn_df['FRN'] == row['FRN']]
            if not usn_entry.empty:
                if row['$SI_Modified'] < usn_entry['Timestamp'].min():
                    anomalies.append({
                        'pattern': 'timestomping_confirmed',
                        'file': row['Path'],
                        'mft_time': row['$SI_Modified'],
                        'usn_time': usn_entry['Timestamp'].min(),
                        'confidence': 'CONFIRMED',
                        'anti_forensics': True
                    })
    
    # Pattern 3: ShimCache exists but Amcache missing
    shimcache_paths = set(shimcache_df['Path'])
    amcache_paths = set(amcache_df['Path'])
    missing_amcache = shimcache_paths - amcache_paths
    if missing_amcache:
        anomalies.append({
            'pattern': 'amcache_cleared',
            'evidence': list(missing_amcache),
            'confidence': 'PROBABLE',  # Could be normal for some files
            'anti_forensics': True
        })
    
    return anomalies
```

#### Rule 3: Execution Validation Hierarchy
```python
def validate_execution(file_path, artifacts_dict):
    """
    Apply reliability hierarchy to determine execution confidence.
    
    Professional hierarchy:
    - Observation only: ShellBags, ShimCache (visual), Amcache (automated scan)
    - Probable execution: Prefetch (run count, last run times)
    - Definitive execution: Prefetch + EVTX 4688 + temporal alignment
    """
    evidence = []
    
    # Check each artifact
    if file_path in artifacts_dict.get('shellbags', []):
        evidence.append(('observation', 'ShellBags'))
    
    if file_path in artifacts_dict.get('shimcache', []):
        evidence.append(('observation', 'ShimCache'))
    
    if file_path in artifacts_dict.get('amcache', []):
        evidence.append(('observation', 'Amcache'))
    
    if file_path in artifacts_dict.get('prefetch', []):
        prefetch_entry = artifacts_dict['prefetch'][file_path]
        if prefetch_entry['run_count'] > 0:
            evidence.append(('probable_execution', 'Prefetch'))
    
    if file_path in artifacts_dict.get('evtx_4688', []):
        evtx_entry = artifacts_dict['evtx_4688'][file_path]
        evidence.append(('definitive_execution', 'EVTX_4688'))
    
    # Determine confidence
    if any(level == 'definitive_execution' for level, _ in evidence):
        if len(evidence) >= 3:
            return 'CONFIRMED', evidence
        return 'PROBABLE', evidence
    elif any(level == 'probable_execution' for level, _ in evidence):
        if len(evidence) >= 2:
            return 'PROBABLE', evidence
        return 'POSSIBLE', evidence
    else:
        return 'OBSERVATION_ONLY', evidence
```

---

## Implementation Roadmap

### Phase 1: Enhanced Temporal Clustering ✅ (Already Implemented)
- `find_temporal_clusters(window_seconds=10)` in timeline-analyst
- Entity extraction across all artifacts
- Source counting for confidence scoring

### Phase 2: Anti-Forensics Detection Layer (NEW)
Add to specialists:
- **mft-analyst**: Timestomping detection ($SI vs $FN, fractional seconds)
- **amcache-analyst**: Staged malware detection (LinkDate vs MFT birth)
- **prefetch-analyst**: Orphaned prefetch detection (no MFT match)
- **registry-analyst + shimcache**: Cache consistency checks

### Phase 3: Execution Validation Hierarchy (NEW)
Add to correlation engine:
- Classify findings by observation vs execution
- Apply reliability hierarchy from Prefetch guide
- Upgrade confidence when multiple execution artifacts align

### Phase 4: Focused Timeline Windows (NEW)
Add to timeline tools:
- `query_timeline_window(pivot_time, window_minutes=5)`
- Pivot-based analysis (IDS alert, suspicious file, anomalous logon)
- Sub-window analysis (±10s for causality, ±5min for context)

### Phase 5: Cross-Validation Rules (NEW)
Add to timeline-analyst:
- Deletion detection (Prefetch without MFT)
- Timestomping validation (MFT vs USN vs ShimCache)
- Cache clearing detection (ShimCache vs Amcache gaps)
- Log clearing detection (EVTX 1102 → trigger VSS recovery)

---

## Key Takeaways for Our Framework

1. **Temporal proximity is king**: ±5 minutes for incident window, ±10 seconds for causality
2. **3+ sources = CONFIRMED**: Layered evidence defeats anti-forensics
3. **Observation ≠ Execution**: Use reliability hierarchy to avoid false positives
4. **USN Journal is truth**: Cannot be forged, validates timestamps
5. **Cross-validate everything**: One artifact alone proves nothing defensible
6. **Stack anomalies**: Layer filtering to make malicious activity obvious
7. **Pivot point analysis**: Start with known suspicious, extract time slice, observe sequence

**Claude's Role**: Apply these PATTERNS (not hardcoded rules) to reason about correlations. The clustering is mechanical, the interpretation is intelligent.

---

## 4. **Browser-Based C2 Detection and Correlation**

### Professional Pattern (from DFIR & Network Forensics)

**Beaconing Detection**:
- Fixed intervals (every N seconds) = automated C2
- Jitter (randomized ±X seconds) = evasion attempt
- DNS tunneling (high query volume, long subdomain labels, TXT records)
- HTTP/HTTPS on non-standard ports (not 80/443/8080)

**C2 Channel Identification**:
- Non-browser process communicating over 80/443 = suspicious
- Browser process on non-standard ports = suspicious
- Raw IP addresses (not DNS resolved) = infrastructure indicator
- Legitimate service abuse (Dropbox API, Pastebin, Google Docs)

**Framework Implementation**:
```python
# Memory scan_network + Browser history correlation
memory_conns = get_findings(artifact_type="network_connection")
browser_urls = get_findings(artifact_type="browser_history")

for conn in memory_conns:
    dest_ip = conn['destination_ip']
    dest_port = conn['destination_port']
    process = conn['process_name']
    
    # Check 1: Non-browser on web ports
    if dest_port in [80, 443, 8080] and 'chrome' not in process.lower() and 'firefox' not in process.lower():
        flag_as(confidence=0.90, reason="non_browser_web_traffic")
    
    # Check 2: Browser history correlation
    if process in ['chrome.exe', 'firefox.exe']:
        # Find matching URL in browser history within ±30 seconds
        matching_urls = [u for u in browser_urls if dest_ip in u['url'] and abs(u['timestamp'] - conn['timestamp']) < 30]
        if not matching_urls:
            flag_as(confidence=0.85, reason="network_connection_no_browser_history")
```

**SRUM Exfiltration Correlation**:
```python
# Correlate memory network connections with SRUM bytes_sent
srum_df = run_analysis(csv_path, "df[df['BytesSent'] > 100*1024*1024]")  # >100MB
for row in srum_df:
    process_name = row['ProcessName']
    bytes_sent = row['BytesSent']
    # Cross-reference with memory network connections
    matching_conns = [c for c in memory_conns if process_name in c['process_name']]
    if matching_conns:
        add_finding(f"{process_name} sent {bytes_sent/1e9:.2f}GB", confidence=0.95)
```

---

## 5. **LNK Files and Jump Lists: Proving File Access**

### Professional Pattern (from Prefetch Deep Dive)

**What LNK Files Prove**:
- User interaction: File was accessed via Explorer or Desktop shortcut
- Target metadata: File size, timestamps, volume serial, MAC address (DLT)
- Network activity: UNC paths track remote file access without local copy

**Jump Lists AppID Mapping**:
- AutomaticDestinations: System-generated recent files per app
- CustomDestinations: User-pinned files
- DestList stream: Entry number, pin status, hostname, full path

**Correlation Pattern: Defensible File Access Timeline**:
```
LNK created 14:32:01 → ShellBag 14:32:02 → RecentDocs 14:32:03 = USER ACCESSED FILE
```

**Framework Implementation**:
```python
# Three-source file access validation
lnk_files = get_findings(artifact_type="lnk_file")
shellbags = get_findings(artifact_type="shellbag")
recent_docs = get_findings(artifact_type="registry_recent")

for lnk in lnk_files:
    target_path = lnk['target_path']
    lnk_time = lnk['timestamp']
    
    # Find corroborating ShellBag within ±5 minutes
    shellbag_match = [s for s in shellbags if target_path in s['path'] and abs(s['timestamp'] - lnk_time) < 300]
    
    # Find corroborating RecentDocs
    recent_match = [r for r in recent_docs if target_path in r['path']]
    
    sources = 1 + len(shellbag_match) + len(recent_match)
    if sources >= 3:
        add_finding(f"Confirmed file access: {target_path}", confidence=1.00, corroborated_by=["lnk", "shellbag", "recentdocs"])
    elif sources == 2:
        add_finding(f"Probable file access: {target_path}", confidence=0.85)
```

**Anti-Forensics: Missing LNK for Expected Activity**:
- User claims "I never opened that file" but Prefetch + MFT show access = potential lie
- Expected LNK missing but ShellBag present = LNK was deleted

---

## 6. **VSS Recovery Workflows: Post-Incident Artifact Extraction**

### Professional Pattern (from DFIR VSS Module)

**VSS Structure**:
- Catalog file: Tracks active shadow copies (GUID + creation timestamp)
- Store files: 16KB copy-on-write chunks
- Creation triggers: Windows Update, app installs, System Restore, scheduled tasks

**Post-Event ID 1102 Recovery**:
```
Event ID 1102 detected at 2024-03-15T14:45:00Z
→ Check VSS creation timestamps: vss1=2024-03-14, vss2=2024-03-10
→ vss1 pre-dates log clearing by 1 day
→ Extract Security.evtx from vss1 → recover deleted events
```

**Framework Implementation**:
```python
# Detect Event ID 1102 (log clearing)
evtx_findings = get_findings(artifact_type="evtx_event")
log_cleared = [f for f in evtx_findings if "1102" in f['description']]

if log_cleared:
    clearing_time = log_cleared[0]['timestamp']
    
    # Check VSS availability
    vss_findings = get_findings(artifact_type="vss_snapshot")
    pre_clearing_vss = [v for v in vss_findings if v['created'] < clearing_time]
    
    if pre_clearing_vss:
        add_finding(
            f"Security.evtx cleared at {clearing_time}, but {len(pre_clearing_vss)} VSS snapshots pre-date clearing",
            confidence=1.00,
            recommended_action=f"Extract Security.evtx from VSS {pre_clearing_vss[0]['id']}"
        )
```

**Pre-Incident Baseline Comparison**:
- Extract registry hives from oldest VSS = clean baseline
- Compare current Run keys vs VSS Run keys = identify new persistence
- MFT comparison: files created after compromise but before VSS = staging window

**Temporal Analysis**:
- VSS creation timestamp vs incident timeline
- If VSS created during attack window = may contain attacker artifacts
- If VSS created before attack = clean baseline

---

## 7. **Ransomware-Specific Forensic Patterns**

### Professional Pattern (from DFIR Ransomware Module)

**Initial Infection Vector Correlation**:

**RDP Brute Force**:
```
Event ID 4625 (Failed Logon) × 100 within 60s → Type 3, Error 0xC000006A
Event ID 4624 (Successful) Type 10 → RDP session established
```

**Phishing Attachment**:
```
Zone.Identifier ADS → ReferrerUrl = phishing infrastructure
LNK file created (attachment opened) → Prefetch first run → Event ID 4688
```

**File Encryption Detection**:
```python
# USN Journal: DATA_OVERWRITE sequences
usn_df = run_analysis(usn_csv, "df[df['Reason'].str.contains('DATA_OVERWRITE')]")
overwrite_burst = usn_df.groupby(usn_df['Timestamp'].dt.floor('1min')).size()
if (overwrite_burst > 1000).any():
    add_finding("USN Journal shows 1000+ DATA_OVERWRITE in 1 minute - file encryption detected", confidence=1.00)

# MFT: Rapid modification timestamps
mft_df = run_analysis(mft_csv, "df[df['$SI_Modified'] > '2024-03-15T14:00:00']")
rapid_mods = mft_df.groupby(mft_df['$SI_Modified'].dt.floor('1s')).size()
if (rapid_mods > 100).any():
    add_finding("MFT shows 100+ file modifications per second - encryption in progress", confidence=0.95)
```

**Shadow Copy Deletion Detection**:
```
Event ID 4688: vssadmin.exe delete shadows /all
VSS Service Event IDs: Store deletion confirmations
Registry: VSS key modifications
```

**Exfiltration Before Encryption**:
```python
# SRUM: Bytes sent spike before encryption timestamp
srum_df = run_analysis(srum_csv, "df.sort_values('Timestamp')")
# Find spike >10GB within 1 hour before encryption
encryption_time = get_encryption_timestamp()
pre_encryption = srum_df[srum_df['Timestamp'] < encryption_time]
exfil_window = pre_encryption[pre_encryption['Timestamp'] > (encryption_time - timedelta(hours=1))]
total_sent = exfil_window['BytesSent'].sum()
if total_sent > 10*1024**3:
    add_finding(f"SRUM shows {total_sent/1e9:.2f}GB sent in 1h before encryption - data exfiltration", confidence=0.95)
```

---

## 8. **Email Phishing Correlation: Patient Zero Identification**

### Professional Pattern (from DFIR Email Forensics)

**Zone.Identifier ADS: Attachment Download Proof**:
- `ReferrerUrl`: Email client or webmail URL
- `HostUrl`: Attachment staging server (attacker infrastructure)
- `ZoneId=3`: Internet zone = downloaded from web
- `ZoneId=4`: Restricted sites = blocked but user bypassed

**Correlation Chain**:
```
1. Email received (PST/OST timestamp or webmail browser history)
2. Attachment opened (LNK file creation = user double-clicked)
3. Prefetch first execution (run_count=1, FirstRun timestamp)
4. Event ID 4688 process creation (proves execution)
5. Network connection within ±10s (C2 beacon)
```

**Framework Implementation**:
```python
# Find Zone.Identifier artifacts
zone_id_findings = get_findings(artifact_type="zone_identifier")

for zone in zone_id_findings:
    file_path = zone['file_path']
    download_time = zone['timestamp']
    referrer_url = zone.get('ReferrerUrl', '')
    host_url = zone.get('HostUrl', '')
    
    # Find corresponding Prefetch within ±5 minutes
    prefetch_findings = get_findings(artifact_type="prefetch_entry")
    matching_prefetch = [p for p in prefetch_findings if file_path in p['executable_path'] and abs(p['FirstRun'] - download_time) < 300]
    
    # Find Event ID 4688 within ±10 seconds of Prefetch
    if matching_prefetch:
        prefetch_time = matching_prefetch[0]['FirstRun']
        evtx_findings = get_findings(artifact_type="evtx_event")
        matching_evtx = [e for e in evtx_findings if "4688" in e['event_id'] and abs(e['timestamp'] - prefetch_time) < 10]
        
        if matching_evtx:
            add_finding(
                f"Phishing attack confirmed: {file_path} downloaded from {host_url}, executed at {prefetch_time}",
                confidence=1.00,
                attack_vector="phishing",
                corroborated_by=["zone_identifier", "prefetch", "evtx_4688"]
            )
```

**Patient Zero**: Earliest email delivery timestamp with matching execution chain.

---

## 9. **Cloud Storage Exfiltration Detection**

### Professional Pattern (from Network Forensics)

**Sync Client Artifacts**:
- OneDrive: `sync_diagnostics_*.log`, SQLite databases
- Dropbox: `.dropbox.cache`, `sync_history.db`
- Google Drive: `sync_config.db`, `snapshot.db`

**Correlation Pattern**:
```python
# Browser history: Cloud service access
browser_urls = get_findings(artifact_type="browser_history")
cloud_domains = ['dropbox.com', 'onedrive.live.com', 'drive.google.com']
cloud_access = [u for u in browser_urls if any(d in u['url'] for d in cloud_domains)]

# SRUM: Bytes sent to cloud domains
srum_df = run_analysis(srum_csv, "df[df['ProcessName'].str.contains('dropbox|onedrive|googledrivesync', case=False)]")
cloud_transfers = srum_df[srum_df['BytesSent'] > 100*1024*1024]  # >100MB

# Temporal correlation: Access + transfer within ±1 hour
for transfer in cloud_transfers:
    transfer_time = transfer['Timestamp']
    matching_access = [a for a in cloud_access if abs(a['timestamp'] - transfer_time) < 3600]
    
    if matching_access:
        add_finding(
            f"{transfer['ProcessName']} uploaded {transfer['BytesSent']/1e9:.2f}GB via {matching_access[0]['url']}",
            confidence=0.90,
            exfiltration_method="cloud_storage"
        )
```

**Large Uploads Outside Business Hours**:
```python
# Flag uploads >1GB between 6pm-6am
for transfer in cloud_transfers:
    hour = transfer['Timestamp'].hour
    if (hour < 6 or hour >= 18) and transfer['BytesSent'] > 1*1024**3:
        add_finding(f"Off-hours cloud upload: {transfer['BytesSent']/1e9:.2f}GB at {transfer['Timestamp']}", confidence=0.85)
```

---

## 10. **Malware IOC Correlation Across Hosts**

### Professional Pattern (from Malware Analysis Integration)

**Hash Correlation (Renamed Malware)**:
```python
# Amcache SHA-1 tracking across different filenames
amcache_findings = get_findings(artifact_type="amcache_entry")
hash_groups = {}
for finding in amcache_findings:
    sha1 = finding.get('SHA1', '')
    if sha1:
        hash_groups.setdefault(sha1, []).append(finding)

# Flag same hash, different paths = renamed malware
for sha1, findings in hash_groups.items():
    if len(findings) > 1:
        paths = [f['file_path'] for f in findings]
        add_finding(
            f"Same binary (SHA1={sha1[:8]}) observed at {len(paths)} different paths - renamed malware indicator",
            paths=paths,
            confidence=0.95,
            ioc_type="renamed_malware"
        )
```

**PE Metadata Linking**:
```python
# Compile timestamp correlation
amcache_df = run_analysis(amcache_csv, "df[['FilePath', 'LinkDate', 'FileSize']].drop_duplicates()")
mft_df = run_analysis(mft_csv, "df[['FullPath', '$FN_Birth']].drop_duplicates()")

# Staged malware: LinkDate << $FN_Birth (compiled months before deployment)
merged = amcache_df.merge(mft_df, left_on='FilePath', right_on='FullPath')
merged['days_diff'] = (merged['$FN_Birth'] - merged['LinkDate']).dt.days
staged = merged[merged['days_diff'] > 30]

for row in staged.itertuples():
    add_finding(
        f"Staged malware: {row.FilePath} compiled {row.days_diff} days before appearing on system",
        confidence=0.90,
        technique="pre_compiled_campaign"
    )
```

**Config Extraction (C2 Domains)**:
```python
# Extract domains from malware strings analysis
# Correlate with memory network connections
malware_domains = extract_domains_from_strings(malware_path)
memory_conns = get_findings(artifact_type="network_connection")

for domain in malware_domains:
    matching_conns = [c for c in memory_conns if domain in c.get('destination', '')]
    if matching_conns:
        add_finding(
            f"C2 domain {domain} extracted from malware and observed in memory network connections",
            confidence=1.00,
            ioc_type="c2_infrastructure"
        )
```

---

## 11. **Comprehensive Anti-Forensics Detection Matrix**

### Timestomping Detection (Multi-Source Validation)

**Layer 1: MFT $SI vs $FN**:
```python
mft_df = run_analysis(mft_csv, "df[df['$SI_Modified'] < df['$FN_Modified']]")
# SI can be user-modified, FN is kernel-only
```

**Layer 2: Fractional Seconds Zeroing**:
```python
mft_df = run_analysis(mft_csv, "df[df['$SI_Modified'].dt.microsecond == 0]")
# Natural timestamps have 100-nanosecond resolution
```

**Layer 3: PE Compile Time vs MFT**:
```python
# Amcache LinkDate > MFT $SI_Created = backdated
amcache_df = run_analysis(amcache_csv, "df[['FilePath', 'LinkDate']]")
mft_df = run_analysis(mft_csv, "df[['FullPath', '$SI_Created']]")
merged = amcache_df.merge(mft_df, left_on='FilePath', right_on='FullPath')
backdated = merged[merged['LinkDate'] > merged['$SI_Created']]
```

**Layer 4: USN Journal as Truth Anchor**:
```python
# USN timestamps cannot be forged - compare with MFT
# If MFT != USN by >1 hour = timestomping confirmed
```

### Log Manipulation Detection

**Event ID 1102: Security Log Cleared**:
- All-or-nothing action (cannot selectively delete)
- Requires admin rights
- Triggers VSS recovery workflow

**Audit Policy Tampering (Event ID 4719)**:
- Disabling specific event categories
- Correlate with suspicious activity windows

**Selective Event Deletion**:
- Gaps in Event ID sequences (4624/4625 bursts with missing IDs)
- Timeline correlation: missing events during known attack window

### Artifact Deletion Patterns

**Orphaned Prefetch**:
```python
prefetch_paths = set(get_findings(artifact_type="prefetch_entry")['executable_path'])
mft_paths = set(get_findings(artifact_type="mft_entry")['FullPath'])
orphaned = prefetch_paths - mft_paths
# Prefetch exists but binary deleted from MFT
```

**ShimCache Present, Amcache Missing**:
- ShimCache buffers in memory → persists across reboots
- Amcache writes to disk → can be cleared
- Gap = selective cache clearing

### Process Hiding (DKOM)

**Memory Process vs Disk Artifacts**:
```python
# Process in memory but no Prefetch/Amcache/MFT = injected or DKOM
memory_processes = get_findings(artifact_type="memory_process")
disk_executables = get_all_disk_executable_paths()
hidden = [p for p in memory_processes if p['image_path'] not in disk_executables]
```

**EPROCESS Unlinking**:
- Process in `psscan` but not `pslist` = DKOM rootkit
- PEB manipulation: Fake process name in PEB vs real name in EPROCESS

---

## 12. **Real-World Attack Sequence Reconstruction**

### Multi-Stage Intrusion Timeline (from IR Case Studies)

**Kill Chain Phases with Forensic Indicators**:

**1. Reconnaissance (TA0043)**:
```
Days -7 to -1: Network scanning, OSINT gathering
Indicators:
- Network flows: Port scans, service enumeration
- SIEM: Failed auth attempts from recon IPs
Forensic gap: Often external, no host artifacts
```

**2. Initial Access (TA0001)**:
```
Day 0, 09:15:00: Phishing email delivered
Day 0, 09:47:23: User opens malicious attachment
Indicators:
- PST/OST: Email delivery timestamp
- Zone.Identifier: Attachment download
- LNK: Attachment opened (user double-click)
- Prefetch: First execution (run_count=1)
- Event ID 4688: Process creation
```

**3. Execution (TA0002)**:
```
Day 0, 09:47:25: Malware executes, establishes C2
Indicators:
- Memory: Process in memory, network connection
- EVTX 5156: Network connection to C2 IP
- Registry: Autostart persistence created
- Amcache: SHA-1 hash recorded
```

**4. Credential Access (TA0006)**:
```
Day 0, 10:15:00: LSASS memory dump
Indicators:
- Event ID 4656: Object access (LSASS.exe)
- Event ID 4663: Object read
- Sysmon 10: Process access (SourceImage → LSASS)
- Memory: Mimikatz strings, credential structures
```

**5. Lateral Movement (TA0008)**:
```
Day 0, 14:32:00: PsExec to DC01
Indicators:
- Event ID 4624 Type 3: Network logon from WKSTN01
- Event ID 4672: Special privileges assigned
- Event ID 7045: Service installation (PSEXESVC)
- Event ID 5140: Share access (\\DC01\ADMIN$)
- MFT: malware.exe M timestamp < B timestamp (SMB copy)
```

**6. Exfiltration (TA0010)**:
```
Day 2, 02:00:00: Data exfiltration via cloud
Indicators:
- SRUM: 50GB sent via onedrive.exe
- Browser history: OneDrive access at 01:58:00
- Network connections: TLS to onedrive.live.com
- Off-hours activity (2am) = automated exfiltration
```

**7. Impact (TA0040)**:
```
Day 2, 03:00:00: Ransomware encryption
Indicators:
- Event ID 4688: vssadmin.exe delete shadows /all
- USN Journal: 10,000+ DATA_OVERWRITE per minute
- MFT: 5,000+ file modifications per second
- Ransom note creation timestamp
```

### Dwell Time Calculation

```python
initial_compromise = datetime.fromisoformat("2024-03-15T09:47:23Z")
detection_time = datetime.fromisoformat("2024-03-17T08:15:00Z")
dwell_time = (detection_time - initial_compromise).total_seconds() / 3600
# 46.5 hours dwell time
```

**Breakout Time** (eCrime median: 62 minutes):
```python
initial_access = datetime.fromisoformat("2024-03-15T09:47:23Z")
lateral_movement = datetime.fromisoformat("2024-03-15T14:32:00Z")
breakout_time = (lateral_movement - initial_access).total_seconds() / 60
# 285 minutes = 4h 45m (slower than median)
```

---

## Summary: Professional Workflow Integration

**The Framework NOW Implements**:

1. ✅ **Execution Validation Hierarchy** (semantics.py)
2. ✅ **10 Correlation Checks** (correlation.py) - including 4 new anti-forensics checks
3. ✅ **Temporal Clustering** (correlation.py) - ±5 min windows, multi-source bursts
4. ✅ **Browser C2 Detection** - Memory + SRUM + Browser history correlation
5. ✅ **LNK/Jump Lists** - Three-source file access validation
6. ✅ **VSS Recovery** - Post-1102 log recovery workflows
7. ✅ **Ransomware Patterns** - USN bursts, Shadow copy deletion, SRUM exfiltration
8. ✅ **Phishing Correlation** - Zone.Identifier → LNK → Prefetch → EVTX chain
9. ✅ **Cloud Exfiltration** - SRUM + browser + off-hours detection
10. ✅ **Malware IOC Tracking** - Hash correlation, PE metadata, config extraction
11. ✅ **Anti-Forensics Matrix** - Timestomping, log manipulation, artifact deletion
12. ✅ **Attack Sequence Reconstruction** - Multi-stage timeline, dwell time, breakout time

**All patterns are AGNOSTIC** - work across any Windows investigation, no hardcoded IOCs.
