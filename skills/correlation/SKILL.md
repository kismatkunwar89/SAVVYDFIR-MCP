# Cross-Artifact Correlation Methodology

**Skill file for:** Interpreting the results of `correlation.compare_disk_and_memory()` and the 6 specific correlation checks it performs.
**Load when:** Entering Phase 4 (Correlation) of any triage, or when interpreting a DiscrepancyAlert.

---

## Overview

Cross-artifact correlation is SAVVYDFIR-MCP's novel contribution. Where single-artifact analysis misses approximately 36% of forensic indicators, two-source fusion (disk + memory) raises detection coverage to 63.6% (SynthChain, Zenodo 2026).

The `compare_disk_and_memory()` tool runs 6 specific checks that are individually documented below. Each check identifies a class of attacker behavior that is invisible when analyzing either disk or memory in isolation.

---

## Running Correlation

```python
# Single call — runs all 6 checks automatically
result = await correlation.compare_disk_and_memory(case_id=<case_id>)
```

The tool reads the current `CaseState` (all prior disk and memory findings) and returns a `CorrelationReport` containing:
- `discrepancies: list[DiscrepancyAlert]` — one per detected anomaly
- `summary_stats: dict` — counts by check type and severity
- `recommended_followup: list[str]` — ordered list of tools to run next

**Prerequisite:** Phases 2 and 3 must be complete. The correlation engine reads from disk and memory findings already recorded in the case state.

---

## The 6 Correlation Checks

### Check 1 — Process in Memory with No Disk Binary

**What it detects:** Fileless malware that runs entirely in memory without a corresponding executable file on disk.

**How it works:**
- For each process in `processes.json` (`memory.list_processes()` output), attempt to resolve the process image path to a file on the disk image.
- Flag any process where the declared image path does not resolve to a readable, intact file on disk.

**Forensic significance:** Legitimate Windows processes always have a backing binary on disk. A process running from a path that does not exist on disk is strong evidence of:
- Fileless malware injection (e.g., PowerShell `Invoke-Shellcode`)
- Process hollowing (legitimate process started, then its memory replaced with malicious code)
- Reflective DLL injection

**Classification guidance:**

| Evidence | Classification |
|---|---|
| Process has no disk binary + no Prefetch entry | OBSERVATION (fileless — no execution trace on disk) |
| Process has no disk binary + Prefetch entry exists | INFERENCE (binary was deleted post-execution) — see Check 2 |
| Process has no disk binary but is a known-benign memfd/anonymous mapping | HYPOTHESIS (may be benign) — requires YARA confirmation |

**Required follow-up:**
- `disk.list_deleted_files()` — check if the binary was recently deleted
- `disk.extract_prefetch()` — check if execution was logged before deletion
- `yara.scan_memory(pid=<pid>)` — confirm malicious code in the memory region

---

### Check 2 — Prefetch / Amcache Entry for a Deleted Binary

**What it detects:** Evidence that a malicious binary was executed and then deleted to evade detection (post-exploitation cleanup).

**How it works:**
- For each Prefetch entry in `prefetch.csv` and each Amcache entry in `amcache.csv`, check whether the referenced executable path exists on the current disk image.
- Flag any entry where the execution artifact exists (Prefetch/Amcache) but the binary does not.

**Forensic significance:** Prefetch and Amcache record execution evidence independently of the file system. Attackers who delete their tools after use cannot retroactively remove these records without specialized anti-forensic techniques.

**Classification guidance:**

| Evidence | Classification |
|---|---|
| Prefetch entry + binary missing + MFT shows deletion in relevant time window | OBSERVATION (execution + cleanup confirmed) |
| Prefetch entry + binary missing + no MFT deletion record | INFERENCE (binary deleted, MFT record reused — less precise timing) |
| Amcache SHA1 entry + binary missing | INFERENCE (hash preserves identity even without file) |
| Prefetch entry + binary in wrong location vs. declared path | HYPOTHESIS (possible path hijacking) |

**Required follow-up:**
- `disk.extract_mft_timeline()` — find the deletion timestamp
- `disk.list_deleted_files()` — attempt to carve or identify the deleted binary by name
- `timeline.query_timeline()` — build full event sequence around the deletion time

---

### Check 3 — VAD Anomaly on a Legitimate Process Path

**What it detects:** Code injection or process hollowing into a legitimate Windows process (svchost.exe, explorer.exe, lsass.exe, etc.).

**How it works:**
- For each process flagged by `memory.detect_injection()` (malfind results), cross-reference the process name against the list of known-legitimate system processes.
- A VAD anomaly (Virtual Address Descriptor with `PAGE_EXECUTE_READWRITE` permissions, or a private region at an address normally occupied by a system DLL) on a legitimate process path indicates injection.

**The three VAD anomaly types:**

| Anomaly | Description | Typical Technique |
|---|---|---|
| `PAGE_EXECUTE_READWRITE` private region | Memory that is writable AND executable — unnecessary for legitimate code | Shellcode injection, reflective loader |
| Executable anonymous mapping | No backing file but marked executable | Fileless shellcode |
| Section mismatch | DLL in VAD list does not match on-disk DLL (different size or PE headers) | DLL hollowing or side-loading |

**Forensic significance:** `PAGE_EXECUTE_READWRITE` regions are a strong indicator of active shellcode. Legitimate DLLs are almost always loaded as `PAGE_EXECUTE_READ` (not writable).

**Classification guidance:**

| Evidence | Classification |
|---|---|
| `PAGE_EXECUTE_READWRITE` VAD + YARA hit in that region | OBSERVATION (confirmed malicious code in process memory) |
| `PAGE_EXECUTE_READWRITE` VAD + no YARA hit + process is svchost.exe | HYPOTHESIS (strong indicator but not confirmed) |
| Section mismatch (hollowed DLL) | INFERENCE if ≥2 observations (VAD + PE header mismatch) support it |
| `PAGE_EXECUTE_READWRITE` VAD on `java.exe` or browser processes | HYPOTHESIS (may be JIT compilation — benign) |

**Required follow-up:**
- `memory.list_dlls(pid=<pid>)` — enumerate all loaded modules; check for unsigned or out-of-place DLLs
- `yara.scan_memory(pid=<pid>, rule_set=["shellcode_generic", "cobalt_strike", "meterpreter"])` — identify payload

---

### Check 4 — Network Connection with No Disk Artifact

**What it detects:** Fileless command-and-control (C2) — a network connection originating from a process that has no corresponding binary on disk and no disk-based execution trace.

**How it works:**
- For each network connection in `network_connections.json` (from `memory.scan_network()`), identify the originating PID.
- Cross-reference the PID's image path against disk artifacts (binary existence, Prefetch, Amcache).
- Flag connections where the originating process has no disk artifact trail.

**Forensic significance:** Legitimate network connections are always traceable to a disk-resident binary (browser, OS component, installed application). A connection from a process with no disk trace is a high-fidelity indicator of fileless malware.

**Classification guidance:**

| Evidence | Classification |
|---|---|
| External IP connection + originating process has no disk binary + no Prefetch | OBSERVATION (fileless C2 confirmed if external IP is non-Microsoft/non-CDN) |
| External IP connection + binary deleted (Prefetch exists, binary missing) | INFERENCE (C2 tool deleted post-execution but connection was established) |
| External IP connection + legitimate process (e.g., lsass.exe) | OBSERVATION if process is also flagged with VAD anomaly (Check 3 compound) |
| Internal IP connection + no disk artifact | HYPOTHESIS (may be lateral movement; requires network topology context) |

**Required follow-up:**
- Check `manifest.json` network topology — is the destination IP an internal trusted host?
- `disk.extract_registry_run_keys()` — persistence mechanism for reconnection
- `timeline.query_timeline()` — when did the connection first appear relative to other suspicious events?

---

### Check 5 — Registry Persistence Key for a Missing Binary

**What it detects:** Evidence that a malware binary was installed with registry persistence (Run/RunOnce keys) and subsequently removed — the classic "cleaned malware" pattern.

**How it works:**
- For each registry persistence entry in `registry_run_keys.csv` (from `disk.extract_registry_run_keys()`), attempt to resolve the target executable path against the current disk image.
- Flag any persistence key that points to a path where no file currently exists.

**Forensic significance:** Attackers who remove their binaries often forget to also clean the registry Run keys. This is a reliable indicator of past presence. Even if the binary is gone, the key preserves the intended persistence path and often the binary name.

**The key locations to check:**

| Location | Key |
|---|---|
| User startup (all users) | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| User startup (current user) | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| One-time startup | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` |
| Service entries | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` |
| Scheduled tasks | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` |

**Classification guidance:**

| Evidence | Classification |
|---|---|
| Run key pointing to non-existent path + Prefetch entry for that binary | OBSERVATION (execution + persistence + cleanup confirmed) |
| Run key pointing to non-existent path + no Prefetch | INFERENCE (persistence installed, execution timing unknown) |
| Run key pointing to non-existent path + binary name matches known malware family | HYPOTHESIS (requires hash or YARA confirmation) |
| Run key with suspicious name (random characters, typosquat of system binary) but binary exists | HYPOTHESIS (binary present — classify after Check 1) |

**Required follow-up:**
- `disk.extract_prefetch()` — confirm the binary was executed
- `disk.extract_mft_timeline()` — find when the binary was deleted
- `disk.list_deleted_files()` — attempt to recover binary from unallocated space

---

### Check 6 — Standard Information vs. Filename Timestamp Mismatch (Timestomping Detection)

**What it detects:** Timestomping — an attacker technique that modifies the `$STANDARD_INFORMATION` (SI) attribute timestamps of a file to blend in with legitimate system files, while the `$FILE_NAME` (FN) attribute timestamps (which are harder to modify) reveal the true creation time.

**How it works:**
- For each file in `mft_timeline.csv` where the SI `$Created` timestamp is significantly earlier than the FN `$Created` timestamp (threshold: typically >1 hour difference), flag as a timestomping candidate.
- SI timestamps are trivially modified by `SetFileTime()` and similar APIs. FN timestamps are updated by the NTFS kernel and are not accessible to `SetFileTime()`.

**The timestamp attributes:**

| Attribute | Contains | Can be modified by attacker? |
|---|---|---|
| `$STANDARD_INFORMATION ($SI)` | Created, Modified, Accessed, MFT Modified | Yes — via `SetFileTime()`, `timestomp`, `Metasploit` |
| `$FILE_NAME ($FN)` | Created, Modified, Accessed, MFT Modified | No — set by NTFS kernel only |

**Typical patterns:**

| Pattern | Interpretation |
|---|---|
| SI Created = 2008-01-01, FN Created = 2026-04-30 | File was backdated — timestomped |
| SI Modified earlier than SI Created | Impossible naturally — certain indicator of manipulation |
| SI timestamps cluster on a round value (00:00:00.000) | Automated timestomping tool (Metasploit `timestomp` resets to 01/01/1970) |
| SI and FN differ by exactly the local UTC offset | Timezone confusion artifact — may be benign |

**Classification guidance:**

| Evidence | Classification |
|---|---|
| SI Created significantly earlier than FN Created + file is executable + suspicious process ran from that path | OBSERVATION (timestomping confirmed with corroborating execution trace) |
| SI Created significantly earlier than FN Created alone | HYPOTHESIS (timestomping likely; requires execution trace to confirm malicious intent) |
| SI Modified before SI Created | OBSERVATION (impossible without manipulation — independent of other evidence) |
| Round SI timestamp (1970 / 1601) | OBSERVATION of tool-based timestomping |

**Required follow-up:**
- `timeline.query_timeline()` — search for FN timestamp cluster around the true creation time
- `disk.extract_prefetch()` — confirm the binary was executed despite its backdated timestamp
- `disk.get_amcache()` — Amcache records its own timestamps independently of MFT

---

## Compound Analysis (Multi-Check Correlation)

Single-check hits are investigate-worthy. Multi-check hits on the same artifact are high-confidence.

| Combination | Confidence | Likely Technique |
|---|---|---|
| Check 1 + Check 3 (no disk binary + VAD anomaly on a process) | Very High | Process hollowing or reflective injection |
| Check 2 + Check 5 (deleted binary + registry persistence key) | Very High | Installed malware, persistence, then cleanup |
| Check 3 + Check 4 (VAD anomaly + network from injected process) | Very High | Active C2 beacon running in injected memory |
| Check 1 + Check 4 (no disk binary + network connection) | Very High | Fileless C2 |
| Check 6 + Check 2 (timestomping + deleted binary) | High | Staged attack with anti-forensic cleanup |
| Any single check + YARA hit | High | Confirmed known-bad signature in the flagged artifact |
| Any 2+ checks on the same PID | Strong | The process is very likely compromised |

---

## Summary Decision Table

| Discrepancy Count (same PID/artifact) | Recommended Action |
|---|---|
| 0 | No compromise indicator from correlation. Proceed to Phase 5 enrichment on other suspicious artifacts. |
| 1 | Investigate thoroughly. Run recommended_followup. May be benign — document findings. |
| 2+ | Strong compromise indicator. Treat as INFERENCE. Run all enrichment tools. |
| Any + YARA hit | High-confidence. Elevate to OBSERVATION once artifact_path + offset are confirmed. |
