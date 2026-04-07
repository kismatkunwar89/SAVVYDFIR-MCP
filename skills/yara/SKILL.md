# YARA Scanning Reference

**Load when:** Performing signature-based scanning during Phase 5 enrichment or on-demand.

---

## Scan Disk Files

```bash
# Scan a directory recursively
yara -r /opt/SAVVYDFIR-MCP/yara-rules/malware.yar /mnt/disk/

# Scan a specific file
yara /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar /mnt/disk/Windows/Temp/suspicious.exe

# Scan with all rules in a directory
yara -r /opt/SAVVYDFIR-MCP/yara-rules/ /mnt/disk/Users/

# Show matching strings (verbose)
yara -r -s /opt/SAVVYDFIR-MCP/yara-rules/malware.yar /mnt/disk/
```

---

## Scan Memory Dump

### Direct YARA scan on raw dump
```bash
yara /opt/SAVVYDFIR-MCP/yara-rules/malware.yar /evidence/memory/dump.raw
```

### Via Volatility 3 (process-aware scanning)
```bash
vol3 -f /evidence/memory/dump.raw yarascan.YaraScan --yara-file /opt/SAVVYDFIR-MCP/yara-rules/malware.yar
```
Volatility YARA scan provides process context (PID, process name) for each match.

### Scan specific process memory
```bash
vol3 -f /evidence/memory/dump.raw yarascan.YaraScan --yara-file /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar --pid 1284
```

---

## Key Rule Categories

| Category | Detects | Typical Location |
|---|---|---|
| Cobalt Strike | Beacon config, malleable C2, reflective loader | Memory, temp files |
| Meterpreter | Staged/stageless payloads, migrate stubs | Memory, dropped files |
| Process Injection | Shellcode patterns, NtCreateThread stubs | Memory regions (malfind) |
| Credential Theft | Mimikatz strings, lsass dump patterns | Memory, disk |
| Webshells | PHP/ASP/JSP webshell patterns | Web root directories |
| Ransomware | Encryption routines, ransom note patterns | Disk, memory |
| Persistence | Scheduled task XML, service DLL patterns | Registry exports, disk |

---

## Rule Locations on SIFT

```
/opt/SAVVYDFIR-MCP/yara-rules/          # Project-specific rules
/opt/yara-rules/                          # System-wide rules (if installed)
/usr/share/yara/                          # Package-provided rules
```

---

## Interpreting Results

### Match output format
```
RuleName  /path/to/matched/file
```

### With -s flag (string matches)
```
RuleName  /path/to/file
0x1a4:$beacon_config: { 00 01 00 01 00 02 ... }
0x2f0:$sleep_mask: { 48 89 5C 24 08 ... }
```

### Cross-referencing YARA hits
1. YARA hit on disk file: check Prefetch/Amcache for execution evidence
2. YARA hit in memory: correlate PID with `vol3 windows.pslist` output
3. YARA hit + malfind region: strong indicator of active injection — classify as OBSERVATION if artifact_path + offset are available
