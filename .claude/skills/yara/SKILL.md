---
name: yara
description: Load when performing YARA signature scanning on disk images, memory dumps, or extracted files. Covers Cobalt Strike detection, process injection signatures, and custom rule creation.
allowed-tools:
  - Bash
---

# YARA Scanning Reference

## Disk Scanning
```bash
# Scan entire mounted filesystem:
yara -r /opt/SAVVYDFIR-MCP/yara-rules/all.yar /mnt/disk/ 2>/dev/null

# Scan specific directory:
yara -r /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar /mnt/disk/Windows/System32/

# Scan extracted file:
yara /opt/SAVVYDFIR-MCP/yara-rules/all.yar /cases/extracted_file

# Show matching strings (verbose):
yara -r -s /opt/SAVVYDFIR-MCP/yara-rules/malware.yar /mnt/disk/
```

## Memory Scanning via Volatility
```bash
vol3 -f /evidence/memory/extracted/dump.raw \
  yarascan.YaraScan \
  --yara-file /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar

# Scan specific process:
vol3 -f /evidence/memory/extracted/dump.raw \
  yarascan.YaraScan \
  --yara-file /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar --pid PID
```

## Direct Memory Scan
```bash
yara /opt/SAVVYDFIR-MCP/yara-rules/malware.yar /evidence/memory/extracted/dump.raw
```

## Key YARA Rule Categories
| Category | Detects |
|---|---|
| Cobalt Strike | Beacon config, malleable C2, reflective loader |
| Meterpreter | Staged/stageless payloads, migrate stubs |
| Process Injection | Shellcode patterns, NtCreateThread stubs |
| Credential Theft | Mimikatz strings, lsass dump patterns |
| Webshells | PHP/ASP/JSP webshell patterns |
| Ransomware | Encryption routines, ransom note patterns |
| Persistence | Scheduled task XML, service DLL patterns |

## Rule Locations
```
/opt/SAVVYDFIR-MCP/yara-rules/   # Project-specific rules
/opt/yara-rules/                   # System-wide rules (if installed)
```

## Cross-Reference YARA Hits
1. YARA hit on disk file: check Prefetch/Amcache for execution evidence
2. YARA hit in memory: correlate PID with `vol3 windows.pslist` output
3. YARA hit + malfind region: strong indicator — classify as OBSERVATION if artifact_path + offset available

## Ralph Wiggum Loop
If yara returns permission errors: add `2>/dev/null` to suppress access denied on system files
If no rules directory: check `/opt/SAVVYDFIR-MCP/yara-rules/` exists
If vol3 yarascan fails: ensure memory dump is extracted from ZIP first
