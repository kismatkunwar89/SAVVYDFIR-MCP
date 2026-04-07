---
name: memory-forensics
description: Load when analyzing memory dumps, process lists, network connections, code injection, credential theft, or any Volatility 3 analysis. Covers Windows memory forensics from ZIP extraction to IOC identification.
allowed-tools:
  - Bash
---

# Memory Forensics — Volatility 3 Reference

## Step 1: Extract Memory Dump (if ZIP)
```bash
cd /evidence/memory/
7z x base-wkstn-01-mem.zip -o/evidence/memory/extracted/
# Raw dump will be at /evidence/memory/extracted/*.raw or *.mem or *.dmp
MEM=/evidence/memory/extracted/$(ls /evidence/memory/extracted/ | head -1)
```

## Step 2: Essential Plugins

### Process Analysis
```bash
vol3 -f $MEM windows.pslist          # Running processes (from EPROCESS list)
vol3 -f $MEM windows.psscan          # All processes including hidden/terminated
vol3 -f $MEM windows.cmdline         # Command line arguments per process
vol3 -f $MEM windows.pstree          # Process parent-child relationships
```

### Network Connections
```bash
vol3 -f $MEM windows.netscan         # Active + recently closed connections
vol3 -f $MEM windows.netstat         # Current network connections
```

### Code Injection & Malware
```bash
vol3 -f $MEM windows.malfind         # Memory regions with executable code injected
vol3 -f $MEM windows.malfind --pid PID  # Scan specific process
vol3 -f $MEM windows.dlllist --pid PID  # DLLs loaded by specific process
vol3 -f $MEM windows.handles --pid PID  # Handles opened by process
vol3 -f $MEM windows.vadinfo --pid PID  # Virtual address descriptors
```

### Credential Theft
```bash
vol3 -f $MEM windows.hashdump        # SAM database hashes
vol3 -f $MEM windows.lsadump         # LSA secrets
```

### YARA Integration
```bash
vol3 -f $MEM yarascan.YaraScan --yara-file /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar
vol3 -f $MEM yarascan.YaraScan --yara-file /opt/SAVVYDFIR-MCP/yara-rules/cobalt_strike.yar --pid PID
```

## IOC Patterns to Look For
- Process running as SYSTEM that shouldn't be (notepad, msedge, svchost with wrong parent)
- PAGE_EXECUTE_READWRITE memory regions in legitimate processes (injection indicator)
- Orphan processes (PPID points to non-existent or wrong process)
- Outbound connections on unexpected ports from system processes
- Named pipes matching `\\\\.\\pipe\\XXXXXXXX` (Cobalt Strike SMB beacon)
- `cmd.exe` spawned by `winword.exe` or `excel.exe` (macro execution)
- `powershell.exe` with `-enc` or `-e` flag (encoded command)
- `svchost.exe` not spawned by `services.exe` (masquerading)
- Process name typosquats (`svch0st`, `scvhost`)

## Ralph Wiggum Loop
If vol3 fails:
1. Check if file is still zipped: `file $MEM` — should say "data" not "Zip archive"
2. Check path: `ls -lh $MEM`
3. Try with full path: `vol3 -f /evidence/memory/extracted/filename.raw windows.pslist`
4. Check file size: 0-byte file means extraction failed
