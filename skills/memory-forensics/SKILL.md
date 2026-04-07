# Memory Forensics — Volatility 3 Reference

**Load when:** Analyzing memory dumps during Phase 3 or enrichment.

---

## Pre-Analysis: Extract Compressed Dumps

Memory dumps are often delivered as ZIP archives. Extract before analysis:

```bash
# Check if file is a ZIP
file /evidence/memory/dump.zip
# Extract
7z x /evidence/memory/dump.zip -o/evidence/memory/
# Verify raw dump exists
ls -la /evidence/memory/*.raw /evidence/memory/*.mem /evidence/memory/*.vmem
```

**Ralph Wiggum Loop:** If vol3 fails with "Unsupported file format" or similar:
1. Check if the file is still zipped: `file /evidence/memory/dump.raw` — if it says "Zip archive", extract it
2. Check the path is correct: `ls -la /evidence/memory/`
3. Check file size — a 0-byte file means extraction failed
4. Try with full path: `vol3 -f /evidence/memory/dump.raw windows.info`

---

## Essential Plugins

### OS Profile Detection (run first)
```bash
vol3 -f /evidence/memory/dump.raw windows.info
```
Confirms OS version, build number, architecture. Must succeed before other plugins.

### Process Listing (linked list walk)
```bash
vol3 -f /evidence/memory/dump.raw windows.pslist
```
Walks `PsActiveProcessHead` doubly-linked list. Shows OS-visible processes with PID, PPID, name, create/exit times.

### Process Scanning (pool tag scan)
```bash
vol3 -f /evidence/memory/dump.raw windows.psscan
```
Scans raw memory for EPROCESS pool tags. Finds unlinked (DKOM-hidden) processes. **Compare with pslist** — processes in psscan but NOT in pslist are hidden.

### Command Lines
```bash
vol3 -f /evidence/memory/dump.raw windows.cmdline
```
Shows full command line arguments for each process. Critical for identifying malicious parameters.

### Network Connections
```bash
vol3 -f /evidence/memory/dump.raw windows.netscan
```
Extracts TCP/UDP endpoints including closed/TIME_WAIT connections. Shows local/remote IP:port and owning PID.

### Injection Detection (malfind)
```bash
vol3 -f /evidence/memory/dump.raw windows.malfind
```
Finds memory regions that are executable + writable + anonymous (no backing file). Strong indicator of shellcode injection. Optionally filter by PID:
```bash
vol3 -f /evidence/memory/dump.raw windows.malfind --pid 1284
```

### DLL Listing
```bash
vol3 -f /evidence/memory/dump.raw windows.dlllist --pid 1284
```
Lists all loaded DLLs for a specific PID. Look for DLLs loaded from temp dirs, AppData, or without disk backing.

### Handle Listing
```bash
vol3 -f /evidence/memory/dump.raw windows.handles --pid 1284
```
Shows open handles (files, registry keys, mutexes). Useful for identifying what resources a process is accessing.

### VAD Info
```bash
vol3 -f /evidence/memory/dump.raw windows.vadinfo --pid 1284
```
Detailed Virtual Address Descriptor dump. Shows protection flags, mapped files, and region sizes.

---

## Interpreting Output

### pslist vs psscan Comparison
- Process in both: normal, OS-visible process
- Process in psscan only: **DKOM-hidden** — rootkit or advanced malware unlinked from process list
- Process in pslist only: should not happen; indicates memory corruption or analysis error

### malfind Indicators
- `PAGE_EXECUTE_READWRITE` + `MZ` header at region start: reflectively loaded PE
- `PAGE_EXECUTE_READWRITE` + no PE header: raw shellcode (Cobalt Strike, Meterpreter)
- Legitimate exceptions: JIT compilers (.NET CLR, Java, browsers)

### Network IOC Patterns
- `svchost.exe` connecting to external IPs on non-standard ports (not 80/443)
- `rundll32.exe` or `regsvr32.exe` with active connections
- Any process with connections to known-bad IPs from manifest IOC list
- Processes with many connections to the same external IP (beaconing)

---

## Common IOC Patterns

| Pattern | Significance |
|---|---|
| `cmd.exe` spawned by `winword.exe` or `excel.exe` | Macro-based initial access |
| `powershell.exe` with `-enc` or `-e` flag | Encoded command execution |
| `svchost.exe` not spawned by `services.exe` | Masquerading / process injection |
| Process name typosquats (`svch0st`, `scvhost`) | Masquerading |
| `rundll32.exe` loading DLL from %TEMP% or %APPDATA% | Suspicious DLL execution |
| Multiple `svchost.exe` instances with same service group | Possible process hollowing |
