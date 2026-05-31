---
name: tools-reference
description: Load when you need exact command syntax for SIFT Workstation tools. Covers Volatility 3, Sleuth Kit, EZ Tools, Plaso, YARA, and Regripper with actual invocation examples and output parsing guidance.
allowed-tools:
  - Bash
---

# Tools Reference - Exact Command Syntax

## Volatility 3 (Memory Analysis)
```bash
MEM=/evidence/memory/extracted/dump.raw

# Process analysis
vol3 -f $MEM windows.pslist          # Running processes (EPROCESS list walk)
vol3 -f $MEM windows.psscan          # All processes (pool tag scan - finds hidden)
vol3 -f $MEM windows.pstree          # Process tree with parent-child
vol3 -f $MEM windows.cmdline         # Command lines per process

# Network
vol3 -f $MEM windows.netscan         # Active + recently closed connections
vol3 -f $MEM windows.netstat         # Current connections

# Injection detection
vol3 -f $MEM windows.malfind         # All suspicious VAD regions
vol3 -f $MEM windows.malfind --pid PID  # Specific process
vol3 -f $MEM windows.vadinfo --pid PID  # Full VAD details

# DLLs and handles
vol3 -f $MEM windows.dlllist --pid PID  # Loaded DLLs
vol3 -f $MEM windows.handles --pid PID  # Open handles

# Credentials
vol3 -f $MEM windows.hashdump        # SAM database hashes
vol3 -f $MEM windows.lsadump         # LSA secrets

# YARA in memory
vol3 -f $MEM yarascan.YaraScan --yara-file /path/to/rules.yar
vol3 -f $MEM yarascan.YaraScan --yara-file /path/to/rules.yar --pid PID
```

## Sleuth Kit (Disk Analysis)
```bash
# Mount E01
mkdir -p /mnt/evidence /mnt/disk
ewfmount /evidence/disk/image.E01 /mnt/evidence/
mmls /mnt/evidence/ewf1              # Get partition offsets
OFFSET=2048                          # Replace with actual NTFS offset
mount -o ro,loop,offset=$((OFFSET*512)) /mnt/evidence/ewf1 /mnt/disk/

# List files
fls -r -p /mnt/evidence/ewf1 -o $OFFSET | head -100   # All files
fls -r -p -d /mnt/evidence/ewf1 -o $OFFSET             # Deleted only

# Extract by inode
icat -o $OFFSET /mnt/evidence/ewf1 INODE > /cases/extracted_file

# Filesystem stats
fsstat -o $OFFSET /mnt/evidence/ewf1

# Extract $MFT (always inode 0)
icat -o $OFFSET /mnt/evidence/ewf1 0 > /cases/mft/\$MFT
```

## EZ Tools (Windows Artifact Parsing)
```bash
# MFT parsing
MFTECmd -f /cases/mft/\$MFT --csv /cases/mft/ --csvf mft_output.csv

# Event log parsing
EvtxECmd -f /mnt/disk/Windows/System32/winevt/Logs/Security.evtx --csv /cases/evtx/ --csvf security.csv
EvtxECmd -d /mnt/disk/Windows/System32/winevt/Logs/ --csv /cases/evtx/ --csvf all_logs.csv

# Prefetch
PECmd -d /mnt/disk/Windows/Prefetch/ --csv /cases/prefetch/ --csvf prefetch.csv

# Application Compatibility Cache
AppCompatCacheParser -f /mnt/disk/Windows/System32/config/SYSTEM --csv /cases/shimcache/ --csvf shimcache.csv

# LNK files
LECmd -d /mnt/disk/Users/ --csv /cases/lnk/ --csvf lnk.csv -q

# Jump Lists
JLECmd -d /mnt/disk/Users/ --csv /cases/jumplists/ --csvf jumplists.csv -q

# ShellBags
SBECmd -d /mnt/disk/Users/ --csv /cases/shellbags/ --csvf shellbags.csv
```

## Plaso / log2timeline
```bash
# Create super timeline (slow - 30-120 min for 100GB image)
log2timeline.py --parsers win10 /cases/timeline/case.plaso /mnt/disk/

# Query timeline
psort.py -o dynamic /cases/timeline/case.plaso "date > \'2026-01-01\' AND date < \'2026-02-01\'" > /cases/timeline/filtered.csv
psort.py -o l2tcsv /cases/timeline/case.plaso > /cases/timeline/full.csv
```

## YARA
```bash
# Scan directory
yara -r /path/to/rules.yar /mnt/disk/Windows/Temp/

# Scan specific file
yara /path/to/rules.yar /cases/extracted/suspicious.exe

# Scan memory dump
yara /path/to/rules.yar /evidence/memory/extracted/dump.raw
```

## Regripper
```bash
regripper -r /mnt/disk/Windows/System32/config/SAM -p samparse
regripper -r /mnt/disk/Windows/System32/config/SYSTEM -p services
regripper -r /mnt/disk/Users/*/NTUSER.DAT -p userassist
```

## Key Artifact Paths (Windows)
```
/mnt/disk/Windows/System32/config/         # Registry hives
/mnt/disk/Windows/Prefetch/                # Prefetch files
/mnt/disk/Windows/System32/winevt/Logs/    # Event logs
/mnt/disk/$MFT                             # Master File Table
/mnt/disk/Users/*/NTUSER.DAT              # User registry
/mnt/disk/Users/*/AppData/                 # User artifacts
```
