---
name: timeline
description: Load when creating super timelines, correlating events across multiple artifact sources, or analyzing temporal patterns with Plaso log2timeline. Covers timeline creation, filtering, and analysis.
allowed-tools:
  - Bash
---

# Timeline Analysis — Plaso / log2timeline Reference

## Step 1: Create Plaso Storage File
```bash
mkdir -p /cases/timeline

# From mounted disk (comprehensive — takes 20-40 min):
log2timeline.py /cases/timeline/case.plaso /mnt/disk/

# With specific parser preset:
log2timeline.py --parsers win10 /cases/timeline/case.plaso /mnt/disk/

# From specific directories (faster):
log2timeline.py --parsers winevtx /cases/timeline/case.plaso /mnt/disk/Windows/System32/winevt/Logs/
```
Parser presets: `win10` (default), `win7`, `linux`, `macos`

## Step 2: Filter and Export
```bash
# Export full timeline to CSV:
psort.py -o l2tcsv -w /cases/timeline/timeline.csv /cases/timeline/case.plaso

# Filter by time range:
psort.py -o l2tcsv -w /cases/timeline/filtered.csv /cases/timeline/case.plaso \
  "date > '2023-01-15 00:00:00' AND date < '2023-01-26 00:00:00'"

# Filter by content:
psort.py -o l2tcsv -w /cases/timeline/filtered.csv /cases/timeline/case.plaso \
  "message contains 'cmd.exe'"
```

## Step 3: Correlate with Memory Findings
After memory analysis identifies suspicious processes:
1. Note process creation timestamp from `vol3 windows.pslist`
2. Query timeline around that timestamp (+-5 minutes)
3. Look for: file creation, registry mods, service creation, network events

```bash
psort.py -o l2tcsv -w /cases/timeline/window.csv /cases/timeline/case.plaso \
  "date > '2023-01-20 14:20:00' AND date < '2023-01-20 14:30:00'"
```

## Step 4: Analyze for Patterns
```bash
grep -i "stun.exe\|wacsvc\|bhv.exe" /cases/timeline/timeline.csv
grep "Prefetch\|UserAssist\|AppCompatCache" /cases/timeline/timeline.csv | grep "2023-01"
grep -E "ZZZZ|_rename_" /cases/timeline/timeline.csv
```

## Output Format (l2tcsv)
Columns: `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`

## Ralph Wiggum Loop
If log2timeline fails: ensure /mnt/disk is mounted first
If psort fails: check plaso file with `ls -lh /cases/timeline/case.plaso`
If timeline empty: try explicit parsers `--parsers 'winevt,prefetch,winreg'`
