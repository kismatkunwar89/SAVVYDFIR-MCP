# Timeline — Plaso/log2timeline Reference

**Load when:** Building or querying super timelines during Phase 2, 5, or enrichment.

---

## Create Super Timeline

```bash
# Full timeline from mounted disk
log2timeline.py /cases/timeline.plaso /mnt/disk/

# With specific parser preset
log2timeline.py --parsers win10 /cases/timeline.plaso /mnt/disk/

# From specific directories only (faster)
log2timeline.py --parsers winevtx /cases/timeline_evtx.plaso /mnt/disk/Windows/System32/winevt/Logs/
```

**Parser presets:** `win10` (default, all Windows 10 parsers), `win7`, `linux`, `macos`

**Duration:** 30-120 minutes for a 100GB image. For time-constrained investigations, use targeted parsers.

---

## Filter and Export

### Export full timeline to CSV
```bash
psort.py -o l2tcsv /cases/timeline.plaso -w /cases/timeline.csv
```

### Time-range filter
```bash
psort.py -o l2tcsv /cases/timeline.plaso "date > '2026-03-01T00:00:00' AND date < '2026-03-02T00:00:00'" -w /cases/timeline_filtered.csv
```

### Content filter
```bash
psort.py -o l2tcsv /cases/timeline.plaso "message contains 'cmd.exe'" -w /cases/timeline_cmd.csv
```

### Combined filter
```bash
psort.py -o l2tcsv /cases/timeline.plaso "date > '2026-03-01T00:00:00' AND message contains 'powershell'" -w /cases/timeline_ps.csv
```

---

## Key Timestamp Sources

| Source | What It Records | Forensic Value |
|---|---|---|
| MFT ($SI timestamps) | File create/modify/access/change | Can be timestomped |
| MFT ($FN timestamps) | Kernel-set create/modify | Cannot be timestomped via SetFileTime |
| Prefetch | Last 8 execution times | Binary execution proof |
| Event logs | Logon, process create, service install | Activity timeline |
| Registry | Key last-write timestamps | Configuration changes |
| LNK files | Target MAC timestamps | File access proof |
| USN Journal | File system change journal | Near real-time change log |

---

## Correlating with Memory Findings

After memory analysis identifies suspicious processes (Phase 3):

1. Note the process creation timestamp from `vol3 windows.pslist`
2. Query timeline around that timestamp (+-5 minutes):
   ```bash
   psort.py -o l2tcsv /cases/timeline.plaso "date > '2026-03-01T14:20:00' AND date < '2026-03-01T14:30:00'" -w /cases/timeline_window.csv
   ```
3. Look for:
   - File creation events matching the process binary
   - Registry modifications (persistence installation)
   - Event log entries (service creation, logon events)
   - Network-related events in the same window

---

## Output Format (l2tcsv)

Columns: `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`

- **MACB**: Modified/Accessed/Created/Birth indicator
- **source**: Parser that produced the event (e.g., `FILE`, `EVT`, `REG`)
- **desc**: Full event description
