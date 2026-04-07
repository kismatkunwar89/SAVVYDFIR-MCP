# EZ Tools — Eric Zimmerman Tools Reference

**Load when:** Parsing Windows artifacts: MFT, event logs, registry, shimcache, LNK files, jump lists, shellbags.

All EZ tools are installed on SIFT via .NET. Output goes to `/cases/` directory.

---

## MFTECmd — Master File Table Parser

```bash
MFTECmd -f '/mnt/disk/$MFT' --csv /cases/mft/ --csvf mft.csv
```

**Key output columns:** EntryNumber, ParentEntryNumber, FileName, SI_Created, SI_Modified, FN_Created, FN_Modified, InUse, IsDirectory

**Timestomping detection:** Compare SI_Created vs FN_Created. Difference >1 hour = likely timestomped. SI Modified < SI Created = impossible without manipulation.

---

## EvtxECmd — Windows Event Log Parser

```bash
# Parse Security log
EvtxECmd -f '/mnt/disk/Windows/System32/winevt/Logs/Security.evtx' --csv /cases/evtx/ --csvf security.csv

# Parse System log
EvtxECmd -f '/mnt/disk/Windows/System32/winevt/Logs/System.evtx' --csv /cases/evtx/ --csvf system.csv

# Parse all logs in directory
EvtxECmd -d '/mnt/disk/Windows/System32/winevt/Logs/' --csv /cases/evtx/ --csvf all_events.csv
```

**Critical Event IDs:**
| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon (Type 3=network, Type 10=RDP) |
| 4625 | Security | Failed logon (brute force indicator) |
| 4688 | Security | Process creation (if audit enabled) |
| 4672 | Security | Special privileges assigned (admin logon) |
| 7045 | System | New service installed (persistence) |
| 1 | Sysmon | Process creation with hash + parent |
| 3 | Sysmon | Network connection |

---

## AppCompatCacheParser — Shimcache

```bash
AppCompatCacheParser -f '/cases/registry/SYSTEM' --csv /cases/ --csvf shimcache.csv
```

Parses the Application Compatibility Cache from SYSTEM hive. Shows executables that were **present on disk** (not necessarily executed on recent Windows versions).

---

## LECmd — LNK File Parser

```bash
# Parse all LNK files in a directory
LECmd -d '/mnt/disk/Users' --csv /cases/lnk/ --csvf lnk_files.csv

# Parse single LNK file
LECmd -f '/mnt/disk/Users/admin/Desktop/tool.lnk' --csv /cases/lnk/
```

LNK files record: target path, MAC timestamps, volume serial number, machine hostname. Useful for proving file access even after deletion.

---

## JLECmd — Jump List Parser

```bash
JLECmd -d '/mnt/disk/Users/admin/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations' --csv /cases/jumplists/ --csvf jumplists.csv
```

Jump lists show recently accessed files per application. Survives file deletion.

---

## SBECmd — Shellbags Explorer

```bash
# Parse from NTUSER.DAT
SBECmd -d '/cases/registry/' --csv /cases/shellbags/ --csvf shellbags.csv
```

Shellbags record folder access history. Proves a user navigated to a directory even if the directory is now deleted.

---

## regripper — Registry Hive Parser

```bash
# Parse SYSTEM hive
regripper -r /cases/registry/SYSTEM -a > /cases/registry/system_all.txt

# Parse NTUSER.DAT
regripper -r '/cases/registry/NTUSER.DAT' -a > /cases/registry/ntuser_all.txt

# Parse SOFTWARE hive
regripper -r /cases/registry/SOFTWARE -a > /cases/registry/software_all.txt
```

Key plugins: services, run, runonce, userassist, shellfolders, typedurls, mru.

---

## Output Directory Convention

All EZ tool output goes to `/cases/<artifact_type>/`:
```
/cases/mft/mft.csv
/cases/evtx/security.csv
/cases/lnk/lnk_files.csv
/cases/jumplists/jumplists.csv
/cases/shellbags/shellbags.csv
/cases/registry/system_all.txt
```
