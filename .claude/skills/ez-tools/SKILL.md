---
name: ez-tools
description: Load when analyzing Windows artifacts including MFT, event logs, prefetch files, LNK files, jump lists, registry hives, or ShimCache. Eric Zimmerman EZ Tools reference for SIFT.
allowed-tools:
  - Bash
---

# EZ Tools — Eric Zimmerman Windows Artifacts Reference

## Setup (run once per session)
```bash
mkdir -p /cases/mft /cases/evtx /cases/prefetch /cases/lnk /cases/registry
MOUNT=/mnt/disk   # Adjust to your mount point
```

## MFT Analysis — MFTECmd
```bash
MFTECmd -f "$MOUNT/\$MFT" --csv /cases/mft/ --csvf mft.csv
# Output: /cases/mft/mft.csv — all file metadata with timestamps
# Timestomping: compare SI_Created vs FN_Created — difference >1hr = timestomped
```

## Event Log Analysis — EvtxECmd
```bash
EvtxECmd -f "$MOUNT/Windows/System32/winevt/Logs/Security.evtx" --csv /cases/evtx/ --csvf security.csv
EvtxECmd -f "$MOUNT/Windows/System32/winevt/Logs/System.evtx" --csv /cases/evtx/ --csvf system.csv
EvtxECmd -d "$MOUNT/Windows/System32/winevt/Logs/" --csv /cases/evtx/
```
Key EIDs: 4624 (logon), 4625 (failed), 4672 (admin), 4688 (process create), 7045 (service install), Sysmon 1/3

## Prefetch Analysis — PECmd
```bash
PECmd -d "$MOUNT/Windows/Prefetch/" --csv /cases/prefetch/ --csvf prefetch.csv
# Shows execution times, run counts, files accessed
```

## ShimCache — AppCompatCacheParser
```bash
AppCompatCacheParser -f "$MOUNT/Windows/System32/config/SYSTEM" --csv /cases/registry/ --csvf shimcache.csv
```

## LNK Files — LECmd
```bash
LECmd -d "$MOUNT/Users/" -q --csv /cases/lnk/ --csvf lnk.csv
# Reveals files accessed even if deleted
```

## Jump Lists — JLECmd
```bash
JLECmd -d "$MOUNT/Users/" --csv /cases/lnk/ --csvf jumplists.csv
```

## Shellbags — SBECmd
```bash
SBECmd -d /cases/registry/ --csv /cases/shellbags/ --csvf shellbags.csv
```

## Registry — RegRipper
```bash
regripper -r "$MOUNT/Windows/System32/config/SOFTWARE" -a > /cases/registry/software.txt
regripper -r "$MOUNT/Windows/System32/config/SYSTEM" -a > /cases/registry/system.txt
regripper -r "$MOUNT/Users/USERNAME/NTUSER.DAT" -a > /cases/registry/ntuser.txt
```

## Ralph Wiggum Loop
If MFTECmd fails: check .NET with `dotnet --version`
If path not found: verify mount with `ls /mnt/disk/` and adjust MOUNT variable
If CSV empty: check output directory exists and has write permission
