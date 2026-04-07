---
name: disk-forensics
description: Load when mounting E01 forensic images, analyzing filesystems, extracting files by inode, or performing any Sleuth Kit disk analysis. Covers ewfmount, fls, mmls, icat workflow.
allowed-tools:
  - Bash
---

# Disk Forensics — Sleuth Kit + ewfmount Reference

## Step 1: Mount E01 Image
```bash
mkdir -p /mnt/evidence /mnt/disk
ewfmount /evidence/disk/base-wkstn-01-c-drive.E01 /mnt/evidence/
ls /mnt/evidence/   # Should show ewf1
```

## Step 2: Get Partition Table
```bash
mmls /mnt/evidence/ewf1
# Note the Start offset for the Windows partition (usually largest, type NTFS)
# Example: 002:  NTFS  0000002048  0000206847  0000204800
OFFSET=2048  # Replace with actual offset from mmls output
```

## Step 3: Mount Filesystem
```bash
mount -o ro,loop,offset=$((OFFSET*512)) /mnt/evidence/ewf1 /mnt/disk/
ls /mnt/disk/   # Should show Windows directory structure
```

## Step 4: Key Artifact Locations
```bash
/mnt/disk/Windows/System32/config/        # Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY)
/mnt/disk/Windows/Prefetch/               # Prefetch files (.pf)
/mnt/disk/Windows/System32/winevt/Logs/   # Event logs (.evtx)
/mnt/disk/$MFT                            # Master File Table
/mnt/disk/Users/*/AppData/                # User artifacts
/mnt/disk/Users/*/NTUSER.DAT             # User registry hive
```

## Step 5: List Filesystem with fls
```bash
fls -r -p /mnt/evidence/ewf1 -o $OFFSET | head -100   # List all files
fls -r -p -d /mnt/evidence/ewf1 -o $OFFSET             # List deleted files only
fls -r -p /mnt/evidence/ewf1 -o $OFFSET | grep -i "stun\|update\|bhv"  # Search for IOC
```

## Step 6: Extract Files by Inode
```bash
# Get inode from fls output (first column)
icat -o $OFFSET /mnt/evidence/ewf1 INODE_NUMBER > /cases/extracted_file
```

## Step 7: Filesystem Stats
```bash
fsstat -o $OFFSET /mnt/evidence/ewf1   # FS type, volume name, cluster size
```

## Extract MFT from Unmounted Image
```bash
icat -o $OFFSET /mnt/evidence/ewf1 0 > /cases/mft/\$MFT   # MFT is always inode 0
```

## Cleanup
```bash
umount /mnt/disk
umount /mnt/evidence
```

## Ralph Wiggum Loop
If ewfmount fails: check `ls /evidence/disk/` for correct filename
If mount fails: re-check offset with `mmls /mnt/evidence/ewf1` — use the NTFS partition
If fls returns empty: verify offset is correct, try without -o flag first
