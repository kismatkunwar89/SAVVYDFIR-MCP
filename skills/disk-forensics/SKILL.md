# Disk Forensics — Sleuth Kit + ewfmount Reference

**Load when:** Mounting disk images or performing filesystem analysis during Phase 2.

---

## Mounting E01 Images

### Step 1: Mount E01 as raw device
```bash
mkdir -p /mnt/evidence
ewfmount /evidence/disk/image.E01 /mnt/evidence/
```
This exposes `/mnt/evidence/ewf1` as a raw block device.

### Step 2: Get partition layout
```bash
mmls /mnt/evidence/ewf1
```
Output shows partition table. Find the NTFS partition — note the **Start** sector offset (typically 2048 for GPT, 63 for MBR).

### Step 3: Mount the partition read-only
```bash
# Calculate byte offset: Start_sector * 512
mount -o ro,loop,offset=$((2048*512)) /mnt/evidence/ewf1 /mnt/disk
```
Replace `2048` with the actual start sector from mmls output.

### Step 4: Verify mount
```bash
ls /mnt/disk/Windows/System32/
```

---

## Mounting Raw/DD Images

```bash
# Get partition offset
mmls /evidence/disk/image.raw

# Mount directly
mount -o ro,loop,offset=$((OFFSET*512)) /evidence/disk/image.raw /mnt/disk
```

---

## Filesystem Operations (without mounting)

### List all files recursively
```bash
fls -r -p /mnt/evidence/ewf1 -o 2048
```
`-r` recursive, `-p` full path display. Replace `2048` with partition offset in sectors.

### List deleted files only
```bash
fls -r -p -d /mnt/evidence/ewf1 -o 2048
```
`-d` shows deleted entries. Deleted files show `*` prefix.

### Extract file by inode number
```bash
icat -o 2048 /mnt/evidence/ewf1 12345 > /cases/extracted_file.bin
```
Replace `12345` with the inode from fls output.

### Get filesystem statistics
```bash
fsstat -o 2048 /mnt/evidence/ewf1
```
Shows filesystem type, volume name, timestamps, cluster size.

---

## Key Artifacts to Prioritize

After mounting, extract these artifacts first (ordered by forensic value):

| Priority | Artifact | Typical Path | Tool |
|---|---|---|---|
| 1 | $MFT | `/$MFT` (root, inode 0) | `MFTECmd` via ez-tools skill |
| 2 | Registry hives | `/Windows/System32/config/{SAM,SYSTEM,SOFTWARE,SECURITY}` | `regripper` |
| 3 | User registry | `/Users/*/NTUSER.DAT` | `regripper` |
| 4 | Event logs | `/Windows/System32/winevt/Logs/*.evtx` | `EvtxECmd` via ez-tools skill |
| 5 | Prefetch | `/Windows/Prefetch/*.pf` | `AppCompatCacheParser` or MCP tools |
| 6 | Amcache | `/Windows/appcompat/Programs/Amcache.hve` | MCP `disk.get_amcache` tool |
| 7 | LNK files | `/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` | `LECmd` |
| 8 | Jump Lists | `/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/` | `JLECmd` |

### Extract $MFT from unmounted image
```bash
# Find $MFT inode (always inode 0 on NTFS)
icat -o 2048 /mnt/evidence/ewf1 0 > /cases/mft/\$MFT
```

### Extract registry hives
```bash
# Find inode for SYSTEM hive
fls -r -p /mnt/evidence/ewf1 -o 2048 | grep -i "windows/system32/config/system$"
# Extract by inode
icat -o 2048 /mnt/evidence/ewf1 INODE > /cases/registry/SYSTEM
```

---

## Unmounting

Always unmount when done:
```bash
umount /mnt/disk
umount /mnt/evidence
```
