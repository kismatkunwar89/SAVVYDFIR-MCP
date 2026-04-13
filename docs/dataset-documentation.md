# Dataset Documentation

**SAVVYDFIR-MCP — Evidence Corpus: SRL-2018 (SANS Realistic Lab 2018)**

This document records the evidence files used to evaluate SAVVYDFIR-MCP, their provenance, integrity hashes, and the findings produced per host. All placeholder values in `[BRACKETS]` must be completed after evidence files are acquired and hashed.

---

## 1. Corpus Provenance

| Field | Value |
|---|---|
| **Corpus name** | SANS Realistic Lab 2018 (SRL-2018) |
| **Source** | SANS Institute — FOR508 Advanced Incident Response course |
| **Access method** | Licensed via SANS FOR508 course materials |
| **License** | Educational use only — not redistributable |
| **Scenario description** | Multi-host enterprise compromise simulating an APT campaign with initial access via spearphishing, lateral movement, credential theft, and data staging |
| **Number of hosts** | 22 |
| **Evidence types** | Disk images (E01 format) + memory dumps (raw/zip) |

---

## 2. Environment Versions

| Component | Version |
|---|---|
| SIFT Workstation | [RECORD EXACT VERSION, e.g., `sift-vm-3.0-amd64.20240415`] |
| Ubuntu | [e.g., `22.04.3 LTS`] |
| Volatility 3 | `/opt/volatility3-2.20.0/vol.py` — version 2.20.0 |
| EZ Tools suite | [e.g., `2024-01-15` release] |
| PECmd version | `dotnet /opt/zimmermantools/PECmd.dll --version` → [RECORD] |
| AmcacheParser version | [RECORD] |
| MFTECmd version | [RECORD] |
| EvtxECmd version | [RECORD] |
| RECmd version | [RECORD] |
| Sleuth Kit | `fls --version` → [RECORD] |
| Plaso | `log2timeline.py --version` → [RECORD] |
| YARA | `yara --version` → [RECORD] |
| Python | `python3 --version` → [RECORD] |
| FastMCP | `pip show fastmcp` → [RECORD] |
| Anthropic model | [RECORD model ID used for investigation runs, e.g., `claude-opus-4-5`] |

---

## 3. Evidence File Inventory

### 3.1 Primary Demo Case: base-wkstn-01

| Field | Value |
|---|---|
| **Case ID** | SRL-2018-WKSTN-01 |
| **Host** | base-wkstn-01 |
| **Role** | User workstation — primary demo case |
| **Disk image path** | `/evidence/SRL-2018/base-wkstn-01-c-drive.E01` |
| **Disk image size** | [e.g., 15.8 GB] |
| **Disk image SHA-256** | `[RECORD SHA-256 HASH OF .E01 FILE]` |
| **Memory dump path** | `/evidence/SRL-2018/base-wkstn-01-mem.raw` (or `.zip`) |
| **Memory dump size** | [e.g., 1.2 GB] |
| **Memory dump SHA-256** | `[RECORD SHA-256 HASH OF MEMORY DUMP]` |
| **OS version** | [Detected by `detect_profile()`, e.g., `Windows 10 x64 Build 17763`] |
| **Evidence verified at** | [Timestamp of first `verify_integrity()` call] |

**Verification commands:**

```bash
sha256sum /evidence/SRL-2018/base-wkstn-01-c-drive.E01
sha256sum /evidence/SRL-2018/base-wkstn-01-mem.raw
ewfverify /evidence/SRL-2018/base-wkstn-01-c-drive.E01
```

### 3.2 Remaining Hosts (Breadth Pass)

| Host | Disk Image SHA-256 | Memory Dump SHA-256 | Size (Disk) | Size (Mem) |
|---|---|---|---|---|
| base-wkstn-02 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-03 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-04 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-05 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-06 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-07 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-08 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-09 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-wkstn-10 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-dc-01 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-dc-02 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-srv-01 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-srv-02 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-srv-03 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| base-srv-04 | [RECORD] | [RECORD] | [RECORD] | [RECORD] |
| [additional hosts] | [RECORD] | [RECORD] | [RECORD] | [RECORD] |

---

## 4. Ground Truth Summary

### 4.1 base-wkstn-01 Ground Truth Findings

The following findings were established through manual analysis before running SAVVYDFIR-MCP. They constitute the ground truth for the primary accuracy evaluation.

| GT-ID | Finding Type | Artifact Source | Description | Artifact Path | Offset / Key |
|---|---|---|---|---|---|
| GT-W01-001 | [e.g., `process_injection`] | [e.g., `memory`] | [Description from manual analysis] | [Artifact path] | [Offset or PID] |
| GT-W01-002 | [e.g., `persistence`] | [e.g., `disk`] | [Description] | [Path] | [Registry key path] |
| GT-W01-003 | [e.g., `lateral_movement`] | [e.g., `disk`] | [Description] | [Event log path] | [Event ID + timestamp] |
| GT-W01-004 | [e.g., `defense_evasion`] | [e.g., `disk`] | [Description] | [Path] | [Inode] |
| GT-W01-005 | [e.g., `timestomping`] | [e.g., `disk`] | [Description] | [Path] | [MFT entry number] |
| [Add rows as found] | | | | | |

**Total ground truth findings for base-wkstn-01:** [RECORD COUNT after manual analysis]

### 4.2 Per-Host Ground Truth Summary

| Host | Total GT Findings | Compromise Level | Primary Indicators |
|---|---|---|---|
| base-wkstn-01 | [RECORD] | High | Persistence, injection, lateral movement |
| base-wkstn-02 | [RECORD] | [RECORD] | [RECORD] |
| base-dc-01 | [RECORD] | [RECORD] | Credential access, replication abuse |
| [remaining hosts] | [RECORD] | [RECORD] | [RECORD] |

---

## 5. Evidence Integrity Verification Protocol

### At Investigation Start

```bash
# For each evidence file:
sha256sum /evidence/SRL-2018/<hostname>-c-drive.E01 > /evidence/SRL-2018/<hostname>-c-drive.E01.sha256
sha256sum /evidence/SRL-2018/<hostname>-mem.raw > /evidence/SRL-2018/<hostname>-mem.raw.sha256

# ewfverify for E01 images (checks embedded MD5/SHA1 from acquisition):
ewfverify /evidence/SRL-2018/<hostname>-c-drive.E01
```

The MCP tool `verify_integrity()` wraps `ewfverify` and records the result in `audit.jsonl` automatically.

### At Investigation End

The Stop hook re-runs `verify_integrity()` and compares `integrity_hash_start` with `integrity_hash_end`. A mismatch would indicate evidence modification — which should never happen given read-only mount options and SafeRunner's path deny list.

### Mount Options (Read-Only Enforcement)

```bash
# Mount E01 image read-only via ewfmount (libewf):
sudo ewfmount /evidence/SRL-2018/base-wkstn-01-c-drive.E01 /mnt/disk-base-wkstn-01
# ewfmount always mounts read-only — no write option exists

# Verify mount options:
mount | grep /mnt/disk-base-wkstn-01
# Expected: ewf1 on /mnt/disk-base-wkstn-01 type fuse (ro,...)

# Mount the filesystem from the ewfmount device:
sudo mount -o ro,noatime /mnt/disk-base-wkstn-01/ewf1 /mnt/filesystem-base-wkstn-01
```

---

## 6. Known Corpus Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| SRL-2018 represents a simulated scenario, not a live incident | Findings may reflect scenario design artifacts rather than novel attacker behavior | Results are clearly scoped as "SRL-2018 evaluation" — generalization claims are avoided |
| Memory dump acquisition time may not align exactly with disk image acquisition time | Some in-memory artifacts may reference files that do not yet appear as deleted on disk (or vice versa) | Cross-artifact time-gap discrepancies are noted in findings rather than flagged as errors |
| Some evidence files may not be available for all 22 hosts if course license does not include full corpus | Reduces breadth pass coverage | Evaluation reports actual host count, not claimed count |
| E01 images include embedded hashes from acquisition — ewfverify checks these, not re-acquisition | Cannot independently verify chain of custody beyond SANS acquisition | Document SANS as trusted evidence custodian |

---

## 7. Data Privacy and Handling

- SRL-2018 is synthetic data created by SANS Institute for educational purposes. It does not contain real personal information.
- Evidence files are not committed to the public GitHub repository.
- Only the SHA-256 hashes and the `examples/SRL-2018-WKSTN-01/analysis/` directory (containing derived outputs) are committed.
- The `examples/` directory is reviewed before commit to ensure no PII is present in EVTX event payloads or registry values.
