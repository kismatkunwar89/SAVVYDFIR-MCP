# Case Brief — {{CASE_ID}}

> **Template version:** 1.0 — replace all `{{PLACEHOLDER}}` values before starting investigation.
> **Load order:** Read this file first, then load `skills/savvydfir-triage/SKILL.md` and begin Phase 1.

---

## Case Identification

| Field | Value |
|---|---|
| Case ID | `{{CASE_ID}}` |
| Case Name | {{CASE_NAME}} |
| Date Opened | {{YYYY-MM-DD}} (UTC) |
| Lead Investigator | {{INVESTIGATOR_NAME}} |
| Investigation Goal | {{INVESTIGATION_GOAL}} |
| Max Iterations | {{MAX_ITERATIONS}} (default: 4) |

---

## Evidence Files

All evidence files must be present and readable before beginning Phase 1 (Integrity Verification). Cross-reference paths and hashes against `manifest.json`.

### Disk Images

| Host | File Path | Image Type | Size | Expected SHA256 | Mount Point |
|---|---|---|---|---|---|
| {{HOST_01}} | `/cases/{{CASE_ID}}/evidence/{{DISK_IMAGE_01}}` | {{E01\|raw\|dd\|AFF}} | {{SIZE_GB}} GB | `{{SHA256_HASH}}` | `/mnt/{{HOST_01}}/` |
| {{HOST_02}} | `/cases/{{CASE_ID}}/evidence/{{DISK_IMAGE_02}}` | {{E01\|raw\|dd\|AFF}} | {{SIZE_GB}} GB | `{{SHA256_HASH}}` | `/mnt/{{HOST_02}}/` |

### Memory Dumps

| Host | File Path | Size | Expected SHA256 |
|---|---|---|---|
| {{HOST_01}} | `/cases/{{CASE_ID}}/evidence/{{MEMORY_DUMP_01}}` | {{SIZE_GB}} GB | `{{SHA256_HASH}}` |
| {{HOST_02}} | `/cases/{{CASE_ID}}/evidence/{{MEMORY_DUMP_02}}` | {{SIZE_GB}} GB | `{{SHA256_HASH}}` |

---

## Mount Commands

Use these commands to make disk images accessible before running disk analysis tools. Run them after Phase 1 integrity verification passes.

```bash
# E01 image — use ewfmount
ewfmount /cases/{{CASE_ID}}/evidence/{{DISK_IMAGE_01}} /mnt/{{HOST_01}}-ewf/
mount -o ro,loop,offset=$(({{PARTITION_OFFSET}} * 512)) \
    /mnt/{{HOST_01}}-ewf/ewf1 \
    /mnt/{{HOST_01}}/

# Raw/DD image — mount directly
mount -o ro,loop,offset=$(({{PARTITION_OFFSET}} * 512)) \
    /cases/{{CASE_ID}}/evidence/{{DISK_IMAGE_01}} \
    /mnt/{{HOST_01}}/

# Find partition offset (run first if unknown)
mmls /cases/{{CASE_ID}}/evidence/{{DISK_IMAGE_01}}
```

> Note: Always mount read-only (`-o ro`). Never mount in read-write mode.

---

## Investigation Goal

{{INVESTIGATION_GOAL_DETAILED}}

### Specific Questions to Answer
1. {{QUESTION_01}}
2. {{QUESTION_02}}
3. {{QUESTION_03}}

### Success Criteria
The investigation is complete when:
- {{SUCCESS_CRITERION_01}}
- {{SUCCESS_CRITERION_02}}

---

## Suspected Time Window

| Field | Value |
|---|---|
| Earliest suspicious activity | `{{YYYY-MM-DDTHH:MM:SSZ}}` (UTC) |
| Latest suspicious activity | `{{YYYY-MM-DDTHH:MM:SSZ}}` (UTC) |
| Source of time window estimate | {{TIMEWINDOW_SOURCE}} |

Focus timeline analysis on `±30 minutes` around each boundary unless evidence suggests a wider window.

---

## Network Topology

Provide this context before running network analysis in Phase 3. The agent uses it to distinguish internal-to-internal connections (potentially lateral movement) from internal-to-external connections (C2 candidates).

| Host | IP Address | Role | OS |
|---|---|---|---|
| {{HOST_01}} | `{{IP_01}}` | {{ROLE_01 (e.g., workstation, DC, file server)}} | {{OS_VERSION_01}} |
| {{HOST_02}} | `{{IP_02}}` | {{ROLE_02}} | {{OS_VERSION_02}} |

### Network Segments

| Segment | CIDR | Description |
|---|---|---|
| {{SEGMENT_NAME_01}} | `{{CIDR_01}}` | {{SEGMENT_DESCRIPTION_01}} |
| {{SEGMENT_NAME_02}} | `{{CIDR_02}}` | {{SEGMENT_DESCRIPTION_02}} |

### Known Legitimate External IPs

List IPs that are expected in network connections (Windows Update, antivirus, etc.):

- `{{KNOWN_SAFE_IP_01}}` — {{DESCRIPTION_01}}
- `{{KNOWN_SAFE_IP_02}}` — {{DESCRIPTION_02}}

---

## Known IOCs

Provide all known indicators of compromise at case open. The agent uses these to prioritize findings and filter timeline events.

### File Hashes (SHA256)
```
{{SHA256_HASH_01}}  # {{HASH_DESCRIPTION_01}}
{{SHA256_HASH_02}}  # {{HASH_DESCRIPTION_02}}
```

### File Names / Paths
```
{{SUSPICIOUS_FILENAME_01}}
{{SUSPICIOUS_PATH_01}}
```

### IP Addresses / Domains
```
{{SUSPICIOUS_IP_01}}  # {{IP_DESCRIPTION_01}}
{{SUSPICIOUS_DOMAIN_01}}  # {{DOMAIN_DESCRIPTION_01}}
```

### Registry Keys
```
{{SUSPICIOUS_REGKEY_01}}
```

### Process Names
```
{{SUSPICIOUS_PROCESS_01}}
```

---

## Prior Investigation Notes

{{PRIOR_NOTES}}

> If no prior notes exist, leave this section blank or write "None."

---

## Instructions to Agent

1. Read this file completely before calling any tools.
2. Load `skills/savvydfir-triage/SKILL.md` now.
3. Begin with Phase 1: call `evidence.verify_integrity()` for every evidence file listed in the Evidence Files table above.
4. Use the mount commands in the Mount Commands section after integrity passes.
5. Use the Known IOCs as filter inputs when querying timelines and running YARA scans.
6. Use the Network Topology to classify connections as internal vs. external.
7. Target the Suspected Time Window when querying Plaso timeline data.
8. Do NOT ask questions. Run autonomously until completion or max_iterations.
9. Write all output to `./analysis/`, `./reports/`, and `./exports/`.

---

## Output Locations

| Artifact | Path |
|---|---|
| All findings (structured) | `./analysis/findings.json` |
| Audit trail (all tool calls) | `./analysis/audit.jsonl` |
| MFT timeline | `./analysis/mft_timeline.csv` |
| Prefetch analysis | `./analysis/prefetch.csv` |
| Amcache analysis | `./analysis/amcache.csv` |
| Process list | `./analysis/processes.json` |
| Network connections | `./analysis/network_connections.json` |
| Injection candidates | `./analysis/injection_candidates.json` |
| Investigation narrative | `./reports/narrative.md` |
| Case state export | `./exports/case_state.json` |
| PDF report (optional) | `./reports/report.pdf` |
