# SAVVYDFIR-MCP — Single-Host Disk Baseline (Start)

> Purpose: a practical disk-first evaluation baseline for our current single-host testing.
> This is extracted from the broader SRL / CRIMSON OSPREY baseline, but trimmed to what we can fairly score on one host.

## Scope

Assumption:

- current single-host disk focus is `nfury` in the hackathon corpus
- this maps most closely to `rd01` in the DFIR material

What this baseline is for:

- early disk/timeline evaluation
- host-local false-positive control
- checking whether filtering and narrowing changes improve result quality

What this baseline is not for:

- full-network precision/recall claims
- cross-host lateral movement completeness
- memory-only detection scoring
- final competition-wide metrics

Use this as a `starting point`, not as a claim that the whole intrusion is fully covered.

## In Scope

Artifact families we should score on this host now:

- filesystem timeline
- MFT / USN / Super Timeline artifacts
- Prefetch
- ShimCache / Amcache where available
- LNK / UserAssist / RunMRU
- Registry artifacts
- Scheduled tasks and services
- EVTX / Defender / PowerShell transcript evidence stored on disk
- Browser / download artifacts
- Anti-forensics visible from disk
- VSS-based recovery evidence

## Out of Scope For This Start Baseline

- memory-only findings such as malfind, injected VADs, orphaned processes, and beacon config
- findings that only exist on other hosts
- multi-host inferences unless they are directly evidenced in this host's event logs or staged files
- total-network impact scoring

## Core Must-Hit Disk Findings

These are the highest-value host-local findings the disk pipeline should surface first.

| ID | Finding | Expected Kind | Main Artifact Families | Minimum Provenance Needed |
|---|---|---|---|---|
| D1 | `STUN.exe` scheduled task persistence | OBSERVATION | scheduled task, filesystem | path to task target or recovered task reference |
| D2 | `STUN.exe` has no Prefetch despite confirmed execution | OBSERVATION | prefetch + corroborating execution evidence | absence of PF plus corroborating execution source |
| D3 | `STUN.exe` timestomped (`SI < FN`) | OBSERVATION | MFT / timeline | explicit timestamp anomaly |
| D4 | `installoffice2019.bat` scheduled task | OBSERVATION | scheduled task, filesystem | path or task evidence |
| D5 | `packer-windows-update.ps1` encoded loader | OBSERVATION | scheduled task, script content | path plus encoded PowerShell evidence |
| D6 | `pssdnsvc.exe` disguised service persistence | OBSERVATION | service config, filesystem | service name/path |
| D7 | `C:\\Windows\\Update` created by `wacsvc` | OBSERVATION | MFT, timeline, LNK, EVTX | directory creation time plus actor if available |
| D8 | `EdgeUpdater.exe` and/or `EdgeUpdater.cfg` dropped in `C:\\Windows\\Update` | OBSERVATION | filesystem timeline | file path and timestamp |
| D9 | `data.bat` and `test.bat` created in `C:\\Windows\\Update\\rec\\` | OBSERVATION | filesystem timeline, VSS | file path and timestamp or VSS recovery |
| D10 | Recon output files existed under `C:\\Windows\\Update\\rec\\` | OBSERVATION | filesystem, LNK, VSS, USN | file list or recovered names |
| D11 | SDelete evidence for `rec\\` wipe | OBSERVATION | registry, USN, super timeline | `EulaAccepted` and/or `Z`-pattern wipe evidence |
| D12 | VSS snapshots preserve deleted attacker files | OBSERVATION | VSS | snapshot timestamp and recoverable attacker content |
| D13 | `werfault.exe` and/or `svchost.exe` attacker copies in `C:\\Windows\\Update` | OBSERVATION | ShimCache, Zone.Identifier, timeline | path plus artifact source |
| D14 | `wacsvc` downloaded `bhv.exe` | OBSERVATION | ShimCache, browser history, downloads | `C:\\Users\\wacsvc\\Downloads\\bhv.exe` or equivalent |
| D15 | `bhv.exe` was renamed/deployed as `EdgeUpdater.exe` | OBSERVATION | sigcheck, path correlation, timeline | either rename linkage or same-tool equivalence |
| D16 | `ph.exe` downloaded by `wacsvc` | OBSERVATION | downloads, browser, ShimCache | path or download evidence |
| D17 | `px.exe` downloaded by `wacsvc` | OBSERVATION | downloads, browser | path or download evidence |
| D18 | Defender first quarantines `SRLUpdate.exe` around `2023-01-25 00:41:57 UTC` | OBSERVATION | Defender logs | quarantine event with timestamp |

## Strong Disk Enrichment Findings

These are still useful and should count, but they are secondary to the core set above.

| ID | Finding | Expected Kind | Main Artifact Families | Notes |
|---|---|---|---|---|
| E1 | `wacsvc` first RDP logon from `172.16.6.18` / `phoenix` | OBSERVATION | EVTX | host-local event log evidence is enough |
| E2 | `tdungan` used `runas` against `wacsvc` | OBSERVATION | EVTX | strong pivot indicator from host logs |
| E3 | C$ share mounts from `172.16.6.18` to this host | OBSERVATION | EVTX | acceptable as single-host EVTX evidence |
| E4 | Cobalt Strike PowerShell fingerprint: `-nop -exec bypass -EncodedCommand` | OBSERVATION | PowerShell logs | hunt pattern across ScriptBlock / transcript artifacts |
| E5 | `wacsvc` browsed `secure.csharefile.com` for attacker tooling | OBSERVATION | browser history | any of `bhv.exe`, `ph.exe`, `px.exe` URLs count |
| E6 | `wacsvc` browsed internal `dev01` Elastic/Kibana | OBSERVATION | browser history | useful operator-behavior confirmation |
| E7 | Bitcoin address lookup `18bSTrufLfuvHwS7JYuF626MBGULSmxTgR` | OBSERVATION | browser history | attribution enrichment, not core intrusion proof |
| E8 | `regedit.exe` executed by `wacsvc`, targeting `HKCU\\Environment` | OBSERVATION | UserAssist, Prefetch, RunMRU | operator activity, lower priority |
| E9 | `STUN.exe` compilation time `2023-01-13` near incident date | OBSERVATION | sigcheck / PE metadata | malware characterization enrichment |
| E10 | LNK evidence confirms `wacsvc` opened `C:\\Windows\\Update` and recon outputs | OBSERVATION | LNK | strong disk corroboration |

## Known Benign / Suppression Rules For This Host

These are important so we do not mistake “interesting” for “malicious.”

- `Slack` autostart Run key under `tdungan` is normal on its own.
- The PowerShell warning dates `2022-10-20`, `2022-10-21`, `2022-11-11`, and `2022-11-12` are expected Chocolatey deployment noise and should be filtered during hunting.
- `Notepad++` and `FoxitPDFReader` downloads in `tdungan`'s profile are legitimate by themselves.
- A signed publisher does `not` make a tool benign.
  `bhv.exe` and `EdgeUpdater.exe` are still relevant because attacker use matters more than publisher trust.
- Missing Prefetch is `not` proof of non-execution.
  In this scenario it is suspicious only because other evidence confirms execution.
- `Zone.Identifier` on `werfault.exe` is strong download evidence, but it should be corroborated with path context before becoming a high-confidence finding.
- Pre-incident baseline admin activity, such as older normal admin share access, should not be mixed with incident-period findings.

## Practical Scoring For This Start Baseline

- `TP`
  correct finding on the current host, with correct artifact family and enough provenance to verify it
- `Partial TP`
  correct story, but grouped too broadly, missing provenance, or mislabeled as inference when it should be observation
- `FP`
  surfaced as a finding even though it is not in this host-local baseline and is not clearly marked as hypothesis
- `FN`
  a core disk finding is missing entirely

Important scoring rules:

- one grouped result may satisfy more than one row if it preserves the underlying artifact lineage
- do not score memory-only misses against this disk baseline
- do not score network-wide misses against this disk baseline
- prefer `artifact_path + timestamp + source artifact family` over prose-only matches

## Suggested Initial Metric Slice

For early refinement, score only these first:

1. `Core recall`
   How many of `D1-D18` are found?
2. `Core precision`
   Of findings surfaced as disk findings, how many map cleanly to `D1-D18` or `E1-E10`?
3. `Suppression quality`
   Did the system avoid promoting known-benign rules and weak standalone anomalies?
4. `Provenance quality`
   Did each finding carry enough artifact detail to verify it?

## What To Add Later

When we expand beyond this start baseline, add:

- host-specific baselines for `nromanoff`, `tdungan`, and `controller`
- memory ground truth
- cross-host lateral movement and exfiltration scoring
- final case-wide precision / recall
- promotion-policy scoring across `suppressed`, `candidate`, `inferred`, and `confirmed`

## Source

Derived from:

- [savvydfir_baseline_FULL.md](/home/secsavvy/SAVVYDFIR-MCP/savvydfir_baseline_FULL.md)

This trimmed baseline is intentionally conservative.
It is meant to help us improve the current disk pipeline without pretending we already have complete multi-host evaluation coverage.
