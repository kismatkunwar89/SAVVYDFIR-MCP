# Novel Contribution Statement

**SAVVYDFIR-MCP - FIND EVIL! Hackathon 2026**
**Author:** Kismat Kunwar

> This document was committed before April 15, 2026 (hackathon start date) to establish priority on the three novel contributions described below.

---

## Overview

SAVVYDFIR-MCP extends [Protocol SIFT](https://github.com/teamdfir/protocol-sift) - SANS's own Claude Code DFIR framework - with three capabilities that are absent from all existing published DFIR-LLM systems, including DFIR-Chain (IEEE 2025), Valhuntir (AppliedIR), and the raw Protocol SIFT baseline.

The three contributions address a single root problem: **current LLM-DFIR systems analyze each artifact type in isolation, produce untyped outputs, and have no mechanism to detect or correct contradictions in their own findings.** SAVVYDFIR-MCP solves all three dimensions simultaneously.

---

## Contribution 1: Cross-Artifact Contradiction Detection

### Statement

`compare_disk_and_memory()` automatically identifies forensically significant discrepancies between disk and memory evidence collected from the same host. This capability is absent from all existing Protocol SIFT extensions and published DFIR-LLM systems.

### Technical Detail

The function executes six specific checks against the authoritative case state:

| Check | Disk Evidence Source | Memory Evidence Source | Forensic Indicator |
|---|---|---|---|
| 1. Process no disk binary | `extract_mft_timeline`, `list_deleted_files` | `list_processes`, `scan_processes` | Fileless malware, deleted-after-execution anti-forensics |
| 2. Prefetch/Amcache for deleted binary | `extract_prefetch`, `get_amcache`, `list_deleted_files` | - | Post-exploitation cleanup - binary executed then deleted |
| 3. VAD anomaly on legitimate process | `extract_mft_timeline` (path exists, appears signed) | `detect_injection` | Process hollowing, reflective DLL injection |
| 4. Network connection with no disk artifact | `extract_mft_timeline`, `extract_prefetch` | `scan_network` | Fileless C2, PowerShell/WMI-based lateral movement |
| 5. Registry persistence key → missing binary | `extract_registry_run_keys`, `list_deleted_files` | - | Cleaned malware that achieved persistence before removal |
| 6. $SI vs $FN timestamp mismatch | `extract_mft_timeline` ($STANDARD_INFORMATION vs $FILE_NAME timestamps) | - | Timestomping via `SetFileTime()` API |

Each triggered check produces a `DiscrepancyAlert` with `severity`, `description`, `affected_finding_ids`, and a `recommended_followup` list of MCP tool names to call next.

### Academic Justification

**SynthChain (arXiv, March 2026)** found that the best single evidence source reaches only 0.391 weighted tag/step coverage and 0.403 mean chain reconstruction for software supply chain attacks. A minimal two-source fusion immediately boosts coverage to 0.636 and reconstruction to 0.639 - approximately a 1.6× improvement. SAVVYDFIR-MCP's correlation engine is the operational implementation of this multi-source fusion principle applied to DFIR triage. Citation: SynthChain: A Synthetic Benchmark and Forensic Analysis of Advanced and Stealthy Software Supply Chain Attacks, arXiv:2603.16694, https://arxiv.org/abs/2603.16694.

**DFIR-Chain (IEEE, August 2025)** - the closest prior work - combines Volatility, YARA, and LLMs for automated memory triage but has no cross-source correlation: it analyzes memory in isolation, with no disk-artifact cross-referencing. Citation: DFIR-Chain, IEEE 2025, https://ieeexplore.ieee.org/document/11187513/.

**Lang & Schreck (ACM Digital Threats, December 2025)** demonstrate that LLMs interpreting raw Volatility `malfind` output achieve precision often below 20% across 240 trials. The primary source of false positives is failure to cross-reference memory injection indicators against disk artifacts (e.g., flagging Windows Defender's `MsMpEng.exe` as malicious). Our correlation check 3 (VAD anomaly on legitimate process path) directly addresses this false-positive pattern by checking whether the injected process has a legitimate disk presence. Citation: Lang & Schreck, ACM Digital Threats 2025, https://dl.acm.org/doi/10.1145/3748263.

---

## Contribution 2: Evidence-Triggered Self-Correction

### Statement

The agent's self-correction loop fires when physical evidence contradicts itself - not when the LLM second-guesses its own text. This produces forensically meaningful corrections with auditable provenance, rather than stylistic revisions.

### Technical Detail

A `CORRECTION_EVENT` is logged when:

1. `compare_disk_and_memory()` returns a `DiscrepancyAlert`
2. A tool exits non-zero or returns an empty result set
3. A new finding contradicts a prior `OBSERVATION` or `INFERENCE`

Each event contains: `prior_claim`, `contradiction_source` (which tool or finding triggered the correction), `revised_claim`, `affected_finding_ids`, `confidence_delta`, and `correction_type` (one of `evidence_contradiction`, `tool_error_recovery`, `reclassification`).

The correction sequence:

```
1. Log CORRECTION_EVENT → audit.jsonl (prior_claim, contradiction_source, revised_claim)
2. Downgrade affected findings → evidence_kind: HYPOTHESIS; add to contradicted_by
3. Run recommended_followup tools
4. Re-evaluate:
   - Contradiction confirmed → promote to OBSERVATION with revised_claim
   - Benign explanation found → mark REJECTED with documented reason
5. Record confidence_delta in CorrectionEvent
```

This is a closed loop: corrections never go unresolved. If `max_iterations` is reached before resolution, the contradiction is documented in `CaseState.open_questions`.

### Academic Justification

**ProveRAG (IEEE Access, December 2025)** demonstrates that self-critique with evidence cross-referencing achieves 99% accuracy for exploitation information and 97% for mitigation strategies - vs. 6% for mitigation with prompt-only approaches and 47% with chunking retrieval. SAVVYDFIR-MCP's self-correction loop is the forensic analog of ProveRAG's self-critique mechanism: the agent generates findings, then the correlation engine critiques them using cross-artifact physical evidence. Citation: ProveRAG, IEEE Access 2025, https://ieeexplore.ieee.org/document/11272947/, arXiv:2410.17406.

**PROV-AGENT (IEEE, 2025)** establishes a formal provenance model for agentic workflows using W3C PROV semantics. SAVVYDFIR-MCP's `audit.jsonl` format is PROV-compatible: `Execution` → PROV `Activity`, `Finding` → PROV `Entity`, `CorrectionEvent` → PROV `wasRevisionOf`. The `execution_id` → `finding_id` linkage implements `wasGeneratedBy`. Citation: PROV-AGENT, IEEE 2025, https://ieeexplore.ieee.org/document/11181558/.

**DFIR-Metric (arXiv, May 2025)** evaluated 14 LLMs and found no model fully solved a NIST forensic string search task, with CTF performance peaking at 28% confidence index (GPT-4.1). The multi-step reasoning breakdowns identified in DFIR-Metric are directly addressed by our structured triage phases, which prevent the agent from jumping to conclusions before corroborating evidence is gathered. Citation: DFIR-Metric, arXiv:2505.19973, https://arxiv.org/html/2505.19973v1.

---

## Contribution 3: Architectural Read-Only Enforcement

### Statement

The MCP server enforces zero-spoliation guarantees at the transport layer through backend-owned CLI construction, validated mount options, and deny-listed write operations - not through prompt instructions that can be overridden by a compromised prompt or a jailbreak.

### Technical Detail

The `SafeRunner` base class enforces four layers of protection:

1. **Backend-owned CLI construction** - Claude never constructs or sees raw command lines. Each MCP tool builds the subprocess argument list internally. The LLM calls `detect_injection(dump_path="/evidence/mem.raw", pid=1832)` and the tool constructs `["python3", "/opt/volatility3-2.20.0/vol.py", "-f", "/evidence/mem.raw", "windows.malfind", "--pid", "1832"]`.

2. **`subprocess.run(shell=False)`** - shell=False is enforced at the class level. No string interpolation into a shell string is possible, eliminating shell injection.

3. **Path validation** - every path argument is resolved to absolute form via `Path.resolve()` before being checked against a deny list. This prevents `../../etc/shadow` traversal attacks.

4. **Command deny list** - destructive commands (`rm`, `dd`, `wget`, `curl`, `ssh`, `scp`, `mkfs`, `fdisk`, `shred`, `chmod`) are blocked at the `SafeRunner` level, independent of `settings.json`. Even if `settings.json` is modified by a prompt injection, the `SafeRunner` deny list still applies.

There is no `run_command()` tool that would allow Claude to execute arbitrary commands.

### Academic Justification

**MCP Safety Audit (arXiv, April 2025)** found that current MCP implementations allow major security exploits including malicious code execution, remote access control, and credential theft. The audit specifically recommends: (a) input validation at the tool layer, (b) no generic command execution tools, (c) principle of least privilege. SAVVYDFIR-MCP implements all three recommendations. Citation: MCP Safety Audit, arXiv:2504.03767, https://arxiv.org/abs/2504.03767.

**Forensic integrity standards** from the forensics.wiki NTFS article establish that write access to mounted evidence is the primary spoliation risk in digital forensics. Protocol SIFT uses `ewfmount` with read-only options; SAVVYDFIR-MCP adds a second enforcement layer by denying writes to `/mnt/` and `/cases/*/evidence/` at the MCP transport layer. Citation: forensics.wiki NTFS, https://forensics.wiki/new_technology_file_system_(ntfs)/.

---

## Differentiation from Prior Work

| Capability | Protocol SIFT | DFIR-Chain (IEEE 2025) | Valhuntir (AppliedIR) | **SAVVYDFIR-MCP** |
|---|---|---|---|---|
| MCP server with typed tools | None | None | 86 tools / 8 backends | 24 deep tools |
| Cross-artifact correlation | None | None (memory only) | None | 6 checks, `compare_disk_and_memory()` |
| Evidence-triggered self-correction | None | None | None | `CORRECTION_EVENT` loop |
| Structured audit trail | 1-line summary per session | None documented | None documented | Per-tool-call JSONL with finding linkage |
| Finding data model | None (LLM context only) | None | Findings w/ provenance | Full Pydantic model with `evidence_kind` enum |
| Read-only enforcement | Prompt instructions | Not documented | Not documented | SafeRunner transport-layer enforcement |
| Autonomous execution | Human-driven | Human-driven | Human-in-the-loop | Fully autonomous; self-corrects |

---

## References

1. SynthChain: A Synthetic Benchmark and Forensic Analysis of Advanced and Stealthy Software Supply Chain Attacks. arXiv:2603.16694 (March 2026). https://arxiv.org/abs/2603.16694
2. DFIR-Chain: Integrating Memory Forensics, YARA Scanning, and LLM Summarization for Automated Triage. IEEE (August 2025). https://ieeexplore.ieee.org/document/11187513/
3. Lang & Schreck: Leveraging LLMs for Memory Forensics: A Comparative Analysis of Malware Detection. ACM Digital Threats (December 2025). https://dl.acm.org/doi/10.1145/3748263
4. ProveRAG: Provenance-Driven Vulnerability Analysis with Automated Retrieval Augmented Generation. IEEE Access (December 2025). https://ieeexplore.ieee.org/document/11272947/; arXiv:2410.17406
5. PROV-AGENT: Unified Provenance for Tracking AI Agent Interactions in Agentic Workflows. IEEE (2025). https://ieeexplore.ieee.org/document/11181558/
6. DFIR-Metric: A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response. arXiv:2505.19973 (May 2025). https://arxiv.org/html/2505.19973v1
7. MCP Safety Audit: LLMs with the Model Context Protocol Allow Major Security Exploits. arXiv:2504.03767 (April 2025). https://arxiv.org/abs/2504.03767
8. forensics.wiki: New Technology File System (NTFS). https://forensics.wiki/new_technology_file_system_(ntfs)/
