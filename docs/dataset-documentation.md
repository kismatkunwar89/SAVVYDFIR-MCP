# Dataset Documentation

**SAVVYDFIR-MCP — Evaluation datasets**

SAVVYDFIR-MCP was evaluated on five independent DFIR cases. Evidence images are
**not** committed to this repository; ground-truth answer keys are kept analyst-side
(`scripts/eval/ground_truth/`, gitignored — never on the workstation). This document
records each dataset's provenance, scope, and source. Results are in
[`accuracy-report.md`](accuracy-report.md); full run artifacts in
[`agent-execution-logs/`](agent-execution-logs/).

## Datasets

| Case ID | Scenario | OS | Source | Provenance |
|---------|----------|----|--------|------------|
| `NIST-DATALEAK-2015-PC` | insider data leak | Windows (disk-only) | [NIST CFReDS](https://cfreds.nist.gov) "Data Leakage" | NIST (U.S. Gov, public domain). GT from the official answer key. |
| `NIST-HACKINGCASE-2004-MREVIL` | war-driving / credential theft | Windows XP | [NIST CFReDS Hacking Case](https://cfreds-archive.nist.gov/Hacking_Case.html) | NIST (public domain). GT from the official 31-question answer key. EnCase image, MD5 `aee4fcd9301c03b3b054623ca261959a`. |
| `ALI-WEBSERVER-WIN-L0ZZQ76PMUF` | web-server breach (XAMPP/DVWA) | Windows Server 2008 | [Ali Hadi DFIR Challenge #1](https://www.ashemery.com/dfir.html) | Public training case. GT cross-corroborated from published walkthroughs (instructor key not public). |
| `ROCBA-2020-FREDS-LAPTOP` | insider IP theft | Windows | SANS course material | Synthetic course dataset (not public); used per course terms. |
| `LONEWOLF-2018-DESKTOP-PM6C56D` | mass-shooting plot | Windows | SANS course material | Synthetic course dataset (not public); used per course terms. |

## Ground-truth methodology

Ground truth for each case was established **without LLM involvement** — from the
dataset's official answer key (NIST cases), cross-corroborated public walkthroughs
(Ali Hadi), or the case's forensic report (SANS cases) — and encoded as an answer-key
YAML with distinctive anchors and known-negatives. The scorer
(`scripts/eval/gt_match_scorer.py`) matches the agent's findings against it. See
[`eval-methodology.md`](eval-methodology.md).

## Integrity & privacy

- Evidence images are referenced by path only; they are not redistributed here.
- NIST CFReDS data is U.S. Government public-domain. The Ali Hadi case is public
  training material. The two SANS-course datasets are synthetic (no real PII) and
  are not redistributed.
- Image hashes (where published by the source, e.g. the NIST Hacking Case MD5) were
  verified on download.

## Not included

A multi-host enterprise corpus (SANS Realistic Lab, SRL-2018) is supported by the
framework's multi-host pipeline (`merge_host_graphs`, `build_reports_index`) but was
**not** run for this submission — it is deferred future work, not part of the
reported results above.
