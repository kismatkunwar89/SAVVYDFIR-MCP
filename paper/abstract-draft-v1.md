# Workflow Contracts and Provenance Chains for LLM-Mediated Digital Forensics: A Case Study with the SAVVYDFIR-MCP Framework

**Target venue:** DFRWS APAC 2026
**Authors:** Kismat Kunwar [+ co-authors TBD]
**Abstract draft v1 — 2026-05-26**

---

## Abstract (target: 250–300 words)

Large Language Model (LLM) agents are increasingly proposed as digital
forensic co-pilots, yet existing work rarely addresses two failure modes
critical to evidentiary integrity: (1) LLM agents silently skip mandatory
forensic steps under context-window pressure and subsequently misreport
"skipped" as "failed", and (2) LLM-generated findings lack source-traceable
provenance, making them inadmissible under chain-of-custody scrutiny. We
present SAVVYDFIR-MCP, an open-source DFIR framework that addresses both
through architectural primitives rather than prompt engineering: (a)
PreToolUse workflow contracts that block phase transitions until mandatory
tools have either succeeded or recorded explicit absence markers, and (b)
CTX provenance chains that link every finding `F-N` to a source heuristic
`.md` file via the chain `F-N → execution_id E-N → context_id CTX-N →
canonical_path + SHA-256_hash`. The framework exposes 56 typed forensic
tools to Claude Code via the Model Context Protocol (MCP), deterministically
injects DFIR heuristic slices at tool-response time (a two-tier
alternative to retrieval-augmented generation), and enforces a Section 3-
lite finding schema requiring `alternative_hypothesis`, `evidence_against_it`,
and `disposition` for any finding promoted to CONFIRMED. We evaluate across
two publicly available SANS intrusion datasets (HACKATHON-2026-WKSTN01,
ROCBA Standard Forensic Case) over nine iteration runs (~30 hours of
agent execution). We document empirically that, prior to phase-gate
enforcement, the agent skipped 3/7 mandatory Phase 2 disk-extraction tools
and falsely claimed they had failed; after enforcement, coverage rose to
7/7 with no narrative-fact divergence (validated by audit-log cross-check).
We contribute the framework (MIT-licensed), a court-defensibility
checklist for AI-DFIR outputs, and a reproducible methodology for
evaluating agentic forensic systems on public datasets.

---

## Keywords (5–7)
LLM agents, digital forensics, Model Context Protocol (MCP), chain of
custody, provenance, workflow enforcement, court-defensible AI

---

## Why this fits DFRWS APAC 2026

| DFRWS scope criterion | How this paper fits |
|---|---|
| Novel methods + measurable evaluation | CTX provenance chain + 9-run empirical data |
| Reproducibility | Open source v1.0.0-rc.1, public SANS datasets |
| Operational relevance | Built for SIFT Workstation, used in hackathon |
| Honest reporting | Documents Run 8 failures explicitly + the fix |
| Cross-cutting (AI + forensics) | MCP is a 2024 protocol, first DFIR application |

---

## Open questions for co-authors

1. **Comparative baseline strength** — for full paper, do we benchmark against
   (a) human analyst time on same dataset, (b) Plaso-only timeline analysis,
   (c) commercial AXIOM/Magnet output? Pick one for the paper or include all?

2. **Statistical rigor** — 9 runs is real but small. Do we need to commit to
   3+ runs per configuration (with-gate vs without-gate) for proper
   significance, or is documented before/after sufficient for DFRWS?

3. **Dataset count** — HACKATHON + ROCBA is 2. A third (e.g. one of the
   other SRL-2018 hosts: DC, FILE, WKSTN-05) would strengthen the agnostic
   claim. ~1 week extra work per host.

4. **Author list** — solo author OK for DFRWS APAC, or do we want a faculty
   co-author for institutional credibility?
