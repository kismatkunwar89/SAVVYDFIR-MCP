# Paper Plan — Handoff Document

**Date locked:** 2026-05-26
**Authors:** Kismat Kunwar
**Status:** Plan locked via 4 rounds of tri-agent consensus (Claude + peer reviewer + peer reviewer)
**Do not delete.** Reference document for paper writing work.

---

## 0. CRITICAL — Paper vs Hackathon are SEPARATE

This document is about the **academic paper**, NOT the SANS hackathon submission.

| Aspect | SANS Hackathon Submission | This Paper (DFRWS APAC 2026) |
|---|---|---|
| **What** | SAVVYDFIR-MCP tool + 8 runs + open-source code | A proposed methodology (FFAI-DI), shared so investigators don't reinvent it |
| **Approach** | Tool-first: "here is our framework, here are runs" | Methodology-first: "here is a way of working, applicable to any tool" |
| **Subject** | SAVVYDFIR-MCP is THE subject | SAVVYDFIR-MCP is referenced once as existence proof |
| **Audience** | Hackathon judges, SANS community | DFRWS APAC research community, forensic methodology readers |
| **Document** | Repository + writeup + demo | 10pp double-blind peer-reviewed paper |
| **Independence** | Submitted separately to SANS hackathon | Submitted separately to DFRWS APAC research track |

**Do NOT combine the two submissions.** The hackathon submission and the academic paper serve different purposes and audiences. The paper is informed by the lessons learned during the hackathon work but is not a writeup of it.

---

## 1. Paper Identity (LOCKED)

| Field | Value |
|---|---|
| **Working title** | "Forensics-First, AI-Second: A Methodology for AI-Augmented Digital Investigation" |
| **Optional subtitle** | "Reference Instantiation and Case Evaluation" |
| **Methodology name** | FFAI-DI (Forensics-First AI-Augmented Digital Investigation) — defined once in §3, prose elsewhere |
| **Paper type** | Proposal/methodology paper (Studiawan-template precedent) |
| **Target venue** | DFRWS APAC 2026, research-paper track |
| **Format** | 10 pages, two-column, double-blind |
| **Proceedings** | DFRWS APAC + Elsevier *Forensic Science International: Digital Investigation* |
| **Author** | Solo (Kismat Kunwar); faculty co-author optional |
| **Code disclosure** | Anonymized via `anonymous.4open.science` for blind submission; real GitHub link in camera-ready |

---

## 2. The Contribution (LOCKED)

Paper proposes the **FFAI-DI methodology** with five requirements. Each requirement is **portable** (any DFIR team can adopt with their own tools) and is paired with our **reference binding** (how we implemented it in SAVVYDFIR-MCP — referenced once, not the contribution).

### Five Methodology Requirements

| # | PORTABLE REQUIREMENT | REFERENCE BINDING (ours) |
|---|---|---|
| **R1** | Evidence mediation — bulk artifacts never enter LLM context | `csv_path` handles + locally-executed `run_analysis(pandas_code)` on MCP server |
| **R2** | Workflow contracts — mandatory steps enforced before phase transition | PreToolUse hook on Claude Code (`workflow-enforce-pre.py`) |
| **R3** | CTX provenance — source-traceable findings (finding → execution → context → canonical heuristic source + SHA-256) | CTX-N chain in `_contracts.py` writing to `audit.jsonl` |
| **R4** | Section 3-lite finding schema — alternative-hypothesis + disposition required for CONFIRMED findings | Pydantic schema in `models/evidence_finding.py` with `disposition` enum gate |
| **R5** | Honest narrative under context pressure — audit-cross-checked agent claims | Audit-log vs narrative diff script (recommended addition, see blockers) |

The contribution is the **requirement set**, not the implementation. Readers adopt the methodology in their own tooling (Magnet, Autopsy, custom Plaso pipelines, etc.).

---

## 3. Empirical Anchor (LOCKED)

- **One case study:** HACKATHON-2026-WKSTN01 (Run 7 data, already captured in `runs/run-7-rocba/` and earlier run captures)
- **One traceability table:** Requirement → reference binding → case-study evidence → measured outcome
- **Documented failure mode:** Run 8 honesty failure (skipped Phase 2 tools, agent narrative claimed they failed) — described abstractly as forensic-specific agent failure mode, with workflow contracts as the architectural mitigation
- **NO statistical N-runs:** Studiawan/Khalid precedent — single case study walkthrough is sufficient at this venue

---

## 4. Custody Framing (mandatory in paper)

**Data-flow table required:**

| Artifact class | Storage location | Crosses LLM boundary? | Retention risk | Mitigation |
|---|---|---|---|---|
| Raw E01 / memory dumps | Local (`/evidence/`) | **NO** | None — architectural | Read-only RBAC |
| Full MFT / EVTX / Amcache CSVs | Local (`/cases/...`) | **NO** | None — handle-only | `csv_path` mediation |
| State + audit ledger | Local (`analysis/`) | **NO** | None | Append-only |
| Generated reports | Local (`reports/`) | **NO** | None | Operator-controlled |
| **Heuristic slices (.md content)** | **Local source** | **YES** (in prompts) | Anthropic retention policy | Local-LLM eliminates |
| **Tool response summaries** | **Local source** | **YES** (in prompts) | Anthropic retention policy | Local-LLM eliminates |
| **Investigation narrative + findings prose** | **Local source** | **YES** (in prompts) | Anthropic retention policy | Local-LLM eliminates |

**Position in paper:**
- Bulk evidence stays local (real architectural property — defensible)
- Derived summaries cross LLM boundary **per deployment profile**
- **Local-LLM (Ollama / llama.cpp / vLLM) as canonical case** in the paper
- **Cloud LLM (Claude API) as evaluated variant** — honest disclosure
- Cite Carrier's "data never leaves your control" principle and explicitly position our work within it

**Anti-pattern to avoid:** Saying "data never leaves your control" while using Claude API. That conflates bulk-evidence custody (true) with derived-info custody (not true under cloud LLM). Both peer reviewer and peer reviewer flagged this as desk-reject risk.

---

## 5. Paper Structure (LOCKED — 10pp)

| § | Section | Pages | Content |
|---|---|---|---|
| 1 | Introduction + problem | ~1.5 | DFIR investigators waste time on AI-augmentation rediscovery; no shared methodology |
| 2 | Background + related work | ~1.5 | Carrier, Casey, Studiawan 2025, Khalid 2024, Gruber 2024, Lee 2025, Cellebrite messaging |
| 3 | FFAI-DI Methodology | ~2 | Five portable requirements articulated + named once |
| 4 | Method components | ~1.5 | Five requirements detailed with portable/binding split |
| 5 | Reference instantiation | ~1.5 | MCP-based prototype, generic architecture, single proper noun mention |
| 6 | Case study + traceability table | ~1.5 | HACKATHON-2026-WKSTN01 walkthrough demonstrating the methodology + Run 8 failure mode + mitigation |
| 7 | Deployment profiles + custody data-flow | ~0.5 | Local vs cloud LLM, custody tiers, evidence-boundary disclosure |
| 8 | Discussion + limitations + research agenda | ~0.5 | Honest limitations, future work, open research questions |

---

## 6. Open Blockers (CONFIRMED by peer reviewer in Round 4 sign-off)

| # | Blocker | Status | When in schedule |
|---|---|---|---|
| 1 | **Run 9** — Phase 3 entry gate validated end-to-end | ✅ **CLEARED 2026-05-26** — ROCBA-2020-FREDS-LAPTOP completed with 63 findings, 3 CONFIRMED, all 5 case-briefing questions answered. Captured at `runs/run-9-rocba/`. | — |
| 2 | **Traceability table** — 5 requirements with real numbers (not `[RECORD]` placeholders) | OPEN | Week 4 |
| 3 | **Dataset license framing** — remove "publicly available" language; use "licensed forensic corpora with released audit methodology" if SRL-2018 is educational-only | OPEN | Week 1 |
| 4 | **Custody data-flow table** — built per the table in §4 above | OPEN | Week 4 |
| 5 | **Abstract written** — Studiawan-template, methodology-first lede, SAVVYDFIR-MCP mentioned once, no court-admissibility overclaim | OPEN | Week 1 |
| 6 | **Anonymous repo mirror** — set up via `anonymous.4open.science` for double-blind submission | OPEN | Week 5 |

**Non-blocking but strongly recommended:**
- Baseline experiment (with-gate vs without-gate) on same manifest, even N=1, for §6
- `scripts/validate_run.py` outputs cited as evidence in §6
- One additional run (Run 10) to demonstrate methodology stability

---

## 7. Workload + Timeline (4-5 weeks, solo author)

**Assumes DFRWS APAC 2026 deadlines** (need to be confirmed against actual CFP):

| Week | Deliverable |
|---|---|
| **Week 1** | 500-word abstract + §1 (intro) + §2 (related work) + license framing fix |
| **Week 2** | §3 (methodology) + §4 (components) |
| **Week 3** | Run 9 (Phase 3 gate validation) + §5 (reference instantiation) + §6 (case study) |
| **Week 4** | §7 (custody data-flow table) + §8 (discussion) + traceability table |
| **Week 5** | Polish + anonymize for blind review + set up `anonymous.4open.science` + submit |

**Critical path:** Run 9 is the longest blocking dependency (1 day of compute) and must happen by Week 3.

---

## 8. Consensus History (Rounds 1-4)

### Round 1 (2026-05-26)
- **Topic:** Initial paper-angle selection
- **Verdict:** Angle A (code-mediation tool paper)
- **User feedback:** Rejected — too narrow

### Round 2 (2026-05-26)
- **Topic:** Independent research on prior art + venue
- **Findings:** Heavy prior-art pressure (Studiawan, Khalid, Gruber, Lee, Carrier, Cellebrite). DFRWS APAC research track requires implementation + evaluation. No position-paper lane in main track. peer reviewer caught 3 fatal blockers (dataset license trap, reproducibility broken, dataset story split 3 ways).
- **Verdict:** GO with hybrid framing — operating model + Angle A as empirical proof

### Round 3 (2026-05-26)
- **Topic:** Methodology-first vs tool-first framing
- **Verdict:** GO with hybrid — named methodology (FFAI-DI), understated prototype reference, requirement-satisfaction evaluation
- **peer reviewer's amendment:** Each requirement must be labeled PORTABLE + REFERENCE BINDING (so the methodology is genuinely portable, not tool-specific)
- **User refinement:** Independent of SANS hackathon — paper is pure proposal so investigators don't waste time

### Round 4 (2026-05-26 — final sign-off)
- **peer reviewer:** CONDITIONAL SIGN-OFF (6 blockers listed, no framing dissent)
- **peer reviewer:** Round 3 sign-off carries (Round 4 hit usage limit; retry not required since Round 3 was unambiguous)

**Audit transcript:** `/tmp/peer-review/conversation.jsonl`

---

## 9. Prior Art (must cite + differentiate)

| Paper / source | Venue / year | What they did | Our differentiation |
|---|---|---|---|
| **Studiawan, Breitinger, Scanlon** — Towards a standardized methodology for evaluating LLM-based DF timeline analysis | DFRWS APAC 2025 | Proposed methodology for **evaluating** LLM-DF | We propose methodology for **conducting** AI-augmented investigation under forensic constraints |
| **Khalid, Iqbal, Fung** — Towards a unified XAI-based framework for DF | DFRWS APAC 2024 | XAI framework for ML-based forensic predictions + case study | Different scope — workflow mediation with provenance, not XAI explanation generation |
| **Gruber & Freiling** — The Cyber-traceological Model | DFRWS APAC 2024 | Model-based investigative reasoning | Cite as prior art for "case model" terminology; our state ledger is structured, not their full traceological model |
| **Lee et al.** — DF-Graph: Structured and explainable analysis | DFRWS APAC 2025 | Graph-RAG + forensic QA with citations | Our provenance is finer-grained (heuristic source + SHA-256 + execution_id) |
| **Voigt, Freiling, Hargreaves** — Re-imagen (synthetic forensic data) | DFRWS APAC 2024 | LLM-generated background activity | Different problem space — they generate test data, we mediate investigation |
| **Brian Carrier** — public DFIR+AI principles | LinkedIn/blog | Human control, traceability, verification, refutation, AI disclosure, customer-cloud LLM | **HIGHEST narrative threat** — must cite and align; our paper adds operationalizable mechanisms |
| **Cellebrite / Magnet AXIOM AI** | Commercial messaging | Purpose-built forensic AI with artifact-level traceability | Our work is open, auditable, methodology-portable; commercial is closed-source assistant |

**Motivation-only (NOT proceedings-cited):**
- Rob van Os, "AI-driven SOC" (LinkedIn thought piece — one paragraph motivation max)

---

## 10. What to Reuse / What to Build

### Reuse (already exists in repo)

- **CLAUDE.md** — 7-phase methodology (we follow established DFIR methodology, paper can cite)
- **`workflow-enforce-pre.py`** — PreToolUse Phase 3 gate (reference binding for R2)
- **`_contracts.py`** — CTX provenance injection (reference binding for R3)
- **`models/evidence_finding.py`** — Section 3-lite schema (reference binding for R4)
- **`audit.jsonl` + `state.json`** — Audit chain artifacts
- **Run 1-7 captured data** — Empirical anchor for case study
- **Run 8 honesty failure** — Documented failure mode for §6
- **`docs/correlation-methodology.md`, `docs/forensic-artifacts.md`** — Background DFIR methodology citations

### Build (new for paper)

| Item | Purpose | Effort |
|---|---|---|
| Run 9 (Phase 3 gate validation) | Empirical anchor for §6 | 1 day compute |
| Traceability table population | §6 evidence | 1 day |
| Custody data-flow table | §7 honesty | 4 hours |
| Anonymous repo mirror | Blind submission | 30 min |
| Audit-vs-narrative diff script | R5 reference binding evidence | 4 hours |
| 500-word abstract | Submission | 1-2 days |
| Full 10pp paper | Submission | 4-5 weeks total |

---

## 11. Anti-Patterns (explicitly REJECTED in consensus)

- ❌ **"SAVVYDFIR-MCP: A Framework for..."** — Tool-first title rejected in Round 3
- ❌ **Statistical RCT with N=3+ runs** — Not required at venue per Studiawan/Khalid precedent
- ❌ **"Publicly available SANS datasets"** — License trap (SRL-2018 is educational-only)
- ❌ **"Bulk forensic data never leaves analyst control"** — Conflates bulk evidence custody (true) with derived-info custody (false under cloud LLM)
- ❌ **"Court-admissible / inadmissible"** — Legal overreach without counsel review
- ❌ **"Continuously updated probabilistic case model"** — `state.json` is a structured ledger, not probabilistic; calling it probabilistic is desk-reject bait
- ❌ **Combined paper + hackathon writeup** — Separate documents, separate audiences
- ❌ **Pure essay without implementation evidence** — DFRWS APAC research track requires demonstration
- ❌ **Heavy SOC analogy from Rob van Os** — LinkedIn thought piece, motivation only (1 paragraph max)
- ❌ **Statistical claims about LLM outputs** — Non-deterministic; claim deterministic FRAMEWORK properties instead

---

## 12. Key Definitions

| Term | Meaning |
|---|---|
| **FFAI-DI** | Forensics-First AI-Augmented Digital Investigation (the methodology this paper proposes) |
| **Portable requirement** | A methodology rule that any DFIR team can adopt with their own tooling |
| **Reference binding** | How we implemented a requirement in SAVVYDFIR-MCP (not the contribution, just demonstration) |
| **CTX provenance** | Source-traceable finding chain: F-N → E-N → CTX-N → canonical heuristic .md + SHA-256 |
| **Section 3-lite finding schema** | Pydantic schema requiring `alternative_hypothesis` + `evidence_against_it` + `disposition` for CONFIRMED status |
| **Workflow contract** | Pre/post hook that enforces methodology rules at tool-invocation time |
| **Evidence mediation** | Pattern where the LLM never sees bulk artifacts; only handles + filtered query results |
| **Case study system** | The reference instantiation used for the case study (= SAVVYDFIR-MCP, but referred to neutrally) |

---

## 13. Open Questions Still Pending User

1. **DFRWS APAC 2026 actual deadlines** — what are dates "9" and "5" you mentioned? Need to look up the actual CFP to confirm. → User to confirm OR Claude to look up.
2. **Acronym vs prose** — Lock FFAI-DI as the acronym, or use prose only ("forensics-first AI-augmented investigation")? → User decision before §3 written.
3. **Dataset commit** — HACKATHON-2026-WKSTN01 Run 7 confirmed as the canonical case study? → User confirm.
4. **Faculty co-author** — Solo or co-authored? peer reviewer said nice-to-have, not blocking.
5. **Run 9 timing** — Need to launch before Week 3; ready when user authorizes.

---

## 14. Files Created So Far

| File | Status | Notes |
|---|---|---|
| `paper/abstract-draft-v1.md` | **SUPERSEDED** | First draft was Angle A framing; new draft will be methodology-first per Round 3 consensus. Keep as historical artifact but do not use. |
| `paperplanhandoff.md` (this file) | **CURRENT** | The locked plan and reference document |

---

## 15. Next Concrete Step

After user confirms (1) DFRWS APAC 2026 deadlines and (2) FFAI-DI naming preference:

**Day 1 task:** Write the 500-word abstract under the locked methodology-first framing, using Studiawan 2025 abstract as structural template.

---

**End of handoff document.** This document is the source of truth for the paper plan. Any future paper work should reference this file first.
