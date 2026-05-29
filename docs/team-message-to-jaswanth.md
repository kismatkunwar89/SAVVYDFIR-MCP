# Message to Jaswanth — FIND-EVIL Architecture Direction (v2, tri-agent reviewed)

Hey Jaswanth —

Read all three of your docs (Integration Handoff, ADK Build Scaffold, KNOX-ADHD Dry-Run) plus the trajectory HTML. The architectural thinking is genuinely strong — your bridge facade design, FindingPayload contract concept, negative attestations, GPG-signed provenance — these are real wins. I want to be honest about what we should ship together for 2026-06-15 and what we should hold for after.

This message went through tri-agent adversarial review (Claude + peer reviewer + peer reviewer with repo access). Corrections caught:

- Our `sift_mcp/server.py` exposes **56 MCP tools** (verified: `grep -c "^@mcp.tool" sift_mcp/server.py` = 56). Your docs said 56; that was right. My earlier reply said 31 — that was wrong. Apologies.
- Our actual finding contract is **`EvidenceFinding`** (Pydantic, `sift_mcp/models/evidence_finding.py`) submitted via **`submit_finding`** returning `F-NNN + execution_id`. Your "FindingPayload" concept maps to this — but please build to the existing schema, not a new name.
- Authoritative tool catalog at runtime is `describe_tool_catalog()` — use this, not a hardcoded count.

---

## 1. Current state of SAVVYDFIR-MCP — what's true today

- Master is at commit `13fd348`. Pushed today after a long bug-fix session.
- Four critical evaluator-readiness bugs fixed today and on master:
  - `install.sh` was deploying a stale HOME `~/.claude/settings.json` over the project-local one → `claude login` crashed for fresh users (fix: don't deploy; project-local is source of truth). Commit `89ed2f5`.
  - `.mcp.json` hardcoded `/opt/SAVVYDFIR-MCP/server.py` — broken on any non-cloud install. Now uses `./venv/bin/python3 -m sift_mcp.server` (relative). Commit `99e145b`.
  - `.claude/settings.json` hooks invoked system `python3` which has no pydantic on Ubuntu 24.04 → all 5 hooks silently failed with `ModuleNotFoundError` → cascade misdiagnosed as "Fix case-templates/manifest.json". Now uses `./venv/bin/python3`. Commit `13fd348`.
  - `SafeRunner.drop_captured_output(keep_chars=8192)` was truncating ALL tool stdout to 16 KB — meant for dotnet OOM mitigation, broke Vol3 JSON output → `scan_processes` parsed 0 rows from a 731 KB stdout on a 2,186-row pslist. Fixed via per-runner opt-out class attribute. Same commit.
- Run history: README documents prior **Run 9 = 63 findings**, full 7-phase ROCBA-style case, full report + graph. That's the baseline maturity.
- Currently in-flight: a fresh ROCBA Phase 1 run that I halted earlier to discuss your docs — produced 23 memory-pillar findings (vs the broken pre-fix run's 1). That's an interrupted preview, not submission output.

What's framework-agnostic in our stack:
- `sift_mcp/server.py` — 56 forensic tools over FastMCP stdio
- `audit.jsonl` and `state.json` — plain JSON
- All tool runners (`sift_mcp/runners/*`) — pure Python subprocess wrappers
- Evidence integrity (RBAC, read-only mounts) — enforced inside `server.py`

What's bound to Claude Code:
- `.claude/hooks/*.py` (PreToolUse, PostToolUse, Stop, SessionStart) — Claude Code hook schema, no portability to other agent runtimes
- `scripts/agent_trigger.py` — references Claude Task tool + delegate_queue
- `CLAUDE.md` + `.claude/skills/investigation-workflow/SKILL.md` — Claude system prompt + skill schema
- Coverage gate (`.claude/hooks/workflow-enforce-post.py:MANDATORY_PHASE_TOOLS`) matches on specific `mcp__savvydfir__*` tool names — this is what produces our `CorrectionEvent` audit rows = criterion #1 tiebreaker proof

The MCP layer is the durable asset. The orchestrator is the swappable layer.

---

## 2. Time reality — deadline logic, not dev-day math

17 days to 2026-06-15. Beyond engineering, calendar time gets consumed by 8 submission components (GitHub repo, demo video ≤5 min, architecture diagram, written description, dataset docs, accuracy report, try-it-out instructions, execution logs). Two of those (demo video + accuracy report) need a stable, working pipeline to record against — they can't start until the pipeline is locked.

This makes an ADK orchestrator swap **out of scope** before 2026-06-15. Not because the idea is bad, but because re-platforming the enforcement plane that produces our criterion-#1 self-correction proof, and stabilizing the new plane well enough to record a 5-minute demo against, won't fit alongside the 8-component submission packaging burn.

A bounded **MCP-contract portability POC** is in scope and is genuinely the strongest architectural-judging story we can tell — see §3.

---

## 3. What we propose — contract-level portability POC (not peer pipeline)

**Critical reframe from my earlier message:** I previously proposed a "head-to-head comparison run" — same evidence through both pipelines, compare findings. The tri-agent review correctly flagged this as asymmetric submission risk:

- Claude Code path runs the full 7-phase workflow with mandatory `sigma_hunt`, `compare_disk_and_memory`, per-PID `list_dlls`, etc. — gated coverage.
- An ADK POC with 2-3 MCP tool calls will produce sparse output by design.
- A side-by-side comparison where one path is mature and the other is minimal-by-scope does NOT look like portability proof. It looks like a broken second product, and it hurts criterion #2 (IR Accuracy).

The right framing is **contract-level portability**, not investigative-output parity. What we prove:

> "The MCP server is a stable, typed forensic execution contract. Two different orchestrators — Claude Code (analyst workbench) and an ADK service (architectural portability proof) — both successfully call into it, produce valid `EvidenceFinding` records, and write to the same `audit.jsonl` ledger with linked `execution_id`s. The MCP layer is framework-neutral."

That sentence is the criterion #4 (architectural vs prompt-based) winner. The architectural enforcement is the MCP contract itself, not a specific orchestrator.

### Submission architecture

| Layer | Hackathon role |
|-------|----------------|
| `sift_mcp.server` — 56 tools, FastMCP stdio | Primary forensic execution. Unchanged. |
| Claude Code | Primary orchestrator. Runs the full investigation demo. Records criterion-#1 self-correction proof via hooks. |
| ADK POC client (your build) | **Appendix-tier** portability proof. Demonstrates one MCP session against the same server, produces ≥1 valid `EvidenceFinding`, writes 1 `audit.jsonl` row with resolvable `execution_id`. ~30-second clip in demo video, not equal runtime. |
| GPG-signed report git repo | Tamper-evident provenance on the final report output. |
| Negative attestations | Formal contract — `negative_attestations[]` field on the report payload, derived from real `run_analysis` executions with 0-row results. |

The submission diagram shows Claude Code as the primary client of MCP. The ADK POC appears in an **appendix box** labeled "Alternate MCP Client — Portability Proof", with one arrow back to MCP. Single primary, one appendix. No parallel-pipeline implication.

(Note: my `docs/ENTERPRISE-ADK-LAYER.md` describes a post-hackathon two-client production deployment where ADK becomes the primary service client and Claude Code becomes the analyst workbench. That's the Q3/Q4 2026 picture, not the submission picture. The submission diagram and the enterprise diagram are different — and that's intentional and explained in the write-up.)

---

## 4. What from your design becomes the submission

Adopted with explicit credit to your design influence:

1. **GPG-signed report git repo (your ITEM-3 idea).** After `generate_report` finishes, `reports/<case_id>/` gets `git init` + GPG-signed commits using a project demo key. `verify-report.sh` proves any tampering. MCP team owns implementation (~1h). Caveat from review: signing UX must be reproducible — broken GPG verification is worse than unsigned `git init` with tree-hash in `audit.jsonl`.

2. **Negative attestations (your ITEM-4 / FindingPayload concept).** New `negative_attestations[]` field on the report payload. Each entry: `{query_description, search_scope, execution_id, search_bounds, result: "not_found"}`. MUST be derived from real `run_analysis` executions where bounds covered the search window AND the dataframe returned 0 rows. Hard constraint: not LLM-generated prose. MCP team owns implementation (~2h). Surfaces in `report.html` as an explicit "Negative Findings" section.

Owned by you:

3. **ADK POC client in a separate `findevil_service/` package.** Lives outside `sift_mcp/`. Spawns `./venv/bin/python3 -m sift_mcp.server` as a stdio subprocess (the post-fix invocation). Discovers the tool catalog via `describe_tool_catalog()` — do NOT hardcode tool counts. Calls 2-3 MCP tools end-to-end (suggested chain: `start_investigation` → one extraction such as `list_processes` → `submit_finding`). Returns a valid `EvidenceFinding` with `F-NNN` + resolvable `source_execution_id`. Estimated 3-4 dev-days. NOT trying to be the primary orchestrator. PROVING contract portability.

4. **Dual-client architecture diagram.** Single diagram. Primary: Claude Code → MCP → forensic output. Appendix: ADK client → MCP (same server) → `submit_finding` proof. Caption: "MCP forensic contract is framework-agnostic; primary workbench client and architectural portability proof both validate against the same audit ledger." 1 day.

5. **Your contribution section in the submission write-up.** Section that names you as architectural co-designer: dual-client design, negative-attestation contract, GPG provenance chain, post-hackathon enterprise direction (referencing `docs/ENTERPRISE-ADK-LAYER.md`). You write this directly.

---

## 5. Hard constraints — what your POC must respect

- **No edits to `.claude/hooks/`, `.claude/settings.json`, `CLAUDE.md`, or `.claude/skills/`** before 2026-06-15. These are the criterion-#1 self-correction enforcement plane; touching them risks the working pipeline.
- **MCP server invocation:** `./venv/bin/python3 -m sift_mcp.server` (the post-fix relative path). Do NOT hardcode `/opt/SAVVYDFIR-MCP/...` like the prior handoff doc — that path doesn't exist on a fresh install.
- **Tool catalog:** discover at runtime via `describe_tool_catalog()`. Don't hardcode counts.
- **Finding contract:** call `submit_finding(...)` with proper `EvidenceFinding` fields (schema in `sift_mcp/models/evidence_finding.py`). Must produce `F-NNN` + resolvable `source_execution_id` in `audit.jsonl`. This IS the FindingPayload concept — built to the actual repo schema.
- **Output paths:** write under `analysis/` or `reports/` only. Never `/evidence/` or `/mnt/` (RBAC enforced in `server.py`).
- **Timestamps:** UTC, ISO-8601. Use the `timestamp_observed` field convention introduced today (commit `13fd348` precursor work).
- **`audit.jsonl`:** schema v2 row with `execution_id` linkage. Your POC's audit row should be indistinguishable in shape from a Claude Code-originated row.

---

## 6. Abort condition

If your POC isn't producing **one valid `submit_finding(...)` call that returns `F-NNN` with a resolvable `execution_id` in `audit.jsonl`** by 2026-06-08 (Day 10, 7 days before deadline), we drop the ADK demo client from submission. You stay on as architecture-diagram + write-up contributor + post-hackathon ADK owner per the enterprise direction doc.

This is not a fail signal — it's calendar protection. The 7-day buffer is required for demo video recording, accuracy report writing, and submission packaging. If we miss that window with both pipelines live, we miss with neither.

Why this specific bar: `submit_finding` + resolvable `execution_id` is the smallest verifiable contract artifact that proves the MCP layer accepted a non-Claude-Code client. It's binary — either the audit row exists with linkage, or it doesn't. No "almost there" ambiguity.

---

## 7. What we are NOT doing

(Tri-agent consensus rejections, with brief why — all in the formal `review-findevil-integration-2026-05-29.md` doc if you want the verbatim reviewer quotes):

- **Full ADK orchestrator swap.** Discards the Claude Code hook plane that produces criterion-#1 proof. 17 days insufficient for re-platform + re-record demo.
- **2-tool facade replacing Claude Code's 56-tool MCP surface.** Our hook coverage gate (`.claude/hooks/workflow-enforce-post.py:MANDATORY_PHASE_TOOLS`) matches on specific tool names — a facade routing everything as `safe_route(...)` would silently break the gate. The facade IS the right shape for YOUR ADK package's own surface; don't apply it to Claude Code's surface.
- **Replay verification gate** (your Pattern 3). Doubles wall-clock per case (~75-90min → ~150-180min), no judging scoring line for replay, Vol3/dotnet parsers aren't bit-identical on re-run.
- **Combo finishers** (Pattern 2). Cross-artifact correlation already done via `compare_disk_and_memory` (10 checks) + `find_temporal_clusters`. Persona-paired dispatch reintroduces the Run-2 delegate failure mode (Task subagent 32K ceiling).
- **Lamport clocks.** Single-host serial `executions[]` with UTC `timestamp_observed` already gives causal ordering. Lamport is for distributed multi-writer streams.
- **Per-persona cryptographic signing.** Simulated `@*-analyst` personas aren't real trust boundaries. Crypto without independent signers is ceremony, not provenance.

The post-hackathon enterprise picture (multi-tenant, three-tier model routing, OIDC identity, SOAR-callable HTTP, OTel observability) is in `docs/ENTERPRISE-ADK-LAYER.md`. Your design is the foundation for that. The hackathon is one milestone on that road, not the whole road.

---

## 8. Three questions I need answered to lock this in

1. **Does the SANS / Devpost submission rule mandate a specific framework, or just "autonomous agent + audit trail"?** The two-client portability framing depends on this. If a specific framework is required, we revise. (`research/RESEARCH_SOURCES.md` reads it as the latter, but please confirm with your reading of the rules.)
2. **Can your ADK POC stay strictly outside `.claude/hooks/` and `.claude/settings.json` until 2026-06-15?** Tri-agent consensus flagged this as the load-bearing safety constraint. If you need a hook change for your POC to work, we discuss before you build.
3. **Are you willing to scope down to the contract-level POC (3-4 dev-days) + dual-client diagram (1 day) + write-up contribution, with the 2026-06-08 abort condition?** If yes, I open scoped tickets this weekend.

---

## Appendix — references

- `docs/ENTERPRISE-ADK-LAYER.md` — post-hackathon enterprise architecture; multi-tenant ADK service over the same MCP server
- `review-findevil-integration-2026-05-29.md` — verbatim adversarial-review quotes on each of your 9 architectural ideas
- `sift_mcp/models/evidence_finding.py` — `EvidenceFinding` schema (the actual repo contract behind your FindingPayload concept)
- `sift_mcp/server.py:submit_finding` — the entry point your POC calls
- `.mcp.json` — the canonical MCP server invocation pattern (relative, post-fix)
- `analysis/audit.jsonl` schema — the audit row your POC must produce

Talk soon.

— Kismat
