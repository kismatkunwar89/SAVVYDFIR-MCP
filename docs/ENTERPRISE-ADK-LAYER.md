# Enterprise ADK Layer Over SAVVYDFIR-MCP - Architecture Brief

**Status:** Strategic / post-hackathon
**Audience:** Both teams (Claude Code investigation side + Google ADK orchestration side)
**Decision context:** Tri-agent consensus on 2026-05-29 rejected an ADK orchestrator swap *for the 17-day hackathon window*. This document argues that for **enterprise triage at scale** the ADK layer is not just acceptable - it's the right shape, and our existing MCP server is already positioned to support it.

---

## 1. The honest baseline: yes, the current framework is Claude Code-oriented

It's worth saying plainly. Today the orchestration plane is bound to Claude Code in three places:

| Layer | Binding |
|-------|---------|
| Hook execution | `.claude/settings.json` + `.claude/hooks/*.py` use Claude Code's `PreToolUse` / `PostToolUse` / `SessionStart` / `Stop` schema. No portability to other agent runtimes. |
| Subagent dispatch | `scripts/agent_trigger.py` references Claude's `Task` tool + `delegate_queue` model. The 11 `@*-analyst` agents live in `.claude/agents/*.md` (Claude Code subagent schema). |
| Investigator surface | `CLAUDE.md` is the agent's system prompt. Investigation workflow lives in a Claude `Skill` (`.claude/skills/investigation-workflow/SKILL.md`). |

**What's NOT Claude Code-bound:**

| Layer | Status |
|-------|--------|
| `sift_mcp/server.py` - 31 forensic tools | Pure FastMCP stdio. Any MCP client (ADK, OpenAI, Anthropic SDK, custom Python) can call it. |
| `audit.jsonl` - execution provenance | Plain JSONL. No client coupling. |
| `state.json` - case state | Plain JSON. No client coupling. |
| Tool runners (`sift_mcp/runners/*`) | Pure Python. Volatility/Sleuthkit/Chainsaw subprocess wrappers. |
| Evidence integrity (RBAC, read-only mounts) | Enforced inside `sift_mcp/server.py` - survives any client. |
| Heuristic context (`prepare_hypothesis_context`) | MCP tool. Client-agnostic. |

**This is the leverage point.** The forensic execution layer is already framework-neutral. What's missing for enterprise is a different *orchestration plane* - and ADK is a reasonable choice for it.

---

## 2. Why enterprises need something Claude Code can't give

Claude Code is excellent for: a single analyst at a workstation, interactive investigation, exploration-heavy work, and hackathon demos where a human is in the loop. It is not designed for:

| Enterprise requirement | Claude Code gap | Why ADK (or equivalent control-plane runtime) wins |
|------------------------|-----------------|----------------------------------------------------|
| **Triage at scale** - thousands of EDR/SOAR alerts/day, most of which are benign and need a deterministic verdict in seconds | Claude Code is interactive-shell-shaped; no native queueing, no backpressure | ADK agent loop runs as a service. Deterministic pre-filter handles 80% of alerts without spending an LLM token. |
| **Multi-tenant isolation** - MSSP serving 50 customers; per-tenant evidence, audit, billing, key separation | `~/.claude/` is single-user; `analysis/state.json` is single-case | ADK process can scope `case_id` → tenant → storage prefix → KMS key per request, programmatically. |
| **Model routing / cost discipline** - cheap model for triage (Deepseek/Haiku), expensive model for narration (Claude Opus/Gemini Pro) | Single model per session; switching mid-session is awkward | ADK can pick `model=cheap` for classification, `model=expensive` for the final report. Cost per investigation drops 70-90%. |
| **Long-run / batch** - overnight sweep of 200 hosts, parallel disk image triage, weekly retrospective re-runs against new Sigma rules | Claude Code session has finite TTL; not designed for headless 12h runs across hundreds of artifacts | ADK runs as a daemon. Each case is an idempotent job. Queue depth, parallelism cap, retry policy all programmable. |
| **API/SOAR integration** - investigation kicked off by SOAR (Splunk SOAR, Tines, XSOAR) on EDR alert, results posted back to ticket | Claude Code is a CLI; no HTTP surface | ADK process exposes `POST /investigations` + `GET /investigations/{id}/findings` → SOAR-callable. |
| **Authn/authz / SOC 2** - per-user access, MFA-bound API keys, audit trail tied to identity not local user | No user identity model; one local shell | ADK request carries identity (OIDC/SAML) → forensic tools logged with `actor`, not `os.getuid`. |
| **Observability** - Prometheus metrics, distributed tracing, alerting on stuck investigations, queue depth dashboards | None; you `tail -f audit.jsonl` | ADK process emits OpenTelemetry traces, metrics, structured logs to whatever SIEM. |
| **Deterministic-first triage** - most "alerts" are routine; LLM only for genuinely ambiguous cases | Claude reads everything | ADK Layer-1 (YARA + Sigma + regex + heuristic rules) classifies most cases without invoking a model. Cuts compute + latency dramatically. |

**Bottom line:** Claude Code is a *workbench*. ADK (or equivalent) is a *service*. Enterprises need the service, with the workbench available as a power-user fallback.

---

## 3. The architecture - keep MCP as the execution plane, add ADK as the control plane

```
┌────────────────────────────────────────────────────────────────────┐
│  Enterprise SOAR / SIEM / Analyst UI / API Client                  │
│  (Splunk SOAR / Tines / XSOAR / custom UI / cron job)              │
└─────────────────────────┬──────────────────────────────────────────┘
                          │  HTTP/gRPC + OIDC identity
                          ▼
┌────────────────────────────────────────────────────────────────────┐
│  ADK Orchestration Service  (Python daemon, K8s deployment)        │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  Layer 0 - Request gateway                                │     │
│  │  authn + tenant resolution + rate limit + idempotency key │     │
│  └──────────────────────┬───────────────────────────────────┘     │
│                         ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  Layer 1 - Deterministic triage  (NO LLM tokens)         │     │
│  │  YARA + Sigma + regex IOC scan + magic-byte classifier   │     │
│  │  + heuristic verdict engine + alert correlator           │     │
│  │  Outputs: route_decision, evidence_classification,       │     │
│  │  pre_extracted_iocs, suggested_tool_subset               │     │
│  └──────────────────────┬───────────────────────────────────┘     │
│                         ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  Layer 2 - Model router  (cost-aware)                    │     │
│  │  if triage_confident → skip LLM, emit deterministic verdict  │ │
│  │  elif triage_class == 'simple' → cheap_model              │     │
│  │  elif triage_class == 'complex' → expensive_model         │     │
│  │  always_use_for_narration → narrator_model                │     │
│  └──────────────────────┬───────────────────────────────────┘     │
│                         ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  Layer 3 - ADK Investigator Loop  (hypothesis-pivot-     │     │
│  │  verify) - calls MCP forensic tools via stdio facade     │     │
│  │  Sees: structured triage output + tool catalog +         │     │
│  │  finding ledger. Never sees raw evidence bytes.          │     │
│  └──────────────────────┬───────────────────────────────────┘     │
│                         ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  Layer 4 - Narrator  (read-only report generation)       │     │
│  │  Cannot call forensic tools. Reads structured findings,  │     │
│  │  writes executive summary + ATT&CK mapping + timeline.   │     │
│  └──────────────────────┬───────────────────────────────────┘     │
│                         ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  Layer 5 - Provenance packaging                          │     │
│  │  GPG-signed git repo + audit.jsonl + replay recipes +    │     │
│  │  evidence hash manifest + tenant-scoped object storage   │     │
│  └──────────────────────────────────────────────────────────┘     │
└─────────────────────────┬──────────────────────────────────────────┘
                          │  MCP stdio (or gRPC over MCP)
                          ▼
┌────────────────────────────────────────────────────────────────────┐
│  sift_mcp.server  - UNCHANGED                                      │
│  31 forensic tools · RBAC · read-only evidence mounts ·            │
│  audit.jsonl writer · state.json deepcopy · CorrectionEvent gates  │
└────────────────────────────────────────────────────────────────────┘
```

**The split is the value.**

- Forensic correctness lives in MCP. Built, tested, ROCBA-validated. Don't touch.
- Triage policy, model economics, tenant isolation, SLA, observability, REST/SOAR integration all live in ADK. Built where they belong.

Claude Code becomes one of *several* clients of the same MCP server - the analyst workbench client. ADK becomes the production service client.

---

## 4. Enterprise best practices for the ADK layer

### 4.1 Deterministic-first triage - never spend a token on a known-benign verdict

```python
# Pseudocode - Layer 1
def triage(evidence_ref) -> TriageVerdict:
    classification = classify_by_magic(evidence_ref)
    yara_hits = run_yara_rules(evidence_ref, ruleset=tenant.ruleset)
    sigma_hits = run_sigma_rules(evidence_ref, ruleset=tenant.ruleset)
    iocs = extract_iocs_regex(evidence_ref)

    if yara_hits.empty and sigma_hits.empty and iocs.empty:
        return TriageVerdict(
            confidence="HIGH",
            verdict="BENIGN_NO_LLM_NEEDED",
            evidence_hash=sha256(evidence_ref),
            llm_cost=0,
        )

    return TriageVerdict(
        confidence="needs_llm",
        suggested_route=ROUTE_MANIFEST[classification],
        pre_extracted=iocs,
        priority=score_by_rules(yara_hits, sigma_hits),
    )
```

Most enterprise alerts are noise. A SOAR pipeline that asks the LLM to investigate every alert burns thousands of dollars/day for verdicts the rule engine could have given for free. Layer 1 catches the noise.

### 4.2 Model routing - three tiers, not one

```python
# Pseudocode - Layer 2
TIERS = {
    "cheap":     "deepseek-v4-pro",         # triage, classification, structured extraction
    "expensive": "claude-opus-4-7",         # hypothesis formation, pivot reasoning
    "narrator":  "gemini-2.5-flash",        # narrative prose, ATT&CK mapping, summary
}

def route_request(triage_verdict) -> str:
    if triage_verdict.confidence == "HIGH":
        return "no_llm"
    if triage_verdict.complexity_score < 0.4:
        return TIERS["cheap"]
    return TIERS["expensive"]
```

The narrator is always the cheapest "smart" model - it doesn't reason, it just renders structured findings into prose. Forensic reasoning gets the expensive model only when needed. Cost per case drops 70-90% vs always-Opus.

### 4.3 Per-tenant isolation - case_id → tenant → storage prefix → key

```python
# Pseudocode - Layer 0
def resolve_tenant(request) -> TenantCtx:
    identity = validate_oidc(request.token)
    tenant_id = identity.tenant
    return TenantCtx(
        tenant_id=tenant_id,
        storage_prefix=f"s3://savvydfir/{tenant_id}/",
        kms_key=f"arn:aws:kms:.../alias/savvydfir-{tenant_id}",
        rate_limit=tenant_quotas[tenant_id],
        sigma_ruleset=tenant_rulesets[tenant_id],
        audit_destination=f"siem://{tenant_id}/dfir/",
    )
```

`audit.jsonl` then writes through tenant-scoped destination. `analysis/state.json` lives under tenant prefix. Cross-tenant evidence leakage becomes architecturally impossible, not promise-based.

### 4.4 Idempotency - every investigation request carries a key

```python
# Pseudocode - Layer 0
@app.post("/investigations")
def create_investigation(req: InvestigationRequest):
    if existing := db.find_by_idempotency_key(req.idempotency_key):
        return existing  # safe retry - no double work
    return start_new_investigation(req)
```

SOAR retries are inevitable; idempotency keys mean retrying doesn't re-run a 90-minute investigation.

### 4.5 Backpressure - concurrency cap with explicit queue

The VM is 4 vCPU / 7.6 GB. A 5th concurrent investigation OOMs. ADK service must:

```python
SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_INVESTIGATIONS)
async def investigate(req):
    async with SEMAPHORE:
        return await run_investigation(req)
```

Excess requests queue with explicit ETA returned to caller. SOAR retries don't pile up.

### 4.6 Observability - every step instrumented

| Signal | What |
|--------|------|
| Metric | `investigation.duration_seconds{phase=}`, `investigation.findings_total{status=}`, `tool.duration_seconds{tool=}`, `llm.tokens{tier=,direction=}`, `llm.cost_usd{tenant=}` |
| Trace | One OTel trace per investigation, span per phase, span per MCP tool call, span per LLM call. Spans tagged with `case_id`, `tenant_id`, `model`, `tool_name`. |
| Log | Structured JSON; same fields as audit.jsonl + identity context |
| Alert | `investigation.stuck` (no phase progress > 30 min), `investigation.failed`, `llm.cost.budget_exceeded`, `tool.error_rate` |

This is non-negotiable for production. Claude Code's `audit.jsonl` is a great forensic artifact but not an operations dashboard.

### 4.7 Idempotent re-runs against updated rules

Enterprise workflow: every Tuesday, re-run last 30 days of investigations against newly-released Sigma rules. New findings get auto-routed to analyst queue.

```python
# Pseudocode - replay
for case in last_30_days_cases:
    new_sigma_hits = run_sigma_rules(case.evidence_ref, ruleset=new_rules)
    delta = diff(new_sigma_hits, case.sigma_findings)
    if delta:
        create_alert(case_id=case.id, delta=delta)
```

Requires: deterministic evidence hash, idempotent rule application, ability to compute deltas between investigation runs. ADK service can model this naturally; Claude Code cannot.

### 4.8 RBAC inside MCP - tenant-bound paths

Today `sift_mcp/server.py` enforces RBAC against hardcoded prefixes (`/evidence/`, `/mnt/`, `/cases/`). For multi-tenant, this needs:

```python
# sift_mcp/server.py - future
def _validate_path(path, ctx):
    allowed_prefixes = ctx.tenant.allowed_paths  # injected by ADK
    if not any(path.startswith(p) for p in allowed_prefixes):
        raise PathDenied(f"path {path} outside tenant {ctx.tenant.id} scope")
```

ADK passes tenant scope to MCP at session start; MCP enforces it on every tool call. This is the only change to the MCP layer required by the ADK addition.

---

## 5. Bridge contract - what ADK calls into MCP for

ADK should treat MCP as a typed RPC surface. Three categories:

| Category | MCP tools used | When |
|----------|----------------|------|
| **Preflight + setup** | `start_investigation`, `mount_image`, `verify_integrity`, `load_memory` | Per investigation, once |
| **Extraction (deterministic)** | `extract_mft_timeline`, `extract_usn_journal`, `summarize_evtx`, `extract_prefetch`, `get_amcache`, `extract_shimcache`, `extract_registry_run_keys`, `extract_srum`, `sigma_hunt` | Layer 1 triage + Layer 3 investigator. Can run without LLM. |
| **Hypothesis-bound** | `prepare_hypothesis_context`, `record_hypotheses`, `run_analysis`, `submit_finding`, `compare_disk_and_memory`, `find_temporal_clusters`, `generate_report`, `generate_graph` | Layer 3 only - LLM in the loop |

**Best practice:** ADK should NOT call extraction tools from inside the LLM loop. Call them deterministically in Layer 1 before any LLM call. The LLM only sees the *summary* + `applicable_heuristics` + detection anchors - which is exactly what `prepare_hypothesis_context` already returns.

---

## 6. Where this lands relative to the hackathon

**Hackathon (2026-06-15):** Claude Code stays as the orchestrator. Two ideas from teammate's plan adopted:
- GPG-signed report git repo (ITEM-3, ~1h)
- Negative attestations (ITEM-4, ~2h)

Architecture diagram in the submission shows MCP as the forensic execution plane with a *single client* (Claude Code). One arrow.

**Post-hackathon Q3/Q4 2026:** Add ADK as a SECOND client of the same MCP server. Architecture diagram updates to show two clients (Claude Code workbench + ADK service). No code in the MCP layer changes except the optional tenant-scoped RBAC injection from §4.8.

**This is why the consensus rejected the ADK *swap* but did not reject ADK as a concept.** The MCP layer is the durable asset. The orchestrator is the swappable layer. We're not betting the framework on Claude Code - we're betting it on MCP. Anything that speaks MCP (Claude Code today, ADK tomorrow, your own Python client next quarter) is a valid front-end.

---

## 7. Concrete next steps if/when ADK layer is built

1. **Stand up `findevil_service/`** as a separate Python package (NOT inside `sift_mcp/`). Imports `mcp` client SDK. Spawns `sift_mcp.server` as a stdio subprocess just like Claude Code does.
2. **Implement Layer 0-5** in order. Layers 0-2 can ship without an LLM call at all - that's the cost-control phase.
3. **Inject tenant scope** into MCP session via a new MCP server option (`SAVVYDFIR_TENANT_CONFIG` env var pointing at a per-tenant JSON). One small change to `sift_mcp/server.py::RBAC paths` to honor it.
4. **OTel + Prometheus** from day one. No "we'll add observability later." Cost discipline requires day-1 visibility.
5. **Idempotency + queueing** before ever exposing the HTTP surface. SOAR will hammer it.
6. **CI matrix**: run the same investigation through both Claude Code (workbench mode) and ADK (service mode) against a fixture case. Same findings should come out. Drift = bug in one or the other.

---

## 8. The honest tradeoffs

| Pro | Con |
|-----|-----|
| Production cost discipline (cheap model triage) | Adds significant engineering surface to maintain |
| Multi-tenant isolation enforceable architecturally | Requires SRE / DevOps maturity to operate |
| SOAR-integrable, batch-friendly, headless | Loses the interactive-analyst workbench feel for power users (mitigated: keep Claude Code as second client) |
| Observability becomes first-class | Requires OTel + metric pipeline + dashboarding investment |
| Per-tenant rulesets, key management, billing | Vendor lock to ADK (mitigated: ADK is open-source) |
| Long-run sweeps + replay become natural | Building well takes 4-8 engineer-weeks minimum |

**For a single analyst doing CTF / IR consulting:** stay on Claude Code. The workbench is the right shape.

**For an MSSP running 50-client managed DFIR:** build the ADK layer. The service is the right shape.

**For the hackathon:** Claude Code wins because it's shipped, runs, and produces criterion-#1 self-correction proof today.

**For the company after the hackathon:** the value of SAVVYDFIR-MCP is the MCP server. The orchestrator decision becomes a "which client do you want today?" question, not an architectural commitment.

---

## 9. Summary table - what runs where

| Concern | Claude Code (today, hackathon) | ADK service (future, enterprise) |
|---------|--------------------------------|-----------------------------------|
| Orchestrator | Claude Code agent loop | ADK agent service |
| Hooks / phase gates | `.claude/hooks/*.py` | ADK middleware + Layer 1 |
| Subagent dispatch | Claude Code Task tool | ADK parallel-thread workers |
| Forensic execution | MCP server (UNCHANGED) | MCP server (UNCHANGED) |
| Audit | `audit.jsonl` + `state.json` (local files) | Same files PLUS OTel + SIEM forward + tenant-scoped storage |
| Identity | OS user | OIDC/SAML federated identity |
| Multi-tenant | No | Yes, architecturally enforced |
| Model | One per session | Three-tier router (cheap / expensive / narrator) |
| Run mode | Interactive shell | Headless service + queue |
| Triggered by | Human typing prompt | SOAR / cron / API call |
| Scaling | Single user / single VM | K8s deployment, horizontal scale |
| Cost discipline | Manual | Deterministic-first triage + model router |
| Workbench mode for analyst | YES (this is its strength) | Out of scope (use Claude Code) |

---

**Closing:** the framework is not Claude-bound at the forensic layer. The framework IS Claude-bound at the orchestration layer - and that's a deliberate choice for the hackathon because the orchestrator is where criterion #1 lives. Post-hackathon, ADK is the right shape for the second orchestrator, and the MCP server is ready to support it without major changes.
