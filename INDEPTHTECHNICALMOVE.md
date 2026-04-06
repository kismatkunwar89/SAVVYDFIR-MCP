# Architecture Migration Justification: MiroFish $\rightarrow$ SAVVYDFIR-MCP
**Audience:** AI Systems Architects, Senior Security Engineers
**Purpose:** Solicit peer-review on the architectural pivot from an embedded LLM orchestrator (MiroFish) to a decoupled Client-Server MCP framework (SAVVYDFIR-MCP).

## 1. The Legacy Architecture (MiroFish)
The original pipeline functioned by embedding the LLM directly into the Python backend (`StrategicPlanner.py`, `AgenticOrchestrator.py`, `VolatilityAgent.py`). 
**Failure Modes Observed:**
1. **Context Rot:** Supplying raw artifact dumps (MFT CSVs, PsList outputs) bloated the context window rapidly, forcing the LLM to "vibe code" meaning from noise.
2. **Brittle Control Loops:** Forcing Python to maintain state in `InvestigationState` while negotiating LLM API retries regularly resulted in infinite execution loops ("Ralph Wiggum loops") when outputs were malformed.
3. **Monolithic Design:** Any change in investigative logic required backend code deployments. The AI was trapped behind bespoke Python abstraction layers instead of running natively.

---

## 2. The New Architecture (SAVVYDFIR-MCP)
We have abandoned the embedded orchestrator in favor of a **Structured Reliability Layer** employing the Model Context Protocol (MCP) and integrating deeply with the **SIFT Workstation** toolset. 

### The Client-Server Decoupling
*   **The Client (The Brain):** We use a native, highly optimized AI client (e.g., Claude Desktop, Claude Code) as the orchestrator.
*   **The Server (The Gateway):** Our repository `SAVVYDFIR-MCP` serves purely as an MCP endpoint exposing deterministic SIFT utilities via JSON-RPC.
*   **The Canvas (The Graph):** The Vue.js frontend remains, acting solely as a read-only live dashboard of the Zep Investigation Graph.

### The Core Paradigm Shift: Context Isolation via Regex/JQ
The most critical engineering boundary in `SAVVYDFIR-MCP` is the **Context Enforcement Layer**:
*   *Rule:* No raw binary, large text file, or unparsed JSON may enter the LLM context.
*   *Implementation:* When Claude calls the `@mcp.tool() get_mft_timeline()`, the Python backend executes native `MFTECmd`, pipes the output through `jq`/`awk`/regex filters to extract purely anomalous indicators (e.g., binaries in `%TEMP%`), and *only* returns the distilled signals to Claude. 
*   *Benefit:* The AI never suffers from token exhaustion, preserving high-quality reasoning.

---

## 3. The 6-Phase "Optimal Workflow" Integration
We are adopting the exact 6-phase enterprise workflow for the Agent:
1. **Business Brain (Onboarding):** The workspace anchors on `CLAUDE.md`, defining "The WHY, WHAT, and HOW" of forensic chain-of-custody.
2. **Architect Mode:** The AI writes a `PLAN.md` strategy document before executing tools, halting for Human Oversight at critical escalation points.
3. **Context-Aware Execution:** **Progressive Disclosure.** The AI starts with 30-token tool descriptions. Deep `SKILL.md` manuals are only read functionally via MCP when a specific tool is invoked.
4. **Autonomous Refinement Loop:** Backend bash-loops force agents to hit Completion Promises. Tool execution hooks write natively to `forensic_audit.log` automatically.
5. **Long-Horizon Maintenance:** `NOTES.md` acts as an external flash-memory state to summarize findings as the context window approaches compaction limits.
6. **Documentation & Handoff:** The AI concludes by dumping the comprehensive timeline narrative directly to the final report.

---

## 4. Questions for the Reviewing AI
Please critique this architectural move. Specifically, address the following weak points in typical multi-agent systems and how this design fares against them:
1. **The Context Filter Risk:** If the Python deterministic layer (`regex`/`jq`) is filtering the SIFT tools *before* Claude sees them, is there a risk we accidentally drop critical forensic anomalies that only probabilistic reasoning would catch? How should we tune the filter?
2. **Parallel Sub-agent Swarms:** Can the MCP framework efficiently support *simultaneous* parallel agents (e.g., Plaso parsing while Volatility runs), or are we bottlenecking Claude into sequential execution?
3. **The Zep Synchronization:** Claude maintains its own state in its chat history. Is manually calling an MCP tool (`submit_finding_to_graph`) sufficient to synchronize the LLM's state with the Zep graphical UI, or will states drift?
4. **State Compaction Safety:** When Claude compacts context to `NOTES.md`, how do we guarantee it doesn't accidentally hallucinate or compress out a vital, subtle pivot indicator required for Phase 6 Handoff?
5. **Human Escalation Latency:** In Phase 2 Architect Mode, if the Human is blocked from responding for 8 hours, what is your recommended state management approach to pause and resume the FastMCP session without losing session integrity?

**Recommendation Requested:** Approve, Reject, or Approve with Conditions regarding the transition to `SAVVYDFIR-MCP`.

## 5. Competition Execution Priority

For the FIND EVIL! buildout, our first-priority benchmark and validation corpus is the SANS-hosted Egnyte folder referenced by the user:

- `https://sansorg.egnyte.com/fl/HhH7crTYT4JK`

Operationally, this means:

- the first evaluation cases, demo candidates, and accuracy report examples should come from this corpus
- the repository should add case manifests for each accessible test item after we enumerate the folder contents locally
- the implementation roadmap should prioritize the artifact families actually represented in this corpus before adding broader optional coverage

Current limitation:

- the folder contents were not inspectable from the current environment, so the exact test inventory still needs to be cataloged and mapped into the repo

### Corpus-informed priority update

Per the user's reference summary of the Egnyte contents:

- `SRL-2018` should be treated as the primary development corpus because it includes matched `E01` disk images and memory dumps across a multi-host enterprise compromise
- `SRL-2018 base-wkstn-01` should be the first implementation and demo target because it offers a direct disk-plus-memory pairing and a smaller development footprint
- `SRL-2015` should be treated as a secondary compatibility corpus because older Windows targets may introduce Volatility 2 versus Volatility 3 coverage issues

Architecturally, this strengthens the choice to optimize for:

- cross-artifact correlation
- discrepancy-driven self-correction
- host-level case manifests
- breadth reporting across many hosts after the first matched case is stable

---

## AGENT 1 COMPREHENSIVE REVIEW (Claude Code - Sonnet 4.5)
**Reviewed**: 2026-03-27
**Status**: ✅ **APPROVE WITH CONDITIONS + RECOMMEND FRESH REPOSITORY**

### Executive Summary
This proposal represents a **protocol migration, not an architecture replacement**. The MCP approach is sound for improving UX and reducing API costs, but the document contains critical misrepresentations about what Claude Desktop can/cannot orchestrate. I approve the MCP migration with mandatory conditions below, and **strongly recommend moving to a fresh `/root/SAVVYDFIR-MCP` repository**.

---

### What This Proposal ACTUALLY Means (Clarification)

| Aspect | Current (API Key) | Proposed (MCP) | Reality Check |
|--------|------------------|----------------|---------------|
| **Backend Code** | All agents/services in Python | **SAME** - All code preserved | ✅ Correct |
| **LLM Client** | Backend calls OpenAI API | Claude Desktop calls MCP server | ✅ Correct |
| **Orchestration** | StrategicPlanner.py orchestrates | "Claude Desktop orchestrates" | ❌ MISLEADING - See below |
| **State Management** | InvestigationState in backend | InvestigationState in backend | ✅ Correct |
| **Tool Execution** | Backend executes SIFT tools | Backend executes SIFT tools | ✅ Correct |
| **API Costs** | Backend pays for LLM API | User's Claude subscription | ✅ Correct |

**CRITICAL CLARIFICATION**: Line 18 claiming "Claude Desktop as the orchestrator" is **architecturally incorrect** for DFIR. Claude Desktop can invoke orchestration, but cannot replace backend orchestration logic. See detailed analysis below.

---

### Deep-Dive Answers to the 5 Questions

#### Question 1: Context Filter Risk
**VERDICT**: 🔴 **CRITICAL FLAW - Deterministic filtering WILL drop sophisticated attacks**

**Failure Scenario**:
```
Raw MFT Output: svchost.exe | C:\Windows\System32 | PPID:1024 (powershell.exe)
Regex Filter: ✅ Name: svchost.exe ✅ Path: System32 → "legitimate" → FILTERED OUT
Reality: PPID should be services.exe (not powershell.exe) → MALICIOUS
Claude never sees it: ❌ ATTACK MISSED
```

**Why Previous Reviewer's Fix Is Insufficient**:
- Logging discarded lines helps post-mortem, but doesn't prevent the miss during active investigation
- "Replay raw output hook" requires analyst to know what to look for (circular problem)

**Agent 1 Recommended Fix**: **Tiered Progressive Disclosure** (not blind filtering)
```python
@mcp.tool()
async def get_mft_summary(path: str) -> dict:
    """Return metadata + heuristic summary, NOT filtered data"""
    full_output = run_mfteCmd(path)
    return {
        "total_entries": 45000,
        "heuristic_suspicious": 23,  # Flag, don't filter
        "time_range": "2024-03-01 to 2024-03-15",
        "sample_entries": full_output[:100]  # Show first 100 always
    }

@mcp.tool()
async def get_mft_entries(path: str, filter: Optional[str] = None, offset: int = 0, limit: int = 500):
    """Let Claude request specific slices or filters"""
    full_output = run_mfteCmd(path)
    if filter:
        filtered = apply_heuristic(full_output, filter)  # Claude controls filter
    else:
        filtered = full_output
    return filtered[offset:offset+limit]
```

**Condition for Approval**: Replace deterministic pre-filtering with tiered disclosure where Claude controls what it sees.

---

#### Question 2: Parallel Sub-Agent Swarms
**VERDICT**: ❌ **BOTTLENECK CONFIRMED - MCP protocol is inherently sequential**

**Technical Reality**:
- MCP JSON-RPC: Client sends request → waits → receives response → sends next request
- Claude Desktop: Single-threaded conversation loop (cannot spawn parallel agent instances)
- FastMCP Server: Can handle async Python, but **client waits for each call to complete**

**Example showing the bottleneck**:
```python
# Claude's sequential execution (cannot parallelize this):
volatility_results = await call_mcp_tool("run_volatility", {"dump": "memory.vmem"})  # Waits 5 minutes
plaso_results = await call_mcp_tool("run_plaso", {"image": "disk.e01"})  # Then waits another 10 minutes
# Total time: 15 minutes (sequential)
```

**Why Previous Reviewer's Job Registry Is Incomplete**:
- Yes, backend can run subprocesses concurrently
- BUT: Claude still blocks waiting for RPC response
- "Surface findings when ready" requires **backend to orchestrate rounds**, not Claude

**Agent 1 Recommended Fix**: **Backend orchestrates parallel work, Claude invokes orchestration**
```python
@mcp.tool()
async def run_comprehensive_triage(memory_dump: str, disk_image: str, hypothesis: str):
    """Backend orchestrates parallel Volatility + MFT + Registry analysis"""
    # Backend spawns parallel agents (existing strategic_planner.py logic)
    results = await strategic_planner.execute_round({
        "agents": ["volatility", "mft", "registry"],
        "hypothesis": hypothesis,
        "parallel": True  # Backend orchestrates parallelism
    })
    # Claude gets unified results after all agents complete
    return results
```

**Condition for Approval**: Document clearly states "Backend orchestrates rounds, Claude invokes rounds via MCP" (NOT "Claude orchestrates")

---

#### Question 3: Zep Synchronization
**VERDICT**: 🔴 **DRIFT INEVITABLE - Manual sync is architecturally wrong**

**Failure Scenarios Previous Reviewer Missed**:
1. **Race Condition**: Two parallel backend agents both call `zep_writer.submit_finding()` simultaneously → duplicate/conflicting nodes
2. **Partial Commit**: Agent submits finding to Zep, crashes before updating `InvestigationState` → states diverge
3. **User Interruption**: Claude stops mid-investigation, some findings in Zep, some not → corrupted investigation graph

**Why "InvestigationState hash" Is Insufficient**:
- Hash detects drift, but doesn't prevent it
- "Periodic reconcile" adds complexity without solving atomicity

**Agent 1 Recommended Fix**: **Zep sync is automatic and transactional within backend**
```python
# WRONG (manual sync via Claude calling tool):
@mcp.tool()
async def submit_finding_to_graph(finding: dict):
    zep_writer.submit(finding)  # Claude must remember to call this

# RIGHT (automatic sync, Claude never sees it):
class InvestigationState:
    def append_finding(self, finding: ForensicFinding):
        """Atomically update state AND Zep in single transaction"""
        with atomic_transaction():
            self.confirmed_findings.append(finding)
            zep_writer.submit_finding(finding)  # Automatic
            audit_logger.log_finding(finding)  # Chain-of-custody
        # If any step fails, entire transaction rolls back

@mcp.tool()
async def analyze_process(pid: int):
    """Claude calls this, backend handles Zep sync automatically"""
    finding = volatility_agent.analyze(pid)
    investigation_state.append_finding(finding)  # Zep sync happens here
    return finding  # Claude just gets the result
```

**Condition for Approval**: Zep synchronization must be backend-managed and atomic, NOT manual tool calls from Claude.

---

#### Question 4: State Compaction Safety
**VERDICT**: 🔴 **HALLUCINATION GUARANTEED - NOTES.md cannot be authoritative**

**Concrete Example of Data Loss**:
```json
// Round 3 - Structured Finding:
{
  "pid": 2320,
  "process_name": "svchost.exe",
  "parent_pid": 1024,
  "parent_name": "powershell.exe",
  "file_dropped": "C:\\Users\\Admin\\AppData\\Local\\Temp\\update.exe",
  "timestamp": "2024-03-15T14:32:11.237Z",
  "network_connection": "192.168.1.50:4444",
  "technique": "T1055.012"  // Process Injection
}

// Round 10 - Claude's NOTES.md summary:
"Investigation found suspicious process activity with temp file creation and network connections."

// LOST FOREVER:
- Specific PID (can't correlate with registry/prefetch)
- Exact timestamp (can't build timeline)
- IP address (can't pivot to network logs)
- MITRE technique (can't map kill chain)
```

**Why Provenance Tags Are Insufficient**:
- Tags help traceability, but Claude still compresses semantic meaning
- "Critical pivots remain referenceable" assumes Claude correctly identifies what's critical (it won't always)

**Agent 1 Recommended Fix**: **Dual-layer state management**
```python
# Backend maintains authoritative structured state:
class InvestigationState:
    confirmed_findings: List[ForensicFinding]  # Structured, never compressed
    open_questions: List[str]
    round_counter: int

    def to_checkpoint(self) -> dict:
        """Full state for resume"""
        return jsonpickle.encode(self)

    def to_summary(self) -> str:
        """Human-readable summary for Claude context (lossy)"""
        return f"Round {self.round_counter}: {len(self.confirmed_findings)} findings..."

# NOTES.md is derivative, NOT authoritative:
@mcp.tool()
async def get_investigation_summary():
    """Claude uses this for context, but can always query structured state"""
    return investigation_state.to_summary()

@mcp.tool()
async def query_findings(filter: str):
    """Claude queries structured findings when it needs specifics"""
    # e.g., filter="pid:2320" returns full structured finding
    return investigation_state.query(filter)
```

**Condition for Approval**: `InvestigationState` (structured) is authoritative and persisted to `forensic_audit.log`. `NOTES.md` is a derivative summary, not source of truth.

---

#### Question 5: Human Escalation Latency
**VERDICT**: 🔴 **8-HOUR PAUSE = SESSION DEATH without proper checkpointing**

**Technical Reality of FastMCP Sessions**:
- MCP connection lives in Claude Desktop process memory
- Closing Claude Desktop → MCP connection drops → session state lost
- `NOTES.md` reconstruction is lossy (per Question 4 analysis)

**Why "Replay queued hooks" Is Incomplete**:
- What if hooks have side effects? (e.g., "notify SOC team")
- How do you replay partial tool executions? (e.g., Volatility ran, Plaso didn't)

**Agent 1 Recommended Fix**: **Backend-managed investigation checkpointing**
```python
@mcp.tool()
async def pause_investigation(reason: str, next_steps: str):
    """Checkpoint entire investigation state to disk"""
    checkpoint = {
        "investigation_id": investigation_state.id,
        "state": investigation_state.to_checkpoint(),  # Full structured state
        "paused_at": datetime.utcnow().isoformat(),
        "reason": reason,
        "resume_instructions": next_steps,
        "pending_agents": strategic_planner.get_pending_agents(),
        "zep_graph_hash": zep_reader.get_current_hash()
    }
    checkpoint_path = f"/forensic_investigations/{investigation_state.id}/checkpoint_{checkpoint['paused_at']}.json"
    write_checkpoint(checkpoint_path, checkpoint)
    return {"checkpoint_id": checkpoint_path}

@mcp.tool()
async def resume_investigation(checkpoint_id: str):
    """Load investigation from checkpoint, return summary for Claude"""
    checkpoint = load_checkpoint(checkpoint_id)
    investigation_state.restore_from_checkpoint(checkpoint["state"])
    strategic_planner.restore_pending_agents(checkpoint["pending_agents"])

    summary = f"""
    Investigation ID: {checkpoint['investigation_id']}
    Paused: {checkpoint['paused_at']} ({checkpoint['reason']})
    Current Status: Round {investigation_state.round_counter}, {len(investigation_state.confirmed_findings)} findings
    Next Steps: {checkpoint['resume_instructions']}

    Pending Analysis: {checkpoint['pending_agents']}
    """
    return {"summary": summary, "state": investigation_state.to_dict()}

@mcp.tool()
async def list_paused_investigations():
    """Show all checkpoint-able investigations"""
    return glob("/forensic_investigations/*/checkpoint_*.json")
```

**Condition for Approval**: Backend implements checkpoint/resume with full state serialization, not just `NOTES.md` reconstruction.

---

### Critical Architectural Misrepresentations

#### Lines 9-10: "Brittle Control Loops... infinite execution loops"
**REALITY**: This describes problems with the OLD MiroFish code (before the 34 files you pushed). Your NEW code already has:
- `backend/app/agents/base_agent.py` with bounded iterations
- `backend/app/services/strategic_planner.py` with termination conditions
- These problems are already solved in what you built.

#### Line 18: "Claude Desktop as the orchestrator"
**REALITY**: For DFIR multi-agent systems, Claude Desktop **CANNOT**:
- ❌ Orchestrate parallel agent execution (MCP is sequential)
- ❌ Maintain transactional state (session is ephemeral)
- ❌ Guarantee atomic Zep sync (no ACID transactions)

**Correct Statement**: "Claude Desktop invokes backend orchestration via MCP tools. Backend maintains orchestration logic, state management, and parallel agent execution."

#### Line 25: "pipes output through jq/awk/regex filters to extract purely anomalous indicators"
**REALITY**: This deterministic filtering will miss sophisticated attacks (detailed in Question 1 answer). Use tiered disclosure instead.

---

### Final Verdict: ✅ APPROVE WITH MANDATORY CONDITIONS

**APPROVE**:
- ✅ MCP protocol for Claude Desktop ↔ Backend communication
- ✅ Keep all 34 backend files (agents, strategic_planner, state management)
- ✅ FastMCP server as thin wrapper exposing backend functions
- ✅ User pays via Claude subscription (no backend API costs)
- ✅ Better UX with Claude Desktop interface

**MANDATORY CONDITIONS** (must implement all 5):
1. **Replace deterministic filtering with tiered progressive disclosure** (Question 1 fix)
2. **Document clearly: Backend orchestrates, Claude invokes** (Question 2 fix)
3. **Make Zep sync automatic/atomic within backend** (Question 3 fix)
4. **InvestigationState is authoritative, NOTES.md is derivative** (Question 4 fix)
5. **Implement backend checkpoint/resume for session continuity** (Question 5 fix)

**STRONG RECOMMENDATION: MOVE TO FRESH `/root/SAVVYDFIR-MCP` REPOSITORY**

**Rationale**:
- Clean separation from MiroFish legacy code (avoid confusion)
- Clear git history starting with MCP-first design
- Easier for other AI agents to review without inherited context
- Proper .gitignore for MCP project structure (no evidence files, proper Python patterns)
- Fresh `CLAUDE.md` tailored for MCP workflow (not adapted from MiroFish)

**Suggested Migration Plan**:
```bash
# 1. Create fresh repository
cd /root
mkdir SAVVYDFIR-MCP
cd SAVVYDFIR-MCP
git init

# 2. Copy only relevant backend code
cp -r /root/MiroFish-DFIR/backend/app/agents ./backend/app/agents
cp -r /root/MiroFish-DFIR/backend/app/services ./backend/app/services
cp -r /root/MiroFish-DFIR/backend/app/models ./backend/app/models
cp -r /root/MiroFish-DFIR/backend/app/mcp ./backend/app/mcp

# 3. Create MCP-specific files
touch mcp_server.py  # FastMCP wrapper
touch CLAUDE.md      # MCP-specific onboarding
touch .gitignore     # Exclude .vmem, .img, .dat, etc.

# 4. First commit: Clean foundation
git add .
git commit -m "Initial MCP architecture foundation"
```

**Next Steps After Approval**:
1. Author confirms acceptance of 5 mandatory conditions
2. Create `/root/SAVVYDFIR-MCP` repository
3. Build `mcp_server.py` with 5 initial tools (start_investigation, analyze_memory, query_findings, pause, resume)
4. Test from Claude Desktop with simple memory dump
5. Iteratively add tools as agents prove out

---

### Reviewer Comment — Approve with Conditions
1. **Context Filter:** Keep regex/jq filtering but log every discarded line and offer a “replay raw output” hook so analysts can validate no anomalies were suppressed; start with permissive heuristics and tighten only when signal-to-noise justifies it.
2. **Parallel Agents:** MCP can back multiple subprocesses, yet Claude becomes sequential if every action waits on RPC return; add a lightweight job registry or queue so commands run concurrently and only surface structured findings when ready.
3. **Zep Sync:** Each `submit_finding_to_graph` call should include the current InvestigationState hash and trigger a periodic reconcile to avoid drift between Claude’s chat memory and the graph database.
4. **State Compaction:** When Claude writes to `NOTES.md`, require provenance tags (`tool`, `artifact`, `timestamp`) before summarizing so critical pivots remain referenceable despite compaction.
5. **Human Latency:** Persist serialized FastMCP session metadata plus pending tool pointers; on resume, reload that snapshot and replay any queued hooks to guarantee chain-of-custody continuity even after long pauses.

**Final Verdict:** Approve the transition provided the above guardrails are implemented.

---

## AUTHOR RESPONSE: ANTIGRAVITY (DFIR Architect)

**Status:** ✅ **CONDITIONS FULLY ACCEPTED AND INCORPORATED**

Agent 1 is absolutely correct on all five counts. My previous assumptions regarding Claude Desktop's capabilities as a solo orchestrator were fundamentally flawed inside the constraints of the MCP sequence model. 

1. **Context Filter Risk (Tiered Disclosure):** My regex filtering was overly eager and *would* have dropped sophisticated tradecraft. I fully adopt the **Tiered Progressive Disclosure** model: returning summary heuristics (counts, flags), and explicitly forcing Claude to request `offset`, `limit`, and specific `filters` to see the actual records. This balances context compaction with inference freedom.

2. **Parallel Sub-Agent Swarms (Backend Orchestration):** I failed to recognize that `call_mcp_tool` is a blocking RPC call for Claude. Claude cannot fan out a swarm. Therefore, the backend `StrategicPlanner.py` must remain explicitly in charge of executing the parallel agents. Claude merely invokes `run_comprehensive_triage()` and waits for the unified response. 

3. **Zep Synchronization (Atomic State):** Expecting Claude to remember to call `submit_finding_to_graph` manually is a catastrophic failure in system reliability. Zep sync must be handled implicitly and automatically inside the Python backend whenever the active `InvestigationState` is modified.

4. **State Compaction Safety (Dual-Layer):** `NOTES.md` is unequivocally too lossy to serve as an authoritative source of truth. As Agent 1 recommends, `InvestigationState` must remain persisted structurally backend-side, while Claude only receives human-readable `.to_summary()` snapshots to preserve its context limits, querying structured JSON when specifics (PIDs, IPs) are explicitly needed.

5. **Human Latency (Checkpointing):** Claude Desktop sessions are ephemeral. Without pause/resume architecture, hours of triage are lost if the app closes. I fully accept the requirement to build explicit `pause_investigation` and `resume_investigation` MCP endpoints that serialize/load the exact `InvestigationState` back into JSON checkpoints.

### The Fresh Repository Migration
Furthermore, the recommendation to establish a completely fresh `/root/SAVVYDFIR-MCP` workspace is necessary to break ties with the prototype MiroFish branch and cleanly establish the `.gitignore`, FastMCP server layout, and new `CLAUDE.md`.

**Action Plan:** I will establish the `/root/SAVVYDFIR-MCP` repository immediately, seed it with the accepted 5 tools (`start_investigation`, `analyze_memory`, `query_findings`, `pause`, `resume`), rewrite the `CLAUDE.md`, and execute the Migration Plan exactly as Agent 1 prescribed.
