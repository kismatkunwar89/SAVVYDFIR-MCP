# SAVVYDFIR-MCP FIND EVIL! Winning Plan

Last updated: 2026-04-03

## Executive Decision

We are not building a standalone MCP server product.

We are building a **Claude Code-driven Protocol SIFT autonomous incident response system** where:

- **Claude Code** is the primary agentic execution engine
- **SAVVYDFIR-MCP** is the purpose-built MCP backend
- **SIFT Workstation tools** are the deterministic forensic engines
- **Structured logs and provenance** make every finding traceable

This aligns with the official rules requiring an **agentic framework as the primary execution engine** and with the challenge guidance that a **custom MCP server** is the most sound architecture in evaluation.

## Winning Thesis

Build a self-correcting Protocol SIFT extension that uses Claude Code to investigate a case across **disk/timeline + memory** evidence through typed, read-only MCP tools, then produces a structured investigative narrative with full execution traces and explicit evidence provenance.

Short pitch:

`Claude Code autonomously triages cross-artifact evidence through our custom MCP server, self-corrects when analysis is incomplete or inconsistent, and produces traceable DFIR findings with architectural guardrails against evidence spoliation.`

## Why This Direction Wins

The judges score six equally weighted criteria:

1. Autonomous Execution Quality
2. IR Accuracy
3. Breadth and Depth of Analysis
4. Constraint Implementation
5. Audit Trail Quality
6. Usability and Documentation

This plan is optimized to score well on all six at once:

- `Autonomy`
  Claude Code drives sequencing, pivots, and retries.
- `Accuracy`
  Findings are tied to artifacts, offsets, timestamps, files, or log entries.
- `Breadth/Depth`
  We cover more than one evidence class without becoming shallow.
- `Constraints`
  The MCP layer enforces typed, read-only access.
- `Auditability`
  Every finding maps back to exact tool executions.
- `Usability`
  Judges can run it locally on SIFT with a README and sample datasets.

## Architecture Choice

### Chosen architecture

**Primary execution engine:** Claude Code

**Primary system architecture:** Custom MCP Server

**Behavioral model:** Single-agent self-correcting triage loop

**Scaling model later:** Specialized routing and optional sub-agent decomposition

### Why not the other paths first

- `Direct Agent Extension only`
  Fastest path, but weaker on architectural guardrails if used alone.

- `Multi-agent framework first`
  Too much complexity too early. Harder to debug, log, and stabilize.

- `Alternative IDE path`
  Possible, but not the strongest fit for evidence integrity.

### Final strategic position

We are entering on the **agentic framework track** using **Claude Code as the execution engine**, while differentiating on **a custom MCP safety/control plane** that makes the agent more reliable, more token-efficient, and more defensible.

## Concepts To Borrow From Valhuntir

Valhuntir is the official example quality bar referenced on the FIND EVIL! resources page. We should borrow its strongest architectural and operational ideas without copying its core human-in-the-loop workflow.

### Concepts worth adopting

- `Case-first data model`
  Keep findings, timeline events, evidence records, audit logs, and reports centered around a clearly structured case directory.

- `Modular MCP backend separation`
  Separate concerns such as forensic execution, case/state management, reporting, enrichment, and auditability instead of collapsing everything into one monolithic server.

- `Structured response envelopes`
  Return tool responses with provenance, caveats, corroboration suggestions, and discipline reminders rather than raw output only.

- `Evidence registration and integrity verification`
  Make integrity verification a first-class step before or during deeper triage.

- `Strong documentation and setup flow`
  Match the level of polish shown in Valhuntir’s docs, architecture pages, setup scripts, and tests.

- `Audit-first design`
  Treat audit trails and traceability as a core execution path, not optional post-processing.

- `Gateway and backend clarity`
  Be explicit about where the agent runs, where MCP services run, where evidence lives, and how trust boundaries are enforced.

### Concepts we should not center our design on

- `Human approval as the primary finding state transition`
  That is valuable for rigorous review workflows, but our competitive advantage is autonomous execution quality.

- `Generic command execution as the normal forensic interface`
  Even a denylist-protected `run_command` model is weaker than our typed, high-inference-constraint MCP design.

- `Matching Valhuntir’s full feature surface`
  We should not try to outbuild its breadth. We should outscore it on autonomy, self-correction, and cross-artifact reasoning.

### Our differentiation against Valhuntir

We should aim to combine:

- Valhuntir’s discipline and platform polish
- with our typed, read-only MCP surface
- with our autonomous self-correcting loop
- with explicit disk-plus-memory discrepancy detection and reconciliation

## High Inference Constraint

The MCP layer should be designed around a **high inference constraint**. The agent should not be forced to guess CLI syntax, flags, or safe execution patterns when the backend can encode them directly.

### Required design rule

- never expose a broad `run_command()` or equivalent shell passthrough as the normal forensic interface

### What to expose instead

- semantically named, typed MCP tools
- backend-owned parameter validation
- backend-owned CLI flag construction
- structured responses instead of raw terminal dumps

### Examples

- `get_file_system_hierarchy_using_fls(image_path, inode=None)`
- `parse_amcache_json(image_path)`
- `extract_mft_timeline(image_path)`
- `summarize_evtx(image_path, channel_or_filter)`

This reduces hallucinated tool usage, syntax mistakes, and accidental misuse of forensic CLIs.

## Submission Scope

### Required system behavior

The project must demonstrate all of the following:

- self-correction without human intervention
- findings traceable to concrete evidence
- structured investigative narrative, not just raw logs
- repeatable operation on SIFT Workstation

### Competitive forensic scope

The winning balance is:

- **Phase 1 competitive MVP**
  Disk/timeline + memory correlation

- **Phase 2 extension**
  Registry and Windows artifact enrichment

- **Phase 3 stretch**
  Network/log pivots or remote endpoint triage via MCP

### Why not memory-only

Memory-only may still be viable, but a stronger competition entry should show the agent can connect multiple artifact types the way a senior analyst would. The best practical compromise is:

- disk timeline to identify suspicious artifact history
- Windows artifact pivots for execution and persistence clues
- memory analysis to verify active process/network behavior

## Concrete Project To Build

### Project title

`SAVVYDFIR-MCP: A self-correcting cross-artifact Protocol SIFT copilot`

### Demo scenario

Given a disk image and memory capture from the same host, the system should:

1. extract a timeline and suspicious disk artifacts
2. identify execution and persistence clues
3. pivot into memory for active process/network evidence
4. detect contradictions or missing evidence
5. retry with adjusted tools or parameters
6. produce a structured triage narrative and exportable log trail

### What the judges should see

- Claude Code driving the investigation
- typed MCP tools being called
- at least one visible self-correction sequence
- findings labeled by confidence and evidence type
- a final report tied to artifact-level evidence

## System Design

## Layer 1: Agent

Claude Code handles:

- high-level reasoning
- tool sequencing
- follow-up pivots
- self-correction decisions
- report synthesis

Claude Code does **not** get generic shell authority over evidence handling in the final architecture.

## Layer 2: MCP Control Plane

SAVVYDFIR-MCP handles:

- typed forensic tool exposure
- parameter normalization
- safe subprocess execution
- bounded raw output capture
- parser orchestration
- validator execution
- structured state management
- audit logging
- checkpointing and export

It should also own the translation from investigator intent to exact CLI syntax so the LLM reasons over forensic concepts, not brittle command construction.

## Layer 3: Deterministic Tool Layer

SIFT tools perform the actual forensic extraction:

- Volatility 3
- Plaso / `log2timeline.py`
- `psort.py`
- Sleuth Kit tools
- Windows artifact parsers such as EZ Tools where available
- YARA for enrichment and hunting

## Layer 4: Output Layer

Outputs include:

- authoritative structured investigation state
- audit JSONL
- graph/timeline visualizations
- final triage report
- evidence dataset documentation
- accuracy report

## MCP Surface To Implement

The MCP server must expose **typed, semantically named tools**, not generic shell execution.

### Core disk/timeline tools

- `extract_mft_timeline(image_path)`
- `get_file_system_hierarchy_using_fls(image_path, inode=None)`
- `run_log2timeline(image_path)`
- `query_psort(timeline_path, query)`
- `list_deleted_files(image_path)`
- `get_file_metadata(image_path, path_or_inode)`
- `extract_prefetch_entries(image_path)`
- `extract_amcache_entries(image_path)`
- `parse_amcache_json(image_path)`
- `extract_registry_run_keys(image_path)`
- `summarize_evtx(image_path, channel_or_filter)`

### Core memory tools

- `detect_memory_profile(memory_path)`
- `run_pslist(memory_path)`
- `run_netscan(memory_path)`
- `run_malfind(memory_path)`
- `run_dlllist(memory_path, pid)`
- `dump_process_if_suspicious(memory_path, pid)`

### Correlation and hunting tools

- `compare_disk_and_memory_indicators(case_id)`
- `run_yara_on_files(target_path_or_case_id, rule_set)`
- `run_yara_on_memory(memory_path, rule_set)`
- `query_findings(filter_expression)`
- `read_authoritative_state(case_id)`
- `export_execution_trace(case_id)`

### High-level orchestrated tools

- `triage_case(case_manifest, max_iterations=4)`
- `resume_case(case_id)`
- `checkpoint_case(case_id, reason)`

The high-level tools are for the agent loop. The lower-level tools are for explainability, testing, and controlled pivots.

## Case Manifest Design

Use a structured case manifest instead of ad hoc inputs.

Suggested fields:

- `case_id`
- `disk_image_path`
- `memory_image_path`
- `optional_artifacts`
- `target_time_window`
- `known_iocs`
- `investigation_goal`
- `constraints`

This makes the run reproducible and easier for judges to follow.

## Authoritative Data Model

The backend must own structured truth. Chat summaries are not authoritative.

### Finding model

Each finding should include:

- `finding_id`
- `case_id`
- `finding_type`
- `artifact_type`
- `artifact_path`
- `artifact_offset`
- `timestamp_observed`
- `tool_name`
- `tool_args`
- `command_line`
- `execution_id`
- `iteration`
- `evidence_kind`
- `finding_status`
- `confidence`
- `raw_evidence_reference`
- `description`
- `supporting_indicators`
- `contradicted_by`
- `related_finding_ids`

### Execution model

Each tool execution should include:

- `execution_id`
- `case_id`
- `iteration`
- `tool_name`
- `parameters`
- `command_line`
- `start_time`
- `end_time`
- `duration_seconds`
- `exit_code`
- `stdout_reference`
- `stderr_reference`
- `validator_results`
- `agent_reason`

### Evidence typing

Every output must distinguish among:

- `observation`
  Directly supported by forensic output
- `inference`
  Supported analytic conclusion
- `hypothesis`
  Candidate lead requiring confirmation
- `rejected`
  Considered and ruled out

## Self-Correcting Agent Loop

This is the heart of the project.

### Loop design

1. Start with the case manifest and investigation goal
2. Run first-pass disk/timeline triage
3. Extract suspicious indicators
4. Pivot to supporting Windows artifacts
5. Pivot into memory for active verification
6. Run validators
7. If contradictions or failures exist, classify the issue
8. Adjust the next step or rerun with narrower/better parameters
9. Continue until completion criteria or `max_iterations`
10. Produce final narrative and export trace logs

### Persistent loop implementation pattern

Use a durable loop state on disk so learning survives retries and interruptions.

Suggested control files:

- `analysis/prd.json`
  current tasks, status, retry targets, and completion promises
- `analysis/progress.txt`
  compact human-readable notes on failures, lessons, and iteration changes

This gives the agent persistent working memory without making the chat transcript authoritative.

### Self-correction triggers

- tool failed or timed out
- parser returned malformed or empty result
- suspicious disk artifact has no supporting memory evidence
- memory process has no supporting disk/timeline explanation
- evidence supports only a hypothesis, not a confirmed finding
- a prior assumption is contradicted by a later artifact

### Self-correction actions

- rerun a tool with adjusted parameters
- run a follow-up tool in the same artifact family
- pivot to a second artifact family
- downgrade the claim strength
- preserve the contradiction explicitly in the report
- stop and mark unsupported rather than hallucinate

### Hook-driven reflection

Use Claude Code hooks to force reflection when tools fail or sessions end.

- `PostToolUse` or equivalent failure hook
  inspect `stderr`, classify the failure, update loop state, and trigger the next retry decision
- `Stop` hook
  append a session summary and final execution checkpoint to the audit log

Hooks should enrich the loop, not replace authoritative backend state.

### Loop guardrails

- hard `max_iterations`
- explicit completion promises
- bounded artifact scope
- no destructive tools
- mandatory logging of each retry decision

## Completion Promises

The agent should stop only when one of these is true:

- all high-confidence suspicious indicators have been checked against at least one corroborating artifact source
- no unresolved contradictions remain above a configured severity threshold
- maximum iterations reached and the unresolved issues are documented

This is stronger than “run some tools and stop.”

## Forensic Playbook Strategy

### Playbook 1: Initial disk/timeline triage

Goal:

- identify suspicious file creation, execution, persistence, and timeline anomalies

Tool families:

- Sleuth Kit
- Plaso
- EZ Tools or equivalent Windows artifact parsers

Recommended concrete parsers:

- `MFTECmd`
- `RECmd`
- `EvtxECmd`
- `AmcacheParser`

### Playbook 2: Memory verification

Goal:

- determine whether suspicious disk indicators correspond to active or recently active processes, injected memory, or network connections

Tool families:

- Volatility 3

Recommended pivot logic:

- if timeline, Amcache, Prefetch, or Registry Run key analysis surfaces an anomalous executable, persistence entry, or suspicious parent-child execution chain, the agent must pivot into memory automatically
- use `windows.pslist`, `windows.malfind`, and `windows.netscan` as the primary verification chain

### Playbook 3: Cross-artifact reconciliation

Goal:

- determine whether the story told by disk/timeline and memory is coherent

Examples:

- a file appears in timeline but not in expected execution artifacts
- a malicious process appears in memory with no clear disk parent
- persistence exists on disk but no active process remains in memory

### Playbook 4: Threat enrichment

Goal:

- increase confidence through signatures and pattern matching

Tool families:

- YARA
- hashing
- IOC matching

## Evaluation Strategy

The project needs a real eval system from the start.

### Core eval types

- `artifact correctness evals`
  Did the run identify the correct artifact-level indicators?

- `workflow evals`
  Did the agent choose appropriate next tools and pivots?

- `self-correction evals`
  Did the system recover from failure or contradiction?

- `narrative evals`
  Is the report structured, useful, and honest about uncertainty?

### Metrics

- confirmed findings
- inferred findings
- false positives
- missed expected findings
- unsupported claims
- self-correction count
- time to first high-confidence finding
- total tool executions
- mean iterations per case

### Benchmark data requirements

For each benchmark case, document:

- source of dataset
- artifact types present
- expected findings
- known limitations
- what the system found
- what it missed

### First-priority benchmark corpus

Our first-priority test and benchmark source is the SANS-hosted Egnyte folder provided by the user:

- `https://sansorg.egnyte.com/fl/HhH7crTYT4JK`

Treat this folder as the primary competition test corpus for early validation, demo selection, and accuracy reporting.

Important note:

- I could not inspect the Egnyte contents directly from this environment, so the exact file inventory, artifact types, and case mapping still need to be enumerated locally once access is available
- once enumerated, we should create a manifest for each case in `analysis/` and tag each one by artifact family such as disk, memory, timeline, logs, or network
- the first demo case should come from this corpus if licensing and reproducibility permit it

### Corpus-correlated understanding

Based on the user's corpus notes, the Egnyte test set currently contains two main scenario groups:

- `SRL-2015`
  four Windows VM disk images, distributed as zipped VM disks
- `SRL-2018`
  seven `E01` disk images plus twenty-two memory dumps representing a full enterprise compromise

This has immediate planning implications:

- `SRL-2018` is the primary target for development, demoing, and evaluation
- `SRL-2015` is still valuable, but should be treated mainly as a compatibility and regression corpus because older Windows versions may be less reliable in Volatility 3
- the empty `MEMORY IMAGES` folder should be treated as a future expansion path, not a blocker

### Primary demo and development case

The first end-to-end case should be:

- `SRL-2018 base-wkstn-01`

Reason:

- it has a matched `E01` disk image and memory dump
- it is smaller than many of the other corpus items
- it gives us the cleanest first implementation target for disk-plus-memory correlation

### Corpus strategy

Use the corpus in three tiers:

- `Tier 1`
  `SRL-2018 base-wkstn-01` for the first runnable MVP and primary demo
- `Tier 2`
  two to three additional matched `SRL-2018` hosts for cross-host validation and stronger accuracy reporting
- `Tier 3`
  the full twenty-two memory dumps plus matched disks where available for breadth claims in the accuracy report

### Known technical risk from the corpus

The user notes an important tooling risk:

- Volatility coverage for Windows XP and Windows 7 32-bit is generally stronger in Volatility 2 than in Volatility 3

Planning implication:

- do not anchor the MVP or demo on `SRL-2015`
- document Volatility 2 versus Volatility 3 compatibility in the accuracy report
- treat older-host support as an explicit test matrix item rather than assuming parity

### Case manifest example

The corpus validates the case-manifest approach. A representative manifest should look like:

```json
{
  "case_id": "SRL-2018-WKSTN-01",
  "disk_image_path": "/cases/SRL-2018/base-wkstn-01-c-drive.E01",
  "memory_image_path": "/cases/SRL-2018/base-wkstn-01-mem.raw",
  "scenario": "APT lateral movement - 2018 enterprise compromise"
}
```

### Natural self-correction opportunities from the corpus

The `SRL-2018` APT-style enterprise scenario should naturally produce discrepancy-driven retries:

- disk artifacts with no live memory confirmation
- live memory processes with weak or missing disk lineage
- persistence traces on disk without currently running processes
- potential fileless or injected-memory behavior

This is ideal for demonstrating the self-correcting loop without fabricating an artificial retry scenario.

### Candidate benchmark suites

- `DFIR-Metric`
  useful for multi-step reasoning and DFIR task understanding across disk and memory style cases
- `CFA-Bench`
  useful if we extend into network/log-driven incident workflows and want checkpoint-based evaluation

Use them only if they are practically runnable in the hackathon environment; otherwise document the gap and supplement with reproducible local benchmark cases.

### Scoring philosophy

Honesty beats inflated claims.

The accuracy report should explicitly list:

- missed pivots
- false positives
- unsupported inferences
- cases where the loop failed to self-correct fully

## Constraint and Safety Design

Constraint implementation is an equal-weight judging criterion. Treat it as a feature, not a footnote.

### Architectural constraints

- no generic `run_command()` for the agent in the final path
- read-only evidence handling
- scratchpad-only extraction targets
- credentials only via environment or local config, never hardcoded
- case data paths validated before execution

### Claude Code environment guardrails

Configure Claude Code settings so that:

- non-destructive forensic CLIs can be pre-approved where appropriate
- destructive commands are explicitly denied
- write access is scoped to `analysis/`, `exports/`, or other designated scratch locations

Commands to explicitly deny in the final operating guidance include patterns such as:

- `rm -rf`
- `dd` when used for destructive writes
- `wget`
- `curl`

The exact allow/deny policy should be documented in repo configuration and the accuracy report.

### Safety tests to document

- prompt-injection style attempt to ask the agent to modify evidence
- attempt to call a destructive operation through the MCP layer
- malformed path or path traversal style input
- oversized raw output response handling

The README and accuracy report should document what happened in each test.

## Audit Trail Design

This is non-negotiable.

### Required log categories

- `agent_decision`
- `llm_request`
- `llm_response`
- `tool_call`
- `tool_result`
- `validator_check`
- `retry_decision`
- `finding_created`
- `finding_updated`
- `finding_rejected`
- `checkpoint_created`
- `report_generated`

### Session tracing

If feasible, integrate an open-source session tracing layer such as `NOVA Protector` or an equivalent local tracer to capture:

- MCP calls
- file reads
- command executions
- session-level timelines

This should generate judge-friendly trace artifacts such as HTML reports under a dedicated path like `.nova-protector/reports/` or an equivalent local directory.

If NOVA Protector is not practical in the final build, we should still preserve the same traceability guarantees through native JSONL logs and exported summaries.

### Every finding must map to

- case id
- iteration
- tool execution id
- raw evidence reference
- final confidence and status

### Log formats

- JSONL for machine-readable traces
- optional Markdown/HTML summarized trace for judges

## Demo Plan

The demo video must be less than five minutes and show live terminal execution.

### Demo flow

1. Introduce the case briefly
2. Launch the agent against a real case manifest
3. Show typed MCP tool usage in the terminal trace
4. Show one self-correction sequence clearly
5. Show the final structured narrative and findings
6. Show where the execution log proves each claim

### What not to do

- no slide-only demo
- no marketing-style animation without terminal proof
- no hidden manual intervention during a claimed autonomous sequence

## Documentation Package

We must ship all required submission materials and make them strong.

### Required repo files

- `README.md`
- `LICENSE`
- `docs/architecture-diagram.md`
- `docs/dataset-documentation.md`
- `docs/accuracy-report.md`
- `docs/demo-script.md`
- `docs/execution-log-sample.md`

### README requirements

- install steps
- dependencies
- required environment variables
- how to run on SIFT
- how to run benchmark cases
- how to inspect logs
- architecture overview
- guardrail summary
- Claude Code settings / hook configuration summary

## Novel Contribution Positioning

The rules require the work to be substantially new during the hackathon period.

Our novel contribution should be described as:

- an agentic Protocol SIFT execution loop specialized for autonomous DFIR triage
- a typed MCP forensic control plane for safer and more reliable tool use
- cross-artifact reconciliation logic across disk/timeline and memory
- structured self-correction with iteration traces and provenance

Existing open-source tools remain the deterministic extraction engines, but the orchestration, validation, provenance model, and correlation behavior are the novel layer.

## Competition Roadmap

### Phase 0: Before hackathon start

Goal:

- prepare architecture, repo structure, and implementation design without claiming completed hackathon work

Tasks:

- finalize plan
- define data models and tool contracts
- clean repo structure
- document assumptions

### Phase 1: Week 1 of submission period

Goal:

- get a minimal end-to-end agentic run working on one case

Tasks:

- wire Claude Code to the MCP server
- replace mocked memory tool logic
- implement one disk/timeline tool path
- add JSONL logging skeleton
- prepare `SRL-2018 base-wkstn-01` as the first complete development case

Exit criteria:

- one case can be run from terminal through the agent with logged MCP calls

### Phase 2: Week 2

Goal:

- establish cross-artifact capability

Tasks:

- add MFT/timeline extraction
- add memory verification path
- build finding and execution provenance models
- persist authoritative state

Exit criteria:

- disk/timeline and memory findings can be correlated in one case

### Phase 3: Week 3

Goal:

- make the system genuinely autonomous, not just scripted

Tasks:

- add validators
- add retry logic
- add contradiction handling
- add completion promises

Exit criteria:

- at least one case shows a visible self-correction and successful reroute

### Phase 4: Week 4

Goal:

- increase analytical power and confidence

Tasks:

- add Windows artifact enrichment
- add YARA-based enrichment
- improve narrative generation

Exit criteria:

- the final report distinguishes observation, inference, and hypothesis clearly

### Phase 5: Week 5

Goal:

- turn the system into a measurable submission

Tasks:

- build benchmark harness
- enumerate the Egnyte test corpus into case manifests
- scale from the primary `base-wkstn-01` case to additional matched `SRL-2018` hosts
- create dataset documentation
- write accuracy report
- capture representative logs

Exit criteria:

- accuracy and failure modes are documented honestly

### Phase 6: Week 6

Goal:

- submission packaging and rehearsal

Tasks:

- finalize README
- create architecture diagram
- record demo
- verify public repo and license visibility

Exit criteria:

- all submission artifacts are ready before the deadline

## File-Level Backlog

### Backend files to modify

- `backend/app/mcp/server.py`
  Replace the mocked memory-only tool surface with typed cross-artifact forensic tools and high-level orchestration entry points.

- `backend/app/playbooks/memory_playbook.py`
  Convert from demo logic into real memory verification routines tied into the broader case triage loop.

- `backend/app/parsers/volatility_parser.py`
  Replace mock detections with structured parsers for real Volatility output.

- `backend/app/models/state.py`
  Expand into authoritative case, finding, and provenance state.

- `backend/app/main.py`
  Expose richer APIs for findings, iterations, logs, and provenance.

### New backend modules

- `backend/app/tools/volatility_runner.py`
- `backend/app/tools/plaso_runner.py`
- `backend/app/tools/sleuthkit_runner.py`
- `backend/app/tools/windows_artifact_runner.py`
- `backend/app/tools/yara_runner.py`
- `backend/app/validators/case_validators.py`
- `backend/app/logging/audit.py`
- `backend/app/orchestration/case_loop.py`
- `backend/app/models/execution.py`

### Frontend files to modify

- `frontend/src/App.vue`
  Add case-level status, iteration count, and execution trace access.

- `frontend/src/components/GraphPanel.vue`
  Add provenance, evidence type, and confidence/status detail views.

### New documentation files

- `README.md`
- `LICENSE`
- `docs/architecture-diagram.md`
- `docs/dataset-documentation.md`
- `docs/accuracy-report.md`
- `docs/demo-script.md`
- `docs/execution-log-sample.md`
- `docs/agent-behavior.md`

## MVP Definition

The MVP is ready when all of the following are true:

- Claude Code is the visible primary execution engine
- the MCP server exposes typed, read-only forensic tools
- one real case can be processed across disk/timeline and memory
- at least one self-correction cycle happens automatically
- findings are traceable to exact tool executions
- the final output is a structured investigative narrative
- the repo contains runnable setup instructions and a license

## Stretch Goals

- optional specialized sub-agent routing for artifact families
- remote endpoint triage through MCP
- richer graph visualization
- judge-friendly HTML execution trace export

Only pursue these after the MVP is stable.

## Top Risks

### Risk: too much breadth, not enough reliability

Mitigation:

- commit to disk/timeline + memory first
- start with one matched `SRL-2018` host before expanding to the full enterprise set
- treat other artifact types as optional extensions

### Risk: corpus/tool incompatibility on older Windows versions

Mitigation:

- treat `SRL-2015` as a secondary corpus
- explicitly test Volatility 3 compatibility before promising support
- document when Volatility 2 is required or when coverage is incomplete

### Risk: agent appears scripted instead of autonomous

Mitigation:

- log agent reasons for tool choice
- demonstrate at least one genuine retry or pivot
- preserve iteration-over-iteration changes

### Risk: logs are incomplete

Mitigation:

- make logging part of the execution path, not an afterthought
- fail closed if execution records cannot be written

### Risk: rules compliance gaps

Mitigation:

- keep public repo
- add MIT or Apache 2.0 license
- maintain English-language documentation
- verify demo, diagram, logs, dataset doc, and accuracy report all exist

## Immediate Next Actions

1. Reframe the repo and README around **Claude Code as the execution engine** and **SAVVYDFIR-MCP as the MCP backend**.
2. Replace the mocked memory workflow with real Volatility-backed execution.
3. Add one real disk/timeline path through Plaso, Sleuth Kit, and at least one Windows artifact parser such as `MFTECmd` or `RECmd`.
4. Implement authoritative state, JSONL audit logging, and hook-assisted session summaries.
5. Build the first self-correcting case loop with `max_iterations`, `analysis/prd.json`, and `analysis/progress.txt`.
6. Start with `SRL-2018 base-wkstn-01` as the first end-to-end case, then enumerate the remaining Egnyte corpus into local case manifests before expanding to `DFIR-Metric` or `CFA-Bench`.

## Source Index

Supporting research sources are listed in `RESEARCH_SOURCES.md`. The official rules you provided should now be treated as the controlling submission requirements if any earlier notes conflict.
