# Reviewer's Guide — SAVVYDFIR-MCP

A two-minute orientation for a Find Evil! judge (or any reviewer). It maps the six judging
criteria to exact files, and gives **pre-verified traces you can reproduce yourself** — the
rules guarantee every finding is traceable to the tool execution that produced it, so this
guide just shows you the shortest path to confirming that.

Everything below is checkable from a clone of this repo; no SIFT VM required.

---

## Where each criterion lives

| # | Criterion | Look here |
|---|-----------|-----------|
| 1 | Autonomous Execution Quality | `docs/agent-execution-logs/<case>/trace.html` (session arc) + the **correction events** in `audit.jsonl` (§3 below) |
| 2 | IR Accuracy | `docs/accuracy-report.md` (incl. **Measurement caveats** + honest FN/per-case gaps) + the **three-claim trace** (§2 below) |
| 3 | Breadth & Depth | `docs/architecture.md` (disk + memory + registry + logs); cross-source correlation = `compare_disk_and_memory` (10 checks) and `find_temporal_clusters` |
| 4 | Constraint Implementation | `docs/architecture.md` "Trust & security boundaries" + "Evidence Integrity Model"; bypass test: `tests/test_evidence_integrity_bypass.py` (§4 below) |
| 5 | Audit Trail Quality | hash-chained `docs/agent-execution-logs/<case>/audit.jsonl` (§2 + §5 below) |
| 6 | Usability & Documentation | `README.md` (Prerequisites/Installation/Usage), this guide, per-case `RUN-NOTES.md` |

**Architectural pattern:** Custom MCP Server — a purpose-built Model Context Protocol server
exposing ~65 typed, read-only forensic tools to the Claude Code agent over stdio JSON-RPC. Not
an LLM wrapper. Claude Code is the runtime/model; this project is the forensic tooling,
deterministic guardrails, correlation engine, and reporting.

---

## 2. Three-claim trace (reproduce these)

Each CONFIRMED finding cites an `execution_id` that resolves to a real row in that case's
hash-chained `audit.jsonl`. Two cases, four pre-verified examples — pick any three:

**Case `ROCBA-2020-FREDS-LAPTOP-v1.2.0`** (`docs/agent-execution-logs/ROCBA-2020-FREDS-LAPTOP-v1.2.0/`):

| Finding | Claim | execution_id | Produced by |
|---------|-------|--------------|-------------|
| **F-124** | Data-staging temporal cluster, 03:42–03:46 UTC 2020-11-14, **4 independent sources** (EVTX+MFT+file_system+Prefetch), MITRE T1005 | `E-206` | `correlation.find_temporal_clusters` @ 2026-06-08T01:10:27Z |
| **F-125** | Email-exfil temporal cluster, 14:00–14:04 UTC, **3 independent sources** (EVTX+file_system+registry), T1114.001 | `E-206` | same correlation run |

**Case `ALI-WEBSERVER-WIN-L0ZZQ76PMUF`** (`docs/agent-execution-logs/ALI-WEBSERVER-WIN-L0ZZQ76PMUF/`):

| Finding | Claim | execution_id | Produced by |
|---------|-------|--------------|-------------|
| **F-426** | Web-shell deployment 2015-09-03 07:10–07:14, **3 independent sources** (MFT, ShellBags, USN Journal), T1505.003 | `E-118` | `correlation.find_temporal_clusters` @ 2026-06-06T13:33:24Z |
| **F-427** | Interactive RDP account-creation, **2 sources** (EVTX 4624 Type 10 + UserAssist) within 62s, T1136.001 | `E-118` | same correlation run |

**Reproduce (≈30 seconds):**

```bash
cd docs/agent-execution-logs/ROCBA-2020-FREDS-LAPTOP-v1.2.0
# the finding cites E-206; confirm that execution_id exists in the ledger and see what it ran:
grep '"E-206"' audit.jsonl | head -1 | python3 -m json.tool | grep -E '"tool_name"|"event_type"|"timestamp"'
```

The finding's `execution_id` is in each finding object of `report.json` (`all_findings[]`,
field `execution_id`) and rendered in `report.html`. If it resolves in `audit.jsonl`, the trace
is **supported**.

> **Honesty note:** the **judged v1.1.1 ROCBA baseline** (`ROCBA-2020-FREDS-LAPTOP/`) predates
> audit-log retention and ships **no** `audit.jsonl` — see its `NOTE.md`. Use the **v1.2.0**
> ROCBA dir or **ALI** (above) for a reproducible trace; both ship the full hash-chained ledger.

---

## 3. Self-correction (in the logs, not the video)

These are **automated framework corrections**, not narrated demo moments. After analysis,
`compare_disk_and_memory` runs 10 contradiction checks; when disk and memory disagree, the
engine writes a `correction_event` to `audit.jsonl` and demotes the overconfident finding.

```bash
cd docs/agent-execution-logs/ROCBA-2020-FREDS-LAPTOP-v1.2.0
python3 - <<'PY'
import json
for e in (json.loads(l) for l in open("audit.jsonl") if l.strip()):
    c=e.get("correction_event")
    if c: print(c["original_finding_id"], c["correction_type"],
                c["original_confidence"],"->",c["revised_confidence"])
PY
```

Expected: **5 events**, each `evidence_contradiction`, confidence `HIGH -> MEDIUM`. The trigger
is a genuine cross-artifact disagreement detected by code — not an injected error. (ALI shows 1
such event; the count is in each `report.json:correction_events_count`.)

---

## 4. Constraint Implementation (architectural, testable)

- **Read-only by construction.** `SafeRunner` validates every command against `DENY_PATHS`;
  any write/destructive op targeting `/evidence/` or `/mnt/` is blocked **in code**
  (`subprocess.run(shell=False)`, path validation + deny list) — the model cannot prompt past
  it. Bypass attempts are exercised by `tests/test_evidence_integrity_bypass.py`.
- **Evidence integrity.** Hashes verified at start and end; mismatch raises a CRITICAL alert
  (`docs/architecture.md` "Evidence Integrity Model").
- **Provenance gate.** A CONFIRMED finding's `execution_id` must resolve to a real ledger row;
  inherited/placeholder/auto IDs are auto-demoted (`tests/test_confirmed_integrity.py`).
- **Trust boundaries** are drawn on the diagram in `docs/architecture.md`.

Run the guardrail tests: `python -m pytest tests/test_evidence_integrity_bypass.py tests/test_confirmed_integrity.py -q`

---

## 5. Verify the audit log hasn't been tampered with

The ledger is a linked hash chain. A real check **recomputes** each `entry_hash` (the canonical
algorithm is in `sift_mcp/audit.py`) — link-only checks are insufficient. Full verifier and
the report↔ledger SHA-256 binding are documented in
[`agent-execution-logs/README.md`](agent-execution-logs/README.md#why-the-hash-chain-matters).
On every committed log it passes (e.g. ROCBA-v1.2.0: 483 rows, 0 mismatches, 0 broken links).

---

## 6. Claim-to-code (two headline claims → implementation)

| Headline claim | Implementing code |
|----------------|-------------------|
| "10 automated disk-vs-memory contradiction checks drive self-correction" | `sift_mcp/` correlation engine (`compare_disk_and_memory`); corrections written to `audit.jsonl` as `correction_event` rows |
| "CONFIRMED status is gated by code: ≥2 independent sources + ruled-out alternative + resolvable provenance" | enforced at the finding API + report layer; guarded by `tests/test_confirmed_integrity.py`; see CLAUDE.md "CONFIRMED-status invariants" |

---

## 7. Read the honest parts first

- `docs/accuracy-report.md` — **Measurement caveats** (precision unmeasured; "0 scored
  hallucinations" is a narrow known-negative bar, not a zero-error guarantee), per-case false
  negatives (OST email, Google-Drive DB, browser-download specifics, pcap/AV gaps), and the
  v1.1.1-vs-v1.2.0 disclosure.
- Documented gaps and absences are recorded, not hidden — that is the point. Per the rules,
  honesty is valued over perfection.
</content>
