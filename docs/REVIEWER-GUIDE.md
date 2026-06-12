# Reviewer's Guide

A short orientation for anyone reviewing this repository. It maps the documentation to the six
Find Evil! judging criteria and points to traces you can reproduce yourself from a clone. No SIFT
VM is required for any step below.

The intent is to make verification fast, not to argue a score. Every example here was checked
against the committed files before it was written down.

## Where each criterion is addressed

| # | Criterion | Where to look |
|---|-----------|---------------|
| 1 | Autonomous Execution Quality | `docs/agent-execution-logs/<case>/trace.html` for the session arc, plus the correction events in `audit.jsonl` (section 3) |
| 2 | IR Accuracy | `docs/accuracy-report.md`, including the Measurement caveats and per-case false negatives, plus the finding-to-execution trace (section 2) |
| 3 | Breadth and Depth | `docs/architecture.md` (disk, memory, registry, logs). Cross-source correlation is `compare_disk_and_memory` (10 checks) and `find_temporal_clusters` |
| 4 | Constraint Implementation | `docs/architecture.md` trust boundaries and Evidence Integrity Model, with the bypass test at `tests/test_evidence_integrity_bypass.py` (section 4) |
| 5 | Audit Trail Quality | the hash-chained `docs/agent-execution-logs/<case>/audit.jsonl` (sections 2 and 5) |
| 6 | Usability and Documentation | `README.md` (Prerequisites, Installation, Usage), this guide, and the per-case `RUN-NOTES.md` |

The architectural pattern is a custom Model Context Protocol server. It exposes typed, read-only
forensic tools to the Claude Code agent over stdio JSON-RPC. Claude Code provides the runtime,
model, and MCP plumbing. This project provides the forensic tools, the deterministic guardrails,
the correlation engine, and the reporting layer.

## 2. Tracing a finding to the tool execution that produced it

Each CONFIRMED finding records an `execution_id` that resolves to a row in that case's
`audit.jsonl`. Four examples are listed below, drawn from two cases. Pick any of them.

Case `ROCBA-2020-FREDS-LAPTOP-v1.2.0` (`docs/agent-execution-logs/ROCBA-2020-FREDS-LAPTOP-v1.2.0/`):

| Finding | Claim | execution_id | Produced by |
|---------|-------|--------------|-------------|
| F-124 | Data-staging temporal cluster, 03:42 to 03:46 UTC 2020-11-14, 4 independent sources (EVTX, MFT, file_system, Prefetch), MITRE T1005 | E-206 | `correlation.find_temporal_clusters` |
| F-125 | Email-exfil temporal cluster, 14:00 to 14:04 UTC, 3 independent sources (EVTX, file_system, registry), T1114.001 | E-206 | same correlation run |

Case `ALI-WEBSERVER-WIN-L0ZZQ76PMUF` (`docs/agent-execution-logs/ALI-WEBSERVER-WIN-L0ZZQ76PMUF/`):

| Finding | Claim | execution_id | Produced by |
|---------|-------|--------------|-------------|
| F-426 | Web-shell deployment 2015-09-03 07:10 to 07:14, 3 independent sources (MFT, ShellBags, USN Journal), T1505.003 | E-118 | `correlation.find_temporal_clusters` |
| F-427 | Interactive RDP account creation, 2 sources (EVTX 4624 Type 10 and UserAssist) within 62 seconds, T1136.001 | E-118 | same correlation run |

To reproduce, confirm the cited `execution_id` exists in the ledger:

```bash
cd docs/agent-execution-logs/ROCBA-2020-FREDS-LAPTOP-v1.2.0
grep '"E-206"' audit.jsonl | head -1 | python3 -m json.tool | grep -E '"event_type"|"timestamp"'
```

The `execution_id` for each finding is in `report.json` under `all_findings[]` and is rendered
in `report.html`. If the id resolves in `audit.jsonl`, the trace is supported.

Note on the baseline case: the judged v1.1.1 ROCBA run (`ROCBA-2020-FREDS-LAPTOP/`) predates
audit-log retention and ships no `audit.jsonl`. Its `NOTE.md` explains this. Use the v1.2.0 ROCBA
directory or the ALI case above for a reproducible trace; both ship the full hash-chained ledger.

## 3. Self-correction in the logs

The corrections are written by the framework, not narrated in the demo. After analysis,
`compare_disk_and_memory` runs 10 contradiction checks. When disk and memory disagree, the engine
writes a `correction_event` to `audit.jsonl` and lowers the confidence of the affected finding.

```bash
cd docs/agent-execution-logs/ROCBA-2020-FREDS-LAPTOP-v1.2.0
python3 - <<'PY'
import json
for e in (json.loads(l) for l in open("audit.jsonl") if l.strip()):
    c = e.get("correction_event")
    if c:
        print(c["original_finding_id"], c["correction_type"],
              c["original_confidence"], "->", c["revised_confidence"])
PY
```

This run records 5 events, each `evidence_contradiction`, confidence HIGH to MEDIUM. The trigger
is a cross-artifact disagreement detected in code, not an injected error. The ALI case records 1
such event. The count per case is in `report.json` under `correction_events_count`.

## 4. Constraint implementation

- Read-only by construction. `SafeRunner` validates every command against `DENY_PATHS`. A write
  or destructive operation targeting `/evidence/` or `/mnt/` is blocked in code, using
  `subprocess.run(shell=False)` plus path validation and a deny list. Bypass attempts are
  exercised by `tests/test_evidence_integrity_bypass.py`.
- Evidence integrity. Hashes are verified at the start and end of an investigation. A mismatch
  raises a CRITICAL alert. See the Evidence Integrity Model in `docs/architecture.md`.
- Provenance gate. A CONFIRMED finding's `execution_id` must resolve to a real ledger row.
  Inherited, placeholder, and auto-generated ids are demoted. See
  `tests/test_confirmed_integrity.py`.
- Trust boundaries are drawn on the diagram in `docs/architecture.md`.

To run the guardrail tests:

```bash
python -m pytest tests/test_evidence_integrity_bypass.py tests/test_confirmed_integrity.py -q
```

## 5. Verifying the audit log is intact

The ledger is a linked hash chain. A sound check recomputes each `entry_hash` using the canonical
algorithm in `sift_mcp/audit.py`; checking only the chain links is not sufficient. The full
verifier and the report-to-ledger SHA-256 binding are documented in
[`agent-execution-logs/README.md`](agent-execution-logs/README.md). It passes on every committed
log. For example, the ROCBA v1.2.0 ledger has 483 rows with 0 hash mismatches and 0 broken links.

## 6. Headline claims and the code behind them

| Claim | Implementing code |
|-------|-------------------|
| Disk-versus-memory contradiction checks drive self-correction | the correlation engine in `sift_mcp/` (`compare_disk_and_memory`); corrections are written to `audit.jsonl` as `correction_event` rows |
| CONFIRMED status is gated by code: two or more independent sources, a ruled-out alternative, and resolvable provenance | enforced at the finding API and the report layer; guarded by `tests/test_confirmed_integrity.py`; see the CONFIRMED-status invariants in `CLAUDE.md` |

## 7. The honest parts

`docs/accuracy-report.md` states the limits plainly: precision is not measured because the ground
truth is non-exhaustive; "0 scored hallucinations" is a narrow known-negative check, not a
zero-error guarantee; and the per-case false negatives (such as OST email, the Google Drive client
database, browser-download specifics, and pcap or AV gaps) are listed rather than omitted. The
report also discloses that the recall figures were measured on the v1.1.1 engine and have not yet
been re-scored on v1.2.0. Documented gaps are recorded on purpose.
</content>
