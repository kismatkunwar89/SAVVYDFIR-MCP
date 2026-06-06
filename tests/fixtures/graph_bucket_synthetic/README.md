# Synthetic graph BUCKET_MAP fixture

D5 carry-forward from `review-graph-impl-plan-2026-05-30.md`. Validates every fallback path of the JS `BUCKET_MAP` in `templates/graph.html` against a controlled set of 10 synthetic findings.

## What's here

| File | Purpose |
|------|---------|
| `state.json` | 10 synthetic findings, each crafted to exercise one BUCKET_MAP fallback path. All have `confidence=0.95` + `finding_status=CONFIRMED` + a placeholder `mitre_technique` so the graph-emit noise filter (`conf<0.80 && !mitre && !CONFIRMED/PROBABLE`) doesn't drop them. |
| `audit.jsonl` | Minimal one-line audit entry so `investigation_graph.py` can build the graph without complaining about missing execution context. |
| `README.md` | This file. |

## What each finding tests

| F-ID | artifact_type | artifact_subtype | tool_name | Expected bucket |
|------|---|---|---|---|
| F-001 | _(absent)_ | _(absent)_ | synthetic | **Uncategorized** (no artifact_type → catch-all) |
| F-002 | `""` | `""` | synthetic | **Uncategorized** (empty artifact_type → catch-all) |
| F-003 | `disk` | `""` | synthetic | **Other / Disk** (disk + no subtype) |
| F-004 | `disk` | `future_unknown_subtype` | synthetic | **Other / Disk** (disk + unmapped subtype → bare disk) |
| F-005 | `cloud` | `""` | synthetic | **Uncategorized** (unknown artifact_type family) |
| F-006 | `disk` | `sigma` | `disk.sigma_hunt` | **Rule Detection / Sigma** |
| F-007 | `disk` | `hayabusa` | `disk.hayabusa_hunt` | **Rule Detection / Hayabusa** |
| F-008 | `yara` | `""` | `yara_scan` | **Rule Detection / YARA** |
| F-009 | `disk` | `evtx_event` | `disk.summarize_evtx` | **Event Logs / EVTX** (flat - no channel sub-grouping) |
| F-010 | `disk` | `""` | `disk.extract_registry_run_keys` | **Registry** (subtype empty → tool_name fallback wins) |
| F-011 | `disk` | `mft` | `disk.extract_mft_timeline` | **Filesystem** + infra-path REDACTION probe (artifact_path + supporting_indicators carry `/opt/SAVVYDFIR-MCP/`, `/cases/`, `/evidence/` prefixes that MUST be scrubbed; `investigator@example.test` + `ROOT\...` registry path MUST be preserved) |

## Redaction validation (judge-facing publish safety)

F-011 doubles as the infra-path redaction regression case. After rendering:

```bash
# INFRA prefixes MUST be ZERO in the rendered graph.html:
grep -c "/opt/SAVVYDFIR\|/cases/SYNTHETIC\|/evidence/synthetic" /tmp/.../graph.html   # → 0

# Evidence MUST be preserved:
grep -c "investigator@example.test" /tmp/.../graph.html   # → >0
grep -c "ControlSet001" /tmp/.../graph.html               # → >0 (registry path)

# Placeholders MUST appear:
grep -c "<install>\|<case-dir>\|<evidence>" /tmp/.../graph.html  # → >0
```

The redaction is a recursive pass over the entire graph payload (`_redact_infra_paths` in `scripts/investigation_graph.py`) applied before BOTH graph.json and graph.html are written - see `docs/graph-ui-design.md`.

## How to run the validation

```bash
python3 scripts/investigation_graph.py \
  --state tests/fixtures/graph_bucket_synthetic/state.json \
  --audit tests/fixtures/graph_bucket_synthetic/audit.jsonl \
  --output /tmp/savvydfir-bucket-fixture/graph.html
```

Open `/tmp/savvydfir-bucket-fixture/graph.html` in a browser with DevTools console open. Verify:

1. **Sidebar shows the expected buckets with the expected counts.** Specifically:
   - `Other / Disk` should show count = 2 (F-003 + F-004).
   - `Uncategorized` should show count = 3 (F-001 + F-002 + F-005).
   - `Rule Detection` should show count = 3 (F-006 + F-007 + F-008), expandable to Sigma / Hayabusa / YARA sub-rows.
   - `Event Logs / EVTX` should show count = 1 (F-009).
   - `Registry` should show count = 1 (F-010 - proves the `tool_name` fallback works).

2. **Zero JS console exceptions** on page load, on clicking each bucket, on `↺ Show all` reset.

3. **All 10 findings render** as nodes on the canvas (no noise-filter drops). If any are missing, the noise filter dropped them - check `confidence`, `finding_status`, or `mitre_technique`.

## When to extend the fixture

Add a new case to `state.json` whenever:

- A new `artifact_type` family is introduced by an MCP tool. Cover both the explicit-subtype and bare-artifact_type paths.
- A new tool is added to the `TOOL_NAME_TO_SUBTYPE` map in `templates/graph.html`. Add a fixture case with `artifact_subtype=""` and the new `tool_name` set.
- A new `BUCKET_MAP` key is added (e.g. a new `Filesystem` sub-row).

The existing 10 cases should keep passing. If they break, the BUCKET_MAP regressed.
