# graph.html UI Design — Final State + Deltas-from-Consensus

**Last updated:** 2026-05-30
**Files:** `templates/graph.html`, `scripts/investigation_graph.py:497`
**Synthetic fixture:** `tests/fixtures/graph_bucket_synthetic/state.json` (10 cases, all bucket fallback paths)
**Consensus archives:** `consensus-graph-artifact-tree-2026-05-30.md` (design), `consensus-graph-impl-plan-2026-05-30.md` (implementation)

This document is the **permanent record** of why the shipped graph.html UI diverges from the consensus-ratified spec. Read this before re-introducing any of the removed features.

---

## What the UI actually does today

The Graph tab of `reports/<case_id>/graph.html` renders a force-directed D3 graph of the case's findings, their evidence sources, and the case node. The sidebar has five sections:

1. **Search** — substring match against node labels.
2. **Artifact Type** — tree of forensic-artifact buckets driven by the `BUCKET_MAP` JS dict. Click a row to filter the canvas to that bucket.
3. **Analysis Layers** — second section for detection/correlation buckets (Rule Detection, Correlation).
4. **Node Roles** — four checkboxes (Case, Evidence Source, Finding, Correction). All four checked by default.
5. **Evidence Kind** — colored legend with corpus counts (OBSERVATION / INFERENCE / HYPOTHESIS / REJECTED).

Canvas chrome:
- **`View:` chip** (top-left) — names the active view (`Findings Overview` / a bucket name / `N buckets selected`).
- **`Visible: X / Y` status** — live count vs corpus total.
- **`↺ Show all` button** (top-right) — resets bucket filters and returns to the default view. Always available.

There is no Focus Mode. There is no corroboration-chain bridge button. Provenance lineage is shown by the always-on `Case → Evidence Source → Finding` arrow tree.

---

## Why these UX choices (the deltas from consensus)

The original peer reviewer design consensus (`consensus-graph-artifact-tree-2026-05-30.md`) ratified a 7-knob spec that included a Focus Mode subsystem (hop-radius slider + Focus button + Show corroboration chain button + Evidence Source hidden-by-default). The implementation initially landed that spec, then iterated against real `runs/run-9-rocba/` data and real-user feedback. Five deltas resulted:

### Delta 1 — Focus Mode removed

**Consensus position:** Focus Mode was Knobs 4 + 5 (focus button + corroboration-chain bridge). peer reviewer's sign-off explicitly named it "the strongest judge-facing idea so far."

**Live-debug reality:** the user judged the subsystem to be UX complexity tax. The provenance story (which corroboration chain was supposed to surface) is already told by the always-on `Case → Evidence Source → Finding` arrow tree — judges don't need an extra modal to see lineage.

**What stayed:** the detail panel still shows `corroborated_by:` on every Finding. Clicking a CONFIRMED inference still lets a judge read the corroboration chain by reading the panel. We just removed the canvas-isolation view that highlighted only the chain.

**If you want to re-introduce it:** ship a follow-up PR. Don't re-add it because the consensus mentions it — the consensus is superseded by the user feedback recorded here.

### Delta 2 — Evidence Source default-checked

**Consensus position:** Evidence Source unchecked-by-default to keep the first impression uncluttered.

**Live-debug reality:** with Evidence Source hidden, the default canvas was a flat constellation of green dots with no edges visible. Judges couldn't see provenance without first finding and toggling a checkbox they didn't know existed.

**What changed:** `state.visibleRoles` defaults to `Set(['case','evidence_source','finding','correction'])`. The Node Roles checkbox is checked at page load. User can still uncheck it to get the original consensus-style view.

**Drilling override (preserved):** when `state.selectedBuckets.size > 0`, the internal `effectiveRoles` Set force-includes `evidence_source` even if the user has unchecked the box. Drilling into a bucket always shows the lineage edges.

### Delta 3 — `TOOL_NAME_TO_SUBTYPE` fallback

**Consensus position:** none. The consensus assumed `artifact_subtype` would be populated by the framework at submit_finding time.

**Live-debug reality:** the actual `runs/run-9-rocba/state.json` had 28/61 findings with `artifact_subtype=""`. They landed in `Other / Disk`. That's 46% of the corpus in an uninformative bucket — a UX failure.

**What was added:** the `TOOL_NAME_TO_SUBTYPE` map in `templates/graph.html` infers the subtype from `tool_name` (with the framework's `disk.` / `memory.` prefix stripped via `split('.').pop()`). After the fallback ships, **zero findings** in run-9-rocba land in `Other / Disk`.

**The proper long-term fix** (out of scope for this PR): populate `artifact_subtype` at submit_finding time in the framework, so the fallback isn't needed. The fallback handles legacy state.json files forever.

### Delta 4 — Adaptive force tuning + zoom floors

**Consensus position:** none. The consensus assumed D3's default behaviour was fine.

**Live-debug reality:** D3 force-simulation parameters tuned for ~60 nodes (`chargeStrength=-300`, `linkDistance=100`, `collisionPad=8`) flung small subsets to the canvas corners as specks when the user filtered. `fitGraph` had a 0.9x scale cap that prevented zooming IN on sparse subsets, and iterated the full corpus including stale hidden-node positions, so bounds were always huge.

**What was added:**
- Force parameters scale to visible node count (3 bands at fnCount > 40 / > 15 / else).
- Position reset on filter — nodes spawn on a cosine-arc circle around canvas center.
- `fitGraph` iterates `simulation.nodes()` (the current visible set) instead of full corpus.
- Scale cap raised 0.9 → 3.0.
- Zoom floors: visible ≤ 6 → ≥2.5x, ≤ 15 → ≥1.8x, ≤ 30 → ≥1.3x.
- Fit triggers via three independent paths (`simulation.on('end')`, 600ms after `rerender()`, 2500ms fallback).

### Delta 5 — Label dy + edge-label visibility band

**Consensus position:** none. Labels were always-on at default zoom.

**Live-debug reality:** circle node labels sit `sz/2+14` below the center, but rectangle (Case / Evidence Source) nodes have a much taller hitbox — labels at `sz/2+14` overlapped the rectangle bottom edge. Edge labels (`produced` ×60 at the disk-source hub) created an unreadable text soup.

**What was added:**
- Per-shape `labelDy`: rectangles use `sz*0.7 + 16`; correction diamonds use `sz*0.9 + 14`; circles use `sz/2 + 14`.
- Edge labels visible only in the zoom band `0.8 < zoom < 1.6`. Outside that band they hide.

---

## How to add a new artifact family

When a new MCP tool emits findings with a new `artifact_type` or `artifact_subtype`:

1. **If the new tool sets `artifact_subtype` correctly:** add an entry to `BUCKET_MAP` in `templates/graph.html`. Key is `"<artifact_type>:<artifact_subtype>"` lowercase. Pick a sensible section (`'artifact'` or `'analysis'`), bucket name, and optional sub label.

2. **If the new tool only sets `artifact_type`:** add an entry to `BUCKET_MAP` keyed on `"<artifact_type>"` bare.

3. **If the new tool predates this fix and leaves `artifact_subtype` blank:** add a `TOOL_NAME_TO_SUBTYPE` entry mapping the tool name (without the `disk.` / `memory.` prefix) to the appropriate subtype.

4. **Unknown families fall through to `Uncategorized`** (for unknown `artifact_type`) or `Other / Disk` (for explicit `disk` with unmapped subtype) — the sidebar never breaks, but the new family won't be discoverable until you add it.

5. **Verify** with the synthetic fixture (`tests/fixtures/graph_bucket_synthetic/state.json`) — add a new case to that fixture covering the new family. The validator inline in the file confirms expected bucket placement.

---

## Publish-safety: infra-path redaction (judge-facing artifacts)

Both `reports/<case_id>/graph.html` and `graph.json` are self-contained, publishable artifacts served by the static HTTP server. Embedded node fields (`artifact_path`, `provenance.command_line`, `supporting_indicators`, `embedding_text`, `outputs_summary`, etc.) can carry operator-side paths copied out of `state.json` / `audit.jsonl` — e.g. `/opt/SAVVYDFIR-MCP/...`, `/home/<operator>/...`, `/cases/<id>/...`. Those reveal the install location and operator, and **fail the judge-facing agnostic bar** (peer reviewer consensus 2026-05-30, `consensus-graph-remote-ready-2026-05-30.md`).

`scripts/investigation_graph.py` runs a **recursive infra-path redaction pass** (`_redact_infra_paths` over the whole `graph_data` structure, applied before BOTH graph.json and graph.html are written). It scrubs ONLY infrastructure path prefixes:

| Prefix | Placeholder |
|--------|-------------|
| `/opt/SAVVYDFIR-MCP/`, `~/SAVVYDFIR-MCP/`, `/home/<user>/SAVVYDFIR-MCP/` | `<install>/` |
| `~/` (operator home), `/home/<user>/` | `<home>/` |
| `/cases/<case_id>/` (and any `/cases/*/`) | `<case-dir>/` |
| `/evidence/<dataset>/` | `<evidence>/` |
| `/mnt/<x>/` | `<mount>/` |
| `/tmp/<random-tail>` | `<tmp>` |

**Preserved (forensic evidence — never touched):** case-side emails, attacker/victim IPs, Windows registry paths (`ROOT\...`), hostnames from the image, finding IDs, the case_id as a label (not a path), MITRE technique IDs, tool names.

**Why recursive (peer reviewer carry-forward):** a fixed field list misses `supporting_indicators` / `outputs_summary` / `agent_reason` / future fields. The pass walks every string in the payload.

**Agnostic:** all patterns derive from `os.path` / `Path.home()` + the `case_id` arg — zero hardcoded operator/host/case tokens. The regression probe is fixture finding F-011 (see `tests/fixtures/graph_bucket_synthetic/`).

**Acceptance grep on rendered output** (must be ZERO): `/opt/SAVVYDFIR`, `/home/`, `venv`, the VM IP, `/cases/`, `/evidence/`, `/mnt/`. Must still be PRESENT: case emails, registry paths, attacker IPs.

## Agnostic guarantee

Every value driving the sidebar is computed from `GRAPH_DATA` at render time. There are zero hardcoded case identifiers, finding IDs, hostnames, IPs, dates, or MITRE technique IDs in either changed file. The grep gate enforces this mechanically:

```bash
grep -iE "ROCBA|frocba|stark|2020-11|52\.249|SRL-FORGE|fred|kismat|referenceensics|10\.0\.0\.33|F-08[0-9]|F-09[0-9]" \
    templates/graph.html scripts/investigation_graph.py
```

Must return zero hits. If you touch either file, re-run the grep before committing.

---

## Six peer reviewer interaction guardrails (still held)

These were named load-bearing in the implementation consensus. The shipped UI honors all six except #4 (which is moot because Focus Mode is gone):

1. ✓ **Caret click expands/collapses only.** Never filters.
2. ✓ **Category row click = filter.** Toggle on/off.
3. ✓ **Finding row click = select + open detail panel.** Does NOT auto-focus.
4. — **Focus is explicit.** N/A — no Focus Mode.
5. ✓ **Sidebar counts are static corpus counts.** Canvas status line shows visible count separately.
6. ✓ **Every filtered/focused state has an obvious `↺ Show all` reset.**

---

## When to revisit this design

- **A future PR re-introduces Focus Mode or corroboration-chain bridge.** Discuss the UX tradeoff explicitly. Don't ship it because the original consensus mentioned it — get a fresh user sign-off.
- **A new artifact family appears.** Add to `BUCKET_MAP` (or `TOOL_NAME_TO_SUBTYPE` if subtype is missing) + the synthetic fixture.
- **The framework starts populating `artifact_subtype` reliably at submit_finding time.** Once verified, the `TOOL_NAME_TO_SUBTYPE` fallback becomes dead code — leave it as backward-compat for legacy state.json files.
- **EVTX channel sub-grouping becomes implementable.** Channel data is currently on raw EventRecord artifacts only, not Finding records. If the framework propagates `channel` to Findings, the BUCKET_MAP can grow a nested level under Event Logs / EVTX. Density trigger from the original consensus: ≥10 findings AND ≥2 distinct channels.
