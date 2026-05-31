#!/usr/bin/env python3
"""Operational invariant checker for a SAVVYDFIR-MCP investigation run.

Reads analysis/state.json (and the matching audit.jsonl if --strict) and
asserts the invariants the framework is supposed to guarantee. Exit code
0 = all pass, 1 = at least one fails. Designed for CI and post-run sanity.

Run2 lesson: a run can "complete" with 12 findings but skip sigma_hunt
entirely, leaving zero rule-based detections. This script catches that.

Usage
-----
    python3 scripts/validate_run.py                              # default paths
    python3 scripts/validate_run.py --state analysis/state.json  # explicit
    python3 scripts/validate_run.py --case-id HACKATHON-2026-WKSTN01
    python3 scripts/validate_run.py --strict                     # also audit.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = REPO_ROOT / "analysis" / "state.json"
DEFAULT_AUDIT = REPO_ROOT / "analysis" / "audit.jsonl"


# round-3 #M: share the bypass-resistant predicates with reporting.py
# instead of re-implementing them here (split-brain risk).
sys.path.insert(0, str(REPO_ROOT))
from sift_mcp.reporting import _needs_sigma_hunt_run, evaluate_ir_coverage_gate  # noqa: E402


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"❌ state.json not found at {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_audit(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


# ---------- invariants ----------

def check_sigma_hunt_succeeded(state: dict[str, Any]) -> tuple[bool, str]:
    """round-2 #H + round-3: share predicate with reporting.py to avoid split-brain.

    Successful = exit_code 0 AND duration > 0 AND audit_completed_entry_hash
    AND durable Chainsaw output (.json hint in outputs_summary OR
    finding_ids_generated populated OR explicit output_handle).
    Failed/timed-out/never-ran/no-output all fail.
    """
    executions = state.get("executions", [])
    if _needs_sigma_hunt_run(executions):
        return False, "no successful sigma_hunt execution with durable output recorded"
    for ex in executions:
        tool = str(ex.get("tool_name") or "")
        if tool != "detection.sigma_hunt" and not tool.endswith(".sigma_hunt"):
            continue
        try:
            ec = int(ex.get("exit_code") or -1)
        except (TypeError, ValueError):
            continue
        if ec != 0:
            continue
        return True, (
            f"sigma_hunt OK (exec {ex.get('execution_id')}, "
            f"{ex.get('duration_seconds'):.2f}s, "
            f"summary: {str(ex.get('outputs_summary') or '')[:80]})"
        )
    return False, "no successful sigma_hunt execution with durable output recorded"


def check_specialist_findings(state: dict[str, Any], minimum: int = 1) -> tuple[bool, str]:
    """At least one specialist subagent must have contributed.

    round-7 P2: prior implementation hardcoded ≥5 which was a Run2-
    specific assertion. Clean systems can legitimately produce fewer
    specialist findings. The invariant is "specialists were actually
    invoked", not a specific count.

    Override via env: SAVVYDFIR_MIN_SPECIALIST_FINDINGS=N.

    Provenance can be carried in finding.provenance.generated_by or
    finding.assigned_agent. Run2 had 0 specialist findings - all from main.
    """
    try:
        minimum = int(os.environ.get("SAVVYDFIR_MIN_SPECIALIST_FINDINGS", minimum))
    except ValueError:
        pass
    specialists = 0
    seen_agents: set[str] = set()
    for f in state.get("findings", []):
        agent = ""
        prov = f.get("provenance")
        if isinstance(prov, dict):
            agent = str(prov.get("generated_by") or prov.get("assigned_agent") or "")
        if not agent:
            agent = str(f.get("assigned_agent") or "")
        agent_norm = agent.lstrip("@").lower()
        if agent_norm and agent_norm not in ("main-agent", "main", "user", ""):
            specialists += 1
            seen_agents.add(agent_norm)
    ok = specialists >= minimum
    return ok, (
        f"{specialists} specialist findings across {len(seen_agents)} agents "
        f"(need ≥{minimum}; override via SAVVYDFIR_MIN_SPECIALIST_FINDINGS)"
    )


def check_coverage_gate(state: dict[str, Any]) -> tuple[bool, str]:
    """Recompute the gate live from state.

    round-3 #M: prior implementation trusted a stored ir_coverage_gate
    field with `ok: True`. A stale or manually-persisted ok flag could pass
    even when the actual executions/findings would have failed the gate.
    Now we recompute from raw state every time using the same evaluate_ir_
    coverage_gate function the report uses.
    """
    executions = state.get("executions") or []
    findings = state.get("findings") or []
    # sigma_result fields the gate looks at: anti_forensics_warnings.
    # Best-effort: pull from state if previously recorded.
    sigma_result = {
        "anti_forensics_warnings": state.get("anti_forensics_warnings") or [],
    }
    try:
        result = evaluate_ir_coverage_gate(
            findings=findings, executions=executions, sigma_result=sigma_result,
        )
    except Exception as exc:
        return False, f"recompute raised {type(exc).__name__}: {exc}"
    if result.get("ok") is True:
        return True, "coverage gate ok (recomputed live from state)"
    missing = result.get("missing") or []
    tools = ", ".join(m.get("tool", "?") for m in missing[:3])
    suffix = f" (+{len(missing)-3} more)" if len(missing) > 3 else ""
    return False, f"coverage gate has {len(missing)} gap(s): {tools}{suffix}"


def check_no_error_dispatch(audit_path: Path) -> tuple[bool, str]:
    """Verify the hook never tried to dispatch a specialist on a tool error.

    Looks for /tmp/savvydfir_delegate.json history (if archived) - best-effort.
    Run2 had the hook dispatching evtx-analyst even when summarize_evtx
    returned status=error. Fixed in f6eef87.
    """
    # We can't fully verify retrospectively without trigger history.
    # Check audit for the bug signature: tool error followed by lane lock.
    records = _load_audit(audit_path)
    errors_followed_by_lane: list[str] = []
    prev_was_error = False
    prev_tool = ""
    for r in records:
        tool = str(r.get("tool") or "")
        et = str(r.get("event_type") or "")
        if et == "completed":
            exit_code = r.get("exit_code")
            if exit_code is not None and int(exit_code) != 0:
                prev_was_error = True
                prev_tool = tool
                continue
            if prev_was_error and tool == "state.record_analysis_lane":
                # Lane being recorded right after a tool error - Run2 pattern.
                errors_followed_by_lane.append(prev_tool)
            prev_was_error = False
            prev_tool = ""
    if errors_followed_by_lane:
        return False, (
            f"{len(errors_followed_by_lane)} tool errors triggered immediate lane writes "
            f"(first: {errors_followed_by_lane[0]})"
        )
    return True, "no error-to-lane dispatch pattern detected"


def check_report_generated(state: dict[str, Any], case_id: str | None) -> tuple[bool, str]:
    case = case_id or state.get("case_id") or ""
    if not case:
        return False, "no case_id resolvable"
    report = REPO_ROOT / "reports" / case / "report.html"
    graph = REPO_ROOT / "reports" / case / "graph.html"
    if report.is_file() and graph.is_file():
        return True, f"report.html + graph.html present for {case}"
    missing = []
    if not report.is_file():
        missing.append("report.html")
    if not graph.is_file():
        missing.append("graph.html")
    return False, f"missing for {case}: {', '.join(missing)}"


# ---------- runner ----------

INVARIANTS = [
    ("sigma_hunt_succeeded", check_sigma_hunt_succeeded, "state"),
    ("specialist_findings_ge_5", check_specialist_findings, "state"),
    ("coverage_gate_passed", check_coverage_gate, "state"),
    ("report_generated", check_report_generated, "state+case"),
    ("no_error_dispatch", check_no_error_dispatch, "audit"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--case-id", type=str, default=None)
    parser.add_argument(
        "--allow-missing-audit",
        action="store_true",
        help=(
            "DOWNGRADE-ONLY. When set, missing audit.jsonl skips the hook-regression "
            "invariant AND the run is reported as INCOMPLETE-PASS (never full PASS). "
            "Prior default silently skipped this invariant."
        ),
    )
    args = parser.parse_args()

    state = _load_state(args.state)
    case_id = args.case_id or state.get("case_id")

    print(f"validate_run.py — case {case_id} — state {args.state}")
    print()

    audit_skipped = False
    failures: list[str] = []
    for name, fn, sig in INVARIANTS:
        try:
            if sig == "state":
                ok, msg = fn(state)
            elif sig == "state+case":
                ok, msg = fn(state, case_id)
            elif sig == "audit":
                if not args.audit.is_file():
                    if not args.allow_missing_audit:
                        # Default: audit.jsonl REQUIRED - fail loudly.
                        ok, msg = False, (
                            f"audit.jsonl not found at {args.audit}. Pass "
                            "--allow-missing-audit for downgraded validation."
                        )
                    else:
                        print(f"⏭  {name}: audit.jsonl absent, INVARIANT NOT VERIFIED "
                              f"(--allow-missing-audit downgrades result)")
                        audit_skipped = True
                        continue
                else:
                    ok, msg = fn(args.audit)
            else:
                ok, msg = False, f"unknown invariant signature {sig}"
        except Exception as exc:
            ok, msg = False, f"check raised {type(exc).__name__}: {exc}"
        marker = "✅" if ok else "❌"
        print(f"{marker} {name}: {msg}")
        if not ok:
            failures.append(name)

    print()
    if failures:
        print(f"FAIL — {len(failures)} invariant(s) failed: {', '.join(failures)}")
        return 1
    if audit_skipped:
        print("INCOMPLETE-PASS — state invariants ok but audit-backed invariants skipped")
        return 1
    print("PASS — all operational invariants satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
