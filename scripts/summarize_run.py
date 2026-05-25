#!/usr/bin/env python3
"""Unified post-mortem for a SAVVYDFIR investigation.

Reads every audit surface (analysis/state.json, analysis/audit.jsonl,
/tmp/savvydfir_delegation_ledger.jsonl, /tmp/savvydfir_current_session.json,
reports/{case_id}/report.json) and emits ONE consolidated summary with:

  * Session metadata (id, start/end, total duration)
  * Phase timeline (Phase 1..7 buckets, eid + duration per call)
  * Lane completion: which lanes were Path A (specialist) vs Path B (main-agent)
  * Delegation ledger decision counts (task_attempt / outcome / would_*)
  * Findings by gate status: CONFIRMED, ACTIVE-demoted-by-gate, ACTIVE-other
  * Gate coverage: each mandatory tool's exit_code + duration
  * Report-generation attempt sequence (allow_partial transitions)

Two output formats: ``markdown`` (default, human-readable) and ``json``.

Usage:
  python3 scripts/summarize_run.py --case-id HACKATHON-2026-WKSTN01
  python3 scripts/summarize_run.py --case-id <id> --format json
  python3 scripts/summarize_run.py --case-id <id> --out /tmp/run.md

As a library:
  from scripts.summarize_run import build_summary
  summary = build_summary(case_id, analysis_dir, ledger_path, session_ptr_path)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

# Phase classifier — keep in sync with CLAUDE.md
PHASE_MAP: dict[str, str] = {
    # Phase 1 — Volatile data (memory)
    "memory.list_processes": "1_memory",
    "memory.scan_processes": "1_memory",
    "memory.detect_injection": "1_memory",
    "memory.scan_network": "1_memory",
    "memory.list_dlls": "1_memory",
    "memory.load_memory": "1_memory",
    # Phase 2 — Triage baseline (disk)
    "disk.extract_mft_timeline": "2_disk",
    "disk.extract_usn_journal": "2_disk",
    "disk.summarize_evtx": "2_disk",
    "disk.extract_prefetch": "2_disk",
    "disk.get_amcache": "2_disk",
    "disk.extract_shimcache": "2_disk",
    "disk.extract_registry_run_keys": "2_disk",
    "disk.extract_srum": "2_disk",
    "disk.extract_windows_artifacts": "2_disk",
    "disk.extract_pca": "2_disk",
    "disk.mount_image": "2_disk",
    # Phase 3 — Detection engines
    "detection.sigma_hunt": "3_detection",
    "detection.hayabusa_hunt": "3_detection",
    "detection.sigma_scan": "3_detection",
    "detection.analyze_vss": "3_detection",
    # Phase 5 — Cross-artifact correlation
    "correlation.compare_disk_and_memory": "5_correlation",
    "correlation.find_temporal_clusters": "5_correlation",
    "correlation.flag_discrepancy": "5_correlation",
    "timeline.build_timeline": "5_correlation",
    "timeline.query_timeline": "5_correlation",
    # Phase 7 — Reporting
    "reporting.generate_report": "7_reporting",
    "graph.generate_graph": "7_reporting",
    "graph.merge_host_graphs": "7_reporting",
    "graph.build_reports_index": "7_reporting",
    # Workflow control (not a phase)
    "state.add_finding": "workflow",
    "state.record_analysis_lane": "workflow",
    "state.read_state": "workflow",
    "state.export_trace": "workflow",
    "state.flag_discrepancy": "workflow",
    "state.update_finding": "workflow",
}

# Mandatory tools per CLAUDE.md coverage gate
MANDATORY_TOOLS: dict[str, str] = {
    "memory.list_processes":       "list_processes",
    "memory.scan_processes":       "scan_processes",
    "memory.detect_injection":     "detect_injection",
    "memory.scan_network":         "scan_network",
    "memory.list_dlls":            "list_dlls",
    "disk.extract_mft_timeline":   "extract_mft_timeline",
    "disk.extract_usn_journal":    "extract_usn_journal",
    "disk.summarize_evtx":         "summarize_evtx",
    "disk.extract_prefetch":       "extract_prefetch",
    "disk.get_amcache":            "get_amcache",
    "disk.extract_shimcache":      "extract_shimcache",
    "disk.extract_registry_run_keys": "extract_registry_run_keys",
    "disk.extract_srum":           "extract_srum",
    "detection.sigma_hunt":        "sigma_hunt",
    "correlation.compare_disk_and_memory": "compare_disk_and_memory",
}


def _classify_phase(tool: str) -> str:
    return PHASE_MAP.get(tool, "other")


def _phase_label(phase: str) -> str:
    labels = {
        "1_memory":      "Phase 1 — Memory (volatile)",
        "2_disk":        "Phase 2 — Disk triage",
        "3_detection":   "Phase 3 — Detection engines",
        "5_correlation": "Phase 5 — Cross-artifact correlation",
        "7_reporting":   "Phase 7 — Reporting",
        "workflow":      "Workflow control",
        "other":         "Other",
    }
    return labels.get(phase, phase)


def _read_json_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return rows
    return rows


def _utcparse(ts: Any) -> Optional[datetime]:
    if not isinstance(ts, str) or not ts.strip():
        return None
    text = ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _humanize_seconds(s: float) -> str:
    if s is None:
        return "?"
    s = float(s)
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s), 60)
    if m < 60:
        return f"{m}m {sec}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {sec}s"


def _resolve_paths(
    case_id: str,
    analysis_dir: Optional[Path],
    ledger_path: Optional[Path],
    session_ptr_path: Optional[Path],
    reports_dir: Optional[Path],
) -> dict[str, Path]:
    cwd = Path.cwd()
    if analysis_dir is None:
        env_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR")
        analysis_dir = Path(env_dir) if env_dir else (cwd / "analysis")
    if ledger_path is None:
        env_lp = os.environ.get("SAVVYDFIR_DELEGATION_LEDGER")
        ledger_path = Path(env_lp) if env_lp else Path("/tmp/savvydfir_delegation_ledger.jsonl")
    if session_ptr_path is None:
        env_sp = os.environ.get("SAVVYDFIR_SESSION_POINTER")
        session_ptr_path = Path(env_sp) if env_sp else Path("/tmp/savvydfir_current_session.json")
    if reports_dir is None:
        reports_dir = cwd / "reports" / case_id
    return {
        "analysis_dir": analysis_dir,
        "state_path": analysis_dir / "state.json",
        "audit_path": analysis_dir / "audit.jsonl",
        "ledger_path": ledger_path,
        "session_ptr_path": session_ptr_path,
        "reports_dir": reports_dir,
        "report_json": reports_dir / "report.json",
    }


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_session_section(audit_rows: list[dict], session_ptr: Optional[dict]) -> dict:
    started_at = None
    ended_at = None
    if audit_rows:
        first_ts = _utcparse(audit_rows[0].get("timestamp"))
        last_ts = _utcparse(audit_rows[-1].get("timestamp"))
        if first_ts:
            started_at = first_ts.isoformat()
        if last_ts:
            ended_at = last_ts.isoformat()
    duration_seconds: Optional[float] = None
    first_ts_obj = _utcparse(audit_rows[0].get("timestamp")) if audit_rows else None
    last_ts_obj = _utcparse(audit_rows[-1].get("timestamp")) if audit_rows else None
    if first_ts_obj and last_ts_obj:
        duration_seconds = (last_ts_obj - first_ts_obj).total_seconds()
    return {
        "session_id": (session_ptr or {}).get("session_id"),
        "session_pointer_cwd": (session_ptr or {}).get("cwd"),
        "session_pointer_started_at": (session_ptr or {}).get("started_at"),
        "audit_first_ts": started_at,
        "audit_last_ts": ended_at,
        "audit_duration_seconds": duration_seconds,
        "audit_duration_human": _humanize_seconds(duration_seconds) if duration_seconds else None,
    }


def _build_phase_timeline(audit_rows: list[dict]) -> dict[str, list[dict]]:
    """Bucket completed tool calls by phase. Each entry includes
    execution_id, tool, duration, exit_code, finding_ids_generated."""
    out: dict[str, list[dict]] = defaultdict(list)
    for row in audit_rows:
        if row.get("event_type") != "completed":
            continue
        tool = row.get("tool") or ""
        phase = _classify_phase(tool)
        out[phase].append({
            "timestamp": row.get("timestamp"),
            "execution_id": row.get("execution_id"),
            "tool": tool,
            "duration_seconds": row.get("duration_seconds"),
            "exit_code": row.get("exit_code"),
            "finding_ids_generated": row.get("finding_ids_generated") or [],
            "parameters_summary": _summarize_parameters(row.get("parameters")),
        })
    return dict(out)


def _summarize_parameters(params: Any) -> Optional[str]:
    if not isinstance(params, dict):
        return None
    keep = {}
    for key in ("case_id", "lane_id", "pid", "allow_partial",
                "status", "assigned_agent", "image_path", "csv_path"):
        if key in params and params[key] is not None:
            keep[key] = params[key]
    if not keep:
        return None
    return ", ".join(f"{k}={v!r}" for k, v in keep.items())


def _build_lanes_section(state: dict, ledger_rows_session: list[dict]) -> list[dict]:
    """For each lane, attribute Path A vs Path B and surface gaps + ledger evidence."""
    lanes_in_state = state.get("analysis_lanes") or []
    # Per-lane ledger summary
    lane_ledger: dict[str, dict] = defaultdict(lambda: {
        "task_attempts": 0, "outcomes": Counter(), "delegation_required": 0,
    })
    for r in ledger_rows_session:
        lane_id = r.get("lane_id")
        if not lane_id:
            continue
        ev = r.get("event")
        if ev == "delegation_required":
            lane_ledger[lane_id]["delegation_required"] += 1
        elif ev == "task_attempt":
            lane_ledger[lane_id]["task_attempts"] += 1
        elif ev == "task_outcome":
            outcome = r.get("outcome") or "unknown"
            lane_ledger[lane_id]["outcomes"][outcome] += 1

    rows = []
    for lane in lanes_in_state:
        if not isinstance(lane, dict):
            continue
        lane_id = lane.get("lane_id") or ""
        assigned = lane.get("assigned_agent") or ""
        is_path_a = bool(assigned) and "analyst" in assigned.lower()
        gaps = lane.get("data_gaps") or []
        gap_summaries = []
        for g in gaps:
            if isinstance(g, dict):
                reason = g.get("reason") or g.get("gap") or ""
                severity = g.get("severity") or ""
                gap_summaries.append(f"{severity}: {reason}" if severity else reason)
            elif isinstance(g, str):
                gap_summaries.append(g)
        rows.append({
            "lane_id": lane_id,
            "status": lane.get("status"),
            "assigned_agent": assigned,
            "path": "A" if is_path_a else "B",
            "finding_count": len(lane.get("finding_ids") or []),
            "gap_count": len(gaps),
            "gap_summaries": gap_summaries[:3],
            "ledger": {
                "delegation_required": lane_ledger[lane_id]["delegation_required"],
                "task_attempts": lane_ledger[lane_id]["task_attempts"],
                "outcomes": dict(lane_ledger[lane_id]["outcomes"]),
            },
        })
    return rows


def _build_ledger_section(ledger_rows_session: list[dict]) -> dict:
    by_event = Counter(r.get("event") for r in ledger_rows_session)
    outcome_dist = Counter(r.get("outcome") for r in ledger_rows_session if r.get("event") == "task_outcome")
    decision_breakdown = []
    for r in ledger_rows_session:
        ev = r.get("event") or ""
        if ev.startswith("path_b_"):
            decision_breakdown.append({
                "event": ev,
                "lane_id": r.get("lane_id"),
                "specialist": r.get("specialist"),
                "decision_basis": r.get("decision_basis"),
                "timestamp": r.get("timestamp"),
            })
    return {
        "row_count": len(ledger_rows_session),
        "by_event": dict(by_event),
        "task_outcome_distribution": dict(outcome_dist),
        "path_b_decisions": decision_breakdown,
    }


def _build_findings_section(state: dict) -> dict:
    findings = state.get("findings") or []
    by_status = Counter(f.get("finding_status") for f in findings)
    confirmed = []
    demoted = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        status = f.get("finding_status")
        csi = f.get("confidence_support_inputs") or {}
        blocks = csi.get("confirmed_gate_blocks") if isinstance(csi, dict) else None
        rec = {
            "finding_id": f.get("finding_id"),
            "finding_type": f.get("finding_type"),
            "confidence": f.get("confidence"),
            "execution_id": f.get("execution_id"),
            "execution_id_source": csi.get("execution_id_source") if isinstance(csi, dict) else None,
            "requires_re_extraction": f.get("requires_re_extraction"),
            "disposition": f.get("disposition"),
        }
        if status == "CONFIRMED":
            confirmed.append(rec)
        elif blocks:
            rec["blocks"] = blocks
            demoted.append(rec)
    # finding_type histogram for ACTIVE
    type_hist = Counter(f.get("finding_type") for f in findings if f.get("finding_status") == "ACTIVE")
    return {
        "total": len(findings),
        "by_status": dict(by_status),
        "confirmed_findings": confirmed[:20],
        "demoted_findings": demoted[:20],
        "active_finding_type_top10": type_hist.most_common(10),
    }


def _build_gate_coverage(audit_rows: list[dict]) -> dict:
    """For each mandatory tool, surface its last completed run."""
    by_tool: dict[str, dict] = {}
    for row in audit_rows:
        if row.get("event_type") != "completed":
            continue
        tool = row.get("tool") or ""
        if tool not in MANDATORY_TOOLS:
            continue
        prior = by_tool.get(tool)
        ts = _utcparse(row.get("timestamp"))
        if (prior is None) or (ts and (_utcparse(prior.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)) < ts):
            by_tool[tool] = row
    summary = {}
    for tool, short in MANDATORY_TOOLS.items():
        row = by_tool.get(tool)
        if row:
            summary[short] = {
                "ran": True,
                "execution_id": row.get("execution_id"),
                "duration_seconds": row.get("duration_seconds"),
                "exit_code": row.get("exit_code"),
                "outputs_summary": (row.get("outputs_summary") or "")[:120],
            }
        else:
            summary[short] = {"ran": False}
    summary["__missing__"] = [short for short, s in summary.items() if not s.get("ran")]
    return summary


def _build_report_attempts(audit_rows: list[dict]) -> list[dict]:
    out = []
    for row in audit_rows:
        if row.get("event_type") != "completed":
            continue
        if row.get("tool") != "reporting.generate_report":
            continue
        params = row.get("parameters") or {}
        out.append({
            "timestamp": row.get("timestamp"),
            "execution_id": row.get("execution_id"),
            "allow_partial": params.get("allow_partial"),
            "exit_code": row.get("exit_code"),
            "outputs_summary": (row.get("outputs_summary") or "")[:200],
        })
    return out


def _build_failures_section(audit_rows: list[dict], max_items: int = 5) -> list[dict]:
    """Last N audit rows where exit_code is non-zero / non-null."""
    failures = []
    for row in audit_rows:
        if row.get("event_type") != "completed":
            continue
        ec = row.get("exit_code")
        if ec not in (0, None):
            failures.append({
                "timestamp": row.get("timestamp"),
                "execution_id": row.get("execution_id"),
                "tool": row.get("tool"),
                "exit_code": ec,
                "outputs_summary": (row.get("outputs_summary") or "")[:200],
            })
    return failures[-max_items:]


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def build_summary(
    case_id: str,
    *,
    analysis_dir: Optional[Path] = None,
    ledger_path: Optional[Path] = None,
    session_ptr_path: Optional[Path] = None,
    reports_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Build the consolidated summary dict for *case_id*."""
    paths = _resolve_paths(case_id, analysis_dir, ledger_path, session_ptr_path, reports_dir)

    state = _read_json_file(paths["state_path"]) or {}
    audit_rows = _read_jsonl(paths["audit_path"])
    ledger_rows_all = _read_jsonl(paths["ledger_path"])
    session_ptr = _read_json_file(paths["session_ptr_path"]) or {}
    report_json = _read_json_file(paths["report_json"]) or {}

    # Filter ledger to the current session only (if a pointer is set)
    active_session_id = session_ptr.get("session_id")
    if active_session_id:
        ledger_rows_session = [r for r in ledger_rows_all if r.get("session_id") == active_session_id]
    else:
        ledger_rows_session = ledger_rows_all

    return {
        "case_id": case_id,
        "paths": {k: str(v) for k, v in paths.items()},
        "session": _build_session_section(audit_rows, session_ptr),
        "phase_timeline": _build_phase_timeline(audit_rows),
        "lanes": _build_lanes_section(state, ledger_rows_session),
        "ledger_summary": _build_ledger_section(ledger_rows_session),
        "findings": _build_findings_section(state),
        "gate_coverage": _build_gate_coverage(audit_rows),
        "report_attempts": _build_report_attempts(audit_rows),
        "failures": _build_failures_section(audit_rows),
        "report_artifact_summary": {
            "report_html_exists": (paths["reports_dir"] / "report.html").exists(),
            "report_json_exists": paths["report_json"].exists(),
            "report_status": (report_json or {}).get("status") if isinstance(report_json, dict) else None,
        },
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def render_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# SAVVYDFIR Run Summary — {summary['case_id']}")
    a("")

    # Session
    sess = summary["session"]
    a("## Session")
    a(f"- session_id: `{sess.get('session_id') or '(none)'}`")
    a(f"- audit_first_ts: `{sess.get('audit_first_ts') or '(none)'}`")
    a(f"- audit_last_ts:  `{sess.get('audit_last_ts') or '(none)'}`")
    a(f"- duration: **{sess.get('audit_duration_human') or '(n/a)'}**")
    a("")

    # Phase timeline
    a("## Phase Timeline")
    timeline = summary["phase_timeline"]
    for phase in ("1_memory", "2_disk", "3_detection", "5_correlation", "7_reporting", "workflow", "other"):
        entries = timeline.get(phase) or []
        if not entries:
            continue
        a(f"### {_phase_label(phase)} ({len(entries)} call{'s' if len(entries) != 1 else ''})")
        for e in entries:
            dur = _humanize_seconds(e.get("duration_seconds")) if e.get("duration_seconds") is not None else "?"
            ec = e.get("exit_code")
            ec_mark = "ok" if ec in (0, None) else f"exit={ec}"
            fids = e.get("finding_ids_generated") or []
            fid_part = f" → {len(fids)} finding(s)" if fids else ""
            params = e.get("parameters_summary")
            param_part = f"  [{params}]" if params else ""
            a(f"- `{e.get('execution_id') or '?':<6}` {e.get('tool'):<40} {dur:<8} {ec_mark}{fid_part}{param_part}")
        a("")

    # Lanes
    a("## Lanes (Path attribution)")
    a("| Lane | Status | Agent | Path | Findings | Task Attempts | Outcomes |")
    a("|------|--------|-------|------|----------|---------------|----------|")
    for lane in summary["lanes"]:
        outcomes_str = ", ".join(f"{k}={v}" for k, v in (lane["ledger"]["outcomes"] or {}).items())
        a(
            f"| {lane.get('lane_id') or '?'} "
            f"| {lane.get('status') or '?'} "
            f"| {lane.get('assigned_agent') or '?'} "
            f"| **{lane.get('path')}** "
            f"| {lane.get('finding_count')} "
            f"| {lane['ledger']['task_attempts']} "
            f"| {outcomes_str or '-'} |"
        )
    # Surface gaps inline
    for lane in summary["lanes"]:
        if lane.get("gap_summaries"):
            a("")
            a(f"**Gaps for `{lane.get('lane_id')}`:**")
            for g in lane["gap_summaries"]:
                a(f"  - {g}")
    a("")

    # Ledger summary
    ledger = summary["ledger_summary"]
    a("## Delegation Ledger")
    a(f"- Total session rows: {ledger['row_count']}")
    if ledger["by_event"]:
        a("- By event:")
        for ev, c in sorted(ledger["by_event"].items(), key=lambda x: -x[1]):
            a(f"  - `{ev}`: {c}")
    if ledger["task_outcome_distribution"]:
        a("- Task-outcome distribution:")
        for outcome, c in sorted(ledger["task_outcome_distribution"].items(), key=lambda x: -x[1]):
            a(f"  - `{outcome}`: {c}")
    if ledger["path_b_decisions"]:
        a("- Path B decisions (most recent first):")
        for d in ledger["path_b_decisions"][-10:][::-1]:
            a(
                f"  - `{d['event']}` lane=`{d.get('lane_id') or '?'}` "
                f"specialist=`{d.get('specialist') or '?'}` "
                f"basis=`{(d.get('decision_basis') or '')[:120]}`"
            )
    a("")

    # Findings
    findings = summary["findings"]
    a("## Findings")
    a(f"- Total: **{findings['total']}**")
    for status, c in sorted(findings["by_status"].items(), key=lambda x: -x[1]):
        a(f"  - `{status}`: {c}")
    a("")
    if findings["confirmed_findings"]:
        a(f"### CONFIRMED ({len(findings['confirmed_findings'])} shown, capped at 20)")
        for f in findings["confirmed_findings"]:
            a(
                f"- `{f['finding_id']}` type=`{f.get('finding_type') or '?'}` "
                f"conf={f.get('confidence')} eid=`{f.get('execution_id')}` "
                f"src=`{f.get('execution_id_source') or 'n/a'}` "
                f"disposition=`{f.get('disposition') or 'n/a'}`"
            )
        a("")
    if findings["demoted_findings"]:
        a(f"### ACTIVE — demoted by gate ({len(findings['demoted_findings'])} shown)")
        a("These were CONFIRMED candidates that failed the provenance or alternative-hypothesis gate.")
        for f in findings["demoted_findings"]:
            blocks = f.get("blocks") or []
            blocks_str = ", ".join(f"`{b}`" for b in blocks)
            a(
                f"- `{f['finding_id']}` type=`{f.get('finding_type') or '?'}` "
                f"blocks=[{blocks_str}] "
                f"requires_re_extraction={f.get('requires_re_extraction')}"
            )
        a("")
    if findings.get("active_finding_type_top10"):
        a("### ACTIVE finding-type distribution (top 10)")
        for ftype, c in findings["active_finding_type_top10"]:
            a(f"- `{ftype or '?'}`: {c}")
        a("")

    # Gate coverage
    cov = summary["gate_coverage"]
    a("## Gate Coverage (mandatory tools)")
    missing = cov.get("__missing__", [])
    if missing:
        a(f"**MISSING ({len(missing)}):** " + ", ".join(f"`{m}`" for m in missing))
    a("")
    a("| Tool | Ran | execution_id | Duration | Exit | Output |")
    a("|------|-----|--------------|----------|------|--------|")
    for short, s in cov.items():
        if short.startswith("__"):
            continue
        if s.get("ran"):
            dur = _humanize_seconds(s.get("duration_seconds"))
            a(
                f"| `{short}` | ok | `{s['execution_id']}` | {dur} "
                f"| {s.get('exit_code')} | {s.get('outputs_summary','')[:60]} |"
            )
        else:
            a(f"| `{short}` | MISSING | - | - | - | - |")
    a("")

    # Report attempts
    attempts = summary["report_attempts"]
    if attempts:
        a("## Report-Generation Attempts")
        for attempt in attempts:
            a(
                f"- `{attempt['execution_id']}` "
                f"allow_partial={attempt.get('allow_partial')} "
                f"exit={attempt.get('exit_code')} "
                f"→ {attempt.get('outputs_summary','')[:120]}"
            )
        a("")

    # Failures
    failures = summary.get("failures", [])
    if failures:
        a("## Recent Failures (last 5)")
        for f in failures:
            a(
                f"- `{f.get('execution_id')}` {f.get('tool')} "
                f"exit={f.get('exit_code')} :: {(f.get('outputs_summary') or '')[:160]}"
            )
        a("")

    # Artifact summary
    ras = summary.get("report_artifact_summary", {})
    a("## Final Artifact")
    a(f"- report.html: {'present' if ras.get('report_html_exists') else 'MISSING'}")
    a(f"- report.json: {'present' if ras.get('report_json_exists') else 'MISSING'}")
    if ras.get("report_status"):
        a(f"- report status: `{ras['report_status']}`")
    a("")

    # Footer
    a("---")
    a("Generated by `scripts/summarize_run.py`. Source files:")
    for key, p in summary.get("paths", {}).items():
        a(f"- `{key}`: `{p}`")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case-id", required=True, help="Case identifier (e.g. HACKATHON-2026-WKSTN01)")
    parser.add_argument("--analysis-dir", type=Path, default=None,
                        help="Directory containing state.json + audit.jsonl (default: ./analysis or SAVVYDFIR_ANALYSIS_DIR)")
    parser.add_argument("--ledger", type=Path, default=None,
                        help="Delegation ledger path (default: /tmp/savvydfir_delegation_ledger.jsonl)")
    parser.add_argument("--session-pointer", type=Path, default=None,
                        help="Session pointer path (default: /tmp/savvydfir_current_session.json)")
    parser.add_argument("--reports-dir", type=Path, default=None,
                        help="Reports dir for this case (default: ./reports/<case-id>)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--out", type=Path, default=None,
                        help="Output file (default: stdout)")
    args = parser.parse_args(argv)

    summary = build_summary(
        args.case_id,
        analysis_dir=args.analysis_dir,
        ledger_path=args.ledger,
        session_ptr_path=args.session_pointer,
        reports_dir=args.reports_dir,
    )

    if args.format == "json":
        payload = json.dumps(summary, indent=2, default=str)
    else:
        payload = render_markdown(summary)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
        print(f"wrote: {args.out}", file=sys.stderr)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
