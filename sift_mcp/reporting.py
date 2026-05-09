"""Report-generation helpers that stay importable without FastMCP."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def _parse_iso8601(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _pending_delegate_is_fresh(
    pending_delegate: dict[str, Any], *, delegate_file: Path
) -> bool:
    try:
        max_age_seconds = int(
            os.environ.get("SAVVYDFIR_TRIGGER_MAX_AGE_SECONDS", "21600") or "21600"
        )
    except ValueError:
        max_age_seconds = 21600
    if max_age_seconds <= 0:
        return True

    created_at = _parse_iso8601(pending_delegate.get("created_at"))
    if created_at is None:
        modified_at = datetime.fromtimestamp(
            delegate_file.stat().st_mtime, tz=timezone.utc
        )
    else:
        modified_at = created_at
    age_seconds = (datetime.now(timezone.utc) - modified_at).total_seconds()
    return age_seconds <= max_age_seconds


def _pending_delegate_blocks_case(
    pending_delegate: dict[str, Any], *, case_id: str, delegate_file: Path
) -> bool:
    if pending_delegate.get("processed") is not False:
        return False
    if not _pending_delegate_is_fresh(pending_delegate, delegate_file=delegate_file):
        return False
    pending_case_id = str(pending_delegate.get("case_id") or "").strip()
    if pending_case_id and pending_case_id != case_id:
        return False
    return True


def _status_label(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


# Status precedence: CONFIRMED findings surface first, then HYPOTHESIS → OBSERVATION.
# REJECTED findings are demoted to last.
_STATUS_PRECEDENCE: dict[str, int] = {
    "CONFIRMED": 4,
    "HYPOTHESIS": 3,
    "ACTIVE": 2,
    "OBSERVATION": 1,
    "REJECTED": 0,
}


def _short_description(value: Any, limit: int = 140) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _rank_findings(findings: list[dict[str, Any]], *, limit: int = 25) -> list[dict[str, Any]]:
    findings = [
        finding for finding in findings
        if str(finding.get("finding_kind") or "validated").lower() != "raw_detector_hit"
    ]

    def _sort_key(finding: dict[str, Any]) -> tuple[int, float, str]:
        status = _status_label(finding.get("finding_status"))
        precedence = _STATUS_PRECEDENCE.get(status, 1)
        confidence = float(finding.get("confidence", 0.0) or 0.0)
        recency = str(finding.get("updated_at") or finding.get("created_at") or "")
        return (precedence, confidence, recency)

    ranked = sorted(findings, key=_sort_key, reverse=True)
    return [dict(finding) for finding in ranked[:limit]]


def _split_findings_by_status(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Bucket findings by normalized status."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        status = _status_label(f.get("finding_status"))
        buckets.setdefault(status, []).append(f)
    return buckets


def _count_by_key(
    findings: list[dict[str, Any]], key: str,
) -> dict[str, int]:
    """Count findings grouped by a given key field."""
    counts: dict[str, int] = {}
    for f in findings:
        val = str(f.get(key) or "UNKNOWN").upper()
        counts[val] = counts.get(val, 0) + 1
    return counts


def _finding_quality_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Clarify raw finding counts versus reportable investigation claims."""
    status_breakdown = _count_by_key(findings, "finding_status")
    kind_breakdown = _count_by_key(findings, "finding_kind")
    reportable_statuses = {"CONFIRMED", "HYPOTHESIS", "ACTIVE"}
    raw_detector_hits = kind_breakdown.get("RAW_DETECTOR_HIT", 0)
    reportable_count = sum(
        1
        for finding in findings
        if (
            _status_label(finding.get("finding_status")) in reportable_statuses
            and str(finding.get("finding_kind") or "validated").lower() != "raw_detector_hit"
        )
    )
    return {
        "raw_persisted_findings": len(findings),
        "raw_detector_hits": raw_detector_hits,
        "reportable_findings": reportable_count,
        "confirmed_findings": status_breakdown.get("CONFIRMED", 0),
        "active_or_hypothesis_findings": (
            status_breakdown.get("ACTIVE", 0) + status_breakdown.get("HYPOTHESIS", 0)
        ),
        "rejected_findings": status_breakdown.get("REJECTED", 0),
        "semantics": (
            "findings_count is the raw persisted finding-record count. "
            "It is not a de-duplicated incident count. Sigma and other detector "
            "observations can be stored as raw_detector_hit records; use "
            "reportable_findings, raw_detector_hits, and status_breakdown for "
            "investigation quality."
        ),
    }


def _render_findings_rows(findings: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('finding_id', '')))}</td>"
            f"<td>{html.escape(_status_label(finding.get('finding_status')))}</td>"
            f"<td>{float(finding.get('confidence', 0.0) or 0.0):.3f}</td>"
            f"<td>{html.escape(str(finding.get('tool_name', '')))}</td>"
            f"<td>{html.escape(_short_description(finding.get('description', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='5'>No findings recorded.</td></tr>"


def _render_tactic_tags(tactics: list[dict[str, Any]], *, class_name: str) -> str:
    if not tactics:
        return "<span class='tag muted'>None</span>"
    return "".join(
        f"<span class='tag {class_name}'>{html.escape(tactic['id'])} — {html.escape(tactic['name'])}</span>"
        for tactic in tactics
    )


def _render_suggested_tools(suggestions: dict[str, list[str]]) -> str:
    if not suggestions:
        return "<li>No additional ATT&amp;CK blind-spot follow-up suggested.</li>"
    items: list[str] = []
    for tactic_id, tools in suggestions.items():
        items.append(
            f"<li><strong>{html.escape(tactic_id)}</strong>: {html.escape(', '.join(tools))}</li>"
        )
    return "\n".join(items)


def _render_leads(leads: list[dict[str, Any]]) -> str:
    if not leads:
        return "<tr><td colspan='5'>No actionable leads recorded.</td></tr>"
    rows: list[str] = []
    for lead in leads[:25]:
        pivot = lead.get("next_pivot") if isinstance(lead.get("next_pivot"), dict) else {}
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(lead.get('severity', '')))}</td>"
            f"<td>{html.escape(str(lead.get('detector', '')))}</td>"
            f"<td>{float(lead.get('confidence', 0.0) or 0.0):.2f}</td>"
            f"<td>{html.escape(_short_description(lead.get('description', ''), 180))}</td>"
            f"<td>{html.escape(str(pivot.get('human_readable') or ''))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_warning_items(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<li>None recorded.</li>"
    return "".join(
        f"<li><strong>{html.escape(str(item.get('type') or item.get('detector') or 'warning'))}</strong>: "
        f"{html.escape(str(item.get('message') or item.get('description') or item))}</li>"
        for item in items
    )


def _render_json_items(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<li>None recorded.</li>"
    return "".join(
        f"<li><pre>{html.escape(json.dumps(item, indent=2, default=str))}</pre></li>"
        for item in items
    )


def _render_lane_rows(lanes: list[dict[str, Any]]) -> str:
    if not lanes:
        return "<tr><td colspan='7'>No analysis lanes recorded.</td></tr>"
    rows: list[str] = []
    for lane in lanes:
        agents = [str(lane.get("assigned_agent") or "")]
        agents.extend(str(agent) for agent in (lane.get("supporting_agents") or []))
        agent_text = ", ".join(agent for agent in agents if agent)
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(lane.get('lane_id') or ''))}</td>"
            f"<td>{html.escape(str(lane.get('status') or ''))}</td>"
            f"<td>{'yes' if lane.get('required') else 'no'}</td>"
            f"<td>{html.escape(agent_text or 'unowned')}</td>"
            f"<td>{len(lane.get('execution_ids', []) or [])}</td>"
            f"<td>{len(lane.get('finding_ids', []) or [])}</td>"
            f"<td>{html.escape(_short_description(lane.get('summary') or '', 180))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


_LANE_SPECS: dict[str, dict[str, Any]] = {
    "evidence_access": {"title": "Evidence Access", "required": False, "phase": "phase0"},
    "memory": {"title": "Memory Analyst", "required": True, "phase": "analysis"},
    "disk_execution_persistence": {"title": "Disk Execution and Persistence", "required": True, "phase": "analysis"},
    "event_auth": {"title": "Event Log and Auth", "required": True, "phase": "analysis"},
    "anti_forensics_recovery": {"title": "Anti-Forensics and Recovery", "required": True, "phase": "analysis"},
    "timeline_correlation": {"title": "Timeline and Correlation", "required": True, "phase": "analysis"},
}

EXPECTED_LANE_AGENTS: dict[str, tuple[str, ...]] = {
    "memory": ("memory-analyst",),
    "disk_execution_persistence": (
        "registry-analyst",
        "prefetch-analyst",
        "amcache-analyst",
        "browser-analyst",
    ),
    "event_auth": ("evtx-analyst",),
    "anti_forensics_recovery": (
        "evtx-analyst",
        "sigma-analyst",
        "timeline-analyst",
    ),
    "timeline_correlation": (
        "mft-analyst",
        "sigma-analyst",
        "srum-analyst",
        "timeline-analyst",
        "corroboration-analyst",
    ),
}

_BARE_TOOL_ALIASES: dict[str, str] = {
    "analyze_vss": "disk.analyze_vss",
    "sigma_hunt": "detection.sigma_hunt",
    "sigma_scan": "detection.sigma_scan",
    "query_sigma_results": "detection.query_sigma_results",
    "compare_disk_and_memory": "correlation.compare_disk_and_memory",
    "generate_graph": "graph.generate_graph",
}


def _canonical_tool_name(tool_name: Any) -> str:
    text = str(tool_name or "").strip()
    if not text:
        return ""
    if "." in text:
        return text.lower()
    return _BARE_TOOL_ALIASES.get(text, text).lower()


def _lane_template(lane_id: str, *, legacy_inferred: bool = False) -> dict[str, Any]:
    spec = _LANE_SPECS.get(lane_id, {})
    return {
        "lane_id": lane_id,
        "title": spec.get("title", lane_id.replace("_", " ").title()),
        "status": "UNKNOWN" if legacy_inferred else "PENDING",
        "required": bool(spec.get("required", True)),
        "legacy_inferred": legacy_inferred,
        "phase": spec.get("phase", "analysis"),
        "assigned_agent": None,
        "supporting_agents": [],
        "summary": "",
        "lane_inference_confidence": "low" if legacy_inferred else None,
        "execution_ids": [],
        "finding_ids": [],
        "related_lane_ids": [],
        "data_gaps": [],
        "anti_forensics_warnings": [],
        "next_pivots": [],
        "started_at": None,
        "completed_at": None,
    }


def _infer_lane_from_tool_name(tool_name: Any) -> str | None:
    canonical = _canonical_tool_name(tool_name)
    if not canonical:
        return None
    if canonical.startswith("memory."):
        return "memory"
    if canonical in {
        "disk.extract_mft_timeline",
        "disk.extract_prefetch",
        "disk.get_amcache",
        "disk.extract_shimcache",
        "disk.extract_registry_run_keys",
        "disk.extract_pca",
        "disk.extract_srum",
        "disk.extract_scheduled_tasks",
    }:
        return "disk_execution_persistence"
    if canonical in {
        "disk.summarize_evtx",
        "detection.sigma_hunt",
        "detection.sigma_scan",
        "detection.query_sigma_results",
    }:
        return "event_auth"
    if canonical == "disk.analyze_vss":
        return "anti_forensics_recovery"
    if canonical.startswith("correlation.") or canonical.startswith("timeline.") or canonical.startswith("graph."):
        return "timeline_correlation"
    return None


def _infer_lane_from_finding(finding: dict[str, Any]) -> tuple[str | None, str | None]:
    finding_type = str(finding.get("finding_type") or "").lower()
    description = str(finding.get("description") or "").lower()
    if finding_type == "anti_forensics_recovery" or any(token in description for token in ("shadow cop", "log clear", "empty log", "wiped")):
        return "anti_forensics_recovery", "medium"
    lane_id = _infer_lane_from_tool_name(finding.get("tool_name"))
    if lane_id:
        return lane_id, "high"
    if any(token in description for token in ("scheduled task", "services.xml", "gpo", "run key", "timestomp")):
        return "disk_execution_persistence", "medium"
    if any(token in description for token in ("winrm", "lateral movement", "connection", "c2", "netscan")):
        return "timeline_correlation", "medium"
    return None, None


def classify_missing_artifact_record(
    *,
    artifact_family: str,
    is_mandatory: bool,
    exists: bool | None = None,
    parser_succeeded: bool | None = None,
    record_count: int | None = None,
    file_size_bytes: int | None = None,
    corroborating_signals: list[str] | None = None,
    reason: str | None = None,
    lane_id: str | None = None,
) -> dict[str, Any]:
    signals = [str(signal) for signal in (corroborating_signals or []) if str(signal).strip()]
    classification = "unknown"
    if exists is False:
        classification = "not_collected" if is_mandatory else "outside_manifest_scope"
    elif parser_succeeded is False:
        classification = "parser_failed"
    elif record_count == 0 or (file_size_bytes is not None and file_size_bytes < 131072):
        classification = "wiped" if signals else "empty"
    elif exists and parser_succeeded:
        classification = "present"
    return {
        "artifact_family": artifact_family,
        "classification": classification,
        "reason": reason or "",
        "lane_id": lane_id,
        "corroborating_signals": signals,
    }


def _merge_warning_lists(*collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for collection in collections:
        for item in collection:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("type") or item.get("detector") or item.get("classification") or ""),
                str(item.get("message") or item.get("description") or item.get("reason") or ""),
                str(item.get("lane_id") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
    return merged


MANDATORY_DISK_TOOL_SUFFIXES = frozenset({
    "extract_mft_timeline",
    "summarize_evtx",
    "extract_registry_run_keys",
    "get_amcache",
    "extract_prefetch",
})
MANDATORY_MEMORY_TOOL_SUFFIXES = frozenset({
    "list_processes",
    "scan_processes",
    "scan_network",
})
_EXTENDED_ANTI_FORENSICS_PATTERNS = (
    "1102",
    "104",
    "wevtutil",
    "sdelete",
    "cipher /w",
    "cipher ",
    "clearing event",
    "event log was cleared",
    "audit log was cleared",
    "cleared the security log",
)


def _execution_tool_suffix(tool_name: str) -> str:
    tn = str(tool_name or "").strip()
    if "." in tn:
        return tn.rsplit(".", 1)[-1]
    return tn


def _collect_execution_suffixes(executions: list[dict[str, Any]]) -> set[str]:
    return {_execution_tool_suffix(e.get("tool_name")) for e in executions}


def _needs_detect_injection(findings: list[dict[str, Any]]) -> bool:
    for f in findings:
        try:
            if int(f.get("psscan_only_count") or 0) > 0:
                return True
        except (TypeError, ValueError):
            pass
        if f.get("requires_deeper_analysis") is True:
            return True
    return False


def _needs_list_dlls(findings: list[dict[str, Any]]) -> bool:
    for f in findings:
        pids = f.get("network_followup_pids") or f.get("network_pids") or []
        if isinstance(pids, list) and len(pids) > 0:
            return True
    return False


def _signals_extended_anti_forensics_coverage(
    findings: list[dict[str, Any]],
    sigma_result: dict[str, Any],
) -> bool:
    if sigma_result.get("anti_forensics_warnings"):
        return True
    for f in findings:
        blob = f"{f.get('description', '')} {f.get('tool_name', '')}".lower()
        if any(p in blob for p in _EXTENDED_ANTI_FORENSICS_PATTERNS):
            return True
    return False


def evaluate_ir_coverage_gate(
    *,
    findings: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    sigma_result: dict[str, Any],
) -> dict[str, Any]:
    """Return missing Windows IR tool coverage required before a final report."""
    suffixes = _collect_execution_suffixes(executions)
    missing: list[dict[str, Any]] = []

    def _add(tool: str, suffix: str, classification: str, reason: str) -> None:
        if suffix in suffixes:
            return
        missing.append(
            {
                "tool": tool,
                "classification": classification,
                "reason": reason,
            }
        )

    for suff in ("list_processes", "scan_processes", "scan_network"):
        _add(
            f"memory.{suff}",
            suff,
            "mandatory_memory_baseline",
            "Universal Windows IR memory triage requires pslist, psscan, and netscan.",
        )

    if _needs_detect_injection(findings):
        _add(
            "memory.detect_injection",
            "detect_injection",
            "memory_hidden_process_followup",
            "Psscan-only PIDs or requires_deeper_analysis; run detect_injection on the dump.",
        )
    if _needs_list_dlls(findings):
        _add(
            "memory.list_dlls",
            "list_dlls",
            "memory_network_pid_followup",
            "Established external connections; run list_dlls for owning PIDs.",
        )

    for suff in sorted(MANDATORY_DISK_TOOL_SUFFIXES):
        _add(
            f"disk.{suff}",
            suff,
            "mandatory_disk_baseline",
            "Universal Windows IR disk triage requires MFT, EVTX, registry, Amcache, and Prefetch.",
        )

    if _signals_extended_anti_forensics_coverage(findings, sigma_result):
        for suff, full in (
            ("analyze_vss", "disk.analyze_vss"),
            ("extract_shimcache", "disk.extract_shimcache"),
            ("extract_srum", "disk.extract_srum"),
        ):
            _add(
                full,
                suff,
                "anti_forensics_signal",
                "Anti-forensics or log-manipulation signals require VSS, ShimCache, and SRUM follow-up.",
            )

    if not missing:
        return {"ok": True, "missing": [], "next_required_tool": None}
    return {
        "ok": False,
        "missing": missing,
        "next_required_tool": missing[0]["tool"],
    }


def refresh_report_graph_flags(
    *,
    case_id: str,
    reports_root: str = "./reports",
) -> dict[str, Any]:
    """Update graph_missing / data_gaps in an existing report.json after graph generation."""
    report_dir = (Path(reports_root) / case_id).resolve()
    report_json_path = report_dir / "report.json"
    if not report_json_path.is_file():
        return {"status": "skipped", "reason": "report.json not found"}

    try:
        payload = json.loads(report_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "error", "reason": str(exc)}

    graph_html_path = report_dir / "graph.html"
    graph_json_path = report_dir / "graph.json"
    graph_exists = graph_html_path.is_file() or graph_json_path.is_file()

    status_flags = dict(payload.get("status_flags") or {})
    status_flags["graph_missing"] = not graph_exists
    payload["status_flags"] = status_flags

    gaps = [g for g in (payload.get("data_gaps") or []) if isinstance(g, dict)]
    gaps = [g for g in gaps if g.get("classification") != "graph_missing"]
    if not graph_exists:
        gaps.append(
            {
                "artifact_family": "graph",
                "classification": "graph_missing",
                "reason": "graph.html / graph.json not present under report directory.",
                "lane_id": "timeline_correlation",
                "next_required_tool": "generate_graph",
            }
        )
    payload["data_gaps"] = gaps
    payload["next_required_tool"] = "generate_graph" if not graph_exists else None
    if graph_exists and "graph_path" not in payload:
        payload["graph_path"] = str(graph_html_path) if graph_html_path.is_file() else None
        payload["graph_json_path"] = str(graph_json_path) if graph_json_path.is_file() else None

    try:
        report_json_path.write_text(
            json.dumps(payload, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        return {"status": "error", "reason": str(exc)}

    return {
        "status": "ok",
        "graph_missing": not graph_exists,
        "report_json_path": str(report_json_path),
    }


def _lane_has_work(lane: dict[str, Any]) -> bool:
    return bool(lane.get("execution_ids") or lane.get("finding_ids"))


def _lane_owned(lane: dict[str, Any]) -> bool:
    return bool(lane.get("assigned_agent") or lane.get("supporting_agents"))


def build_orchestration_warnings(analysis_lanes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Warn when required lanes are complete only by inference."""
    warnings: list[dict[str, Any]] = []
    for lane in analysis_lanes:
        lane_id = str(lane.get("lane_id") or "")
        if not lane.get("required"):
            continue
        if _lane_owned(lane):
            continue
        if str(lane.get("status") or "") in {"PENDING", "IN_PROGRESS", "FAILED"}:
            continue
        if not _lane_has_work(lane):
            continue
        warnings.append(
            {
                "type": "specialist_lane_not_recorded",
                "lane_id": lane_id,
                "expected_agents": list(EXPECTED_LANE_AGENTS.get(lane_id, ())),
                "message": (
                    "Lane has tool executions or findings but no explicit specialist "
                    "lane record. Treat this as inferred coverage until "
                    "record_analysis_lane validates the specialist or main-agent return."
                ),
            }
        )
    return warnings


def _validate_subagent_lane_ids(
    lane: dict[str, Any],
    *,
    persisted_execution_ids: set[str],
    persisted_finding_ids: set[str],
) -> list[dict[str, Any]]:
    """Return fail-closed data gaps for subagent lane IDs absent from state."""
    if not _lane_owned(lane):
        return []

    execution_ids = {
        str(execution_id).strip()
        for execution_id in (lane.get("execution_ids") or [])
        if str(execution_id).strip()
    }
    finding_ids = {
        str(finding_id).strip()
        for finding_id in (lane.get("finding_ids") or [])
        if str(finding_id).strip()
    }
    missing_execution_ids = sorted(execution_ids - persisted_execution_ids)
    missing_finding_ids = sorted(finding_ids - persisted_finding_ids)
    if not missing_execution_ids and not missing_finding_ids:
        return []

    return [
        {
            "artifact_family": lane.get("lane_id") or "analysis_lane",
            "classification": "subagent_return_invalid",
            "reason": (
                "Subagent lane references execution or finding IDs that are "
                "not present in persisted state."
            ),
            "lane_id": lane.get("lane_id"),
            "assigned_agent": lane.get("assigned_agent"),
            "missing_execution_ids": missing_execution_ids,
            "missing_finding_ids": missing_finding_ids,
        }
    ]


def _synthesize_analysis_lanes(
    *,
    findings: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    persisted_lanes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    lanes: dict[str, dict[str, Any]] = {}
    if persisted_lanes:
        for lane in persisted_lanes:
            lane_id = str(lane.get("lane_id") or "").strip()
            if not lane_id:
                continue
            merged = _lane_template(lane_id, legacy_inferred=bool(lane.get("legacy_inferred")))
            merged.update(dict(lane))
            merged.setdefault("supporting_agents", [])
            lanes[lane_id] = merged
    else:
        for lane_id in _LANE_SPECS:
            lanes[lane_id] = _lane_template(lane_id, legacy_inferred=True)

    for execution in executions:
        lane_id = _infer_lane_from_tool_name(execution.get("tool_name"))
        if not lane_id:
            continue
        lane = lanes.setdefault(lane_id, _lane_template(lane_id, legacy_inferred=not persisted_lanes))
        execution_id = str(execution.get("execution_id") or "").strip()
        if execution_id and execution_id not in lane["execution_ids"]:
            lane["execution_ids"].append(execution_id)
        if lane["status"] in {"PENDING", "UNKNOWN"}:
            lane["status"] = "COMPLETE"

    for finding in findings:
        lane_id, confidence = _infer_lane_from_finding(finding)
        if not lane_id:
            continue
        lane = lanes.setdefault(lane_id, _lane_template(lane_id, legacy_inferred=not persisted_lanes))
        finding_id = str(finding.get("finding_id") or "").strip()
        if finding_id and finding_id not in lane["finding_ids"]:
            lane["finding_ids"].append(finding_id)
        if lane.get("lane_inference_confidence") in (None, "low") and confidence:
            lane["lane_inference_confidence"] = confidence
        if lane["status"] in {"PENDING", "UNKNOWN"}:
            lane["status"] = "COMPLETE"

    anti_lane = lanes.get("anti_forensics_recovery")
    sigma_owned_lane = next(
        (
            lane for lane in lanes.values()
            if lane.get("assigned_agent") == "sigma-analyst"
            or "sigma-analyst" in (lane.get("supporting_agents") or [])
        ),
        None,
    )
    if anti_lane and _lane_has_work(anti_lane) and not _lane_owned(anti_lane) and sigma_owned_lane:
        anti_lane["assigned_agent"] = "sigma-analyst"
        anti_lane["supporting_agents"] = sorted(
            set((anti_lane.get("supporting_agents") or []) + ["evtx-analyst"])
        )
        anti_lane["summary"] = anti_lane.get("summary") or (
            "Anti-forensics findings were produced during Sigma/event analysis; "
            "ownership derived from the recorded sigma-analyst lane."
        )

    return [lanes[lane_id] for lane_id in _LANE_SPECS if lane_id in lanes]


def validate_report(
    *,
    state_manager: Any,
    findings: list[dict[str, Any]],
    sigma_result: dict[str, Any],
) -> dict[str, Any]:
    executions = state_manager.get_executions()
    persisted_lanes = state_manager.get_analysis_lanes()
    persisted_execution_ids = {
        str(execution.get("execution_id") or "").strip()
        for execution in executions
        if str(execution.get("execution_id") or "").strip()
    }
    persisted_finding_ids = {
        str(finding.get("finding_id") or "").strip()
        for finding in findings
        if str(finding.get("finding_id") or "").strip()
    }
    analysis_lanes = _synthesize_analysis_lanes(
        findings=findings,
        executions=executions,
        persisted_lanes=persisted_lanes,
    )
    unresolved = sum(
        1
        for f in findings
        if (f.get("contradicted_by") or [])
        and str(f.get("finding_status") or "").upper() != "REJECTED"
    )

    anti_forensics_warnings = _merge_warning_lists(
        list(sigma_result.get("anti_forensics_warnings", [])),
    )
    data_gaps = list(sigma_result.get("data_gaps", []))

    for lane in analysis_lanes:
        lane_id = lane.get("lane_id")
        invalid_subagent_gaps = _validate_subagent_lane_ids(
            lane,
            persisted_execution_ids=persisted_execution_ids,
            persisted_finding_ids=persisted_finding_ids,
        )
        if invalid_subagent_gaps:
            lane["status"] = "FAILED"
            lane["data_gaps"] = _merge_warning_lists(
                lane.get("data_gaps", []),
                invalid_subagent_gaps,
            )
            data_gaps = _merge_warning_lists(data_gaps, invalid_subagent_gaps)
        if lane_id == "anti_forensics_recovery":
            anti_findings = [
                finding for finding in findings
                if str(finding.get("finding_type") or "").lower() == "anti_forensics_recovery"
            ]
            if anti_findings and lane["status"] in {"PENDING", "UNKNOWN", "COMPLETE"}:
                lane["status"] = "COMPLETE_WITH_GAPS"
                if not lane["data_gaps"]:
                    lane["data_gaps"].append(
                        {
                            "artifact_family": "anti_forensics_recovery",
                            "classification": "not_collected",
                            "reason": "Analyst anti-forensics evidence exists without structured classification.",
                            "lane_id": lane_id,
                        }
                    )
            if lane["data_gaps"]:
                data_gaps = _merge_warning_lists(data_gaps, lane["data_gaps"])
        elif lane.get("required"):
            if lane["status"] == "PENDING":
                lane["status"] = "FAILED"
            if lane["status"] == "FAILED":
                lane["data_gaps"].append(
                    {
                        "artifact_family": lane_id,
                        "classification": "not_collected",
                        "reason": "Required lane has no recorded executions or findings.",
                        "lane_id": lane_id,
                    }
                )
                data_gaps = _merge_warning_lists(data_gaps, lane["data_gaps"])

    required_lanes = [lane for lane in analysis_lanes if lane.get("required")]
    all_required_complete = bool(required_lanes) and all(
        str(lane.get("status") or "") == "COMPLETE" for lane in required_lanes
    )
    orchestration_warnings = build_orchestration_warnings(analysis_lanes)
    specialist_lanes_inferred = bool(orchestration_warnings)
    if specialist_lanes_inferred:
        for warning in orchestration_warnings:
            warning_lane_id = warning.get("lane_id")
            if not warning_lane_id:
                continue
            inferred_gap = {
                "artifact_family": warning_lane_id,
                "classification": "lane_not_owned_by_subagent",
                "reason": (
                    "Required lane has executions or findings but no "
                    "specialist or main-agent record. Call record_analysis_lane "
                    "to validate ownership before TRIAGE_COMPLETE is honest."
                ),
                "lane_id": warning_lane_id,
                "expected_agents": warning.get("expected_agents", []),
            }
            data_gaps = _merge_warning_lists(data_gaps, [inferred_gap])
    status_flags = {
        "open_leads": bool(sigma_result.get("actionable_leads", [])),
        "anti_forensics_warning": bool(anti_forensics_warnings),
        "unresolved_discrepancy": unresolved > 0,
        "specialist_lanes_inferred": specialist_lanes_inferred,
    }
    triage_status = (
        "TRIAGE_COMPLETE"
        if (
            all_required_complete
            and not anti_forensics_warnings
            and not unresolved
            and not specialist_lanes_inferred
        )
        else "COMPLETE_WITH_GAPS"
    )
    return {
        "analysis_lanes": analysis_lanes,
        "anti_forensics_warnings": anti_forensics_warnings,
        "data_gaps": data_gaps,
        "orchestration_warnings": orchestration_warnings,
        "status_flags": status_flags,
        "triage_status": triage_status,
    }


def render_report_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    sigma = payload["sigma_scan"]
    coverage = payload["coverage"]
    top_findings = payload["top_findings"]
    open_questions = payload.get("open_questions", [])
    status_breakdown = payload.get("status_breakdown", {})
    evidence_kind_breakdown = payload.get("evidence_kind_breakdown", {})
    triage_status = payload.get("triage_status", summary.get("triage_status", "UNKNOWN"))
    status_flags = payload.get("status_flags", {})
    actionable_leads = payload.get("actionable_leads", [])
    anti_forensics_warnings = payload.get("anti_forensics_warnings", [])
    data_gaps = payload.get("data_gaps", [])
    analysis_lanes = payload.get("analysis_lanes", [])
    orchestration_warnings = payload.get("orchestration_warnings", [])

    confirmed_count = status_breakdown.get("CONFIRMED", 0)
    hypothesis_count = status_breakdown.get("HYPOTHESIS", 0) + status_breakdown.get("ACTIVE", 0)

    # Split top findings into confirmed vs active leads
    confirmed_findings = [
        f for f in top_findings
        if _status_label(f.get("finding_status")) == "CONFIRMED"
    ]
    active_findings = [
        f for f in top_findings
        if _status_label(f.get("finding_status")) in ("HYPOTHESIS", "ACTIVE", "OBSERVATION")
    ]

    no_confirmed_banner = ""
    if confirmed_count == 0:
        no_confirmed_banner = (
            '<div class="card" style="border-color: var(--warn);">'
            '<h2 style="color: var(--warn);">No Structurally Confirmed Findings</h2>'
            "<p>No findings have been independently corroborated by multiple artifact sources. "
            "All findings below are hypotheses or observations that require further validation.</p>"
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAVVYDFIR-MCP Report — {html.escape(payload['case_id'])}</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #111827;
    --card: #1f2937;
    --border: #374151;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --good: #22c55e;
    --warn: #f59e0b;
    --danger: #ef4444;
    --mono: 'JetBrains Mono', 'Cascadia Code', monospace;
    --sans: 'Inter', system-ui, sans-serif;
  }}
  body {{ margin: 0; background: radial-gradient(circle at top, #172554, var(--bg)); color: var(--text); font-family: var(--sans); }}
  main {{ max-width: 1180px; margin: 0 auto; padding: 2rem; }}
  h1, h2 {{ margin: 0 0 0.75rem; }}
  p, li {{ color: var(--text); }}
  .subtitle {{ color: var(--muted); margin-bottom: 1.5rem; font-family: var(--mono); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ background: color-mix(in srgb, var(--card) 88%, black); border: 1px solid var(--border); border-radius: 16px; padding: 1rem 1.1rem; margin-bottom: 1.2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.18); }}
  .metric-label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  .metric-value {{ font-size: 1.8rem; font-weight: 700; margin-top: 0.3rem; }}
  .accent {{ color: var(--accent); }}
  .good {{ color: var(--good); }}
  .warn {{ color: var(--warn); }}
  .danger {{ color: var(--danger); }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 0.45rem; }}
  .tag {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 999px; font-size: 0.78rem; font-family: var(--mono); }}
  .tag.covered {{ background: rgba(34,197,94,0.15); color: #86efac; border: 1px solid rgba(34,197,94,0.25); }}
  .tag.uncovered {{ background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.25); }}
  .tag.muted {{ background: rgba(156,163,175,0.12); color: var(--muted); border: 1px solid rgba(156,163,175,0.18); }}
  pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: rgba(15,23,42,0.85); border: 1px solid var(--border); border-radius: 12px; padding: 1rem; font-family: var(--mono); color: #dbeafe; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th, td {{ text-align: left; padding: 0.7rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.08); vertical-align: top; }}
  th {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  ul {{ margin: 0.3rem 0 0; padding-left: 1.2rem; }}
</style>
</head>
<body>
<main>
  <h1>SAVVYDFIR-MCP Investigation Report</h1>
  <div class="subtitle">{html.escape(payload['case_id'])} · {html.escape(str(payload['report_path']))}</div>

  <section class="grid">
    <div class="card"><div class="metric-label">Case Status</div><div class="metric-value accent">{html.escape(summary.get('status', 'UNKNOWN'))}</div></div>
    <div class="card"><div class="metric-label">Triage Status</div><div class="metric-value warn">{html.escape(str(triage_status))}</div></div>
    <div class="card"><div class="metric-label">Findings</div><div class="metric-value">{summary.get('findings_count', 0)}</div></div>
    <div class="card"><div class="metric-label">Confirmed</div><div class="metric-value good">{summary.get('confirmed_count', 0)}</div></div>
    <div class="card"><div class="metric-label">Unresolved</div><div class="metric-value warn">{summary.get('unresolved_discrepancies', 0)}</div></div>
    <div class="card"><div class="metric-label">Sigma Hits</div><div class="metric-value danger">{sigma.get('total_hits', 0)}</div></div>
    <div class="card"><div class="metric-label">Coverage</div><div class="metric-value">{coverage.get('coverage_percent', 0):.1f}%</div></div>
  </section>

  <section class="card">
    <h2>Executive Summary</h2>
    <p>Case <strong>{html.escape(payload['case_id'])}</strong> contains <strong>{summary.get('findings_count', 0)}</strong> findings, of which <strong>{confirmed_count}</strong> are confirmed and <strong>{hypothesis_count}</strong> are hypotheses/active leads. The current unresolved discrepancy count is <strong>{summary.get('unresolved_discrepancies', 0)}</strong>. Sigma preflight reported <strong>{sigma.get('critical_count', 0)}</strong> CRITICAL and <strong>{sigma.get('high_count', 0)}</strong> HIGH anomalies.</p>
  </section>

  {no_confirmed_banner}

  <section class="card">
    <h2>Sigma Anomaly Summary</h2>
    <pre>{html.escape(str(sigma.get('summary_markdown', 'No anomalies detected.')))}</pre>
  </section>

  <section class="card">
    <h2>Top Actionable Leads</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Detector</th><th>Confidence</th><th>Description</th><th>Recommended Next Pivot</th></tr>
      </thead>
      <tbody>
        {_render_leads(actionable_leads)}
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>Anti-Forensics Warnings</h2>
    <ul>{_render_warning_items(anti_forensics_warnings)}</ul>
  </section>

  <section class="card">
    <h2>Data Gaps</h2>
    <ul>{_render_warning_items(data_gaps)}</ul>
    <div class="metric-label" style="margin-top: 1rem;">Status Flags</div>
    <pre>{html.escape(json.dumps(status_flags, indent=2, default=str))}</pre>
  </section>

  <section class="card">
    <h2>Orchestration Warnings</h2>
    <ul>{_render_json_items(orchestration_warnings)}</ul>
  </section>

  <section class="card">
    <h2>Analysis Lanes</h2>
    <table>
      <thead>
        <tr><th>Lane</th><th>Status</th><th>Required</th><th>Agents</th><th>Executions</th><th>Findings</th><th>Summary</th></tr>
      </thead>
      <tbody>
        {_render_lane_rows(analysis_lanes)}
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>ATT&amp;CK Coverage</h2>
    <p>Coverage is currently <strong>{coverage.get('coverage_percent', 0):.1f}%</strong>.</p>
    <div class="metric-label">Covered Tactics</div>
    <div class="tags">{_render_tactic_tags(coverage.get('covered_tactics', []), class_name='covered')}</div>
    <div class="metric-label" style="margin-top: 1rem;">Uncovered Tactics</div>
    <div class="tags">{_render_tactic_tags(coverage.get('uncovered_tactics', []), class_name='uncovered')}</div>
    <div class="metric-label" style="margin-top: 1rem;">Suggested Next Tools</div>
    <ul>{_render_suggested_tools(coverage.get('suggested_next_tools', {}))}</ul>
  </section>

  <section class="card">
    <h2>Open Questions</h2>
    <ul>
      {''.join(f"<li>{html.escape(str(question))}</li>" for question in open_questions) if open_questions else '<li>No open questions recorded.</li>'}
    </ul>
  </section>

  <section class="card">
    <h2>Top Confirmed Findings</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Status</th><th>Confidence</th><th>Tool</th><th>Description</th></tr>
      </thead>
      <tbody>
        {_render_findings_rows(confirmed_findings) if confirmed_findings else "<tr><td colspan='5'>No confirmed findings — all evidence requires further corroboration.</td></tr>"}
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>Top Active Leads</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Status</th><th>Confidence</th><th>Tool</th><th>Description</th></tr>
      </thead>
      <tbody>
        {_render_findings_rows(active_findings)}
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>Findings Status Breakdown</h2>
    <div class="grid">
      {''.join(f'<div class="card"><div class="metric-label">{html.escape(k)}</div><div class="metric-value">{v}</div></div>' for k, v in sorted(status_breakdown.items()))}
    </div>
  </section>
</main>
</body>
</html>
"""


def generate_report_payload(
    *,
    case_id: str,
    state_manager: Any,
    sigma_scan_fn: Callable[[str], dict[str, Any]],
    coverage_fn: Callable[[str], dict[str, Any]],
    reports_root: str = "./reports",
    allow_partial: bool = False,
    delegate_path: str | None = None,
) -> dict[str, Any]:
    """Build the final report payload, write HTML, and then mark the case complete."""
    report_dir = (Path(reports_root) / case_id).resolve()
    report_path = report_dir / "report.html"
    report_json_path = report_dir / "report.json"
    graph_html_path = report_dir / "graph.html"
    graph_json_path = report_dir / "graph.json"

    delegate_file = Path(
        delegate_path
        or os.environ.get("SAVVYDFIR_DELEGATE_PATH")
        or "/tmp/savvydfir_delegate.json"
    )
    if delegate_file.exists():
        try:
            pending_delegate = json.loads(delegate_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pending_delegate = {"path": str(delegate_file), "error": "unreadable delegate file"}
        if (
            isinstance(pending_delegate, dict)
            and _pending_delegate_blocks_case(
                pending_delegate,
                case_id=case_id,
                delegate_file=delegate_file,
            )
            and not allow_partial
        ):
            return {
                "status": "needs_delegate",
                "tool": "generate_report",
                "case_id": case_id,
                "reason": "A specialist delegate is pending; final report files were not written.",
                "pending_delegate": pending_delegate,
                "next_required_tool": "record_analysis_lane",
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
            }

    graph_missing = not (graph_html_path.exists() or graph_json_path.exists())
    if graph_missing and not allow_partial:
        return {
            "status": "needs_graph",
            "tool": "generate_report",
            "case_id": case_id,
            "reason": "Graph output is required before final report files are written.",
            "next_required_tool": "generate_graph",
            "recommended_call": {
                "tool": "generate_graph",
                "arguments": {"case_id": case_id},
            },
            "report_path": str(report_path),
            "report_json_path": str(report_json_path),
            "graph_path": str(graph_html_path),
            "graph_json_path": str(graph_json_path),
        }

    sigma_result = sigma_scan_fn(case_id)
    if sigma_result.get("status") == "error":
        return {
            "status": "error",
            "tool": "generate_report",
            "error": sigma_result.get("error", "sigma_scan preflight failed"),
            "sigma_scan": sigma_result,
        }

    coverage_result = coverage_fn(case_id)
    if coverage_result.get("status") == "error":
        return {
            "status": "error",
            "tool": "generate_report",
            "error": coverage_result.get("error", "coverage_report failed"),
            "sigma_scan": sigma_result,
            "coverage": coverage_result,
        }

    findings = state_manager.get_findings()
    executions = state_manager.get_executions()
    if not allow_partial:
        coverage_check = evaluate_ir_coverage_gate(
            findings=findings,
            executions=executions,
            sigma_result=sigma_result,
        )
        if not coverage_check["ok"]:
            return {
                "status": "needs_coverage",
                "tool": "generate_report",
                "case_id": case_id,
                "reason": "Required Windows IR artifact coverage is incomplete.",
                "missing_coverage": coverage_check["missing"],
                "next_required_tool": coverage_check["next_required_tool"],
                "report_path": str(report_path),
                "report_json_path": str(report_json_path),
            }

    pre_summary = state_manager.to_summary()
    report_dir.mkdir(parents=True, exist_ok=True)

    status_breakdown = _count_by_key(findings, "finding_status")
    evidence_kind_breakdown = _count_by_key(findings, "evidence_kind")
    finding_kind_breakdown = _count_by_key(findings, "finding_kind")
    finding_quality = _finding_quality_summary(findings)
    report_generated_at = datetime.now(timezone.utc).isoformat()

    actionable_leads = list(sigma_result.get("actionable_leads", []))
    validation = validate_report(
        state_manager=state_manager,
        findings=findings,
        sigma_result=sigma_result,
    )
    anti_forensics_warnings = validation["anti_forensics_warnings"]
    data_gaps = validation["data_gaps"]
    status_flags = validation["status_flags"]
    triage_status = validation["triage_status"]
    analysis_lanes = validation["analysis_lanes"]
    orchestration_warnings = validation["orchestration_warnings"]
    unresolved_discrepancies = [
        dict(finding) for finding in state_manager.get_unresolved_discrepancies()
    ]
    unresolved = len(unresolved_discrepancies)
    if graph_missing:
        graph_gap = {
            "artifact_family": "graph",
            "classification": "graph_missing",
            "reason": "Final report exists without graph.html or graph.json. Call generate_graph(case_id) before treating the case as fully complete.",
            "lane_id": "timeline_correlation",
            "next_required_tool": "generate_graph",
        }
        data_gaps = _merge_warning_lists(data_gaps, [graph_gap])
        status_flags = dict(status_flags)
        status_flags["graph_missing"] = True
        triage_status = "COMPLETE_WITH_GAPS"

    payload = {
        "status": "ok",
        "case_id": case_id,
        "summary": {**pre_summary, "status": "COMPLETE", "triage_status": triage_status},
        "triage_status": triage_status,
        "status_flags": status_flags,
        "actionable_leads": actionable_leads,
        "analysis_lanes": analysis_lanes,
        "orchestration_warnings": orchestration_warnings,
        "anti_forensics_warnings": anti_forensics_warnings,
        "data_gaps": data_gaps,
        "findings_count": pre_summary.get("findings_count", 0),
        "unresolved_count": unresolved,
        "unresolved_discrepancies": unresolved_discrepancies,
        "open_questions": pre_summary.get("open_questions", []),
        "sigma_scan": sigma_result,
        "coverage": coverage_result,
        "artifact_coverage": coverage_result,
        "top_findings": _rank_findings(findings),
        "status_breakdown": status_breakdown,
        "evidence_kind_breakdown": evidence_kind_breakdown,
        "finding_kind_breakdown": finding_kind_breakdown,
        "finding_quality_summary": finding_quality,
        "report_generated_at": report_generated_at,
        "report_path": str(report_path),
        "report_json_path": str(report_json_path),
        "graph_path": str(graph_html_path) if graph_html_path.exists() else None,
        "graph_json_path": str(graph_json_path) if graph_json_path.exists() else None,
        "next_required_tool": "generate_graph" if graph_missing else None,
    }
    payload["top_confirmed_findings"] = [
        dict(finding)
        for finding in payload["top_findings"]
        if _status_label(finding.get("finding_status")) == "CONFIRMED"
    ][:10]
    payload["top_active_leads"] = [
        dict(finding)
        for finding in payload["top_findings"]
        if _status_label(finding.get("finding_status")) in {"HYPOTHESIS", "ACTIVE", "OBSERVATION"}
        and str(finding.get("finding_kind") or "validated").lower() != "raw_detector_hit"
    ][:10]

    state_manager.update_triage_state(
        triage_status=triage_status,
        status_flags=status_flags,
        analysis_lanes=analysis_lanes,
        actionable_leads=actionable_leads,
        artifact_coverage=coverage_result,
        anti_forensics_warnings=anti_forensics_warnings,
        data_gaps=data_gaps,
    )
    state_manager.set_status("COMPLETE")
    summary = state_manager.to_summary()
    payload["summary"] = summary
    payload["triage_status"] = summary.get("triage_status", triage_status)
    payload["status_flags"] = summary.get("status_flags", status_flags)
    payload["analysis_lanes"] = summary.get("analysis_lanes", analysis_lanes)
    payload["orchestration_warnings"] = orchestration_warnings
    payload["findings_count"] = summary.get("findings_count", 0)
    payload["unresolved_count"] = len(payload.get("unresolved_discrepancies", []))
    status_flags_payload = dict(payload.get("status_flags") or {})
    status_flags_payload["unresolved_discrepancy"] = payload["unresolved_count"] > 0
    payload["status_flags"] = status_flags_payload
    payload["open_questions"] = summary.get("open_questions", [])
    report_path.write_text(render_report_html(payload), encoding="utf-8")
    report_json_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return payload
