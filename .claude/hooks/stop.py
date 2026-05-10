#!/usr/bin/env python3
"""Stop hook: block session end when SAVVYDFIR investigations are incomplete."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

DEFAULT_DELEGATE_PATH = "/tmp/savvydfir_delegate.json"
FINAL_LANE_STATUSES = {"COMPLETE", "COMPLETE_WITH_GAPS"}


def _analysis_dir() -> Path:
    return Path(os.environ.get("SAVVYDFIR_ANALYSIS_DIR", "./analysis")).resolve()


def _state_path() -> Path:
    return _analysis_dir() / "state.json"


def _reports_root() -> Path:
    configured = os.environ.get("SAVVYDFIR_REPORTS_DIR")
    if configured:
        return Path(configured).resolve()
    analysis_dir = _analysis_dir()
    if analysis_dir.name == "analysis":
        return (analysis_dir.parent / "reports").resolve()
    return (Path.cwd() / "reports").resolve()


def _delegate_path() -> Path:
    return Path(os.environ.get("SAVVYDFIR_DELEGATE_PATH", DEFAULT_DELEGATE_PATH)).resolve()


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _is_active_investigation(state: dict[str, Any]) -> bool:
    if str(state.get("case_id") or "").strip():
        return True
    for key in ("status", "triage_status"):
        if str(state.get(key) or "").strip():
            return True
    for key in ("findings", "executions", "analysis_lanes"):
        value = state.get(key)
        if isinstance(value, list) and value:
            return True
    return False


def _incomplete_required_lanes(state: dict[str, Any]) -> list[str]:
    lanes = state.get("analysis_lanes")
    if not isinstance(lanes, list):
        return []
    pending: list[str] = []
    for lane in lanes:
        if not isinstance(lane, dict) or not lane.get("required"):
            continue
        status = str(lane.get("status") or "PENDING").upper()
        if status not in FINAL_LANE_STATUSES:
            lane_id = str(lane.get("lane_id") or "").strip()
            if lane_id:
                pending.append(lane_id)
    return pending


def _pending_delegate_lane() -> str | None:
    payload = _load_json(_delegate_path())
    if not payload or payload.get("processed") is True:
        return None
    lane_id = str(payload.get("lane_id") or "").strip()
    return lane_id or None


def _missing_final_artifacts(case_id: str) -> list[str]:
    report_dir = _reports_root() / case_id
    expected = {
        "report.json": report_dir / "report.json",
        "report.html": report_dir / "report.html",
        "graph.json": report_dir / "graph.json",
        "graph.html": report_dir / "graph.html",
    }
    return [name for name, path in expected.items() if not path.is_file()]


def _block(reason: str) -> None:
    print(json.dumps({"decision": "block", "reason": reason}))


def _approve() -> None:
    print(json.dumps({"decision": "approve"}))


def main() -> None:
    try:
        json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return

    state_path = _state_path()
    if not state_path.is_file():
        _approve()
        return

    state = _load_json(state_path)
    if not state:
        _block(
            "Investigation state is unreadable. Fix analysis/state.json before ending the session."
        )
        return
    if not _is_active_investigation(state):
        _approve()
        return

    pending_delegate_lane = _pending_delegate_lane()
    if pending_delegate_lane:
        _block(
            "Investigation incomplete: pending delegate for lane "
            f"{pending_delegate_lane}. Call get_investigation_gates(case_id=...), "
            "finish the pending lane with evidence or COMPLETE_WITH_GAPS, then continue."
        )
        return

    incomplete_lanes = _incomplete_required_lanes(state)
    if incomplete_lanes:
        lanes_text = ", ".join(sorted(incomplete_lanes))
        _block(
            "Investigation incomplete: required lanes still open: "
            f"{lanes_text}. Call get_investigation_gates(case_id=...), finish those "
            "lanes with evidence or COMPLETE_WITH_GAPS, then continue."
        )
        return

    case_id = str(state.get("case_id") or "").strip()
    if not case_id:
        _block(
            "Investigation state is active but missing case_id. Fix state before ending the session."
        )
        return

    missing_artifacts = _missing_final_artifacts(case_id)
    if missing_artifacts:
        artifacts_text = ", ".join(missing_artifacts)
        _block(
            "Investigation incomplete: final artifacts missing: "
            f"{artifacts_text}. Call generate_graph(case_id=...) and "
            "generate_report(case_id=...) before ending the session."
        )
        return

    if str(state.get("status") or "").upper() != "COMPLETE":
        _block(
            "Investigation incomplete: state status is not COMPLETE. "
            "Call generate_report(case_id=...) after the required lanes and graph are ready."
        )
        return

    _approve()


if __name__ == "__main__":
    main()
