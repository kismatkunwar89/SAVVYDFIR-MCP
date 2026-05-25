"""Append-only delegation ledger — observation phase (3a).

Hook-owned source of truth for Path A vs Path B authorization (per
peer reviewer consensus 2026-05-19 ITEM-2/ITEM-3). NO enforcement at this phase;
this module only WRITES rows and provides READ helpers. Enforcement
(workflow-enforce-pre.py reading the ledger to deny/allow) lands in
Phase 3b/3c.

Schema (one JSON object per line):
{
  "timestamp": "<UTC ISO8601>",
  "session_id": "<from SessionStart hook stdin>",
  "event": "delegation_required" | "task_attempt" | "task_outcome"
         | "task_unavailable_session" | "path_b_would_deny"
         | "path_b_would_allow" | "path_b_denied",
  "lane_id":  "<savvydfir lane, e.g. memory, disk_execution_persistence>",
  "specialist": "<subagent type, e.g. memory-analyst>",
  "tool": "<MCP tool that triggered delegation, when applicable>",
  "attempt_id": "<UUID linking task_attempt -> task_outcome>",
  "outcome": "success" | "timeout" | "error" | "prose_only" | "malformed_json",
  "excerpt": "<first 200 chars of Task return, redacted of secrets>",
  "decision_basis": "<for dry-run / enforcement rows>",
}

Path: /tmp/savvydfir_delegation_ledger.jsonl
Session pointer: /tmp/savvydfir_current_session.json (written by SessionStart)

Cross-session contamination is prevented by mandatory session_id matching
on all reads — rows whose session_id != the current session do not
authorize anything.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

LEDGER_PATH = Path(
    os.environ.get(
        "SAVVYDFIR_DELEGATION_LEDGER",
        "/tmp/savvydfir_delegation_ledger.jsonl",
    )
)
SESSION_POINTER_PATH = Path(
    os.environ.get(
        "SAVVYDFIR_SESSION_POINTER",
        "/tmp/savvydfir_current_session.json",
    )
)

# Outcomes that authorize Path B fallback for the same lane in the same session.
FAILED_OUTCOMES = frozenset({"timeout", "error", "prose_only", "malformed_json"})
SUCCESS_OUTCOMES = frozenset({"success"})

VALID_EVENTS = frozenset({
    "delegation_required",
    "task_attempt",
    "task_outcome",
    "task_unavailable_session",
    "path_b_would_deny",
    "path_b_would_allow",
    "path_b_denied",
    # DEFECT-2 corroboration-dispatch idempotency
    "skip_redispatch_pending_delegate",
    "skip_redispatch_lane_already_corroborated",
    "skip_redispatch_prereqs_incomplete",
    # DEFECT-3 stale-delegate distinctions (peer reviewer consensus 2026-05-20)
    "stale_delegate_dismissed",
    "delegate_satisfied_by_lane_record",
    "delegate_satisfied_by_path_b_allowance",
    # C-PRIME (peer reviewer consensus 2026-05-20 final round) — repair guard
    "repair_required",       # prose_only / malformed_json detected; parent should spawn json-repair
    "repair_attempted",      # parent has spawned the json-repair Task (idempotency anchor)
    "repair_succeeded",      # json-repair returned valid contract JSON
    "repair_failed",         # json-repair itself returned prose / no usable findings
})


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def write_session_pointer(session_id: str, **extra: Any) -> None:
    """SessionStart hook calls this to record the current session_id.

    Uses a per-process tmp filename to avoid the multi-user trap where a
    stale tmp file from another uid (e.g. root vs sansdfir) blocks writes.
    """
    payload = {
        "session_id": session_id,
        "started_at": _utcnow_iso(),
        **extra,
    }
    try:
        SESSION_POINTER_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Per-process + per-uuid tmp name avoids cross-user .tmp collisions.
        tmp = SESSION_POINTER_PATH.with_suffix(
            f"{SESSION_POINTER_PATH.suffix}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        )
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        try:
            os.replace(tmp, SESSION_POINTER_PATH)
        except OSError:
            # Atomic replace failed (e.g. target owned by another uid).
            # Fall back to overwrite-in-place with permissive mode so future
            # writers from any uid can update it.
            try:
                fd = os.open(
                    SESSION_POINTER_PATH,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o666,
                )
                try:
                    os.write(fd, json.dumps(payload).encode("utf-8"))
                finally:
                    os.close(fd)
                try:
                    os.chmod(SESSION_POINTER_PATH, 0o666)
                except OSError:
                    pass
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
    except OSError:
        # Fail-open: ledger absence must never break hooks.
        return


def read_current_session_id() -> Optional[str]:
    """Read the current session_id written by the SessionStart hook."""
    try:
        if not SESSION_POINTER_PATH.exists():
            return None
        data = json.loads(SESSION_POINTER_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    sid = data.get("session_id")
    if isinstance(sid, str) and sid:
        return sid
    return None


def append_row(
    event: str,
    *,
    session_id: Optional[str] = None,
    lane_id: Optional[str] = None,
    specialist: Optional[str] = None,
    tool: Optional[str] = None,
    attempt_id: Optional[str] = None,
    outcome: Optional[str] = None,
    excerpt: Optional[str] = None,
    decision_basis: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Atomically append a single ledger row.

    Returns the written row dict on success, or None on failure (fail-open).
    """
    if event not in VALID_EVENTS:
        return None
    if not session_id:
        session_id = read_current_session_id()
    if not session_id:
        # Without a session_id the row cannot authorize anything; skip.
        return None
    row: dict[str, Any] = {
        "timestamp": _utcnow_iso(),
        "session_id": session_id,
        "event": event,
    }
    for key, value in (
        ("lane_id", lane_id),
        ("specialist", specialist),
        ("tool", tool),
        ("attempt_id", attempt_id),
        ("outcome", outcome),
        ("excerpt", excerpt),
        ("decision_basis", decision_basis),
    ):
        if value is not None and value != "":
            row[key] = value
    if extra:
        for key, value in extra.items():
            if key not in row and value is not None:
                row[key] = value
    try:
        LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        # O_APPEND guarantees atomicity for writes <= PIPE_BUF on POSIX,
        # which our single-line JSON well satisfies.
        # Mode 0o666 lets any uid append (sansdfir vs root run interleaving
        # in dev environments). umask still restricts.
        fd = os.open(
            LEDGER_PATH,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o666,
        )
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            # Ensure the file is writable by any uid even after creation
            # (umask may have stripped group/other write).
            os.chmod(LEDGER_PATH, 0o666)
        except OSError:
            pass
        return row
    except OSError:
        return None


def new_attempt_id() -> str:
    return str(uuid.uuid4())


def read_session_rows(
    session_id: Optional[str] = None,
    *,
    lane_id: Optional[str] = None,
    event: Optional[str] = None,
    events: Optional[Iterable[str]] = None,
) -> list[dict[str, Any]]:
    """Read rows for the current session (or a specific one).

    Cross-session rows are filtered out — only rows whose ``session_id``
    matches the resolved session are returned. This is the invariant that
    prevents yesterday's timeout from authorizing today's Path B.
    """
    sid = session_id or read_current_session_id()
    if not sid:
        return []
    if not LEDGER_PATH.exists():
        return []
    target_events = set(events) if events else None
    if event:
        target_events = (target_events or set()) | {event}
    rows: list[dict[str, Any]] = []
    try:
        with LEDGER_PATH.open(encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if obj.get("session_id") != sid:
                    continue
                if target_events and obj.get("event") not in target_events:
                    continue
                if lane_id is not None and obj.get("lane_id") != lane_id:
                    continue
                rows.append(obj)
    except OSError:
        return []
    return rows


def has_failed_task_outcome(lane_id: str, session_id: Optional[str] = None) -> bool:
    """True if the current session has a task_outcome row for *lane_id*
    with outcome in FAILED_OUTCOMES.

    This is the read primitive workflow-enforce-pre.py uses to decide
    whether Path B is authorized for a specialist lane (Phase 3b/3c).
    Phase 3a does not call this — it only writes rows.
    """
    rows = read_session_rows(
        session_id=session_id,
        lane_id=lane_id,
        event="task_outcome",
    )
    return any(r.get("outcome") in FAILED_OUTCOMES for r in rows)


def has_unavailable_marker(session_id: Optional[str] = None) -> bool:
    """True if the current session has a task_unavailable_session marker."""
    return bool(
        read_session_rows(session_id=session_id, event="task_unavailable_session")
    )


def has_successful_task_outcome(lane_id: str, session_id: Optional[str] = None) -> bool:
    """True if the current session has a task_outcome row for *lane_id*
    with outcome == 'success'."""
    rows = read_session_rows(
        session_id=session_id,
        lane_id=lane_id,
        event="task_outcome",
    )
    return any(r.get("outcome") in SUCCESS_OUTCOMES for r in rows)


def lookup_attempt(attempt_id: str, session_id: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Return the most-recent row for *attempt_id* in the current session."""
    if not attempt_id:
        return None
    rows = read_session_rows(session_id=session_id)
    matches = [r for r in rows if r.get("attempt_id") == attempt_id]
    return matches[-1] if matches else None


__all__ = [
    "LEDGER_PATH",
    "SESSION_POINTER_PATH",
    "FAILED_OUTCOMES",
    "SUCCESS_OUTCOMES",
    "VALID_EVENTS",
    "append_row",
    "new_attempt_id",
    "read_current_session_id",
    "read_session_rows",
    "write_session_pointer",
    "has_failed_task_outcome",
    "has_unavailable_marker",
    "has_successful_task_outcome",
    "lookup_attempt",
]
