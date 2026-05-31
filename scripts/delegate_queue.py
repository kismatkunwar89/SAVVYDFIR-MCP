"""Per-lane delegate queue manager.

Replaces single-trigger blocking with per-lane FIFO queues. Specialists can
run in parallel across lanes; within a lane, specialists run serially.

Queue file structure:
{
  "event_auth": [
    {"tool": "summarize_evtx", "subagent_type": "evtx-analyst", ...},
    {"tool": "hayabusa_hunt", "subagent_type": "sigma-analyst", ...}
  ],
  "timeline_correlation": [
    {"tool": "extract_mft_timeline", "subagent_type": "mft-analyst", ...},
    {"tool": "sigma_hunt", "subagent_type": "sigma-analyst", ...}
  ],
  "disk_execution_persistence": [...],
  "memory": [...],
  "anti_forensics_recovery": [...]
}

Each lane's queue is a list of delegate dicts. Head of queue (index 0) is
the currently pending delegate. When processed, it's popped from the queue.
"""
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


DEFAULT_QUEUE_PATH = "/tmp/savvydfir_delegate_queue.json"

# DEFECT-2 / deterministic delegate idempotency.
# A delegate is uniquely identified by the tuple
#   (case_id, lane_id, subagent_type, iteration)
# Anything with the same key is the SAME logical work item, and the
# dispatcher must not re-enqueue it while a prior instance is pending or
# was satisfied successfully. Status transitions:
#   pending  -> processed (set when mark_delegate_processed pops the head)
#   pending  -> stale_dismissed (set when generate_report sees the lane
#                                already satisfied by the same specialist)
#   pending  -> failed (set when the Task outcome was timeout/error/etc.;
#                       retry_count++ allows controlled re-dispatch)
DELEGATE_STATUS_VALUES = frozenset({"pending", "processed", "stale_dismissed", "failed"})
MAX_DELEGATE_RETRIES = 3


def compute_delegate_key(
    case_id: str,
    lane_id: str,
    subagent_type: str,
    iteration: Any = 1,
) -> str:
    """Return the deterministic key for a delegate's idempotency lookup.

    Two delegates with the same (case_id, lane_id, subagent_type, iteration)
    are the SAME logical work item - the dispatcher refuses to re-enqueue
    a pending duplicate (DEFECT-2 fix).
    """
    payload = "|".join([
        str(case_id or "").strip(),
        str(lane_id or "").strip(),
        str(subagent_type or "").strip().lstrip("@"),
        str(iteration or 1),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _migrate_legacy_delegate(delegate: dict[str, Any]) -> dict[str, Any]:
    """Backfill DEFECT-2 fields on a legacy queue entry that pre-dates them.

    Legacy entries had: tool, subagent_type, prompt, lane_id, case_id,
    created_at, processed (bool), agent_call, instruction.
    New entries also carry: delegate_key, status, retry_count, processed_at,
    processed_reason. Reading code must tolerate either shape.
    """
    if not isinstance(delegate, dict):
        return delegate
    if "delegate_key" not in delegate or not delegate.get("delegate_key"):
        delegate["delegate_key"] = compute_delegate_key(
            delegate.get("case_id") or "",
            delegate.get("lane_id") or "",
            delegate.get("subagent_type") or "",
            delegate.get("iteration") or 1,
        )
    if "status" not in delegate:
        # Translate the legacy boolean into the new enum.
        if delegate.get("processed") is True:
            delegate["status"] = "processed"
        else:
            delegate["status"] = "pending"
    if delegate["status"] not in DELEGATE_STATUS_VALUES:
        delegate["status"] = "pending"
    delegate.setdefault("retry_count", 0)
    # C-PRIME: repair attempts are tracked
    # separately from retry_count so a specialist that needed repair
    # doesn't burn its full retry budget on the repair pass.
    delegate.setdefault("repair_count", 0)
    return delegate


def _get_queue_path() -> Path:
    """Return the queue file path from env or default."""
    return Path(os.environ.get("SAVVYDFIR_DELEGATE_QUEUE_PATH", DEFAULT_QUEUE_PATH))


def _read_queue() -> dict[str, list[dict[str, Any]]]:
    """Read the entire per-lane queue structure. Returns empty dict if missing.

    Auto-migrates legacy entries (missing delegate_key / status / retry_count)
    on the fly so old queue files from prior sessions don't crash the new
    idempotency logic.
    """
    path = _get_queue_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        for lane_id, entries in data.items():
            if not isinstance(entries, list):
                continue
            migrated = []
            for entry in entries:
                if isinstance(entry, dict):
                    # Ensure lane_id is set on the entry so the migration sees it.
                    entry.setdefault("lane_id", lane_id)
                    migrated.append(_migrate_legacy_delegate(entry))
            out[lane_id] = migrated
        return out
    except (OSError, IOError, json.JSONDecodeError):
        pass
    return {}


def _write_queue(queue: dict[str, list[dict[str, Any]]]) -> None:
    """Write the entire queue structure atomically.

    Handles the multi-uid trap where root and sansdfir interleave: a stale
    file owned by another uid can block direct writes even at mode 0o666.
    Strategy:
      1. Write to a per-pid+uuid tmp file in the same directory.
      2. os.replace() to overwrite the target atomically.
      3. If os.replace fails (permission/cross-mount), fall back to
         O_TRUNC overwrite with permissive mode so future writers from
         any uid can update it.
    """
    path = _get_queue_path()
    cleaned = {k: v for k, v in queue.items() if v}
    payload = json.dumps(cleaned, indent=2)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(
            f"{path.suffix}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        )
        try:
            tmp.write_text(payload, encoding="utf-8")
            try:
                os.replace(tmp, path)
            except OSError:
                # Atomic replace failed (target owned by another uid).
                # Fall back to in-place overwrite with permissive mode.
                fd = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o666,
                )
                try:
                    os.write(fd, payload.encode("utf-8"))
                finally:
                    os.close(fd)
                try:
                    os.chmod(path, 0o666)
                except OSError:
                    pass
                try:
                    tmp.unlink()
                except OSError:
                    pass
        except (OSError, IOError):
            # Tmp write itself failed - try direct write as last resort.
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o666,
            )
            try:
                os.write(fd, payload.encode("utf-8"))
            finally:
                os.close(fd)
            try:
                os.chmod(path, 0o666)
            except OSError:
                pass
    except (OSError, IOError):
        pass  # Queue file is advisory - failure must not block


def enqueue_delegate(lane_id: str, delegate: dict[str, Any]) -> None:
    """Append a delegate to the specified lane's queue.

    Args:
        lane_id: Lane identifier (e.g., "event_auth", "timeline_correlation")
        delegate: Delegate dict with subagent_type, prompt, tool, etc.
    """
    if not lane_id or not isinstance(delegate, dict):
        return

    queue = _read_queue()
    if lane_id not in queue:
        queue[lane_id] = []

    # Add timestamp (only if caller didn't supply one) and mark unprocessed.
    # We respect a caller-supplied created_at so legacy entries with a real
    # creation time aren't relabeled to "now" on re-enqueue.
    delegate.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    delegate["processed"] = False
    delegate.setdefault("lane_id", lane_id)
    # DEFECT-2 fields - deterministic idempotency anchor
    delegate.setdefault(
        "delegate_key",
        compute_delegate_key(
            delegate.get("case_id") or "",
            lane_id,
            delegate.get("subagent_type") or "",
            delegate.get("iteration") or 1,
        ),
    )
    delegate.setdefault("status", "pending")
    delegate.setdefault("retry_count", 0)

    queue[lane_id].append(delegate)
    _write_queue(queue)


def find_existing_by_key(
    delegate_key: str,
    *,
    statuses: Optional[Iterable[str]] = None,
) -> Optional[dict[str, Any]]:
    """Return the first queue entry matching *delegate_key* (and optional
    status filter), or None.

    Used by the corroboration dispatcher to suppress re-enqueues of the same
    logical work item that is already pending or completed.
    """
    if not delegate_key:
        return None
    queue = _read_queue()
    status_set = {s.lower() for s in statuses} if statuses else None
    for lane_id, entries in queue.items():
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("delegate_key") or "").strip() != delegate_key:
                continue
            entry_status = str(entry.get("status") or "pending").lower()
            if status_set is not None and entry_status not in status_set:
                continue
            # Ensure lane_id is set for the caller
            entry.setdefault("lane_id", lane_id)
            return entry
    return None


def mark_delegate_stale(
    delegate_key: str,
    *,
    reason: str = "lane_satisfied_after_delegate_created",
) -> Optional[dict[str, Any]]:
    """Transition a delegate to status='stale_dismissed' in place.

    Returns the updated entry (with reason + processed_at filled in) or None
    if no match was found. Idempotent - calling twice on the same key is
    safe and returns the already-stale entry on the second call.
    """
    if not delegate_key:
        return None
    queue = _read_queue()
    changed = False
    updated_entry: Optional[dict[str, Any]] = None
    for lane_id, entries in queue.items():
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("delegate_key") or "").strip() != delegate_key:
                continue
            if entry.get("status") != "stale_dismissed":
                entry["status"] = "stale_dismissed"
                entry["processed"] = True
                entry["processed_at"] = datetime.now(timezone.utc).isoformat()
                entry["processed_reason"] = reason
                changed = True
            updated_entry = entry
            updated_entry.setdefault("lane_id", lane_id)
    if changed:
        _write_queue(queue)
    return updated_entry


def mark_delegate_failed(
    delegate_key: str,
    *,
    reason: str = "task_outcome_failure",
) -> Optional[dict[str, Any]]:
    """Transition a delegate to status='failed' and bump retry_count.

    Returns the updated entry, or None if not found. Callers that want to
    retry should check ``retry_count < MAX_DELEGATE_RETRIES``.
    """
    if not delegate_key:
        return None
    queue = _read_queue()
    changed = False
    updated_entry: Optional[dict[str, Any]] = None
    for lane_id, entries in queue.items():
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("delegate_key") or "").strip() != delegate_key:
                continue
            entry["status"] = "failed"
            entry["processed"] = False
            entry["processed_at"] = datetime.now(timezone.utc).isoformat()
            entry["processed_reason"] = reason
            entry["retry_count"] = int(entry.get("retry_count") or 0) + 1
            updated_entry = entry
            updated_entry.setdefault("lane_id", lane_id)
            changed = True
    if changed:
        _write_queue(queue)
    return updated_entry


def all_pending_delegates() -> list[dict[str, Any]]:
    """Flatten the queue into a list of pending entries with lane_id attached.

    Excludes entries whose status is processed/stale_dismissed - used by
    the report gate to surface ONLY work that is genuinely still pending.
    """
    queue = _read_queue()
    out: list[dict[str, Any]] = []
    for lane_id, entries in queue.items():
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            status = str(entry.get("status") or "pending").lower()
            if status in {"processed", "stale_dismissed"}:
                continue
            if entry.get("processed") is True and status not in {"failed"}:
                # Legacy entries already marked processed but missing status.
                continue
            entry.setdefault("lane_id", lane_id)
            out.append(entry)
    return out


def get_pending_delegate(lane_id: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Get the next pending delegate.

    Args:
        lane_id: If specified, return pending delegate for this lane only.
                 If None, return the first pending delegate across all lanes
                 (prioritized by lane order: event_auth, timeline_correlation,
                 disk_execution_persistence, memory, anti_forensics_recovery).

    Returns:
        Delegate dict with lane_id added, or None if no pending delegates.
    """
    queue = _read_queue()

    if lane_id:
        # Get head of specific lane's queue
        lane_queue = queue.get(lane_id, [])
        if lane_queue:
            delegate = lane_queue[0]
            delegate["lane_id"] = lane_id  # Ensure lane_id is present
            return delegate
        return None

    # Return first pending delegate across all lanes (prioritized order)
    lane_priority = [
        "event_auth",
        "timeline_correlation",
        "disk_execution_persistence",
        "memory",
        "anti_forensics_recovery",
    ]

    # Check prioritized lanes first
    for lane in lane_priority:
        if lane in queue and queue[lane]:
            delegate = queue[lane][0]
            delegate["lane_id"] = lane
            return delegate

    # Check any remaining lanes
    for lane, delegates in queue.items():
        if delegates:
            delegate = delegates[0]
            delegate["lane_id"] = lane
            return delegate

    return None


def mark_delegate_processed(lane_id: str) -> None:
    """Pop the head delegate from the specified lane's queue.

    Args:
        lane_id: Lane identifier whose head delegate should be removed.
    """
    if not lane_id:
        return

    queue = _read_queue()
    lane_queue = queue.get(lane_id, [])

    if lane_queue:
        # Remove head of queue
        lane_queue.pop(0)
        queue[lane_id] = lane_queue
        _write_queue(queue)


def is_tool_already_queued(lane_id: str, tool_name: str) -> bool:
    """Check if a tool is already queued in the specified lane.

    Used to prevent duplicate delegates for the same tool in the same lane.

    Args:
        lane_id: Lane identifier to check
        tool_name: Tool name to look for

    Returns:
        True if tool is already in this lane's queue, False otherwise.
    """
    if not lane_id or not tool_name:
        return False

    queue = _read_queue()
    lane_queue = queue.get(lane_id, [])

    # Normalize tool name for comparison
    normalized = tool_name.split("__")[-1].split(".")[-1]

    for delegate in lane_queue:
        delegate_tool = str(delegate.get("tool", ""))
        delegate_normalized = delegate_tool.split("__")[-1].split(".")[-1]
        if delegate_normalized == normalized:
            return True

    return False


def get_queue_status() -> dict[str, Any]:
    """Get current queue status for debugging/monitoring.

    Returns:
        Dict with per-lane counts and total pending.
    """
    queue = _read_queue()
    return {
        "per_lane": {lane: len(delegates) for lane, delegates in queue.items()},
        "total_pending": sum(len(delegates) for delegates in queue.values()),
        "lanes_with_work": list(queue.keys()),
    }
