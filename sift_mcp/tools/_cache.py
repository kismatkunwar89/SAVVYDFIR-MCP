"""Shared cache helpers for idempotent tool responses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Optional

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager


def build_cache_key(tool_name: str, params: dict[str, Any]) -> str:
    """Return a deterministic cache key for a tool + normalized parameters."""
    payload = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{tool_name}:{digest}"


def get_valid_cached_artifact(
    state_manager: CaseStateManager,
    cache_key: str,
    *,
    path_key: str,
    required_keys: Optional[Iterable[str]] = None,
) -> Optional[dict[str, Any]]:
    """Return cached metadata only when the backing artifact still exists."""
    cached = state_manager.get_artifact_cache(cache_key)
    if not isinstance(cached, dict):
        return None

    for key in required_keys or ():
        if key not in cached or cached[key] is None or cached[key] == "":
            return None

    artifact_path = cached.get(path_key)
    if not isinstance(artifact_path, str) or not artifact_path:
        return None

    path = Path(artifact_path)
    if not path.exists() or not path.is_file() or path.stat().st_size == 0:
        return None

    return cached


def probe_durable_output_csv(
    output_base: str,
    case_id: str,
    subtype: str,
    *,
    filename: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Legacy disk-output reuse probe (idempotency, review 2026-06-04).

    The artifact cache lives in state.json. When state is cleared for a fresh
    investigation but the durable artifacts under ``/cases/<id>/artifacts/`` are
    kept, the cache index is gone and extractors RE-PARSE despite the output CSV
    already existing. This probe is the review-approved LEGACY fallback: when
    the normal state-cache misses, look for the durable output CSV on disk and,
    if present + non-empty, return reuse metadata so the extractor can skip the
    parse.

    It is explicitly weaker than the fingerprinted state cache (no parser-version
    / source-fingerprint check), so the result is tagged
    ``reuse_confidence="legacy_unverified"`` and the caller MUST surface a
    warning + honor ``force_reparse``. Returns None when no durable CSV exists.
    """
    if not output_base or not case_id or not subtype:
        return None
    out_dir = Path(output_base) / case_id / "artifacts" / subtype
    if not out_dir.is_dir():
        return None
    candidates: list[Path] = []
    if filename:
        p = out_dir / filename
        if p.is_file():
            candidates.append(p)
    if not candidates:
        candidates = sorted(
            (p for p in out_dir.glob("*.csv") if p.is_file() and p.stat().st_size > 0),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    for p in candidates:
        try:
            if p.is_file() and p.stat().st_size > 0:
                return {
                    "csv_path": str(p),
                    "reused_output": True,
                    "reuse_confidence": "legacy_unverified",
                    "reuse_note": (
                        "Durable output CSV reused from disk (state cache absent). "
                        "Not fingerprint-verified against source image/parser "
                        "version - pass force_reparse=True to regenerate."
                    ),
                }
        except OSError:
            continue
    return None


def record_cache_hit(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
    *,
    tool_name: str,
    parameters: dict[str, Any],
    cache_key: str,
    artifact_path: str,
    cache_source_execution_id: Optional[str],
    agent_turn: int = 0,
) -> dict[str, Any]:
    """Write a normal audit/state execution record for a cache hit."""
    execution_id = audit_logger.next_execution_id()
    command_line = f"CACHE_HIT {tool_name}"
    audit_parameters = dict(parameters)
    audit_parameters["_cache_key"] = cache_key

    audit_logger.log_execution(
        execution_id=execution_id,
        tool_name=tool_name,
        parameters=audit_parameters,
        command_line=command_line,
        agent_turn=agent_turn,
    )

    outputs_summary = (
        f"Cache hit: reused artifact {artifact_path}"
        + (
            f" from execution {cache_source_execution_id}"
            if cache_source_execution_id
            else ""
        )
    )

    audit_logger.log_result(
        execution_id=execution_id,
        exit_code=0,
        duration=0.0,
        outputs_summary=outputs_summary,
        finding_ids=[],
        correction_event=None,
        tool_name=tool_name,
        command_line=command_line,
        parameters=audit_parameters,
        agent_turn=agent_turn,
    )

    state_manager.add_execution(
        {
            "execution_id": execution_id,
            "tool_name": tool_name,
            "command_line": command_line,
            "parameters": audit_parameters,
            "agent_turn": agent_turn,
            "duration_seconds": 0.0,
            "exit_code": 0,
            "outputs_summary": outputs_summary,
            "cache_hit": True,
            "cache_source_execution_id": cache_source_execution_id,
        }
    )

    return {
        "execution_id": execution_id,
        "raw_command": command_line,
    }
