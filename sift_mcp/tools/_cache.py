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
