"""Shared MCP response-contract helpers for representative forensic tools."""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from sift_mcp.tool_catalog import domain_metadata_for_tool, tool_domain_for

DEFAULT_EVIDENCE_EXCERPT_MAX_CHARS = 1600

__all__ = [
    "DEFAULT_EVIDENCE_EXCERPT_MAX_CHARS",
    "build_contract_response",
    "build_follow_up_option",
    "build_handle",
    "build_provenance",
    "compact_unique",
    "fence_evidence_content",
    "sanitize_nested_text",
    "sanitize_payload_fields",
    "state_path_for_manager",
]


def compact_unique(values: Iterable[Any], limit: int = 10) -> list[str]:
    """Return unique, truthy stringified values in first-seen order."""
    seen: set[str] = set()
    compacted: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        compacted.append(text)
        if len(compacted) >= limit:
            break
    return compacted


def fence_evidence_content(
    text: Optional[str],
    max_chars: int = DEFAULT_EVIDENCE_EXCERPT_MAX_CHARS,
) -> Optional[str]:
    """Fence model-facing evidence content so it is treated as data, not instruction.

    The default 1600-character cap is intentional: it keeps excerpts small
    enough to avoid prompt flooding while still preserving enough raw context
    for a reviewer or follow-up pivot. Full raw artifacts stay recoverable via
    persisted CSV/storage handles and provenance paths.
    """
    if not text:
        return None
    cleaned = str(text).replace("\x00", "")
    cleaned = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned).strip()
    if not cleaned:
        return None
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 3].rstrip() + "..."
    return f"<EVIDENCE_CONTENT>{cleaned}</EVIDENCE_CONTENT>"


def sanitize_nested_text(value: Any) -> Any:
    """Recursively fence string content while preserving structural types.

    Tuples are normalized to lists because MCP responses are serialized as JSON
    objects and arrays; keeping tuple identity would not survive transport.
    """
    if isinstance(value, str):
        return fence_evidence_content(value)
    if isinstance(value, list):
        return [sanitize_nested_text(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_nested_text(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_nested_text(item) for key, item in value.items()}
    return value


def sanitize_payload_fields(payload: dict[str, Any], *fields: str) -> dict[str, Any]:
    """Fence the selected payload fields if they contain raw artifact text."""
    sanitized = dict(payload)
    for field in fields:
        if field in sanitized and sanitized[field] is not None:
            sanitized[field] = sanitize_nested_text(sanitized[field])
    return sanitized


def state_path_for_manager(state_manager: Any) -> Optional[str]:
    """Return the resolved state path for a case/state manager when available."""
    if state_manager is None:
        return None
    getter = getattr(state_manager, "get_state_path", None)
    if getter is None:
        return None
    try:
        return str(getter())
    except Exception:
        return None


def build_handle(
    *,
    kind: str,
    path: str,
    query_tool: Optional[str] = None,
    description: Optional[str] = None,
    tool_name: Optional[str] = None,
    domain: Optional[str] = None,
) -> dict[str, Any]:
    """Build a reusable handle for a persisted artifact."""
    resolved_domain = domain or tool_domain_for(tool_name)
    handle = {
        "kind": kind,
        "path": path,
        "query_tool": query_tool,
        "description": description,
        "domain": resolved_domain,
    }
    return {key: value for key, value in handle.items() if value not in (None, "", [], {})}


def build_follow_up_option(
    tool: str,
    *,
    reason: Optional[str] = None,
    parameters: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Describe one safe MCP follow-up pivot."""
    option = {
        "tool": tool,
        "reason": reason,
        "parameters": parameters or None,
    }
    return {key: value for key, value in option.items() if value not in (None, "", [], {})}


def build_provenance(
    *,
    tool_name: str,
    execution_id: Optional[str],
    raw_command: Optional[str] = None,
    state_path: Optional[str] = None,
    csv_path: Optional[str] = None,
    storage_path: Optional[str] = None,
    source_path: Optional[str] = None,
    cache_hit: Optional[bool] = None,
    cache_source_execution_id: Optional[str] = None,
    artifact_paths: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Build common provenance fields for contract-hardened responses."""
    artifact_refs = compact_unique(
        [
            *(artifact_paths or []),
            csv_path,
            storage_path,
            source_path,
        ],
        limit=12,
    )
    provenance = {
        "tool_name": tool_name,
        "execution_id": execution_id,
        "raw_command": raw_command,
        "state_path": state_path,
        "csv_path": csv_path,
        "storage_path": storage_path,
        "source_path": source_path,
        "cache_hit": cache_hit,
        "cache_source_execution_id": cache_source_execution_id,
        "artifact_paths": artifact_refs or None,
    }
    return {key: value for key, value in provenance.items() if value not in (None, "", [], {})}


def build_contract_response(
    payload: dict[str, Any],
    *,
    tool_name: str,
    summary: str,
    normalized_observations: list[dict[str, Any]],
    provenance: dict[str, Any],
    pivot_entities: dict[str, Any],
    follow_up_options: list[dict[str, Any]],
    preview: Optional[list[dict[str, Any]]] = None,
    evidence_excerpt: Optional[str] = None,
    handle: Optional[dict[str, Any]] = None,
    query_constraints: Optional[dict[str, Any]] = None,
    domain_metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Attach the shared MCP response envelope without removing legacy keys."""
    response = dict(payload)
    response["tool"] = tool_name
    response["summary"] = summary
    response["normalized_observations"] = normalized_observations
    response["provenance"] = provenance
    response["pivot_entities"] = {
        key: value
        for key, value in pivot_entities.items()
        if value not in (None, "", [], {})
    }
    response["follow_up_options"] = follow_up_options
    response["preview"] = preview if preview is not None else normalized_observations[:5]
    resolved_domain_metadata = domain_metadata or domain_metadata_for_tool(tool_name)
    if resolved_domain_metadata:
        response["domain_metadata"] = resolved_domain_metadata
    if evidence_excerpt:
        response["evidence_excerpt"] = fence_evidence_content(evidence_excerpt)
    if handle:
        response["handle"] = handle
    if query_constraints:
        response["query_constraints"] = {
            key: value
            for key, value in query_constraints.items()
            if value not in (None, "", [], {})
        }
    return response
