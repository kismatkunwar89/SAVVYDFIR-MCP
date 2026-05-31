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


# W1.7 - Tier-1 heuristic injection map: tool_name (or prefix) → artifact key
# matching the .claude/agents/<artifact>-analyst.md canonical files.
# Used by build_contract_response() to attach `applicable_heuristics` slice
# directly to the extraction tool's response payload (CR13 Option X Tier-1).
_HEURISTIC_ARTIFACT_FOR_TOOL: dict[str, str] = {
    "memory.list_processes": "memory",
    "memory.scan_processes": "memory",
    "memory.detect_injection": "memory",
    "memory.scan_network": "memory",
    "memory.list_dlls": "memory",
    "memory.load_memory": "memory",
    "disk.extract_mft_timeline": "mft",
    "disk.extract_usn_journal": "mft",
    "disk.summarize_evtx": "evtx",
    "disk.extract_prefetch": "prefetch",
    "disk.get_amcache": "amcache",
    "disk.extract_shimcache": "registry",
    "disk.extract_registry_run_keys": "registry",
    "disk.extract_srum": "srum",
    "detection.sigma_hunt": "sigma",
    "detection.hayabusa_hunt": "sigma",
    "detection.sigma_scan": "sigma",
}


def _resolve_heuristic_artifact(tool_name: str) -> Optional[str]:
    """Map a tool name to its canonical .md artifact name, or None if no map."""
    if not tool_name:
        return None
    if tool_name in _HEURISTIC_ARTIFACT_FOR_TOOL:
        return _HEURISTIC_ARTIFACT_FOR_TOOL[tool_name]
    # Try prefix match (tool may be namespaced differently in some callers)
    for key, art in _HEURISTIC_ARTIFACT_FOR_TOOL.items():
        if tool_name.endswith(key.split(".")[-1]):
            return art
    return None


# W1.7 (Run 2 consensus 2026-05-24, +signed): runtime-dep registry.
# server.py wires _state_manager / _audit_logger here via init_all_tools so the
# CONTRACT path (build_contract_response → _attach_heuristic_slice) has live
# singletons without lazy `from sift_mcp.server import ...`. The lazy import
# pattern produced silent audit/state divergence in Run 2 (8 audit rows, 3
# state refs) - Q1 fix.
_runtime_state_manager: Any = None
_runtime_audit_logger: Any = None


def set_runtime_deps(state_manager: Any, audit_logger: Any) -> None:
    """Register the live state_manager + audit_logger for contract-path
    heuristic injection. Called once from init_all_tools at server startup.

    Missing-deps behavior: if this is not called, _attach_heuristic_slice
    skips injection AND surfaces ``applicable_heuristics_skipped_reason``
    on the response (fail-visible ).
    """
    global _runtime_state_manager, _runtime_audit_logger
    _runtime_state_manager = state_manager
    _runtime_audit_logger = audit_logger


def _attach_heuristic_slice(
    response: dict[str, Any],
    *,
    tool_name: str,
    case_id: Optional[str],
    execution_id: Optional[str],
    state_manager: Any = None,
    audit_logger: Any = None,
) -> None:
    """W1.7 Tier-1: attach a heuristic slice to the response payload if the
    tool is one of the artifact extractors AND the artifact has a canonical
    .md file.

    Dep resolution (Run 2 consensus 2026-05-24):
      1. Explicit kwargs (finalize path passes; defense-in-depth in callers)
      2. Module-level registry set via set_runtime_deps (contract path,
         registered from init_all_tools)
      3. Neither available → skip injection AND set
         response["applicable_heuristics_skipped_reason"] (fail-visible)

    NO lazy `from sift_mcp.server import ...` - that pattern caused Run 2's
    CONTRACT-path state-write loss (BUG-4). All state-write errors are
    re-raised (not swallowed); only audit-write errors are best-effort.

    GUARDS:
      (a) skip if `applicable_heuristics` already present (double-injection)
      (b) execution_id required (no E-000 or empty)
      (c) mapped tool only (via _resolve_heuristic_artifact)
      (d) reject case_id="unknown" (the _case_id() fallback when unloaded)
    """
    # Guard (a)
    if isinstance(response.get("applicable_heuristics"), dict):
        return
    # Guard (c)
    artifact = _resolve_heuristic_artifact(tool_name)
    if not artifact:
        return
    # Guard (d)
    if not case_id or case_id == "unknown":
        return
    # Guard (b)
    if not execution_id or execution_id == "E-000":
        return

    # Dep resolution
    resolved_state = state_manager if state_manager is not None else _runtime_state_manager
    resolved_audit = audit_logger if audit_logger is not None else _runtime_audit_logger
    if resolved_state is None or resolved_audit is None:
        response["applicable_heuristics_skipped_reason"] = (
            "missing_runtime_deps — call set_runtime_deps from init_all_tools"
        )
        return

    # Load the slice (failures here are non-fatal - heuristic catalog is data)
    try:
        import sys
        from pathlib import Path as _P
        scripts_dir = str(_P(__file__).resolve().parent.parent.parent / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        import extract_heuristic_slice as _ex  # type: ignore
        slice_data = _ex.extract_tier1_slice(artifact)
    except Exception as exc:
        response["applicable_heuristics_skipped_reason"] = f"slice_load_failed: {exc}"
        return
    if slice_data is None or not slice_data.get("section_found"):
        response["applicable_heuristics_skipped_reason"] = "no_slice_for_artifact"
        return

    excerpt_hash = slice_data.get("excerpt_hash") or ""
    # State READ is allowed to swallow (read-only, can't corrupt)
    try:
        existing = resolved_state.lookup_heuristic_ref(artifact, excerpt_hash)
    except Exception:
        existing = None
    if existing:
        response["applicable_heuristics"] = {
            "artifact": artifact,
            "ctx_id": existing["context_id"],
            "ref_only": True,
            "reason": "already_loaded_in_session",
            "source_path": slice_data.get("source_path"),
        }
        return

    # State WRITE path - surfaces errors (Q1 mandate: no silent swallow
    # of state writes; only audit writes are best-effort).
    ctx_id = resolved_state.next_context_id()
    section_label = " + ".join(slice_data.get("sections_included") or ["unknown"])
    # Audit write - best-effort (audit failure shouldn't lose state ref)
    try:
        resolved_audit.log_context_bundle(
            case_id=case_id,
            artifact=artifact,
            heuristic_source_path=slice_data.get("source_path") or "",
            heuristic_source_hash=slice_data.get("source_hash") or "",
            heuristic_section=section_label,
            heuristic_excerpt_hash=excerpt_hash,
            excerpt_token_count=int(slice_data.get("token_count") or 0),
            triggered_by=tool_name,
            execution_id=execution_id,
            context_id=ctx_id,
        )
    except Exception as exc:
        response.setdefault("audit_write_warning", f"context_bundle: {exc}")
    # State write - surface errors (was swallowed in Run 2; BUG-4 root cause)
    resolved_state.record_heuristic_ref(
        context_id=ctx_id,
        artifact=artifact,
        source_hash=slice_data.get("source_hash") or "",
        excerpt_hash=excerpt_hash,
        section=section_label,
        triggered_by=tool_name,
    )
    response["applicable_heuristics"] = {
        "artifact": artifact,
        "ctx_id": ctx_id,
        "source_path": slice_data["source_path"],
        "source_hash": slice_data["source_hash"],
        "sections": slice_data["sections_included"],
        "content": f"<HEURISTIC ctx_id=\"{ctx_id}\" artifact=\"{artifact}\">\n{slice_data['content']}\n</HEURISTIC>",
        "token_count": slice_data["token_count"],
        "agent_instruction": (
            f"Forensic heuristics for {artifact} are inline above (CTX={ctx_id}). "
            "Apply them when analyzing the csv_path/output_path from this tool. "
            f"Cite this CTX in heuristic_context_refs of any finding you "
            "register from this artifact."
        ),
    }


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
    case_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    state_manager: Any = None,
    audit_logger: Any = None,
) -> dict[str, Any]:
    """Attach the shared MCP response envelope without removing legacy keys.

    W1.7 (CR13 Option X): if `case_id` is supplied and the tool maps to a
    canonical heuristic .md file (per `_HEURISTIC_ARTIFACT_FOR_TOOL`), the
    response will include an `applicable_heuristics` field carrying the
    Tier-1 heuristic slice (~800 tokens) for that artifact. Dedup via
    state.heuristic_refs_loaded - subsequent calls in the same lane return
    refs-only.

    `case_id` and `execution_id` are optional for backward compatibility -
    callers that don't yet thread them through skip heuristic injection
    silently.
    """
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
    # W1.7 Tier-1 heuristic injection (best-effort, never blocks)
    _attach_heuristic_slice(
        response,
        tool_name=tool_name,
        case_id=case_id,
        execution_id=execution_id,
        state_manager=state_manager,
        audit_logger=audit_logger,
    )
    return response
