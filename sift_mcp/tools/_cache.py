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


def _entry_hash(entry: Any) -> Optional[str]:
    """Best-effort extract entry_hash from an AuditEntry (dict-like) or None."""
    try:
        if hasattr(entry, "get"):
            return entry.get("entry_hash")
    except Exception:
        pass
    return None


# --- F-A durable-reuse: versioned sidecar fingerprint (review 2026-06-04) ---
# Reuse a prior dotnet-parsed CSV after state.json (and its artifact-cache index)
# is cleared, IF the source evidence is unchanged. Read-only forensic evidence
# makes size+mtime a defensible fingerprint; an EVTX *directory* uses a per-file
# manifest hash (dir mtime alone is insufficient). SHA-256 of content is optional
# (env), not default on multi-GB blobs.
_SIDECAR_SCHEMA = 1
_SIDECAR_SUFFIX = ".savvyreuse.json"


def _sidecar_path(csv_path: str) -> Path:
    return Path(str(csv_path) + _SIDECAR_SUFFIX)


def source_fingerprint(source_path: str) -> Optional[dict[str, Any]]:
    """Cheap, deterministic fingerprint of a raw evidence source (file or dir).

    File: resolved path + size + mtime_ns. Directory (e.g. EVTX corpus): a
    manifest hash over each file's (relpath, size, mtime_ns) — catches changed,
    added or removed files without hashing GBs of content.
    """
    p = Path(source_path)
    try:
        if p.is_dir():
            entries = []
            total = 0
            for f in sorted(p.rglob("*")):
                if f.is_file():
                    st = f.stat()
                    entries.append(f"{f.relative_to(p)}|{st.st_size}|{st.st_mtime_ns}")
                    total += st.st_size
            manifest = hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()
            return {"kind": "dir", "path": str(p.resolve()),
                    "file_count": len(entries), "total_bytes": total,
                    "manifest_sha256": manifest}
        if p.is_file():
            st = p.stat()
            return {"kind": "file", "path": str(p.resolve()),
                    "size": st.st_size, "mtime_ns": st.st_mtime_ns}
    except OSError:
        return None
    return None


def fingerprints_match(a: Optional[dict[str, Any]], b: Optional[dict[str, Any]]) -> bool:
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if a.get("kind") != b.get("kind"):
        return False
    if a.get("kind") == "file":
        return a.get("size") == b.get("size") and a.get("mtime_ns") == b.get("mtime_ns")
    if a.get("kind") == "dir":
        return (a.get("file_count") == b.get("file_count")
                and a.get("manifest_sha256") == b.get("manifest_sha256"))
    return False


def write_reuse_sidecar(csv_path: str, *, tool_name: str, source_path: str,
                        parser_version: Optional[str] = None) -> None:
    """Persist the source fingerprint next to a freshly-parsed CSV so a later run
    (after state clear) can verify-and-reuse it. Best-effort; never raises."""
    try:
        fp = source_fingerprint(source_path)
        if not fp:
            return
        sidecar = {
            "schema": _SIDECAR_SCHEMA,
            "tool": tool_name,
            "parser_version": parser_version,
            "fingerprint_algo": "size_mtime_manifest",
            "source_fingerprint": fp,
            "csv_path": str(csv_path),
        }
        _sidecar_path(csv_path).write_text(json.dumps(sidecar), encoding="utf-8")
    except OSError:
        pass


def _read_reuse_sidecar(csv_path: str) -> Optional[dict[str, Any]]:
    try:
        raw = _sidecar_path(csv_path).read_text(encoding="utf-8")
        d = json.loads(raw)
        return d if isinstance(d, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def try_durable_reuse(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
    *,
    tool_name: str,
    parameters: dict[str, Any],
    output_base: str,
    case_id: str,
    subtype: str,
    canonical_filename: str,
    source_path: Optional[str],
    force_reparse: bool = False,
) -> Optional[dict[str, Any]]:
    """Probe the durable output CSV; if present (and source unchanged when a
    sidecar exists), record a cache-hit and return reuse metadata so the caller
    can SKIP the dotnet parse. Returns None -> caller must parse normally.

    Reuse confidence:
      - ``fingerprint_verified``: sidecar present AND source fingerprint matches.
      - ``legacy_unverified``:   CSV exists but no sidecar (pre-dates this change)
        -> reused with a warning; pass force_reparse=True to regenerate.
    Source changed (sidecar present, fingerprint mismatch) -> returns None (reparse).
    """
    if force_reparse:
        try:
            probe = probe_durable_output_csv(output_base, case_id, subtype, filename=canonical_filename)
            if probe:
                _sidecar_path(probe["csv_path"]).unlink(missing_ok=True)  # invalidate
        except (OSError, TypeError):
            pass
        return None

    probe = probe_durable_output_csv(output_base, case_id, subtype, filename=canonical_filename)
    if not probe:
        return None
    csv_path = probe["csv_path"]

    confidence = "legacy_unverified"
    sidecar = _read_reuse_sidecar(csv_path)
    if sidecar and source_path:
        current = source_fingerprint(source_path)
        if fingerprints_match(sidecar.get("source_fingerprint"), current):
            confidence = "fingerprint_verified"
        else:
            return None  # source evidence changed -> must reparse

    meta = record_cache_hit(
        audit_logger, state_manager,
        tool_name=tool_name, parameters=parameters,
        cache_key=build_cache_key(tool_name, parameters),
        artifact_path=csv_path, cache_source_execution_id=None,
    )
    return {
        "csv_path": csv_path,
        "reused_output": True,
        "reuse_confidence": confidence,
        "reuse_note": (
            "Durable output CSV reused (source fingerprint verified)."
            if confidence == "fingerprint_verified" else
            "Durable output CSV reused WITHOUT fingerprint verification (no sidecar; "
            "pre-dates reuse-tracking). Pass force_reparse=True to regenerate."
        ),
        "execution_id": meta["execution_id"],
        "raw_command": meta["raw_command"],
    }


# ===========================================================================
# Durable-reuse v2: source-set + parameter + parser-signature fingerprint.
#
# v1 (above) keys on a SINGLE source path (size+mtime) and IGNORES tool
# parameters - so an EVTX reuse can return a CSV parsed under a different
# channel filter (the parameter-staleness bug). v2 fixes this with:
#   - a multi-file/dir SOURCE-SET manifest fingerprint (path+size+mtime ->
#     manifest_sha256), so file-access tools that read N hives/dirs/DBs
#     invalidate when ANY material input changes;
#   - a PARAMETER fingerprint (canonical-JSON sha256) so a channel/EID/date
#     change invalidates reuse;
#   - a PARSER_SIGNATURE so a parser-version bump invalidates reuse.
# Correctness > reuse: ANY mismatch (source-set OR params OR parser_signature),
# or a missing/invalid v2 sidecar (incl. a v1 sidecar) -> NO reuse, re-parse.
# ===========================================================================
_SIDECAR_SCHEMA_V2 = 2


def build_source_set_fingerprint(paths: Iterable[str]) -> dict[str, Any]:
    """Build a deterministic manifest fingerprint over a set of material inputs.

    Each path may be a file OR a directory. For a directory, every contained
    file (recursive) contributes (relpath, size, mtime_ns); for a file, its
    own (path, size, mtime_ns). The manifest is sorted+hashed so adding,
    removing, resizing, or re-timestamping ANY input changes manifest_sha256.
    Missing paths contribute a ``missing`` entry (so a vanished input also
    invalidates). Returns ``{entries:[...], manifest_sha256, source_count}``.
    """
    entries: list[dict[str, Any]] = []
    lines: list[str] = []
    for raw in sorted({str(p) for p in paths if p}):
        p = Path(raw)
        try:
            if p.is_dir():
                files: list[str] = []
                total = 0
                fcount = 0
                for f in sorted(p.rglob("*")):
                    if f.is_file():
                        st = f.stat()
                        files.append(f"{f.relative_to(p)}|{st.st_size}|{st.st_mtime_ns}")
                        total += st.st_size
                        fcount += 1
                dir_manifest = hashlib.sha256("\n".join(files).encode("utf-8")).hexdigest()
                entries.append({"path": str(p.resolve()), "kind": "dir",
                                "file_count": fcount, "total_bytes": total,
                                "manifest_sha256": dir_manifest})
                lines.append(f"dir|{p.resolve()}|{fcount}|{total}|{dir_manifest}")
            elif p.is_file():
                st = p.stat()
                entries.append({"path": str(p.resolve()), "kind": "file",
                                "size": st.st_size, "mtime_ns": st.st_mtime_ns})
                lines.append(f"file|{p.resolve()}|{st.st_size}|{st.st_mtime_ns}")
            else:
                entries.append({"path": raw, "kind": "missing"})
                lines.append(f"missing|{raw}")
        except OSError:
            entries.append({"path": raw, "kind": "error"})
            lines.append(f"error|{raw}")
    manifest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    return {"entries": entries, "manifest_sha256": manifest, "source_count": len(entries)}


def build_parameter_fingerprint(params: dict[str, Any]) -> str:
    """Canonical-JSON sha256 of the tool parameters that affect the output.

    Sort keys, normalize separators, ``default=str`` for non-JSON types. A
    channel-filter / EID / date-range change therefore changes the digest and
    invalidates reuse (fixes the v1 EVTX parameter-staleness bug).
    """
    payload = json.dumps(params or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_reuse_sidecar_v2(
    csv_path: str,
    *,
    tool_name: str,
    parser_signature: str,
    source_paths: Iterable[str],
    parameters: dict[str, Any],
) -> None:
    """Persist a v2 sidecar next to a freshly-parsed CSV. Best-effort; never raises.

    Caller MUST only invoke this on a SUCCESSFUL parse with a durable CSV (never
    on partial_collection / collection_failed / tool_incompatible / zero rows) -
    no-poisoned-cache invariant.
    """
    try:
        sidecar = {
            "schema": _SIDECAR_SCHEMA_V2,
            "tool": tool_name,
            "parser_signature": parser_signature,
            "parameter_fingerprint": build_parameter_fingerprint(parameters),
            "source_set_fingerprint": build_source_set_fingerprint(source_paths),
            "csv_path": str(csv_path),
        }
        _sidecar_path(csv_path).write_text(json.dumps(sidecar), encoding="utf-8")
    except OSError:
        pass


def try_durable_reuse_v2(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
    *,
    tool_name: str,
    parser_signature: str,
    source_paths: Iterable[str],
    parameters: dict[str, Any],
    output_base: str,
    case_id: str,
    subtype: str,
    canonical_filename: str,
    force_reparse: bool = False,
) -> Optional[dict[str, Any]]:
    """Probe the durable output CSV; reuse ONLY when a valid v2 sidecar exists
    AND ALL of {source-set, parameters, parser_signature} match. Else return
    None so the caller re-parses (correctness > reuse). v1 sidecars are ignored.

    On a verified match: record_cache_hit -> auditable success execution under
    the CANONICAL tool name -> returns reuse metadata (csv_path, execution_id,
    raw_command). The caller MUST recreate its extraction observation finding
    with the FRESH execution_id (findings-on-reuse, NOT a silent skip).
    """
    source_paths = list(source_paths or [])
    if force_reparse:
        try:
            probe = probe_durable_output_csv(output_base, case_id, subtype, filename=canonical_filename)
            if probe:
                _sidecar_path(probe["csv_path"]).unlink(missing_ok=True)
        except (OSError, TypeError):
            pass
        return None

    probe = probe_durable_output_csv(output_base, case_id, subtype, filename=canonical_filename)
    if not probe:
        return None
    csv_path = probe["csv_path"]

    sidecar = _read_reuse_sidecar(csv_path)
    # Strict: require a v2 sidecar. No sidecar, or a v1 sidecar -> no reuse.
    if not isinstance(sidecar, dict) or sidecar.get("schema") != _SIDECAR_SCHEMA_V2:
        return None
    if sidecar.get("parser_signature") != parser_signature:
        return None
    if sidecar.get("parameter_fingerprint") != build_parameter_fingerprint(parameters):
        return None
    current_sources = build_source_set_fingerprint(source_paths)
    prior_sources = sidecar.get("source_set_fingerprint")
    if (not isinstance(prior_sources, dict)
            or prior_sources.get("manifest_sha256") != current_sources.get("manifest_sha256")):
        return None

    meta = record_cache_hit(
        audit_logger, state_manager,
        tool_name=tool_name, parameters=parameters,
        cache_key=build_cache_key(tool_name, parameters),
        artifact_path=csv_path, cache_source_execution_id=None,
    )
    return {
        "csv_path": csv_path,
        "reused_output": True,
        "reuse_confidence": "fingerprint_verified",
        "reuse_note": (
            "Durable output CSV reused (v2: source-set + parameters + parser "
            "signature verified). Parse skipped; pass force_reparse=True to regenerate."
        ),
        "execution_id": meta["execution_id"],
        "raw_command": meta["raw_command"],
    }


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
    duration_seconds: float = 0.0,
) -> dict[str, Any]:
    """Write a normal audit/state execution record for a cache hit.

    Blocker #1 (review 2026-06-04): the cache-hit execution row MUST
    satisfy reporting._execution_was_successful (exit_code==0 AND
    duration_seconds > 0 AND audit_completed_entry_hash present), not only the
    stop-hook gate (exit_code in (0,None)). Otherwise a reused artifact counts as
    "done" for the stop hook but FAILS the report coverage gate, blocking
    generate_report. We therefore record a positive duration (the measured reuse
    handling time, or a small positive floor - a cache hit is a legitimate
    success, not the 0.02s silent-failure pattern the gate guards against) and
    persist both the started + completed audit entry hashes onto the state row.
    """
    execution_id = audit_logger.next_execution_id()
    command_line = f"CACHE_HIT {tool_name}"
    audit_parameters = dict(parameters)
    audit_parameters["_cache_key"] = cache_key

    # Positive duration so the report gate's duration>0 check passes. Reuse is a
    # real success; the dotnet parse was legitimately skipped, not silently failed.
    try:
        dur = float(duration_seconds)
    except (TypeError, ValueError):
        dur = 0.0
    if dur <= 0.0:
        dur = 0.001
    dur = round(dur, 4)

    started = audit_logger.log_execution(
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

    completed = audit_logger.log_result(
        execution_id=execution_id,
        exit_code=0,
        duration=dur,
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
            "iteration": getattr(audit_logger, "current_iteration", None),
            "duration_seconds": dur,
            "exit_code": 0,
            "outputs_summary": outputs_summary,
            "audit_started_entry_hash": _entry_hash(started),
            "audit_completed_entry_hash": _entry_hash(completed),
            "cache_hit": True,
            "cache_source_execution_id": cache_source_execution_id,
        }
    )

    return {
        "execution_id": execution_id,
        "raw_command": command_line,
    }
