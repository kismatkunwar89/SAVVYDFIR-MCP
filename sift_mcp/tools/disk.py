"""
sift_mcp.tools.disk
~~~~~~~~~~~~~~~~~~~~

Disk forensics MCP tools for SAVVYDFIR-MCP.

All six tools wrap EZ Tools (via :class:`~sift_mcp.runners.eztools.EZToolsRunner`)
or The Sleuth Kit (via :class:`~sift_mcp.runners.sleuthkit.SleuthKitRunner`),
parse the CLI output into typed Pydantic models, and return plain dicts.

Tools
-----
- ``extract_prefetch``         - Prefetch execution evidence via ``pyscca``.
- ``get_amcache``              - AmcacheParser: SHA-1 evidence of execution.
- ``extract_mft_timeline``     - MFTECmd: Full NTFS MFT with SI/FN timestamps
                                  (timestomping detection).
- ``list_deleted_files``       - fls -rd: Deleted file recovery via TSK.
- ``summarize_evtx``           - EvtxECmd: Windows event log parsing.
- ``extract_registry_run_keys``- RECmd: Persistence key extraction.

Design pattern
--------------
Module-level ``_ez_runner``, ``_sk_runner``, ``_state``, and ``_audit``
singletons are injected via :func:`init_tools`.  EZ Tools write CSV output
to a temporary directory; after execution the tool reads and parses that file.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from sift_mcp.models.artifacts import (
    AmcacheRecord,
    DeletedFile,
    EventRecord,
    MftEntry,
    PrefetchRecord,
    RegistryRunKey,
)
from sift_mcp.models.finding import EvidenceKind, Finding, FindingStatus
from sift_mcp.semantics import adaptive_eids_from_findings, promote_corroborated_findings
from sift_mcp.tools._cache import (
    build_cache_key,
    get_valid_cached_artifact,
    record_cache_hit,
    try_durable_reuse,
    write_reuse_sidecar,
)
from sift_mcp.tools._contracts import (
    build_contract_response,
    build_follow_up_option,
    build_handle,
    build_provenance,
    compact_unique,
    sanitize_payload_fields,
    state_path_for_manager,
)

if TYPE_CHECKING:
    from sift_mcp.audit import AuditLogger
    from sift_mcp.runners.eztools import EZToolsRunner
    from sift_mcp.runners.sleuthkit import SleuthKitRunner
    from sift_mcp.state import CaseStateManager


__all__ = [
    "init_tools",
    "extract_prefetch",
    "get_amcache",
    "extract_mft_timeline",
    "list_deleted_files",
    "summarize_evtx",
    "extract_registry_run_keys",
]


# ---------------------------------------------------------------------------
# Module-level singletons - set via init_tools()
# ---------------------------------------------------------------------------

_ez_runner: Optional["EZToolsRunner"] = None
_sk_runner: Optional["SleuthKitRunner"] = None
_state: Optional["CaseStateManager"] = None
_audit: Optional["AuditLogger"] = None


def init_tools(
    state_manager: "CaseStateManager",
    audit_logger: "AuditLogger",
    ez_runner: Optional["EZToolsRunner"] = None,
    sk_runner: Optional["SleuthKitRunner"] = None,
) -> None:
    """Inject dependencies into this module's singleton slots.

    Must be called once at MCP server startup before any tool function is
    invoked.

    Parameters
    ----------
    state_manager:
        The initialised :class:`~sift_mcp.state.CaseStateManager` for this case.
    audit_logger:
        The :class:`~sift_mcp.audit.AuditLogger` for this case.
    ez_runner:
        Optional pre-built :class:`~sift_mcp.runners.eztools.EZToolsRunner`.
        When ``None`` a new runner is created with the supplied audit_logger.
    sk_runner:
        Optional pre-built :class:`~sift_mcp.runners.sleuthkit.SleuthKitRunner`.
        When ``None`` a new runner is created with the supplied audit_logger.
    """
    global _ez_runner, _sk_runner, _state, _audit
    _state = state_manager
    _audit = audit_logger
    if ez_runner is not None:
        _ez_runner = ez_runner
    else:
        from sift_mcp.runners.eztools import EZToolsRunner
        _ez_runner = EZToolsRunner(
            audit_logger=audit_logger,
            state_manager=state_manager,
        )
    if sk_runner is not None:
        _sk_runner = sk_runner
    else:
        from sift_mcp.runners.sleuthkit import SleuthKitRunner
        _sk_runner = SleuthKitRunner(
            audit_logger=audit_logger,
            state_manager=state_manager,
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _case_id() -> str:
    """Return the current case ID from state, or 'unknown'."""
    if _state is None:
        return "unknown"
    try:
        return _state.case_id
    except Exception:
        return "unknown"


def _artifact_output_dir(tool_short_name: str) -> Path:
    """Return the durable artifact directory for one disk tool."""
    return (
        Path(os.environ.get("OUTPUT_BASE", "/cases"))
        / _case_id()
        / "artifacts"
        / tool_short_name
    )


def _persistence_fix_hint(output_root: Path) -> str:
    configured_base = Path(os.environ.get("OUTPUT_BASE", "/cases"))
    return (
        f"Ensure OUTPUT_BASE ({configured_base}) is writable and that "
        f"{output_root} can be created, then rerun the tool."
    )


def _preflight_artifact_persistence(
    tool_short_name: str,
    filename: str,
) -> dict[str, Any]:
    """Validate the durable artifact destination before expensive work starts."""
    output_root = _artifact_output_dir(tool_short_name)
    expected_path = output_root / filename
    try:
        output_root.mkdir(parents=True, exist_ok=True)
        probe = tempfile.NamedTemporaryFile(
            dir=str(output_root),
            prefix=".savvydfir_preflight_",
            delete=False,
        )
        probe.write(b"ok")
        probe.close()
        Path(probe.name).unlink(missing_ok=True)
        return {
            "ok": True,
            "status": "durable",
            "output_root": str(output_root),
            "persisted_path": str(expected_path),
            "reason": f"Durable artifact path is writable under {output_root}.",
            "fix_hint": None,
        }
    except OSError as exc:
        return {
            "ok": False,
            "status": "transient",
            "output_root": str(output_root),
            "persisted_path": None,
            "reason": (
                f"Unable to persist analyst-facing artifact output under {output_root}: {exc}"
            ),
            "fix_hint": _persistence_fix_hint(output_root),
        }


def _artifact_preflight_error(
    *,
    tool_name: str,
    preflight: dict[str, Any],
) -> dict[str, Any]:
    """Return a standard response when durable artifact output is unavailable."""
    return {
        "tool_name": tool_name,
        "status": "error",
        "error_message": str(
            preflight.get("reason")
            or "Artifact persistence preflight failed."
        ),
        "data": [],
        "findings_created": [],
        "execution_id": None,
        "raw_command": None,
        "artifact_persistence": {
            "status": "transient",
            "persisted_path": None,
            "reason": str(preflight.get("reason") or ""),
            "fix_hint": preflight.get("fix_hint"),
        },
    }


def _finalize_artifact_persistence(
    *,
    artifact_label: str,
    persisted_path: Optional[str],
    preflight: Optional[dict[str, Any]],
) -> tuple[Optional[str], dict[str, Any]]:
    """Return the durable analyst-facing path and artifact_persistence block."""
    normalized_path = _resolved_path_str(persisted_path) if persisted_path else None
    if (
        normalized_path
        and Path(normalized_path).exists()
        and not _is_transient_persisted_path(normalized_path)
    ):
        return normalized_path, {
            "status": "durable",
            "persisted_path": normalized_path,
            "reason": f"{artifact_label} persisted to analyst-facing artifact storage.",
            "fix_hint": None,
        }

    preflight_reason = str(preflight.get("reason") or "").strip() if isinstance(preflight, dict) else ""
    preflight_hint = preflight.get("fix_hint") if isinstance(preflight, dict) else None
    output_root = Path(str(preflight.get("output_root"))) if isinstance(preflight, dict) and preflight.get("output_root") else _artifact_output_dir("unknown")
    if normalized_path and _is_transient_persisted_path(normalized_path):
        reason = (
            f"{artifact_label} was produced, but persistence fell back to a transient temp path "
            "that will not survive after the tool returns."
        )
    elif preflight_reason:
        reason = preflight_reason
    else:
        reason = (
            f"{artifact_label} was produced, but persistence did not create a durable "
            "analyst-facing handle."
        )

    return None, {
        "status": "transient",
        "persisted_path": None,
        "reason": reason,
        "fix_hint": preflight_hint or _persistence_fix_hint(output_root),
    }


def _current_iteration() -> int:
    """Return the current audit iteration number."""
    if _audit is None:
        return 1
    return _audit.current_iteration


def _persist_csv(tmp_csv_path: str, tool_short_name: str) -> str:
    """Copy a tempdir CSV to a persistent artifact path and return the new path.

    Pattern: $OUTPUT_BASE/<case_id>/artifacts/<tool_short_name>/<filename>
    Allows run_analysis() to query the full dataset after the tool returns.
    Returns the persistent path on success, original path on failure.
    """
    import shutil as _shutil
    src_path = Path(tmp_csv_path)
    if not src_path.exists():
        return tmp_csv_path
    base = _artifact_output_dir(tool_short_name)
    try:
        base.mkdir(parents=True, exist_ok=True)
        dest = base / src_path.name
        _shutil.copy2(str(src_path), str(dest))
        return str(dest)
    except OSError:
        return tmp_csv_path


def _is_transient_persisted_path(path: Optional[str]) -> bool:
    text = str(path or "").strip().lower()
    return text.startswith("/tmp/savvydfir_") or text.startswith("/var/tmp/savvydfir_")


def _persist_rows_as_csv(
    rows: list[dict[str, Any]],
    *,
    tool_short_name: str,
    filename: str,
) -> Optional[str]:
    """Persist structured rows as a reusable CSV artifact."""
    try:
        with tempfile.TemporaryDirectory(prefix=f"savvydfir_{tool_short_name}_rows_") as tmp_dir:
            tmp_csv = os.path.join(tmp_dir, filename)
            _write_csv_rows(
                [{key: "" if value is None else str(value) for key, value in row.items()} for row in rows],
                tmp_csv,
            )
            return _persist_csv(tmp_csv, tool_short_name)
    except Exception:
        return None


def _read_csv(csv_path: str) -> list[dict[str, str]]:
    """Read a CSV file (with UTF-8 BOM handling) and return rows as dicts.

    Parameters
    ----------
    csv_path:
        Absolute path to the CSV file written by an EZ Tools process.

    Returns
    -------
    list[dict[str, str]]
        Rows in file order, each as a ``{column_name: value}`` dict.
        Returns an empty list if the file is absent or empty.
    """
    p = Path(csv_path)
    if not p.exists() or p.stat().st_size == 0:
        return []
    # Read raw bytes and strip NUL bytes (MFTECmd emits NUL in some rows)
    raw = p.read_bytes().replace(b'\x00', b'')
    text = raw.decode('utf-8-sig', errors='replace')
    import io
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def _write_csv_rows(rows: list[dict[str, str]], csv_path: str) -> None:
    """Write dict rows to CSV while preserving first-seen field order."""
    path = Path(csv_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _parse_dt(value: str) -> Optional[datetime]:
    """Parse a datetime string from an EZ Tools CSV into a ``datetime`` object.

    EZ Tools uses ISO 8601 format with varying levels of precision.  Returns
    ``None`` if the value is empty or unparseable.
    """
    if not value or value.strip() in ("", "N/A", "null", "NULL", "None"):
        return None
    value = value.strip()
    # Normalise to a form Python can parse
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _warn_if_empty(result: dict, tool_name: str, path: str, min_expected: int = 1) -> dict:
    """Upgrade status to 'warning' if records=0 but path exists.

    Silent 0-record success is the worst failure mode - it looks like
    a clean system when the tool silently failed. This makes it loud.
    """
    count = result.get("records_count", len(result.get("data", [])))
    if count == 0 and os.path.exists(path):
        result = dict(result)
        result["status"] = "warning"
        result["warning"] = (
            f"{tool_name} found 0 records but path exists: {path}. "
            f"Verify mount point and tool parameters. "
            f"A clean Windows system should always have records here."
        )
    return result


def _normalize_response_format(response_format: str) -> Optional[str]:
    """Validate and normalize the heavy-tool response format selector."""
    normalized = (response_format or "summary").strip().lower()
    if normalized in {"summary", "detailed"}:
        return normalized
    return None


def _apply_response_format(
    result: dict[str, Any],
    *,
    response_format: str,
    records: list[Any],
    total_records: int,
) -> dict[str, Any]:
    """Return a summary-first or detailed response payload."""
    payload = dict(result)
    normalized = _normalize_response_format(response_format)
    if normalized:
        payload["response_format"] = normalized
    if normalized == "summary":
        payload.pop("data", None)
        payload["records_count"] = len(records)
        payload["total_records"] = total_records
        note = payload.get("note")
        # NOTE: detailed mode returns a BOUNDED inline sample (memory-safety cap),
        # not the full record set -- never advertise it as "the full array".
        _detail_hint = (
            'Raw records omitted by default; response_format="detailed" returns a '
            "bounded inline sample. Use csv_path + run_analysis() for full fidelity."
        )
        if isinstance(note, str) and note:
            payload["note"] = f"{note} {_detail_hint}"
        else:
            payload["note"] = _detail_hint
        return payload

    if normalized == "detailed":
        payload["data"] = [record.model_dump(
            mode="json") for record in records]
        payload["records_count"] = len(records)
        payload["total_records"] = total_records
    return payload


def _resolved_path_str(path: str) -> str:
    """Return a resolved absolute path string when possible."""
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _any_glob(path: Path, pattern: str) -> bool:
    try:
        return any(path.glob(pattern))
    except OSError:
        return False


def _shared_windows_root_candidates() -> list[Path]:
    """Return common mounted Windows roots that tools may reuse."""
    candidates: list[Path] = []
    for root in (Path("/mnt/disk"),):
        if _path_exists(root):
            candidates.append(root)
    return candidates


def _ci_resolve(root: Path, *parts: str) -> Optional[Path]:
    """Resolve a path under ``root`` matching each component CASE-INSENSITIVELY.

    NTFS is case-insensitive, but a Linux ntfs-3g mount is case-SENSITIVE, so an
    XP/older image whose top dir is ``WINDOWS`` (uppercase) would not resolve a
    hardcoded ``Windows`` lookup (Hacking Case 2026-06-06 edge case: 81 Prefetch
    .pf were missed and falsely reported artifact_absent). This walks each path
    component, preferring an exact match (fast path) then falling back to a
    case-folded scan of the directory's children. Returns the real resolved Path
    if every component matched, else ``None``.
    """
    cur = root
    if not _path_exists(cur):
        return None
    for part in parts:
        nxt = cur / part
        if _path_exists(nxt):
            cur = nxt
            continue
        found: Optional[Path] = None
        try:
            target = part.lower()
            for child in cur.iterdir():
                if child.name.lower() == target:
                    found = child
                    break
        except OSError:
            return None
        if found is None:
            return None
        cur = found
    return cur


def _candidate_windows_volume_roots(image_path: str) -> list[Path]:
    """Return possible Windows volume roots for mounted-evidence lookups."""
    base = Path(image_path)
    candidates: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path) -> None:
        text = str(path)
        if text in seen:
            return
        seen.add(text)
        candidates.append(path)

    for shared_root in _shared_windows_root_candidates():
        _add(shared_root)

    if _path_is_dir(base):
        if _ci_resolve(base, "Windows") is not None:
            _add(base)
        if _ci_resolve(base / "mnt" / "C", "Windows") is not None:
            _add(base / "mnt" / "C")

    if not candidates and _path_is_dir(base):
        if _path_exists(base / "mnt" / "C"):
            _add(base / "mnt" / "C")
        else:
            _add(base)

    return candidates


def _resolve_windows_relative_path(image_path: str, *relative_parts: str) -> str:
    """Resolve a Windows-relative artifact path from a mounted/root image path."""
    volume_roots = _candidate_windows_volume_roots(image_path)
    for root in volume_roots:
        # case-insensitive resolve (handles XP/older uppercase WINDOWS on a
        # case-sensitive ntfs-3g mount); falls back to exact join below.
        resolved = _ci_resolve(root, *relative_parts)
        if resolved is not None:
            return str(resolved)
    for root in volume_roots:
        candidate = root.joinpath(*relative_parts)
        if _path_exists(candidate):
            return str(candidate)
    if volume_roots:
        return str(volume_roots[0].joinpath(*relative_parts))
    base = Path(image_path)
    return str(base.joinpath("mnt", "C", *relative_parts))


def _raw_artifact_base() -> Path:
    return Path(os.environ.get("OUTPUT_BASE", "/cases")) / _case_id() / "artifacts" / "raw"


def probe_durable_raw(raw_base: Path, kind: str) -> Optional[str]:
    """Content-aware probe for a durable staged artifact under an EXPLICIT raw_base.

    Parameterized form (durable-reuse review 2026-06-03): callers pass the
    raw_base they computed from their OWN case_id, so server.py staging never
    probes the wrong case via module-level _case_id() state. Returns a path ONLY
    when the expected artifact files are actually present (rejects empty/partial
    dirs - a prior bug let an empty raw/evtx shadow a valid mounted Windows root).
    """
    base = Path(raw_base)
    if kind == "evtx":
        candidate = base / "evtx"
        if candidate.is_dir() and any(candidate.glob("*.evtx")):
            return str(candidate)
        return None
    if kind == "registry":
        candidate = base / "registry"
        if candidate.is_dir():
            # Run-8 lesson: a SAM-only staging dir was treated as valid here,
            # then RECmd produced SAM-only output and persistence data was
            # lost (no Run keys, no services). For persistence analysis we
            # need SYSTEM and/or SOFTWARE - the hives that actually carry
            # Run keys + ControlSet\Services. Return the dir only if at
            # least one of those is present; SAM or NTUSER alone is not
            # enough to call this "a registry dir for persistence work".
            for required in ("SYSTEM", "SOFTWARE"):
                if (candidate / required).is_file():
                    return str(candidate)
        return None
    if kind == "prefetch":
        candidate = base / "prefetch"
        if candidate.is_dir() and any(candidate.glob("*.pf")):
            return str(candidate)
        return None
    if kind == "amcache":
        candidate = base / "amcache" / "Amcache.hve"
        if candidate.is_file() and candidate.stat().st_size > 0:
            return str(candidate)
        return None
    if kind == "mft":
        candidate = base / "mft" / "$MFT"
        if candidate.is_file() and candidate.stat().st_size > 0:
            return str(candidate)
        return None
    if kind == "srum":
        candidate = base / "srum" / "SRUDB.dat"
        if candidate.is_file() and candidate.stat().st_size > 0:
            return str(candidate)
        return None
    if kind == "usn":
        usn_dir = base / "usn"
        if usn_dir.is_dir():
            # known staged journal names (mirror _resolve_usn_path_input variants)
            for name in ("$J", "$UsnJrnl_$J", "$UsnJrnl_J", "UsnJrnl_J",
                         "usn_journal_J", "$UsnJrnl"):
                cand = usn_dir / name
                if cand.is_file() and cand.stat().st_size > 0:
                    return str(usn_dir)
            # fallback: any non-empty staged file in the usn dir
            try:
                for cand in usn_dir.iterdir():
                    if cand.is_file() and cand.stat().st_size > 0:
                        return str(usn_dir)
            except OSError:
                pass
        return None
    return None


def _durable_raw_artifact_path(kind: str) -> Optional[str]:
    """Back-compat wrapper: probe under the module-state case raw base.

    Downstream disk.py parsers keep calling this (module _case_id() base);
    server.py staging calls probe_durable_raw(raw_base, kind) with its OWN
    case_id-derived base to avoid wrong-case probing (durable-reuse review).
    """
    return probe_durable_raw(_raw_artifact_base(), kind)


# ---------------------------------------------------------------------------
# Extraction-failure classification (review 2026-06-03).
# Family-aware BASENAME matching (NOT path substring - 'system' must not match
# every Windows/System32/* path) + narrow stderr decompression signatures so a
# torn/compressed live artifact routes to RECOVERY (VSS) instead of retry.
# Pure + importable (no fastmcp) so server.py uses these for both
# critical_failures[] and the per-file data_gaps.
# ---------------------------------------------------------------------------
_CRITICAL_FAILURE_BASENAMES: dict[str, frozenset[str]] = {
    "evtx": frozenset({"security.evtx", "system.evtx"}),
    "registry": frozenset({"system", "software", "sam", "security", "ntuser.dat"}),
    "mft": frozenset({"$mft"}),
}
# stderr signatures that indicate decompression / compressed-data corruption
# (recover via VSS) vs a generic/retryable failure (timeout, write, bad meta).
_DECOMPRESSION_SIGNATURES: tuple[str, ...] = (
    "value too large", "ntfs_uncompress", "uncompress", "decompress",
    "compression", "compressed", "compunit", "data error", "lzxpress",
    "invalid compressed", "unable to decompress", "bad compression",
)


def _failure_basename(failure: dict[str, Any]) -> str:
    sp = str(failure.get("source_path") or "").replace("\\", "/")
    return sp.rsplit("/", 1)[-1].strip().lower()


def is_critical_extraction_failure(failure: dict[str, Any]) -> bool:
    """True iff this per-file failure is a forensically critical artifact,
    matched by FAMILY + exact BASENAME (never path substring)."""
    fam = str(failure.get("family") or "").strip().lower()
    base = _failure_basename(failure)
    if base in _CRITICAL_FAILURE_BASENAMES.get(fam, frozenset()):
        return True
    # per-user NTUSER staging slug: {user}_NTUSER.DAT
    if fam == "registry" and base.endswith("ntuser.dat"):
        return True
    return False


def classify_extraction_failure(failure: dict[str, Any]) -> str:
    """'damaged_artifact_recovery_required' (decompression/corruption -> VSS) or
    'critical_artifact_extraction_failed' (generic/retryable). stderr is a
    heuristic recovery HINT, not proof of cluster damage."""
    stderr = str(failure.get("stderr") or "").lower()
    if any(sig in stderr for sig in _DECOMPRESSION_SIGNATURES):
        return "damaged_artifact_recovery_required"
    return "critical_artifact_extraction_failed"


def _unsafe_runtime_tmp_input(path: str) -> bool:
    """Reject broad or ad hoc /tmp artifact sources created by manual recovery."""
    try:
        resolved = str(Path(path).resolve())
    except (OSError, RuntimeError, ValueError):
        resolved = str(path)
    normalized = resolved.rstrip("/")
    tmp_exact = {
        "/tmp",
        "/tmp/Security.evtx",
        "/tmp/System.evtx",
        "/tmp/Microsoft-Windows-Sysmon%4Operational.evtx",
    }
    if normalized in tmp_exact:
        return True
    return any(
        normalized == prefix or normalized.startswith(prefix + "/")
        for prefix in ("/tmp/registry", "/tmp/amcache", "/tmp/Prefetch")
    )


def _unsafe_path_error(
    tool_name: str,
    *,
    input_name: str,
    resolved_path: str,
    image_path: str,
) -> dict[str, Any]:
    return {
        **_path_missing_error(
            tool_name,
            input_name=input_name,
            resolved_path=resolved_path,
            image_path=image_path,
        ),
        "error_message": (
            f"Unsafe transient artifact source rejected for {input_name}: {resolved_path}. "
            "Use durable /cases/{case_id}/artifacts/raw paths from extract_windows_artifacts."
        ),
        "needs_extract_windows_artifacts": True,
        "recommended_tool_call": (
            f"extract_windows_artifacts(case_id='{_case_id()}', image_path='{image_path}')"
        ),
    }


def _resolve_evtx_dir_input(image_path: str, evtx_dir: Optional[str]) -> str:
    """Resolve the EVTX directory to use for parsing.

    A.2 fix: durable extracted-artifacts path (/cases/{case}/artifacts/raw/evtx)
    is preferred over scanning the image/mount root, because raw mount paths
    like /mnt/evidence/ewf1 do not auto-navigate to the Windows partition
    and the mount-root fallback returns a non-existent path. Run2 evidence:
    main agent called summarize_evtx with the mount root first, the call
    failed, and the hook then dispatched evtx-analyst on the failure.

    Resolution order:
      1. explicit evtx_dir argument (caller knows best)
      2. durable extracted artifacts (proves extract_windows_artifacts ran)
      3. image_path is a single .evtx file → use its parent
      4. image_path is a directory containing .evtx files → use it
      5. mount-root fallback via Windows/System32/winevt/Logs
    """
    if evtx_dir is not None:
        return evtx_dir
    # A.2: prefer durable path BEFORE scanning image_path. If the operator
    # has already extracted artifacts, those win regardless of what
    # image_path was passed.
    durable = _durable_raw_artifact_path("evtx")
    if durable:
        return durable
    base = Path(image_path)
    if _path_is_file(base) and base.suffix.lower() == ".evtx":
        return str(base.parent)
    if _path_is_dir(base) and _any_glob(base, "*.evtx"):
        return str(base)
    return _resolve_windows_relative_path(
        image_path, "Windows", "System32", "winevt", "Logs"
    )


def _resolve_registry_hive_dir_input(image_path: str, hive_dir: Optional[str]) -> str:
    """A.2: durable extracted artifacts take precedence over image_path scan."""
    if hive_dir is not None:
        return hive_dir
    durable = _durable_raw_artifact_path("registry")
    if durable:
        return durable
    base = Path(image_path)
    if _path_is_file(base) and base.name.upper() in {
        "SYSTEM",
        "SOFTWARE",
        "SECURITY",
        "SAM",
        "NTUSER.DAT",
    }:
        return str(base.parent)
    if _path_is_dir(base) and any(_path_exists(base / name) for name in ("SYSTEM", "SOFTWARE", "NTUSER.DAT")):
        return str(base)
    return _resolve_windows_relative_path(
        image_path, "Windows", "System32", "config"
    )


def _resolve_amcache_hive_input(image_path: str, hive_path: Optional[str]) -> str:
    """A.2: durable extracted artifacts win over image_path scan."""
    if hive_path is not None:
        return hive_path
    durable = _durable_raw_artifact_path("amcache")
    if durable:
        return durable
    base = Path(image_path)
    if _path_is_file(base) and base.name.lower() == "amcache.hve":
        return str(base)
    return _resolve_windows_relative_path(
        image_path, "Windows", "appcompat", "Programs", "Amcache.hve"
    )


def _resolve_prefetch_dir_input(image_path: str, prefetch_dir: Optional[str]) -> str:
    """A.2: durable extracted artifacts win over image_path scan."""
    if prefetch_dir is not None:
        return prefetch_dir
    durable = _durable_raw_artifact_path("prefetch")
    if durable:
        return durable
    base = Path(image_path)
    if _path_is_dir(base) and _any_glob(base, "*.pf"):
        return str(base)
    return _resolve_windows_relative_path(image_path, "Windows", "Prefetch")


def _resolve_mft_path_input(image_path: str, mft_path: Optional[str]) -> str:
    """A.2: durable extracted artifacts win over image_path scan."""
    if mft_path is not None:
        return mft_path
    durable = _durable_raw_artifact_path("mft")
    if durable:
        return durable
    base = Path(image_path)
    if _path_is_file(base) and base.name == "$MFT":
        return str(base)
    return _resolve_windows_relative_path(image_path, "$MFT")


def _path_missing_error(
    tool_name: str,
    *,
    input_name: str,
    resolved_path: str,
    image_path: str,
) -> dict[str, Any]:
    """Return a standardised error when an inferred artifact path does not exist."""
    return {
        "tool_name": tool_name,
        "status": "error",
        "error_message": (
            f"Resolved {input_name} does not exist: {resolved_path}. "
            "Provide the artifact path explicitly or mount the Windows volume root first."
        ),
        "data": [],
        "findings_created": [],
        "execution_id": None,
        "raw_command": None,
        "input_name": input_name,
        "resolved_path": resolved_path,
        "image_path": image_path,
        "needs_extract_windows_artifacts": True,
        "recommended_tool_call": (
            f"extract_windows_artifacts(case_id='{_case_id()}', image_path='{image_path}')"
        ),
    }


def _dt_to_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()


def _normalize_prefetch_match_key(path: str) -> str:
    """Normalize a Prefetch file path into a comparable relative artifact key."""
    text = str(path or "").strip().strip('"').strip("'")
    if not text:
        return ""
    normalized = re.sub(r"/+", "/", text.replace("\\", "/").lower()).strip()
    if not normalized:
        return ""
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/mnt/disk/"):
        normalized = normalized[len("/mnt/disk/"):]
    elif re.match(r"^[a-z]:/", normalized):
        normalized = normalized[3:]
    elif normalized.startswith("/cases/"):
        case_mount = re.search(r"/mnt/[a-z]/(.+)$", normalized)
        normalized = case_mount.group(1) if case_mount else normalized.lstrip("/")
    else:
        normalized = normalized.lstrip("/")
    return normalized.lstrip("./").rstrip("/")


def _prefetch_match_keys(path: str) -> list[str]:
    """Return full-path and basename keys for best-effort Prefetch joins."""
    normalized = _normalize_prefetch_match_key(path)
    if not normalized:
        return []
    keys = [normalized]
    basename = normalized.rsplit("/", 1)[-1]
    if basename and basename not in keys:
        keys.append(basename)
    return keys


def _latest_durable_csv_for_tool(tool_name: str) -> Optional[str]:
    """Return the latest durable CSV linked to *tool_name* in state executions."""
    if _state is None:
        return None
    for execution in reversed(_state.get_executions(tool_name=tool_name)):
        refs = execution.get("raw_evidence_refs") or []
        preferred: list[str] = []
        fallback: list[str] = []
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            path = str(ref.get("path") or "").strip()
            if not path:
                continue
            resolved = _resolved_path_str(path)
            if (
                not resolved.lower().endswith(".csv")
                or _is_transient_persisted_path(resolved)
                or not Path(resolved).exists()
            ):
                continue
            role = str(ref.get("role") or "").strip().lower()
            if role in {"derived", "handle"}:
                preferred.append(resolved)
            else:
                fallback.append(resolved)
        if preferred:
            return preferred[0]
        if fallback:
            return fallback[0]
    return None


def _prefetch_mft_candidate_path(row: dict[str, str]) -> str:
    """Build a comparable Prefetch file path from an MFT CSV row."""
    file_name = str(row.get("FileName") or "").strip()
    parent_path = str(row.get("ParentPath") or row.get("FilePath") or "").strip()
    if parent_path and file_name:
        trimmed_parent = parent_path.rstrip("/\\")
        return f"{trimmed_parent}/{file_name}"
    return file_name or parent_path


def _prefetch_mft_timestamp_lookup(csv_path: str) -> dict[str, dict[str, Any]]:
    """Build a lookup of Prefetch file metadata from a durable MFT CSV.

    Streams the (potentially large) MFT CSV one row at a time so this lookup
    never materializes the whole file in memory (the MFT OOM twin).
    """
    lookup: dict[str, dict[str, Any]] = {}
    for row in _iter_csv_rows(csv_path):
        candidate_path = _prefetch_mft_candidate_path(row)
        if not candidate_path.lower().endswith(".pf"):
            continue
        metadata = {
            "pf_created_time": _parse_dt(row.get("Created0x10") or row.get("SICreated") or ""),
            "pf_modified_time": _parse_dt(
                row.get("LastModified0x10") or row.get("SIModified") or ""
            ),
            "pf_timestamp_source": "mft",
        }
        if metadata["pf_created_time"] is None and metadata["pf_modified_time"] is None:
            continue
        for key in _prefetch_match_keys(candidate_path):
            lookup.setdefault(key, metadata)
    return lookup


def _prefetch_metadata_from_stat_result(stat_result: os.stat_result) -> dict[str, Any]:
    """Map a stat result into `.pf` file metadata without using ctime."""
    created = None
    modified = None
    try:
        if getattr(stat_result, "st_atime", 0):
            created = datetime.fromtimestamp(stat_result.st_atime, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        created = None
    try:
        if getattr(stat_result, "st_mtime", 0):
            modified = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        modified = None
    return {
        "pf_created_time": created,
        "pf_modified_time": modified,
        "pf_timestamp_source": "mounted_ntfs_stat" if created or modified else None,
    }


def _prefetch_metadata_from_stat(prefetch_path: str) -> Optional[dict[str, Any]]:
    """Read `.pf` file metadata from the mounted NTFS-backed filesystem."""
    path = Path(prefetch_path)
    if not path.exists() or not path.is_file():
        return None
    try:
        metadata = _prefetch_metadata_from_stat_result(path.stat())
    except OSError:
        return None
    if metadata["pf_created_time"] is None and metadata["pf_modified_time"] is None:
        return None
    return metadata


def _enrich_prefetch_records_with_filesystem_metadata(
    records: list[PrefetchRecord],
) -> None:
    """Populate `.pf` file metadata from MFT when available, else mounted stat()."""
    if not records:
        return
    mft_lookup: dict[str, dict[str, Any]] = {}
    mft_csv = _latest_durable_csv_for_tool("disk.extract_mft_timeline")
    if mft_csv:
        mft_lookup = _prefetch_mft_timestamp_lookup(mft_csv)
    for record in records:
        metadata: Optional[dict[str, Any]] = None
        for key in _prefetch_match_keys(record.prefetch_path):
            metadata = mft_lookup.get(key)
            if metadata:
                break
        if not metadata:
            metadata = _prefetch_metadata_from_stat(record.prefetch_path)
        if metadata:
            record.pf_created_time = metadata.get("pf_created_time")
            record.pf_modified_time = metadata.get("pf_modified_time")
            record.pf_timestamp_source = metadata.get("pf_timestamp_source")


def _prefetch_contract_payload(
    *,
    response: dict[str, Any],
    records: list[PrefetchRecord],
    image_path: str,
    prefetch_dir: str,
    csv_path: Optional[str],
) -> dict[str, Any]:
    normalized = [
        {
            "executable_name": record.executable_name,
            "run_count": record.run_count,
            "last_run_times": [_dt_to_iso(value) for value in record.last_run_times],
            "pf_created_time": _dt_to_iso(record.pf_created_time),
            "pf_modified_time": _dt_to_iso(record.pf_modified_time),
            "pf_timestamp_source": record.pf_timestamp_source,
            "prefetch_path": record.prefetch_path,
        }
        for record in records[:20]
    ]
    summary = (
        f"Prefetch parsed {response.get('records_count', len(records))} execution artifacts "
        f"from {prefetch_dir}. `last_run_times` capture exact Prefetch-native execution history; "
        f"`pf_created_time` and `pf_modified_time` are `.pf` file metadata. "
        f"Persisted CSV{' available' if csv_path else ' unavailable'} for deeper review."
    )
    return build_contract_response(
        response,
        case_id=_case_id(),
        execution_id=response.get("execution_id"),
        state_manager=_state,
        audit_logger=_audit,
        tool_name="disk.extract_prefetch",
        summary=summary,
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="disk.extract_prefetch",
            execution_id=response.get("execution_id"),
            raw_command=response.get("raw_command"),
            state_path=state_path_for_manager(_state),
            csv_path=csv_path,
            artifact_paths=[prefetch_dir],
        ),
        pivot_entities={
            "executable_names": compact_unique(record.executable_name for record in records),
            "prefetch_paths": compact_unique(record.prefetch_path for record in records),
            "referenced_files": compact_unique(
                path for record in records for path in record.referenced_files
            ),
            "last_run_times": compact_unique(
                _dt_to_iso(timestamp)
                for record in records
                for timestamp in record.last_run_times
            ),
            "pf_file_timestamps": compact_unique(
                _dt_to_iso(record.pf_modified_time) or _dt_to_iso(record.pf_created_time)
                for record in records
            ),
            "pf_timestamp_sources": compact_unique(record.pf_timestamp_source for record in records),
        },
        follow_up_options=[
            build_follow_up_option(
                "get_amcache",
                reason="Recover hashes and publisher metadata for executed binaries.",
                parameters={"image_path": image_path},
            ),
            build_follow_up_option(
                "summarize_evtx",
                reason="Correlate execution with Security 4688 process-creation evidence.",
                parameters={"image_path": image_path, "event_ids": "4688"},
            ),
            build_follow_up_option(
                "extract_mft_timeline",
                reason="Pivot from execution evidence into file creation and timestomping context.",
                parameters={"image_path": image_path},
            ),
        ],
        handle=build_handle(
            kind="csv",
            path=csv_path,
            description="Persisted Prefetch artifact snapshot.",
            tool_name="disk.extract_prefetch",
        ) if csv_path else None,
    )


def _amcache_contract_payload(
    *,
    response: dict[str, Any],
    records: list[AmcacheRecord],
    image_path: str,
    hive_path: str,
    csv_path: Optional[str],
) -> dict[str, Any]:
    normalized = [
        {
            "file_path": record.file_path,
            "sha1_hash": record.sha1_hash,
            "publisher": record.publisher,
            "install_time": _dt_to_iso(record.install_time),
        }
        for record in records[:20]
    ]
    summary = (
        f"Amcache returned {response.get('records_count', len(records))} execution records from {hive_path}. "
        f"Persisted CSV{' is available' if csv_path else ' is unavailable'} for hash and path pivots."
    )
    return build_contract_response(
        response,
        case_id=_case_id(),
        execution_id=response.get("execution_id"),
        state_manager=_state,
        audit_logger=_audit,
        tool_name="disk.get_amcache",
        summary=summary,
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="disk.get_amcache",
            execution_id=response.get("execution_id"),
            raw_command=response.get("raw_command"),
            state_path=state_path_for_manager(_state),
            csv_path=csv_path,
            artifact_paths=[hive_path],
        ),
        pivot_entities={
            "file_paths": compact_unique(record.file_path for record in records),
            "sha1_hashes": compact_unique(record.sha1_hash for record in records),
            "publishers": compact_unique(record.publisher for record in records),
        },
        follow_up_options=[
            build_follow_up_option(
                "extract_prefetch",
                reason="Confirm execution count and first/last run timestamps.",
                parameters={"image_path": image_path},
            ),
            build_follow_up_option(
                "summarize_evtx",
                reason="Correlate binaries with process-creation and service-install events.",
                parameters={"image_path": image_path, "event_ids": "4688,7045,4698"},
            ),
            build_follow_up_option(
                "extract_registry_run_keys",
                reason="Check whether executed binaries were also persisted via ASEPs.",
                parameters={"image_path": image_path},
            ),
        ],
        handle=build_handle(
            kind="csv",
            path=csv_path,
            description="Persisted Amcache execution dataset.",
            tool_name="disk.get_amcache",
        ) if csv_path else None,
    )


def _mft_contract_payload(
    *,
    response: dict[str, Any],
    records: list[MftEntry],
    image_path: str,
    mft_path: str,
    csv_path: Optional[str],
    normalized: Optional[list[dict[str, Any]]] = None,
    pivot_entities: Optional[dict[str, Any]] = None,
    evidence_excerpt: Optional[str] = None,
) -> dict[str, Any]:
    # Streaming callers pass FULL-scan aggregates (over every row) so pivots
    # reflect the whole CSV, not the retained sample. Legacy / direct tests
    # derive them from `records`.
    if normalized is None:
        normalized = [
            {
                "entry_number": record.entry_number,
                "file_path": record.file_path,
                "si_created": _dt_to_iso(record.si_created),
                "fn_created": _dt_to_iso(record.fn_created),
                "is_deleted": record.is_deleted,
            }
            for record in records[:20]
        ]
    summary = (
        f"MFT timeline returned {response.get('total_records', response.get('records_count', len(records)))} rows "
        f"from {mft_path} with {response.get('timestomping_candidates', 0)} timestomping candidates."
    )
    if evidence_excerpt is None:
        evidence_excerpt = next(
            (record.file_path for record in records if record.file_path),
            None,
        )
    if pivot_entities is None:
        pivot_entities = {
            "file_paths": compact_unique(record.file_path for record in records),
            "entry_numbers": compact_unique(record.entry_number for record in records),
            "timestamps": compact_unique(
                _dt_to_iso(record.fn_created) or _dt_to_iso(record.si_created)
                for record in records
            ),
        }
    return build_contract_response(
        response,
        case_id=_case_id(),
        execution_id=response.get("execution_id"),
        state_manager=_state,
        audit_logger=_audit,
        tool_name="disk.extract_mft_timeline",
        summary=summary,
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="disk.extract_mft_timeline",
            execution_id=response.get("execution_id"),
            raw_command=response.get("raw_command"),
            state_path=state_path_for_manager(_state),
            csv_path=csv_path,
            cache_hit=response.get("cache_hit"),
            cache_source_execution_id=response.get("cache_source_execution_id"),
            artifact_paths=[mft_path],
        ),
        pivot_entities={
            "file_paths": compact_unique(record.file_path for record in records),
            "entry_numbers": compact_unique(record.entry_number for record in records),
            "timestamps": compact_unique(
                _dt_to_iso(record.fn_created) or _dt_to_iso(record.si_created)
                for record in records
            ),
        },
        follow_up_options=[
            build_follow_up_option(
                "extract_prefetch",
                reason="Correlate file-system activity with execution evidence.",
                parameters={"image_path": image_path},
            ),
            build_follow_up_option(
                "get_amcache",
                reason="Recover hashes for suspicious executables or deleted binaries.",
                parameters={"image_path": image_path},
            ),
            build_follow_up_option(
                "summarize_evtx",
                reason="Cross-reference file activity with process creation or service-install events.",
                parameters={"image_path": image_path, "event_ids": "4688,7045,4698"},
            ),
        ],
        handle=build_handle(
            kind="csv",
            path=csv_path,
            description="Persisted MFTECmd CSV output.",
            tool_name="disk.extract_mft_timeline",
        ) if csv_path else None,
        evidence_excerpt=evidence_excerpt,
    )


def _evtx_contract_payload(
    *,
    response: dict[str, Any],
    records: list[EventRecord],
    image_path: str,
    evtx_dir: str,
    csv_path: Optional[str],
    channel_counts: Optional[dict[str, int]] = None,
    pivot_entities: Optional[dict[str, Any]] = None,
    normalized: Optional[list[dict[str, Any]]] = None,
    evidence_excerpt: Optional[str] = None,
) -> dict[str, Any]:
    # Streaming callers pass FULL-scan aggregates (computed over every row) so
    # the histogram/pivots reflect the whole CSV, not just the retained sample.
    # When omitted (legacy / direct unit tests) we derive them from `records`.
    if channel_counts is None:
        channel_counts = {}
        for record in records:
            channel_counts[record.channel] = channel_counts.get(record.channel, 0) + 1
    if normalized is None:
        normalized = [
            {
                "event_id": record.event_id,
                "channel": record.channel,
                "timestamp": _dt_to_iso(record.timestamp),
                "computer": record.computer,
                "provider": record.provider,
            }
            for record in records[:20]
        ]
    if evidence_excerpt is None:
        evidence_excerpt = next(
            (record.message_summary for record in records if record.message_summary),
            None,
        )
    if pivot_entities is None:
        pivot_entities = {
            "event_ids": compact_unique(record.event_id for record in records),
            "channels": compact_unique(record.channel for record in records),
            "computers": compact_unique(record.computer for record in records),
            "user_sids": compact_unique(record.user_sid for record in records),
            "process_paths": compact_unique(_extract_evtx_process_paths(records)),
        }
    return build_contract_response(
        response,
        case_id=_case_id(),
        execution_id=response.get("execution_id"),
        state_manager=_state,
        audit_logger=_audit,
        tool_name="disk.summarize_evtx",
        summary=(
            f"EVTX summarization returned {response.get('records_count', len(records))} rows "
            f"from {evtx_dir}. Channel filter: {response.get('channel_filter') or 'all'}."
        ),
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="disk.summarize_evtx",
            execution_id=response.get("execution_id"),
            raw_command=response.get("raw_command"),
            state_path=state_path_for_manager(_state),
            csv_path=csv_path or None,
            cache_hit=response.get("cache_hit"),
            cache_source_execution_id=response.get("cache_source_execution_id"),
            artifact_paths=[evtx_dir],
        ),
        pivot_entities=pivot_entities,
        follow_up_options=[
            build_follow_up_option(
                "extract_prefetch",
                reason="Confirm binaries referenced in 4688/Sysmon process events.",
                parameters={"image_path": image_path},
            ),
            build_follow_up_option(
                "get_amcache",
                reason="Pivot from event log process names into hash-backed execution evidence.",
                parameters={"image_path": image_path},
            ),
            build_follow_up_option(
                "extract_registry_run_keys",
                reason="Check whether suspicious services or scheduled tasks are also persisted in registry ASEPs.",
                parameters={"image_path": image_path},
            ),
        ],
        preview=[
            {"channel": channel, "count": count}
            for channel, count in sorted(channel_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        evidence_excerpt=evidence_excerpt,
        handle=build_handle(
            kind="csv",
            path=csv_path,
            description="Persisted EvtxECmd CSV output.",
            tool_name="disk.summarize_evtx",
        ) if csv_path else None,
        query_constraints={
            "start_date": response.get("date_range", {}).get("start") if isinstance(response.get("date_range"), dict) else None,
            "end_date": response.get("date_range", {}).get("end") if isinstance(response.get("date_range"), dict) else None,
            "channel": response.get("channel_filter"),
            "event_ids": response.get("event_id_filter"),
        },
    )


def _registry_contract_payload(
    *,
    response: dict[str, Any],
    records: list[RegistryRunKey],
    image_path: str,
    hive_dir: str,
    csv_path: Optional[str],
    suppressed_csv_path: Optional[str],
) -> dict[str, Any]:
    normalized = [
        {
            "hive": record.hive,
            "key_path": record.key_path,
            "value_name": record.value_name,
            "persistence_type": record.persistence_type,
        }
        for record in records[:20]
    ]
    follow_up_options = [
        build_follow_up_option(
            "extract_prefetch",
            reason="Correlate registry ASEPs with execution evidence.",
            parameters={"image_path": image_path},
        ),
        build_follow_up_option(
            "get_amcache",
            reason="Pivot from persisted targets into hash-backed execution records.",
            parameters={"image_path": image_path},
        ),
        build_follow_up_option(
            "summarize_evtx",
            reason="Correlate persistence mechanisms with service, task, and process events.",
            parameters={"image_path": image_path, "event_ids": "4688,4698,7045"},
        ),
    ]
    return build_contract_response(
        response,
        case_id=_case_id(),
        execution_id=response.get("execution_id"),
        state_manager=_state,
        audit_logger=_audit,
        tool_name="disk.extract_registry_run_keys",
        summary=(
            f"Registry persistence extraction returned {response.get('records_count', len(records))} rows "
            f"from {hive_dir}. Persisted main CSV{' available' if csv_path else ' unavailable'}."
        ),
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="disk.extract_registry_run_keys",
            execution_id=response.get("execution_id"),
            raw_command=response.get("raw_command"),
            state_path=state_path_for_manager(_state),
            csv_path=csv_path,
            cache_hit=response.get("cache_hit"),
            cache_source_execution_id=response.get("cache_source_execution_id"),
            artifact_paths=[hive_dir, suppressed_csv_path] if suppressed_csv_path else [hive_dir],
        ),
        pivot_entities={
            "persistence_types": compact_unique(record.persistence_type for record in records),
            "registry_paths": compact_unique(record.key_path for record in records),
            "value_names": compact_unique(record.value_name for record in records),
            "targets": compact_unique(record.value_data for record in records),
        },
        follow_up_options=follow_up_options,
        handle=build_handle(
            kind="csv",
            path=csv_path,
            description="Persisted grouped registry persistence dataset.",
            tool_name="disk.extract_registry_run_keys",
        ) if csv_path else None,
    )


# Canonical hive-replay lives in tools/_hive_replay.py (shared with shimcache /
# SRUM in server.py). Aliased here so existing call sites keep working.
from sift_mcp.tools._hive_replay import replay_hive_with_rla as _replay_hive_with_rla


def _not_initialised(tool_name: str) -> dict[str, Any]:
    """Return a standardised error response for uninitialised singletons."""
    return {
        "tool_name": tool_name,
        "status": "error",
        "error_message": "Tools not initialised. Call init_tools() first.",
        "data": [],
        "findings_created": [],
        "execution_id": None,
        "raw_command": None,
    }


def _runner_error(tool_name: str, exc: Exception, execution_id: Optional[str] = None) -> dict[str, Any]:
    """Return a standardised error response for runner failures."""
    return {
        "tool_name": tool_name,
        "status": "error",
        "error_message": f"Runner error: {exc}",
        "data": [],
        "findings_created": [],
        "execution_id": execution_id,
        "raw_command": str(exc),
        "stderr": "",
    }


# ---------------------------------------------------------------------------
# MFT streaming-summary bounds (memory-safety; review 2026-06-03).
# extract_mft_timeline previously did _read_csv (whole $MFT CSV -> list[dict])
# + _build_mft_records (parallel list[MftEntry]) -- the same full-materialization
# pattern that OOM-killed the server on a large EVTX CSV. A busy / DC-scale $MFT
# is the highest residual crash twin. We stream the CSV in one pass, create the
# per-entry timestomping findings INLINE (depth preserved exactly), and retain
# only bounded aggregates + a head sample. Individual timestomping findings are
# capped (state-bloat safety) with an aggregate-overflow finding + a truncation
# flag; the candidate COUNT is always exact.
# ---------------------------------------------------------------------------
_MFT_SAMPLE_CAP = 500            # hard cap on retained MftEntry sample (inline + memory)
_MFT_PIVOT_CAP = 64              # first-seen dedup cap per pivot dim (>> compact_unique limit 10)
_MFT_TIMESTOMP_FINDING_CAP = 1000  # max individual timestomping Findings persisted; overflow -> 1 aggregate


def _iter_csv_rows(csv_path: str):
    """Yield EZ-tool CSV rows one dict at a time (streaming; never materializes
    the whole file). NUL-stripped per line; field-size limit raised for wide
    payloads. Yields nothing if the file is absent / empty / unreadable.
    """
    p = Path(csv_path)
    try:
        if not p.exists() or p.stat().st_size == 0:
            return
    except OSError:
        return
    try:
        csv.field_size_limit(_EVTX_CSV_FIELD_LIMIT)
    except (OverflowError, ValueError):
        try:
            csv.field_size_limit(2**31 - 1)
        except (OverflowError, ValueError):
            pass
    try:
        with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for row in csv.DictReader(_nul_stripped(fh)):
                yield row
    except OSError:
        return


def _mft_entry_from_row(row: dict[str, str]) -> Optional[MftEntry]:
    """Parse one MFTECmd CSV row into an MftEntry (shared by _build_mft_records
    and the streaming summary, so sample records are byte-identical). Returns
    None on parse failure (preserving the legacy per-row skip semantics).
    """
    try:
        entry_num_raw = row.get("EntryNumber") or row.get("MFTEntry") or "0"
        try:
            entry_num = int(entry_num_raw)
        except (ValueError, TypeError):
            entry_num = 0

        seq_raw = row.get("SequenceNumber") or row.get("Sequence") or ""
        try:
            sequence = int(seq_raw) if seq_raw.strip() else None
        except (ValueError, TypeError):
            sequence = None

        file_path_val = (
            row.get("FileName") or row.get("FilePath") or row.get("ParentPath") or ""
        ).strip()

        si_created = _parse_dt(row.get("Created0x10") or row.get("SICreated") or "")
        si_modified = _parse_dt(row.get("LastModified0x10") or row.get("SIModified") or "")
        si_accessed = _parse_dt(row.get("LastAccess0x10") or row.get("SIAccessed") or "")
        si_entry_mod = _parse_dt(
            row.get("MFTRecordChange0x10") or row.get("SIEntryModified") or "")

        fn_created = _parse_dt(row.get("Created0x30") or row.get("FNCreated") or "")
        fn_modified = _parse_dt(row.get("LastModified0x30") or row.get("FNModified") or "")
        fn_accessed = _parse_dt(row.get("LastAccess0x30") or row.get("FNAccessed") or "")
        fn_entry_mod = _parse_dt(
            row.get("MFTRecordChange0x30") or row.get("FNEntryModified") or "")

        is_deleted = (row.get("InUse") or row.get("IsDeleted") or "").strip().lower() in (
            "false", "0", "no", "deleted",
        )
        is_dir = (row.get("IsDirectory") or row.get("IsDir") or "").strip().lower() in (
            "true", "1", "yes",
        )

        size_raw = row.get("FileSize") or row.get("LogicalSize") or ""
        try:
            file_size = int(size_raw) if size_raw.strip() else None
        except (ValueError, TypeError):
            file_size = None

        parent_raw = row.get("ParentEntryNumber") or row.get("ParentMFTEntry") or ""
        try:
            parent_entry = int(parent_raw) if parent_raw.strip() else None
        except (ValueError, TypeError):
            parent_entry = None

        return MftEntry(
            entry_number=entry_num,
            sequence=sequence,
            file_path=file_path_val or None,
            si_created=si_created,
            si_modified=si_modified,
            si_accessed=si_accessed,
            si_entry_modified=si_entry_mod,
            fn_created=fn_created,
            fn_modified=fn_modified,
            fn_accessed=fn_accessed,
            fn_entry_modified=fn_entry_mod,
            is_deleted=is_deleted,
            is_directory=is_dir,
            file_size=file_size,
            parent_entry=parent_entry,
        )
    except Exception:
        return None


def _mft_timestomping_finding(
    entry: MftEntry, *, mft_path: str, tool: str, execution_id: str
) -> Finding:
    """Build the exact per-entry timestomping Finding (T1070.006). Shared so the
    streaming path and the legacy path emit byte-identical findings."""
    file_path_val = entry.file_path or ""
    return Finding(
        case_id=_case_id(),
        finding_type="timestomping",
        artifact_type="disk",
        artifact_path=mft_path,
        artifact_offset=str(entry.entry_number),
        tool_name=tool,
        execution_id=execution_id,
        iteration=_current_iteration(),
        evidence_kind=EvidenceKind.OBSERVATION,
        finding_status=FindingStatus.ACTIVE,
        confidence=0.8,
        # Artifact event-time for find_temporal_clusters (Run 9 fix). Use $SI
        # created - the timestamp the attacker manipulated; $FN created is
        # preserved on disk but reflects file-creation, not the timestomping.
        timestamp_observed=entry.si_created,
        description=(
            f"Possible timestomping detected for MFT entry {entry.entry_number} "
            f"({file_path_val or 'unknown path'}). "
            f"$SI Created ({entry.si_created.isoformat()}) precedes "
            f"$FN Created ({entry.fn_created.isoformat()}), which is physically "
            "impossible on a normal write — SI timestamps may have been "
            "retroactively modified to evade timeline analysis."
        ),
        supporting_indicators=[
            f"si_created={entry.si_created.isoformat()}",
            f"fn_created={entry.fn_created.isoformat()}",
            f"mft_entry={entry.entry_number}",
            file_path_val or "",
        ],
        mitre_tactic="TA0005",
        mitre_technique="T1070.006",
    )


def _is_timestomp_candidate(entry: MftEntry) -> bool:
    return (
        entry.si_created is not None
        and entry.fn_created is not None
        and entry.si_created < entry.fn_created
    )


def _stream_mft_summary(
    csv_path: str,
    *,
    mft_path: str,
    tool: str,
    execution_id: str,
    create_findings: bool,
) -> dict[str, Any]:
    """Single streaming pass over an MFTECmd CSV. Memory-bounded replacement for
    _read_csv + _build_mft_records. Creates per-entry timestomping findings
    INLINE (preserving every candidate, capped at _MFT_TIMESTOMP_FINDING_CAP
    with an aggregate-overflow finding) while retaining only a bounded sample +
    full-scan capped pivots. timestomping_candidates is always the exact count.
    """
    raw_rows = 0
    timestomping_candidates = 0
    finding_ids: list[str] = []
    sample: list[MftEntry] = []
    earliest_si = None
    overflow_paths: list[str] = []   # a few example paths beyond the cap, for the aggregate
    pivot_paths: list[str] = []
    pivot_entries: list[int] = []
    pivot_timestamps: list[str] = []
    seen_path: set[str] = set()
    seen_entry: set[int] = set()
    seen_ts: set[str] = set()
    evidence_excerpt: Optional[str] = None

    def _add_capped(ordered: list, seen: set, value: Any, cap: int) -> None:
        if value is None or value in seen or len(ordered) >= cap:
            return
        seen.add(value)
        ordered.append(value)

    for row in _iter_csv_rows(csv_path):
        raw_rows += 1
        entry = _mft_entry_from_row(row)
        if entry is None:
            continue
        _add_capped(pivot_paths, seen_path, entry.file_path, _MFT_PIVOT_CAP)
        _add_capped(pivot_entries, seen_entry, entry.entry_number, _MFT_PIVOT_CAP)
        ts_val = _dt_to_iso(entry.fn_created) or _dt_to_iso(entry.si_created)
        _add_capped(pivot_timestamps, seen_ts, ts_val, _MFT_PIVOT_CAP)
        if len(sample) < _MFT_SAMPLE_CAP:
            sample.append(entry)
            if evidence_excerpt is None and entry.file_path:
                evidence_excerpt = entry.file_path
        if _is_timestomp_candidate(entry):
            timestomping_candidates += 1
            if earliest_si is None or entry.si_created < earliest_si:
                earliest_si = entry.si_created
            if create_findings and _state is not None:
                if len(finding_ids) < _MFT_TIMESTOMP_FINDING_CAP:
                    finding_ids.append(
                        _state.add_finding(
                            _mft_timestomping_finding(
                                entry, mft_path=mft_path, tool=tool,
                                execution_id=execution_id,
                            ).model_dump(mode="json")
                        )
                    )
                elif len(overflow_paths) < 10:
                    overflow_paths.append(entry.file_path or f"entry {entry.entry_number}")

    truncated = timestomping_candidates > len(finding_ids) if create_findings else False
    if create_findings and truncated and _state is not None:
        # One aggregate finding covers the candidates beyond the individual cap.
        # Stable group_key (no volatile F-ids in dedup material) so reruns dedup.
        not_recorded = timestomping_candidates - len(finding_ids)
        agg = Finding(
            case_id=_case_id(),
            finding_type="timestomping",
            artifact_type="disk",
            artifact_path=mft_path,
            tool_name=tool,
            execution_id=execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.8,
            timestamp_observed=earliest_si,
            description=(
                f"{timestomping_candidates} MFT entries show $SI Created preceding "
                f"$FN Created (possible timestomping, T1070.006). The first "
                f"{len(finding_ids)} are recorded as individual findings; the remaining "
                f"{not_recorded} are not individually recorded — analyze the full set via "
                f"run_analysis() over the persisted MFT CSV. Examples beyond the cap: "
                f"{', '.join(overflow_paths) or 'see CSV'}."
            ),
            supporting_indicators=[
                f"timestomping_candidates={timestomping_candidates}",
                f"individual_findings={len(finding_ids)}",
                f"not_individually_recorded={not_recorded}",
                "group_key=mft_timestomping_overflow",
            ],
            mitre_tactic="TA0005",
            mitre_technique="T1070.006",
        )
        finding_ids.append(_state.add_finding(agg.model_dump(mode="json")))

    return {
        "raw_rows": raw_rows,
        "timestomping_candidates": timestomping_candidates,
        "finding_ids": finding_ids,
        "timestomping_findings_truncated": truncated,
        "sample": sample,
        "pivot_paths": pivot_paths,
        "pivot_entries": pivot_entries,
        "pivot_timestamps": pivot_timestamps,
        "evidence_excerpt": evidence_excerpt,
    }


def _mft_contract_inputs(stream: dict[str, Any]):
    """Build (normalized_observations, pivot_entities) for the MFT contract from
    a streaming-summary result. Pivots are full-scan capped first-seen sets (not
    sample-derived), so depth matches the legacy path exactly."""
    sample = stream["sample"]
    normalized = [
        {
            "entry_number": record.entry_number,
            "file_path": record.file_path,
            "si_created": _dt_to_iso(record.si_created),
            "fn_created": _dt_to_iso(record.fn_created),
            "is_deleted": record.is_deleted,
        }
        for record in sample[:20]
    ]
    pivots = {
        "file_paths": compact_unique(stream["pivot_paths"]),
        "entry_numbers": compact_unique(stream["pivot_entries"]),
        "timestamps": compact_unique(stream["pivot_timestamps"]),
    }
    return normalized, pivots


def _build_mft_records(
    rows: list[dict[str, str]],
    *,
    mft_path: str,
    tool: str,
    execution_id: str,
    create_findings: bool,
) -> tuple[list[MftEntry], list[str], int]:
    """Parse MFTECmd rows into records and optional findings.

    Legacy materializing path, retained for back-compat and equivalence tests.
    extract_mft_timeline no longer calls this (it streams via _stream_mft_summary);
    the per-row parse + finding are shared via _mft_entry_from_row /
    _mft_timestomping_finding so outputs stay byte-identical.
    """
    records: list[MftEntry] = []
    finding_ids: list[str] = []
    timestomping_candidates = 0

    for row in rows:
        entry = _mft_entry_from_row(row)
        if entry is None:
            continue
        records.append(entry)
        if _is_timestomp_candidate(entry):
            timestomping_candidates += 1
            if create_findings and _state is not None:
                finding_ids.append(
                    _state.add_finding(
                        _mft_timestomping_finding(
                            entry, mft_path=mft_path, tool=tool,
                            execution_id=execution_id,
                        ).model_dump(mode="json")
                    )
                )

    return records, finding_ids, timestomping_candidates


# ---------------------------------------------------------------------------
# EVTX streaming-summary bounds (memory-safety; review 2026-06-02).
#
# summarize_evtx must stay memory-bounded on the SANS SIFT Workstation (the
# fixed target, ~8-16 GB RAM) REGARDLESS of how broad an --inc EID set the
# investigating agent requests. PowerShell ScriptBlock logging (4104/4103)
# embeds full script text and is extremely high-volume: a busy host can emit a
# multi-GB / multi-million-row EvtxECmd CSV. Materializing that CSV into a
# Python list[dict] + a parallel list[EventRecord] (the legacy path) balloons
# RSS to >15 GB and triggers the OOM killer.
#
# Every analytical output summarize_evtx produces is bounded: a total count, a
# per-channel histogram, capped first-seen pivot sets (compact_unique only
# emits 10), a head sample for the contract, and one count-based finding. The
# real analyst depth lives in the PERSISTED CSV (csv_path), mined on demand via
# run_analysis -- it is untouched by these bounds. So we compute the full-scan
# aggregates in a SINGLE streaming pass and retain only a bounded sample.
# ---------------------------------------------------------------------------
_EVTX_SAMPLE_CAP = 500            # hard cap on retained EventRecord sample (inline + memory)
_EVTX_PIVOT_CAP = 64              # first-seen dedup cap per pivot dim (>> compact_unique limit 10)
_EVTX_PROCESS_PATH_CAP = 5000     # dedup cap for 4688/Sysmon process paths (promotion + pivot)
_EVTX_WIDE_FIELD_MAX_CHARS = 1024  # truncate retained extra_field values (kills 4104 heap blow-up)
# csv field-size limit must exceed a single 4104 ScriptBlockText payload, or
# csv.reader raises "field larger than field limit" and silently drops the row.
_EVTX_CSV_FIELD_LIMIT = 64 * 1024 * 1024  # 64 MiB per field
# extra_fields columns dropped from the RETAINED sample only (full values stay
# in the CSV). Normalized (lowercase, no spaces/underscores) for matching.
_EVTX_WIDE_FIELD_DROP = frozenset({
    "scriptblocktext",
    "payloaddata2", "payloaddata3", "payloaddata4",
    "payloaddata5", "payloaddata6",
})
_EVTX_SKIP_COLS = frozenset({
    "EventId", "EventID", "Id", "Channel", "EventChannel",
    "TimeCreated", "Timestamp", "Date/Time - UTC",
    "PayloadData1", "MapDescription", "UserData", "Message",
    "Computer", "UserSID", "UserId", "Level",
    "Provider", "ProviderName", "SourceName",
})
_EVTX_PROCESS_KEYS = (
    "newprocessname", "processname", "imagename", "image",
    "application", "commandline", "processpath",
)
_EVTX_PATH_RE = re.compile(
    r"[A-Za-z]:\\[^\"'\r\n]+\.(?:exe|dll|cmd|bat|ps1|vbs)", re.IGNORECASE
)


def _evtx_record_from_row(
    row: dict[str, str],
    channel: Optional[str],
    *,
    truncate_wide: bool = False,
) -> Optional[EventRecord]:
    """Build one EventRecord from an EvtxECmd CSV row.

    Shared by the streaming summary (``_stream_evtx_summary``) and the legacy
    ``_build_evtx_records`` so a retained sample record is byte-identical to the
    legacy record EXCEPT for optional wide-field truncation. Returns ``None``
    when the row is filtered out by *channel* or cannot be parsed.

    When *truncate_wide* is True, known-wide payload columns
    (``ScriptBlockText``, ``PayloadData2..N``) are dropped and any remaining
    field longer than ``_EVTX_WIDE_FIELD_MAX_CHARS`` is truncated, so retaining
    a bounded sample of PowerShell-heavy 4104 rows cannot blow up RSS. The full
    untruncated values remain in the persisted CSV.
    """
    try:
        ch = (row.get("Channel") or row.get("EventChannel") or "").strip()
        if channel and ch.lower() != channel.lower():
            return None

        event_id_raw = row.get("EventId") or row.get("EventID") or row.get("Id") or "0"
        try:
            event_id = int(event_id_raw)
        except (ValueError, TypeError):
            event_id = 0

        ts = _parse_dt(
            row.get("TimeCreated") or row.get("Timestamp") or row.get("Date/Time - UTC") or ""
        )
        if ts is None:
            ts = datetime.now(tz=timezone.utc)

        message = (
            row.get("PayloadData1")
            or row.get("MapDescription")
            or row.get("UserData")
            or row.get("Message")
            or f"Event ID {event_id}"
        ).strip()[:500]

        extra: dict[str, Any] = {}
        for k, v in row.items():
            if k in _EVTX_SKIP_COLS or not v or not v.strip():
                continue
            if truncate_wide:
                kn = k.lower().replace(" ", "").replace("_", "")
                if kn in _EVTX_WIDE_FIELD_DROP:
                    continue
                if len(v) > _EVTX_WIDE_FIELD_MAX_CHARS:
                    v = v[:_EVTX_WIDE_FIELD_MAX_CHARS] + "...[truncated]"
            extra[k] = v

        return EventRecord(
            event_id=event_id,
            channel=ch or "Unknown",
            provider=(
                row.get("Provider") or row.get("ProviderName") or row.get("SourceName") or None
            ),
            timestamp=ts,
            level=row.get("Level") or row.get("LevelDisplayName") or None,
            computer=row.get("Computer") or None,
            user_sid=(row.get("UserSID") or row.get("UserId") or None),
            message_summary=message or f"Event {event_id}",
            raw_xml_ref=None,
            extra_fields=extra,
        )
    except Exception:
        return None


def _evtx_paths_from_record(record: EventRecord) -> list[str]:
    """Extract candidate process paths from one 4688 / Sysmon-1 EventRecord."""
    if record.event_id not in {1, 4688}:
        return []
    candidates: list[str] = []
    for key, value in record.extra_fields.items():
        key_norm = key.lower().replace(" ", "").replace("_", "")
        text = str(value or "").strip()
        if not text:
            continue
        if any(name in key_norm for name in _EVTX_PROCESS_KEYS):
            match = _EVTX_PATH_RE.search(text)
            candidates.append(match.group(0) if match else text)
    if not record.extra_fields:
        candidates.extend(_EVTX_PATH_RE.findall(record.message_summary))
    return [candidate for candidate in candidates if candidate]


def _nul_stripped(fh: "io.TextIOBase"):
    """Yield lines with embedded NULs removed (EvtxECmd CSVs can carry them).

    Wrapping the file object preserves csv.reader's ability to read across
    physical lines for quoted multi-line fields (e.g. 4104 ScriptBlockText).
    """
    for line in fh:
        yield line.replace("\x00", "")


def _stream_evtx_summary(
    csv_path: str,
    *,
    channel: Optional[str] = None,
) -> dict[str, Any]:
    """Single streaming pass over an EvtxECmd CSV producing bounded aggregates.

    Replaces ``_read_csv`` + ``_build_evtx_records`` for summarize_evtx so RSS
    stays flat regardless of CSV size. Computes the FULL-scan aggregates the
    contract needs (total count, per-channel histogram, first-seen pivot sets,
    deduped process paths) plus a bounded head sample. The full per-row data is
    never materialized.

    Returns a dict with: ``total_records``, ``channel_counts`` (full histogram),
    ``pivot_event_ids`` / ``pivot_channels`` / ``pivot_computers`` /
    ``pivot_user_sids`` (first-seen, capped), ``process_paths`` (deduped,
    capped), ``sample`` (list[EventRecord], wide fields truncated),
    ``evidence_excerpt``.
    """
    total = 0          # channel-MATCHED + parsed rows (what records_count derives from)
    raw_rows = 0       # EVERY CSV data row read (== legacy len(_read_csv())); == total when channel=None
    channel_counts: dict[str, int] = {}
    pivot_event_ids: list[int] = []
    pivot_channels: list[str] = []
    pivot_computers: list[str] = []
    pivot_user_sids: list[str] = []
    process_paths: list[str] = []
    seen_eid: set[int] = set()
    seen_ch: set[str] = set()
    seen_comp: set[str] = set()
    seen_sid: set[str] = set()
    seen_path: set[str] = set()
    sample: list[EventRecord] = []
    evidence_excerpt: Optional[str] = None

    def _add_capped(ordered: list, seen: set, value: Any, cap: int) -> None:
        if value is None or value in seen or len(ordered) >= cap:
            return
        seen.add(value)
        ordered.append(value)

    empty = {
        "total_records": 0,
        "raw_rows": 0,
        "matched_records": 0,
        "channel_counts": {},
        "pivot_event_ids": [],
        "pivot_channels": [],
        "pivot_computers": [],
        "pivot_user_sids": [],
        "process_paths": [],
        "sample": [],
        "evidence_excerpt": None,
    }
    p = Path(csv_path)
    try:
        if not p.exists() or p.stat().st_size == 0:
            return empty
    except OSError:
        return empty

    try:
        csv.field_size_limit(_EVTX_CSV_FIELD_LIMIT)
    except (OverflowError, ValueError):
        try:
            csv.field_size_limit(2**31 - 1)
        except (OverflowError, ValueError):
            pass

    try:
        with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(_nul_stripped(fh))
            for row in reader:
                # raw_rows tracks the FULL CSV the csv_path handle contains
                # (legacy len(_read_csv())), counted before channel filtering so
                # total_records never understates the backing store.
                raw_rows += 1
                # Full (untruncated) record: transient -- used for aggregates +
                # path extraction, then discarded unless it joins the sample.
                rec = _evtx_record_from_row(row, channel, truncate_wide=False)
                if rec is None:
                    continue
                total += 1
                channel_counts[rec.channel] = channel_counts.get(rec.channel, 0) + 1
                _add_capped(pivot_event_ids, seen_eid, rec.event_id, _EVTX_PIVOT_CAP)
                _add_capped(pivot_channels, seen_ch, rec.channel, _EVTX_PIVOT_CAP)
                if rec.computer:
                    _add_capped(pivot_computers, seen_comp, rec.computer, _EVTX_PIVOT_CAP)
                if rec.user_sid:
                    _add_capped(pivot_user_sids, seen_sid, rec.user_sid, _EVTX_PIVOT_CAP)
                for path in _evtx_paths_from_record(rec):
                    _add_capped(process_paths, seen_path, path, _EVTX_PROCESS_PATH_CAP)
                if len(sample) < _EVTX_SAMPLE_CAP:
                    srec = _evtx_record_from_row(row, channel, truncate_wide=True)
                    if srec is not None:
                        sample.append(srec)
                        if evidence_excerpt is None and srec.message_summary:
                            evidence_excerpt = srec.message_summary
    except OSError:
        # Unreadable mid-stream: return whatever was accumulated rather than
        # raising (caller treats the partial summary as the result).
        pass

    return {
        # total_records = raw CSV rows (matches csv_path + legacy len(_read_csv()));
        # matched_records = channel-matched rows; equal when channel is None.
        "total_records": raw_rows,
        "raw_rows": raw_rows,
        "matched_records": total,
        "channel_counts": channel_counts,
        "pivot_event_ids": pivot_event_ids,
        "pivot_channels": pivot_channels,
        "pivot_computers": pivot_computers,
        "pivot_user_sids": pivot_user_sids,
        "process_paths": process_paths,
        "sample": sample,
        "evidence_excerpt": evidence_excerpt,
    }


def _evtx_summary_finding_ids(
    total_records: int,
    *,
    evtx_dir: str,
    channel: Optional[str],
    execution_id: str,
) -> list[str]:
    """Persist the single count-based EVTX summary finding (streaming path).

    Byte-identical to the finding the legacy _build_evtx_records produced with
    create_findings=True, but driven by the streamed total instead of a
    materialized record list. No finding when nothing parsed.
    """
    if not total_records or _state is None:
        return []
    finding = Finding(
        case_id=_case_id(),
        finding_type="other",
        artifact_type="disk",
        artifact_path=evtx_dir,
        tool_name="disk.summarize_evtx",
        execution_id=execution_id,
        iteration=_current_iteration(),
        evidence_kind=EvidenceKind.OBSERVATION,
        finding_status=FindingStatus.ACTIVE,
        confidence=0.9,
        description=(
            f"Parsed {total_records} event log entries from {evtx_dir}"
            + (f" (channel filter: {channel})" if channel else "")
            + ". Events may reveal logon activity, process creation, service "
            "installation, and other attacker behaviours."
        ),
        supporting_indicators=[evtx_dir],
    )
    return [_state.add_finding(finding.model_dump(mode="json"))]


def _evtx_contract_inputs(
    stream: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build the (normalized_observations, pivot_entities) the EVTX contract
    needs from a streaming-summary result. Pivots use the FULL-scan capped
    first-seen sets (not the sample) so depth matches the legacy path exactly.
    """
    sample = stream["sample"]
    normalized = [
        {
            "event_id": record.event_id,
            "channel": record.channel,
            "timestamp": _dt_to_iso(record.timestamp),
            "computer": record.computer,
            "provider": record.provider,
        }
        for record in sample[:20]
    ]
    pivots = {
        "event_ids": compact_unique(stream["pivot_event_ids"]),
        "channels": compact_unique(stream["pivot_channels"]),
        "computers": compact_unique(stream["pivot_computers"]),
        "user_sids": compact_unique(stream["pivot_user_sids"]),
        "process_paths": compact_unique(stream["process_paths"]),
    }
    return normalized, pivots


def _build_evtx_records(
    rows: list[dict[str, str]],
    *,
    evtx_dir: str,
    channel: Optional[str],
    tool: str,
    execution_id: str,
    create_findings: bool,
) -> tuple[list[EventRecord], list[str]]:
    """Parse EvtxECmd rows into records and optional summary finding.

    Legacy materializing path, retained for back-compat and direct unit tests.
    summarize_evtx no longer calls this (it streams via _stream_evtx_summary);
    the per-row parse is shared via _evtx_record_from_row.
    """
    records: list[EventRecord] = []

    for row in rows:
        rec = _evtx_record_from_row(row, channel)
        if rec is not None:
            records.append(rec)

    finding_ids: list[str] = []
    if records and create_findings and _state is not None:
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="disk",
            artifact_path=evtx_dir,
            tool_name=tool,
            execution_id=execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=(
                f"Parsed {len(records)} event log entries from {evtx_dir}"
                + (f" (channel filter: {channel})" if channel else "")
                + ". Events may reveal logon activity, process creation, service "
                "installation, and other attacker behaviours."
            ),
            supporting_indicators=[evtx_dir],
        )
        finding_ids.append(_state.add_finding(finding.model_dump(mode="json")))

    return records, finding_ids


def _extract_evtx_process_paths(records: list[EventRecord]) -> list[str]:
    """Extract candidate process paths from 4688 / Sysmon-1 style events."""
    candidates: list[str] = []
    for record in records:
        candidates.extend(_evtx_paths_from_record(record))
    return candidates


def _build_registry_records(
    rows: list[dict[str, str]],
    *,
    tool: str,
    execution_id: str,
    batch_file_used: Optional[str],
    create_findings: bool,
) -> tuple[list[RegistryRunKey], list[str], dict[str, int], dict[str, Any]]:
    """Parse RECmd rows into records and grouped high-signal persistence findings.

    Returns (records, finding_ids, persistence_type_counts, grouping_meta).
    grouping_meta carries suppression_summary, grouping_context,
    promoted_group_count, and suppressed_group_count for the response.
    """
    records: list[RegistryRunKey] = []
    persistence_type_counts: dict[str, int] = {}

    # --- Phase 1: parse all rows into RegistryRunKey records ---
    for row in rows:
        try:
            key_path = (row.get("KeyPath") or row.get("Path") or "").strip()
            if not key_path:
                continue

            ptype = _classify_persistence(key_path)
            if ptype is None:
                if batch_file_used:
                    batch_cat = (row.get("Category") or "").strip()
                    ptype = batch_cat.lower().replace(" ", "_") if batch_cat else "other"
                else:
                    continue

            value_name = (row.get("ValueName")
                          or row.get("Name") or "").strip()
            value_data = (row.get("ValueData") or row.get(
                "Data") or row.get("Value") or "").strip()
            if not value_data:
                continue

            hive_name = (row.get("HiveType") or row.get(
                "Hive") or Path(key_path).name).strip()
            record = RegistryRunKey(
                hive=hive_name,
                key_path=key_path,
                value_name=value_name or "(Default)",
                value_data=value_data,
                last_write_time=_parse_dt(
                    row.get("LastWriteTimestamp") or row.get(
                        "LastWriteTime") or ""
                ),
                persistence_type=ptype,  # type: ignore[arg-type]
            )
            records.append(record)
            persistence_type_counts[ptype] = persistence_type_counts.get(
                ptype, 0) + 1
        except Exception:
            continue

    # --- Phase 2: group and promote narrowly ---
    finding_ids: list[str] = []
    grouping_meta = _group_and_promote_registry(
        records,
        tool=tool,
        execution_id=execution_id,
        create_findings=create_findings,
        finding_ids_out=finding_ids,
    )

    return records, finding_ids, persistence_type_counts, grouping_meta


# ---------------------------------------------------------------------------
# Registry grouping / promotion helpers  (One-Shot Quality Recovery)
# ---------------------------------------------------------------------------

_USER_WRITABLE_PREFIXES = (
    "\\users\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "\\recycle.bin\\",
    "\\perflogs\\",
)

_SYSTEM_PREFIXES = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
)

_INTERPRETER_BASENAMES = frozenset({
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
})

# ASEP classes that ALWAYS promote (no path filtering)
_ALWAYS_PROMOTE_CLASSES = frozenset({
    "winlogon_shell",
    "winlogon_userinit",
    "appinit_dlls",
    "lsa_package",
    "credential_provider",
    "ifeo",
    "active_setup",
    "bootexecute",
    "print_monitor",
})

# ASEP classes that need path-based filtering
_RUN_KEY_CLASSES = frozenset({"run", "runonce", "runservices"})


def _extract_target_path(value_data: str) -> str:
    """Extract the executable target from a registry value data string."""
    text = value_data.strip().strip('"').strip("'")
    # Handle paths with arguments: "C:\path\binary.exe -arg" -> C:\path\binary.exe
    parts = re.split(r'\s+(?=-|/)', text, maxsplit=1)
    return parts[0].strip().strip('"').strip("'")


def _normalize_target_for_grouping(value_data: str) -> str:
    """Return a lowercase normalized target path for group_key construction."""
    target = _extract_target_path(value_data).lower()
    # Strip drive letter if present (C:\... -> \...)
    if len(target) >= 2 and target[1] == ':':
        target = target[2:]
    return target or value_data[:80].lower()


def _is_user_writable_path(target: str) -> bool:
    lower = target.lower()
    return any(prefix in lower for prefix in _USER_WRITABLE_PREFIXES)


def _is_system_path(target: str) -> bool:
    lower = target.lower()
    return any(prefix in lower for prefix in _SYSTEM_PREFIXES)


def _is_interpreter_target(target: str) -> bool:
    # Handle Windows-style backslash paths on Linux
    basename = target.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower().strip()
    return basename in _INTERPRETER_BASENAMES


def _classify_promotion_reason(
    ptype: str,
    target: str,
    support_count: int,
) -> Optional[str]:
    """Return the promotion_reason if the group qualifies, else None."""
    ptype_lower = ptype.lower()

    # Always-promote classes
    if ptype_lower in _ALWAYS_PROMOTE_CLASSES:
        return "rare_autostart_class"

    # Run/RunOnce/RunServices: conditional
    if ptype_lower in _RUN_KEY_CLASSES:
        if _is_user_writable_path(target):
            return "user_writable_target"
        if _is_interpreter_target(target):
            return "interpreter_target"
        if not target or target == "(default)":
            return "missing_or_unparsed_target"
        if support_count > 1:
            return "duplicate_persistence_target"
        return None

    # Services: conditional
    if ptype_lower == "services":
        if _is_user_writable_path(target):
            return "user_writable_target"
        if _is_interpreter_target(target):
            return "interpreter_target"
        if not _is_system_path(target) and support_count > 1:
            return "non_system_service_target"
        return None

    # Other persistence classes: no auto-promote
    return None


def _mitre_technique_for_ptype(ptype: str) -> str:
    ptype_lower = ptype.lower()
    if ptype_lower in ("run", "runonce"):
        return "T1547.001"
    if ptype_lower == "appinit_dlls":
        return "T1546.010"
    if ptype_lower in ("winlogon_shell", "winlogon_userinit"):
        return "T1547.004"
    if ptype_lower == "services":
        return "T1543.003"
    if ptype_lower == "lsa_package":
        return "T1547.005"
    if ptype_lower == "bootexecute":
        return "T1547.012"
    if ptype_lower == "ifeo":
        return "T1546.012"
    if ptype_lower == "active_setup":
        return "T1547.014"
    if ptype_lower == "print_monitor":
        return "T1547.003"
    if ptype_lower == "credential_provider":
        return "T1547.002"
    return "T1547"


def _group_and_promote_registry(
    records: list[RegistryRunKey],
    *,
    tool: str,
    execution_id: str,
    create_findings: bool,
    finding_ids_out: list[str],
) -> dict[str, Any]:
    """Group registry records and promote only high-signal candidates into findings.

    Returns grouping_meta dict with suppression_summary, grouping_context,
    promoted_group_count, suppressed_group_count.
    """
    from collections import defaultdict

    # Eligible persistence types for grouping/promotion consideration
    eligible_types = _ALWAYS_PROMOTE_CLASSES | _RUN_KEY_CLASSES | {"services"}

    # Group by (persistence_type, normalized_target)
    groups: dict[str, list[RegistryRunKey]] = defaultdict(list)
    for record in records:
        ptype = str(record.persistence_type or "").lower()
        if ptype not in eligible_types:
            continue
        target = _normalize_target_for_grouping(record.value_data)
        group_key = f"registry:{ptype}:{target}"
        groups[group_key].append(record)

    promoted_groups: list[dict[str, Any]] = []
    suppressed_groups: list[dict[str, Any]] = []
    suppressed_rows: list[dict[str, Any]] = []

    for group_key, group_records in groups.items():
        ptype = str(group_records[0].persistence_type or "").lower()
        target = _normalize_target_for_grouping(group_records[0].value_data)
        support_count = len(group_records)

        reason = _classify_promotion_reason(ptype, target, support_count)
        if reason is None:
            suppressed_groups.append({
                "group_key": group_key,
                "persistence_type": ptype,
                "target": target,
                "support_count": support_count,
            })
            suppressed_rows.extend(
                record.model_dump(mode="json")
                for record in group_records
            )
            continue

        promoted_groups.append({
            "group_key": group_key,
            "persistence_type": ptype,
            "target": target,
            "support_count": support_count,
            "promotion_reason": reason,
        })

        if create_findings and _state is not None:
            representative = group_records[0]
            mitre_tech = _mitre_technique_for_ptype(ptype)
            sample_values = "; ".join(
                f"{r.value_name}={r.value_data[:80]}"
                for r in group_records[:3]
            )
            finding = Finding(
                case_id=_case_id(),
                finding_type="persistence",
                artifact_type="disk",
                artifact_path=representative.key_path,
                tool_name=tool,
                execution_id=execution_id,
                iteration=_current_iteration(),
                evidence_kind=EvidenceKind.OBSERVATION,
                finding_status=FindingStatus.ACTIVE,
                confidence=0.85,
                description=(
                    f"Registry persistence group ({ptype}): "
                    f"{support_count} row(s) targeting {target[:120]}. "
                    f"Samples: {sample_values[:200]}. "
                    f"Promotion: {reason}."
                ),
                supporting_indicators=[
                    representative.key_path,
                    f"target={target[:200]}",
                    f"support_count={support_count}",
                ],
                mitre_tactic="TA0003",
                mitre_technique=mitre_tech,
                group_key=group_key,
                support_count=support_count,
                promotion_reason=reason,
            )
            finding_ids_out.append(
                _state.add_finding(finding.model_dump(mode="json"))
            )

    grouping_context = {
        "promoted": promoted_groups,
        "suppressed_sample": suppressed_groups[:10],
        "total_eligible_records": sum(len(g) for g in groups.values()),
    }
    suppression_summary = {
        "total_registry_rows_parsed": len(records),
        "eligible_for_grouping": sum(len(g) for g in groups.values()),
        "total_groups": len(groups),
        "promoted_groups": len(promoted_groups),
        "suppressed_groups": len(suppressed_groups),
        "suppressed_rows": sum(g["support_count"] for g in suppressed_groups),
    }

    return {
        "suppression_summary": suppression_summary,
        "grouping_context": grouping_context,
        "promoted_group_count": len(promoted_groups),
        "suppressed_group_count": len(suppressed_groups),
        "suppressed_rows": suppressed_rows,
    }


# ---------------------------------------------------------------------------
# DFIR constants - case-agnostic, universally applicable
# ---------------------------------------------------------------------------

#: 26 universal Windows Event IDs that are relevant across ALL DFIR cases.
#: Defaulting to this set prevents context flooding from millions of
#: informational events while capturing the core attacker lifecycle.
DFIR_ESSENTIAL_EIDS: list[int] = [
    # Authentication & Logon (T1078)
    4624,   # Successful logon
    4625,   # Failed logon
    4634,   # Logoff
    4648,   # Explicit credential logon (runas, RDP)
    4672,   # Special privileges assigned (admin logon)
    # Account Management (T1136)
    4720,   # User account created
    4732,   # Member added to local group
    # Process Execution (T1059, T1204)
    4688,   # Process creation (requires audit policy)
    4689,   # Process exit
    # Service & Scheduled Task Persistence (T1543, T1053)
    7045,   # New service installed
    4698,   # Scheduled task created
    4702,   # Scheduled task updated
    # Object Access & Policy Changes
    4663,   # Attempt to access an object (file audit)
    4670,   # Permissions on an object changed
    4719,   # System audit policy changed
    # Logon Session Tracking
    4776,   # NTLM credential validation
    4768,   # Kerberos TGT requested
    4769,   # Kerberos service ticket requested
    # Lateral Movement Indicators (T1021)
    5140,   # Network share accessed
    5145,   # Detailed file share access
    # PowerShell (T1059.001)
    4103,   # PowerShell module logging
    4104,   # PowerShell script block logging
    # Windows Defender / AV (T1562.001)
    1116,   # Windows Defender detection
    1117,   # Windows Defender action taken
    # Sysmon (if available)
    1,      # Sysmon process creation
    3,      # Sysmon network connection
]

#: Common paths where RECmd DFIRBatch.reb may be found on SIFT Workstation.
#: Checked in order; the first existing path is used.
DFIR_BATCH_PATHS: list[str] = [
    "/opt/zimmermantools/RECmd/BatchExamples/DFIRBatch.reb",
    "/opt/zimmermantools/BatchExamples/DFIRBatch.reb",
    "/usr/local/share/zimmermantools/BatchExamples/DFIRBatch.reb",
]


# ---------------------------------------------------------------------------
# Tool: extract_prefetch
# ---------------------------------------------------------------------------

# Persistence-related keys to flag in registry scanning
_PERSISTENCE_KEY_PATTERNS = {
    "\\run\\": "run",
    "\\runonce\\": "runonce",
    "\\runservices\\": "run",
    "appinit_dlls": "appinit_dlls",
    "\\winlogon": "winlogon_shell",
    "userinit": "winlogon_userinit",
    "\\services\\": "services",
    "lsa": "lsa_package",
    "session manager": "session_manager",
    "browser helper": "browser_helper",
    "credential provider": "credential_provider",
    "shelliconoverlayidentifiers": "shell_extension",
    "shellserviceobjectdelayload": "shell_extension",
}


def extract_prefetch(
    image_path: str,
    prefetch_dir: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
    response_format: str = "summary",
) -> dict[str, Any]:
    """Extract Windows Prefetch execution evidence on Linux with `pyscca`.

    Prefetch files (``.pf``) are stored in ``C:\\Windows\\Prefetch`` and
    record up to 8 execution timestamps plus the list of files referenced
    during the binary's first seconds. Exact recent execution history is
    surfaced in ``last_run_times``. Separate `.pf` file metadata is returned
    as ``pf_created_time`` / ``pf_modified_time`` when it can be sourced from
    durable MFT output or mounted NTFS-backed filesystem metadata.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image (``.E01``, ``.dd``, ``.raw``).
        Used to derive the default Prefetch directory path if *prefetch_dir*
        is not given.
    prefetch_dir:
        Absolute path to the mounted Prefetch directory on the evidence image
        (e.g. ``/cases/SRL-2018/evidence/mnt/C/Windows/Prefetch``).
        When ``None``, a default path is constructed from the image path.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of PrefetchRecord dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``.
    """
    tool = "disk.extract_prefetch"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)

    prefetch_dir = _resolve_prefetch_dir_input(image_path, prefetch_dir)
    resolved_prefetch_dir = _resolved_path_str(prefetch_dir)
    if _unsafe_runtime_tmp_input(resolved_prefetch_dir):
        return _unsafe_path_error(
            tool,
            input_name="prefetch_dir",
            resolved_path=resolved_prefetch_dir,
            image_path=image_path,
        )
    if not Path(resolved_prefetch_dir).exists():
        return _path_missing_error(
            tool,
            input_name="prefetch_dir",
            resolved_path=resolved_prefetch_dir,
            image_path=image_path,
        )
    preflight = _preflight_artifact_persistence("prefetch", "prefetch.csv")
    if not preflight.get("ok"):
        return _artifact_preflight_error(tool_name=tool, preflight=preflight)

    # Use pyscca (libscca) - handles Windows 10 MAM-compressed .pf files on Linux
    # and exposes Prefetch-native run history without relying on Windows-only PECmd.
    records: list[PrefetchRecord] = []
    finding_ids: list[str] = []
    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = f"pyscca {resolved_prefetch_dir}/*.pf"
    _audit.log_execution(
        execution_id=exec_id,
        tool_name=tool,
        parameters={"prefetch_dir": resolved_prefetch_dir},
        command_line=raw_command,
    )

    try:
        import pyscca
    except ImportError:
        _audit.log_result(
            execution_id=exec_id,
            exit_code=1,
            duration=time.monotonic() - started_at,
            outputs_summary="pyscca not installed",
            finding_ids=[],
            tool_name=tool,
            command_line=raw_command,
            parameters={"prefetch_dir": resolved_prefetch_dir},
        )
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "pyscca not installed. Run: pip3 install libscca",
            "data": [], "findings_created": [], "records_count": 0,
        }

    pf_files = sorted(Path(resolved_prefetch_dir).glob("*.pf"))
    if max_entries > 0:
        pf_files = pf_files[:max_entries]

    for pf_file in pf_files:
        try:
            pf = pyscca.open(str(pf_file))
            exec_name = pf.executable_filename or pf_file.stem
            run_count = pf.run_count or 1

            last_run_times: list[datetime] = []
            for i in range(8):
                try:
                    rt = pf.get_last_run_time(i)
                    if rt and rt.year > 1970:
                        last_run_times.append(rt)
                except Exception:
                    break

            referenced_files: list[str] = []
            for i in range(pf.number_of_filenames):
                try:
                    referenced_files.append(pf.get_filename(i))
                except Exception:
                    pass

            record = PrefetchRecord(
                executable_name=exec_name,
                prefetch_path=str(pf_file),
                run_count=max(run_count, 1),
                last_run_times=last_run_times[:8],
                referenced_files=referenced_files[:50],
            )
            records.append(record)
        except Exception:
            continue

    _enrich_prefetch_records_with_filesystem_metadata(records)
    pf_timestamp_source_counts: dict[str, int] = {}
    for record in records:
        key = record.pf_timestamp_source or "unavailable"
        pf_timestamp_source_counts[key] = pf_timestamp_source_counts.get(key, 0) + 1

    # One summary finding for the whole batch - not one per .pf file
    if records:
        first_runs = sorted(
            [r for r in records if r.last_run_times],
            key=lambda r: r.last_run_times[0]
        )
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="disk",
            artifact_path=resolved_prefetch_dir,
            tool_name=tool,
            execution_id=exec_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.95,
            description=(
                f"Prefetch: parsed {len(records)} .pf files from {resolved_prefetch_dir}. "
                f"Binaries executed range: {first_runs[0].executable_name if first_runs else 'unknown'} "
                f"to {first_runs[-1].executable_name if first_runs else 'unknown'}. "
                "Use run_analysis() to identify suspicious execution patterns."
            ),
            supporting_indicators=[r.executable_name for r in records[:20]],
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)
        promote_corroborated_findings(
            _state,
            "prefetch",
            [record.executable_name for record in records if record.executable_name],
        )
    record_rows = [r.model_dump(mode="json") for r in records]
    persistent_csv = _persist_rows_as_csv(
        record_rows,
        tool_short_name="prefetch",
        filename="prefetch.csv",
    )
    durable_csv, artifact_persistence = _finalize_artifact_persistence(
        artifact_label="Prefetch CSV",
        persisted_path=persistent_csv,
        preflight=preflight,
    )
    response: dict[str, Any] = {
        "tool_name": tool,
        "status": "success" if durable_csv else "warning",
        "findings_created": finding_ids,
        "execution_id": exec_id,
        "raw_command": raw_command,
        "records_count": len(records),
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "response_format": normalized_format,
        "requires_agent": "@prefetch-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for multi-path execution, orphaned .pf files, "
            f"and suspicious binaries. {len(records)} total rows."
            if durable_csv
            else (
                "Analyze the returned Prefetch summary and rerun extract_prefetch after fixing "
                "artifact persistence to obtain a reusable handle for deeper pivots."
            )
        ),
    }
    _audit.log_result(
        execution_id=exec_id,
        exit_code=0,
        duration=time.monotonic() - started_at,
        outputs_summary=f"parsed {len(records)} prefetch records",
        finding_ids=finding_ids,
        tool_name=tool,
        command_line=raw_command,
        parameters={"prefetch_dir": resolved_prefetch_dir},
    )
    if normalized_format == "detailed":
        response["data"] = record_rows
    else:
        preview = record_rows[:10]
        response["preview"] = preview
        response["summary"] = (
            f"{len(records)} prefetch entries parsed from {prefetch_dir}. "
            f"`last_run_times` reflects exact Prefetch-native execution history; "
            f"`pf_created_time` / `pf_modified_time` are `.pf` file metadata. "
            f"Full data at {durable_csv or 'not persisted'}."
        )
        response["note"] = (
            'Full data array omitted by default; pass response_format="detailed" '
            "for the complete data."
        )
    response["pf_timestamp_source_counts"] = pf_timestamp_source_counts
    if not durable_csv:
        response["warning"] = (
            "Prefetch rows were parsed successfully, but the CSV output could not be persisted to "
            "a durable artifact path. Use the summary now and rerun after fixing OUTPUT_BASE to "
            "obtain a reusable handle."
        )
    response = _warn_if_empty(response, "extract_prefetch", prefetch_dir)
    return _prefetch_contract_payload(
        response=response,
        records=records,
        image_path=image_path,
        prefetch_dir=prefetch_dir,
        csv_path=durable_csv,
    )


# ---------------------------------------------------------------------------
# Tool: get_amcache
# ---------------------------------------------------------------------------


def get_amcache(
    image_path: str,
    hive_path: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
    response_format: str = "summary",
) -> dict[str, Any]:
    """Extract execution evidence from the Amcache.hve registry hive.

    Wraps ``dotnet /opt/zimmermantools/AmcacheParser.dll`` on SIFT Workstation.

    Amcache records the SHA-1 hash of every executed binary at first run.
    This hash persists even after the binary is deleted, enabling
    threat-intelligence lookups to identify malware.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image.  Used to derive the default
        Amcache.hve path if *hive_path* is not given.
    hive_path:
        Absolute path to the ``Amcache.hve`` file within the mounted evidence
        image (e.g. ``/cases/SRL-2018/evidence/mnt/C/Windows/appcompat/Programs/Amcache.hve``).
        When ``None``, a default path is constructed.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of AmcacheRecord dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``.
    """
    tool = "disk.get_amcache"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)
    if normalized_format is None:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "Invalid response_format. Use 'summary' or 'detailed'.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    hive_path = _resolve_amcache_hive_input(image_path, hive_path)
    resolved_hive_path = _resolved_path_str(hive_path)
    if _unsafe_runtime_tmp_input(resolved_hive_path):
        return _unsafe_path_error(
            tool,
            input_name="hive_path",
            resolved_path=resolved_hive_path,
            image_path=image_path,
        )
    if not Path(resolved_hive_path).exists():
        return _path_missing_error(
            tool,
            input_name="hive_path",
            resolved_path=resolved_hive_path,
            image_path=image_path,
        )
    preflight = _preflight_artifact_persistence(
        "amcache",
        "amcache_UnassociatedFileEntries.csv",
    )
    if not preflight.get("ok"):
        return _artifact_preflight_error(tool_name=tool, preflight=preflight)

    with tempfile.TemporaryDirectory(prefix="savvydfir_amcache_") as tmp_dir:
        csv_filename = "amcache.csv"
        # AmcacheParser outputs multiple CSVs with stem prefix:
        # amcache_UnassociatedFileEntries.csv is the execution evidence file
        csv_path = os.path.join(tmp_dir, "amcache_UnassociatedFileEntries.csv")

        try:
            result = _ez_runner.run_amcacheparser(
                hive_path=resolved_hive_path,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
                tool_name=tool,
            )
        except Exception as exc:
            return _runner_error(tool, exc)

        if not result.ok and not Path(csv_path).exists():
            return {
                "tool_name": tool,
                "status": "error",
                "error_message": (
                    f"AmcacheParser exited with code {result.exit_code}. "
                    f"stderr: {result.stderr[:300]}"
                ),
                "data": [],
                "findings_created": [],
                "execution_id": result.execution_id,
                "raw_command": result.command_line,
                "stderr": result.stderr,
            }

        rows = _read_csv(csv_path)
        persistent_csv = _persist_csv(csv_path, "amcache")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="Amcache CSV",
            persisted_path=persistent_csv,
            preflight=preflight,
        )

    records: list[AmcacheRecord] = []
    finding_ids: list[str] = []

    for row in rows:
        try:
            file_path_val = (
                row.get("FullPath") or row.get(
                    "FilePath") or row.get("Path") or ""
            ).strip()
            if not file_path_val:
                continue

            sha1 = (row.get("SHA1") or row.get("Sha1")
                    or row.get("Hash") or "").strip()
            if sha1.startswith("0000") and len(sha1) == 40:
                # Some AmcacheParser versions prefix SHA-1 with leading zeros from the key
                sha1 = sha1.lstrip("0") or sha1

            size_raw = row.get("FileSize") or row.get("Size") or ""
            try:
                file_size = int(size_raw) if size_raw.strip() else None
            except (ValueError, TypeError):
                file_size = None

            record = AmcacheRecord(
                file_path=file_path_val,
                sha1_hash=sha1 or None,
                file_size=file_size,
                publisher=row.get("Publisher") or row.get(
                    "CompanyName") or None,
                product_name=row.get("ProductName") or row.get(
                    "Product") or None,
                compile_time=_parse_dt(row.get("CompileTime") or row.get(
                    "PEHeaderCompileTime") or ""),
                install_time=_parse_dt(
                    row.get("InstallDate") or row.get("CreatedOn") or ""),
                last_modified=_parse_dt(row.get("LastModifiedDate") or row.get(
                    "KeyLastWriteTimestamp") or ""),
            )
            records.append(record)

        except Exception:
            continue

    # One summary finding for the whole batch - not one per Amcache entry
    if records:
        suspicious = [
            r for r in records
            if r.file_path and any(
                p in r.file_path.lower()
                for p in ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\public\\")
            )
        ]
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="disk",
            artifact_path=hive_path,
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=(
                f"Amcache: parsed {len(records)} execution records from {hive_path}. "
                + (f"{len(suspicious)} entries in suspicious paths (Temp/AppData/Downloads). " if suspicious else "")
                + "Use run_analysis() to pivot on SHA-1 hashes or filter by path."
            ),
            supporting_indicators=[
                r.file_path for r in suspicious[:10]] or [hive_path],
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)
        promote_corroborated_findings(
            _state,
            "amcache",
            [record.file_path for record in records if record.file_path],
        )

    if max_entries and max_entries > 0:
        records = records[:max_entries]
    response = {
        "tool_name": tool,
        "status": "success" if durable_csv else "warning",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
        "total_records": len(rows),
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "response_format": normalized_format,
        "note": (
            f"Returning {len(records)} of {len(rows)} total rows. Full CSV at {durable_csv}."
            if durable_csv
            else (
                f"Returning {len(records)} of {len(rows)} total rows. "
                "CSV persistence did not produce a durable analyst-facing handle; "
                "fix OUTPUT_BASE and rerun get_amcache before using run_analysis()."
            )
        ),
        "requires_agent": "@amcache-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for renamed malware, suspicious execution paths, and hash pivots. "
            f"{len(rows)} total rows."
            if durable_csv
            else (
                "Analyze the Amcache summary now, then rerun get_amcache after fixing artifact "
                "persistence to obtain a reusable handle for hash pivots."
            )
        ),
    }
    if normalized_format == "detailed":
        response["data"] = [r.model_dump(mode="json") for r in records]
    else:
        response["preview"] = [r.model_dump(mode="json") for r in records[:10]]
    if not durable_csv:
        response["warning"] = (
            "Amcache rows were parsed successfully, but the CSV output could not be persisted to "
            "a durable artifact path."
        )
    response = _warn_if_empty(response, "get_amcache", hive_path)
    return _amcache_contract_payload(
        response=response,
        records=records,
        image_path=image_path,
        hive_path=hive_path,
        csv_path=durable_csv,
    )


# ---------------------------------------------------------------------------
# Tool: extract_mft_timeline
# ---------------------------------------------------------------------------


def extract_mft_timeline(
    image_path: str,
    mft_path: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
    response_format: str = "summary",
    force_reparse: bool = False,
) -> dict[str, Any]:
    """Parse the NTFS Master File Table into a timestomping-aware timeline.

    Wraps ``dotnet /opt/zimmermantools/MFTECmd.dll`` on SIFT Workstation.

    Each MFT entry contains both ``$STANDARD_INFORMATION`` (SI) and
    ``$FILE_NAME`` (FN) timestamp sets.  SI timestamps can be modified at
    user level; FN timestamps require kernel access.  A discrepancy between
    SI and FN timestamps is a strong indicator of **timestomping**.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image.  Used to derive the default
        ``$MFT`` path if *mft_path* is not given.
    mft_path:
        Absolute path to the ``$MFT`` file within the mounted evidence image
        (e.g. ``/cases/SRL-2018/evidence/mnt/C/$MFT``).
        When ``None``, a default path is constructed.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of MftEntry dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``, ``timestomping_candidates`` (count of entries where
        SI Created < FN Created, suggesting retroactive timestamp modification).
    """
    tool = "disk.extract_mft_timeline"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)
    if normalized_format is None:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "Invalid response_format. Use 'summary' or 'detailed'.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    mft_path = _resolve_mft_path_input(image_path, mft_path)
    resolved_mft_path = _resolved_path_str(mft_path)
    if _unsafe_runtime_tmp_input(resolved_mft_path):
        return _unsafe_path_error(
            tool,
            input_name="mft_path",
            resolved_path=resolved_mft_path,
            image_path=image_path,
        )
    if not Path(resolved_mft_path).exists():
        return _path_missing_error(
            tool,
            input_name="mft_path",
            resolved_path=resolved_mft_path,
            image_path=image_path,
        )
    preflight = _preflight_artifact_persistence("mft", "mft_timeline.csv")
    if not preflight.get("ok"):
        return _artifact_preflight_error(tool_name=tool, preflight=preflight)

    cache_key = build_cache_key(tool, {"mft_path": resolved_mft_path})
    cached = get_valid_cached_artifact(
        _state,
        cache_key,
        path_key="csv_path",
        required_keys=("csv_path", "source_execution_id",
                       "timestomping_candidates"),
    )
    if cached is not None:
        cache_meta = record_cache_hit(
            _audit,
            _state,
            tool_name=tool,
            parameters={"mft_path": resolved_mft_path},
            cache_key=cache_key,
            artifact_path=str(cached["csv_path"]),
            cache_source_execution_id=str(
                cached.get("source_execution_id") or ""),
        )
        # Memory-bounded: stream the cached CSV (same helper as the fresh path).
        # create_findings=False -- the cached run already persisted the findings;
        # reuse cached["findings_created"] rather than re-creating them.
        stream = _stream_mft_summary(
            str(cached["csv_path"]),
            mft_path=mft_path,
            tool=tool,
            execution_id=cache_meta["execution_id"],
            create_findings=False,
        )
        total_records = stream["raw_rows"]
        timestomping_candidates = stream["timestomping_candidates"]
        cached_candidates = cached.get("timestomping_candidates")
        if cached_candidates is not None and cached_candidates != timestomping_candidates:
            # Recomputed count drifted from the cached value: surface, don't hide.
            log_warning = getattr(_audit, "log_warning", None)
            if callable(log_warning):
                log_warning(
                    tool,
                    f"cache-hit timestomping_candidates recompute ({timestomping_candidates}) "
                    f"!= cached ({cached_candidates}) for {cached['csv_path']}",
                )
        sample = stream["sample"]
        detailed_records = (
            sample[:max_entries] if (max_entries and max_entries > 0) else list(sample)
        )
        response = {
            "tool_name": tool,
            "status": "success",
            "findings_created": list(cached.get("findings_created", [])),
            "execution_id": cache_meta["execution_id"],
            "raw_command": cache_meta["raw_command"],
            "records_count": len(detailed_records),
            "total_records": total_records,
            "matched_records": total_records,
            "timestomping_candidates": timestomping_candidates,
            "data_truncated": total_records > len(detailed_records),
            "data_scope": "head_sample",
            "sample_cap": _MFT_SAMPLE_CAP,
            "csv_path": str(cached["csv_path"]),
            "note": (
                f"Returning a bounded sample of {len(detailed_records)} of {total_records} "
                f"MFT rows. Full CSV at {cached['csv_path']}."
            ),
            "requires_agent": cached.get("requires_agent", "@mft-analyst"),
            "agent_instruction": cached.get(
                "agent_instruction",
                f"Analyze {cached['csv_path']} for timestomping, attacker file drops, staging. {total_records} total rows.",
            ),
            "cache_hit": True,
            "cache_source_execution_id": cached.get("source_execution_id"),
            "artifact_persistence": {
                "status": "durable",
                "persisted_path": str(cached["csv_path"]),
                "reason": "Cached MFTECmd CSV is available at a durable artifact path.",
                "fix_hint": None,
            },
        }
        formatted = _apply_response_format(
            response,
            response_format=normalized_format,
            records=detailed_records,
            total_records=total_records,
        )
        formatted = _warn_if_empty(formatted, "extract_mft_timeline", mft_path, min_expected=10000)
        normalized_obs, pivots = _mft_contract_inputs(stream)
        return _mft_contract_payload(
            response=formatted,
            records=detailed_records,
            image_path=image_path,
            mft_path=mft_path,
            csv_path=str(cached["csv_path"]),
            normalized=normalized_obs,
            pivot_entities=pivots,
            evidence_excerpt=stream["evidence_excerpt"],
        )

    # F-A durable reuse (review 2026-06-04): after the state-cache MISS,
    # if the durable mft_timeline.csv already exists and the source $MFT is
    # unchanged (size+mtime sidecar), reuse it and SKIP the MFTECmd parse. Because
    # state may have been cleared (cache index gone), the prior findings are gone
    # too -> this is a SEPARATE branch from the state-cache hit: create_findings
    # =True with the reuse execution_id so the fresh investigation gets findings.
    reuse = try_durable_reuse(
        _audit, _state,
        tool_name=tool,
        parameters={"mft_path": resolved_mft_path},
        output_base=os.environ.get("OUTPUT_BASE", "/cases"),
        case_id=_case_id(),
        subtype="mft",
        canonical_filename="mft_timeline.csv",
        source_path=resolved_mft_path,
        force_reparse=force_reparse,
    )
    if reuse is not None:
        reuse_csv = reuse["csv_path"]
        stream = _stream_mft_summary(
            reuse_csv,
            mft_path=resolved_mft_path,
            tool=tool,
            execution_id=reuse["execution_id"],
            create_findings=True,
        )
        finding_ids = stream["finding_ids"]
        timestomping_candidates = stream["timestomping_candidates"]
        total_records = stream["raw_rows"]
        sample = stream["sample"]
        detailed_records = (
            sample[:max_entries] if (max_entries and max_entries > 0) else list(sample)
        )
        response = {
            "tool_name": tool,
            "status": "success",
            "findings_created": finding_ids,
            "execution_id": reuse["execution_id"],
            "raw_command": reuse["raw_command"],
            "records_count": len(detailed_records),
            "total_records": total_records,
            "matched_records": total_records,
            "timestomping_candidates": timestomping_candidates,
            "timestomping_findings_truncated": stream["timestomping_findings_truncated"],
            "data_truncated": total_records > len(detailed_records),
            "data_scope": "head_sample",
            "sample_cap": _MFT_SAMPLE_CAP,
            "csv_path": reuse_csv,
            "reused_output": True,
            "reuse_confidence": reuse["reuse_confidence"],
            "note": (
                f"Reused durable MFT CSV ({reuse['reuse_confidence']}); MFTECmd parse "
                f"skipped, findings recreated. {total_records} rows at {reuse_csv}. "
                + reuse.get("reuse_note", "")
            ),
            "requires_agent": "@mft-analyst",
            "agent_instruction": (
                f"Analyze {reuse_csv} for timestomping, attacker file drops, staging. "
                f"{total_records} total rows."
            ),
            "cache_hit": True,
            "artifact_persistence": {
                "status": "durable",
                "persisted_path": reuse_csv,
                "reason": "Reused durable MFTECmd CSV (source fingerprint checked).",
                "fix_hint": None,
            },
        }
        formatted = _apply_response_format(
            response,
            response_format=normalized_format,
            records=detailed_records,
            total_records=total_records,
        )
        formatted = _warn_if_empty(formatted, "extract_mft_timeline", mft_path, min_expected=10000)
        normalized_obs, pivots = _mft_contract_inputs(stream)
        return _mft_contract_payload(
            response=formatted,
            records=detailed_records,
            image_path=image_path,
            mft_path=mft_path,
            csv_path=reuse_csv,
            normalized=normalized_obs,
            pivot_entities=pivots,
            evidence_excerpt=stream["evidence_excerpt"],
        )

    with tempfile.TemporaryDirectory(prefix="savvydfir_mftecmd_") as tmp_dir:
        csv_filename = "mft_timeline.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_mftecmd(
                mft_path=resolved_mft_path,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
                tool_name=tool,
            )
        except Exception as exc:
            return _runner_error(tool, exc)

        if not result.ok and not Path(csv_path).exists():
            return {
                "tool_name": tool,
                "status": "error",
                "error_message": (
                    f"MFTECmd exited with code {result.exit_code}. "
                    f"stderr: {result.stderr[:300]}"
                ),
                "data": [],
                "findings_created": [],
                "execution_id": result.execution_id,
                "raw_command": result.command_line,
                "stderr": result.stderr,
            }

        # Memory-bounded: stream the (possibly large) $MFT CSV instead of
        # _read_csv + _build_mft_records materializing every entry.
        persistent_csv = _persist_csv(csv_path, "mft")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="MFT CSV",
            persisted_path=persistent_csv,
            preflight=preflight,
        )
        # F-A: stamp a source-fingerprint sidecar next to the durable CSV so a
        # later run (after state clear) can verify-and-reuse instead of re-parsing.
        if durable_csv:
            write_reuse_sidecar(durable_csv, tool_name=tool, source_path=resolved_mft_path)
        # Stream from the durable CSV if persisted (so findings cite the durable
        # path), else from the temp CSV while still inside the temp dir.
        stream = _stream_mft_summary(
            durable_csv or csv_path,
            mft_path=resolved_mft_path,
            tool=tool,
            execution_id=result.execution_id,
            create_findings=True,
        )

    finding_ids = stream["finding_ids"]
    timestomping_candidates = stream["timestomping_candidates"]
    total_records = stream["raw_rows"]
    sample = stream["sample"]
    detailed_records = (
        sample[:max_entries] if (max_entries and max_entries > 0) else list(sample)
    )
    response = {
        "tool_name": tool,
        "status": "success" if durable_csv else "warning",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(detailed_records),
        "total_records": total_records,
        "matched_records": total_records,
        "timestomping_candidates": timestomping_candidates,
        "timestomping_findings_truncated": stream["timestomping_findings_truncated"],
        "data_truncated": total_records > len(detailed_records),
        "data_scope": "head_sample",
        "sample_cap": _MFT_SAMPLE_CAP,
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "note": (
            f"Returning a bounded sample of {len(detailed_records)} of {total_records} MFT rows. Full CSV at {durable_csv}."
            if durable_csv
            else (
                f"Returning a bounded sample of {len(detailed_records)} of {total_records} MFT rows. "
                "CSV persistence did not produce a durable analyst-facing handle; "
                "fix OUTPUT_BASE and rerun extract_mft_timeline before using run_analysis()."
            )
        ),
        "requires_agent": "@mft-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for timestomping, attacker file drops, staging. {total_records} total rows."
            if durable_csv
            else (
                "Analyze the MFT summary now, then rerun extract_mft_timeline after fixing "
                "artifact persistence to obtain a reusable handle."
            )
        ),
        "cache_hit": False,
        "cache_source_execution_id": None,
    }
    response = _apply_response_format(
        response,
        response_format=normalized_format,
        records=detailed_records,
        total_records=total_records,
    )
    response = _warn_if_empty(
        response, "extract_mft_timeline", mft_path, min_expected=10000)
    if not durable_csv:
        response["warning"] = (
            "MFT rows were parsed successfully, but the CSV output could not be persisted to a "
            "durable artifact path."
        )
    if durable_csv:
        _state.cache_artifact(
            cache_key,
            {
                "source_execution_id": result.execution_id,
                "csv_path": durable_csv,
                "findings_created": finding_ids,
                "requires_agent": response.get("requires_agent"),
                "agent_instruction": response.get("agent_instruction"),
                "timestomping_candidates": timestomping_candidates,
                "total_records": total_records,
            },
        )
    normalized_obs, pivots = _mft_contract_inputs(stream)
    return _mft_contract_payload(
        response=response,
        records=detailed_records,
        image_path=image_path,
        mft_path=mft_path,
        csv_path=durable_csv,
        normalized=normalized_obs,
        pivot_entities=pivots,
        evidence_excerpt=stream["evidence_excerpt"],
    )


# ---------------------------------------------------------------------------
# Tool: extract_usn_journal (B.2)
# ---------------------------------------------------------------------------


def _resolve_usn_path_input(image_path: str, usn_path: Optional[str]) -> str:
    """Resolve $UsnJrnl:$J path. A.2-style: durable artifacts beat scan.

    The icat staging step writes the ADS as a flat file under
    /cases/<id>/artifacts/raw/usn/. Naming has drifted across staging
    revisions - we accept all known variants AND fall back to scanning
    the directory for any file >0 bytes that contains 'UsnJrnl' or 'J'.
    """
    if usn_path is not None:
        return usn_path
    cid = _case_id()
    base = Path(os.environ.get("OUTPUT_BASE", "/cases")) / cid / "artifacts" / "raw" / "usn"
    if base.is_dir():
        # Known staged filenames across staging revisions
        for candidate_name in (
            "$UsnJrnl_$J",   # current staging (extract_windows_artifacts)
            "$UsnJrnl:$J",   # raw ADS-style (some mount paths)
            "$J",            # icat-direct extract
            "UsnJrnl_J",     # sanitized variant
            "usn_journal_J",
            "J",
        ):
            candidate = base / candidate_name
            if candidate.is_file() and candidate.stat().st_size > 0:
                return str(candidate)
        # Last-resort directory scan - pick the largest UsnJrnl/J-ish file.
        # Defensive: if any future staging revision uses yet another name,
        # the file is still found as long as its name carries "UsnJrnl"
        # or starts with "J" or "$J".
        try:
            candidates = []
            for child in base.iterdir():
                if not child.is_file():
                    continue
                size = child.stat().st_size
                if size <= 0:
                    continue
                name = child.name
                if (
                    "UsnJrnl" in name
                    or name.startswith("J")
                    or name.startswith("$J")
                    or "usn" in name.lower()
                ):
                    candidates.append((size, child))
            if candidates:
                candidates.sort(reverse=True)  # largest first
                return str(candidates[0][1])
        except OSError:
            pass
    base_img = Path(image_path)
    if _path_is_file(base_img) and base_img.name in ("$J", "UsnJrnl_J", "$UsnJrnl_$J"):
        return str(base_img)
    # Last resort: Windows-relative; rarely useful since $J is an ADS
    return _resolve_windows_relative_path(
        image_path, "$Extend", "$UsnJrnl_J"  # mount-translated ADS name varies
    )


def extract_usn_journal(
    image_path: str,
    usn_path: Optional[str] = None,
    mft_path: Optional[str] = None,
    case_id: Optional[str] = None,
    response_format: str = "summary",
    force_reparse: bool = False,
) -> dict[str, Any]:
    """Parse the NTFS USN Journal ($UsnJrnl:$J) via MFTECmd.

    B.2 - USN persists filesystem-change records that the MFT itself may
    overwrite. Critical for ransomware/exfiltration timelines because:
      - rename/delete is recorded with timestamps even after the MFT
        record is reallocated
      - 'BasicInfoChange + FileCreate + DataExtend' chains reveal
        encryption activity (ransomware) and large-file staging (exfil)

    Like extract_mft_timeline, USN output is LARGE (often >1M rows). We
    return a summary + csv_path handle ONLY - the parent agent must use
    run_analysis() against the CSV, never load rows into context.
    Specialist analyst: @mft-analyst (handles both MFT and USN pivots).

    Parameters
    ----------
    image_path:
        Image path (used to resolve case_id and durable artifact dir).
    usn_path:
        Optional explicit path to the extracted $J file. When None,
        prefers /cases/<case>/artifacts/raw/usn/$J (durable artifact)
        before falling back to scanning image_path.
    mft_path:
        Optional $MFT path. When given, MFTECmd resolves parent paths
        for each USN record (substantially more useful for triage).
    case_id:
        Overrides the resolved case_id for output naming.
    response_format:
        "summary" (default) returns counts and the csv_path; "detailed"
        adds a small preview (first 25 rows). Detailed format must NOT
        be the default per project rules on large artifacts.
    """
    tool = "disk.extract_usn_journal"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    normalized_format = _normalize_response_format(response_format)
    if normalized_format is None:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "Invalid response_format. Use 'summary' or 'detailed'.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    usn_path = _resolve_usn_path_input(image_path, usn_path)
    resolved_usn = _resolved_path_str(usn_path)
    if _unsafe_runtime_tmp_input(resolved_usn):
        return _unsafe_path_error(
            tool, input_name="usn_path", resolved_path=resolved_usn,
            image_path=image_path,
        )
    if not Path(resolved_usn).is_file():
        return _path_missing_error(
            tool, input_name="usn_path", resolved_path=resolved_usn,
            image_path=image_path,
        )

    # If mft_path not explicit, try to find a durable one (A.2 pattern)
    if mft_path is None:
        durable_mft = _durable_raw_artifact_path("mft")
        if durable_mft and Path(durable_mft).is_file():
            mft_path = durable_mft

    # F-A durable reuse (review 2026-06-04): USN has no state-cache, so
    # probe the durable usn_journal.csv BEFORE the (slow, 4GB-source) MFTECmd USN
    # parse. If present + source $J unchanged, reuse it, recreate the summary
    # finding with the reuse execution_id, and skip the parse. This is what breaks
    # the cleared-state -> reparse -> timeout -> stop-hook re-demand loop for USN.
    reuse = try_durable_reuse(
        _audit, _state,
        tool_name=tool,
        parameters={"usn_path": resolved_usn},
        output_base=os.environ.get("OUTPUT_BASE", "/cases"),
        case_id=_case_id(),
        subtype="usn",
        canonical_filename="usn_journal.csv",
        source_path=resolved_usn,
        force_reparse=force_reparse,
    )
    if reuse is not None:
        reuse_csv = reuse["csv_path"]
        total_rows = 0
        try:
            with open(reuse_csv, "r", encoding="utf-8-sig", newline="") as fh:
                total_rows = max(0, sum(1 for _ in fh) - 1)
        except OSError:
            total_rows = 0
        finding_ids: list[str] = []
        try:
            finding_ids.append(_state.add_finding({
                "case_id": _case_id(),
                "finding_type": "other",
                "artifact_type": "disk",
                "artifact_path": resolved_usn,
                "tool_name": tool,
                "execution_id": reuse["execution_id"],
                "iteration": _current_iteration(),
                "evidence_kind": "observation",
                "finding_status": "active",
                "confidence": 0.7 if total_rows > 0 else 0.4,
                "description": (
                    f"USN Journal reused ({reuse['reuse_confidence']}): {total_rows} change "
                    f"records from {resolved_usn}. Use run_analysis on the CSV for "
                    "rename/delete/large-write pivots."
                ),
                "supporting_indicators": [
                    f"row_count={total_rows}",
                    f"csv={reuse_csv}",
                    f"mft_correlated={'yes' if mft_path else 'no'}",
                    f"reuse_confidence={reuse['reuse_confidence']}",
                ],
            }))
        except Exception:
            pass
        response = {
            "tool_name": tool,
            "status": "success",
            "data": [],
            "findings_created": finding_ids,
            "execution_id": reuse["execution_id"],
            "raw_command": reuse["raw_command"],
            "total_records": total_rows,
            "csv_path": reuse_csv,
            "reused_output": True,
            "reuse_confidence": reuse["reuse_confidence"],
            "cache_hit": True,
            "mft_correlated": bool(mft_path),
            "artifact_persistence": {
                "status": "durable", "persisted_path": reuse_csv,
                "reason": "Reused durable USN CSV (MFTECmd parse skipped).", "fix_hint": None,
            },
            "requires_agent": "@mft-analyst",
            "agent_instruction": (
                f"USN journal at {reuse_csv} ({total_rows} records). Run targeted "
                "run_analysis queries (rename-burst, encryption signature, staging dirs). "
                "Do NOT load the full CSV into context."
            ),
            "note": (
                f"Reused durable USN CSV ({reuse['reuse_confidence']}); {total_rows} records; "
                f"finding recreated. {reuse.get('reuse_note','')}"
            ),
        }
        return _finalize_tool_response_with_envelope(tool, response)

    with tempfile.TemporaryDirectory(prefix="savvydfir_usn_") as tmp_dir:
        csv_filename = "usn_journal.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        # Size-aware USN timeout (review 2026-06-06): the $UsnJrnl:$J can be
        # multi-GB and the flat 1800s default timed out on the Hacking Case. Scale
        # by the staged $J size (60s/GB, volatility precedent), capped at 3600s so
        # a pathological journal can't block the 4-vCPU host for hours. If it still
        # times out, the honest collection_timeout gap stands.
        try:
            _usn_gb = os.path.getsize(resolved_usn) / (1024 ** 3)
        except OSError:
            _usn_gb = 0.0
        _usn_timeout = max(1800, min(3600, int(1800 + 60 * _usn_gb)))
        try:
            result = _ez_runner.run_mftecmd_usn(
                usn_path=resolved_usn,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
                mft_path=mft_path,
                tool_name=tool,
                timeout=_usn_timeout,
            )
        except Exception as exc:
            return _runner_error(tool, exc)

        if not result.ok and not Path(csv_path).exists():
            return {
                "tool_name": tool,
                "status": "error",
                "error_message": (
                    f"MFTECmd (USN mode) exited with code {result.exit_code}. "
                    f"stderr: {result.stderr[:300]}"
                ),
                "data": [],
                "findings_created": [],
                "execution_id": result.execution_id,
                "raw_command": result.command_line,
                "stderr": result.stderr,
            }

        # Stream-count rows without loading the whole CSV (large artifact rule)
        total_rows = 0
        try:
            with open(csv_path, "r", encoding="utf-8-sig", newline="") as fh:
                # Subtract 1 for header row
                total_rows = max(0, sum(1 for _ in fh) - 1)
        except OSError:
            total_rows = 0

        persistent_csv = _persist_csv(csv_path, "usn")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="USN journal CSV",
            persisted_path=persistent_csv,
            preflight={"ok": True},  # USN doesn't have its own preflight
        )
        # F-A: stamp source-fingerprint sidecar for verify-and-reuse next run.
        if durable_csv:
            write_reuse_sidecar(durable_csv, tool_name=tool, source_path=resolved_usn)

    # Build a small preview when detailed is requested (capped at 25 rows)
    preview: list[dict[str, Any]] = []
    if normalized_format == "detailed" and durable_csv:
        try:
            import csv as _csv
            with open(durable_csv, "r", encoding="utf-8-sig", newline="") as fh:
                reader = _csv.DictReader(fh)
                for i, row in enumerate(reader):
                    if i >= 25:
                        break
                    preview.append(dict(row))
        except OSError:
            pass

    # Single summary finding so the report gate sees structured proof
    # the tool ran. Suspicious-pattern detection is left to the analyst
    # working through run_analysis on the CSV.
    finding_ids: list[str] = []
    try:
        finding_dict = {
            "case_id": _case_id(),
            "finding_type": "other",
            "artifact_type": "disk",
            "artifact_path": resolved_usn,
            "tool_name": tool,
            "execution_id": result.execution_id,
            "iteration": _current_iteration(),
            "evidence_kind": "observation",
            "finding_status": "active",
            "confidence": 0.7 if total_rows > 0 else 0.4,
            "description": (
                f"USN Journal parsed: {total_rows} change records from {resolved_usn}. "
                "Use run_analysis on the CSV for rename/delete/large-write pivots."
            ),
            "supporting_indicators": [
                f"row_count={total_rows}",
                f"csv={durable_csv or 'transient'}",
                f"mft_correlated={'yes' if mft_path else 'no'}",
            ],
        }
        finding_ids.append(_state.add_finding(finding_dict))
    except Exception:
        pass

    response = {
        "tool_name": tool,
        "status": "success" if durable_csv else "warning",
        # Phase B boundary: explicit empty data array even on success -
        # USN context is large and never inlined. Clients/hooks enforce
        # the contract by checking data == [].
        "data": [],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "total_records": total_rows,
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "mft_correlated": bool(mft_path),
        "requires_agent": "@mft-analyst",
        "agent_instruction": (
            f"USN journal at {durable_csv} ({total_rows} records). Run targeted "
            "run_analysis queries: rename-burst detection (BasicInfoChange + "
            "DataExtend), encryption signature (FileCreate then large RenameNewName "
            "to .encrypted/.locked/.crypt), and staging directories (mass creates "
            "under Temp / Downloads). Do NOT load the full CSV into context."
        ),
        "note": (
            f"{total_rows} USN records persisted at {durable_csv}. Summary-only "
            "response; specialist must query via run_analysis to avoid context bloat."
            if durable_csv
            else "USN parsed but CSV persistence failed; fix OUTPUT_BASE and re-run."
        ),
    }
    if normalized_format == "detailed":
        response["preview"] = preview
    return _finalize_tool_response_with_envelope(tool, response)


def _finalize_tool_response_with_envelope(tool: str, response: dict[str, Any]) -> dict[str, Any]:
    """Helper: tools imported into server.py go through _finalize_tool_response;
    when invoked directly from a test or other module, this no-op shim keeps
    the response structure consistent. server.py's mcp wrapper does the
    forensic envelope binding."""
    return response


# ---------------------------------------------------------------------------
# Tool: list_deleted_files
# ---------------------------------------------------------------------------

# fls output format:
# r/r * 12345-128-1:  path/to/file.exe
# d/d * 12346-128-1:  path/to/dir/
# The '*' flag indicates deleted; 'd/d' is directory, 'r/r' is regular file
_FLS_LINE_RE = re.compile(
    r"^([drlu])/([\drlu-])\s+\*?\s*(\S+):\s+(.*)$"
)


def list_deleted_files(
    device_path: str = "/mnt/disk",
    offset: Optional[int] = None,
    image_path: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 500,
    response_format: str = "summary",
    limit: Optional[int] = None,
    page_offset: int = 0,
) -> dict[str, Any]:
    # image_path is an alias for device_path (server.py compat)
    if image_path and device_path == "/mnt/disk":
        device_path = image_path
    """List deleted files in a disk image using The Sleuth Kit ``fls``.

    Wraps ``fls -rd`` (recursive, deleted-only) on SIFT Workstation.

    Deleted files retain their directory entry until the inode is reallocated,
    making them recoverable with ``icat``.  Summary mode persists the complete
    parsed result to a durable JSON handle and returns only a bounded preview
    so large deleted-file sets do not flood agent context.

    Parameters
    ----------
    device_path:
        Path to the disk image or EWF file (e.g. ``/cases/SRL-2018/evidence/disk.E01``).
    offset:
        Sector offset of the target partition (from ``mmls``).  When ``None``,
        TSK assumes a single-partition image.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``preview``, ``storage_path``,
        ``findings_created``, ``execution_id``, ``raw_command``, and
        ``records_count``.  Detailed mode includes a bounded ``data`` page.
    """
    tool = "disk.list_deleted_files"
    if _sk_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    try:
        result = _sk_runner.fls(
            device_path=device_path,
            recursive=True,
            deleted_only=True,
            offset=offset,
            tool_name=tool,
        )
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok and not result.stdout:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"fls exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
        }

    records: list[DeletedFile] = []
    finding_ids: list[str] = []

    # OOM mitigation - fls stdout on a full MFT is multi-MB. Materialize the
    # line list once and immediately release the raw buffer so the heap
    # doesn't carry it through the per-line scoring loop below.
    _fls_lines = result.stdout.splitlines()
    if hasattr(result, "release_stdout"): result.release_stdout()

    for line in _fls_lines:
        line = line.strip()
        if not line:
            continue

        # fls output: type_code/alloc_flag [*] inode: name
        # Example: r/r * 12345-128-1: Windows/Temp/evil.exe
        # Split on first colon after the inode number
        # Detect deleted entries (lines containing ' * ')
        deleted = " * " in line or line.startswith("* ") or "\t*\t" in line

        # Extract inode and path
        parts = line.split(":", 1)
        if len(parts) < 2:
            continue

        left, file_path_val = parts[0].strip(), parts[1].strip()

        # left contains something like "r/r * 12345-128-1" or "d/d   12345"
        tokens = left.split()
        if not tokens:
            continue

        # Last token should be the inode; first should be type/alloc
        inode = tokens[-1] if tokens else ""
        type_flag = tokens[0] if tokens else "r/r"

        # Skip unallocated meta entries
        if inode in ("0", "$OrphanFiles", ""):
            continue

        file_type: str = "file"
        if type_flag.startswith("d"):
            file_type = "directory"

        # Parent inode: not directly provided by fls, skip
        parent_inode: Optional[str] = None

        try:
            record = DeletedFile(
                inode=inode,
                file_path=file_path_val,
                file_type=file_type,  # type: ignore[arg-type]
                size=None,
                deleted_time=None,
                parent_inode=parent_inode,
            )
            records.append(record)
        except Exception:
            continue

    # Create a single summary finding for the batch
    if records:
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="disk",
            artifact_path=device_path,
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=(
                f"Found {len(records)} deleted file entries in {device_path} "
                f"(partition offset: {offset or 'auto-detect'}). "
                "Deleted entries may be recoverable with icat."
            ),
            supporting_indicators=[r.file_path for r in records[:20]],
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)

    response_mode = str(response_format or "summary").strip().lower()
    if response_mode not in {"summary", "detailed"}:
        response_mode = "summary"
    page_start = max(0, int(page_offset or 0))
    page_limit = max(1, int(limit if limit is not None else max_entries or 50))
    preview_limit = min(page_limit, max(1, int(max_entries or 50)), 50)
    serialized_records = [r.model_dump(mode="json") for r in records]
    preview = serialized_records[:preview_limit]
    page = serialized_records[page_start : page_start + page_limit]

    storage_path: Optional[str] = None
    try:
        output_dir = _artifact_output_dir("deleted_files")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "deleted_files.json"
        output_path.write_text(
            json.dumps(
                {
                    "tool_name": tool,
                    "records_count": len(serialized_records),
                    "raw_command": result.command_line,
                    "records": serialized_records,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        storage_path = str(output_path)
    except OSError:
        storage_path = None

    response = {
        "tool_name": tool,
        "status": "success",
        "preview": preview,
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
        "records_returned": len(page if response_mode == "detailed" else preview),
        "storage_path": storage_path,
        "response_format": response_mode,
        "note": (
            f"Summary mode returned {len(preview)} preview rows from {len(records)} "
            f"deleted entries. Full parsed output is at {storage_path}."
            if storage_path
            else f"Summary mode returned {len(preview)} preview rows from {len(records)} deleted entries."
        ),
    }
    if response_mode == "detailed":
        response["data"] = page
        response["page_offset"] = page_start
        response["page_limit"] = page_limit
    return response


# ---------------------------------------------------------------------------
# Tool: summarize_evtx - helpers
# ---------------------------------------------------------------------------

# High-value attack-surface channels: extract if present and non-empty.
# Baseline (Security/System/Application/Defender) are always processed.
_EVTX_HIGH_VALUE_STEMS = frozenset({
    "microsoft-windows-sysmon%4operational",
    "microsoft-windows-powershell%4operational",
    "microsoft-windows-terminalservices-rdpclient%4operational",
    "microsoft-windows-terminalservices-localsessionmanager%4operational",
    "microsoft-windows-taskscheduler%4operational",
    "microsoft-windows-winrm%4operational",
    "microsoft-windows-wmi-activity%4operational",
    "microsoft-windows-smbserver%4security",
    "microsoft-windows-smbclient%4security",
    "microsoft-windows-windows firewall with advanced security%4firewall",
})

_EVTX_BASELINE_STEMS = frozenset({
    "security",
    "system",
    "application",
    "microsoft-windows-windows defender%4operational",
})


def _enumerate_evtx_channels(evtx_dir: str) -> dict[str, Any]:
    """Scan evtx_dir for .evtx files; classify each as present or empty.

    Returns a dict keyed by channel stem (lower-case filename without
    extension).  Each value contains size_bytes, is_present (>4 KB),
    tier ('baseline', 'high_value', or 'other'), and file_path.
    """
    directory = Path(evtx_dir)
    inventory: dict[str, Any] = {}
    for evtx_file in sorted(directory.glob("*.evtx")):
        try:
            size = evtx_file.stat().st_size
        except OSError:
            size = 0
        stem = evtx_file.stem.lower()
        tier: str
        if stem in _EVTX_BASELINE_STEMS:
            tier = "baseline"
        elif stem in _EVTX_HIGH_VALUE_STEMS:
            tier = "high_value"
        else:
            tier = "other"
        inventory[stem] = {
            "file_path": str(evtx_file),
            "size_bytes": size,
            "is_present": size > 4096,
            "tier": tier,
        }
    present = sum(1 for v in inventory.values() if v["is_present"])
    empty = len(inventory) - present
    return {
        "channels": inventory,
        "total_channels": len(inventory),
        "present_channels": present,
        "empty_channels": empty,
        "baseline_present": [s for s, v in inventory.items() if v["tier"] == "baseline" and v["is_present"]],
        "high_value_present": [s for s, v in inventory.items() if v["tier"] == "high_value" and v["is_present"]],
    }


def _stage_evtx_for_extraction(
    inventory: dict[str, Any],
    tmp_dir: str,
    *,
    fallback_dir: str,
) -> tuple[str, list[str]]:
    """Copy only baseline + present high-value .evtx files into a staging dir.

    Returns (staging_dir, [channel_stems_staged]).  If the inventory contains
    no usable channels we return the original fallback_dir untouched - this
    keeps the legacy "process everything" behaviour as a safety net.

    Run7 Stage 2 behaviour: EvtxECmd runs only against this bounded set,
    matching the plan's selective extraction promise.
    """
    channels = inventory.get("channels") or {}
    selectable = [
        meta for meta in channels.values()
        if meta.get("is_present") and meta.get("tier") in ("baseline", "high_value")
    ]
    if not selectable:
        return fallback_dir, []

    staging = Path(tmp_dir) / "tier_selected"
    staging.mkdir(parents=True, exist_ok=True)
    staged_stems: list[str] = []
    for meta in selectable:
        src = Path(meta["file_path"])
        if not src.is_file():
            continue
        try:
            shutil.copy2(str(src), str(staging / src.name))
            staged_stems.append(src.stem.lower())
        except OSError:
            continue
    if not staged_stems:
        return fallback_dir, []
    return str(staging), staged_stems


def _record_evtx_inventory(inventory: dict[str, Any]) -> None:
    """Persist channel inventory into state artifact_coverage (non-destructive merge).

    update_triage_state replaces artifact_coverage wholesale, so we read the
    current coverage via to_summary() and merge our key into it before writing.
    Otherwise any other coverage data already in state.json gets wiped.
    """
    if _state is None:
        return
    try:
        summary = _state.to_summary()
        triage_status = summary.get("triage_status") or summary.get("status") or "IN_PROGRESS"
        existing_coverage = dict(summary.get("artifact_coverage") or {})
        existing_coverage["evtx_inventory"] = {
            "total_channels": inventory["total_channels"],
            "present_channels": inventory["present_channels"],
            "empty_channels": inventory["empty_channels"],
            "baseline_present": inventory["baseline_present"],
            "high_value_present": inventory["high_value_present"],
            "coverage_debt": [
                s for s, v in inventory["channels"].items()
                if v["tier"] in ("baseline", "high_value") and not v["is_present"]
            ],
        }
        _state.update_triage_state(
            triage_status=triage_status,
            artifact_coverage=existing_coverage,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tool: summarize_evtx
# ---------------------------------------------------------------------------


def summarize_evtx(
    image_path: str,
    evtx_dir: Optional[str] = None,
    channel: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    event_ids: Optional[list[int]] = None,
    response_format: str = "summary",
    force_reparse: bool = False,
) -> dict[str, Any]:
    """Parse Windows EVTX event logs using EvtxECmd (EZ Tools).

    Wraps ``dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`` on SIFT Workstation.

    Processes all ``.evtx`` files in the event log directory and emits a
    unified CSV timeline.  By default, filters to ``DFIR_ESSENTIAL_EIDS``
    (26 universal security-relevant Event IDs) to prevent context flooding
    from millions of informational events.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image.  Used to derive the default
        EVTX directory path if *evtx_dir* is not given.
    evtx_dir:
        Absolute path to the directory containing ``.evtx`` files (e.g.
        ``/cases/SRL-2018/evidence/mnt/C/Windows/System32/winevt/Logs``).
        When ``None``, a default path is constructed.
    channel:
        Optional event log channel name to filter results (case-insensitive).
        E.g. ``"Security"``, ``"System"``, ``"Microsoft-Windows-Sysmon/Operational"``.
        When ``None``, all channels are returned.
    start_date:
        Optional start date filter (ISO 8601, e.g. ``"2024-01-15"``).
        Passed to EvtxECmd ``--sd`` flag.  Only events on or after this
        date are included.
    end_date:
        Optional end date filter (ISO 8601, e.g. ``"2024-02-01"``).
        Passed to EvtxECmd ``--ed`` flag.  Only events on or before this
        date are included.
    event_ids:
        List of Event IDs to include.  Passed to EvtxECmd ``--inc`` flag.
        Defaults to ``DFIR_ESSENTIAL_EIDS`` (26 universal DFIR Event IDs).
        Pass an empty list ``[]`` to disable filtering and return all events.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of EventRecord dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``, ``channel_filter``, ``event_id_filter``.
    """
    tool = "disk.summarize_evtx"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)
    if normalized_format is None:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "Invalid response_format. Use 'summary' or 'detailed'.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    evtx_dir = _resolve_evtx_dir_input(image_path, evtx_dir)
    resolved_evtx_dir = _resolved_path_str(evtx_dir)
    if _unsafe_runtime_tmp_input(resolved_evtx_dir):
        return _unsafe_path_error(
            tool,
            input_name="evtx_dir",
            resolved_path=resolved_evtx_dir,
            image_path=image_path,
        )
    if not Path(resolved_evtx_dir).exists():
        return _path_missing_error(
            tool,
            input_name="evtx_dir",
            resolved_path=resolved_evtx_dir,
            image_path=image_path,
        )
    preflight = _preflight_artifact_persistence("evtx", "evtx_timeline.csv")
    if not preflight.get("ok"):
        return _artifact_preflight_error(tool_name=tool, preflight=preflight)

    # Channel inventory - always enumerate before processing so state.json
    # records which channels are present vs empty vs not extracted.
    evtx_inventory = _enumerate_evtx_channels(resolved_evtx_dir)
    _record_evtx_inventory(evtx_inventory)
    # Context-budget discipline: response carries STATS only, not the
    # full per-channel dict (which can be ~46 KB for 307 channels and is
    # already persisted in state.json:artifact_coverage.evtx_inventory).
    # The agent reads state.json via read_state() to drill in on demand.
    evtx_inventory_summary = {
        "total_channels": evtx_inventory["total_channels"],
        "present_channels": evtx_inventory["present_channels"],
        "empty_channels": evtx_inventory["empty_channels"],
        "baseline_present": evtx_inventory["baseline_present"],
        "high_value_present": evtx_inventory["high_value_present"],
        "drill_in_hint": "Full per-channel detail in state.json:artifact_coverage.evtx_inventory.channels",
    }

    event_id_strategy = "explicit"
    if event_ids is not None:
        effective_eids = event_ids
    else:
        try:
            existing_findings = _state.get_findings()
        except Exception:
            existing_findings = []

        if existing_findings:
            effective_eids = adaptive_eids_from_findings(existing_findings)
            event_id_strategy = "adaptive"
        else:
            effective_eids = DFIR_ESSENTIAL_EIDS
            event_id_strategy = "default"

    # Cache key for idempotency.  When the caller did NOT specify explicit
    # event_ids (event_ids=None → adaptive or default), the cache key is
    # based solely on the stable base params (evtx_dir, channel, dates).
    # This prevents adaptive EID set drift (which changes every call as
    # findings grow) from busting the cache and re-running EvtxECmd 30×.
    caller_specified_eids = event_ids is not None
    cache_base_params = {
        "evtx_dir": resolved_evtx_dir,
        "channel": channel or "",
        "start_date": start_date or "",
        "end_date": end_date or "",
    }
    if caller_specified_eids:
        # Caller explicitly chose EIDs - include them in the cache key
        cache_params = {
            **cache_base_params,
            "event_ids": sorted(effective_eids) if effective_eids else [],
            "event_id_strategy": "explicit",
        }
    else:
        # Auto-selected EIDs (adaptive or default) - cache on base params only
        cache_params = {
            **cache_base_params,
            "event_id_strategy": "auto",
        }
    cache_key = build_cache_key(tool, cache_params)
    cached = get_valid_cached_artifact(
        _state,
        cache_key,
        path_key="csv_path",
        required_keys=("csv_path", "source_execution_id"),
    )
    if cached is not None:
        cache_meta = record_cache_hit(
            _audit,
            _state,
            tool_name=tool,
            parameters={
                "evtx_dir": _resolved_path_str(evtx_dir),
                "channel": channel,
                "start_date": start_date,
                "end_date": end_date,
                "event_ids": list(effective_eids) if effective_eids else [],
            },
            cache_key=cache_key,
            artifact_path=str(cached["csv_path"]),
            cache_source_execution_id=str(
                cached.get("source_execution_id") or ""),
        )
        # Memory-bounded: the cache-hit path MUST use the same streaming helper
        # as the fresh path -- a half-patched cache re-read of the same 2.4GB CSV
        # would OOM identically (review 2026-06-02, non-negotiable).
        stream = _stream_evtx_summary(str(cached["csv_path"]), channel=channel)
        promote_corroborated_findings(
            _state,
            "evtx_process_creation",
            stream["process_paths"],
        )
        total_records = stream["total_records"]      # raw CSV rows
        matched_records = stream["matched_records"]  # channel-matched (== total when channel=None)
        sample = stream["sample"]
        detailed_records = (
            sample[:max_entries] if (max_entries and max_entries > 0) else list(sample)
        )
        response = {
            "tool_name": tool,
            "status": "success",
            "findings_created": list(cached.get("findings_created", [])),
            "execution_id": cache_meta["execution_id"],
            "raw_command": cache_meta["raw_command"],
            "records_count": len(detailed_records),
            "total_records": total_records,
            "matched_records": matched_records,
            "data_truncated": matched_records > len(detailed_records),
            "data_scope": "head_sample",
            "sample_cap": _EVTX_SAMPLE_CAP,
            "csv_path": str(cached["csv_path"]),
            "requires_agent": cached.get("requires_agent", "@evtx-analyst"),
            "agent_instruction": cached.get(
                "agent_instruction",
                f"Analyze {cached['csv_path']} for attacker lifecycle — auth anomalies, lateral movement, persistence. {total_records} total rows.",
            ),
            "note": (
                f"Returning a bounded sample of {len(detailed_records)} inline rows"
                + (f"; {matched_records} matched channel '{channel}'" if channel else "")
                + f"; {total_records} rows in the full CSV at {cached['csv_path']}."
            ),
            "channel_filter": channel,
            "event_id_filter": cached.get(
                "event_id_filter",
                effective_eids if effective_eids else "all",
            ),
            "event_id_strategy": cached.get("event_id_strategy", event_id_strategy),
            "date_range": {
                "start": start_date,
                "end": end_date,
            } if start_date or end_date else None,
            "cache_hit": True,
            "cache_source_execution_id": cached.get("source_execution_id"),
            "artifact_persistence": {
                "status": "durable",
                "persisted_path": str(cached["csv_path"]),
                "reason": "Cached EVTX CSV is available at a durable artifact path.",
                "fix_hint": None,
            },
            "evtx_inventory": evtx_inventory_summary,
        }
        formatted = _apply_response_format(
            response,
            response_format=normalized_format,
            records=detailed_records if normalized_format == "detailed" else sample,
            total_records=total_records,
        )
        formatted = _warn_if_empty(formatted, "summarize_evtx", evtx_dir, min_expected=100)
        if "data" in formatted:
            formatted["data"] = [
                sanitize_payload_fields(record, "message_summary", "extra_fields")
                for record in formatted["data"]
            ]
        normalized_obs, pivots = _evtx_contract_inputs(stream)
        return _evtx_contract_payload(
            response=formatted,
            records=detailed_records if normalized_format == "detailed" else sample,
            image_path=image_path,
            evtx_dir=evtx_dir,
            csv_path=str(cached["csv_path"]),
            channel_counts=stream["channel_counts"],
            pivot_entities=pivots,
            normalized=normalized_obs,
            evidence_excerpt=stream["evidence_excerpt"],
        )

    # F-A durable reuse (review 2026-06-04): after the state-cache MISS,
    # reuse the durable evtx_timeline.csv if the EVTX corpus (per-file manifest
    # fingerprint) is unchanged. EVTX is the heavy parse (420 files -> 2.5GB) that
    # timed out and triggered the stop-hook re-demand loop on cleared state.
    # SEPARATE branch from the state-cache hit: recreate findings via
    # _evtx_summary_finding_ids with the reuse execution_id (cleared state -> the
    # cached findings are gone, so a fresh investigation needs them recreated).
    reuse = try_durable_reuse(
        _audit, _state,
        tool_name=tool,
        parameters={
            "evtx_dir": _resolved_path_str(evtx_dir),
            "channel": channel,
            "start_date": start_date,
            "end_date": end_date,
            "event_ids": list(effective_eids) if effective_eids else [],
        },
        output_base=os.environ.get("OUTPUT_BASE", "/cases"),
        case_id=_case_id(),
        subtype="evtx",
        canonical_filename="evtx_timeline.csv",
        source_path=resolved_evtx_dir,
        force_reparse=force_reparse,
    )
    if reuse is not None:
        reuse_csv = reuse["csv_path"]
        stream = _stream_evtx_summary(reuse_csv, channel=channel)
        promote_corroborated_findings(_state, "evtx_process_creation", stream["process_paths"])
        total_records = stream["total_records"]
        matched_records = stream["matched_records"]
        finding_ids = _evtx_summary_finding_ids(
            matched_records,
            evtx_dir=evtx_dir,
            channel=channel,
            execution_id=reuse["execution_id"],
        )
        sample = stream["sample"]
        detailed_records = (
            sample[:max_entries] if (max_entries and max_entries > 0) else list(sample)
        )
        response = {
            "tool_name": tool,
            "status": "success",
            "findings_created": finding_ids,
            "execution_id": reuse["execution_id"],
            "raw_command": reuse["raw_command"],
            "records_count": len(detailed_records),
            "total_records": total_records,
            "matched_records": matched_records,
            "data_truncated": matched_records > len(detailed_records),
            "data_scope": "head_sample",
            "sample_cap": _EVTX_SAMPLE_CAP,
            "csv_path": reuse_csv,
            "reused_output": True,
            "reuse_confidence": reuse["reuse_confidence"],
            "requires_agent": "@evtx-analyst",
            "agent_instruction": (
                f"Analyze {reuse_csv} for attacker lifecycle — auth anomalies, lateral "
                f"movement, persistence. {total_records} total rows."
            ),
            "note": (
                f"Reused durable EVTX CSV ({reuse['reuse_confidence']}); EvtxECmd parse "
                f"skipped, findings recreated. {total_records} rows at {reuse_csv}. "
                + reuse.get("reuse_note", "")
            ),
            "channel_filter": channel,
            "event_id_filter": effective_eids if effective_eids else "all",
            "event_id_strategy": event_id_strategy,
            "date_range": {"start": start_date, "end": end_date} if start_date or end_date else None,
            "cache_hit": True,
            "cache_source_execution_id": None,
            "artifact_persistence": {
                "status": "durable", "persisted_path": reuse_csv,
                "reason": "Reused durable EvtxECmd CSV (corpus fingerprint checked).",
                "fix_hint": None,
            },
            "evtx_inventory": evtx_inventory_summary,
        }
        formatted = _apply_response_format(
            response,
            response_format=normalized_format,
            records=detailed_records if normalized_format == "detailed" else sample,
            total_records=total_records,
        )
        formatted = _warn_if_empty(formatted, "summarize_evtx", evtx_dir, min_expected=100)
        if "data" in formatted:
            formatted["data"] = [
                sanitize_payload_fields(record, "message_summary", "extra_fields")
                for record in formatted["data"]
            ]
        normalized_obs, pivots = _evtx_contract_inputs(stream)
        return _evtx_contract_payload(
            response=formatted,
            records=detailed_records if normalized_format == "detailed" else sample,
            image_path=image_path,
            evtx_dir=evtx_dir,
            csv_path=reuse_csv,
            channel_counts=stream["channel_counts"],
            pivot_entities=pivots,
            normalized=normalized_obs,
            evidence_excerpt=stream["evidence_excerpt"],
        )

    with tempfile.TemporaryDirectory(prefix="savvydfir_evtx_") as tmp_dir:
        csv_filename = "evtx_timeline.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        # Run7 Stage 2: stage only baseline + present high-value channels into a
        # bounded temp dir. EvtxECmd then processes ONLY those files, matching the
        # plan's promised channel selectivity instead of running against the full
        # evtx_dir.  If the user explicitly passed a `channel` filter, defer to
        # them and pass the original dir through (legacy behaviour).
        staged_evtx_dir = resolved_evtx_dir
        extracted_channels: list[str] = []
        if channel is None:
            try:
                staged_evtx_dir, extracted_channels = _stage_evtx_for_extraction(
                    evtx_inventory, tmp_dir, fallback_dir=resolved_evtx_dir,
                )
            except Exception:
                staged_evtx_dir = resolved_evtx_dir
                extracted_channels = []

        # Default to DFIR_ESSENTIAL_EIDS to prevent context flooding.
        # Pass event_ids=[] explicitly to disable filtering.
        try:
            result = _ez_runner.run_evtxecmd(
                evtx_dir=staged_evtx_dir,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
                start_date=start_date,
                end_date=end_date,
                event_ids=effective_eids if effective_eids else None,
                tool_name=tool,
            )
        except Exception as exc:
            return _runner_error(tool, exc)

        if not result.ok and not Path(csv_path).exists():
            return {
                "tool_name": tool,
                "status": "error",
                "error_message": (
                    f"EvtxECmd exited with code {result.exit_code}. "
                    f"stderr: {result.stderr[:300]}"
                ),
                "data": [],
                "findings_created": [],
                "execution_id": result.execution_id,
                "raw_command": result.command_line,
                "stderr": result.stderr,
            }

        # Memory-bounded: single streaming pass over the (possibly multi-GB)
        # CSV instead of _read_csv + _build_evtx_records materializing every row.
        stream = _stream_evtx_summary(csv_path, channel=channel)
        persistent_csv = _persist_csv(csv_path, "evtx")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="EVTX CSV",
            persisted_path=persistent_csv,
            preflight=preflight,
        )

    total_records = stream["total_records"]      # raw CSV rows (matches csv_path)
    matched_records = stream["matched_records"]  # channel-matched rows (== total when channel=None)
    finding_ids = _evtx_summary_finding_ids(
        matched_records,   # the count-based finding describes matched (parsed) rows, not raw CSV size
        evtx_dir=evtx_dir,
        channel=channel,
        execution_id=result.execution_id,
    )
    sample = stream["sample"]
    detailed_records = (
        sample[:max_entries] if (max_entries and max_entries > 0) else list(sample)
    )
    response = {
        "tool_name": tool,
        "status": "success",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(detailed_records),
        "total_records": total_records,
        "matched_records": matched_records,
        # Inline `data` is a bounded head sample, never the full set -- machine-readable
        # so a consumer cannot mistake len(data) for completeness (review 2026-06-03).
        "data_truncated": matched_records > len(detailed_records),
        "data_scope": "head_sample",
        "sample_cap": _EVTX_SAMPLE_CAP,
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "requires_agent": "@evtx-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for attacker lifecycle — auth anomalies, lateral movement, persistence. {total_records} total rows."
            if durable_csv
            else "Analyze the returned EVTX summary and persisted artifacts for attacker lifecycle pivots; the CSV handle could not be persisted cleanly."
        ),
        "note": (
            f"Returning a bounded sample of {len(detailed_records)} inline rows"
            + (f"; {matched_records} matched channel '{channel}'" if channel else "")
            + f"; {total_records} rows in the full CSV at {durable_csv}."
            if durable_csv
            else (
                f"Returning a bounded sample of {len(detailed_records)} inline rows"
                + (f"; {matched_records} matched channel '{channel}'" if channel else "")
                + f"; {total_records} rows total. "
                "CSV persistence did not produce a durable analyst-facing handle; "
                'rerun summarize_evtx after fixing OUTPUT_BASE permissions before using run_analysis().'
            )
        ),
        "channel_filter": channel,
        "event_id_filter": effective_eids if effective_eids else "all",
        "event_id_strategy": event_id_strategy,
        "date_range": {
            "start": start_date,
            "end": end_date,
        } if start_date or end_date else None,
        "cache_hit": False,
        "cache_source_execution_id": None,
        "evtx_inventory": evtx_inventory_summary,
        "extracted_channels": extracted_channels,
        "channel_selection_mode": "tier_selected" if extracted_channels else "directory_passthrough",
    }
    response = _apply_response_format(
        response,
        response_format=normalized_format,
        records=detailed_records if normalized_format == "detailed" else sample,
        total_records=total_records,
    )
    if not durable_csv:
        response["status"] = "warning"
        response["warning"] = (
            "EVTX rows were parsed successfully, but the CSV output could not be persisted to a durable "
            "artifact path. The returned summary is safe to use, but run_analysis() should wait for a "
            "rerun that produces a persisted csv_path/handle.path."
        )
    response = _warn_if_empty(
        response, "summarize_evtx", evtx_dir, min_expected=100)
    if durable_csv:
        _state.cache_artifact(
            cache_key,
            {
                "source_execution_id": result.execution_id,
                "csv_path": durable_csv,
                "findings_created": finding_ids,
                "requires_agent": response.get("requires_agent"),
                "agent_instruction": response.get("agent_instruction"),
                "total_records": total_records,
                "channel_filter": channel,
                "event_id_filter": effective_eids if effective_eids else "all",
                "event_id_strategy": event_id_strategy,
                "date_range": response.get("date_range"),
            },
        )
        # F-A: stamp a corpus-manifest fingerprint sidecar so a later run (after
        # state clear) verify-and-reuses this 2.5GB CSV instead of re-parsing
        # 420 EVTX files (the parse that timed out + looped on the prior run).
        write_reuse_sidecar(durable_csv, tool_name=tool, source_path=resolved_evtx_dir)
    promote_corroborated_findings(
        _state,
        "evtx_process_creation",
        stream["process_paths"],
    )
    if "data" in response:
        response["data"] = [
            sanitize_payload_fields(record, "message_summary", "extra_fields")
            for record in response["data"]
        ]
    normalized_obs, pivots = _evtx_contract_inputs(stream)
    return _evtx_contract_payload(
        response=response,
        records=detailed_records if normalized_format == "detailed" else sample,
        image_path=image_path,
        evtx_dir=evtx_dir,
        csv_path=durable_csv,
        channel_counts=stream["channel_counts"],
        pivot_entities=pivots,
        normalized=normalized_obs,
        evidence_excerpt=stream["evidence_excerpt"],
    )


# ---------------------------------------------------------------------------
# Tool: extract_registry_run_keys
# ---------------------------------------------------------------------------


def _discover_run_keys_user_hives(image_path: str) -> list[str]:
    """Discover per-user ``NTUSER.DAT`` hives the way ``extract_registry_run_keys``
    does, as a sorted list of resolved path strings.

    Shared by ``extract_registry_run_keys`` (cache write) and
    ``extract_registry_fileaccess`` (cache read) so the ``user_hives`` slot of
    the cache key is byte-identical between the two callers. Case-agnostic: no
    profile name is ever hardcoded; non-interactive profile dirs are skipped via
    ``_NON_USER_PROFILE_DIRS``.
    """
    user_hives_found: list[str] = []
    seen: set[str] = set()
    user_roots: list[Path] = []
    seen_user_roots: set[str] = set()
    for volume_root in _candidate_windows_volume_roots(image_path):
        for users_root in (volume_root / "Users", volume_root / "Documents and Settings"):
            text = str(users_root)
            if text not in seen_user_roots:
                seen_user_roots.add(text)
                user_roots.append(users_root)
    for users_root in user_roots:
        if _path_exists(users_root) and _path_is_dir(users_root):
            try:
                children = sorted(users_root.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                continue
            for user_dir in children:
                # NOTE: preserve extract_registry_run_keys' ORIGINAL skip set
                # exactly (narrower than _NON_USER_PROFILE_DIRS) so run-keys
                # behavior is unchanged AND the cache key stays aligned.
                if _path_is_dir(user_dir) and user_dir.name not in (
                    "Public",
                    "Default",
                    "Default User",
                    "All Users",
                ):
                    ntuser = user_dir / "NTUSER.DAT"
                    if _path_exists(ntuser):
                        resolved = _resolved_path_str(str(ntuser))
                        if resolved not in seen:
                            seen.add(resolved)
                            user_hives_found.append(str(ntuser))
    return user_hives_found


def _registry_run_keys_cache_params(
    *,
    resolved_hive_dir: str,
    batch_mode: bool,
    batch_file_used: Optional[str],
    user_hives_found: list[str],
    sync_batch: bool,
    image_path: str,
) -> dict[str, Any]:
    """Build the cache-key params dict for ``disk.extract_registry_run_keys``.

    Shared between the run-keys cache write and the file-access cache read so the
    key matches exactly. ``image_path`` is included so a SECOND image in the same
    case dir produces a DIFFERENT key (provenance fix - prevents one host's CSV
    being mis-attributed to another).
    """
    return {
        "hive_dir": resolved_hive_dir,
        "batch_mode": batch_mode,
        "batch_file": batch_file_used or "",
        "user_hives": sorted(_resolved_path_str(path) for path in user_hives_found),
        "sync_batch": bool(sync_batch),
        "image_path": _resolved_path_str(image_path),
    }


# Persistence key path fragments to match (lower-case)
_PERSISTENCE_FRAGMENTS: list[tuple[str, str]] = [
    # Run keys - absolute path (NTUSER.DAT or full SOFTWARE path)
    # NOTE: runonce/runservices MUST come before run (run is a substring of them)
    ("\\software\\microsoft\\windows\\currentversion\\runonce", "runonce"),
    ("\\software\\microsoft\\windows\\currentversion\\runservices", "run"),
    ("\\software\\microsoft\\windows\\currentversion\\run", "run"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\runonce", "runonce"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\runservices", "run"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\run", "run"),
    # Run keys - hive-relative (RECmd with -d strips the hive name prefix)
    # NOTE: runonce/runservices MUST come before run (run is a substring of them)
    ("\\currentversion\\runonce", "runonce"),
    ("\\currentversion\\runservices", "run"),
    ("\\currentversion\\run", "run"),
    ("wow6432node\\microsoft\\windows\\currentversion\\runonce", "runonce"),
    ("wow6432node\\microsoft\\windows\\currentversion\\runservices", "run"),
    ("wow6432node\\microsoft\\windows\\currentversion\\run", "run"),
    # AppInit DLLs (T1546.010)
    ("appinit_dlls", "appinit_dlls"),
    # Winlogon (T1547.004)
    ("\\winlogon", "winlogon_shell"),
    ("userinit", "winlogon_userinit"),
    # Services - both absolute and hive-relative (T1543.003)
    ("\\currentcontrolset\\services\\", "services"),
    ("controlset001\\services\\", "services"),
    # LSA packages (T1547.005)
    ("lsaprotection", "lsa_package"),
    ("security packages", "lsa_package"),
    ("authentication packages", "lsa_package"),
    # Session Manager (T1547.012)
    ("session manager", "session_manager"),
    ("bootexecute", "session_manager"),
    # Browser Helper Objects (T1176)
    ("browser helper objects", "browser_helper"),
    # Credential Providers (T1547.002)
    ("credential providers", "credential_provider"),
    # Shell Extensions (T1546.015)
    ("shelliconoverlayidentifiers", "shell_extension"),
    ("shellserviceobjectdelayload", "shell_extension"),
    # Image File Execution Options - debugger hijacking (T1546.012)
    ("image file execution options", "ifeo"),
    # Scheduled Tasks (T1053.005)
    ("\\tasks\\", "scheduled_task"),
    # Active Setup / COM Server (T1547.014)
    ("active setup", "active_setup"),
    ("\\inprocserver32", "com_hijack"),
    ("\\localserver32", "com_hijack"),
    # SilentProcessExit (T1546.012)
    ("silentprocessexit", "silentprocessexit"),
    # Startup folder keys
    ("\\user shell folders", "startup_folder"),
    ("\\shell folders", "startup_folder"),
    ("startupfolder", "startup_folder"),
    # Netsh helper DLL (T1546.007)
    ("netsh\\helper", "netsh_helper"),
    # Time Provider / Print Monitor (T1547.003)
    ("time providers", "time_provider"),
    ("print processors", "print_monitor"),
    ("monitors", "print_monitor"),
]


def _classify_persistence(key_path: str) -> Optional[str]:
    """Return the persistence_type for a registry key path, or None if not persistence-related."""
    key_lower = key_path.lower()
    for fragment, ptype in _PERSISTENCE_FRAGMENTS:
        if fragment in key_lower:
            return ptype
    return None


def extract_registry_run_keys(
    image_path: str,
    hive_dir: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
    batch_mode: bool = True,
    sync_batch: bool = False,
    response_format: str = "summary",
) -> dict[str, Any]:
    """Extract Windows registry persistence keys using RECmd (EZ Tools).

    Wraps ``dotnet /opt/zimmermantools/RECmd/RECmd.dll`` on SIFT Workstation.

    By default, uses DFIRBatch mode (``--bn DFIRBatch.reb``) which targets
    40+ forensically significant registry artifact categories instead of
    dumping all keys.  Falls back to basic mode if the batch file is not found.

    Also scans user NTUSER.DAT hives (from ``Users/*/NTUSER.DAT``) in
    addition to the system hive directory, since per-user Run keys are a
    common persistence mechanism.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image.  Used to derive the default
        hive directory if *hive_dir* is not given.
    hive_dir:
        Absolute path to the directory containing registry hive files
        (e.g. ``/cases/SRL-2018/evidence/mnt/C/Windows/System32/config``).
        When ``None``, a default path is constructed from the image path.
    batch_mode:
        When ``True`` (default), uses DFIRBatch.reb for targeted extraction.
        Searches ``DFIR_BATCH_PATHS`` for the batch file.  Falls back to
        basic mode with a warning if not found.
    sync_batch:
        When ``True``, tells RECmd to download the latest batch definitions
        before running (``--sync``).  Requires network access; default
        ``False``.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of RegistryRunKey dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``, ``persistence_type_counts``, ``batch_file_used``,
        ``user_hives_scanned``.
    """
    tool = "disk.extract_registry_run_keys"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)
    if normalized_format is None:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "Invalid response_format. Use 'summary' or 'detailed'.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    hive_dir = _resolve_registry_hive_dir_input(image_path, hive_dir)
    preflight = _preflight_artifact_persistence("registry", "registry_combined.csv")
    suppressed_preflight = _preflight_artifact_persistence("registry", "registry_suppressed.csv")
    if not preflight.get("ok"):
        return _artifact_preflight_error(tool_name=tool, preflight=preflight)
    resolved_hive_dir = _resolved_path_str(hive_dir)
    if _unsafe_runtime_tmp_input(resolved_hive_dir):
        return _unsafe_path_error(
            tool,
            input_name="hive_dir",
            resolved_path=resolved_hive_dir,
            image_path=image_path,
        )
    if not Path(resolved_hive_dir).exists():
        return _path_missing_error(
            tool,
            input_name="hive_dir",
            resolved_path=resolved_hive_dir,
            image_path=image_path,
        )

    # Resolve DFIRBatch file path
    batch_file_used: Optional[str] = None
    batch_warning: Optional[str] = None
    if batch_mode:
        for candidate in DFIR_BATCH_PATHS:
            if os.path.isfile(candidate):
                batch_file_used = candidate
                break
        if batch_file_used is None:
            batch_warning = (
                "DFIRBatch.reb not found at any of: "
                + ", ".join(DFIR_BATCH_PATHS)
                + ". Falling back to basic mode (all keys). "
                "Install EZ Tools batch files or set batch_mode=False."
            )

    # Discover user NTUSER.DAT hives (shared discovery so the cache key matches
    # exactly between extract_registry_run_keys and extract_registry_fileaccess).
    user_hives_found: list[str] = _discover_run_keys_user_hives(image_path)

    cache_key = build_cache_key(
        tool,
        _registry_run_keys_cache_params(
            resolved_hive_dir=resolved_hive_dir,
            batch_mode=batch_mode,
            batch_file_used=batch_file_used,
            user_hives_found=user_hives_found,
            sync_batch=sync_batch,
            image_path=image_path,
        ),
    )
    cached = None
    if not sync_batch:
        cached = get_valid_cached_artifact(
            _state,
            cache_key,
            path_key="csv_path",
            required_keys=("csv_path", "source_execution_id"),
        )
    if cached is not None:
        rows = _read_csv(str(cached["csv_path"]))
        cache_meta = record_cache_hit(
            _audit,
            _state,
            tool_name=tool,
            parameters={
                "hive_dir": resolved_hive_dir,
                "batch_mode": batch_mode,
                "batch_file": batch_file_used,
                "sync_batch": sync_batch,
                "user_hives": user_hives_found,
            },
            cache_key=cache_key,
            artifact_path=str(cached["csv_path"]),
            cache_source_execution_id=str(
                cached.get("source_execution_id") or ""),
        )
        records, _, persistence_type_counts, grouping_meta = _build_registry_records(
            rows,
            tool=tool,
            execution_id=cache_meta["execution_id"],
            batch_file_used=batch_file_used,
            create_findings=False,
        )
        full_records = list(records)
        detailed_records = list(full_records)
        if max_entries and max_entries > 0:
            detailed_records = detailed_records[:max_entries]

        cached_response: dict[str, Any] = {
            "tool_name": tool,
            "status": "success",
            "findings_created": list(cached.get("findings_created", [])),
            "execution_id": cache_meta["execution_id"],
            "raw_command": cache_meta["raw_command"],
            "records_count": len(detailed_records),
            "total_records": len(rows),
            "csv_path": str(cached["csv_path"]),
            "note": f"Returning {len(detailed_records)} of {len(rows)} rows. Full CSV at {cached['csv_path']}.",
            "requires_agent": cached.get("requires_agent", "@registry-analyst"),
            "agent_instruction": cached.get(
                "agent_instruction",
                f"Analyze {cached['csv_path']} for persistence mechanisms, fileless malware, credential theft. {len(rows)} total rows.",
            ),
            "persistence_type_counts": persistence_type_counts,
            "batch_file_used": batch_file_used,
            "user_hives_scanned": user_hives_found,
            "cache_hit": True,
            "cache_source_execution_id": cached.get("source_execution_id"),
            "artifact_persistence": {
                "status": "durable",
                "persisted_path": str(cached["csv_path"]),
                "reason": "Cached registry CSV is available at a durable artifact path.",
                "fix_hint": None,
            },
            "suppressed_csv_path": cached.get("suppressed_csv_path"),
            "suppressed_row_count": int(cached.get("suppressed_row_count") or 0),
            "suppressed_artifact_persistence": (
                {
                    "status": "durable",
                    "persisted_path": str(cached["suppressed_csv_path"]),
                    "reason": "Cached suppressed registry CSV is available at a durable artifact path.",
                    "fix_hint": None,
                }
                if cached.get("suppressed_csv_path")
                else {
                    "status": "unavailable",
                    "persisted_path": None,
                    "reason": "No suppressed registry CSV was persisted for this cached result.",
                    "fix_hint": None,
                }
            ),
            **grouping_meta,
        }
        if cached.get("suppressed_csv_path"):
            cached_response["suppressed_handle"] = build_handle(
                kind="csv",
                path=str(cached["suppressed_csv_path"]),
                description="Persisted suppressed registry rows for read-only review.",
                tool_name="disk.extract_registry_run_keys",
            )
        if batch_warning:
            cached_response["batch_warning"] = batch_warning
        formatted = _apply_response_format(
            cached_response,
            response_format=normalized_format,
            records=detailed_records if normalized_format == "detailed" else full_records,
            total_records=len(rows),
        )
        formatted = _warn_if_empty(formatted, "extract_registry_run_keys", hive_dir)
        return _registry_contract_payload(
            response=formatted,
            records=detailed_records if normalized_format == "detailed" else full_records,
            image_path=image_path,
            hive_dir=hive_dir,
            csv_path=str(cached["csv_path"]),
            suppressed_csv_path=str(cached.get("suppressed_csv_path") or "") or None,
        )

    with tempfile.TemporaryDirectory(prefix="savvydfir_recmd_") as tmp_dir:
        csv_filename = "registry.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        # Phase 6.1 fix: clean SYSTEM/SOFTWARE/SAM/SECURITY hives with rla.exe
        # before passing to RECmd, to replay transaction logs (.LOG1/.LOG2).
        # Dirty hives produce incorrect/missing keys.
        cleaned_hive_dir = resolved_hive_dir
        system_hive_tmpdirs: list[Path] = []
        try:
            system_hive_names = ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")
            source_hives = [
                Path(resolved_hive_dir) / name
                for name in system_hive_names
                if (Path(resolved_hive_dir) / name).is_file()
            ]
            if source_hives:
                cleaned_dir = Path(tmp_dir) / "cleaned_system_hives"
                cleaned_dir.mkdir(parents=True, exist_ok=True)
                for hive_path in source_hives:
                    try:
                        cleaned_hive, h_in, h_out = _replay_hive_with_rla(
                            hive_path, hive_path.name
                        )
                        system_hive_tmpdirs.extend(
                            [d for d in (h_in, h_out) if d is not None]
                        )
                        shutil.copy2(
                            str(cleaned_hive),
                            str(cleaned_dir / hive_path.name),
                        )
                    except Exception:
                        # rla.exe failure on a single hive is non-fatal -
                        # fall back to the dirty hive AND keep its transaction
                        # logs (.LOG1/.LOG2) so RECmd can still replay them.
                        # round-5 P2-#2: prior fallback dropped logs,
                        # regressing from the original directory which had them.
                        try:
                            shutil.copy2(
                                str(hive_path),
                                str(cleaned_dir / hive_path.name),
                            )
                            for log_suffix in (".LOG1", ".LOG2"):
                                log_src = hive_path.parent / f"{hive_path.name}{log_suffix}"
                                if log_src.is_file():
                                    shutil.copy2(
                                        str(log_src),
                                        str(cleaned_dir / log_src.name),
                                    )
                        except Exception:
                            pass
                cleaned_hive_dir = str(cleaned_dir)

                # H.3 fix: Verify SYSTEM or SOFTWARE present (at least one required for persistence)
                critical_hives = ["SYSTEM", "SOFTWARE"]
                missing = [h for h in critical_hives if not (Path(cleaned_hive_dir) / h).exists()]
                if missing:
                    # Fall back to original hive_dir if it has the critical hives
                    if any((Path(resolved_hive_dir) / h).exists() for h in missing):
                        cleaned_hive_dir = resolved_hive_dir
                        data_gaps.append({
                            "artifact_family": "registry",
                            "classification": "incomplete_hive_selection",
                            "reason": f"Critical hives {missing} not in cleaned dir, using original path",
                            "lane_id": "disk_execution_persistence",
                        })
                    else:
                        # Neither cleaned nor original has them - surface warning
                        data_gaps.append({
                            "artifact_family": "registry",
                            "classification": "missing_system_hives",
                            "reason": f"SYSTEM/SOFTWARE hives not found; persistence analysis incomplete",
                            "lane_id": "disk_execution_persistence",
                        })
        except Exception:
            # Any setup failure → fall back to original hive_dir
            cleaned_hive_dir = resolved_hive_dir

        try:
            result = _ez_runner.run_recmd(
                hive_dir=cleaned_hive_dir,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
                batch_file=batch_file_used,
                sync_batch=sync_batch,
                tool_name=tool,
            )
        except Exception as exc:
            for d in system_hive_tmpdirs:
                shutil.rmtree(d, ignore_errors=True)
            return _runner_error(tool, exc)
        finally:
            for d in system_hive_tmpdirs:
                shutil.rmtree(d, ignore_errors=True)

        if not result.ok and not Path(csv_path).exists():
            return {
                "tool_name": tool,
                "status": "error",
                "error_message": (
                    f"RECmd exited with code {result.exit_code}. "
                    f"stderr: {result.stderr[:300]}"
                ),
                "data": [],
                "findings_created": [],
                "execution_id": result.execution_id,
                "raw_command": result.command_line,
                "stderr": result.stderr,
            }

        rows = _read_csv(csv_path)

        # Also scan user NTUSER.DAT hives for per-user persistence keys
        for idx, user_hive_path in enumerate(user_hives_found, start=1):
            tmp_in: Optional[Path] = None
            tmp_out: Optional[Path] = None
            user_csv = f"registry_user_{idx}.csv"
            user_csv_path = os.path.join(tmp_dir, user_csv)
            try:
                cleaned_hive, tmp_in, tmp_out = _replay_hive_with_rla(
                    Path(user_hive_path),
                    f"{Path(user_hive_path).parent.name}_{idx}",
                )
                user_result = _ez_runner.run_recmd(
                    hive_dir=str(cleaned_hive.parent),
                    csv_dir=tmp_dir,
                    csv_filename=user_csv,
                    batch_file=batch_file_used,
                    sync_batch=False,  # only sync once
                    tool_name=tool,
                )
                if user_result.ok and Path(user_csv_path).exists():
                    rows.extend(_read_csv(user_csv_path))
            except Exception:
                pass  # user hive failures are non-fatal
            finally:
                if tmp_in is not None:
                    shutil.rmtree(tmp_in, ignore_errors=True)
                if tmp_out is not None:
                    shutil.rmtree(tmp_out, ignore_errors=True)

        combined_csv_path = os.path.join(tmp_dir, "registry_combined.csv")
        if rows:
            _write_csv_rows(rows, combined_csv_path)
            persistent_csv = _persist_csv(combined_csv_path, "registry")
        else:
            persistent_csv = _persist_csv(csv_path, "registry")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="Registry CSV",
            persisted_path=persistent_csv,
            preflight=preflight,
        )

    records, finding_ids, persistence_type_counts, grouping_meta = _build_registry_records(
        rows,
        tool=tool,
        execution_id=result.execution_id,
        batch_file_used=batch_file_used,
        create_findings=True,
    )
    full_records = list(records)
    detailed_records = list(full_records)
    if max_entries and max_entries > 0:
        detailed_records = detailed_records[:max_entries]
    suppressed_rows = list(grouping_meta.pop("suppressed_rows", []))
    suppressed_csv_raw = _persist_rows_as_csv(
        suppressed_rows,
        tool_short_name="registry",
        filename="registry_suppressed.csv",
    ) if suppressed_rows else None
    if suppressed_rows:
        durable_suppressed_csv, suppressed_artifact_persistence = _finalize_artifact_persistence(
            artifact_label="Suppressed registry CSV",
            persisted_path=suppressed_csv_raw,
            preflight=suppressed_preflight,
        )
    else:
        durable_suppressed_csv = None
        suppressed_artifact_persistence = {
            "status": "unavailable",
            "persisted_path": None,
            "reason": "No suppressed registry rows were produced for this run.",
            "fix_hint": None,
        }

    response: dict[str, Any] = {
        "tool_name": tool,
        "status": "success" if durable_csv else "warning",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(detailed_records),
        "total_records": len(rows),
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "note": (
            f"Returning {len(detailed_records)} of {len(rows)} rows. Full CSV at {durable_csv}."
            if durable_csv
            else (
                f"Returning {len(detailed_records)} of {len(rows)} rows. "
                "CSV persistence did not produce a durable analyst-facing handle; "
                "fix OUTPUT_BASE and rerun extract_registry_run_keys before using run_analysis()."
            )
        ),
        "requires_agent": "@registry-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for persistence mechanisms, fileless malware, credential theft. {len(rows)} total rows."
            if durable_csv
            else (
                "Analyze the registry summary now, then rerun extract_registry_run_keys after "
                "fixing artifact persistence to obtain a reusable handle."
            )
        ),
        "persistence_type_counts": persistence_type_counts,
        "batch_file_used": batch_file_used,
        "user_hives_scanned": user_hives_found,
        "cache_hit": False,
        "cache_source_execution_id": None,
        "suppressed_csv_path": durable_suppressed_csv,
        "suppressed_row_count": len(suppressed_rows),
        "suppressed_artifact_persistence": suppressed_artifact_persistence,
        **grouping_meta,
    }
    if durable_suppressed_csv:
        response["suppressed_handle"] = build_handle(
            kind="csv",
            path=durable_suppressed_csv,
            description="Persisted suppressed registry rows for read-only review.",
            tool_name="disk.extract_registry_run_keys",
        )
    if batch_warning:
        response["batch_warning"] = batch_warning

    # Run-8 fix: when SYSTEM or SOFTWARE was missing from the hive_dir,
    # RECmd ran but produced incomplete output (e.g. SAM-only). Escalate
    # to a loud warning in the response so the agent doesn't silently
    # accept partial persistence data. Cross-check the hive_dir RECmd
    # actually used (cleaned_hive_dir).
    critical_present = []
    critical_missing = []
    try:
        for h in ("SYSTEM", "SOFTWARE"):
            if (Path(cleaned_hive_dir) / h).is_file():
                critical_present.append(h)
            else:
                critical_missing.append(h)
    except Exception:
        pass
    response["hives_present"] = critical_present
    response["hives_missing"] = critical_missing
    if critical_missing:
        response["status"] = "warning"
        response["critical_hive_warning"] = (
            f"Persistence-critical hives MISSING from {cleaned_hive_dir}: "
            f"{critical_missing}. RECmd output is incomplete — "
            f"Run keys (HKLM\\SOFTWARE\\...\\Run) and services "
            f"(HKLM\\SYSTEM\\CurrentControlSet\\Services) will be absent if "
            "SOFTWARE/SYSTEM aren't both present. Re-run extract_windows_artifacts "
            "and verify the registry/ stage dir contains both hives before retrying."
        )

    response = _apply_response_format(
        response,
        response_format=normalized_format,
        records=detailed_records if normalized_format == "detailed" else full_records,
        total_records=len(rows),
    )
    if not durable_csv:
        response["warning"] = (
            "Registry rows were parsed successfully, but the main CSV output could not be "
            "persisted to a durable artifact path."
        )

    if durable_csv:
        _state.cache_artifact(
            cache_key,
            {
                "source_execution_id": result.execution_id,
                "csv_path": durable_csv,
                "image_path": _resolved_path_str(image_path),
                "suppressed_csv_path": durable_suppressed_csv,
                "suppressed_row_count": len(suppressed_rows),
                "findings_created": finding_ids,
                "requires_agent": response.get("requires_agent"),
                "agent_instruction": response.get("agent_instruction"),
                "total_records": len(rows),
                "persistence_type_counts": persistence_type_counts,
                "batch_file_used": batch_file_used,
                "user_hives_scanned": user_hives_found,
                "batch_warning": batch_warning,
            },
        )
    response = _warn_if_empty(response, "extract_registry_run_keys", hive_dir)
    return _registry_contract_payload(
        response=response,
        records=detailed_records if normalized_format == "detailed" else full_records,
        image_path=image_path,
        hive_dir=hive_dir,
        csv_path=durable_csv,
        suppressed_csv_path=durable_suppressed_csv,
    )


# ===========================================================================
# User-activity extractors (ShellBags / LNK / Jump Lists / Browser / RegFA)
# ---------------------------------------------------------------------------
# Path-B FK-only tools: forensic guidance is injected by server.py's
# _forensic_envelope (in-house YAMLs) at the response layer; these
# tools do NOT carry an applicable_heuristics slice. CSV-passthrough design:
# the EZ tool's own CSV is read via _read_csv, tagged with provenance columns,
# merged across profiles, and persisted via _persist_rows_as_csv /
# _finalize_artifact_persistence. OPTIONAL tools - never added to a mandatory
# gate (server OS legitimately lacks Prefetch/ShellBags/etc.).
#
# Universal / case-agnostic: every user profile under BOTH ``Users/*`` and
# ``Documents and Settings/*`` is auto-discovered. No hardcoded usernames,
# dates, paths, domains, or IPs anywhere in this section.
# ===========================================================================

#: Profile directories that are never real interactive users.
_NON_USER_PROFILE_DIRS = {
    "Public",
    "Default",
    "Default User",
    "All Users",
    "DefaultAppPool",
    "systemprofile",
    "LocalService",
    "NetworkService",
}

#: Standard provenance columns added to every merged user-activity CSV row.
_PROVENANCE_COLUMNS = (
    "source_profile",
    "source_hive",
    "source_artifact_path",
    "parser_command",
    "parser_status",
)


def _user_activity_volume_roots(image_path: str) -> list[Path]:
    """Volume roots for user-profile discovery, ISOLATED to the requested image.

    Unlike :func:`_candidate_windows_volume_roots` (which prepends the shared
    ``/mnt/disk`` root for single-target tools that select ONE resolved path),
    the user-activity extractors ENUMERATE every profile across roots and merge
    them. A stale or concurrent ``/mnt/disk`` mount from another case must
    therefore never be mixed into an explicit ``image_path`` - that would
    attribute another case's ShellBags/LNK/Jump Lists/browser/NTUSER evidence to
    this case (a case-isolation failure). So: roots are derived ONLY from
    ``image_path``. When ``image_path`` does not itself resolve to a mounted
    Windows volume root, this returns an EMPTY list ``[]`` - there is NO
    ambient/shared-mount fallback, so the caller hard-fails rather than scanning
    a stale ``/mnt/disk`` from another case.
    """
    base = Path(image_path)
    explicit: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path) -> None:
        text = str(path)
        if text not in seen:
            seen.add(text)
            explicit.append(path)

    if _path_is_dir(base):
        if any(_path_exists(base / m) for m in ("Windows", "Users", "Documents and Settings")):
            _add(base)
        nested = base / "mnt" / "C"
        if any(_path_exists(nested / m) for m in ("Windows", "Users")):
            _add(nested)

    # No ambient/shared-mount fallback: if image_path did not resolve to a
    # Windows volume root, return [] so the caller hard-fails (status=error)
    # instead of scanning a stale /mnt/disk from another case.
    return explicit


def _iter_user_profile_dirs(image_path: str) -> list[tuple[str, Path]]:
    """Yield ``(profile_name, profile_dir)`` for every discoverable user profile.

    Auto-discovers profiles under BOTH ``Users/*`` and
    ``Documents and Settings/*``, ISOLATED to the requested ``image_path`` (see
    :func:`_user_activity_volume_roots` - a stale ``/mnt/disk`` is never merged
    in). Skips well-known non-interactive profile directories. Case-agnostic -
    no profile name is ever hardcoded.
    """
    seen_roots: set[str] = set()
    profiles: list[tuple[str, Path]] = []
    seen_profiles: set[str] = set()
    for volume_root in _user_activity_volume_roots(image_path):
        for users_root in (
            volume_root / "Users",
            volume_root / "Documents and Settings",
        ):
            root_text = str(users_root)
            if root_text in seen_roots:
                continue
            seen_roots.add(root_text)
            if not (_path_exists(users_root) and _path_is_dir(users_root)):
                continue
            try:
                children = sorted(users_root.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                continue
            for profile_dir in children:
                if not _path_is_dir(profile_dir):
                    continue
                if profile_dir.name in _NON_USER_PROFILE_DIRS:
                    continue
                # Dedup on the RESOLVED real path, not the symbolic path. On
                # modern Windows ``Documents and Settings`` is a junction to
                # ``Users``, so every profile (and its hives) would otherwise be
                # discovered TWICE -> RECmd runs 2x per user (wasteful + latent
                # double-count). Resolving collapses the junction to its target.
                # Preserve order: ``Users/`` is iterated first, so the canonical
                # entry wins. Fall back to the lowercased path string if the
                # filesystem cannot resolve the link (e.g. broken junction).
                try:
                    key = str(profile_dir.resolve()).lower()
                except OSError:
                    key = str(profile_dir).lower()
                if key in seen_profiles:
                    continue
                seen_profiles.add(key)
                profiles.append((profile_dir.name, profile_dir))
    return profiles


def _discover_user_hives(
    image_path: str,
    hive_relpaths: tuple[str, ...],
) -> list[tuple[str, Path, str]]:
    """Discover per-profile registry hives across all user profiles.

    Parameters
    ----------
    image_path:
        Evidence image path / mounted Windows root.
    hive_relpaths:
        Profile-relative hive locations to probe, e.g.
        ``("NTUSER.DAT", "AppData/Local/Microsoft/Windows/UsrClass.dat")``.

    Returns
    -------
    list of ``(profile_name, hive_path, rel)`` for every hive that exists.
    """
    discovered: list[tuple[str, Path, str]] = []
    for profile_name, profile_dir in _iter_user_profile_dirs(image_path):
        for rel in hive_relpaths:
            hive_path = profile_dir.joinpath(*rel.split("/"))
            if _path_exists(hive_path) and _path_is_file(hive_path):
                discovered.append((profile_name, hive_path, rel))
    return discovered


def _discover_user_dirs(
    image_path: str,
    dir_relpaths: tuple[str, ...],
) -> list[tuple[str, Path, str]]:
    """Discover per-profile directories (LNK/JumpLists/browser data roots)."""
    discovered: list[tuple[str, Path, str]] = []
    for profile_name, profile_dir in _iter_user_profile_dirs(image_path):
        for rel in dir_relpaths:
            target = profile_dir.joinpath(*rel.split("/"))
            if _path_exists(target) and _path_is_dir(target):
                discovered.append((profile_name, target, rel))
    return discovered


def _mirror_useractivity_execution_to_state(
    *,
    exec_id: str,
    tool: str,
    raw_command: str,
    parameters: Optional[dict[str, Any]],
    exit_code: int,
    duration: float,
    outputs_summary: str,
    completed_entry: Optional[dict[str, Any]],
) -> None:
    """Execution parity (review 2026-06-03, ship-blocker).

    The 5 file-access extractors call ``_audit.log_result`` directly (not via
    SafeRunner, which mirrors audit -> state at base.py:542). Without this they
    never land in ``state.executions`` for the coverage gate to read, so the
    taxonomy-conditional file-access gate (escape A) could never see "ran +
    documented absence" and would block non-Windows / mount-less cases forever.
    Mirror the runner's add_execution shape for EVERY terminal outcome, including
    ``status=error``/``no_windows_volume`` whose response early-returns elsewhere.
    """
    if _state is None:
        return
    try:
        _state.add_execution({
            "execution_id": exec_id,
            "tool_name": tool,
            "command_line": raw_command,
            "parameters": parameters or {},
            "agent_turn": getattr(_audit, "current_iteration", 1),
            "duration_seconds": round(float(duration or 0.0), 4),
            "exit_code": exit_code,
            "outputs_summary": outputs_summary,
            "iteration": getattr(_audit, "current_iteration", 1),
            "audit_completed_entry_hash": (completed_entry or {}).get("entry_hash"),
        })
    except Exception:
        pass


def _useractivity_no_volume_error(
    *,
    tool: str,
    exec_id: str,
    raw_command: str,
    started_at: float,
    image_path: str,
) -> dict[str, Any]:
    """Hard-fail response when ``image_path`` is not a mounted Windows volume root.

    The user-activity extractors enumerate+merge every profile across volume
    roots. If ``_user_activity_volume_roots(image_path)`` returns ``[]`` (the
    supplied path does not resolve to a directory containing ``Windows/`` or
    ``Users/``), there is NO ambient ``/mnt/disk`` fallback - falling back to a
    shared mount would attribute another case's evidence to this one. So we
    refuse: ``status=error`` (NOT ``artifact_absent`` - this is not a clean
    negative, it is a misconfigured input). The ``outputs_summary`` carries the
    literal ``status=error reason=no_windows_volume_at_image_path`` token and
    MUST NOT contain the substring ``artifact_absent`` (hooks substring-match it).
    """
    summary = (
        "status=error reason=no_windows_volume_at_image_path: image_path "
        f"({image_path}) does not resolve to a mounted Windows volume root; "
        "refusing ambient /mnt/disk fallback to avoid cross-case contamination."
    )
    if _audit is not None:
        _nv_duration = time.monotonic() - started_at
        _nv_completed = _audit.log_result(
            execution_id=exec_id,
            exit_code=1,
            duration=_nv_duration,
            outputs_summary=summary,
            finding_ids=[],
            tool_name=tool,
            command_line=raw_command,
            parameters={"image_path": image_path},
        )
        # Parity: this status=error path must still land in state.executions so
        # the gate reads "ran + documented absence (no_windows_volume)", not "never run".
        _mirror_useractivity_execution_to_state(
            exec_id=exec_id, tool=tool, raw_command=raw_command,
            parameters={"image_path": image_path}, exit_code=1,
            duration=_nv_duration, outputs_summary=summary, completed_entry=_nv_completed,
        )
    return {
        "tool_name": tool,
        "status": "error",
        "execution_id": exec_id,
        "raw_command": raw_command,
        "error": (
            "image_path does not resolve to a mounted Windows volume root "
            "(expected a directory containing Windows/ or Users/); refusing to "
            "fall back to an ambient /mnt/disk mount to avoid cross-case "
            "evidence contamination."
        ),
        "reason": "no_windows_volume_at_image_path",
        "csv_path": None,
        "records_count": 0,
        "total_rows": 0,
        "profiles_checked": [],
        "profiles_with_data": [],
        "parser_failures": [],
        "findings_created": [],
        "preview": [],
    }


def _useractivity_zero_row_response(
    *,
    tool: str,
    exec_id: str,
    raw_command: str,
    started_at: float,
    profiles_checked: list[str],
    parser_failures: list[dict[str, Any]],
    artifact_label: str,
    discovered: bool,
) -> dict[str, Any]:
    """Zero-row response + audit row for user-activity tools (4-way taxonomy).

    A failed collection MUST NOT masquerade as "no evidence exists" (false
    negative). The response ``status`` branches on whether anything was
    discovered and whether any parser/query failures were recorded:

    * ``not discovered``               -> ``artifact_absent`` (exit_code 0).
      Nothing to collect existed (no hives/dirs/DBs found). True negative.
    * ``discovered`` + ``parser_failures`` -> ``collection_failed`` (exit_code 1).
      Evidence existed but the collection FAILED; absence is NOT proven.
      The ``outputs_summary`` MUST NOT contain ``artifact_absent`` (hooks
      substring-match it) so a failed run is never read as a clean negative.
    * ``discovered`` + no failures     -> ``no_data`` (exit_code 0).
      Evidence existed, parsed cleanly, yielded zero rows. Honest negative.

    The success (rows present) branch lives in ``_finalize_useractivity_response``.
    """
    if not discovered:
        status = "artifact_absent"
        exit_code = 0
        summary = (
            f"status=artifact_absent: no {artifact_label} discovered across "
            f"{len(profiles_checked)} profile(s)."
        )
    elif parser_failures:
        status = "collection_failed"
        exit_code = 1
        # MUST NOT contain the substring ``artifact_absent`` (constraint 2).
        summary = (
            f"status=collection_failed: {artifact_label} discovered but "
            f"{len(parser_failures)} parser/query failure(s) across "
            f"{len(profiles_checked)} profile(s); zero rows collected - "
            "absence is NOT evidence of absence."
        )
    else:
        status = "no_data"
        exit_code = 0
        summary = (
            f"status=no_data: {artifact_label} discovered and parsed cleanly "
            f"across {len(profiles_checked)} profile(s) but yielded zero rows."
        )

    if _audit is not None:
        _zr_duration = time.monotonic() - started_at
        _zr_completed = _audit.log_result(
            execution_id=exec_id,
            exit_code=exit_code,
            duration=_zr_duration,
            outputs_summary=summary,
            finding_ids=[],
            tool_name=tool,
            command_line=raw_command,
            parameters={"profiles_checked": profiles_checked},
        )
        # Parity: zero-row outcomes (artifact_absent / no_data / collection_failed)
        # must land in state.executions so the gate can read the status token.
        _mirror_useractivity_execution_to_state(
            exec_id=exec_id, tool=tool, raw_command=raw_command,
            parameters={"profiles_checked": profiles_checked}, exit_code=exit_code,
            duration=_zr_duration, outputs_summary=summary, completed_entry=_zr_completed,
        )
    return {
        "tool_name": tool,
        "status": status,
        "execution_id": exec_id,
        "raw_command": raw_command,
        "csv_path": None,
        "records_count": 0,
        "total_rows": 0,
        "truncated": False,
        "profiles_checked": profiles_checked,
        "profiles_with_data": [],
        "parser_failures": parser_failures,
        "findings_created": [],
        "preview": [],
        "note": summary,
    }


def _finalize_useractivity_response(
    *,
    tool: str,
    exec_id: str,
    raw_command: str,
    started_at: float,
    rows: list[dict[str, Any]],
    profiles_checked: list[str],
    profiles_with_data: list[str],
    parser_failures: list[dict[str, Any]],
    tool_short_name: str,
    csv_filename: str,
    finding_factory,
    max_entries: int,
    preview_cap: int = 10,
) -> dict[str, Any]:
    """Persist rows + build the standard user-activity response contract.

    ``finding_factory`` is a callable ``(durable_csv, total_rows) -> Finding``
    invoked only when rows are present, so each tool words its own defensible
    OBSERVATION finding.
    """
    total_rows = len(rows)
    truncated = bool(max_entries and max_entries > 0 and total_rows > max_entries)

    persistent_csv = _persist_rows_as_csv(
        rows,
        tool_short_name=tool_short_name,
        filename=csv_filename,
    )
    durable_csv, artifact_persistence = _finalize_artifact_persistence(
        artifact_label=f"{tool_short_name} CSV",
        persisted_path=persistent_csv,
        preflight=None,
    )

    finding_ids: list[str] = []
    if rows and finding_factory is not None and _state is not None:
        try:
            finding = finding_factory(durable_csv, total_rows)
            if finding is not None:
                finding_ids.append(_state.add_finding(finding.model_dump(mode="json")))
        except Exception:
            pass

    # Honor a caller-supplied max_entries cap on the preview as well as the
    # hard preview_cap. The durable CSV stays full-size; only the in-response
    # preview is bounded by min(preview_cap, max_entries).
    preview_limit = min(preview_cap, max_entries) if (max_entries and max_entries > 0) else preview_cap
    preview = rows[:preview_limit]

    # Status taxonomy: a discovered source that FAILED to parse is a PARTIAL
    # collection, not a clean success - the CSV is missing the failed source's
    # evidence and a downstream gate/scorer must see that gap rather than read
    # it as "no activity". parser_failures DOMINATES the persistence `warning`:
    # an incomplete collection that ALSO failed to persist is still primarily a
    # collection gap (exit 1), and the persistence problem is surfaced alongside
    # it via artifact_persistence / warning / note (review 2026-06-02).
    failed_sources = [
        str(f.get("profile") or f.get("artifact") or f.get("source") or "?")
        for f in parser_failures
    ]

    if parser_failures:
        status = "partial_collection"
        audit_exit = 1
    elif not durable_csv:
        status = "warning"
        audit_exit = 0
    else:
        status = "success"
        audit_exit = 0

    if parser_failures and not durable_csv:
        note = (
            f"PARTIAL COLLECTION + PERSISTENCE FAILURE: {total_rows} rows merged "
            f"across {len(profiles_with_data)} profile(s), but {len(parser_failures)} "
            f"source(s) FAILED to parse and are MISSING: {', '.join(failed_sources)} "
            f"(treat as a collection gap, NOT 'no activity'); ADDITIONALLY the CSV "
            f"could not be persisted to a durable path - fix OUTPUT_BASE and rerun."
        )
    elif parser_failures:
        note = (
            f"PARTIAL COLLECTION: {total_rows} rows merged across "
            f"{len(profiles_with_data)} profile(s), but {len(parser_failures)} "
            f"source(s) FAILED to parse and are MISSING from the CSV: "
            f"{', '.join(failed_sources)}. Treat their absence as a collection "
            f"gap, NOT as 'no activity'. Full data at {durable_csv}."
        )
    elif not durable_csv:
        note = (
            f"{total_rows} rows parsed but CSV could not be persisted to a durable "
            "path; fix OUTPUT_BASE and rerun."
        )
    else:
        note = (
            f"{total_rows} rows merged across {len(profiles_with_data)} profile(s). "
            f"Full data at {durable_csv}. Preview capped at {preview_limit}."
        )

    response: dict[str, Any] = {
        "tool_name": tool,
        "status": status,
        "execution_id": exec_id,
        "raw_command": raw_command,
        "csv_path": durable_csv,
        "records_count": total_rows,
        "total_rows": total_rows,
        "truncated": truncated,
        "profiles_checked": profiles_checked,
        "profiles_with_data": profiles_with_data,
        "parser_failures": parser_failures,
        "partial_failure_count": len(parser_failures),
        "findings_created": finding_ids,
        "preview": preview,
        "artifact_persistence": artifact_persistence,
        "note": note,
    }
    if not durable_csv:
        response["warning"] = (
            f"Rows were parsed but the {tool_short_name} CSV could not be persisted "
            "to a durable analyst-facing path."
        )

    if _audit is not None:
        _fz_duration = time.monotonic() - started_at
        _fz_summary = (
            f"status={status} merged {total_rows} rows from "
            f"{len(profiles_with_data)} profile(s); "
            f"{len(parser_failures)} parser failure(s)"
            + (f" [{', '.join(failed_sources)}]" if parser_failures else "")
        )
        _fz_completed = _audit.log_result(
            execution_id=exec_id,
            exit_code=audit_exit,
            duration=_fz_duration,
            outputs_summary=_fz_summary,
            finding_ids=finding_ids,
            tool_name=tool,
            command_line=raw_command,
            parameters={"profiles_checked": profiles_checked},
        )
        # Parity: success / partial_collection outcomes also land in state.executions.
        _mirror_useractivity_execution_to_state(
            exec_id=exec_id, tool=tool, raw_command=raw_command,
            parameters={"profiles_checked": profiles_checked}, exit_code=audit_exit,
            duration=_fz_duration, outputs_summary=_fz_summary, completed_entry=_fz_completed,
        )
    return response


def _tag_provenance(
    rows: list[dict[str, str]],
    *,
    source_profile: str,
    source_hive: str,
    source_artifact_path: str,
    parser_command: str,
    parser_status: str,
) -> list[dict[str, Any]]:
    """Add the 5 standard provenance columns to each EZ-tool CSV row."""
    tagged: list[dict[str, Any]] = []
    for row in rows:
        merged = dict(row)
        merged["source_profile"] = source_profile
        merged["source_hive"] = source_hive
        merged["source_artifact_path"] = source_artifact_path
        merged["parser_command"] = parser_command
        merged["parser_status"] = parser_status
        tagged.append(merged)
    return tagged


# ---------------------------------------------------------------------------
# Tool: extract_shellbags (SBECmd)
# ---------------------------------------------------------------------------

def extract_shellbags(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract Windows ShellBags (folder navigation) per user profile via SBECmd.

    Discovers ``UsrClass.dat`` and ``NTUSER.DAT`` for every profile under
    ``Users/*`` and ``Documents and Settings/*``, replays transaction logs
    with rla.exe, runs SBECmd per hive, merges the per-hive CSVs, and tags
    each row with provenance columns.

    A ShellBag proves Explorer RENDERED a folder - NOT that files inside it
    were opened or read. Corroborate with LNK / Jump Lists / RecentDocs.

    image_path MUST be a mounted Windows volume root (e.g. /mnt/disk or
    /mnt/windows_mount after mount_image); a path that is not a Windows volume
    returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_shellbags"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    hives = _discover_user_hives(
        image_path,
        (
            "AppData/Local/Microsoft/Windows/UsrClass.dat",
            "NTUSER.DAT",
        ),
    )
    # Absence matrix: ALWAYS list every discovered profile, not only the ones
    # that yielded this artifact - profiles_with_data tracks coverage separately.
    profiles_checked = sorted({name for name, _ in _iter_user_profile_dirs(image_path)})

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "SBECmd.dll -d <per-profile-hive-dir> --csv <tmp>"
    _audit.log_execution(
        execution_id=exec_id,
        tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not hives:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="ShellBag hives (UsrClass.dat/NTUSER.DAT)",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    parser_failures: list[dict[str, Any]] = []
    tmp_dirs: list[Path] = []
    try:
        for profile_name, hive_path, rel in hives:
            replay_in: Optional[Path] = None
            replay_out: Optional[Path] = None
            replay_ok = True
            replay_reason: Optional[str] = None
            # ``hive_dir`` MUST be a directory holding ONLY this hive - never
            # ``hive_path.parent`` (the live profile dir). On a clean/successful
            # replay that is the rla temp out dir. On a replay RAISE the temp
            # dirs were already cleaned, so stage the lone hive into a fresh
            # temp dir and parse THAT.
            hive_dir: Optional[str] = None
            try:
                cleaned_hive, replay_in, replay_out, replay_ok = _replay_hive_with_rla(
                    hive_path, f"{profile_name}_{hive_path.name}", want_status=True
                )
                hive_dir = str(Path(cleaned_hive).parent)
                if not replay_ok:
                    replay_reason = "rla_nonzero"
            except Exception as exc:
                # Replay RAISED: do NOT fall back to hive_path (its parent is the
                # profile dir). Stage just this hive into a fresh single-hive dir.
                replay_ok = False
                replay_reason = type(exc).__name__
                staged = Path(tempfile.mkdtemp(prefix="savvydfir_sbe_stage_"))
                tmp_dirs.append(staged)
                try:
                    shutil.copy2(str(hive_path), str(staged / hive_path.name))
                except Exception:
                    pass
                hive_dir = str(staged)
            csv_out = Path(tempfile.mkdtemp(prefix="savvydfir_sbe_"))
            tmp_dirs.append(csv_out)
            status = "ok"
            try:
                result = _ez_runner.run_sbecmd(
                    hive_dir=hive_dir,
                    csv_dir=str(csv_out),
                    tool_name=tool,
                )
                if not result.ok:
                    status = f"parser_error:{_ez_runner.classify_error(result)}"
            except Exception as exc:
                status = f"exception:{type(exc).__name__}"
            finally:
                if replay_in is not None:
                    shutil.rmtree(replay_in, ignore_errors=True)
                if replay_out is not None:
                    shutil.rmtree(replay_out, ignore_errors=True)

            # A failed replay is a collection gap even if the parser salvages
            # rows from the unreplayed base hive: stamp the rows non-ok so they
            # are not tagged "ok", and record a parser_failure below.
            if not replay_ok and status == "ok":
                status = "replay_error"
            profile_rows: list[dict[str, str]] = []
            for produced in sorted(csv_out.glob("*.csv")):
                profile_rows.extend(_read_csv(str(produced)))
            if profile_rows:
                merged_rows.extend(_tag_provenance(
                    profile_rows,
                    source_profile=profile_name,
                    source_hive=hive_path.name,
                    source_artifact_path=str(hive_path),
                    parser_command="SBECmd",
                    parser_status=status,
                ))
                profiles_with_data.add(profile_name)
            # A non-ok run is a collection gap REGARDLESS of salvage: record it so
            # the response cannot read as a clean success. recovered_rows lets an
            # analyst distinguish "failed empty" from "failed with partial salvage".
            if not replay_ok:
                parser_failures.append(
                    {
                        "profile": profile_name,
                        "hive": str(hive_path),
                        "status": "replay_error",
                        "reason": replay_reason or "rla_nonzero",
                        "recovered_rows": len(profile_rows),
                    }
                )
            elif status != "ok":
                parser_failures.append(
                    {
                        "profile": profile_name,
                        "hive": str(hive_path),
                        "status": status,
                        "reason": "sbecmd_nonzero_or_error",
                        "recovered_rows": len(profile_rows),
                    }
                )
    finally:
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    if not merged_rows:
        # Hives were discovered (else we returned above) - zero rows is
        # ``no_data`` if parsing was clean, ``collection_failed`` if not.
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures, artifact_label="ShellBag entries",
            discovered=True,
        )

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="disk",
            artifact_path=durable_csv or str(hives[0][1]),
            tool_name=tool,
            execution_id=exec_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"ShellBags: parsed {total_rows} BagMRU entries across "
                f"{len(profiles_with_data)} profile(s). A ShellBag indicates Explorer "
                "RENDERED the folder, NOT that files inside were opened or read; "
                "corroborate with LNK files / Jump Lists / RecentDocs."
            ),
            supporting_indicators=sorted(profiles_with_data)[:20],
        )

    return _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="shellbags", csv_filename="shellbags.csv",
        finding_factory=_finding, max_entries=max_entries,
    )


# ---------------------------------------------------------------------------
# Tool: extract_lnk_files (LECmd)
# ---------------------------------------------------------------------------

def extract_lnk_files(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract LNK shortcut metadata per user profile via LECmd.

    Discovers each profile's ``AppData/Roaming/Microsoft/Windows/Recent``
    directory, runs LECmd recursively, merges per-profile CSVs, and tags
    provenance. A LNK file records that a target was referenced/navigated -
    corroborate with ShellBags + RecentDocs for file-open intent.

    image_path MUST be a mounted Windows volume root (e.g. /mnt/disk or
    /mnt/windows_mount after mount_image); a path that is not a Windows volume
    returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_lnk_files"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    dirs = _discover_user_dirs(
        image_path,
        ("AppData/Roaming/Microsoft/Windows/Recent",),
    )
    # Absence matrix: ALWAYS list every discovered profile (see shellbags note).
    profiles_checked = sorted({name for name, _ in _iter_user_profile_dirs(image_path)})

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "LECmd.dll -d <per-profile-Recent> --csv <tmp> --all -q"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not dirs:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="Recent (LNK) directories",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    parser_failures: list[dict[str, Any]] = []
    tmp_dirs: list[Path] = []
    try:
        for idx, (profile_name, target_dir, rel) in enumerate(dirs, start=1):
            csv_out = Path(tempfile.mkdtemp(prefix="savvydfir_lecmd_"))
            tmp_dirs.append(csv_out)
            csv_name = f"lnk_{idx}.csv"
            status = "ok"
            try:
                result = _ez_runner.run_lecmd(
                    target_dir=str(target_dir), csv_dir=str(csv_out),
                    csv_filename=csv_name, tool_name=tool,
                )
                if not result.ok:
                    status = f"parser_error:{_ez_runner.classify_error(result)}"
            except Exception as exc:
                status = f"exception:{type(exc).__name__}"
            profile_rows: list[dict[str, str]] = []
            for produced in sorted(csv_out.glob("*.csv")):
                profile_rows.extend(_read_csv(str(produced)))
            if profile_rows:
                merged_rows.extend(_tag_provenance(
                    profile_rows, source_profile=profile_name,
                    source_hive="", source_artifact_path=str(target_dir),
                    parser_command="LECmd", parser_status=status,
                ))
                profiles_with_data.add(profile_name)
            # A non-ok run is a collection gap REGARDLESS of salvage (see shellbags).
            if status != "ok":
                parser_failures.append(
                    {
                        "profile": profile_name,
                        "dir": str(target_dir),
                        "status": status,
                        "reason": "lecmd_nonzero_or_error",
                        "recovered_rows": len(profile_rows),
                    }
                )
    finally:
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    if not merged_rows:
        # Recent dirs were discovered (else returned above).
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures, artifact_label="LNK shortcut files",
            discovered=True,
        )

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="other", artifact_type="disk",
            artifact_path=durable_csv or str(dirs[0][1]), tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"LNK files: parsed {total_rows} shortcuts across "
                f"{len(profiles_with_data)} profile(s). A LNK records that a target "
                "path was referenced, NOT that a human clicked it; corroborate with "
                "ShellBags + RecentDocs + Prefetch for open/execution intent."
            ),
            supporting_indicators=sorted(profiles_with_data)[:20],
        )

    return _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="lnk_files", csv_filename="lnk_files.csv",
        finding_factory=_finding, max_entries=max_entries,
    )


# ---------------------------------------------------------------------------
# Tool: extract_jump_lists (JLECmd)
# ---------------------------------------------------------------------------

def extract_jump_lists(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract Jump Lists per user profile via JLECmd.

    Discovers each profile's ``AutomaticDestinations`` and
    ``CustomDestinations`` directories, runs JLECmd recursively, merges
    per-profile CSVs, tags provenance. Jump Lists tie a target file to the
    application (AppId) that opened it.

    image_path MUST be a mounted Windows volume root (e.g. /mnt/disk or
    /mnt/windows_mount after mount_image); a path that is not a Windows volume
    returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_jump_lists"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    dirs = _discover_user_dirs(
        image_path,
        (
            "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
            "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations",
        ),
    )
    # Absence matrix: ALWAYS list every discovered profile (see shellbags note).
    profiles_checked = sorted({name for name, _ in _iter_user_profile_dirs(image_path)})

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "JLECmd.dll -d <per-profile-Destinations> --csv <tmp> --all -q"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not dirs:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="Jump List destination directories",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    parser_failures: list[dict[str, Any]] = []
    tmp_dirs: list[Path] = []
    try:
        for idx, (profile_name, target_dir, rel) in enumerate(dirs, start=1):
            csv_out = Path(tempfile.mkdtemp(prefix="savvydfir_jlecmd_"))
            tmp_dirs.append(csv_out)
            csv_name = f"jl_{idx}.csv"
            status = "ok"
            try:
                result = _ez_runner.run_jlecmd(
                    target_dir=str(target_dir), csv_dir=str(csv_out),
                    csv_filename=csv_name, tool_name=tool,
                )
                if not result.ok:
                    status = f"parser_error:{_ez_runner.classify_error(result)}"
            except Exception as exc:
                status = f"exception:{type(exc).__name__}"
            profile_rows: list[dict[str, str]] = []
            for produced in sorted(csv_out.glob("*.csv")):
                profile_rows.extend(_read_csv(str(produced)))
            if profile_rows:
                merged_rows.extend(_tag_provenance(
                    profile_rows, source_profile=profile_name,
                    source_hive="", source_artifact_path=str(target_dir),
                    parser_command="JLECmd", parser_status=status,
                ))
                profiles_with_data.add(profile_name)
            # A non-ok run is a collection gap REGARDLESS of salvage (see shellbags).
            if status != "ok":
                parser_failures.append(
                    {
                        "profile": profile_name,
                        "dir": str(target_dir),
                        "status": status,
                        "reason": "jlecmd_nonzero_or_error",
                        "recovered_rows": len(profile_rows),
                    }
                )
    finally:
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    if not merged_rows:
        # Destination dirs were discovered (else returned above).
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures, artifact_label="Jump List entries",
            discovered=True,
        )

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="other", artifact_type="disk",
            artifact_path=durable_csv or str(dirs[0][1]), tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"Jump Lists: parsed {total_rows} destination entries across "
                f"{len(profiles_with_data)} profile(s). A Jump List ties a target "
                "file to the application (AppId) that referenced it; corroborate with "
                "LNK + ShellBags before asserting a human opened the file."
            ),
            supporting_indicators=sorted(profiles_with_data)[:20],
        )

    return _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="jump_lists", csv_filename="jump_lists.csv",
        finding_factory=_finding, max_entries=max_entries,
    )


# ---------------------------------------------------------------------------
# Tool: extract_browser_history (native sqlite3)
# ---------------------------------------------------------------------------

def _webkit_to_iso(value: str) -> str:
    """Convert a Chromium WebKit timestamp (micros since 1601-01-01) to UTC ISO."""
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return ""
    if micros <= 0:
        return ""
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=micros)).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _gecko_to_iso(value: str) -> str:
    """Convert a Firefox/Gecko timestamp (micros since 1970-01-01) to UTC ISO."""
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return ""
    if micros <= 0:
        return ""
    try:
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _copy_sqlite_db(db_path: Path, dest_dir: Path) -> Path:
    """Copy a sqlite DB + its -wal/-shm sidecars into ``dest_dir`` (locks)."""
    dest = dest_dir / db_path.name
    shutil.copy2(str(db_path), str(dest))
    for suffix in ("-wal", "-shm"):
        sidecar = db_path.parent / (db_path.name + suffix)
        if _path_exists(sidecar) and _path_is_file(sidecar):
            try:
                shutil.copy2(str(sidecar), str(dest_dir / sidecar.name))
            except OSError:
                pass
    return dest


def _query_chromium_history(
    db_copy: Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """Return ``(visit_rows, download_rows, query_errors)`` from a Chromium DB.

    A DB that connects but whose queries fail (schema drift, corruption,
    encryption) yields zero rows AND a populated ``query_errors`` list so the
    caller can distinguish "connected, parsed cleanly, no rows" (``no_data``)
    from "connected, queries failed" (``collection_failed``) - the latter must
    never be reported as ``artifact_absent``.
    """
    import sqlite3
    visits: list[dict[str, str]] = []
    downloads: list[dict[str, str]] = []
    query_errors: list[dict[str, str]] = []
    conn = sqlite3.connect(f"file:{db_copy}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        try:
            for r in conn.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls"
            ):
                visits.append({
                    "record_type": "visit",
                    "url": str(r["url"] or ""),
                    "title": str(r["title"] or ""),
                    "visit_count": str(r["visit_count"] or ""),
                    "timestamp_utc": _webkit_to_iso(str(r["last_visit_time"] or "")),
                    "target_path": "",
                    "total_bytes": "",
                })
        except sqlite3.Error as exc:
            query_errors.append({
                "db": str(db_copy), "query": "chromium.urls",
                "error": f"{type(exc).__name__}: {exc}",
            })
        try:
            for r in conn.execute(
                "SELECT target_path, total_bytes, start_time, tab_url FROM downloads"
            ):
                downloads.append({
                    "record_type": "download",
                    "url": str(r["tab_url"] or ""),
                    "title": "",
                    "visit_count": "",
                    "timestamp_utc": _webkit_to_iso(str(r["start_time"] or "")),
                    "target_path": str(r["target_path"] or ""),
                    "total_bytes": str(r["total_bytes"] or ""),
                })
        except sqlite3.Error as exc:
            query_errors.append({
                "db": str(db_copy), "query": "chromium.downloads",
                "error": f"{type(exc).__name__}: {exc}",
            })
    finally:
        conn.close()
    return visits, downloads, query_errors


def _query_firefox_history(
    db_copy: Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return ``(rows, query_errors)`` from a Firefox places.sqlite copy.

    See ``_query_chromium_history`` for the query_errors contract: a connected
    DB whose queries fail must surface those failures so the caller never
    reports a failed collection as ``artifact_absent``.
    """
    import sqlite3
    rows: list[dict[str, str]] = []
    query_errors: list[dict[str, str]] = []
    conn = sqlite3.connect(f"file:{db_copy}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        try:
            for r in conn.execute(
                "SELECT url, title, visit_count, last_visit_date FROM moz_places"
            ):
                rows.append({
                    "record_type": "visit",
                    "url": str(r["url"] or ""),
                    "title": str(r["title"] or ""),
                    "visit_count": str(r["visit_count"] or ""),
                    "timestamp_utc": _gecko_to_iso(str(r["last_visit_date"] or "")),
                    "target_path": "",
                    "total_bytes": "",
                })
        except sqlite3.Error as exc:
            query_errors.append({
                "db": str(db_copy), "query": "firefox.moz_places",
                "error": f"{type(exc).__name__}: {exc}",
            })
        # Firefox downloads: moz_annos annotation 'downloads/destinationFileURI'
        try:
            for r in conn.execute(
                "SELECT p.url AS url, a.content AS dest, a.dateAdded AS dateadded "
                "FROM moz_annos a JOIN moz_places p ON p.id = a.place_id "
                "JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id "
                "WHERE attr.name = 'downloads/destinationFileURI'"
            ):
                rows.append({
                    "record_type": "download",
                    "url": str(r["url"] or ""),
                    "title": "",
                    "visit_count": "",
                    "timestamp_utc": _gecko_to_iso(str(r["dateadded"] or "")),
                    "target_path": str(r["dest"] or ""),
                    "total_bytes": "",
                })
        except sqlite3.Error as exc:
            query_errors.append({
                "db": str(db_copy), "query": "firefox.moz_annos",
                "error": f"{type(exc).__name__}: {exc}",
            })
    finally:
        conn.close()
    return rows, query_errors


def extract_browser_history(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract Chromium (Chrome/Edge) + Firefox history & downloads per profile.

    Uses the Python ``sqlite3`` stdlib (NOT an EZ tool). For every user
    profile, auto-detects Chrome/Edge ``History`` and Firefox ``places.sqlite``
    DBs (including sub-profiles like ``Default`` / ``Profile N``), copies the
    DB plus ``-wal``/``-shm`` sidecars to a tmp dir to avoid lock issues, and
    queries URL history (last-visit summary from ``urls`` / ``moz_places``,
    not a full per-visit timeline from ``visits`` / ``moz_historyvisits``) and
    downloads. Each DB is wrapped in try/except so one corrupt DB never aborts
    the tool. Timestamps are normalized to UTC ISO.

    ``max_entries`` caps only the in-response ``preview``; the FULL row set is
    always written to the durable CSV (``truncated`` flags when rows exceed it).

    A history/download record proves the BROWSER PROCESS recorded the event,
    NOT that a specific human initiated it; synced history can originate on
    another device.

    image_path MUST be a mounted Windows volume root (e.g. /mnt/disk or
    /mnt/windows_mount after mount_image); a path that is not a Windows volume
    returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_browser_history"
    if _state is None or _audit is None:
        return _not_initialised(tool)

    # (browser_label, profile_glob_root, db_filename, kind, sub_glob)
    chromium_specs = (
        ("chrome", "AppData/Local/Google/Chrome/User Data", "History"),
        ("edge", "AppData/Local/Microsoft/Edge/User Data", "History"),
    )
    firefox_spec = ("firefox", "AppData/Roaming/Mozilla/Firefox/Profiles", "places.sqlite")

    discovered: list[tuple[str, str, Path]] = []  # (profile, browser, db_path)
    profiles_all = _iter_user_profile_dirs(image_path)
    for profile_name, profile_dir in profiles_all:
        for browser, root_rel, db_name in chromium_specs:
            user_data = profile_dir.joinpath(*root_rel.split("/"))
            if not (_path_exists(user_data) and _path_is_dir(user_data)):
                continue
            # Chromium sub-profiles: Default, Profile 1, Profile 2, ...
            try:
                sub_dirs = [d for d in user_data.iterdir() if _path_is_dir(d)]
            except OSError:
                sub_dirs = []
            for sub in sub_dirs:
                db_path = sub / db_name
                if _path_exists(db_path) and _path_is_file(db_path):
                    discovered.append((profile_name, f"{browser}:{sub.name}", db_path))
        # Firefox profiles
        ff_browser, ff_root_rel, ff_db = firefox_spec
        ff_root = profile_dir.joinpath(*ff_root_rel.split("/"))
        if _path_exists(ff_root) and _path_is_dir(ff_root):
            try:
                ff_subs = [d for d in ff_root.iterdir() if _path_is_dir(d)]
            except OSError:
                ff_subs = []
            for sub in ff_subs:
                db_path = sub / ff_db
                if _path_exists(db_path) and _path_is_file(db_path):
                    discovered.append((profile_name, f"{ff_browser}:{sub.name}", db_path))

    profiles_checked = sorted({name for name, _ in profiles_all})

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "sqlite3(ro) Chromium urls/downloads + Firefox moz_places/moz_annos"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not discovered:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="browser history databases",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    parser_failures: list[dict[str, Any]] = []
    for profile_name, browser, db_path in discovered:
        status = "ok"
        tmp_dir = Path(tempfile.mkdtemp(prefix="savvydfir_browser_"))
        try:
            db_copy = _copy_sqlite_db(db_path, tmp_dir)
            if browser.startswith("firefox"):
                rows, query_errors = _query_firefox_history(db_copy)
            else:
                visits, downloads, query_errors = _query_chromium_history(db_copy)
                rows = visits + downloads
            # A DB that connects but whose queries fail is a COLLECTION failure,
            # not absence of evidence. A genuine query_error (e.g. "no such
            # table") appends to query_errors; a query that succeeds with 0 rows
            # (legitimately-empty/present table) does NOT - so an empty-but-present
            # table keeps status="ok" and produces no parser_failure. Only a
            # NON-EMPTY query_errors flips this DB's status to a non-ok token so
            # the salvaged rows from it are stamped non-ok by _tag_provenance,
            # matching the EZ/RECmd/ShellBag/LNK/Jump salvage parity.
            if query_errors:
                status = "query_error:partial"
        except Exception as exc:
            status = f"exception:{type(exc).__name__}"
            rows = []
            query_errors = []
            parser_failures.append(
                {"profile": profile_name, "browser": browser,
                 "db": str(db_path), "status": status,
                 "reason": f"{type(exc).__name__}", "recovered_rows": 0}
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if rows:
            for r in rows:
                r["browser"] = browser.split(":", 1)[0]
                r["profile"] = browser
            merged_rows.extend(_tag_provenance(
                rows, source_profile=profile_name, source_hive="",
                source_artifact_path=str(db_path),
                parser_command=f"sqlite3:{browser.split(':',1)[0]}",
                parser_status=status,
            ))
            profiles_with_data.add(profile_name)
        # ONE consolidated parser_failure per DB whose queries genuinely errored
        # (status flipped non-ok above), matching the EZ/RECmd entry shape and
        # carrying recovered_rows = rows salvaged from THIS DB. The except-branch
        # already recorded its own failure (and cleared query_errors), so this
        # only fires for the connected-but-partial-query-failure path.
        if query_errors:
            reason = "; ".join(
                f"{qe.get('query', '')}:{qe.get('error', '')}" for qe in query_errors
            ) or "browser_query_error"
            parser_failures.append(
                {"profile": profile_name, "browser": browser,
                 "db": str(db_path), "status": status,
                 "reason": reason, "recovered_rows": len(rows)}
            )

    if not merged_rows:
        # DBs were discovered (else returned above) - zero rows is no_data if
        # all queries ran cleanly, collection_failed if any DB failed to parse.
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures, artifact_label="browser history records",
            discovered=True,
        )

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="other", artifact_type="disk",
            artifact_path=durable_csv or str(discovered[0][2]), tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"Browser history: parsed {total_rows} visit/download records across "
                f"{len(profiles_with_data)} profile(s). A record proves the browser "
                "PROCESS logged the event, NOT that a specific human initiated it; "
                "synced history may originate on another device. Normalize to UTC and "
                "corroborate downloads with $MFT / Prefetch before asserting execution."
            ),
            supporting_indicators=sorted(profiles_with_data)[:20],
        )

    return _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="browser", csv_filename="browser_history.csv",
        finding_factory=_finding, max_entries=max_entries,
    )


# ---------------------------------------------------------------------------
# Tool: extract_registry_fileaccess (per-profile NTUSER via RECmd; no cache reuse)
# ---------------------------------------------------------------------------

#: Well-known per-user file-access registry artifacts. Matched case-insensitively
#: against the DFIRBatch CSV's KeyPath / Category / Description (VM-verified
#: 2026-06-02: real columns are KeyPath/Category/Description/ValueName/
#: LastWriteTimestamp). KeyPath is the authoritative discriminator - DFIRBatch
#: Description strings vary by hive/plugin coverage.
_FILEACCESS_FRAGMENTS = (
    "userassist",
    "opensavepidlmru",
    "typedpaths",
    "recentdocs",
    "lastvisitedpidlmru",
    "runmru",
    "wordwheelquery",
)


def _classify_fileaccess_row(row: dict[str, str]) -> Optional[str]:
    """Return the matched file-access fragment for a registry row, else None."""
    blob = " | ".join(
        str(row.get(col, "") or "")
        for col in ("Category", "KeyPath", "Description", "ValueName")
    ).lower()
    for frag in _FILEACCESS_FRAGMENTS:
        if frag in blob:
            return frag
    return None


# RECmd exit_code can be 0 (run.ok=True) even when it internally ABORTS on a
# dirty hive: it prints a warning and writes zero rows. Treated as legitimate
# no_data, that silently drops the subject user's entire file-access evidence -
# a large NTUSER can yield 0 rows yet the tool returns success/parser_failures=[].
# These case-insensitive markers, found in RECmd stdout/stderr, distinguish a
# dirty-hive abort from a clean parse that simply matched no file-access fragments.
_RECMD_DIRTY_HIVE_MARKERS = (
    "hive is dirty",
    "aborting",
    "found 0 key/value pairs across",
)


def _recmd_dirty_hive_abort(result: Any) -> bool:
    """True if a RunResult's RECmd output indicates a dirty-hive / zero-key abort.

    Inspects ``.stdout`` and ``.stderr`` (the real attributes on ``RunResult``)
    case-insensitively. Used ONLY when the produced CSV had zero rows: a clean
    parse that simply matched nothing leaves no such marker, so this never
    mis-flags legitimate no_data.
    """
    if result is None:
        return False
    blob = " ".join(
        str(getattr(result, attr, "") or "") for attr in ("stdout", "stderr")
    ).lower()
    return any(marker in blob for marker in _RECMD_DIRTY_HIVE_MARKERS)


def extract_registry_fileaccess(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Surface per-user file-access registry artifacts (UserAssist, RecentDocs,
    OpenSavePidlMRU, TypedPaths, LastVisitedPidlMRU, RunMRU, WordWheelQuery).

    Parses each per-profile NTUSER hive directly via RECmd with DFIRBatch (no
    cache reuse; file-access fragments are all HKCU/NTUSER). Each hive is
    parsed in isolation and every row is
    stamped with its actual source profile BEFORE merge, so file-access evidence
    is never mis-attributed across users/hosts. Rows are then filtered to the
    file-access fragment set and tagged with provenance at parse time. Does NOT
    alter run-keys semantics.

    These keys prove a path was WRITTEN to a user-activity list - NOT that a
    human clicked/opened it (background tasks also populate UserAssist).
    LastWriteTimestamp = when the KEY changed, not when a specific value changed.

    image_path MUST be a mounted Windows volume root (e.g. /mnt/disk or
    /mnt/windows_mount after mount_image); a path that is not a Windows volume
    returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_registry_fileaccess"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()

    source_rows: list[dict[str, str]] = []
    source_artifact = ""
    raw_command = ""
    profiles_checked: list[str] = []
    parser_failures: list[dict[str, Any]] = []
    tmp_dirs: list[Path] = []
    # ``discovered`` = did we find ANY source of registry data to parse? Any
    # NTUSER hive being located counts as discovery. A zero-row outcome with
    # discovered=False is a true artifact_absent; discovered=True routes to
    # no_data / collection_failed.
    discovered = False

    # Run RECmd with DFIRBatch directly over each discovered NTUSER hive. There
    # is NO cache-reuse path: the run-keys ``registry_combined.csv`` is scoped to
    # the case dir, NOT to this image/hive set, so reusing it risks mis-attributing
    # one host's UserAssist/RecentDocs to another. Parsing per-NTUSER here is
    # correct-by-construction - each row is stamped with its actual source profile
    # BEFORE merge (design review design review 2026-06-02).
    batch_file_used: Optional[str] = None
    for candidate in DFIR_BATCH_PATHS:
        if os.path.isfile(candidate):
            batch_file_used = candidate
            break
    raw_command = "RECmd.dll --bn DFIRBatch over per-profile NTUSER hives"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    ntuser_hives = _discover_user_hives(image_path, ("NTUSER.DAT",))
    discovered = bool(ntuser_hives)
    # Absence matrix: ALWAYS list every discovered profile (see shellbags note).
    profiles_checked = sorted({name for name, _ in _iter_user_profile_dirs(image_path)})
    try:
        for idx, (profile_name, hive_path, rel) in enumerate(ntuser_hives, start=1):
            replay_in: Optional[Path] = None
            replay_out: Optional[Path] = None
            replay_ok = True
            replay_reason: Optional[str] = None
            # ``hive_dir`` MUST be a directory holding ONLY this hive - never
            # ``hive_path.parent`` (the live profile dir). On a clean/successful
            # replay that is the rla temp out dir. On a replay RAISE the temp
            # dirs were already cleaned, so stage the lone hive into a fresh
            # temp dir and parse THAT.
            hive_dir: Optional[str] = None
            try:
                cleaned_hive, replay_in, replay_out, replay_ok = _replay_hive_with_rla(
                    hive_path, f"{profile_name}_{idx}", want_status=True
                )
                hive_dir = str(Path(cleaned_hive).parent)
                if not replay_ok:
                    replay_reason = "rla_nonzero"
            except Exception as exc:
                # Replay RAISED: do NOT fall back to hive_path (its parent is the
                # profile dir). Stage just this hive into a fresh single-hive dir.
                replay_ok = False
                replay_reason = type(exc).__name__
                staged = Path(tempfile.mkdtemp(prefix="savvydfir_refa_stage_"))
                tmp_dirs.append(staged)
                try:
                    shutil.copy2(str(hive_path), str(staged / hive_path.name))
                except Exception:
                    pass
                hive_dir = str(staged)
            csv_out = Path(tempfile.mkdtemp(prefix="savvydfir_refa_"))
            tmp_dirs.append(csv_out)
            csv_name = f"refa_{idx}.csv"
            status = "ok"
            result = None
            try:
                result = _ez_runner.run_recmd(
                    hive_dir=hive_dir,
                    csv_dir=str(csv_out), csv_filename=csv_name,
                    batch_file=batch_file_used, sync_batch=False, tool_name=tool,
                )
                if not result.ok:
                    status = f"parser_error:{_ez_runner.classify_error(result)}"
            except Exception as exc:
                status = f"exception:{type(exc).__name__}"
            finally:
                if replay_in is not None:
                    shutil.rmtree(replay_in, ignore_errors=True)
                if replay_out is not None:
                    shutil.rmtree(replay_out, ignore_errors=True)
            # A failed replay is a collection gap even if the parser salvages rows
            # from the unreplayed base hive: stamp rows non-ok and record a failure.
            if not replay_ok and status == "ok":
                status = "replay_error"
            produced = csv_out / csv_name
            hive_rows = _read_csv(str(produced)) if _path_exists(produced) else []
            if hive_rows:
                for r in hive_rows:
                    r.setdefault("__source_profile", profile_name)
                    r.setdefault("__source_hive", hive_path.name)
                    r.setdefault("__source_path", str(hive_path))
                    # Propagate the REAL per-hive parser status downstream so the
                    # tagging site stamps salvaged-from-failed rows with the actual
                    # failure status, not a hardcoded "ok".
                    r.setdefault("__source_status", status)
                source_rows.extend(hive_rows)
            # A non-ok run is a collection gap REGARDLESS of salvage: record it even
            # when rows were recovered, so the response cannot read as clean success.
            if not replay_ok:
                parser_failures.append(
                    {
                        "profile": profile_name,
                        "hive": str(hive_path),
                        "status": "replay_error",
                        "reason": replay_reason or "rla_nonzero",
                        "recovered_rows": len(hive_rows),
                    }
                )
            elif status != "ok":
                parser_failures.append(
                    {
                        "profile": profile_name,
                        "hive": str(hive_path),
                        "status": status,
                        "reason": "recmd_nonzero_or_error",
                        "recovered_rows": len(hive_rows),
                    }
                )
            elif _recmd_dirty_hive_abort(result):
                # RECmd reported ok/exit_code=0 yet produced ZERO rows AND its
                # output carries a dirty-hive / zero-key abort marker. This is a
                # silent-drop, NOT legitimate no_data - the hive's evidence was
                # never parsed (rla failed to clean it). Record a parser_failure
                # so the 4-way zero-row taxonomy fires (collection_failed if ALL
                # hives fail this way; success-with-failures if only some do).
                parser_failures.append(
                    {
                        "artifact": str(hive_path),
                        "profile": profile_name,
                        "status": "parser_failed",
                        "reason": "recmd_dirty_hive_or_zero_keys",
                        "recovered_rows": 0,
                    }
                )
    finally:
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    # 3) Filter to file-access fragments and tag provenance.
    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    fragment_counts: dict[str, int] = {}
    for row in source_rows:
        frag = _classify_fileaccess_row(row)
        if not frag:
            continue
        fragment_counts[frag] = fragment_counts.get(frag, 0) + 1
        profile = row.get("__source_profile") or row.get("HiveType") or "unknown"
        src_hive = row.get("__source_hive") or row.get("HiveType") or ""
        src_path = row.get("__source_path") or source_artifact or row.get("HivePath") or ""
        # Real per-hive status (set above); rows salvaged from a failed hive must
        # carry that failure status, NOT a hardcoded "ok" (registry was strictly
        # worse than the EZ-backed loops - review flag, review 2026-06-02).
        src_status = row.get("__source_status") or "ok"
        clean = {k: v for k, v in row.items() if not k.startswith("__")}
        clean["fileaccess_artifact"] = frag
        tagged = _tag_provenance(
            [clean], source_profile=str(profile), source_hive=str(src_hive),
            source_artifact_path=str(src_path), parser_command="RECmd:DFIRBatch",
            parser_status=str(src_status),
        )
        merged_rows.extend(tagged)
        if profile and profile != "unknown":
            profiles_with_data.add(str(profile))

    if not merged_rows:
        # discovered=True when NTUSER hives were found but no row matched the
        # file-access fragment set (no_data), or parsing failed
        # (collection_failed). discovered=False only when nothing at all was
        # located to parse - a true artifact_absent.
        resp = _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures,
            artifact_label="file-access registry artifacts (UserAssist/RecentDocs/etc.)",
            discovered=discovered,
        )
        resp["fragment_counts"] = fragment_counts
        return resp

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="other", artifact_type="disk",
            artifact_path=durable_csv or source_artifact or image_path, tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"Registry file-access: surfaced {total_rows} entries "
                f"({', '.join(sorted(fragment_counts))}). A file-access key proves a "
                "path was WRITTEN to a user-activity list, NOT that a human clicked it "
                "(background tasks populate UserAssist). LastWriteTimestamp = when the "
                "KEY changed, not when a value changed; corroborate with LNK / Jump "
                "Lists / ShellBags."
            ),
            supporting_indicators=sorted(fragment_counts)[:20],
        )

    response = _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="registry_fileaccess", csv_filename="registry_fileaccess.csv",
        finding_factory=_finding, max_entries=max_entries,
    )
    response["fragment_counts"] = fragment_counts
    return response

# ===========================================================================
# New FK-only OPTIONAL extractors (native parsers - no EZ tool / dotnet dep):
#   extract_recycle_bin       - native $I parser, per-SID under $Recycle.Bin
#   extract_powershell_history- native plain-text PSReadline read, per-user
#   extract_scheduled_tasks   - native XML parse of Windows\System32\Tasks
# All mirror the user-activity extractor template (volume-root isolation,
# documented-absence taxonomy, provenance columns, state mirror). Case-agnostic.
# ===========================================================================

#: FILETIME epoch delta: 100-ns intervals between 1601-01-01 and 1970-01-01.
_FILETIME_EPOCH_DELTA = 116444736000000000


def _filetime_to_iso_utc(filetime: int) -> Optional[str]:
    """Convert a 64-bit Windows FILETIME to an ISO-8601 UTC string (or None)."""
    try:
        if filetime <= 0:
            return None
        seconds = (filetime - _FILETIME_EPOCH_DELTA) / 10_000_000.0
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return None


def _parse_recycle_i_file(data: bytes) -> dict[str, Any]:
    """Parse a Recycle Bin ``$I`` metadata blob (v1 fixed-260 / v2 length-prefixed).

    Returns a dict with ``original_path``, ``original_size_bytes``,
    ``deletion_time_utc``, ``i_format_version``. Raises ValueError on a blob too
    short or malformed to interpret so the caller records a parser_failure.
    """
    import struct
    if len(data) < 0x18:
        raise ValueError("i_file_too_short_for_header")
    version = struct.unpack_from("<q", data, 0x00)[0]
    size = struct.unpack_from("<q", data, 0x08)[0]
    filetime = struct.unpack_from("<q", data, 0x10)[0]
    if version == 1:
        # v1: fixed 260 UTF-16LE chars (520 bytes) at offset 0x18, NUL-terminated.
        raw = data[0x18:0x18 + 520]
        path = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        fmt = 1
    elif version == 2:
        if len(data) < 0x1C:
            raise ValueError("i_file_too_short_for_v2_length")
        n_chars = struct.unpack_from("<I", data, 0x18)[0]
        byte_len = n_chars * 2
        raw = data[0x1C:0x1C + byte_len]
        path = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        fmt = 2
    else:
        raise ValueError(f"unknown_i_format_version:{version}")
    return {
        "original_path": path,
        "original_size_bytes": size,
        "deletion_time_utc": _filetime_to_iso_utc(filetime) or "",
        "i_format_version": fmt,
    }


def extract_recycle_bin(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract Windows Recycle Bin ($I/$R) metadata per SID via a native parser.

    Discovers ``$Recycle.Bin/<SID>/$I*`` (+ matching ``$R*``) for every volume
    root derived from image_path, parses the $I binary header (v1 fixed-260 /
    v2 length-prefixed), and merges rows with provenance columns.

    A Recycle Bin entry proves a file was sent to the bin under a SID via the
    Explorer shell - NOT that a specific human deleted it, opened it, or ran it.
    Corroborate with $UsnJrnl rename + $MFT + session attribution.

    image_path MUST be a mounted Windows volume root; a path that is not a
    Windows volume returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_recycle_bin"
    if _state is None or _audit is None:
        return _not_initialised(tool)

    # Per-SID discovery across every volume root (Recycle Bin is per-SID, NOT
    # per-user, so _iter_user_profile_dirs does not apply).
    discovered: list[tuple[str, Path, Optional[Path]]] = []  # (sid, i_file, r_file)
    legacy_seen = False
    for root in _user_activity_volume_roots(image_path):
        for bin_name in ("$Recycle.Bin",):
            bin_dir = root / bin_name
            if not _path_is_dir(bin_dir):
                continue
            try:
                sid_dirs = [d for d in bin_dir.iterdir() if _path_is_dir(d)]
            except OSError:
                sid_dirs = []
            for sid_dir in sid_dirs:
                try:
                    i_files = sorted(sid_dir.glob("$I*"))
                except OSError:
                    i_files = []
                for i_file in i_files:
                    if not _path_is_file(i_file):
                        continue
                    r_name = "$R" + i_file.name[2:]
                    r_file = sid_dir / r_name
                    discovered.append(
                        (sid_dir.name, i_file, r_file if _path_is_file(r_file) else None)
                    )
        # Legacy RECYCLER probe (v1.1 defer: record a gap, do not parse INFO2).
        if _path_is_dir(root / "RECYCLER"):
            legacy_seen = True

    profiles_checked = sorted({sid for sid, _, _ in discovered})

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "native_i_parser <volume>/$Recycle.Bin/<SID>/$I*"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not discovered:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="Recycle Bin $I metadata files",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    parser_failures: list[dict[str, Any]] = []
    for sid, i_file, r_file in discovered:
        status = "ok"
        try:
            data = i_file.read_bytes()
            parsed = _parse_recycle_i_file(data)
        except Exception as exc:
            status = f"parser_error:{type(exc).__name__}"
            parser_failures.append({
                "profile": sid, "artifact": str(i_file), "status": status,
                "reason": str(exc), "recovered_rows": 0,
            })
            continue
        ext = ""
        if parsed.get("original_path"):
            ext = Path(parsed["original_path"]).suffix.lstrip(".").lower()
        row = {
            "sid": sid,
            "original_path": parsed.get("original_path", ""),
            "original_size_bytes": parsed.get("original_size_bytes", 0),
            "deletion_time_utc": parsed.get("deletion_time_utc", ""),
            "i_file_name": i_file.name,
            "r_file_name": r_file.name if r_file is not None else "",
            "content_present": bool(r_file is not None),
            "i_format_version": parsed.get("i_format_version", ""),
            "original_extension": ext,
        }
        merged_rows.extend(_tag_provenance(
            [row], source_profile=sid, source_hive="",
            source_artifact_path=str(i_file),
            parser_command="native_i_parser", parser_status=status,
        ))
        profiles_with_data.add(sid)

    if not merged_rows:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures,
            artifact_label="Recycle Bin $I records", discovered=True,
        )

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="other", artifact_type="disk",
            artifact_path=durable_csv or str(discovered[0][1]), tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"Recycle Bin: parsed {total_rows} $I deletion record(s) across "
                f"{len(profiles_with_data)} SID(s). An entry proves a file was sent "
                "to the bin under a SID via the Explorer shell, NOT that a specific "
                "human deleted/opened/ran it. Corroborate with $UsnJrnl rename + "
                "$MFT + session (EID 4624); resolve SID via ProfileList before "
                "attributing WHO."
            ),
            supporting_indicators=sorted(profiles_with_data)[:20],
        )

    response = _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="recycle_bin", csv_filename="recycle_bin.csv",
        finding_factory=_finding, max_entries=max_entries,
    )
    if legacy_seen:
        response["legacy_info2_not_parsed"] = True
    return response


#: Case-agnostic high-signal PowerShell command patterns (no hardcoded IOCs).
_PS_HIGH_SIGNAL = re.compile(
    r"(-enc(odedcommand)?\b|\biex\b|invoke-expression|downloadstring|"
    r"downloadfile|bitsadmin|certutil|frombase64string|[A-Za-z0-9+/]{60,}={0,2})",
    re.IGNORECASE,
)


def extract_powershell_history(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract PSReadline PowerShell console history per user (native text read).

    Discovers each profile's
    ``AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine`` directory and
    reads every ``*_history.txt`` (ConsoleHost + VSCode/ISE host variants), one
    CSV row per command line, flagging case-agnostic high-signal patterns.

    PSReadline proves commands were ENTERED in an interactive PS console host
    under that user - NOT that they executed, that a human (vs automation) typed
    them, or that earlier commands were not rotated off (default cap 4096 lines).
    The file is attacker-editable (no chain-of-custody on contents). Corroborate
    with PowerShell EVTX 4104 + Prefetch + EID 4688.

    image_path MUST be a mounted Windows volume root; a path that is not a
    Windows volume returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_powershell_history"
    if _state is None or _audit is None:
        return _not_initialised(tool)

    dirs = _discover_user_dirs(
        image_path,
        ("AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine",),
    )
    discovered: list[tuple[str, Path]] = []  # (profile, history_file)
    for profile_name, psr_dir, _rel in dirs:
        try:
            hist_files = sorted(psr_dir.glob("*_history.txt"))
        except OSError:
            hist_files = []
        for hist in hist_files:
            if _path_is_file(hist):
                discovered.append((profile_name, hist))

    profiles_checked = sorted({name for name, _ in _iter_user_profile_dirs(image_path)})

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "native_psreadline_read <profile>/.../PSReadLine/*_history.txt"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not discovered:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="PSReadline history files",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    profiles_with_data: set[str] = set()
    parser_failures: list[dict[str, Any]] = []
    for profile_name, hist in discovered:
        status = "ok"
        try:
            text = hist.read_text(encoding="utf-8", errors="replace")
            mtime = datetime.fromtimestamp(hist.stat().st_mtime, tz=timezone.utc)
            mtime_iso = mtime.strftime("%Y-%m-%dT%H:%M:%S")
        except Exception as exc:
            status = f"parser_error:{type(exc).__name__}"
            parser_failures.append({
                "profile": profile_name, "artifact": str(hist), "status": status,
                "reason": str(exc), "recovered_rows": 0,
            })
            continue
        rows: list[dict[str, Any]] = []
        for idx, line in enumerate(text.splitlines(), start=1):
            if line == "":
                continue
            rows.append({
                "command": line,
                "line_no": idx,
                "source_history_file": hist.name,
                "file_mtime_utc": mtime_iso,
                "high_signal": bool(_PS_HIGH_SIGNAL.search(line)),
            })
        if rows:
            merged_rows.extend(_tag_provenance(
                rows, source_profile=profile_name, source_hive="",
                source_artifact_path=str(hist),
                parser_command="native_psreadline_read", parser_status=status,
            ))
            profiles_with_data.add(profile_name)

    if not merged_rows:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures,
            artifact_label="PSReadline command lines", discovered=True,
        )

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="execution", artifact_type="disk",
            artifact_path=durable_csv or str(discovered[0][1]), tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"PowerShell history: parsed {total_rows} command line(s) across "
                f"{len(profiles_with_data)} profile(s). PSReadline proves commands "
                "were ENTERED in an interactive console host under that user, NOT "
                "that they executed or that a human typed them; the file is "
                "attacker-editable and capped (~4096 lines) so early absence may be "
                "rotation. Corroborate with EVTX 4104 + Prefetch + EID 4688."
            ),
            supporting_indicators=sorted(profiles_with_data)[:20],
        )

    return _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=sorted(profiles_with_data), parser_failures=parser_failures,
        tool_short_name="powershell_history", csv_filename="powershell_history.csv",
        finding_factory=_finding, max_entries=max_entries,
    )


#: Case-agnostic off-path indicators for a scheduled-task command (no hardcoded IOCs).
_TASK_OFF_PATH = re.compile(
    r"(\\temp\\|\\appdata\\|\\users\\public\\|\\\$recycle\.bin\\|"
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|-enc(odedcommand)?\b|frombase64string)",
    re.IGNORECASE,
)


def _parse_task_xml(xml_text: str, task_rel: str) -> dict[str, Any]:
    """Parse a Task Scheduler XML definition into a flat row dict."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_text)

    def _strip(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def _find_text(parent, *names) -> str:
        for el in parent.iter():
            if _strip(el.tag) in names and (el.text or "").strip():
                return el.text.strip()
        return ""

    command = _find_text(root, "Command")
    arguments = _find_text(root, "Arguments")
    principal_userid = _find_text(root, "UserId")
    run_level = _find_text(root, "RunLevel")
    author = _find_text(root, "Author")
    registration_date = _find_text(root, "Date")
    uri = _find_text(root, "URI")
    enabled = _find_text(root, "Enabled")
    # Serialize trigger element names (a compact summary).
    triggers: list[str] = []
    for el in root.iter():
        if _strip(el.tag) == "Triggers":
            for child in list(el):
                triggers.append(_strip(child.tag))
    trigger_summary = ",".join(triggers)
    blob = f"{command} {arguments}".strip()
    off_path = bool(_TASK_OFF_PATH.search(blob)) if blob else False
    builtin = task_rel.replace("\\", "/").lower().startswith("microsoft/windows/")
    return {
        "task_name": task_rel.replace("/", "\\").rsplit("\\", 1)[-1],
        "task_path": task_rel.replace("/", "\\"),
        "command": command,
        "arguments": arguments,
        "triggers": trigger_summary,
        "principal_userid": principal_userid,
        "run_level": run_level,
        "author": author,
        "registration_date": registration_date,
        "uri": uri,
        "enabled": enabled,
        "builtin_baseline": builtin,
        "off_path_command": off_path,
    }


def extract_scheduled_tasks(
    image_path: str,
    case_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract on-disk scheduled-task definitions via a native XML parser.

    Walks ``Windows/System32/Tasks/**`` (recursive, extensionless XML) across
    every volume root, dedups on device/inode (hardlink guard), and parses
    Command/Arguments/Principal/Author/RegistrationInfo per task. All tasks are
    emitted (completeness) with a ``builtin_baseline`` flag so analysts can
    filter the hundreds of legitimate ``\\Microsoft\\Windows\\...`` tasks.

    A task definition proves a task was REGISTERED with a given command/principal
    as of the registration date - NOT that it ever FIRED. Corroborate with
    TaskScheduler EVTX 4698/4702 + 200/201, Prefetch of the target binary, and
    registry TaskCache LastRunTime.

    image_path MUST be a mounted Windows volume root; a path that is not a
    Windows volume returns status=error rather than scanning an ambient mount.
    """
    tool = "disk.extract_scheduled_tasks"
    if _state is None or _audit is None:
        return _not_initialised(tool)

    discovered: list[tuple[Path, str]] = []  # (xml_path, task_rel)
    seen_real: set[str] = set()
    for root in _user_activity_volume_roots(image_path):
        tasks_root = root / "Windows" / "System32" / "Tasks"
        if not _path_is_dir(tasks_root):
            continue
        try:
            candidates = sorted(tasks_root.rglob("*"))
        except OSError:
            candidates = []
        for xml_path in candidates:
            if not _path_is_file(xml_path):
                continue
            # Hardlink guard: dedup on (device, inode) so multiple directory
            # entries pointing at one inode are counted once. resolve() does NOT
            # collapse hardlinks (only symlinks), so stat the inode directly;
            # fall back to the resolved path string when the inode is unavailable.
            try:
                st = xml_path.stat()
                real = (f"{st.st_dev}:{st.st_ino}" if st.st_ino
                        else str(xml_path.resolve()).lower())
            except OSError:
                real = str(xml_path).lower()
            if real in seen_real:
                continue
            seen_real.add(real)
            try:
                rel = str(xml_path.relative_to(tasks_root))
            except ValueError:
                rel = xml_path.name
            discovered.append((xml_path, rel))

    # System-path tool: no per-user profiles. "system" stands in for the column.
    profiles_checked = ["system"] if discovered else []

    exec_id = _audit.next_execution_id()
    started_at = time.monotonic()
    raw_command = "native_task_xml <volume>/Windows/System32/Tasks/**"
    _audit.log_execution(
        execution_id=exec_id, tool_name=tool,
        parameters={"image_path": image_path, "profiles_checked": profiles_checked},
        command_line=raw_command,
    )

    if not _user_activity_volume_roots(image_path):
        return _useractivity_no_volume_error(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, image_path=image_path,
        )

    if not discovered:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=[], artifact_label="scheduled-task XML files (System32\\Tasks)",
            discovered=False,
        )

    merged_rows: list[dict[str, Any]] = []
    parser_failures: list[dict[str, Any]] = []
    for xml_path, rel in discovered:
        status = "ok"
        try:
            xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
            row = _parse_task_xml(xml_text, rel)
        except Exception as exc:
            status = f"parser_error:{type(exc).__name__}"
            parser_failures.append({
                "profile": "system", "artifact": str(xml_path), "status": status,
                "reason": str(exc), "recovered_rows": 0,
            })
            continue
        merged_rows.extend(_tag_provenance(
            [row], source_profile="system", source_hive="",
            source_artifact_path=str(xml_path),
            parser_command="native_task_xml", parser_status=status,
        ))

    if not merged_rows:
        return _useractivity_zero_row_response(
            tool=tool, exec_id=exec_id, raw_command=raw_command,
            started_at=started_at, profiles_checked=profiles_checked,
            parser_failures=parser_failures,
            artifact_label="scheduled-task definitions", discovered=True,
        )

    profiles_with_data = ["system"]

    def _finding(durable_csv, total_rows):
        return Finding(
            case_id=_case_id(), finding_type="persistence", artifact_type="disk",
            artifact_path=durable_csv or str(discovered[0][0]), tool_name=tool,
            execution_id=exec_id, iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION, finding_status=FindingStatus.ACTIVE,
            confidence=0.70,
            description=(
                f"Scheduled tasks: parsed {total_rows} on-disk task definition(s). "
                "A definition proves a task was REGISTERED with a given command/"
                "principal as of the registration date, NOT that it ever FIRED. "
                "Built-in \\Microsoft\\Windows\\ tasks are flagged builtin_baseline; "
                "review off_path_command rows. Corroborate with EVTX 4698/4702 + "
                "200/201, Prefetch, and registry TaskCache LastRunTime."
            ),
            supporting_indicators=["system"],
        )

    return _finalize_useractivity_response(
        tool=tool, exec_id=exec_id, raw_command=raw_command, started_at=started_at,
        rows=merged_rows, profiles_checked=profiles_checked,
        profiles_with_data=profiles_with_data, parser_failures=parser_failures,
        tool_short_name="scheduled_tasks", csv_filename="scheduled_tasks.csv",
        finding_factory=_finding, max_entries=max_entries,
    )
