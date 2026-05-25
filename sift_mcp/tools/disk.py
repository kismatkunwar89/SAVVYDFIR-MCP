"""
sift_mcp.tools.disk
~~~~~~~~~~~~~~~~~~~~

Disk forensics MCP tools for SAVVYDFIR-MCP.

All six tools wrap EZ Tools (via :class:`~sift_mcp.runners.eztools.EZToolsRunner`)
or The Sleuth Kit (via :class:`~sift_mcp.runners.sleuthkit.SleuthKitRunner`),
parse the CLI output into typed Pydantic models, and return plain dicts.

Tools
-----
- ``extract_prefetch``         — Prefetch execution evidence via ``pyscca``.
- ``get_amcache``              — AmcacheParser: SHA-1 evidence of execution.
- ``extract_mft_timeline``     — MFTECmd: Full NTFS MFT with SI/FN timestamps
                                  (timestomping detection).
- ``list_deleted_files``       — fls -rd: Deleted file recovery via TSK.
- ``summarize_evtx``           — EvtxECmd: Windows event log parsing.
- ``extract_registry_run_keys``— RECmd: Persistence key extraction.

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
from datetime import datetime, timezone
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
# Module-level singletons — set via init_tools()
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

    Silent 0-record success is the worst failure mode — it looks like
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
        if isinstance(note, str) and note:
            payload["note"] = (
                f"{note} Raw records omitted by default; pass "
                'response_format="detailed" for the full array.'
            )
        else:
            payload["note"] = (
                'Raw records omitted by default; pass response_format="detailed" '
                "for the full array."
            )
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
        if _path_exists(base / "Windows"):
            _add(base)
        if _path_exists(base / "mnt" / "C" / "Windows"):
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
        candidate = root.joinpath(*relative_parts)
        if _path_exists(candidate):
            return str(candidate)
    if volume_roots:
        return str(volume_roots[0].joinpath(*relative_parts))
    base = Path(image_path)
    return str(base.joinpath("mnt", "C", *relative_parts))


def _raw_artifact_base() -> Path:
    return Path(os.environ.get("OUTPUT_BASE", "/cases")) / _case_id() / "artifacts" / "raw"


def _durable_raw_artifact_path(kind: str) -> Optional[str]:
    """Return a durable extracted artifact path for *kind* — content-aware.

    peer reviewer Phase-A-boundary review: the prior 'first existing path' check
    accepted empty directories created by failed/partial extract_windows_
    artifacts runs. An empty raw/evtx would then shadow a valid mounted
    Windows root and break A.2 path resolution.

    Now: only return a path that contains the artifact files we expect.
    """
    base = _raw_artifact_base()
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
            # need SYSTEM and/or SOFTWARE — the hives that actually carry
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
    return None


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
    """Build a lookup of Prefetch file metadata from a durable MFT CSV."""
    lookup: dict[str, dict[str, Any]] = {}
    for row in _read_csv(csv_path):
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
) -> dict[str, Any]:
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
        f"MFT timeline returned {response.get('records_count', len(records))} rows "
        f"from {mft_path} with {response.get('timestomping_candidates', 0)} timestomping candidates."
    )
    evidence_excerpt = next(
        (record.file_path for record in records if record.file_path),
        None,
    )
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
) -> dict[str, Any]:
    channel_counts: dict[str, int] = {}
    for record in records:
        channel_counts[record.channel] = channel_counts.get(record.channel, 0) + 1
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
    evidence_excerpt = next(
        (record.message_summary for record in records if record.message_summary),
        None,
    )
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
        pivot_entities={
            "event_ids": compact_unique(record.event_id for record in records),
            "channels": compact_unique(record.channel for record in records),
            "computers": compact_unique(record.computer for record in records),
            "user_sids": compact_unique(record.user_sid for record in records),
            "process_paths": compact_unique(_extract_evtx_process_paths(records)),
        },
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


def _replay_hive_with_rla(hive_path: Path, label: str) -> tuple[Path, Path, Path]:
    """Copy one hive plus transaction logs to temp dirs and replay via rla."""
    tmp_in = Path(tempfile.mkdtemp(prefix=f"savvydfir_rla_in_{label}_"))
    tmp_out = Path(tempfile.mkdtemp(prefix=f"savvydfir_rla_out_{label}_"))

    shutil.copy2(str(hive_path), str(tmp_in / hive_path.name))
    for suffix in (".LOG1", ".LOG2"):
        log = hive_path.parent / f"{hive_path.name}{suffix}"
        if log.exists():
            shutil.copy2(str(log), str(tmp_in / log.name))

    rla_bin = Path("/opt/zimmermantools/rla.dll")
    subprocess.run(
        ["/usr/bin/dotnet", str(rla_bin), "-d",
         str(tmp_in), "--out", str(tmp_out)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )

    cleaned_files = [candidate for candidate in tmp_out.iterdir()
                     if candidate.is_file()]
    cleaned_hive = cleaned_files[0] if cleaned_files else (
        tmp_in / hive_path.name)
    return cleaned_hive, tmp_in, tmp_out


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


def _build_mft_records(
    rows: list[dict[str, str]],
    *,
    mft_path: str,
    tool: str,
    execution_id: str,
    create_findings: bool,
) -> tuple[list[MftEntry], list[str], int]:
    """Parse MFTECmd rows into records and optional findings."""
    records: list[MftEntry] = []
    finding_ids: list[str] = []
    timestomping_candidates = 0

    for row in rows:
        try:
            entry_num_raw = row.get(
                "EntryNumber") or row.get("MFTEntry") or "0"
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
                row.get("FileName") or row.get(
                    "FilePath") or row.get("ParentPath") or ""
            ).strip()

            si_created = _parse_dt(row.get("Created0x10")
                                   or row.get("SICreated") or "")
            si_modified = _parse_dt(
                row.get("LastModified0x10") or row.get("SIModified") or "")
            si_accessed = _parse_dt(
                row.get("LastAccess0x10") or row.get("SIAccessed") or "")
            si_entry_mod = _parse_dt(
                row.get("MFTRecordChange0x10") or row.get(
                    "SIEntryModified") or ""
            )

            fn_created = _parse_dt(row.get("Created0x30")
                                   or row.get("FNCreated") or "")
            fn_modified = _parse_dt(
                row.get("LastModified0x30") or row.get("FNModified") or "")
            fn_accessed = _parse_dt(
                row.get("LastAccess0x30") or row.get("FNAccessed") or "")
            fn_entry_mod = _parse_dt(
                row.get("MFTRecordChange0x30") or row.get(
                    "FNEntryModified") or ""
            )

            is_deleted = (row.get("InUse") or row.get("IsDeleted") or "").strip().lower() in (
                "false",
                "0",
                "no",
                "deleted",
            )
            is_dir = (row.get("IsDirectory") or row.get("IsDir") or "").strip().lower() in (
                "true",
                "1",
                "yes",
            )

            size_raw = row.get("FileSize") or row.get("LogicalSize") or ""
            try:
                file_size = int(size_raw) if size_raw.strip() else None
            except (ValueError, TypeError):
                file_size = None

            parent_raw = row.get("ParentEntryNumber") or row.get(
                "ParentMFTEntry") or ""
            try:
                parent_entry = int(parent_raw) if parent_raw.strip() else None
            except (ValueError, TypeError):
                parent_entry = None

            record = MftEntry(
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
            records.append(record)

            if si_created is not None and fn_created is not None and si_created < fn_created:
                timestomping_candidates += 1
                if create_findings and _state is not None:
                    ts_finding = Finding(
                        case_id=_case_id(),
                        finding_type="timestomping",
                        artifact_type="disk",
                        artifact_path=mft_path,
                        artifact_offset=str(entry_num),
                        tool_name=tool,
                        execution_id=execution_id,
                        iteration=_current_iteration(),
                        evidence_kind=EvidenceKind.OBSERVATION,
                        finding_status=FindingStatus.ACTIVE,
                        confidence=0.8,
                        description=(
                            f"Possible timestomping detected for MFT entry {entry_num} "
                            f"({file_path_val or 'unknown path'}). "
                            f"$SI Created ({si_created.isoformat()}) precedes "
                            f"$FN Created ({fn_created.isoformat()}), which is physically "
                            "impossible on a normal write — SI timestamps may have been "
                            "retroactively modified to evade timeline analysis."
                        ),
                        supporting_indicators=[
                            f"si_created={si_created.isoformat()}",
                            f"fn_created={fn_created.isoformat()}",
                            f"mft_entry={entry_num}",
                            file_path_val or "",
                        ],
                        mitre_tactic="TA0005",
                        mitre_technique="T1070.006",
                    )
                    finding_ids.append(_state.add_finding(
                        ts_finding.model_dump(mode="json")))
        except Exception:
            continue

    return records, finding_ids, timestomping_candidates


def _build_evtx_records(
    rows: list[dict[str, str]],
    *,
    evtx_dir: str,
    channel: Optional[str],
    tool: str,
    execution_id: str,
    create_findings: bool,
) -> tuple[list[EventRecord], list[str]]:
    """Parse EvtxECmd rows into records and optional summary finding."""
    records: list[EventRecord] = []

    for row in rows:
        try:
            ch = (row.get("Channel") or row.get("EventChannel") or "").strip()
            if channel and ch.lower() != channel.lower():
                continue

            event_id_raw = row.get("EventId") or row.get(
                "EventID") or row.get("Id") or "0"
            try:
                event_id = int(event_id_raw)
            except (ValueError, TypeError):
                event_id = 0

            ts = _parse_dt(
                row.get("TimeCreated") or row.get(
                    "Timestamp") or row.get("Date/Time - UTC") or ""
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

            skip_cols = {
                "EventId",
                "EventID",
                "Id",
                "Channel",
                "EventChannel",
                "TimeCreated",
                "Timestamp",
                "Date/Time - UTC",
                "PayloadData1",
                "MapDescription",
                "UserData",
                "Message",
                "Computer",
                "UserSID",
                "UserId",
                "Level",
                "Provider",
                "ProviderName",
                "SourceName",
            }
            extra: dict[str, Any] = {
                k: v for k, v in row.items() if k not in skip_cols and v and v.strip()
            }

            records.append(
                EventRecord(
                    event_id=event_id,
                    channel=ch or "Unknown",
                    provider=(
                        row.get("Provider") or row.get(
                            "ProviderName") or row.get("SourceName") or None
                    ),
                    timestamp=ts,
                    level=row.get("Level") or row.get(
                        "LevelDisplayName") or None,
                    computer=row.get("Computer") or None,
                    user_sid=(row.get("UserSID") or row.get("UserId") or None),
                    message_summary=message or f"Event {event_id}",
                    raw_xml_ref=None,
                    extra_fields=extra,
                )
            )
        except Exception:
            continue

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
    interesting_keys = (
        "newprocessname",
        "processname",
        "imagename",
        "image",
        "application",
        "commandline",
        "processpath",
    )
    path_re = re.compile(
        r"[A-Za-z]:\\[^\"'\r\n]+\.(?:exe|dll|cmd|bat|ps1|vbs)", re.IGNORECASE)

    for record in records:
        if record.event_id not in {1, 4688}:
            continue

        for key, value in record.extra_fields.items():
            key_norm = key.lower().replace(" ", "").replace("_", "")
            text = str(value or "").strip()
            if not text:
                continue

            if any(name in key_norm for name in interesting_keys):
                match = path_re.search(text)
                candidates.append(match.group(0) if match else text)

        if not record.extra_fields:
            candidates.extend(path_re.findall(record.message_summary))

    return [candidate for candidate in candidates if candidate]


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
# DFIR constants — case-agnostic, universally applicable
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

    # Use pyscca (libscca) — handles Windows 10 MAM-compressed .pf files on Linux
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

    # One summary finding for the whole batch — not one per .pf file
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

    # One summary finding for the whole batch — not one per Amcache entry
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
        rows = _read_csv(str(cached["csv_path"]))
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
        records, _, timestomping_candidates = _build_mft_records(
            rows,
            mft_path=mft_path,
            tool=tool,
            execution_id=cache_meta["execution_id"],
            create_findings=False,
        )
        full_records = list(records)
        detailed_records = list(full_records)
        if max_entries and max_entries > 0:
            detailed_records = detailed_records[:max_entries]
        response = {
            "tool_name": tool,
            "status": "success",
            "findings_created": list(cached.get("findings_created", [])),
            "execution_id": cache_meta["execution_id"],
            "raw_command": cache_meta["raw_command"],
            "records_count": len(detailed_records),
            "total_records": len(rows),
            "timestomping_candidates": timestomping_candidates,
            "csv_path": str(cached["csv_path"]),
            "note": f"Returning {len(detailed_records)} of {len(rows)} MFT rows. Full CSV at {cached['csv_path']}.",
            "requires_agent": cached.get("requires_agent", "@mft-analyst"),
            "agent_instruction": cached.get(
                "agent_instruction",
                f"Analyze {cached['csv_path']} for timestomping, attacker file drops, staging. {len(rows)} total rows.",
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
            records=detailed_records if normalized_format == "detailed" else full_records,
            total_records=len(rows),
        )
        formatted = _warn_if_empty(formatted, "extract_mft_timeline", mft_path, min_expected=10000)
        return _mft_contract_payload(
            response=formatted,
            records=detailed_records if normalized_format == "detailed" else full_records,
            image_path=image_path,
            mft_path=mft_path,
            csv_path=str(cached["csv_path"]),
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

        rows = _read_csv(csv_path)
        persistent_csv = _persist_csv(csv_path, "mft")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="MFT CSV",
            persisted_path=persistent_csv,
            preflight=preflight,
        )

    records, finding_ids, timestomping_candidates = _build_mft_records(
        rows,
        mft_path=resolved_mft_path,
        tool=tool,
        execution_id=result.execution_id,
        create_findings=True,
    )
    full_records = list(records)
    detailed_records = list(full_records)
    if max_entries and max_entries > 0:
        detailed_records = detailed_records[:max_entries]
    response = {
        "tool_name": tool,
        "status": "success" if durable_csv else "warning",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(detailed_records),
        "total_records": len(rows),
        "timestomping_candidates": timestomping_candidates,
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "note": (
            f"Returning {len(detailed_records)} of {len(rows)} MFT rows. Full CSV at {durable_csv}."
            if durable_csv
            else (
                f"Returning {len(detailed_records)} of {len(rows)} MFT rows. "
                "CSV persistence did not produce a durable analyst-facing handle; "
                "fix OUTPUT_BASE and rerun extract_mft_timeline before using run_analysis()."
            )
        ),
        "requires_agent": "@mft-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for timestomping, attacker file drops, staging. {len(rows)} total rows."
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
        records=detailed_records if normalized_format == "detailed" else full_records,
        total_records=len(rows),
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
                "total_records": len(rows),
            },
        )
    return _mft_contract_payload(
        response=response,
        records=detailed_records if normalized_format == "detailed" else full_records,
        image_path=image_path,
        mft_path=mft_path,
        csv_path=durable_csv,
    )


# ---------------------------------------------------------------------------
# Tool: extract_usn_journal (B.2)
# ---------------------------------------------------------------------------


def _resolve_usn_path_input(image_path: str, usn_path: Optional[str]) -> str:
    """Resolve $UsnJrnl:$J path. A.2-style: durable artifacts beat scan.

    The icat staging step writes the ADS as a flat file under
    /cases/<id>/artifacts/raw/usn/. Naming has drifted across staging
    revisions — we accept all known variants AND fall back to scanning
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
        # Last-resort directory scan — pick the largest UsnJrnl/J-ish file.
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
) -> dict[str, Any]:
    """Parse the NTFS USN Journal ($UsnJrnl:$J) via MFTECmd.

    B.2 — USN persists filesystem-change records that the MFT itself may
    overwrite. Critical for ransomware/exfiltration timelines because:
      - rename/delete is recorded with timestamps even after the MFT
        record is reallocated
      - 'BasicInfoChange + FileCreate + DataExtend' chains reveal
        encryption activity (ransomware) and large-file staging (exfil)

    Like extract_mft_timeline, USN output is LARGE (often >1M rows). We
    return a summary + csv_path handle ONLY — the parent agent must use
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

    with tempfile.TemporaryDirectory(prefix="savvydfir_usn_") as tmp_dir:
        csv_filename = "usn_journal.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_mftecmd_usn(
                usn_path=resolved_usn,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
                mft_path=mft_path,
                tool_name=tool,
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
        # Phase B boundary: explicit empty data array even on success —
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

    for line in result.stdout.splitlines():
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
# Tool: summarize_evtx — helpers
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
    no usable channels we return the original fallback_dir untouched — this
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

    # Channel inventory — always enumerate before processing so state.json
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
        # Caller explicitly chose EIDs — include them in the cache key
        cache_params = {
            **cache_base_params,
            "event_ids": sorted(effective_eids) if effective_eids else [],
            "event_id_strategy": "explicit",
        }
    else:
        # Auto-selected EIDs (adaptive or default) — cache on base params only
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
        rows = _read_csv(str(cached["csv_path"]))
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
        records, _ = _build_evtx_records(
            rows,
            evtx_dir=evtx_dir,
            channel=channel,
            tool=tool,
            execution_id=cache_meta["execution_id"],
            create_findings=False,
        )
        promote_corroborated_findings(
            _state,
            "evtx_process_creation",
            _extract_evtx_process_paths(records),
        )
        full_records = list(records)
        detailed_records = list(full_records)
        if max_entries and max_entries > 0:
            detailed_records = detailed_records[:max_entries]
        response = {
            "tool_name": tool,
            "status": "success",
            "findings_created": list(cached.get("findings_created", [])),
            "execution_id": cache_meta["execution_id"],
            "raw_command": cache_meta["raw_command"],
            "records_count": len(detailed_records),
            "total_records": len(rows),
            "csv_path": str(cached["csv_path"]),
            "requires_agent": cached.get("requires_agent", "@evtx-analyst"),
            "agent_instruction": cached.get(
                "agent_instruction",
                f"Analyze {cached['csv_path']} for attacker lifecycle — auth anomalies, lateral movement, persistence. {len(rows)} total rows.",
            ),
            "note": f"Returning {len(records)} of {len(rows)} rows. Full CSV at {cached['csv_path']}.",
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
            records=detailed_records if normalized_format == "detailed" else full_records,
            total_records=len(rows),
        )
        formatted = _warn_if_empty(formatted, "summarize_evtx", evtx_dir, min_expected=100)
        if "data" in formatted:
            formatted["data"] = [
                sanitize_payload_fields(record, "message_summary", "extra_fields")
                for record in formatted["data"]
            ]
        return _evtx_contract_payload(
            response=formatted,
            records=detailed_records if normalized_format == "detailed" else full_records,
            image_path=image_path,
            evtx_dir=evtx_dir,
            csv_path=str(cached["csv_path"]),
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

        rows = _read_csv(csv_path)
        persistent_csv = _persist_csv(csv_path, "evtx")
        durable_csv, artifact_persistence = _finalize_artifact_persistence(
            artifact_label="EVTX CSV",
            persisted_path=persistent_csv,
            preflight=preflight,
        )

    records, finding_ids = _build_evtx_records(
        rows,
        evtx_dir=evtx_dir,
        channel=channel,
        tool=tool,
        execution_id=result.execution_id,
        create_findings=True,
    )
    full_records = list(records)
    detailed_records = list(full_records)
    if max_entries and max_entries > 0:
        detailed_records = detailed_records[:max_entries]
    response = {
        "tool_name": tool,
        "status": "success",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(detailed_records),
        "total_records": len(rows),
        "csv_path": durable_csv,
        "artifact_persistence": artifact_persistence,
        "requires_agent": "@evtx-analyst",
        "agent_instruction": (
            f"Analyze {durable_csv} for attacker lifecycle — auth anomalies, lateral movement, persistence. {len(rows)} total rows."
            if durable_csv
            else "Analyze the returned EVTX summary and persisted artifacts for attacker lifecycle pivots; the CSV handle could not be persisted cleanly."
        ),
        "note": (
            f"Returning {len(detailed_records)} of {len(rows)} rows. Full CSV at {durable_csv}."
            if durable_csv
            else (
                f"Returning {len(detailed_records)} of {len(rows)} rows. "
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
        records=detailed_records if normalized_format == "detailed" else full_records,
        total_records=len(rows),
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
                "total_records": len(rows),
                "channel_filter": channel,
                "event_id_filter": effective_eids if effective_eids else "all",
                "event_id_strategy": event_id_strategy,
                "date_range": response.get("date_range"),
            },
        )
    promote_corroborated_findings(
        _state,
        "evtx_process_creation",
        _extract_evtx_process_paths(records),
    )
    if "data" in response:
        response["data"] = [
            sanitize_payload_fields(record, "message_summary", "extra_fields")
            for record in response["data"]
        ]
    return _evtx_contract_payload(
        response=response,
        records=detailed_records if normalized_format == "detailed" else full_records,
        image_path=image_path,
        evtx_dir=evtx_dir,
        csv_path=durable_csv,
    )


# ---------------------------------------------------------------------------
# Tool: extract_registry_run_keys
# ---------------------------------------------------------------------------

# Persistence key path fragments to match (lower-case)
_PERSISTENCE_FRAGMENTS: list[tuple[str, str]] = [
    # Run keys — absolute path (NTUSER.DAT or full SOFTWARE path)
    # NOTE: runonce/runservices MUST come before run (run is a substring of them)
    ("\\software\\microsoft\\windows\\currentversion\\runonce", "runonce"),
    ("\\software\\microsoft\\windows\\currentversion\\runservices", "run"),
    ("\\software\\microsoft\\windows\\currentversion\\run", "run"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\runonce", "runonce"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\runservices", "run"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\run", "run"),
    # Run keys — hive-relative (RECmd with -d strips the hive name prefix)
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
    # Services — both absolute and hive-relative (T1543.003)
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
    # Image File Execution Options — debugger hijacking (T1546.012)
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

    user_hives_found: list[str] = []

    # Discover user NTUSER.DAT hives
    user_roots: list[Path] = []
    seen_user_roots: set[str] = set()
    for volume_root in _candidate_windows_volume_roots(image_path):
        for users_root in (volume_root / "Users", volume_root / "Documents and Settings"):
            text = str(users_root)
            if text not in seen_user_roots:
                seen_user_roots.add(text)
                user_roots.append(users_root)
    for users_root in user_roots:
        if users_root.exists() and users_root.is_dir():
            for user_dir in users_root.iterdir():
                if user_dir.is_dir() and user_dir.name not in ("Public", "Default", "Default User", "All Users"):
                    ntuser = user_dir / "NTUSER.DAT"
                    if ntuser.exists():
                        user_hives_found.append(str(ntuser))

    cache_key = build_cache_key(
        tool,
        {
            "hive_dir": resolved_hive_dir,
            "batch_mode": batch_mode,
            "batch_file": batch_file_used or "",
            "user_hives": sorted(_resolved_path_str(path) for path in user_hives_found),
            "sync_batch": bool(sync_batch),
        },
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
                        # rla.exe failure on a single hive is non-fatal —
                        # fall back to the dirty hive AND keep its transaction
                        # logs (.LOG1/.LOG2) so RECmd can still replay them.
                        # peer reviewer round-5 P2-#2: prior fallback dropped logs,
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
                        # Neither cleaned nor original has them — surface warning
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
