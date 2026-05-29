"""
sift_mcp.tools.memory
~~~~~~~~~~~~~~~~~~~~~~

Memory forensics MCP tools for SAVVYDFIR-MCP.

All six tools wrap Volatility 3 (via :class:`~sift_mcp.runners.volatility.VolatilityRunner`),
parse the JSON output (``-r json``) into typed Pydantic models, and return
plain dicts.

Tools
-----
- ``detect_profile``    — windows.info: OS profiling.
- ``list_processes``    — windows.pslist: Live process list with heuristic
                          suspicion scoring.
- ``scan_processes``    — windows.psscan: Pool-scan for hidden/unlinked processes.
- ``scan_network``      — windows.netscan: Network socket/connection scan.
- ``detect_injection``  — windows.malfind: VAD-based injection detection.
- ``list_dlls``         — windows.dlllist: DLL list for a specific PID.

Design pattern
--------------
Module-level ``_runner``, ``_state``, and ``_audit`` singletons are injected
via :func:`init_tools`.  Volatility always emits JSON (``-r json``); tool
functions call ``json.loads(result.stdout)`` then map fields to Pydantic
model constructors.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from sift_mcp.models.artifacts import (
    DllRecord,
    InjectionIndicator,
    NetworkArtifact,
    ProcessRecord,
    ProfileResult,
)
from sift_mcp.models.finding import EvidenceKind, Finding, FindingStatus
from sift_mcp.tool_catalog import domain_metadata_for_tool
from sift_mcp.tools._contracts import (
    build_contract_response,
    build_follow_up_option,
    build_provenance,
    compact_unique,
    sanitize_payload_fields,
    state_path_for_manager,
)

if TYPE_CHECKING:
    from collections import defaultdict as _defaultdict_type  # noqa: F401

    from sift_mcp.audit import AuditLogger
    from sift_mcp.runners.volatility import VolatilityRunner
    from sift_mcp.state import CaseStateManager


__all__ = [
    "init_tools",
    "detect_profile",
    "list_processes",
    "scan_processes",
    "scan_network",
    "detect_injection",
    "list_dlls",
]


# ---------------------------------------------------------------------------
# Module-level singletons — set via init_tools()
# ---------------------------------------------------------------------------

_runner: Optional["VolatilityRunner"] = None
_state: Optional["CaseStateManager"] = None
_audit: Optional["AuditLogger"] = None


def init_tools(
    state_manager: "CaseStateManager",
    audit_logger: "AuditLogger",
    runner: Optional["VolatilityRunner"] = None,
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
    runner:
        Optional pre-built :class:`~sift_mcp.runners.volatility.VolatilityRunner`.
        When ``None`` a new runner is created with the supplied audit_logger.
    """
    global _runner, _state, _audit
    _state = state_manager
    _audit = audit_logger
    if runner is not None:
        _runner = runner
    else:
        from sift_mcp.runners.volatility import VolatilityRunner
        _runner = VolatilityRunner(
            audit_logger=audit_logger,
            state_manager=state_manager,
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _case_id() -> str:
    if _state is None:
        return "unknown"
    try:
        return _state.case_id
    except Exception:
        return "unknown"


def _current_iteration() -> int:
    if _audit is None:
        return 1
    return _audit.current_iteration


def _classify_port(port: Optional[int]) -> str:
    """Classify a port number into a structural bucket for grouping.

    Returns a stable token used as part of the netscan group_key so that
    connections to the same host on similar ports collapse together.
    """
    if port is None or port == 0:
        return "none"
    if port <= 1023:
        return "well_known"
    if port <= 49151:
        return "registered"
    return "ephemeral"


def _not_initialised(tool_name: str) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "status": "error",
        "error_message": "Tools not initialised. Call init_tools() first.",
        "data": [],
        "findings_created": [],
        "execution_id": None,
        "raw_command": None,
    }


def _normalize_response_format(response_format: str) -> Optional[str]:
    """Validate and normalize the heavy-tool response format selector."""
    normalized = (response_format or "summary").strip().lower()
    if normalized in {"summary", "detailed"}:
        return normalized
    return None


def _dump_identifier(dump_path: str) -> str:
    """Derive a filename-safe identifier from a memory dump path.

    E.1 (peer reviewer round-1 P2): in multi-dump cases (enterprise scope with
    one .img per host), pslist/psscan artifacts must be partitioned per
    dump so the gate's psscan_only_count comparison pairs the right
    pslist with the right psscan. Identifier is the basename minus
    extension, with non-safe characters replaced.
    """
    name = Path(dump_path or "").stem or "dump"
    import re as _re
    return _re.sub(r"[^A-Za-z0-9._-]", "_", name)[:64] or "dump"


def _persist_rows_as_csv(
    rows: list[dict[str, Any]],
    *,
    tool_short_name: str,
    filename: str,
    dump_path: Optional[str] = None,
) -> Optional[str]:
    """Persist structured rows as a reusable CSV artifact.

    E.1: when `dump_path` is provided, the CSV is written under a
    dump-keyed subdirectory so a multi-dump case keeps each dump's
    artifacts separate. The legacy `<tool>/<filename>` path is also
    updated to point at the latest run (best-effort) for backwards
    compatibility with anything still reading the legacy filename.
    """
    import csv

    try:
        cid = _case_id()
        base = Path(os.environ.get("OUTPUT_BASE", "/cases")) / cid / "artifacts" / tool_short_name
        base.mkdir(parents=True, exist_ok=True)

        # Dump-keyed destination (E.1) — primary write target.
        dump_id = _dump_identifier(dump_path) if dump_path else None
        if dump_id:
            dump_dest = base / dump_id / filename
            dump_dest.parent.mkdir(parents=True, exist_ok=True)
            dest = dump_dest
        else:
            dest = base / filename

        if not rows:
            dest.write_text("", encoding="utf-8")
        else:
            fieldnames = list(rows[0].keys())
            with dest.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: row.get(k, "") for k in fieldnames})

        # Backwards-compat: also expose at the legacy <tool>/<filename>
        # path. In a single-dump case this is a no-op; in multi-dump
        # cases it is overwritten by the latest call (callers that need
        # dump-specific data must read the dump-keyed path).
        if dump_id:
            legacy = base / filename
            try:
                import shutil as _shutil
                _shutil.copy2(str(dest), str(legacy))
            except Exception:
                pass

        return str(dest)
    except Exception:
        return None


def _runner_error(
    tool_name: str,
    exc: Exception,
    execution_id: Optional[str] = None,
    stderr: str = "",
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "status": "error",
        "error_message": f"Runner error: {exc}",
        "data": [],
        "findings_created": [],
        "execution_id": execution_id,
        "raw_command": str(exc),
        "stderr": stderr,
    }


def _detect_injection_contract_payload(
    *,
    response: dict[str, Any],
    records: list[InjectionIndicator],
    dump_path: str,
) -> dict[str, Any]:
    normalized = [
        {
            "pid": record.pid,
            "process_name": record.process_name,
            "vad_start": record.vad_start,
            "protection": record.protection,
            "has_mz_header": record.has_mz_header,
            "suspicious_score": round(record.suspicious_score, 3),
        }
        for record in records[:20]
    ]
    evidence_excerpt = next(
        (record.disassembly_preview for record in records if record.disassembly_preview),
        None,
    )
    return build_contract_response(
        response,
        case_id=_case_id(),
        execution_id=response.get("execution_id"),
        state_manager=_state,
        audit_logger=_audit,
        tool_name="memory.detect_injection",
        summary=(
            f"Malfind returned {response.get('injection_count', len(records))} suspicious memory regions "
            f"from {dump_path}."
        ),
        normalized_observations=normalized,
        provenance=build_provenance(
            tool_name="memory.detect_injection",
            execution_id=response.get("execution_id"),
            raw_command=response.get("raw_command"),
            state_path=state_path_for_manager(_state),
            artifact_paths=[dump_path],
        ),
        pivot_entities={
            "pids": compact_unique(record.pid for record in records),
            "process_names": compact_unique(record.process_name for record in records),
            "vad_regions": compact_unique(f"{record.vad_start}-{record.vad_end}" for record in records),
            "protections": compact_unique(record.protection for record in records),
        },
        follow_up_options=[
            build_follow_up_option(
                "list_dlls",
                reason="Inspect suspicious processes for sideloaded or reflectively loaded DLLs.",
                parameters={"dump_path": dump_path},
            ),
            build_follow_up_option(
                "scan_network",
                reason="Check whether suspicious processes maintained external network connections.",
                parameters={"dump_path": dump_path},
            ),
            build_follow_up_option(
                "scan_processes",
                reason="Compare malfind candidates with pool-scan process visibility.",
                parameters={"dump_path": dump_path},
            ),
        ],
        evidence_excerpt=evidence_excerpt,
    )


def _parse_vol_dt(value: Any) -> Optional[datetime]:
    """Parse a Volatility JSON datetime value into a Python datetime.

    Volatility 3 emits timestamps in several formats:
    - ISO 8601 strings: ``"2021-05-01T14:23:11.000000"``
    - Integer epoch seconds: ``1619879391``
    - ``"N/A"`` or empty string for absent values
    """
    if value is None:
        return None
    if isinstance(value, (int, float)) and value > 0:
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None
    if isinstance(value, str):
        val = value.strip()
        if not val or val.upper() in ("N/A", "NULL", "NONE", ""):
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(val, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _parse_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 JSON output (``-r json``) into a list of row dicts.

    Volatility 3 emits output as a JSON object with a ``rows`` key and a
    ``columns`` key, or as a JSON array of objects depending on version.

    Parameters
    ----------
    stdout:
        Raw stdout from a Volatility 3 run with ``-r json``.

    Returns
    -------
    list[dict[str, Any]]
        Each element is a dict mapping column names to values.
        Returns an empty list if the output cannot be parsed.
    """
    stdout = stdout.strip()
    if not stdout:
        return []

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        # Volatility sometimes emits non-JSON warnings before the JSON block;
        # try to find the first '[' or '{'
        for start_char in ("[", "{"):
            idx = stdout.find(start_char)
            if idx >= 0:
                try:
                    parsed = json.loads(stdout[idx:])
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return []

    # Handle Volatility 3 columnar format: {"columns": [...], "rows": [[...], ...]}
    if isinstance(parsed, dict) and "columns" in parsed and "rows" in parsed:
        columns: list[str] = parsed["columns"]
        rows: list[list[Any]] = parsed["rows"]
        return [dict(zip(columns, row)) for row in rows]

    # Handle simple JSON array of objects
    if isinstance(parsed, list):
        if not parsed:
            return []
        if isinstance(parsed[0], dict):
            return parsed
        # Array of arrays (unusual but handle gracefully)
        return []

    # Handle single object (e.g. windows.info)
    if isinstance(parsed, dict):
        return [parsed]

    return []


# ---------------------------------------------------------------------------
# Suspicion heuristics for process analysis
# ---------------------------------------------------------------------------

_SYSTEM32 = "\\windows\\system32\\"
_SYSWOW64 = "\\windows\\syswow64\\"

# Known processes that should only run from System32
_SYSTEM32_ONLY: set[str] = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "smss.exe", "taskhost.exe",
    "spoolsv.exe", "lsm.exe", "dwm.exe",
}

# Known legitimate parent-child relationships
# child → expected parent name
_EXPECTED_PARENTS: dict[str, str] = {
    # smss.exe spawns child smss.exe during session init (normal)
    "smss.exe": "system|smss.exe",
    "csrss.exe": "smss.exe",
    "wininit.exe": "smss.exe",
    "winlogon.exe": "smss.exe",
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "svchost.exe": "services.exe",
    "taskhost.exe": "services.exe",
    "spoolsv.exe": "services.exe",
    "explorer.exe": "userinit.exe",
}


def _score_process_suspicion(
    name: str,
    path: Optional[str],
    ppid: int,
    parent_name: Optional[str],
) -> tuple[bool, Optional[str]]:
    """Apply heuristic checks to determine if a process is suspicious.

    Returns
    -------
    tuple[bool, Optional[str]]
        ``(suspicious, reason)`` — ``True`` if any heuristic fires.
    """
    name_lower = name.lower()
    reasons: list[str] = []

    # 1. Single-character process name (rare in legitimate software)
    if len(name) <= 2 and not name.lower().endswith(".exe"):
        reasons.append(f"Unusually short process name: {name!r}")

    # 2. Known system process running from unexpected location
    if name_lower in _SYSTEM32_ONLY and path:
        path_lower = path.lower()
        if _SYSTEM32 not in path_lower and _SYSWOW64 not in path_lower:
            reasons.append(
                f"{name} is expected in System32 but runs from {path!r}"
            )

    # 3. Unexpected parent process
    expected_parent = _EXPECTED_PARENTS.get(name_lower)
    if expected_parent and parent_name:
        # Support pipe-separated list of valid parents (e.g. "system|smss.exe")
        valid_parents = [p.strip().lower() for p in expected_parent.split("|")]
        if parent_name.lower() not in valid_parents:
            reasons.append(
                f"{name} expected parent {expected_parent!r} but got {parent_name!r}"
            )

    # 4. svchost without a -k flag in the command line (common masquerading)
    # (Cannot check command line here without more context; left for calling tool)

    # 5. Common malware masquerading: names that look like system process names
    _MASQUERADE_PATTERNS = [
        (r"^svch[o0]st", "svchost masquerade"),
        (r"^lsas[s5]", "lsass masquerade"),
        (r"^explo[r]er", "explorer masquerade"),
        (r"^cs[r]ss", "csrss masquerade"),
    ]
    for pattern, reason in _MASQUERADE_PATTERNS:
        if re.match(pattern, name_lower) and name_lower not in _EXPECTED_PARENTS:
            reasons.append(f"Possible masquerade: {name!r} matches {reason}")
            break

    if reasons:
        return True, "; ".join(reasons)
    return False, None


# ---------------------------------------------------------------------------
# Tool: detect_profile
# ---------------------------------------------------------------------------


def detect_profile(dump_path: str) -> dict[str, Any]:
    """Detect the OS profile of a memory dump using Volatility 3 windows.info.

    Wraps ``python3 /opt/volatility3-2.20.0/vol.py -r json windows.info``
    on SIFT Workstation.

    This should be the **first tool called** on any new memory dump.  It
    confirms Volatility can parse the dump and returns the OS build information
    needed to interpret other Volatility output.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump (``.raw``, ``.mem``, ``.vmem``,
        ``.lime``).

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list with a single ProfileResult
        dict), ``findings_created``, ``execution_id``, ``raw_command``.
    """
    tool = "memory.detect_profile"
    if _runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    try:
        result = _runner.windows_info(dump_path=dump_path, tool_name=tool)
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"windows.info exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
            "volatility_error": _runner.classify_error(result),
        }

    rows = _parse_json_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation — free the multi-MB stdout now that we have parsed rows

    # windows.info emits key-value rows or a single object.
    # Fields: NtMajorVersion, NtMinorVersion, NtBuildLab, SystemTime,
    # NtSystemRoot, Is64Bit, IsPAE, primary, memory_layer, etc.
    info: dict[str, Any] = {}
    if rows:
        # Columnar format has Variable/Value columns
        for row in rows:
            var = row.get("Variable") or row.get("variable") or ""
            val = row.get("Value") or row.get("value") or ""
            if var:
                info[var] = val
        # If it came as a flat dict
        if not info:
            info = rows[0]

    # Extract OS details
    major = str(info.get("NtMajorVersion") or info.get("MajorVersion") or "")
    minor = str(info.get("NtMinorVersion") or info.get("MinorVersion") or "")
    build_lab = str(info.get("NtBuildLab") or info.get("BuildLab") or "")
    build_number = re.search(r"(\d+)\.", build_lab)
    build_num = build_number.group(1) if build_number else str(
        info.get("NtBuildNumber") or info.get("BuildNumber") or ""
    )

    is_64bit = str(info.get("Is64Bit") or info.get("is64bit") or "").lower() in (
        "true", "1", "yes"
    )
    architecture = "x64" if is_64bit else "x86"

    # Construct a human-readable OS version string
    _WIN_VERSIONS = {
        ("10", "0"): "Windows 10",
        ("6", "3"): "Windows 8.1 / Server 2012 R2",
        ("6", "2"): "Windows 8 / Server 2012",
        ("6", "1"): "Windows 7 / Server 2008 R2",
        ("6", "0"): "Windows Vista / Server 2008",
        ("5", "2"): "Windows XP x64 / Server 2003",
        ("5", "1"): "Windows XP",
    }
    base_version = _WIN_VERSIONS.get(
        (major, minor),
        f"Windows {major}.{minor}" if major else "Windows (unknown)"
    )
    os_version = f"{base_version} (build {build_num})" if build_num else base_version

    try:
        profile = ProfileResult(
            os_name="Windows",
            os_version=os_version,
            architecture=architecture,  # type: ignore[arg-type]
            build_number=build_num or None,
            kernel_base=str(info.get("DTB") or info.get(
                "KernelBase") or "") or None,
        )
    except Exception as exc:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": f"Failed to construct ProfileResult: {exc}",
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "raw_info": info,
        }

    finding = Finding(
        case_id=_case_id(),
        finding_type="other",
        artifact_type="memory",
        artifact_path=dump_path,
        tool_name=tool,
        execution_id=result.execution_id,
        iteration=_current_iteration(),
        evidence_kind=EvidenceKind.OBSERVATION,
        finding_status=FindingStatus.ACTIVE,
        confidence=0.99,
        description=(
            f"Memory dump profiled: {os_version} ({architecture}). "
            f"Build: {build_num or 'unknown'}. "
            f"Volatility 3 successfully parsed the dump header."
        ),
        supporting_indicators=[
            f"os_version={os_version}",
            f"architecture={architecture}",
            f"build={build_num or 'unknown'}",
        ],
    )
    fid = _state.add_finding(finding.model_dump(mode="json"))

    return {
        "tool_name": tool,
        "status": "success",
        "data": [profile.model_dump(mode="json")],
        "findings_created": [fid],
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
    }


# ---------------------------------------------------------------------------
# Tool: list_processes
# ---------------------------------------------------------------------------

def _parse_process_rows(
    rows: list[dict[str, Any]],
    source: str,
) -> list[ProcessRecord]:
    """Convert Volatility JSON rows into ProcessRecord objects.

    Parameters
    ----------
    rows:
        Rows from ``_parse_json_output``.
    source:
        ``"pslist"`` or ``"psscan"``.

    Returns
    -------
    list[ProcessRecord]
    """
    records: list[ProcessRecord] = []
    for row in rows:
        try:
            pid = int(row.get("PID") or row.get("Pid") or row.get("pid") or 0)
            ppid = int(row.get("PPID") or row.get(
                "PPid") or row.get("ppid") or 0)
            name = str(row.get("ImageFileName") or row.get(
                "Name") or row.get("name") or "")
            path = row.get("ImageFilePath") or row.get(
                "Path") or row.get("path") or None
            cmd = row.get("CmdLine") or row.get(
                "CommandLine") or row.get("Cmdline") or None
            threads_raw = row.get("Threads") or row.get(
                "ActiveThreads") or None
            try:
                num_threads = int(
                    threads_raw) if threads_raw is not None else None
            except (TypeError, ValueError):
                num_threads = None
            session_raw = row.get("SessionId") or row.get("SessionID") or None
            try:
                session_id = int(
                    session_raw) if session_raw is not None else None
            except (TypeError, ValueError):
                session_id = None
            wow64_raw = row.get("Wow64") or row.get(
                "IsWow64") or row.get("wow64") or False
            is_wow64 = str(wow64_raw).lower() in ("true", "1", "yes")
            offset = (
                str(row.get("Offset(V)") or row.get(
                    "Offset") or row.get("offset") or "0x0")
            )
            if not offset.startswith("0x"):
                try:
                    offset = hex(int(offset))
                except (ValueError, TypeError):
                    offset = "0x0"

            create_time = _parse_vol_dt(
                row.get("CreateTime") or row.get("create_time") or None
            )
            exit_time = _parse_vol_dt(
                row.get("ExitTime") or row.get("exit_time") or None
            )

            record = ProcessRecord(
                pid=pid,
                ppid=ppid,
                name=name or "unknown",
                path=path if isinstance(path, str) else None,
                command_line=cmd if isinstance(cmd, str) else None,
                create_time=create_time,
                exit_time=exit_time,
                num_threads=num_threads,
                session_id=session_id,
                is_wow64=is_wow64,
                suspicious=False,
                suspicion_reason=None,
                offset=offset,
                source=source,  # type: ignore[arg-type]
            )
            records.append(record)
        except Exception:
            continue
    return records


def list_processes(dump_path: str, case_id: Optional[str] = None, max_results: int = 0, response_format: str = "summary") -> dict[str, Any]:
    """List running processes from a memory dump using Volatility 3 windows.pslist.

    Wraps ``python3 /opt/volatility3-2.20.0/vol.py -r json windows.pslist``
    on SIFT Workstation.

    Reads the doubly-linked PEB process list from the kernel.  Processes that
    are hidden via DKOM (Direct Kernel Object Manipulation) will NOT appear
    here — use :func:`scan_processes` to detect them.

    Heuristic suspicion scoring
    ---------------------------
    The tool applies the following checks to flag suspicious processes:

    * Known system processes (svchost.exe, lsass.exe, etc.) running from
      a path other than ``System32`` or ``SysWOW64``.
    * Single-character or very short process names.
    * Unexpected parent-child relationships (e.g. svchost with a non-services
      parent).

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.
    response_format:
        ``"summary"`` (default) omits the full process array and returns
        counts/preview only.  ``"detailed"`` returns the full data array.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of ProcessRecord dicts with
        suspicion fields populated), ``findings_created``, ``execution_id``,
        ``raw_command``, ``process_count``, ``suspicious_count``.
    """
    tool = "memory.list_processes"
    if _runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)

    try:
        result = _runner.pslist(dump_path=dump_path, tool_name=tool)
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"windows.pslist exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
            "volatility_error": _runner.classify_error(result),
        }

    rows = _parse_json_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation — free the multi-MB stdout now that we have parsed rows
    records = _parse_process_rows(rows, source="pslist")

    # Build a pid → name map for parent-name resolution
    pid_to_name: dict[int, str] = {r.pid: r.name for r in records}

    # Apply suspicion heuristics
    finding_ids: list[str] = []
    suspicious_count = 0
    suspicious_records: list[ProcessRecord] = []

    for idx, record in enumerate(records):
        parent_name = pid_to_name.get(record.ppid)
        suspicious, reason = _score_process_suspicion(
            name=record.name,
            path=record.path,
            ppid=record.ppid,
            parent_name=parent_name,
        )
        # Use model_copy to update fields (Pydantic v2)
        records[idx] = record.model_copy(
            update={"suspicious": suspicious, "suspicion_reason": reason}
        )

        if suspicious:
            suspicious_count += 1
            suspicious_records.append(records[idx])
            finding = Finding(
                case_id=_case_id(),
                finding_type="defense_evasion",
                artifact_type="memory",
                artifact_path=dump_path,
                artifact_offset=record.offset,
                tool_name=tool,
                execution_id=result.execution_id,
                iteration=_current_iteration(),
                evidence_kind=EvidenceKind.HYPOTHESIS,
                finding_status=FindingStatus.ACTIVE,
                confidence=0.7,
                description=(
                    f"Suspicious process: {record.name} (PID {record.pid}). "
                    f"Reason: {reason}. "
                    f"Path: {record.path or 'unknown'}. "
                    f"PPID: {record.ppid} ({parent_name or 'unknown'})."
                ),
                supporting_indicators=[
                    f"pid={record.pid}",
                    f"name={record.name}",
                    f"path={record.path or 'N/A'}",
                    f"offset={record.offset}",
                ],
                mitre_tactic="TA0005",
                mitre_technique="T1036",
            )
            fid = _state.add_finding(finding.model_dump(mode="json"))
            finding_ids.append(fid)

    # peer reviewer round-7 P2: emit a baseline pslist finding carrying pslist_pids
    # so the report gate's _needs_detect_injection can recompute the
    # psscan-pslist delta when scan_processes ran before list_processes.
    # Without this, a stored psscan_unverified=True finding cannot be
    # paired with the eventual pslist baseline.
    baseline_finding = Finding(
        case_id=_case_id(),
        finding_type="other",
        artifact_type="memory",
        artifact_path=dump_path,
        tool_name=tool,
        execution_id=result.execution_id,
        iteration=_current_iteration(),
        evidence_kind=EvidenceKind.OBSERVATION,
        finding_status=FindingStatus.ACTIVE,
        confidence=1.0,
        description=(
            f"Pslist baseline: {len(records)} active processes from {dump_path}."
        ),
        supporting_indicators=[
            f"total_processes={len(records)}",
            dump_path,
        ],
        pslist_pids=sorted(r.pid for r in records),
    )
    try:
        baseline_fid = _state.add_finding(baseline_finding.model_dump(mode="json"))
        finding_ids.append(baseline_fid)
    except Exception:
        pass  # baseline finding is a follow-up aid; suspicious findings are primary

    # Persist all rows to CSV for run_analysis() queries.
    # E.1: include dump_path so the CSV lands under a dump-keyed dir.
    all_rows = [r.model_dump(mode="json") for r in records]
    csv_path = _persist_rows_as_csv(
        all_rows,
        tool_short_name="pslist",
        filename="pslist.csv",
        dump_path=dump_path,
    )

    response: dict[str, Any] = {
        "tool_name": tool,
        "status": "success",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "process_count": len(records),
        "suspicious_count": suspicious_count,
    }
    if csv_path:
        response["csv_path"] = csv_path

    if normalized_format == "detailed":
        response["data"] = all_rows
    else:
        # Summary: preview suspicious + a few representative normal processes
        preview: list[dict[str, Any]] = [r.model_dump(mode="json") for r in suspicious_records[:10]]
        normal_sample = [r for r in records if not r.suspicious][:5]
        preview.extend(r.model_dump(mode="json") for r in normal_sample)
        response["preview"] = preview
        response["summary"] = (
            f"{len(records)} processes found via pslist. "
            f"{suspicious_count} flagged suspicious. "
            f"Full data at {csv_path or 'not persisted'}."
        )
        response["note"] = (
            'Full process array omitted by default; pass response_format="detailed" '
            "for the complete data."
        )

    return response


# ---------------------------------------------------------------------------
# Tool: scan_processes
# ---------------------------------------------------------------------------


def _load_pslist_pids_for_case(dump_path: Optional[str] = None) -> Optional[set[int]]:
    """Load PID set from the pslist CSV that matches the SAME dump.

    E.1 (peer reviewer round-1 P2): a multi-dump case stores each dump's pslist
    at artifacts/pslist/<dump_id>/pslist.csv. The matching psscan run
    must read its own dump's pslist, not whichever pslist was written
    most recently (which would silently compare PIDs across dumps).

    Resolution:
      1. If `dump_path` is provided, try artifacts/pslist/<dump_id>/pslist.csv first.
      2. Fall back to legacy artifacts/pslist/pslist.csv only if the
         dump-keyed file does not exist (single-dump cases pre-E.1).
      3. Return None if neither exists.
    """
    if _state is None:
        return None
    cid = _case_id()
    base = Path(os.environ.get("OUTPUT_BASE", "/cases")) / cid / "artifacts" / "pslist"

    candidates: list[Path] = []
    if dump_path:
        candidates.append(base / _dump_identifier(dump_path) / "pslist.csv")
    candidates.append(base / "pslist.csv")

    csv_path: Optional[Path] = None
    for cand in candidates:
        if cand.is_file():
            csv_path = cand
            break
    if csv_path is None:
        return None

    import csv as _csv
    pids: set[int] = set()
    try:
        with csv_path.open(encoding="utf-8", newline="") as fh:
            reader = _csv.DictReader(fh)
            for row in reader:
                raw = row.get("pid") or row.get("PID") or row.get("Pid") or 0
                try:
                    pids.add(int(raw))
                except (TypeError, ValueError):
                    continue
    except OSError:
        return None
    return pids


def scan_processes(dump_path: str, response_format: str = "summary") -> dict[str, Any]:
    """Scan physical memory for EPROCESS structures using Volatility 3 windows.psscan.

    Wraps ``python3 /opt/volatility3-2.20.0/vol.py -r json windows.psscan``
    on SIFT Workstation.

    Unlike :func:`list_processes`, psscan scans raw memory pages for EPROCESS
    pool tags instead of walking the kernel linked list.  This surfaces
    **hidden processes** (DKOM-unlinked) and **terminated processes** whose
    EPROCESS structures have not yet been overwritten.

    Compare psscan output against pslist output: any process present in psscan
    but absent in pslist was actively hidden by a rootkit.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.
    response_format:
        ``"summary"`` (default) omits the full process array and returns
        counts/preview only.  ``"detailed"`` returns the full data array.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of ProcessRecord dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``process_count``.
    """
    tool = "memory.scan_processes"
    if _runner is None or _state is None or _audit is None:
        return _not_initialised(tool)
    normalized_format = _normalize_response_format(response_format)

    try:
        result = _runner.psscan(dump_path=dump_path, tool_name=tool)
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"windows.psscan exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
            "volatility_error": _runner.classify_error(result),
        }

    rows = _parse_json_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation — free the multi-MB stdout now that we have parsed rows
    records = _parse_process_rows(rows, source="psscan")

    # E.1: pass the current scan's dump_path so we pair with THAT dump's
    # pslist baseline, not a stale pslist from a different memory dump.
    pslist_pids = _load_pslist_pids_for_case(dump_path=dump_path)
    psscan_pids = {r.pid for r in records}
    # peer reviewer round-7 P2: prior implementation set psscan_only_count to
    # len(psscan_pids) when pslist absent, forcing detect_injection on every
    # run even with no actual hidden processes (false positive). Original
    # Run2 set it to 0 (false negative when scan_processes runs first).
    # Correct behavior: report a real delta only when pslist exists, mark
    # the result unverified otherwise. The report gate is patched to
    # recompute the delta from current state at evaluation time, so a
    # later list_processes run satisfies the gate without re-running
    # scan_processes.
    if pslist_pids is not None:
        psscan_only_count = len(psscan_pids - pslist_pids)
        psscan_unverified = False
    else:
        psscan_only_count = 0
        psscan_unverified = True
    requires_deeper = bool(psscan_only_count > 0)

    # Create a summary finding
    finding_ids: list[str] = []
    if records:
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="memory",
            artifact_path=dump_path,
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=(
                f"Pool scan (psscan) found {len(records)} EPROCESS structures in {dump_path}. "
                "This includes terminated/hidden processes not in the active list. "
                "Compare with pslist output to identify DKOM-hidden processes."
            ),
            supporting_indicators=[
                f"total_processes={len(records)}",
                f"psscan_only_count={psscan_only_count}",
                f"psscan_unverified={psscan_unverified}",
                dump_path,
            ],
            psscan_only_count=psscan_only_count,
            psscan_unverified=psscan_unverified,
            psscan_pids=sorted(psscan_pids),
            requires_deeper_analysis=requires_deeper,
            next_required_tool=("detect_injection" if requires_deeper else None),
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)

    # Persist all rows to CSV.
    # E.1: include dump_path so a multi-dump case keeps each dump's psscan separate.
    all_rows = [r.model_dump(mode="json") for r in records]
    csv_path = _persist_rows_as_csv(
        all_rows,
        tool_short_name="psscan",
        filename="psscan.csv",
        dump_path=dump_path,
    )

    response: dict[str, Any] = {
        "tool_name": tool,
        "status": "success",
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "process_count": len(records),
    }
    if csv_path:
        response["csv_path"] = csv_path

    if normalized_format == "detailed":
        response["data"] = all_rows
    else:
        preview = [r.model_dump(mode="json") for r in records[:10]]
        response["preview"] = preview
        response["summary"] = (
            f"{len(records)} EPROCESS structures found via psscan. "
            f"Full data at {csv_path or 'not persisted'}."
        )
        response["note"] = (
            'Full process array omitted by default; pass response_format="detailed" '
            "for the complete data."
        )

    return response


# ---------------------------------------------------------------------------
# Tool: scan_network
# ---------------------------------------------------------------------------


def scan_network(dump_path: str, case_id: Optional[str] = None, max_results: int = 0) -> dict[str, Any]:
    """Scan memory for network connections and sockets using Volatility 3 windows.netscan.

    Wraps ``python3 /opt/volatility3-2.20.0/vol.py -r json windows.netscan``
    on SIFT Workstation.

    Finds TCP/UDP endpoints and connections in the memory image, including
    closed/unlinked socket structures that would not appear in a live
    ``netstat`` listing.  Particularly useful for detecting C2 connections
    that were active at the time of acquisition.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of NetworkArtifact dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``connection_count``, ``established_count``.
    """
    tool = "memory.scan_network"
    if _runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    try:
        result = _runner.netscan(dump_path=dump_path, tool_name=tool)
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"windows.netscan exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
            "volatility_error": _runner.classify_error(result),
        }

    rows = _parse_json_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation — free the multi-MB stdout now that we have parsed rows
    records: list[NetworkArtifact] = []
    finding_ids: list[str] = []
    established_count = 0

    # Phase 5: group established connections by (pid, remote_ip, port_class)
    # instead of emitting one finding per row.
    from collections import defaultdict
    _net_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        try:
            proto_raw = str(row.get("Proto") or row.get(
                "Protocol") or row.get("proto") or "TCP")
            proto = "TCP" if "tcp" in proto_raw.lower() else "UDP"

            local_addr = str(
                row.get("LocalAddr") or row.get(
                    "local_addr") or row.get("LocalIp") or "0.0.0.0"
            )
            local_port_raw = row.get("LocalPort") or row.get("local_port") or 0
            try:
                local_port = int(local_port_raw)
            except (ValueError, TypeError):
                local_port = 0

            foreign_addr_raw = (
                row.get("ForeignAddr") or row.get("RemoteAddr")
                or row.get("remote_addr") or row.get("ForeignIp") or None
            )
            foreign_addr = str(foreign_addr_raw) if foreign_addr_raw else None
            # Treat "0.0.0.0", "*", or "*:*" as listening (no remote)
            if foreign_addr in ("0.0.0.0", "*", "", "N/A"):
                foreign_addr = None

            foreign_port_raw = (
                row.get("ForeignPort") or row.get("RemotePort")
                or row.get("remote_port") or None
            )
            try:
                foreign_port = int(foreign_port_raw) if foreign_port_raw not in (
                    None, "*", "") else None
            except (ValueError, TypeError):
                foreign_port = None

            state = str(
                row.get("State") or row.get(
                    "state") or row.get("ConnectionState") or ""
            ).strip() or None

            pid_raw = row.get("PID") or row.get("Pid") or row.get("pid") or 0
            try:
                pid = int(pid_raw)
            except (ValueError, TypeError):
                pid = 0

            owner = (
                row.get("Owner") or row.get(
                    "Process") or row.get("ImageFileName") or None
            )

            offset_raw = (
                row.get("Offset(P)") or row.get(
                    "Offset") or row.get("offset") or "0x0"
            )
            offset = str(offset_raw)
            if not offset.startswith("0x"):
                try:
                    offset = hex(int(offset))
                except (ValueError, TypeError):
                    offset = "0x0"

            create_time = _parse_vol_dt(
                row.get("CreateTime") or row.get("create_time") or None
            )

            record = NetworkArtifact(
                protocol=proto,  # type: ignore[arg-type]
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=foreign_addr,
                remote_port=foreign_port,
                state=state,
                pid=pid,
                owner_process=str(owner) if owner else None,
                offset=offset,
                create_time=create_time,
            )
            records.append(record)

            if state and state.upper() == "ESTABLISHED":
                established_count += 1

                # Phase 5: accumulate into groups instead of emitting per-row
                if foreign_addr and foreign_addr not in ("127.0.0.1", "::1"):
                    port_class = _classify_port(foreign_port)
                    group_key = f"netscan:{pid}:{foreign_addr}:{port_class}"
                    _net_groups[group_key].append({
                        "pid": pid,
                        "owner": owner,
                        "local_addr": local_addr,
                        "local_port": local_port,
                        "remote_addr": foreign_addr,
                        "remote_port": foreign_port,
                        "proto": proto,
                        "offset": offset,
                    })

        except Exception:
            continue

    # Phase 5: emit one finding per group (pid + remote_ip + port_class)
    suppressed_count = 0
    for group_key, members in _net_groups.items():
        representative = members[0]
        count = len(members)
        ports = compact_unique(str(m["remote_port"]) for m in members)
        local_endpoints = compact_unique(f"{m['local_addr']}:{m['local_port']}" for m in members)
        owner_name = representative["owner"] or "unknown"
        follow_pid = int(representative["pid"])
        finding = Finding(
            case_id=_case_id(),
            finding_type="data_exfil",
            artifact_type="memory",
            artifact_path=dump_path,
            artifact_offset=representative["offset"],
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.75,
            description=(
                f"{count} established {representative['proto']} connection(s) to "
                f"{representative['remote_addr']} (ports: {', '.join(ports)}). "
                f"Owning process: {owner_name} (PID {representative['pid']}). "
                "Grouped connections to the same external host from the same process "
                "may indicate active C2 or data exfiltration."
            ),
            supporting_indicators=(
                [f"remote={representative['remote_addr']}"]
                + [f"port={p}" for p in ports[:5]]
                + local_endpoints[:5]
                + [
                    f"pid={representative['pid']}",
                    f"process={owner_name}",
                    f"connection_count={count}",
                ]
            ),
            mitre_tactic="TA0011",
            mitre_technique="T1071",
            group_key=group_key,
            support_count=count,
            promotion_reason="established_external",
            network_followup_pids=[follow_pid],
            network_pids=[follow_pid],
            next_required_tool="list_dlls",
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)
        suppressed_count += count - 1  # all but the representative

    grouping_context = {
        "strategy": "pid_remoteip_portclass",
        "groups_formed": len(_net_groups),
        "total_candidates": sum(len(m) for m in _net_groups.values()),
        "suppressed_duplicates": suppressed_count,
    }

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "connection_count": len(records),
        "established_count": established_count,
        "suppression_summary": {
            "total_raw_signals": sum(len(m) for m in _net_groups.values()),
            "findings_emitted": len(finding_ids),
            "signals_suppressed": suppressed_count,
            "reason": "Grouped by pid + remote_ip + port_class to reduce noise.",
        },
        "grouping_context": grouping_context,
        "domain_metadata": domain_metadata_for_tool(tool),
    }


# ---------------------------------------------------------------------------
# Tool: detect_injection
# ---------------------------------------------------------------------------


def detect_injection(
    dump_path: str,
    pid: Optional[int] = None,
    case_id: Optional[str] = None,
    max_results: int = 0,
) -> dict[str, Any]:
    """Detect process injection using Volatility 3 windows.malfind.

    Wraps ``python3 /opt/volatility3-2.20.0/vol.py -r json windows.malfind``
    on SIFT Workstation.

    Malfind flags VAD regions that are:
    - Executable (PAGE_EXECUTE_*), AND
    - Not backed by a mapped file on disk (anonymous), OR
    - Have an MZ (PE) header at the base (reflectively-loaded DLL).

    This is one of the most reliable heuristics for detecting shellcode
    injection, reflective DLL injection, and process hollowing.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.
    pid:
        When given, restrict the scan to a single process by PID.
        When ``None``, all processes are scanned.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of InjectionIndicator dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``injection_count``, ``mz_header_count``.
    """
    tool = "memory.detect_injection"
    if _runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    try:
        result = _runner.malfind(dump_path=dump_path, pid=pid, tool_name=tool)
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"windows.malfind exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
            "volatility_error": _runner.classify_error(result),
        }

    rows = _parse_json_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation — free the multi-MB stdout now that we have parsed rows
    records: list[InjectionIndicator] = []
    finding_ids: list[str] = []
    mz_header_count = 0

    # Phase 5: group malfind regions by PID instead of one finding per region.
    from collections import defaultdict
    _injection_groups: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        try:
            row_pid = int(row.get("PID") or row.get(
                "Pid") or row.get("pid") or 0)
            proc_name = str(
                row.get("Process") or row.get(
                    "ImageFileName") or row.get("process") or "unknown"
            )
            vad_start = str(
                row.get("Start VPN") or row.get(
                    "VadStart") or row.get("StartVPN") or "0x0"
            )
            vad_end = str(
                row.get("End VPN") or row.get(
                    "VadEnd") or row.get("EndVPN") or "0x0"
            )
            # Normalise hex addresses
            for addr in (vad_start, vad_end):
                if not addr.startswith("0x"):
                    try:
                        addr = hex(int(addr))
                    except (ValueError, TypeError):
                        pass

            protection = str(
                row.get("Protection") or row.get(
                    "Tag") or row.get("protection") or "UNKNOWN"
            )

            # Check for MZ header in the hex dump field
            hex_dump = str(
                row.get("Hexdump") or row.get(
                    "HexDump") or row.get("hexdump") or ""
            ).lower()
            disasm = str(
                row.get("Disassembly") or row.get(
                    "disasm") or row.get("Dis") or ""
            )
            # MZ magic: 4d 5a at offset 0
            has_mz = (
                hex_dump.startswith("4d 5a") or
                hex_dump.startswith("4d5a") or
                "4d 5a" in hex_dump[:8] or
                str(row.get("MZHeader") or row.get(
                    "HasMzHeader") or "").lower() == "true"
            )
            if has_mz:
                mz_header_count += 1

            # Calculate a heuristic suspicion score
            score = 0.5  # Base score for appearing in malfind at all
            if has_mz:
                score += 0.35  # MZ header is a very strong indicator
            if "execute_readwrite" in protection.lower():
                score += 0.1  # RWX is suspicious
            score = min(score, 1.0)

            record = InjectionIndicator(
                pid=row_pid,
                process_name=proc_name,
                vad_start=vad_start,
                vad_end=vad_end,
                protection=protection,
                has_mz_header=has_mz,
                dump_path=None,
                suspicious_score=score,
                disassembly_preview=disasm[:500] if disasm else None,
            )
            records.append(record)

            # Phase 5: accumulate into per-PID groups
            _injection_groups[row_pid].append({
                "pid": row_pid,
                "process_name": proc_name,
                "vad_start": vad_start,
                "vad_end": vad_end,
                "protection": protection,
                "has_mz": has_mz,
                "score": score,
                "disasm_preview": disasm[:200] if disasm else None,
            })

        except Exception:
            continue

    # Phase 5: emit one finding per PID group, not per VAD region.
    suppressed_count = 0
    for group_pid, members in _injection_groups.items():
        count = len(members)
        representative = members[0]
        proc_name = representative["process_name"]
        max_score = max(m["score"] for m in members)
        group_mz_count = sum(1 for m in members if m["has_mz"])
        has_any_mz = group_mz_count > 0
        mitre_technique = "T1055.001" if has_any_mz else "T1055"
        vad_regions = [f"{m['vad_start']}-{m['vad_end']}" for m in members]
        protections = compact_unique(m["protection"] for m in members)

        # Determine promotion reason
        if has_any_mz:
            promotion_reason = "mz_header_present"
        elif count > 1:
            promotion_reason = "multi_region_injection"
        else:
            promotion_reason = "single_suspicious_region"

        group_key = f"malfind:{group_pid}:{proc_name}"

        finding = Finding(
            case_id=_case_id(),
            finding_type="process_injection",
            artifact_type="memory",
            artifact_path=dump_path,
            artifact_offset=representative["vad_start"],
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=max_score,
            description=(
                f"{count} suspicious VAD region(s) in {proc_name} (PID {group_pid}). "
                + (f"{group_mz_count} region(s) contain MZ headers — likely reflective DLL injection. "
                   if has_any_mz else
                   "Anonymous executable regions — possible shellcode injection. ")
                + f"Protections: {', '.join(protections)}. "
                f"Max suspicion score: {max_score:.2f}."
            ),
            supporting_indicators=(
                [f"pid={group_pid}", f"process={proc_name}"]
                + [f"vad={v}" for v in vad_regions[:5]]
                + [f"protection={p}" for p in protections[:3]]
                + [f"mz_regions={group_mz_count}", f"total_regions={count}"]
            ),
            mitre_tactic="TA0005",
            mitre_technique=mitre_technique,
            group_key=group_key,
            support_count=count,
            promotion_reason=promotion_reason,
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)
        suppressed_count += count - 1  # all but the representative

    grouping_context = {
        "strategy": "pid_process",
        "groups_formed": len(_injection_groups),
        "total_candidates": sum(len(m) for m in _injection_groups.values()),
        "suppressed_duplicates": suppressed_count,
    }

    response = {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "injection_count": len(records),
        "mz_header_count": mz_header_count,
        "requires_agent": "@memory-analyst",
        "agent_instruction": (
            f"Review malfind output for confirmed code injection, hidden processes, and C2 pivots in {dump_path}."
        ),
        "suppression_summary": {
            "total_raw_signals": sum(len(m) for m in _injection_groups.values()),
            "findings_emitted": len(finding_ids),
            "signals_suppressed": suppressed_count,
            "reason": "Grouped by PID/process to reduce per-region noise.",
        },
        "grouping_context": grouping_context,
    }
    if response["data"]:
        response["data"] = [
            sanitize_payload_fields(record, "disassembly_preview")
            for record in response["data"]
        ]
    return _detect_injection_contract_payload(
        response=response,
        records=records,
        dump_path=dump_path,
    )


# ---------------------------------------------------------------------------
# Tool: list_dlls
# ---------------------------------------------------------------------------


def list_dlls(dump_path: str, pid: int) -> dict[str, Any]:
    """List DLLs loaded into a specific process using Volatility 3 windows.dlllist.

    Wraps ``python3 /opt/volatility3-2.20.0/vol.py -r json windows.dlllist --pid <pid>``
    on SIFT Workstation.

    Lists every DLL in a process's PEB loader data structures.  Used to:
    - Confirm a suspicious DLL found by :func:`detect_injection`.
    - Identify DLL hijacking (legitimate DLL name loaded from a suspicious path).
    - Enumerate the attack surface of a specific process.

    DLLs absent from the PEB loader list but present in the VAD (found by
    :func:`detect_injection` with ``has_mz_header=True``) indicate reflective
    loading, a key indicator of advanced injection.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.
    pid:
        PID of the target process.  Use :func:`list_processes` or
        :func:`scan_processes` to enumerate valid PIDs first.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of DllRecord dicts),
        ``findings_created``, ``execution_id``, ``raw_command``, ``dll_count``.
    """
    tool = "memory.list_dlls"
    if _runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    if not isinstance(pid, int) or pid < 0:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": f"Invalid pid {pid!r}: must be a non-negative integer.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    try:
        result = _runner.dlllist(dump_path=dump_path, pid=pid, tool_name=tool)
    except Exception as exc:
        return _runner_error(tool, exc)

    if not result.ok:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": (
                f"windows.dlllist exited with code {result.exit_code}. "
                f"stderr: {result.stderr[:300]}"
            ),
            "data": [],
            "findings_created": [],
            "execution_id": result.execution_id,
            "raw_command": result.command_line,
            "stderr": result.stderr,
            "volatility_error": _runner.classify_error(result),
        }

    rows = _parse_json_output(result.stdout)
    if hasattr(result, "release_stdout"): result.release_stdout()  # OOM mitigation — free the multi-MB stdout now that we have parsed rows
    records: list[DllRecord] = []
    finding_ids: list[str] = []

    for row in rows:
        try:
            row_pid = int(row.get("PID") or row.get(
                "Pid") or row.get("pid") or pid)
            proc_name = str(
                row.get("Process") or row.get(
                    "ImageFileName") or row.get("Name") or "unknown"
            )
            dll_path_raw = str(
                row.get("FullDllName") or row.get(
                    "Path") or row.get("FullPath") or ""
            ).strip()
            dll_name_raw = str(
                row.get("BaseDllName") or row.get(
                    "DllName") or row.get("Name") or ""
            ).strip()
            if not dll_name_raw and dll_path_raw:
                dll_name_raw = Path(dll_path_raw).name

            base_raw = (
                row.get("Base") or row.get(
                    "LoadedDllBase") or row.get("BaseAddress") or "0x0"
            )
            base_addr = str(base_raw)
            if not base_addr.startswith("0x"):
                try:
                    base_addr = hex(int(base_addr))
                except (ValueError, TypeError):
                    base_addr = "0x0"

            size_raw = row.get("Size") or row.get("SizeOfImage") or 0
            try:
                size = int(size_raw)
            except (ValueError, TypeError):
                size = 0

            load_time = _parse_vol_dt(
                row.get("LoadTime") or row.get("load_time") or None
            )

            record = DllRecord(
                pid=row_pid,
                process_name=proc_name,
                dll_path=dll_path_raw or dll_name_raw,
                dll_name=dll_name_raw or Path(dll_path_raw).name,
                base_address=base_addr,
                size=size,
                load_time=load_time,
            )
            records.append(record)

        except Exception:
            continue

    # Create a summary finding
    if records:
        # Flag DLLs loaded from suspicious paths (not System32, SysWOW64, or
        # standard program paths)
        suspicious_dlls = [
            r for r in records
            if r.dll_path and not any(
                fragment in r.dll_path.lower()
                for fragment in (
                    "\\windows\\system32\\",
                    "\\windows\\syswow64\\",
                    "\\program files\\",
                    "\\program files (x86)\\",
                    "\\windows\\winsxs\\",
                )
            )
        ]

        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="memory",
            artifact_path=dump_path,
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=(
                f"PID {pid}: {len(records)} DLLs loaded. "
                + (
                    f"{len(suspicious_dlls)} DLLs loaded from non-standard paths "
                    "(potential DLL hijacking or sideloading). "
                    f"Suspicious DLL paths: {[r.dll_path for r in suspicious_dlls[:5]]}."
                    if suspicious_dlls else
                    "All DLLs loaded from standard Windows paths."
                )
            ),
            supporting_indicators=[
                f"pid={pid}",
                f"dll_count={len(records)}",
                f"suspicious_dll_count={len(suspicious_dlls)}",
            ] + [r.dll_path for r in suspicious_dlls[:10]],
            # E.2: structured PID field so the report gate can verify
            # per-PID coverage of network_followup_pids rather than
            # treating any list_dlls execution as full coverage.
            dlllist_covered_pid=int(pid),
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)
    else:
        # I.1 fix: Zero-row result — still mark PID as covered to satisfy report gate
        # Without this, successful list_dlls with 0 DLLs (exited process, empty load list)
        # permanently blocks report finalization even though the required follow-up executed.
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="memory",
            artifact_path=dump_path,
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=f"PID {pid}: No DLLs loaded (process exited or empty load list)",
            supporting_indicators=[f"pid={pid}", "dll_count=0"],
            dlllist_covered_pid=int(pid),
        )
        fid = _state.add_finding(finding.model_dump(mode="json"))
        finding_ids.append(fid)

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "dll_count": len(records),
    }
