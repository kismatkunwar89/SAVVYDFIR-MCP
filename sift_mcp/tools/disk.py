"""
sift_mcp.tools.disk
~~~~~~~~~~~~~~~~~~~~

Disk forensics MCP tools for SAVVYDFIR-MCP.

All six tools wrap EZ Tools (via :class:`~sift_mcp.runners.eztools.EZToolsRunner`)
or The Sleuth Kit (via :class:`~sift_mcp.runners.sleuthkit.SleuthKitRunner`),
parse the CLI output into typed Pydantic models, and return plain dicts.

Tools
-----
- ``extract_prefetch``         — PECmd: Windows Prefetch execution evidence.
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
import os
import re
import tempfile
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
        _ez_runner = EZToolsRunner(audit_logger=audit_logger)
    if sk_runner is not None:
        _sk_runner = sk_runner
    else:
        from sift_mcp.runners.sleuthkit import SleuthKitRunner
        _sk_runner = SleuthKitRunner(audit_logger=audit_logger)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _case_id() -> str:
    """Return the current case ID from state, or 'unknown'."""
    if _state is None:
        return "unknown"
    try:
        return _state._state.get("case_id", "unknown")
    except Exception:
        return "unknown"


def _current_iteration() -> int:
    """Return the current audit iteration number."""
    if _audit is None:
        return 1
    return _audit.current_iteration


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
    with p.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        return [dict(row) for row in reader]


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
) -> dict[str, Any]:
    """Extract Windows Prefetch execution evidence using PECmd (EZ Tools).

    Wraps ``dotnet /opt/zimmermantools/PECmd.dll`` on SIFT Workstation.

    Prefetch files (``.pf``) are stored in ``C:\\Windows\\Prefetch`` and
    record up to 8 execution timestamps plus the list of files referenced
    during the binary's first seconds.  The ``$SI Created`` time of the ``.pf``
    file equals the **first** execution time — this is forensically significant.

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

    # Derive default prefetch directory from image path
    if prefetch_dir is None:
        base = Path(image_path)
        # Detect if image_path IS the mounted filesystem (e.g. /mnt/disk)
        if (base / "Windows" / "Prefetch").exists():
            prefetch_dir = str(base / "Windows" / "Prefetch")
        elif (base / "Windows").exists():
            prefetch_dir = str(base / "Windows" / "Prefetch")
        else:
            # Legacy convention: <case_dir>/evidence/mnt/C/Windows/Prefetch
            prefetch_dir = str(base / "mnt" / "C" / "Windows" / "Prefetch")

    with tempfile.TemporaryDirectory(prefix="savvydfir_pecmd_") as tmp_dir:
        csv_filename = "prefetch.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_pecmd(
                prefetch_dir_or_file=prefetch_dir,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
            )
        except Exception as exc:
            return _runner_error(tool, exc)

        if not result.ok and not Path(csv_path).exists():
            return {
                "tool_name": tool,
                "status": "error",
                "error_message": (
                    f"PECmd exited with code {result.exit_code}. "
                    f"stderr: {result.stderr[:300]}"
                ),
                "data": [],
                "findings_created": [],
                "execution_id": result.execution_id,
                "raw_command": result.command_line,
                "stderr": result.stderr,
            }

        rows = _read_csv(csv_path)

    records: list[PrefetchRecord] = []
    finding_ids: list[str] = []

    for row in rows:
        try:
            # PECmd CSV columns (may vary slightly by version)
            exec_name = (
                row.get("ExecutableName") or row.get("SourceFileName") or ""
            ).strip()
            pf_path = (
                row.get("SourceFilePath") or row.get("SourceFile") or ""
            ).strip()
            run_count_raw = row.get("RunCount") or row.get("PrefetchCount") or "1"
            try:
                run_count = int(run_count_raw)
            except (ValueError, TypeError):
                run_count = 1

            # Parse up to 8 run times (columns LastRun, PreviousRun1..PreviousRun7)
            last_run_times: list[datetime] = []
            for col in [
                "LastRun",
                "PreviousRun1", "PreviousRun2", "PreviousRun3",
                "PreviousRun4", "PreviousRun5", "PreviousRun6", "PreviousRun7",
            ]:
                dt = _parse_dt(row.get(col, ""))
                if dt is not None:
                    last_run_times.append(dt)

            # Referenced files: comma-separated in the Directories/Files column
            referenced_raw = (
                row.get("FilesLoaded") or row.get("Directories") or ""
            )
            referenced_files = [
                f.strip() for f in referenced_raw.split("|") if f.strip()
            ] if referenced_raw else []

            record = PrefetchRecord(
                executable_name=exec_name or Path(pf_path).stem,
                prefetch_path=pf_path,
                run_count=max(run_count, 1),
                last_run_times=last_run_times[:8],
                referenced_files=referenced_files,
                volume_path=row.get("Volume0Name") or row.get("VolumePath"),
                volume_serial=row.get("Volume0Serial") or row.get("VolumeSerial"),
                source_created=_parse_dt(row.get("SourceCreated") or row.get("Created") or ""),
                source_modified=_parse_dt(row.get("SourceModified") or row.get("Modified") or ""),
            )
            records.append(record)

            # Create a finding for each prefetch record
            finding = Finding(
                case_id=_case_id(),
                finding_type="other",
                artifact_type="disk",
                artifact_path=pf_path or prefetch_dir,
                tool_name=tool,
                execution_id=result.execution_id,
                iteration=_current_iteration(),
                evidence_kind=EvidenceKind.OBSERVATION,
                finding_status=FindingStatus.ACTIVE,
                confidence=0.95,
                description=(
                    f"Prefetch evidence: {exec_name} executed {run_count} time(s). "
                    f"Last run: {last_run_times[0].isoformat() if last_run_times else 'unknown'}. "
                    f"PF file: {pf_path}."
                ),
                supporting_indicators=[pf_path, exec_name] + [
                    t.isoformat() for t in last_run_times[:3]
                ],
            )
            fid = _state.add_finding(finding.model_dump(mode="json"))
            finding_ids.append(fid)

        except Exception:
            # Skip malformed rows without aborting the entire parse
            continue

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
    }


# ---------------------------------------------------------------------------
# Tool: get_amcache
# ---------------------------------------------------------------------------


def get_amcache(
    image_path: str,
    hive_path: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
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

    if hive_path is None:
        base = Path(image_path)
        _amcache = base / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
        if _amcache.exists():
            hive_path = str(_amcache)
        else:
            hive_path = str(base / "mnt" / "C" / "Windows" / "appcompat" / "Programs" / "Amcache.hve")

    with tempfile.TemporaryDirectory(prefix="savvydfir_amcache_") as tmp_dir:
        csv_filename = "amcache.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_amcacheparser(
                hive_path=hive_path,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
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

    records: list[AmcacheRecord] = []
    finding_ids: list[str] = []

    for row in rows:
        try:
            file_path_val = (
                row.get("FullPath") or row.get("FilePath") or row.get("Path") or ""
            ).strip()
            if not file_path_val:
                continue

            sha1 = (row.get("SHA1") or row.get("Sha1") or row.get("Hash") or "").strip()
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
                publisher=row.get("Publisher") or row.get("CompanyName") or None,
                product_name=row.get("ProductName") or row.get("Product") or None,
                compile_time=_parse_dt(row.get("CompileTime") or row.get("PEHeaderCompileTime") or ""),
                install_time=_parse_dt(row.get("InstallDate") or row.get("CreatedOn") or ""),
                last_modified=_parse_dt(row.get("LastModifiedDate") or row.get("KeyLastWriteTimestamp") or ""),
            )
            records.append(record)

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
                    f"Amcache record: {file_path_val} executed. "
                    f"SHA-1: {sha1 or 'N/A'}. "
                    f"Publisher: {record.publisher or 'unknown'}."
                ),
                supporting_indicators=[
                    file_path_val,
                    f"sha1={sha1}" if sha1 else "",
                ],
            )
            fid = _state.add_finding(finding.model_dump(mode="json"))
            finding_ids.append(fid)

        except Exception:
            continue

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
    }


# ---------------------------------------------------------------------------
# Tool: extract_mft_timeline
# ---------------------------------------------------------------------------


def extract_mft_timeline(
    image_path: str,
    mft_path: Optional[str] = None,
    case_id: Optional[str] = None,
    max_entries: int = 0,
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

    if mft_path is None:
        base = Path(image_path)
        _mft = base / "$MFT"
        if _mft.exists():
            mft_path = str(_mft)
        else:
            mft_path = str(base / "mnt" / "C" / "$MFT")

    with tempfile.TemporaryDirectory(prefix="savvydfir_mftecmd_") as tmp_dir:
        csv_filename = "mft_timeline.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_mftecmd(
                mft_path=mft_path,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
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

    records: list[MftEntry] = []
    finding_ids: list[str] = []
    timestomping_candidates = 0

    for row in rows:
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
            si_entry_mod = _parse_dt(row.get("MFTRecordChange0x10") or row.get("SIEntryModified") or "")

            fn_created = _parse_dt(row.get("Created0x30") or row.get("FNCreated") or "")
            fn_modified = _parse_dt(row.get("LastModified0x30") or row.get("FNModified") or "")
            fn_accessed = _parse_dt(row.get("LastAccess0x30") or row.get("FNAccessed") or "")
            fn_entry_mod = _parse_dt(row.get("MFTRecordChange0x30") or row.get("FNEntryModified") or "")

            is_deleted = (row.get("InUse") or row.get("IsDeleted") or "").strip().lower() in (
                "false", "0", "no", "deleted"
            )
            is_dir = (row.get("IsDirectory") or row.get("IsDir") or "").strip().lower() in (
                "true", "1", "yes"
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

            # Detect timestomping: SI Created < FN Created
            if (
                si_created is not None
                and fn_created is not None
                and si_created < fn_created
            ):
                timestomping_candidates += 1
                ts_finding = Finding(
                    case_id=_case_id(),
                    finding_type="timestomping",
                    artifact_type="disk",
                    artifact_path=mft_path,
                    artifact_offset=str(entry_num),
                    tool_name=tool,
                    execution_id=result.execution_id,
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
                fid = _state.add_finding(ts_finding.model_dump(mode="json"))
                finding_ids.append(fid)

        except Exception:
            continue

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
        "timestomping_candidates": timestomping_candidates,
    }


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
    device_path: str,
    offset: Optional[int] = None,
) -> dict[str, Any]:
    """List deleted files in a disk image using The Sleuth Kit ``fls``.

    Wraps ``fls -rd`` (recursive, deleted-only) on SIFT Workstation.

    Deleted files retain their directory entry until the inode is reallocated,
    making them recoverable with ``icat``.  This tool returns the full list
    of deleted entries so the analyst can identify forensically interesting
    artifacts for extraction.

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
        ``tool_name``, ``status``, ``data`` (list of DeletedFile dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``.
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

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
    }


# ---------------------------------------------------------------------------
# Tool: summarize_evtx
# ---------------------------------------------------------------------------


def summarize_evtx(
    image_path: str,
    evtx_dir: Optional[str] = None,
    channel: Optional[str] = None,
) -> dict[str, Any]:
    """Parse Windows EVTX event logs using EvtxECmd (EZ Tools).

    Wraps ``dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`` on SIFT Workstation.

    Processes all ``.evtx`` files in the event log directory and emits a
    unified CSV timeline.  Security-relevant event IDs include 4624/4625
    (logon), 4688/4103 (process creation), 7045 (service install), and
    4698 (scheduled task creation).

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

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of EventRecord dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``, ``channel_filter``.
    """
    tool = "disk.summarize_evtx"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    if evtx_dir is None:
        base = Path(image_path)
        _evtx = base / "Windows" / "System32" / "winevt" / "Logs"
        if _evtx.exists():
            evtx_dir = str(_evtx)
        else:
            evtx_dir = str(base / "mnt" / "C" / "Windows" / "System32" / "winevt" / "Logs")

    with tempfile.TemporaryDirectory(prefix="savvydfir_evtx_") as tmp_dir:
        csv_filename = "evtx_timeline.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_evtxecmd(
                evtx_dir=evtx_dir,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
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

    records: list[EventRecord] = []
    finding_ids: list[str] = []

    for row in rows:
        try:
            ch = (row.get("Channel") or row.get("EventChannel") or "").strip()

            # Apply channel filter
            if channel and ch.lower() != channel.lower():
                continue

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

            # Build extra_fields from all remaining columns
            skip_cols = {
                "EventId", "EventID", "Id", "Channel", "EventChannel",
                "TimeCreated", "Timestamp", "Date/Time - UTC",
                "PayloadData1", "MapDescription", "UserData", "Message",
                "Computer", "UserSID", "UserId", "Level", "Provider",
                "ProviderName", "SourceName",
            }
            extra: dict[str, Any] = {
                k: v for k, v in row.items()
                if k not in skip_cols and v and v.strip()
            }

            record = EventRecord(
                event_id=event_id,
                channel=ch or "Unknown",
                provider=(
                    row.get("Provider") or row.get("ProviderName") or row.get("SourceName") or None
                ),
                timestamp=ts,
                level=row.get("Level") or row.get("LevelDisplayName") or None,
                computer=row.get("Computer") or None,
                user_sid=(
                    row.get("UserSID") or row.get("UserId") or None
                ),
                message_summary=message or f"Event {event_id}",
                raw_xml_ref=None,
                extra_fields=extra,
            )
            records.append(record)

        except Exception:
            continue

    # Create a summary finding if we have records
    if records:
        finding = Finding(
            case_id=_case_id(),
            finding_type="other",
            artifact_type="disk",
            artifact_path=evtx_dir,
            tool_name=tool,
            execution_id=result.execution_id,
            iteration=_current_iteration(),
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=(
                f"Parsed {len(records)} event log entries from {evtx_dir}"
                + (f" (channel filter: {channel})" if channel else "") + ". "
                "Events may reveal logon activity, process creation, service "
                "installation, and other attacker behaviours."
            ),
            supporting_indicators=[evtx_dir],
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
        "records_count": len(records),
        "channel_filter": channel,
    }


# ---------------------------------------------------------------------------
# Tool: extract_registry_run_keys
# ---------------------------------------------------------------------------

# Persistence key path fragments to match (lower-case)
_PERSISTENCE_FRAGMENTS: list[tuple[str, str]] = [
    ("\\software\\microsoft\\windows\\currentversion\\run\\", "run"),
    ("\\software\\microsoft\\windows\\currentversion\\runonce\\", "runonce"),
    ("\\software\\microsoft\\windows\\currentversion\\runservices\\", "run"),
    ("\\software\\wow6432node\\microsoft\\windows\\currentversion\\run\\", "run"),
    ("appinit_dlls", "appinit_dlls"),
    ("\\winlogon", "winlogon_shell"),
    ("userinit", "winlogon_userinit"),
    ("\\system\\currentcontrolset\\services\\", "services"),
    ("lsaprotection", "lsa_package"),
    ("security packages", "lsa_package"),
    ("authentication packages", "lsa_package"),
    ("session manager", "session_manager"),
    ("bootexecute", "session_manager"),
    ("browser helper objects", "browser_helper"),
    ("credential providers", "credential_provider"),
    ("shelliconoverlayidentifiers", "shell_extension"),
    ("shellserviceobjectdelayload", "shell_extension"),
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
) -> dict[str, Any]:
    """Extract Windows registry persistence keys using RECmd (EZ Tools).

    Wraps ``dotnet /opt/zimmermantools/RECmd/RECmd.dll`` on SIFT Workstation.

    Parses all registry hive files in the hive directory and filters for
    persistence-related keys: Run, RunOnce, AppInit_DLLs, WinLogon shell/
    userinit, services, LSA packages, and related autostart locations.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image.  Used to derive the default
        hive directory if *hive_dir* is not given.
    hive_dir:
        Absolute path to the directory containing registry hive files
        (e.g. ``/cases/SRL-2018/evidence/mnt/C/Windows/System32/config``).
        When ``None``, a default path is constructed from the image path.

    Returns
    -------
    dict
        ``tool_name``, ``status``, ``data`` (list of RegistryRunKey dicts),
        ``findings_created``, ``execution_id``, ``raw_command``,
        ``records_count``, ``persistence_type_counts``.
    """
    tool = "disk.extract_registry_run_keys"
    if _ez_runner is None or _state is None or _audit is None:
        return _not_initialised(tool)

    if hive_dir is None:
        base = Path(image_path)
        _config = base / "Windows" / "System32" / "config"
        if _config.exists():
            hive_dir = str(_config)
        else:
            hive_dir = str(base / "mnt" / "C" / "Windows" / "System32" / "config")

    with tempfile.TemporaryDirectory(prefix="savvydfir_recmd_") as tmp_dir:
        csv_filename = "registry.csv"
        csv_path = os.path.join(tmp_dir, csv_filename)

        try:
            result = _ez_runner.run_recmd(
                hive_dir=hive_dir,
                csv_dir=tmp_dir,
                csv_filename=csv_filename,
            )
        except Exception as exc:
            return _runner_error(tool, exc)

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

    records: list[RegistryRunKey] = []
    finding_ids: list[str] = []
    persistence_type_counts: dict[str, int] = {}

    for row in rows:
        try:
            key_path = (
                row.get("HivePath") or row.get("KeyPath") or row.get("Path") or ""
            ).strip()
            if not key_path:
                continue

            # Filter for persistence-related keys only
            ptype = _classify_persistence(key_path)
            if ptype is None:
                continue

            value_name = (
                row.get("ValueName") or row.get("Name") or ""
            ).strip()
            value_data = (
                row.get("ValueData") or row.get("Data") or row.get("Value") or ""
            ).strip()

            if not value_data:
                continue

            hive_name = (
                row.get("HiveType") or row.get("Hive") or Path(key_path).name
            ).strip()

            record = RegistryRunKey(
                hive=hive_name,
                key_path=key_path,
                value_name=value_name or "(Default)",
                value_data=value_data,
                last_write_time=_parse_dt(
                    row.get("LastWriteTimestamp") or row.get("LastWriteTime") or ""
                ),
                persistence_type=ptype,  # type: ignore[arg-type]
            )
            records.append(record)
            persistence_type_counts[ptype] = persistence_type_counts.get(ptype, 0) + 1

            # Create individual finding for each persistence entry
            finding = Finding(
                case_id=_case_id(),
                finding_type="persistence",
                artifact_type="disk",
                artifact_path=key_path,
                tool_name=tool,
                execution_id=result.execution_id,
                iteration=_current_iteration(),
                evidence_kind=EvidenceKind.OBSERVATION,
                finding_status=FindingStatus.ACTIVE,
                confidence=0.85,
                description=(
                    f"Registry persistence entry found: {key_path}\\{value_name} = {value_data[:200]}. "
                    f"Persistence type: {ptype}. "
                    f"This entry executes '{value_data[:100]}' on the configured trigger."
                ),
                supporting_indicators=[
                    key_path,
                    f"value_name={value_name}",
                    f"value_data={value_data[:200]}",
                ],
                mitre_tactic="TA0003",
                mitre_technique=(
                    "T1547.001" if ptype in ("run", "runonce") else
                    "T1546.010" if ptype == "appinit_dlls" else
                    "T1547.004" if ptype in ("winlogon_shell", "winlogon_userinit") else
                    "T1543.003" if ptype == "services" else
                    "T1547.005" if ptype == "lsa_package" else
                    "T1547.012" if ptype == "credential_provider" else
                    "T1547"
                ),
            )
            fid = _state.add_finding(finding.model_dump(mode="json"))
            finding_ids.append(fid)

        except Exception:
            continue

    return {
        "tool_name": tool,
        "status": "success",
        "data": [r.model_dump(mode="json") for r in records],
        "findings_created": finding_ids,
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "records_count": len(records),
        "persistence_type_counts": persistence_type_counts,
    }
