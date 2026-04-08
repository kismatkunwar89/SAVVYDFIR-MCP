"""SAVVYDFIR-MCP Server — Purpose-built forensic MCP backend for Protocol SIFT.

This server exposes 24 typed, read-only forensic tools through the Model Context
Protocol (MCP) using stdio transport. It is designed to be used with Claude Code
as the primary agentic execution engine on SANS SIFT Workstation.

Architecture
------------
* **SafeRunner** — all subprocess calls go through a read-only enforcement layer
  that validates paths, deny-lists destructive commands, and logs every execution
  to ``audit.jsonl`` before and after the subprocess runs.
* **AuditLogger** — append-only JSONL audit trail; every tool invocation produces
  a ``started`` entry before execution and a ``completed`` entry after.
* **CaseStateManager** — single-source-of-truth JSON state file (``state.json``);
  holds all findings with F-NNN IDs, executions with E-NNN IDs, and open questions.
* **FastMCP** — synchronous MCP server over stdio; all tool functions are sync
  because ``SafeRunner`` uses ``subprocess.run()``.

Tool namespaces (24 tools)
--------------------------
Evidence (2):   verify_integrity, get_provenance
Disk (6):       extract_prefetch, get_amcache, extract_mft_timeline,
                list_deleted_files, summarize_evtx, extract_registry_run_keys
Memory (6):     detect_profile, list_processes, scan_processes,
                scan_network, detect_injection, list_dlls
Timeline (2):   build_timeline, query_timeline
YARA (2):       scan_files, scan_memory
Correlation (2): compare_disk_and_memory, flag_discrepancy
State (2):      read_state, export_trace
Graph (2):      generate_graph, serve_graph

Novel contributions
-------------------
1. Cross-artifact contradiction detection via ``compare_disk_and_memory()``
   (6 specific forensic checks — absent from all existing Protocol SIFT
   extensions and published DFIR-LLM systems).
2. Evidence-triggered self-correction: CORRECTION_EVENTs fire when physical
   evidence contradicts itself, not when the LLM contradicts itself.
3. Architectural read-only enforcement at the transport layer via SafeRunner
   (path validation, deny-listed commands, fail-closed audit).
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

from sift_mcp.models.sigma import (
    AnalysisResult,
    ArtifactHit,
    SigmaScanResult,
    ToolResult,
)

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="savvydfir-mcp",
    instructions=(
        "Autonomous DFIR triage agent with cross-artifact correlation and "
        "self-correction. Exposes 24 typed forensic tools over stdio MCP transport "
        "for use with Claude Code on SANS SIFT Workstation."
    ),
)

# ---------------------------------------------------------------------------
# Shared infrastructure (created at import time)
# ---------------------------------------------------------------------------

# Ensure the default analysis directory exists so audit + state files can be written.
_ANALYSIS_DIR = Path("./analysis").resolve()
_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager

_audit_logger = AuditLogger(output_path=str(_ANALYSIS_DIR / "audit.jsonl"))
_state_manager = CaseStateManager(state_path=str(_ANALYSIS_DIR / "state.json"))

# ---------------------------------------------------------------------------
# RBAC path model — case-agnostic read/write enforcement
# ---------------------------------------------------------------------------

#: Paths that are strictly READ-ONLY (evidence and mount points).
EVIDENCE_PATHS: list[str] = ["/evidence/", "/mnt/"]
#: Paths where the agent may write output.
OUTPUT_PATHS: list[str] = ["/cases/", "/tmp/"]
#: Commands that are unconditionally blocked.
BLOCKED_CMDS: list[str] = [
    "rm", "dd", "mkfs", "shred", "wget", "curl", "ssh", "scp",
    "fdisk", "parted", "nc", "netcat", "format", "chmod", "chown",
]


def validate_path(path: str, *, write: bool = False) -> bool:
    """Validate a path against the RBAC model.

    Parameters
    ----------
    path:
        Filesystem path to validate.
    write:
        If True, checks that the path is in OUTPUT_PATHS (writable).
        If False, allows both EVIDENCE_PATHS (read) and OUTPUT_PATHS.

    Returns
    -------
    bool
        True if the path is permitted under the RBAC model.
    """
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        return False

    if write:
        return any(resolved.startswith(p) for p in OUTPUT_PATHS)

    # Read access: allow evidence, mount, and output paths
    allowed = EVIDENCE_PATHS + OUTPUT_PATHS
    return any(resolved.startswith(p) for p in allowed)


# ---------------------------------------------------------------------------
# Tool module init
# ---------------------------------------------------------------------------

from sift_mcp.tools import init_all_tools  # noqa: E402

init_all_tools(
    audit_logger=_audit_logger,
    state_manager=_state_manager,
)

# ---------------------------------------------------------------------------
# Import all tool functions
# ---------------------------------------------------------------------------

from sift_mcp.tools.evidence import verify_integrity as _verify_integrity
from sift_mcp.tools.evidence import get_provenance as _get_provenance

from sift_mcp.tools.disk import extract_prefetch as _extract_prefetch
from sift_mcp.tools.disk import get_amcache as _get_amcache
from sift_mcp.tools.disk import extract_mft_timeline as _extract_mft_timeline
from sift_mcp.tools.disk import list_deleted_files as _list_deleted_files
from sift_mcp.tools.disk import summarize_evtx as _summarize_evtx
from sift_mcp.tools.disk import extract_registry_run_keys as _extract_registry_run_keys

from sift_mcp.tools.timeline import build_timeline as _build_timeline
from sift_mcp.tools.timeline import query_timeline as _query_timeline

from sift_mcp.tools.yara import scan_files as _scan_files
from sift_mcp.tools.yara import scan_memory as _scan_memory

from sift_mcp.tools.correlation import compare_disk_and_memory as _compare_disk_and_memory
from sift_mcp.tools.correlation import flag_discrepancy as _flag_discrepancy

from sift_mcp.tools.state_tools import read_state as _read_state
from sift_mcp.tools.state_tools import export_trace as _export_trace

# Memory tools — optional (module may not be built yet)
try:
    from sift_mcp.tools.memory import detect_profile as _detect_profile  # type: ignore[import]
    from sift_mcp.tools.memory import list_processes as _list_processes  # type: ignore[import]
    from sift_mcp.tools.memory import scan_processes as _scan_processes  # type: ignore[import]
    from sift_mcp.tools.memory import scan_network as _scan_network  # type: ignore[import]
    from sift_mcp.tools.memory import detect_injection as _detect_injection  # type: ignore[import]
    from sift_mcp.tools.memory import list_dlls as _list_dlls  # type: ignore[import]
    _MEMORY_AVAILABLE = True
except ImportError:
    _MEMORY_AVAILABLE = False


def _memory_unavailable(tool_name: str) -> dict[str, Any]:
    return {
        "status": "error",
        "error": (
            f"Memory tool '{tool_name}' is not available — "
            "sift_mcp/tools/memory.py has not been created yet. "
            "Run memory analysis manually using Volatility 3 or wait for "
            "the memory tool module to be added."
        ),
    }


# ===========================================================================
# EVIDENCE NAMESPACE (2 tools)
# ===========================================================================


@mcp.tool()
def verify_integrity(image_path: str) -> dict[str, Any]:
    """Verify the cryptographic integrity of a disk image or memory dump.

    Runs ``ewfverify`` (for E01 images) or ``sha256sum`` (for raw/dd images)
    to compute and compare the image hash against any stored reference hash.

    This is the FIRST tool that should be called when evidence is registered —
    the computed hash is recorded in the audit log and must match the
    case-opening hash when the case is closed (zero-spoliation guarantee).

    Parameters
    ----------
    image_path:
        Absolute path to the evidence file (E01, raw, dd, AFF, or memory dump).

    Returns
    -------
    dict
        IntegrityResult fields: image_path, stored_hash, computed_hash,
        algorithm, verified (bool), verification_time.
    """
    try:
        return _verify_integrity(image_path=image_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "verify_integrity"}


@mcp.tool()
def get_provenance(finding_id: str) -> dict[str, Any]:
    """Trace a forensic finding back to the exact tool execution that produced it.

    Looks up the E-NNN execution ID on *finding_id* and returns the full
    provenance chain: the finding record, the matched audit entries (started +
    completed), the exact command line that was run, and any CORRECTION_EVENTs
    that modified this finding.

    Parameters
    ----------
    finding_id:
        The F-NNN finding identifier (e.g. ``"F-003"``).

    Returns
    -------
    dict
        ProvenanceRecord fields: finding_id, finding, execution entries,
        command_line, correction_events.
    """
    try:
        return _get_provenance(finding_id=finding_id)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "get_provenance"}


# ===========================================================================
# DISK NAMESPACE (6 tools)
# ===========================================================================


@mcp.tool()
def extract_prefetch(
    image_path: str,
    case_id: str = "default",
    max_entries: int = 200,
) -> dict[str, Any]:
    """Extract Windows Prefetch execution artefacts from a disk image.

    Runs ``dotnet PECmd.dll`` (EZ Tools) against the Prefetch directory on
    *image_path* and returns a list of PrefetchRecord dicts.  Prefetch files
    prove binary execution and record the last 8 run times (v26+) plus the
    list of files opened at launch.

    The ``source_created`` timestamp of the .PF file equals the FIRST
    execution time of the binary — forensically significant for establishing
    initial compromise time.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence disk image or mounted directory.
    case_id:
        Case identifier — used to derive the output CSV path.
    max_entries:
        Maximum number of PrefetchRecord entries to return.

    Returns
    -------
    dict
        status, records (list of PrefetchRecord dicts), count, execution_id.
    """
    try:
        return _extract_prefetch(image_path=image_path, case_id=case_id, max_entries=max_entries)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "extract_prefetch"}


@mcp.tool()
def get_amcache(
    image_path: str,
    case_id: str = "default",
    max_entries: int = 500,
) -> dict[str, Any]:
    """Extract Amcache.hve execution evidence from a disk image.

    Runs ``dotnet AmcacheParser.dll`` (EZ Tools) to parse Amcache.hve.
    Returns a list of AmcacheRecord dicts with SHA-1 hashes of executed
    binaries — hashes survive even after the binary is deleted.

    Use the SHA-1 hash to pivot into threat intelligence even for deleted
    binaries.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence disk image or mounted directory.
    case_id:
        Case identifier for output file naming.
    max_entries:
        Maximum number of AmcacheRecord entries to return.

    Returns
    -------
    dict
        status, records (list of AmcacheRecord dicts), count, execution_id.
    """
    try:
        return _get_amcache(image_path=image_path, case_id=case_id, max_entries=max_entries)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "get_amcache"}


@mcp.tool()
def extract_mft_timeline(
    image_path: str,
    case_id: str = "default",
    max_entries: int = 1000,
) -> dict[str, Any]:
    """Parse the NTFS $MFT to build a file system timeline.

    Runs ``dotnet MFTECmd.dll`` (EZ Tools) to parse the Master File Table.
    Returns a list of MftEntry dicts with both ``$STANDARD_INFORMATION``
    (SI) and ``$FILE_NAME`` (FN) timestamps for each file.

    SI timestamps can be modified by user-level APIs (timestomping), but FN
    timestamps require kernel access.  Compare SI vs FN to detect timestamp
    manipulation.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence disk image or mounted directory.
    case_id:
        Case identifier for output file naming.
    max_entries:
        Maximum number of MftEntry records to return.

    Returns
    -------
    dict
        status, records (list of MftEntry dicts), count, execution_id.
    """
    try:
        return _extract_mft_timeline(image_path=image_path, case_id=case_id, max_entries=max_entries)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "extract_mft_timeline"}


@mcp.tool()
def list_deleted_files(
    image_path: str,
    case_id: str = "default",
    max_entries: int = 500,
) -> dict[str, Any]:
    """List deleted files from the filesystem using Sleuth Kit.

    Runs ``fls -rd`` to enumerate deleted directory entries and recover
    file metadata (inode, path, size, timestamps) without writing to the
    evidence volume.

    Cross-reference with Prefetch/Amcache entries to detect tools that were
    executed and then deleted (post-exploitation cleanup).

    Parameters
    ----------
    image_path:
        Absolute path to the evidence disk image.
    case_id:
        Case identifier for output file naming.
    max_entries:
        Maximum number of DeletedFile entries to return.

    Returns
    -------
    dict
        status, records (list of DeletedFile dicts), count, execution_id.
    """
    try:
        return _list_deleted_files(image_path=image_path, case_id=case_id, max_entries=max_entries)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "list_deleted_files"}


@mcp.tool()
def summarize_evtx(
    image_path: str,
    channel: str = "Security",
    case_id: str = "default",
    max_entries: int = 500,
    start_date: str = "",
    end_date: str = "",
    event_ids: str = "",
) -> dict[str, Any]:
    """Parse Windows Event Log (EVTX) files from a disk image.

    Runs ``dotnet EvtxECmd.dll`` (EZ Tools) to extract events from the
    specified log channel.  By default, filters to 26 DFIR-essential Event
    IDs to prevent context flooding.

    Key event IDs (included by default):
    * **4624** — Successful logon (reveals lateral movement)
    * **4625** — Failed logon (brute force indicator)
    * **4688** — Process creation (requires audit policy)
    * **7045** — New service installed (persistence indicator)
    * **4698** — Scheduled task created
    * **4103/4104** — PowerShell logging
    * **1/3** — Sysmon process/network (if available)

    Parameters
    ----------
    image_path:
        Absolute path to the evidence disk image or EVTX file.
    channel:
        Event log channel to parse. Common values: ``"Security"``,
        ``"System"``, ``"Application"``, ``"Sysmon/Operational"``.
    case_id:
        Case identifier for output file naming.
    max_entries:
        Maximum number of EventRecord entries to return.
    start_date:
        ISO 8601 date filter start (e.g. ``"2024-01-15"``).
        Empty string means no start date filter.
    end_date:
        ISO 8601 date filter end (e.g. ``"2024-02-01"``).
        Empty string means no end date filter.
    event_ids:
        Comma-separated Event IDs to include (e.g. ``"4624,4625,7045"``).
        Empty string uses the default DFIR_ESSENTIAL_EIDS (26 IDs).
        Use ``"all"`` to disable filtering and return all events.

    Returns
    -------
    dict
        status, records (list of EventRecord dicts), count, execution_id,
        event_id_filter, date_range.
    """
    try:
        # Parse event_ids string to list[int] or None
        parsed_eids: list[int] | None = None
        if event_ids and event_ids.strip().lower() != "all":
            parsed_eids = [int(x.strip()) for x in event_ids.split(",") if x.strip()]
        elif event_ids.strip().lower() == "all":
            parsed_eids = []  # empty list = disable filtering

        return _summarize_evtx(
            image_path=image_path,
            channel=channel,
            case_id=case_id,
            max_entries=max_entries,
            start_date=start_date or None,
            end_date=end_date or None,
            event_ids=parsed_eids,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "summarize_evtx"}


@mcp.tool()
def extract_registry_run_keys(
    image_path: str,
    case_id: str = "default",
    max_entries: int = 200,
    batch_mode: bool = True,
    sync_batch: bool = False,
) -> dict[str, Any]:
    """Extract Windows registry persistence keys from a disk image.

    Runs ``dotnet RECmd.dll`` (EZ Tools) to extract persistence entries from
    Run/RunOnce, AppInit_DLLs, Winlogon Shell/Userinit, Services, and other
    autostart locations.

    By default, uses DFIRBatch mode (``--bn DFIRBatch.reb``) which targets
    40+ forensically significant registry artifact categories.  Falls back
    to basic mode with a warning if the batch file is not found.

    Also automatically scans user NTUSER.DAT hives for per-user persistence
    keys (a common attacker technique).

    Cross-reference the ``value_data`` (binary path) against disk artefacts
    to detect persistence keys pointing to deleted or non-existent binaries
    (see ``compare_disk_and_memory()`` Check 5).

    Parameters
    ----------
    image_path:
        Absolute path to the evidence disk image or hive file.
    case_id:
        Case identifier for output file naming.
    max_entries:
        Maximum number of RegistryRunKey entries to return.
    batch_mode:
        Use DFIRBatch.reb for targeted extraction (default True).
        Set to False to dump all registry keys.
    sync_batch:
        Download latest batch definitions before running (default False).
        Requires network access.

    Returns
    -------
    dict
        status, records (list of RegistryRunKey dicts), count, execution_id,
        batch_file_used, user_hives_scanned.
    """
    try:
        return _extract_registry_run_keys(
            image_path=image_path,
            case_id=case_id,
            max_entries=max_entries,
            batch_mode=batch_mode,
            sync_batch=sync_batch,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "extract_registry_run_keys"}


# ===========================================================================
# MEMORY NAMESPACE (6 tools)
# ===========================================================================


@mcp.tool()
def detect_profile(dump_path: str) -> dict[str, Any]:
    """Detect the Windows OS profile from a memory dump.

    Runs Volatility 3 ``windows.info.Info`` to identify the OS name, version,
    build number, architecture, and kernel base address.

    This MUST be the first memory tool called on a new dump to confirm that
    Volatility can parse it and to identify the correct symbol tables.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump (.raw, .mem, .lime, .vmem).

    Returns
    -------
    dict
        ProfileResult fields: os_name, os_version, architecture, build_number,
        kernel_base, execution_id.
    """
    if not _MEMORY_AVAILABLE:
        return _memory_unavailable("detect_profile")
    try:
        return _detect_profile(dump_path=dump_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "detect_profile"}


@mcp.tool()
def list_processes(dump_path: str) -> dict[str, Any]:
    """List running processes from a memory dump using the PEB linked list.

    Runs Volatility 3 ``windows.pslist.PsList`` — walks the
    ``PsActiveProcessHead`` doubly-linked list to enumerate OS-visible
    processes.  Compare against ``scan_processes()`` (pool tag scan) to
    detect DKOM-hidden processes.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.

    Returns
    -------
    dict
        status, processes (list of ProcessRecord dicts), count, execution_id.
    """
    if not _MEMORY_AVAILABLE:
        return _memory_unavailable("list_processes")
    try:
        return _list_processes(dump_path=dump_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "list_processes"}


@mcp.tool()
def scan_processes(dump_path: str) -> dict[str, Any]:
    """Scan physical memory for EPROCESS structures (pool tag scan).

    Runs Volatility 3 ``windows.psscan.PsScan`` — searches raw memory pages
    for EPROCESS pool tags rather than walking the linked list.  This surfaces
    unlinked (DKOM-hidden) processes missed by ``list_processes()``.

    Compare results against ``list_processes()`` — processes appearing in
    psscan but not pslist are DKOM-hidden.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.

    Returns
    -------
    dict
        status, processes (list of ProcessRecord dicts with source="psscan"),
        count, execution_id.
    """
    if not _MEMORY_AVAILABLE:
        return _memory_unavailable("scan_processes")
    try:
        return _scan_processes(dump_path=dump_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "scan_processes"}


@mcp.tool()
def scan_network(dump_path: str) -> dict[str, Any]:
    """Extract network connections and sockets from a memory dump.

    Runs Volatility 3 ``windows.netscan.NetScan`` to find TCP/UDP endpoints
    and connections, including closed/unlinked socket structures that netstat
    would not show.

    Network connections with owning PIDs whose executables have no disk
    evidence are a critical indicator of fileless attacks (see
    ``compare_disk_and_memory()`` Check 4).

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.

    Returns
    -------
    dict
        status, connections (list of NetworkArtifact dicts), count, execution_id.
    """
    if not _MEMORY_AVAILABLE:
        return _memory_unavailable("scan_network")
    try:
        return _scan_network(dump_path=dump_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "scan_network"}


@mcp.tool()
def detect_injection(
    dump_path: str,
    pid: Optional[int] = None,
) -> dict[str, Any]:
    """Detect process injection via VAD region analysis (malfind).

    Runs Volatility 3 ``windows.malfind.Malfind`` to identify memory regions
    that are executable, writable, and anonymous (no backing file on disk) —
    a strong indicator of process injection or shellcode.

    Injection in a process running from a legitimate path (System32,
    Program Files) is the most forensically significant case (see
    ``compare_disk_and_memory()`` Check 3).

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.
    pid:
        When provided, restrict the scan to a single PID.
        When ``None``, all processes are scanned.

    Returns
    -------
    dict
        status, injections (list of InjectionIndicator dicts), count, execution_id.
    """
    if not _MEMORY_AVAILABLE:
        return _memory_unavailable("detect_injection")
    try:
        return _detect_injection(dump_path=dump_path, pid=pid)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "detect_injection"}


@mcp.tool()
def list_dlls(dump_path: str, pid: int) -> dict[str, Any]:
    """List DLLs loaded into a specific process from memory.

    Runs Volatility 3 ``windows.dlllist.DllList`` for *pid*.  Unexpected
    DLLs loaded from temp directories, AppData, or without a backing file on
    disk are indicators of DLL injection or sideloading.

    Parameters
    ----------
    dump_path:
        Absolute path to the raw memory dump.
    pid:
        PID of the target process. Use ``list_processes()`` or
        ``scan_processes()`` first to obtain a valid PID.

    Returns
    -------
    dict
        status, dlls (list of DllRecord dicts), count, execution_id.
    """
    if not _MEMORY_AVAILABLE:
        return _memory_unavailable("list_dlls")
    try:
        return _list_dlls(dump_path=dump_path, pid=pid)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "list_dlls"}


# ===========================================================================
# TIMELINE NAMESPACE (2 tools)
# ===========================================================================


@mcp.tool()
def build_timeline(
    source_path: str,
    case_id: str,
    parsers: str = "win10",
) -> dict[str, Any]:
    """Build a Plaso super-timeline from an evidence source.

    Runs ``log2timeline.py`` to ingest all artefact types from *source_path*
    and write a ``.plaso`` storage file.  This step is slow (30–120 minutes
    for a 100 GB image) — for demos, pre-generate the ``.plaso`` file.

    Common parser presets: ``"win10"`` (default), ``"win7"``, ``"linux"``.

    Parameters
    ----------
    source_path:
        Absolute path to the evidence source (image, mounted directory, or
        memory dump).
    case_id:
        Case identifier — used to derive the ``.plaso`` output path in
        ``./analysis/<case_id>/``.
    parsers:
        Plaso parser preset or comma-separated list of parser names.

    Returns
    -------
    dict
        status, storage_path, parser_preset, estimated_event_count,
        duration_seconds, execution_id.
    """
    try:
        return _build_timeline(source_path=source_path, case_id=case_id, parsers=parsers)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "build_timeline"}


@mcp.tool()
def query_timeline(
    plaso_path: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    filter_expr: Optional[str] = None,
    output_format: str = "dynamic",
) -> dict[str, Any]:
    """Query a Plaso storage file and return structured timeline events.

    Runs ``psort.py`` on *plaso_path* with optional time-range and content
    filters.  Returns a list of TimelineEvent dicts sorted chronologically.

    Time filtering example:
        ``start="2026-05-01T00:00:00"`` and ``end="2026-05-01T23:59:59"``

    Content filtering example:
        ``filter_expr="message contains 'cmd.exe'"``

    Both can be combined.

    Parameters
    ----------
    plaso_path:
        Absolute path to the ``.plaso`` storage file from ``build_timeline()``.
    start:
        ISO-8601 lower time bound (e.g. ``"2026-05-01T00:00:00"``).
    end:
        ISO-8601 upper time bound (e.g. ``"2026-05-31T23:59:59"``).
    filter_expr:
        Plaso filter expression (e.g. ``"message contains 'mimikatz'``).
    output_format:
        Plaso output module. Default: ``"dynamic"`` (CSV).

    Returns
    -------
    dict
        status, events (list of TimelineEvent dicts), event_count, execution_id.
    """
    try:
        return _query_timeline(
            plaso_path=plaso_path,
            start=start,
            end=end,
            filter_expr=filter_expr,
            output_format=output_format,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "query_timeline"}


# ===========================================================================
# YARA NAMESPACE (2 tools)
# ===========================================================================


@mcp.tool()
def scan_files(
    rules_path: str,
    target_path: str,
    recursive: bool = False,
) -> dict[str, Any]:
    """Scan a file or directory for YARA rule matches.

    Runs the ``yara`` CLI against *target_path* using the rule set at
    *rules_path*.  Returns a list of match dicts: ``rule_name``,
    ``target_file``, ``matched_strings``.

    An empty match list with ``status="ok"`` means no rules fired — a clean
    result, not an error.

    Parameters
    ----------
    rules_path:
        Absolute path to the YARA rules file (.yar / .yara / .yarc).
    target_path:
        Absolute path to the file or directory to scan.
    recursive:
        When ``True``, recursively scan all files in *target_path* (``-r``).

    Returns
    -------
    dict
        status, matches (list), match_count, execution_id.
    """
    try:
        return _scan_files(rules_path=rules_path, target_path=target_path, recursive=recursive)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "scan_files"}


@mcp.tool()
def scan_memory(
    rules_path: str,
    dump_path: str,
) -> dict[str, Any]:
    """Scan a raw memory dump for YARA rule matches.

    Treats *dump_path* as a flat byte stream and searches for YARA patterns.
    Surfaces in-memory artefacts not present on disk: reflectively loaded
    DLLs, shellcode stubs (Cobalt Strike, Meterpreter), unpacked payloads.

    Cross-reference hits with Volatility ``malfind`` to identify process context.

    Parameters
    ----------
    rules_path:
        Absolute path to the YARA rules file (.yar / .yara / .yarc).
    dump_path:
        Absolute path to the raw memory dump.

    Returns
    -------
    dict
        status, matches (list), match_count, execution_id.
    """
    try:
        return _scan_memory(rules_path=rules_path, dump_path=dump_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "scan_memory"}


# ===========================================================================
# CORRELATION NAMESPACE (2 tools) — THE CORE DIFFERENTIATOR
# ===========================================================================


@mcp.tool()
def compare_disk_and_memory(case_id: str) -> dict[str, Any]:
    """Run all 6 cross-artifact correlation checks against the case state.

    THIS IS THE CORE NOVEL CONTRIBUTION of SAVVYDFIR-MCP.

    Reads the authoritative case state and runs 6 forensic checks that no
    existing Protocol SIFT extension or DFIR-LLM system implements:

    1. **process_no_disk_binary** (HIGH) — Running process with no on-disk
       binary → fileless malware or reflective injection.
    2. **execution_evidence_deleted_binary** (HIGH) — Prefetch/Amcache entry
       for a binary in the deleted-file list → post-exploitation cleanup.
    3. **injection_legitimate_path** (HIGH) — VAD injection on a System32/
       Program Files process → process hollowing or DLL injection.
    4. **network_no_disk_evidence** (MEDIUM) — Network connection from a PID
       with no disk execution evidence → fileless attack.
    5. **persistence_missing_binary** (HIGH) — Run key pointing to a binary
       not found on disk → compromised but remediated host.
    6. **timestomping_detected** (HIGH) — SI timestamps differ from FN
       timestamps by >1 hour → user-level timestamp manipulation.

    For each discrepancy found, the affected findings' ``contradicted_by``
    lists are updated to enable the self-correction loop.

    Parameters
    ----------
    case_id:
        The forensic case identifier (e.g. ``"SRL-2018-WKSTN-01"``).

    Returns
    -------
    dict
        CorrelationReport: case_id, discrepancies (list of DiscrepancyAlert),
        discrepancy_count, disk_findings_count, memory_findings_count,
        confirmed_consistencies, checked_at, summary.
    """
    try:
        return _compare_disk_and_memory(case_id=case_id)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "compare_disk_and_memory"}


@mcp.tool()
def flag_discrepancy(
    finding_id_a: str,
    finding_id_b: str,
    reason: str,
) -> dict[str, Any]:
    """Manually flag a discrepancy between two forensic findings.

    Creates a DiscrepancyAlert and updates both findings' ``contradicted_by``
    lists in the authoritative case state.  Use this when the agent identifies
    a contradiction that the automated correlation engine did not catch — for
    example, when Volatility and a disk artefact give conflicting PID/process
    information.

    This is the manual trigger for the self-correction loop.

    Parameters
    ----------
    finding_id_a:
        F-NNN ID of the first finding (e.g. ``"F-003"``).
    finding_id_b:
        F-NNN ID of the second finding (e.g. ``"F-007"``).
    reason:
        Human-readable explanation of the contradiction.

    Returns
    -------
    dict
        status, discrepancy (DiscrepancyAlert), finding_a (updated),
        finding_b (updated).
    """
    try:
        return _flag_discrepancy(
            finding_id_a=finding_id_a,
            finding_id_b=finding_id_b,
            reason=reason,
        )
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "flag_discrepancy"}


# ===========================================================================
# STATE NAMESPACE (2 tools)
# ===========================================================================


@mcp.tool()
def read_state(case_id: str) -> dict[str, Any]:
    """Return the current authoritative case state summary.

    Reads the ``state.json`` managed by CaseStateManager and returns:
    investigation status, finding/execution counts by category, open
    questions, and the 10 most recently added findings.

    Call this at the start of each triage iteration to resume correctly
    after a server restart.

    Parameters
    ----------
    case_id:
        The forensic case identifier.

    Returns
    -------
    dict
        CaseState summary: case_id, investigation_status, findings_count,
        executions_count, confirmed_count, hypothesis_count, rejected_count,
        unresolved_discrepancies, open_questions, latest_findings,
        created_at, updated_at.
    """
    try:
        return _read_state(case_id=case_id)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "read_state"}


@mcp.tool()
def export_trace(case_id: str) -> dict[str, Any]:
    """Export the full execution trace as a list of audit entries.

    Returns every entry from ``audit.jsonl`` in chronological order.  Each
    entry is either ``event_type="started"`` or ``event_type="completed"``.
    Completed entries include exit code, duration, finding IDs generated, and
    any CORRECTION_EVENT that was produced.

    Use this tool to:
    * Reconstruct the investigation timeline.
    * Verify every finding has a corresponding audit entry.
    * Export for court-admissible documentation.

    Parameters
    ----------
    case_id:
        The forensic case identifier (used for labelling only — the audit
        log is server-global).

    Returns
    -------
    dict
        status, case_id, entry_count, entries (list of AuditEntry dicts),
        started_count, completed_count, correction_events_count.
    """
    try:
        return _export_trace(case_id=case_id)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "export_trace"}


# ===========================================================================
# GRAPH NAMESPACE (2 tools)
# ===========================================================================


@mcp.tool()
def generate_graph(
    case_id: str,
    state_path: Optional[str] = None,
    audit_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> dict[str, Any]:
    """Generate an interactive D3.js investigation graph from case data.

    Runs ``scripts/investigation_graph.py`` to read ``audit.jsonl`` and
    ``state.json`` and produce:

    1. ``graph.json`` — Node/edge graph data for D3.js.
    2. ``graph.html`` — Self-contained interactive HTML visualization with
       force-directed layout, hover tooltips, click provenance, and filters.

    Node types: case, evidence_source, finding (colored by evidence_kind),
    correction.  Edge types: contains, produced, corrected, related,
    contradicts.

    Parameters
    ----------
    case_id:
        The forensic case identifier — used to derive default paths.
    state_path:
        Override path to ``state.json``. Defaults to
        ``./analysis/state.json``.
    audit_path:
        Override path to ``audit.jsonl``. Defaults to
        ``./analysis/audit.jsonl``.
    output_path:
        Override path for ``graph.html`` output. Defaults to
        ``./reports/<case_id>_graph.html``.

    Returns
    -------
    dict
        status, graph_html_path, graph_json_path, node_count, edge_count.
    """
    # Resolve paths
    analysis_dir = Path("./analysis").resolve()
    reports_dir = Path("./reports").resolve()

    resolved_state = Path(state_path).resolve() if state_path else analysis_dir / "state.json"
    resolved_audit = Path(audit_path).resolve() if audit_path else analysis_dir / "audit.jsonl"

    safe_case = case_id.replace("/", "_").replace("\\", "_")
    resolved_output = (
        Path(output_path).resolve() if output_path
        else reports_dir / f"{safe_case}_graph.html"
    )

    # Locate investigation_graph.py relative to this file
    server_dir = Path(__file__).resolve().parent
    graph_script = (server_dir / ".." / "scripts" / "investigation_graph.py").resolve()

    if not graph_script.exists():
        # Try relative to workspace
        graph_script = Path("./scripts/investigation_graph.py").resolve()

    if not graph_script.exists():
        return {
            "status": "error",
            "error": (
                f"investigation_graph.py not found at {graph_script}. "
                "Ensure scripts/investigation_graph.py exists in the project root."
            ),
        }

    # Ensure output directory exists
    try:
        resolved_output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"status": "error", "error": f"Cannot create output directory: {exc}"}

    cmd = [
        sys.executable,
        str(graph_script),
        "--state", str(resolved_state),
        "--audit", str(resolved_audit),
        "--output", str(resolved_output),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "generate_graph timed out (120 s)"}
    except Exception as exc:
        return {"status": "error", "error": f"Failed to run investigation_graph.py: {exc}"}

    if proc.returncode != 0:
        return {
            "status": "error",
            "error": f"investigation_graph.py exited {proc.returncode}",
            "stderr": proc.stderr[:2000],
        }

    # Parse node/edge counts from stdout
    node_count = 0
    edge_count = 0
    for line in proc.stdout.splitlines():
        import re
        m = re.search(r"nodes:\s*(\d+)", line)
        if m:
            node_count = int(m.group(1))
        m = re.search(r"edges:\s*(\d+)", line)
        if m:
            edge_count = int(m.group(1))

    graph_json_path = str(resolved_output.with_name("graph.json"))

    return {
        "status": "ok",
        "case_id": case_id,
        "graph_html_path": str(resolved_output),
        "graph_json_path": graph_json_path,
        "node_count": node_count,
        "edge_count": edge_count,
        "stdout": proc.stdout[-1000:],  # Last 1000 chars of progress output
    }


@mcp.tool()
def serve_graph(
    case_id: str,
    port: int = 8080,
    graph_html_path: Optional[str] = None,
) -> dict[str, Any]:
    """Return the URL and instructions for viewing the investigation graph.

    Does NOT start a web server (the MCP server is a background process that
    should not spawn long-lived subprocesses).  Instead, returns the path to
    the ``graph.html`` file and instructions for the analyst to serve it.

    For browser-accessible serving, run in a separate terminal::

        cd /path/to/graph/dir && python3 -m http.server <port>

    Parameters
    ----------
    case_id:
        The forensic case identifier — used to derive the default graph path.
    port:
        Port number for the suggested http.server command (default 8080).
    graph_html_path:
        Override path to ``graph.html``. Defaults to
        ``./reports/<case_id>_graph.html``.

    Returns
    -------
    dict
        status, graph_html_path, url (the URL to open after serving),
        serve_command (the exact shell command to run).
    """
    safe_case = case_id.replace("/", "_").replace("\\", "_")
    reports_dir = Path("./reports").resolve()

    resolved_html = (
        Path(graph_html_path).resolve() if graph_html_path
        else reports_dir / f"{safe_case}_graph.html"
    )

    if not resolved_html.exists():
        return {
            "status": "error",
            "error": (
                f"graph.html not found at {resolved_html}. "
                "Run generate_graph() first to produce the visualization."
            ),
        }

    serve_dir = str(resolved_html.parent)
    url = f"http://localhost:{port}/{resolved_html.name}"
    serve_command = f"cd {serve_dir} && python3 -m http.server {port}"

    return {
        "status": "ok",
        "case_id": case_id,
        "graph_html_path": str(resolved_html),
        "url": url,
        "serve_command": serve_command,
        "instructions": (
            f"Run the following command in a terminal, then open {url} in a browser:\n"
            f"  {serve_command}"
        ),
    }


# ===========================================================================
# INVESTIGATION LIFECYCLE NAMESPACE (3 tools)
# ===========================================================================


@mcp.tool()
def start_investigation(manifest_path: str) -> dict[str, Any]:
    """Start a new investigation from a case manifest.

    Reads the manifest JSON, initialises the case state, and returns
    investigation parameters.  Supports both "blind" and "seeded" modes:
    in blind mode, known_iocs are NOT included in the response so the
    agent investigates without bias.

    Parameters
    ----------
    manifest_path:
        Absolute path to the manifest.json file.

    Returns
    -------
    dict
        case_id, mode, investigation_goal, disk_images, memory_dumps,
        max_iterations, and (if mode=="seeded") known_iocs.
    """
    import json as _json

    try:
        manifest_file = Path(manifest_path).resolve()
        if not manifest_file.exists():
            return {"status": "error", "error": f"Manifest not found: {manifest_path}"}

        with manifest_file.open("r", encoding="utf-8") as f:
            manifest = _json.load(f)

        case_id = manifest.get("case_id", "UNKNOWN")
        mode = manifest.get("mode", "blind")
        known_iocs = manifest.get("known_iocs", [])

        # Initialise case state
        _state_manager.load(case_id)

        result: dict[str, Any] = {
            "status": "ok",
            "case_id": case_id,
            "mode": mode,
            "investigation_goal": manifest.get("investigation_goal", ""),
            "disk_images": manifest.get("disk_images", []),
            "memory_dumps": manifest.get("memory_dumps", []),
            "max_iterations": manifest.get("max_iterations", 4),
        }

        # Only include IOCs in seeded mode
        if mode == "seeded" and known_iocs:
            result["known_iocs"] = known_iocs

        return result

    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "start_investigation"}


@mcp.tool()
def add_finding(
    case_id: str,
    artifact_type: str,
    evidence_kind: str,
    description: str,
    confidence: float = 0.5,
    status: str = "HYPOTHESIS",
    artifact_path: str = "",
    command: str = "",
) -> dict[str, Any]:
    """Record a forensic finding in the authoritative case state.

    Every finding must cite the source artifact and the command that
    produced it for chain-of-custody compliance.

    Parameters
    ----------
    case_id:
        The forensic case identifier.
    artifact_type:
        Type of artifact (e.g. "process", "prefetch", "registry_key",
        "network_connection", "evtx_event").
    evidence_kind:
        One of "MEMORY_ARTIFACT", "DISK_ARTIFACT", "CORRELATION".
    description:
        Human-readable description of the finding.
    confidence:
        Confidence score 0.0-1.0.
    status:
        One of "OBSERVATION", "INFERENCE", "HYPOTHESIS", "REJECTED".
    artifact_path:
        Path to the source evidence file.
    command:
        The command or tool call that produced this finding.

    Returns
    -------
    dict
        status, finding_id, finding record.
    """
    try:
        finding = {
            "artifact_type": artifact_type,
            "evidence_kind": evidence_kind,
            "description": description,
            "confidence": confidence,
            "status": status,
            "artifact_path": artifact_path,
            "command": command,
            "contradicted_by": [],
        }
        finding_id = _state_manager.add_finding(finding)
        return {
            "status": "ok",
            "finding_id": finding_id,
            "finding": finding,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "add_finding"}


@mcp.tool()
def generate_report(case_id: str) -> dict[str, Any]:
    """Generate the final investigation report from the case state.

    Produces a summary of all findings, unresolved discrepancies,
    and open questions.  This should be the LAST tool called in an
    investigation.

    Parameters
    ----------
    case_id:
        The forensic case identifier.

    Returns
    -------
    dict
        status, summary (CaseState summary), findings_count,
        unresolved_count, open_questions.
    """
    try:
        summary = _state_manager.to_summary()
        _state_manager.set_status("COMPLETE")
        return {
            "status": "ok",
            "case_id": case_id,
            "summary": summary,
            "findings_count": summary.get("findings_count", 0),
            "unresolved_count": summary.get("unresolved_discrepancies", 0),
            "open_questions": summary.get("open_questions", []),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "tool": "generate_report"}


# ===========================================================================
# EVIDENCE MOUNTING NAMESPACE (2 tools)
# ===========================================================================


@mcp.tool()
def mount_image(
    image_path: str,
    mount_point: str = "/mnt/evidence",
    disk_mount: str = "/mnt/disk",
) -> dict[str, Any]:
    """Mount a disk image (E01 or raw) for analysis.

    For E01 images: runs ewfmount then mounts the partition read-only.
    For raw/dd images: mounts partition directly.
    Automatically detects partition offset via mmls.

    Parameters
    ----------
    image_path:
        Absolute path to the disk image file (E01, raw, dd).
    mount_point:
        Directory for ewfmount output. Default: /mnt/evidence
    disk_mount:
        Directory to mount the filesystem. Default: /mnt/disk

    Returns
    -------
    dict
        ToolResult with status, ewf_device (if E01), partition_offset, mount_path.
    """
    import os as _os
    import subprocess as _sp
    import time as _time

    _start = _time.monotonic()

    try:
        # RBAC: image_path must be readable, mount points are in /mnt/ (evidence paths)
        if not validate_path(image_path, write=False):
            return ToolResult(
                status="error", tool="mount_image",
                error=f"RBAC: path not permitted: {image_path}",
            ).model_dump()

        image = Path(image_path).resolve()
        if not image.exists():
            return ToolResult(
                status="error", tool="mount_image",
                error=f"Image not found: {image_path}",
            ).model_dump()

        data: dict[str, Any] = {"image_path": str(image)}
        ewf_device = None

        # --- Pre-flight: detect existing mounts ---
        mount_check = _sp.run(["mount"], capture_output=True, text=True)
        mounts = mount_check.stdout

        if disk_mount in mounts:
            # Already fully mounted — return immediately, skip all steps
            return ToolResult(
                status="ok", tool="mount_image",
                message=f"Already mounted at {disk_mount} (pre-existing mount detected)",
                data={"image_path": str(image), "mount_path": disk_mount,
                      "mount_status": "already_mounted", "already_mounted": True},
            ).model_dump()

        if mount_point in mounts or _os.path.exists(f"{mount_point}/ewf1"):
            # ewfmount already done, skip to partition mount
            ewf_device = f"{mount_point}/ewf1"
            data["ewf_device"] = ewf_device
            data["ewfmount_status"] = "already_mounted"
        else:
            # --- Determine image type ---
            is_e01 = image.suffix.lower() in (".e01", ".ex01", ".s01")

            if is_e01:
                # Step 1: ewfmount
                Path(mount_point).mkdir(parents=True, exist_ok=True)
                proc = _sp.run(
                    ["/usr/bin/ewfmount", str(image), mount_point],
                    capture_output=True, text=True, timeout=120
                )
                if proc.returncode != 0:
                    # Try with nonempty flag if directory has stale FUSE mount
                    if "not empty" in proc.stderr or "nonempty" in proc.stderr:
                        proc = _sp.run(
                            ["/usr/bin/ewfmount", "-X", "nonempty", str(image), mount_point],
                            capture_output=True, text=True, timeout=120
                        )
                    if proc.returncode != 0:
                        return ToolResult(
                            status="error", tool="mount_image",
                            error=f"ewfmount failed: {proc.stderr}",
                            data={"hint": f"Try: umount {mount_point} then retry, or use -X nonempty flag"},
                        ).model_dump()

        # Set device path based on ewf or raw
        is_e01 = image.suffix.lower() in (".e01", ".ex01", ".s01")
        if is_e01 or ewf_device:
            ewf_device = ewf_device or f"{mount_point}/ewf1"
            data["ewf_device"] = ewf_device
            device = ewf_device
        else:
            device = str(image)

        # Step 2: Detect partition offset
        # Strategy: mmls (MBR/GPT) → parted loop-detection (raw FS) → GPT default
        proc = _sp.run(
            ["/usr/bin/mmls", device],
            capture_output=True, text=True, timeout=60
        )
        offset = None
        max_length = 0
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                match = re.match(r"\d+:\s+\d+:\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)", line)
                if match:
                    start = int(match.group(1))
                    length = int(match.group(3))
                    desc = match.group(4).strip()
                    if length > max_length and "NTFS" in desc:
                        max_length = length
                        offset = start
                # Also try simpler mmls format
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        start_val = int(parts[2])
                        len_val = int(parts[4])
                        if len_val > max_length:
                            max_length = len_val
                            offset = start_val
                    except (ValueError, IndexError):
                        pass

        if offset is None:
            # mmls failed or found no partitions — check for raw/loop filesystem
            # (common for E01 images acquired from a single partition, not a whole disk)
            parted_proc = _sp.run(
                ["/usr/sbin/parted", "-s", device, "print"],
                capture_output=True, text=True, timeout=30
            )
            if "loop" in parted_proc.stdout.lower():
                # Raw filesystem with no partition table — mount at offset 0
                offset = 0
                data["offset_source"] = "parted (raw filesystem, no partition table)"
            else:
                # Last resort: GPT default
                offset = 2048
                data["offset_source"] = "default (GPT assumed)"
        else:
            data["offset_source"] = "mmls"

        data["partition_offset_sectors"] = offset
        data["partition_offset_bytes"] = offset * 512

        # Step 3: Mount partition read-only
        Path(disk_mount).mkdir(parents=True, exist_ok=True)
        if offset == 0:
            # Raw filesystem — mount directly, no loop offset needed
            mount_cmd = ["/usr/bin/mount", "-o", "ro", device, disk_mount]
        else:
            mount_cmd = ["/usr/bin/mount", "-o", f"ro,loop,offset={offset * 512}", device, disk_mount]

        proc = _sp.run(mount_cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            return ToolResult(
                status="error", tool="mount_image",
                error=f"mount failed: {proc.stderr}",
                data={"hint": f"Run manually: {' '.join(mount_cmd)}"},
            ).model_dump()

        data["mount_path"] = disk_mount
        data["mount_status"] = "mounted"

        return ToolResult(
            status="ok", tool="mount_image",
            message=f"Image mounted at {disk_mount}",
            data=data,
            duration_seconds=round(_time.monotonic() - _start, 3),
        ).model_dump()

    except Exception as exc:
        return ToolResult(
            status="error", tool="mount_image", error=str(exc),
        ).model_dump()


@mcp.tool()
def load_memory(
    dump_path: str,
    output_dir: str = "/evidence/memory",
) -> dict[str, Any]:
    """Load a memory dump for analysis, extracting from ZIP if needed.

    Checks if the dump is a ZIP archive and extracts it automatically.
    Returns the path to the raw memory dump ready for Volatility 3.

    Parameters
    ----------
    dump_path:
        Absolute path to the memory dump file (.raw, .mem, .vmem, or .zip).
    output_dir:
        Directory for extracted files. Default: /evidence/memory

    Returns
    -------
    dict
        ToolResult with raw_dump_path, file_size, was_extracted.
    """
    import subprocess as _sp
    import time as _time

    _start = _time.monotonic()

    try:
        if not validate_path(dump_path, write=False):
            return ToolResult(
                status="error", tool="load_memory",
                error=f"RBAC: path not permitted: {dump_path}",
            ).model_dump()

        dump = Path(dump_path).resolve()
        if not dump.exists():
            return ToolResult(
                status="error", tool="load_memory",
                error=f"Memory dump not found: {dump_path}",
            ).model_dump()

        data: dict[str, Any] = {"original_path": str(dump)}

        # Check if file is a ZIP archive
        proc = _sp.run(
            ["/usr/bin/file", str(dump)],
            capture_output=True, text=True, timeout=30
        )
        file_type = proc.stdout.lower()

        if "zip" in file_type or dump.suffix.lower() == ".zip":
            # Extract ZIP
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            proc = _sp.run(
                ["/usr/bin/7z", "x", str(dump), f"-o{output_dir}", "-y"],
                capture_output=True, text=True, timeout=600
            )
            if proc.returncode != 0:
                return ToolResult(
                    status="error", tool="load_memory",
                    error=f"Extraction failed: {proc.stderr}",
                ).model_dump()

            data["was_extracted"] = True

            # Find the extracted raw file
            raw_path = None
            for ext in (".raw", ".mem", ".vmem", ".lime", ".dmp"):
                for f in Path(output_dir).rglob(f"*{ext}"):
                    raw_path = f
                    break
                if raw_path:
                    break

            if not raw_path:
                for f in Path(output_dir).iterdir():
                    if f.is_file() and f.stat().st_size > 100_000_000:
                        raw_path = f
                        break

            if not raw_path:
                return ToolResult(
                    status="error", tool="load_memory",
                    error="No memory dump found after extraction",
                    data={"extracted_files": [str(f) for f in Path(output_dir).iterdir()]},
                ).model_dump()

            data["raw_dump_path"] = str(raw_path)
            data["file_size"] = raw_path.stat().st_size
        else:
            data["was_extracted"] = False
            data["raw_dump_path"] = str(dump)
            data["file_size"] = dump.stat().st_size

        return ToolResult(
            status="ok", tool="load_memory",
            message=f"Memory dump ready at {data['raw_dump_path']}",
            data=data,
            duration_seconds=round(_time.monotonic() - _start, 3),
        ).model_dump()

    except Exception as exc:
        return ToolResult(
            status="error", tool="load_memory", error=str(exc),
        ).model_dump()


# ===========================================================================
# SIGMA / UNIVERSAL ANOMALY DETECTION NAMESPACE
# ===========================================================================

# ---- Windows constants for case-agnostic detection ----

#: Processes that MUST have services.exe as parent on a healthy Windows system.
# ---------------------------------------------------------------------------
# Column / key normalization helpers for anomaly detectors
# ---------------------------------------------------------------------------


def _normalize_columns(df):
    """Normalize DataFrame column names: strip, lowercase, replace spaces with underscores.
    EvtxECmd and other EZ Tools produce inconsistent column names across versions."""
    df = df.copy()
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_')
    return df


def _find_col(df, *candidates):
    """Find first matching column name (case-insensitive, normalized)."""
    norm_cols = {c.lower().replace(' ', '_').replace('-', '_'): c for c in df.columns}
    for c in candidates:
        norm = c.lower().replace(' ', '_').replace('-', '_')
        if norm in norm_cols:
            return norm_cols[norm]
        # Try partial match
        matches = [v for k, v in norm_cols.items() if norm in k]
        if matches:
            return matches[0]
    return None


def _normalize_finding(f: dict) -> dict:
    """Normalize a finding dict's keys: strip, lowercase, replace spaces/dashes with underscores.
    This handles inconsistent key names from different EZ Tools versions and tool outputs."""
    return {
        k.strip().lower().replace(' ', '_').replace('-', '_'): v
        for k, v in f.items()
    }


def _find_key(f: dict, *candidates) -> Any:
    """Find first matching key value from a dict (case-insensitive, normalized).
    Returns None if no candidate matches."""
    norm_keys = {k.lower().replace(' ', '_').replace('-', '_'): v for k, v in f.items()}
    for c in candidates:
        norm = c.lower().replace(' ', '_').replace('-', '_')
        if norm in norm_keys:
            return norm_keys[norm]
        # Try partial match
        matches = [v for k, v in norm_keys.items() if norm in k]
        if matches:
            return matches[0]
    return None


_SVCHOST_PARENT = "services.exe"
#: Legitimate svchost path (case-insensitive comparison).
_SVCHOST_PATH = r"c:\windows\system32\svchost.exe"
#: Processes that should run as SYSTEM.
_SYSTEM_PROCESSES = {
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe",
}
#: High-value Windows Security Event IDs.
_HIGH_VALUE_EVTX = {
    4624: ("Logon success", "TA0001", "T1078"),      # Initial Access
    4625: ("Logon failure", "TA0006", "T1110"),       # Credential Access
    4648: ("Explicit logon", "TA0008", "T1021"),      # Lateral Movement
    4672: ("Special privileges", "TA0004", "T1134"),   # Privilege Escalation
    4688: ("Process creation", "TA0002", "T1059"),     # Execution
    4697: ("Service installed", "TA0003", "T1543"),    # Persistence
    4698: ("Scheduled task", "TA0003", "T1053"),       # Persistence
    4720: ("User created", "TA0003", "T1136"),         # Persistence
    7045: ("New service", "TA0003", "T1543.003"),      # Persistence
    1116: ("Defender detection", "TA0005", "T1562"),   # Defense Evasion
}


def _detect_process_anomalies(findings: list[dict]) -> list[ArtifactHit]:
    """Detect universal process anomalies from case state findings.

    Checks:
    - svchost.exe not spawned by services.exe (masquerading)
    - System processes running from non-System32 paths
    - Orphan processes (PPID doesn't exist in process list)
    - Process name typosquats of system processes
    """
    hits: list[ArtifactHit] = []
    findings = [_normalize_finding(f) for f in findings]

    process_findings = [f for f in findings if _find_key(f, "artifact_type") == "process"]
    pids = {_find_key(f, "pid", "processid", "process_id") for f in process_findings}
    pids.discard(None)

    for pf in process_findings:
        pid = _find_key(pf, "pid", "processid", "process_id")
        name = (_find_key(pf, "name", "imagename", "image_name", "processname") or _find_key(pf, "description") or "").lower()
        ppid = _find_key(pf, "ppid", "parent_pid", "parentprocessid", "parentpid")
        path = (_find_key(pf, "artifact_path", "imagepath", "image_path", "path") or "").lower()

        # Check: svchost not spawned by services.exe
        if "svchost" in name and ppid is not None:
            parent_name = ""
            for f2 in process_findings:
                f2_pid = _find_key(f2, "pid", "processid", "process_id")
                if f2_pid == ppid:
                    parent_name = (_find_key(f2, "name", "imagename", "image_name", "processname") or _find_key(f2, "description") or "").lower()
                    break
            if parent_name and _SVCHOST_PARENT not in parent_name:
                hits.append(ArtifactHit(
                    detector="process_anomaly",
                    severity="CRITICAL",
                    description=f"svchost.exe (PID {pid}) has unexpected parent {parent_name} (PID {ppid}) — expected services.exe",
                    artifact_type="process",
                    artifact_path=_find_key(pf, "artifact_path"),
                    raw_data={"pid": pid, "ppid": ppid, "parent_name": parent_name},
                    mitre_technique="T1036.005",
                    mitre_tactic="TA0005",
                    pivot_suggestion=f"Call detect_injection(pid={pid}) and list_dlls(pid={pid})",
                ))

        # Check: orphan process
        if ppid is not None and ppid not in pids and ppid > 4:
            hits.append(ArtifactHit(
                detector="process_anomaly",
                severity="HIGH",
                description=f"Orphan process '{name}' (PID {pid}) — parent PID {ppid} not found in process list",
                artifact_type="process",
                raw_data={"pid": pid, "ppid": ppid},
                mitre_technique="T1134",
                mitre_tactic="TA0005",
                pivot_suggestion="Call scan_processes() to check if parent was DKOM-hidden",
            ))

        # Check: system process from wrong path
        base_name = name.split("\\")[-1].split("/")[-1]
        if base_name in _SYSTEM_PROCESSES and path and "system32" not in path:
            hits.append(ArtifactHit(
                detector="process_anomaly",
                severity="CRITICAL",
                description=f"System process '{base_name}' running from unexpected path: {path}",
                artifact_type="process",
                artifact_path=path,
                raw_data={"pid": pid, "name": base_name, "path": path},
                mitre_technique="T1036.005",
                mitre_tactic="TA0005",
                pivot_suggestion=f"Hash the binary and check VirusTotal: sha256sum {path}",
            ))

    return hits


def _detect_network_anomalies(findings: list[dict]) -> list[ArtifactHit]:
    """Detect universal network anomalies.

    Checks:
    - Outbound connections to non-RFC1918 addresses from system processes
    - Connections on unusual ports (not 80, 443, 53, 445, 135, 139)
    - Listening sockets on high ports (>49152) owned by non-system processes
    """
    hits: list[ArtifactHit] = []
    _COMMON_PORTS = {80, 443, 53, 445, 135, 139, 389, 636, 88, 464, 3389}
    findings = [_normalize_finding(f) for f in findings]
    net_findings = [f for f in findings if _find_key(f, "artifact_type") == "network_connection"]

    for nf in net_findings:
        remote = _find_key(nf, "remote_addr", "foreignaddr", "foreign_addr", "remoteaddress", "remotehost") or ""
        remote_port = _find_key(nf, "remote_port", "foreignport", "foreign_port", "remoteport")
        owner = (_find_key(nf, "owner_process", "owning_process", "processname", "name") or _find_key(nf, "description") or "").lower()
        state = (_find_key(nf, "state", "status", "connection_state") or "").upper()

        # Skip if no remote address
        if not remote or remote in ("0.0.0.0", "::", "*", ""):
            continue

        # Check if remote is non-RFC1918 (external)
        try:
            addr = ipaddress.ip_address(remote)
            is_external = not addr.is_private and not addr.is_loopback and not addr.is_link_local
        except ValueError:
            is_external = False

        # System process making external connections
        if is_external and any(sp in owner for sp in _SYSTEM_PROCESSES):
            hits.append(ArtifactHit(
                detector="network_anomaly",
                severity="HIGH",
                description=f"System process '{owner}' has external connection to {remote}:{remote_port}",
                artifact_type="network",
                raw_data={"remote": remote, "port": remote_port, "owner": owner, "state": state},
                mitre_technique="T1071",
                mitre_tactic="TA0011",
                pivot_suggestion=f"Check if {remote} is a known C2: scan memory for related YARA rules",
            ))

        # Unusual outbound port
        if is_external and remote_port and remote_port not in _COMMON_PORTS and state == "ESTABLISHED":
            hits.append(ArtifactHit(
                detector="network_anomaly",
                severity="MEDIUM",
                description=f"Outbound connection to {remote}:{remote_port} on unusual port from '{owner}'",
                artifact_type="network",
                raw_data={"remote": remote, "port": remote_port, "owner": owner},
                mitre_technique="T1571",
                mitre_tactic="TA0011",
                pivot_suggestion="Check process tree of owning PID for injection indicators",
            ))

    return hits


def _detect_mft_anomalies(findings: list[dict]) -> list[ArtifactHit]:
    """Detect SI<FN timestomping from MFT entries.

    If $STANDARD_INFORMATION Created < $FILE_NAME Created by >1 hour,
    the file was likely timestomped (SI is user-modifiable, FN requires kernel).
    """
    hits: list[ArtifactHit] = []
    findings = [_normalize_finding(f) for f in findings]
    mft_findings = [f for f in findings if _find_key(f, "artifact_type") in ("mft", "mft_entry")]

    for mf in mft_findings:
        si_created = _find_key(mf, "si_created", "created0x10", "sicreated", "standard_information_created")
        fn_created = _find_key(mf, "fn_created", "created0x30", "fncreated", "file_name_created")
        file_path_val = _find_key(mf, "file_path", "filename", "filepath", "path") or "unknown"
        if not si_created or not fn_created:
            continue

        try:
            if isinstance(si_created, str):
                si_dt = datetime.fromisoformat(si_created.replace("Z", "+00:00"))
            else:
                si_dt = si_created
            if isinstance(fn_created, str):
                fn_dt = datetime.fromisoformat(fn_created.replace("Z", "+00:00"))
            else:
                fn_dt = fn_created

            delta = abs((si_dt - fn_dt).total_seconds())
            if delta > 3600:  # >1 hour discrepancy
                hits.append(ArtifactHit(
                    detector="mft_timestomp",
                    severity="HIGH",
                    description=f"Timestomping detected: SI Created differs from FN Created by {delta/3600:.1f}h for {file_path_val}",
                    artifact_type="mft",
                    artifact_path=file_path_val if file_path_val != "unknown" else None,
                    raw_data={"si_created": str(si_created), "fn_created": str(fn_created), "delta_seconds": delta},
                    mitre_technique="T1070.006",
                    mitre_tactic="TA0005",
                    pivot_suggestion="Check prefetch/amcache for true first execution time of this binary",
                ))
        except (ValueError, TypeError):
            continue

    return hits


def _detect_evtx_anomalies(findings: list[dict]) -> list[ArtifactHit]:
    """Flag high-value Windows Event IDs with ATT&CK technique auto-tagging."""
    hits: list[ArtifactHit] = []
    findings = [_normalize_finding(f) for f in findings]
    evtx_findings = [f for f in findings if _find_key(f, "artifact_type") in ("evtx_event", "event_log")]

    for ef in evtx_findings:
        event_id = _find_key(ef, "event_id", "eventid", "id")
        # Coerce to int for lookup
        if event_id is not None:
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
        if event_id and event_id in _HIGH_VALUE_EVTX:
            label, tactic, technique = _HIGH_VALUE_EVTX[event_id]
            msg = _find_key(ef, "description", "message_summary", "message", "payloaddata1") or ""
            channel = _find_key(ef, "channel", "eventchannel", "log_name") or ""
            ts = _find_key(ef, "timestamp", "timecreated", "time_created", "date/time___utc") or ""
            hits.append(ArtifactHit(
                detector="evtx_anomaly",
                severity="HIGH" if event_id in (4688, 4697, 7045, 4698) else "MEDIUM",
                description=f"High-value event {event_id} ({label}): {msg}",
                artifact_type="evtx",
                raw_data={"event_id": event_id, "channel": channel, "timestamp": str(ts)},
                mitre_technique=technique,
                mitre_tactic=tactic,
                pivot_suggestion=f"Correlate event {event_id} with timeline around this timestamp",
            ))

    return hits


def _detect_persistence_anomalies(findings: list[dict]) -> list[ArtifactHit]:
    """Detect persistence keys pointing to suspicious paths or missing binaries."""
    hits: list[ArtifactHit] = []
    _SUSPICIOUS_PATHS = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\public\\"]
    findings = [_normalize_finding(f) for f in findings]
    reg_findings = [f for f in findings if _find_key(f, "artifact_type") in ("registry_key", "persistence")]

    for rf in reg_findings:
        value = (_find_key(rf, "value_data", "valuedata", "data", "value") or _find_key(rf, "artifact_path") or "").lower()
        key_path = _find_key(rf, "key_path", "keypath", "hivepath", "path") or ""

        for sp in _SUSPICIOUS_PATHS:
            if sp in value:
                hits.append(ArtifactHit(
                    detector="persistence_anomaly",
                    severity="HIGH",
                    description=f"Persistence key references suspicious path: {value}",
                    artifact_type="persistence",
                    artifact_path=_find_key(rf, "artifact_path"),
                    raw_data={"key": key_path, "value": value},
                    mitre_technique="T1547.001",
                    mitre_tactic="TA0003",
                    pivot_suggestion=f"Check if binary exists on disk: fls -r | grep '{Path(value).name}'",
                ))
                break

    return hits


def _hits_to_markdown(hits: list[ArtifactHit]) -> str:
    """Convert ArtifactHit list to a markdown summary table."""
    if not hits:
        return "No anomalies detected."

    lines = ["| # | Severity | Detector | Description | ATT&CK |",
             "|---|----------|----------|-------------|--------|"]
    for i, h in enumerate(hits, 1):
        technique = h.mitre_technique or "-"
        desc = h.description[:80] + "..." if len(h.description) > 80 else h.description
        lines.append(f"| {i} | {h.severity} | {h.detector} | {desc} | {technique} |")

    return "\n".join(lines)


@mcp.tool()
def sigma_scan(case_id: str) -> dict[str, Any]:
    """Run universal anomaly detection across all findings in the case state.

    Executes 5 independent anomaly detectors against the authoritative case
    state. Each detector implements case-agnostic detection logic based on
    universal Windows forensic patterns — no hardcoded IPs, usernames, or
    filenames.

    Detectors:
    1. **process_anomaly** — svchost parentage, orphans, wrong-path system procs
    2. **network_anomaly** — RFC1918 exclusion, unusual ports, system proc C2
    3. **mft_timestomp** — SI vs FN timestamp discrepancy (>1 hour = timestomping)
    4. **evtx_anomaly** — High-value Event IDs with auto ATT&CK tagging
    5. **persistence_anomaly** — Run keys pointing to suspicious paths

    Parameters
    ----------
    case_id:
        The forensic case identifier.

    Returns
    -------
    dict
        SigmaScanResult with hits, counts, and markdown summary.
    """
    try:
        state = _state_manager.load(case_id)
        all_findings = state.get("findings", [])

        all_hits: list[ArtifactHit] = []
        detectors_run: list[str] = []

        # Run each detector
        for name, func in [
            ("process_anomaly", _detect_process_anomalies),
            ("network_anomaly", _detect_network_anomalies),
            ("mft_timestomp", _detect_mft_anomalies),
            ("evtx_anomaly", _detect_evtx_anomalies),
            ("persistence_anomaly", _detect_persistence_anomalies),
        ]:
            detectors_run.append(name)
            hits = func(all_findings)
            all_hits.extend(hits)

        critical = sum(1 for h in all_hits if h.severity == "CRITICAL")
        high = sum(1 for h in all_hits if h.severity == "HIGH")

        result = SigmaScanResult(
            case_id=case_id,
            hits=all_hits,
            total_hits=len(all_hits),
            critical_count=critical,
            high_count=high,
            detectors_run=detectors_run,
            summary_markdown=_hits_to_markdown(all_hits),
        )

        return result.model_dump()

    except Exception as exc:
        return ToolResult(
            status="error", tool="sigma_scan", error=str(exc),
        ).model_dump()


@mcp.tool()
def run_analysis(
    data_path: str,
    query: str,
    output_format: str = "table",
) -> dict[str, Any]:
    """Execute a Pandas analysis query on a CSV/JSON data file.

    Provides a safe Pandas interpreter for analyzing forensic tool output
    (MFTECmd CSVs, EvtxECmd CSVs, timeline exports, etc.) without
    requiring the agent to write and execute raw Python scripts.

    The query is a Pandas expression applied to the DataFrame loaded from
    data_path. Available variables: ``df`` (the loaded DataFrame).

    Example queries:
    - ``df[df['EventID'] == 4624].groupby('TargetUserName').size()``
    - ``df.sort_values('Created0x10').head(20)``
    - ``df[df['IsDeleted'] == True][['FileName', 'Created0x10']]``

    Parameters
    ----------
    data_path:
        Absolute path to a CSV or JSON file to load as a DataFrame.
    query:
        A Pandas expression to evaluate. The DataFrame is available as ``df``.
    output_format:
        Output format: ``"table"`` (tabulate), ``"json"``, ``"csv"``.

    Returns
    -------
    dict
        AnalysisResult with tabulated output, row count, column names, and insights.
    """
    try:
        if not validate_path(data_path, write=False):
            return ToolResult(
                status="error", tool="run_analysis",
                error=f"RBAC: path not permitted: {data_path}",
            ).model_dump()

        path = Path(data_path).resolve()
        if not path.exists():
            return ToolResult(
                status="error", tool="run_analysis",
                error=f"File not found: {data_path}",
            ).model_dump()

        # Block dangerous operations in query
        _BLOCKED_PATTERNS = [
            "import ", "exec(", "eval(", "__", "open(", "os.", "sys.",
            "subprocess", "shutil", "pathlib", "glob",
        ]
        for pattern in _BLOCKED_PATTERNS:
            if pattern in query:
                return ToolResult(
                    status="error", tool="run_analysis",
                    error=f"Query contains blocked pattern: {pattern}",
                ).model_dump()

        import pandas as pd

        # Load data
        if path.suffix.lower() == ".json":
            df = pd.read_json(path)
        else:
            df = pd.read_csv(path, low_memory=False)

        # Execute query in restricted namespace
        namespace = {"df": df, "pd": pd}
        result_obj = eval(query, {"__builtins__": {}}, namespace)  # noqa: S307

        # Format output
        if isinstance(result_obj, pd.DataFrame):
            result_df = result_obj
        elif isinstance(result_obj, pd.Series):
            result_df = result_obj.to_frame()
        else:
            result_df = pd.DataFrame({"result": [result_obj]})

        # Limit to 500 rows
        if len(result_df) > 500:
            result_df = result_df.head(500)

        try:
            from tabulate import tabulate
            table_str = tabulate(result_df, headers="keys", tablefmt="pipe", showindex=False)
        except ImportError:
            table_str = result_df.to_string()

        # Generate insights
        insights: list[str] = []
        if len(result_df) > 0:
            insights.append(f"Query returned {len(result_df)} rows")
            for col in result_df.columns:
                if result_df[col].dtype in ("int64", "float64"):
                    insights.append(f"{col}: min={result_df[col].min()}, max={result_df[col].max()}, mean={result_df[col].mean():.2f}")

        analysis = AnalysisResult(
            query=query,
            result_table=table_str,
            row_count=len(result_df),
            columns=list(result_df.columns),
            insights=insights,
            data_source=str(path),
        )

        return analysis.model_dump()

    except Exception as exc:
        return ToolResult(
            status="error", tool="run_analysis", error=str(exc),
        ).model_dump()


# ===========================================================================
# Entry point
# ===========================================================================


if __name__ == "__main__":
    mcp.run()
