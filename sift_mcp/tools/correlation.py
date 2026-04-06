"""
sift_mcp.tools.correlation
~~~~~~~~~~~~~~~~~~~~~~~~~~~

THE CORE DIFFERENTIATOR — Cross-artifact correlation engine for SAVVYDFIR-MCP.

Two tools are exposed:

* ``compare_disk_and_memory`` — Reads the authoritative case state and runs
  6 specific forensic correlation checks, producing a :class:`CorrelationReport`.
* ``flag_discrepancy`` — Manually flag a discrepancy between two specific
  findings.

These tools are synchronous (FastMCP supports sync).

The 6 Correlation Checks
------------------------

1. **Process in memory with no disk binary** — A running process whose
   executable path cannot be found in any disk execution artefact indicates
   fileless malware or post-execution binary deletion.

2. **Prefetch/Amcache entry for deleted binary** — A Prefetch or Amcache
   record proves the binary executed, but ``fls -rd`` shows it was subsequently
   deleted.  Strong post-exploitation cleanup indicator.

3. **VAD anomaly on legitimate-path process** — A ``malfind`` injection
   indicator on a process running from System32 or Program Files is far more
   forensically significant than a hit on an unknown binary.

4. **Network connection with no disk artefact** — A memory-resident network
   connection whose owning process has no corresponding disk execution
   evidence indicates fileless attack or injected shellcode.

5. **Registry persistence for missing binary** — A Run/RunOnce key points to
   a binary path that does not exist on disk — the host was compromised but
   the malware was subsequently cleaned up.

6. **Timestomping detection** — ``$STANDARD_INFORMATION`` timestamps differ
   significantly from ``$FILE_NAME`` timestamps, indicating user-level
   timestamp manipulation.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager

__all__ = [
    "compare_disk_and_memory",
    "flag_discrepancy",
    "init_tools",
]

# ---------------------------------------------------------------------------
# Module-level singletons (initialised by init_tools)
# ---------------------------------------------------------------------------

_audit: Optional[AuditLogger] = None
_state_mgr: Optional[CaseStateManager] = None

# Threshold for timestomping: SI and FN timestamps differ by more than this
_TIMESTOMP_THRESHOLD = timedelta(hours=1)

# Legitimate binary path prefixes (Windows system paths)
_LEGITIMATE_PATHS = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\sysnat",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\windows\\",
)


def init_tools(
    audit_logger: AuditLogger,
    state_manager: CaseStateManager,
) -> None:
    """Wire the shared audit logger and state manager into this tool module.

    Must be called once at server startup before any tool function is invoked.

    Parameters
    ----------
    audit_logger:
        The process-wide :class:`~sift_mcp.audit.AuditLogger` instance.
    state_manager:
        The process-wide :class:`~sift_mcp.state.CaseStateManager` instance.
    """
    global _audit, _state_mgr
    _audit = audit_logger
    _state_mgr = state_manager


# ---------------------------------------------------------------------------
# Tool 1: compare_disk_and_memory
# ---------------------------------------------------------------------------


def compare_disk_and_memory(case_id: str) -> dict[str, Any]:
    """Run all 6 cross-artifact correlation checks against the case state.

    Reads the authoritative case state managed by the
    :class:`~sift_mcp.state.CaseStateManager` and compares disk and memory
    findings for forensically significant discrepancies.

    The 6 checks are:

    1. **process_no_disk_binary** (HIGH) — Process in memory whose executable
       path is absent from all disk execution artefacts.
    2. **execution_evidence_deleted_binary** (HIGH) — Prefetch/Amcache entry
       for a binary that appears in the deleted-file list.
    3. **injection_legitimate_path** (HIGH) — VAD injection indicator on a
       process running from a system path (System32, Program Files, etc.).
    4. **network_no_disk_evidence** (MEDIUM) — Network connection from a PID
       whose owning process has no disk execution evidence.
    5. **persistence_missing_binary** (HIGH) — Registry Run key points to a
       binary path that does not exist in the disk artefacts.
    6. **timestomping_detected** (HIGH) — SI timestamps differ from FN
       timestamps by more than 1 hour, indicating timestomping.

    For each discrepancy, this function also updates the ``contradicted_by``
    lists of the affected findings (if the state manager is loaded for the
    case).

    Parameters
    ----------
    case_id:
        The forensic case identifier (e.g. ``"SRL-2018-WKSTN-01"``).

    Returns
    -------
    dict
        A :class:`~sift_mcp.models.artifacts.CorrelationReport`-shaped dict::

            {
              "status": "ok",
              "case_id": "SRL-2018-WKSTN-01",
              "discrepancies": [
                {
                  "discrepancy_type": "process_no_disk_binary",
                  "severity": "HIGH",
                  "description": "...",
                  "disk_finding_id": null,
                  "memory_finding_id": "F-003",
                  "recommended_action": "Call detect_injection(pid=1832)...",
                  "disk_evidence": {...},
                  "memory_evidence": {...}
                },
                ...
              ],
              "discrepancy_count": 1,
              "disk_findings_count": 12,
              "memory_findings_count": 8,
              "confirmed_consistencies": 5,
              "checked_at": "2026-05-01T14:23:11.000Z",
              "summary": "1 discrepancy found across 6 correlation checks."
            }
    """
    if _state_mgr is None:
        return {"status": "error", "error": "Tool module not initialised — call init_tools() first."}

    # Load state for the given case
    try:
        _state_mgr.load(case_id)
    except Exception as exc:
        return {"status": "error", "error": f"Cannot load case state: {exc}"}

    # Retrieve findings by domain
    try:
        disk_findings = _state_mgr.get_findings(artifact_type="disk")
        memory_findings = _state_mgr.get_findings(artifact_type="memory")
        all_findings = disk_findings + memory_findings
    except Exception as exc:
        return {"status": "error", "error": f"Cannot read findings: {exc}"}

    discrepancies: list[dict[str, Any]] = []
    confirmed_consistencies = 0

    # -----------------------------------------------------------------------
    # Check 1: Process in memory with no disk binary
    # -----------------------------------------------------------------------
    process_records = _extract_typed(memory_findings, finding_type_contains="process")
    disk_paths = _collect_disk_paths(disk_findings)

    for proc_finding in process_records:
        meta = proc_finding.get("supporting_indicators", [])
        proc_path = _extract_indicator(meta, "path:")

        if not proc_path:
            # Try description for path hints
            desc = proc_finding.get("description", "")
            proc_path = _path_from_description(desc)

        if proc_path:
            norm_path = proc_path.lower().replace("\\", "/")
            if not _path_in_set(norm_path, disk_paths):
                alert = _make_discrepancy(
                    discrepancy_type="process_no_disk_binary",
                    severity="HIGH",
                    description=(
                        f"Process found in memory artefacts with executable path "
                        f"'{proc_path}' that does not appear in any disk execution "
                        f"artefact (Prefetch, Amcache, or MFT). This indicates "
                        f"fileless malware, reflective injection, or a binary "
                        f"deleted after execution."
                    ),
                    memory_finding_id=proc_finding.get("finding_id"),
                    disk_finding_id=None,
                    recommended_action=(
                        "Call detect_injection() on the PID, then list_dlls() "
                        "to inspect loaded DLLs. Consider scan_memory() with "
                        "relevant YARA rules."
                    ),
                    disk_evidence=None,
                    memory_evidence={"path": proc_path, "finding_id": proc_finding.get("finding_id")},
                )
                discrepancies.append(alert)
                # Update contradicted_by on the finding
                _add_contradiction(proc_finding.get("finding_id"), "correlation:process_no_disk_binary")
            else:
                confirmed_consistencies += 1
        # Processes with no path data skip this check

    # -----------------------------------------------------------------------
    # Check 2: Prefetch/Amcache entry for deleted binary
    # -----------------------------------------------------------------------
    prefetch_findings = _extract_typed(disk_findings, finding_type_contains="prefetch")
    amcache_findings = _extract_typed(disk_findings, finding_type_contains="amcache")
    execution_findings = prefetch_findings + amcache_findings

    deleted_file_findings = _extract_typed(disk_findings, finding_type_contains="deleted")
    deleted_names = _collect_deleted_file_names(deleted_file_findings)

    for exec_finding in execution_findings:
        exec_name = _extract_indicator(
            exec_finding.get("supporting_indicators", []), "executable:"
        )
        if not exec_name:
            desc = exec_finding.get("description", "")
            exec_name = _exe_from_description(desc)

        if exec_name:
            base_name = os.path.basename(exec_name).lower()
            if base_name in deleted_names:
                # Find matching deleted file finding
                del_fid = _find_deleted_match(deleted_file_findings, base_name)
                alert = _make_discrepancy(
                    discrepancy_type="execution_evidence_deleted_binary",
                    severity="HIGH",
                    description=(
                        f"Disk execution evidence (Prefetch/Amcache) exists for "
                        f"'{exec_name}', but this binary appears in the deleted-file "
                        f"list. This indicates the attacker executed the tool and then "
                        f"deleted it as an anti-forensics measure. The binary may still "
                        f"be resident in memory."
                    ),
                    disk_finding_id=exec_finding.get("finding_id"),
                    memory_finding_id=None,
                    recommended_action=(
                        "Call scan_memory() to check if the binary is still loaded in "
                        "memory. Call query_timeline() around the deletion timestamp to "
                        "establish the cleanup timeline."
                    ),
                    disk_evidence={
                        "executable": exec_name,
                        "exec_finding_id": exec_finding.get("finding_id"),
                        "deleted_finding_id": del_fid,
                    },
                    memory_evidence=None,
                )
                discrepancies.append(alert)
                _add_contradiction(exec_finding.get("finding_id"), "correlation:execution_evidence_deleted_binary")
                if del_fid:
                    _add_contradiction(del_fid, "correlation:execution_evidence_deleted_binary")
            else:
                confirmed_consistencies += 1

    # -----------------------------------------------------------------------
    # Check 3: VAD anomaly on legitimate-path process
    # -----------------------------------------------------------------------
    injection_findings = _extract_typed(memory_findings, finding_type_contains="injection")

    for inj_finding in injection_findings:
        proc_path = _extract_indicator(
            inj_finding.get("supporting_indicators", []), "process_path:"
        )
        if not proc_path:
            proc_path = _path_from_description(inj_finding.get("description", ""))

        if proc_path and _is_legitimate_path(proc_path):
            alert = _make_discrepancy(
                discrepancy_type="injection_legitimate_path",
                severity="HIGH",
                description=(
                    f"VAD injection indicator detected in a process whose executable "
                    f"path '{proc_path}' is a legitimate Windows system location "
                    f"(System32, Program Files, etc.). Process injection specifically "
                    f"targets legitimate processes to evade detection. This is a "
                    f"high-confidence indicator of process hollowing or DLL injection."
                ),
                memory_finding_id=inj_finding.get("finding_id"),
                disk_finding_id=None,
                recommended_action=(
                    "Call list_dlls() for this PID to identify unexpected DLLs. "
                    "Call scan_memory() with Cobalt Strike / Meterpreter YARA rules. "
                    "Verify the process binary hash against known-good baselines."
                ),
                disk_evidence=None,
                memory_evidence={
                    "process_path": proc_path,
                    "injection_finding_id": inj_finding.get("finding_id"),
                },
            )
            discrepancies.append(alert)
            _add_contradiction(inj_finding.get("finding_id"), "correlation:injection_legitimate_path")
        elif proc_path:
            confirmed_consistencies += 1

    # -----------------------------------------------------------------------
    # Check 4: Network connection with no disk artefact
    # -----------------------------------------------------------------------
    network_findings = _extract_typed(memory_findings, finding_type_contains="network")
    disk_process_names = _collect_disk_process_names(disk_findings)

    for net_finding in network_findings:
        owner = _extract_indicator(
            net_finding.get("supporting_indicators", []), "owner_process:"
        )
        if not owner:
            owner = _owner_from_description(net_finding.get("description", ""))

        if owner:
            owner_base = os.path.basename(owner).lower()
            if owner_base not in disk_process_names:
                alert = _make_discrepancy(
                    discrepancy_type="network_no_disk_evidence",
                    severity="MEDIUM",
                    description=(
                        f"Network connection found in memory belonging to process "
                        f"'{owner}', but no disk execution evidence (Prefetch, "
                        f"Amcache, or MFT entry) exists for this binary. This may "
                        f"indicate fileless PowerShell/WMI execution, injected "
                        f"shellcode, or a binary that was deleted after loading."
                    ),
                    memory_finding_id=net_finding.get("finding_id"),
                    disk_finding_id=None,
                    recommended_action=(
                        "Call detect_injection() for the owning PID. "
                        "Call query_timeline() around the connection timestamp "
                        "to find related file system activity."
                    ),
                    disk_evidence=None,
                    memory_evidence={
                        "owner_process": owner,
                        "network_finding_id": net_finding.get("finding_id"),
                    },
                )
                discrepancies.append(alert)
                _add_contradiction(net_finding.get("finding_id"), "correlation:network_no_disk_evidence")
            else:
                confirmed_consistencies += 1

    # -----------------------------------------------------------------------
    # Check 5: Registry persistence for missing binary
    # -----------------------------------------------------------------------
    registry_findings = _extract_typed(disk_findings, finding_type_contains="persistence")
    disk_path_set = _collect_disk_paths(disk_findings)

    for reg_finding in registry_findings:
        reg_path = _extract_indicator(
            reg_finding.get("supporting_indicators", []), "value_data:"
        )
        if not reg_path:
            reg_path = _path_from_description(reg_finding.get("description", ""))

        if reg_path:
            # Strip CLI arguments — take only the binary path portion
            binary_part = reg_path.split('"')[1] if reg_path.startswith('"') else reg_path.split()[0]
            norm_binary = binary_part.lower().replace("\\", "/")
            if not _path_in_set(norm_binary, disk_path_set):
                alert = _make_discrepancy(
                    discrepancy_type="persistence_missing_binary",
                    severity="HIGH",
                    description=(
                        f"Registry persistence key points to binary '{binary_part}', "
                        f"but this path does not exist in any disk artefact. This "
                        f"proves the system was compromised and achieved persistence. "
                        f"The binary was either deleted by the attacker or remediated "
                        f"by AV before evidence collection."
                    ),
                    disk_finding_id=reg_finding.get("finding_id"),
                    memory_finding_id=None,
                    recommended_action=(
                        "Call get_amcache() to check if the binary was ever executed "
                        "(hash may still be present). Call query_timeline() to "
                        "determine when the binary was deleted."
                    ),
                    disk_evidence={
                        "binary_path": binary_part,
                        "registry_finding_id": reg_finding.get("finding_id"),
                    },
                    memory_evidence=None,
                )
                discrepancies.append(alert)
                _add_contradiction(reg_finding.get("finding_id"), "correlation:persistence_missing_binary")
            else:
                confirmed_consistencies += 1

    # -----------------------------------------------------------------------
    # Check 6: Timestomping detection (SI vs FN timestamp mismatch)
    # -----------------------------------------------------------------------
    mft_findings = _extract_typed(disk_findings, finding_type_contains="mft")

    for mft_finding in mft_findings:
        indicators = mft_finding.get("supporting_indicators", [])
        si_created = _extract_timestamp_indicator(indicators, "si_created:")
        fn_created = _extract_timestamp_indicator(indicators, "fn_created:")

        if si_created and fn_created:
            diff = abs(fn_created - si_created)
            if diff > _TIMESTOMP_THRESHOLD:
                file_path = _extract_indicator(indicators, "file_path:") or "unknown"
                alert = _make_discrepancy(
                    discrepancy_type="timestomping_detected",
                    severity="HIGH",
                    description=(
                        f"Timestomping detected on '{file_path}': "
                        f"$STANDARD_INFORMATION Created ({si_created.isoformat()}) "
                        f"differs from $FILE_NAME Created ({fn_created.isoformat()}) "
                        f"by {diff}. SI timestamps can be modified by user-level APIs "
                        f"but FN timestamps require kernel access. This file's "
                        f"apparent creation time was falsified."
                    ),
                    disk_finding_id=mft_finding.get("finding_id"),
                    memory_finding_id=None,
                    recommended_action=(
                        "Call get_amcache() to check the PE link date (compilation "
                        "timestamp) for this binary. Call extract_prefetch() to "
                        "find the actual first-execution time."
                    ),
                    disk_evidence={
                        "file_path": file_path,
                        "si_created": si_created.isoformat(),
                        "fn_created": fn_created.isoformat(),
                        "diff_hours": round(diff.total_seconds() / 3600, 2),
                    },
                    memory_evidence=None,
                )
                discrepancies.append(alert)
                _add_contradiction(mft_finding.get("finding_id"), "correlation:timestomping_detected")
            else:
                confirmed_consistencies += 1

    # -----------------------------------------------------------------------
    # Build summary
    # -----------------------------------------------------------------------
    checked_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    n = len(discrepancies)
    total_checks = (
        len(process_records) + len(execution_findings) + len(injection_findings)
        + len(network_findings) + len(registry_findings) + len(mft_findings)
    )

    if n == 0:
        summary = (
            f"No cross-artifact discrepancies found. "
            f"Examined {len(disk_findings)} disk and {len(memory_findings)} memory findings "
            f"across 6 correlation checks ({confirmed_consistencies} consistent pairs)."
        )
    else:
        severity_counts: dict[str, int] = {}
        for d in discrepancies:
            severity_counts[d["severity"]] = severity_counts.get(d["severity"], 0) + 1
        sev_str = ", ".join(f"{v} {k}" for k, v in severity_counts.items())
        summary = (
            f"{n} discrepanc{'y' if n == 1 else 'ies'} found ({sev_str}) "
            f"across {total_checks} total correlation checks. "
            f"Examined {len(disk_findings)} disk and {len(memory_findings)} memory findings. "
            f"{confirmed_consistencies} cross-artifact pairs are consistent."
        )

    return {
        "status": "ok",
        "case_id": case_id,
        "discrepancies": discrepancies,
        "discrepancy_count": n,
        "disk_findings_count": len(disk_findings),
        "memory_findings_count": len(memory_findings),
        "confirmed_consistencies": confirmed_consistencies,
        "checked_at": checked_at,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Tool 2: flag_discrepancy
# ---------------------------------------------------------------------------


def flag_discrepancy(
    finding_id_a: str,
    finding_id_b: str,
    reason: str,
) -> dict[str, Any]:
    """Manually flag a discrepancy between two findings.

    Creates a :class:`DiscrepancyAlert`-shaped dict and updates both
    findings' ``contradicted_by`` lists in the case state.  Use this when
    the agent identifies a contradiction that the automated correlation
    engine did not catch.

    Parameters
    ----------
    finding_id_a:
        F-NNN ID of the first finding involved.
    finding_id_b:
        F-NNN ID of the second finding involved.
    reason:
        Human-readable explanation of why these findings contradict each
        other (e.g. ``"Process PID 1832 in pslist but binary hash not in "
        "Amcache — likely injected shellcode"``).

    Returns
    -------
    dict
        On success::

            {
              "status": "ok",
              "discrepancy": {
                "discrepancy_type": "manual_flag",
                "severity": "MEDIUM",
                "description": "<reason>",
                "disk_finding_id": "F-001",
                "memory_finding_id": "F-002",
                "recommended_action": "Investigate the contradiction between F-001 and F-002.",
                "disk_evidence": null,
                "memory_evidence": null
              },
              "finding_a": {...},
              "finding_b": {...}
            }

        On error::

            {
              "status": "error",
              "error": "..."
            }
    """
    if _state_mgr is None:
        return {"status": "error", "error": "Tool module not initialised — call init_tools() first."}

    # Retrieve both findings
    finding_a = _state_mgr.get_finding(finding_id_a)
    finding_b = _state_mgr.get_finding(finding_id_b)

    if finding_a is None:
        return {"status": "error", "error": f"Finding {finding_id_a!r} not found in case state."}
    if finding_b is None:
        return {"status": "error", "error": f"Finding {finding_id_b!r} not found in case state."}

    # Update contradicted_by on both findings
    try:
        contradicted_a = list(finding_a.get("contradicted_by") or [])
        if finding_id_b not in contradicted_a:
            contradicted_a.append(finding_id_b)
            _state_mgr.update_finding(finding_id_a, contradicted_by=contradicted_a)

        contradicted_b = list(finding_b.get("contradicted_by") or [])
        if finding_id_a not in contradicted_b:
            contradicted_b.append(finding_id_a)
            _state_mgr.update_finding(finding_id_b, contradicted_by=contradicted_b)
    except Exception as exc:
        return {"status": "error", "error": f"Failed to update findings: {exc}"}

    # Determine which side is disk and which is memory
    art_a = (finding_a.get("artifact_type") or "").lower()
    art_b = (finding_b.get("artifact_type") or "").lower()

    disk_fid = finding_id_a if art_a == "disk" else (finding_id_b if art_b == "disk" else None)
    mem_fid = finding_id_a if art_a == "memory" else (finding_id_b if art_b == "memory" else None)

    discrepancy = _make_discrepancy(
        discrepancy_type="process_no_disk_binary",  # Closest built-in type for manual flags
        severity="MEDIUM",
        description=reason,
        disk_finding_id=disk_fid,
        memory_finding_id=mem_fid,
        recommended_action=(
            f"Investigate the contradiction between {finding_id_a} and "
            f"{finding_id_b}. Consider calling compare_disk_and_memory() "
            f"for a full automated correlation pass."
        ),
        disk_evidence=None,
        memory_evidence=None,
    )

    # Re-fetch updated findings
    updated_a = _state_mgr.get_finding(finding_id_a) or finding_a
    updated_b = _state_mgr.get_finding(finding_id_b) or finding_b

    return {
        "status": "ok",
        "discrepancy": discrepancy,
        "finding_a": updated_a,
        "finding_b": updated_b,
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _make_discrepancy(
    discrepancy_type: str,
    severity: str,
    description: str,
    disk_finding_id: Optional[str],
    memory_finding_id: Optional[str],
    recommended_action: str,
    disk_evidence: Optional[dict[str, Any]],
    memory_evidence: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Construct a DiscrepancyAlert-shaped dict."""
    return {
        "discrepancy_type": discrepancy_type,
        "severity": severity,
        "description": description,
        "disk_finding_id": disk_finding_id,
        "memory_finding_id": memory_finding_id,
        "recommended_action": recommended_action,
        "disk_evidence": disk_evidence,
        "memory_evidence": memory_evidence,
    }


def _extract_typed(
    findings: list[dict[str, Any]],
    finding_type_contains: str,
) -> list[dict[str, Any]]:
    """Filter findings whose ``finding_type`` contains *finding_type_contains*."""
    token = finding_type_contains.lower()
    return [
        f for f in findings
        if token in (f.get("finding_type") or "").lower()
        or token in (f.get("artifact_type") or "").lower()
        or token in (f.get("description") or "").lower()
    ]


def _extract_indicator(indicators: list, prefix: str) -> Optional[str]:
    """Return the value of the first indicator that starts with *prefix*."""
    for ind in indicators:
        s = str(ind)
        if s.lower().startswith(prefix.lower()):
            return s[len(prefix):].strip()
    return None


def _extract_timestamp_indicator(
    indicators: list,
    prefix: str,
) -> Optional[datetime]:
    """Extract and parse a timestamp indicator value."""
    raw = _extract_indicator(indicators, prefix)
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S+00:00"):
        try:
            dt = datetime.strptime(raw[:19], fmt[:len(fmt)])
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _collect_disk_paths(disk_findings: list[dict[str, Any]]) -> set[str]:
    """Collect all normalised file paths mentioned in disk findings."""
    paths: set[str] = set()
    for finding in disk_findings:
        for ind in finding.get("supporting_indicators", []):
            s = str(ind)
            if s.startswith("/") or (len(s) > 1 and s[1] == ":"):
                paths.add(s.lower().replace("\\", "/"))
        # Also check artifact_path
        ap = finding.get("artifact_path", "")
        if ap:
            paths.add(ap.lower().replace("\\", "/"))
    return paths


def _collect_disk_process_names(disk_findings: list[dict[str, Any]]) -> set[str]:
    """Collect all executable basenames from disk execution artefacts."""
    names: set[str] = set()
    for finding in disk_findings:
        for ind in finding.get("supporting_indicators", []):
            s = str(ind)
            if s.lower().startswith("executable:"):
                val = s[11:].strip()
                names.add(os.path.basename(val).lower())
        # Also check executable hints in description
        desc = finding.get("description", "")
        exe = _exe_from_description(desc)
        if exe:
            names.add(os.path.basename(exe).lower())
    return names


def _collect_deleted_file_names(
    deleted_findings: list[dict[str, Any]],
) -> set[str]:
    """Collect lowercased basenames of deleted files."""
    names: set[str] = set()
    for finding in deleted_findings:
        for ind in finding.get("supporting_indicators", []):
            s = str(ind)
            if s.startswith("/") or ":\\" in s or s.lower().startswith("file_path:"):
                path = s[10:].strip() if s.lower().startswith("file_path:") else s
                names.add(os.path.basename(path).lower())
    return names


def _find_deleted_match(
    deleted_findings: list[dict[str, Any]],
    base_name: str,
) -> Optional[str]:
    """Return the finding_id of the first deleted file whose name matches."""
    for finding in deleted_findings:
        for ind in finding.get("supporting_indicators", []):
            s = str(ind)
            if os.path.basename(s).lower() == base_name:
                return finding.get("finding_id")
    return None


def _path_in_set(norm_path: str, path_set: set[str]) -> bool:
    """Check whether *norm_path* or its basename appears in *path_set*."""
    if norm_path in path_set:
        return True
    base = os.path.basename(norm_path)
    return any(base == os.path.basename(p) for p in path_set)


def _is_legitimate_path(path: str) -> bool:
    """Return True if *path* starts with a known Windows system directory."""
    norm = path.lower().replace("\\", "/")
    return any(norm.startswith(lp.replace("\\", "/")) for lp in _LEGITIMATE_PATHS)


def _path_from_description(desc: str) -> Optional[str]:
    """Heuristically extract a Windows/Unix file path from a description string."""
    import re
    # Match Windows paths like C:\Windows\... or Unix paths /usr/...
    m = re.search(r"([A-Za-z]:\\[^\s'\"]+|/[^\s'\"]+\.[a-z]{2,4})", desc)
    return m.group(1) if m else None


def _exe_from_description(desc: str) -> Optional[str]:
    """Heuristically extract an executable name from a description string."""
    import re
    m = re.search(r"([A-Za-z0-9_.-]+\.(?:exe|dll|bat|ps1|vbs|com))", desc, re.IGNORECASE)
    return m.group(1) if m else None


def _owner_from_description(desc: str) -> Optional[str]:
    """Extract owning process name from a network finding description."""
    import re
    # Matches patterns like "owned by svchost.exe" or "process: svchost.exe (PID 1832)"
    m = re.search(
        r"(?:owned by|process:|owner:)\s*([A-Za-z0-9_.-]+\.(?:exe|dll))",
        desc,
        re.IGNORECASE,
    )
    return m.group(1) if m else None


def _add_contradiction(finding_id: Optional[str], source: str) -> None:
    """Update a finding's contradicted_by list with *source* (best-effort)."""
    if not finding_id or _state_mgr is None:
        return
    try:
        finding = _state_mgr.get_finding(finding_id)
        if finding is None:
            return
        contradicted_by = list(finding.get("contradicted_by") or [])
        if source not in contradicted_by:
            contradicted_by.append(source)
            _state_mgr.update_finding(finding_id, contradicted_by=contradicted_by)
    except Exception:
        pass  # Best-effort; never let contradictions block the report
