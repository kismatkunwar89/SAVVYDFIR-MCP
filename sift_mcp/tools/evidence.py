"""
sift_mcp.tools.evidence
~~~~~~~~~~~~~~~~~~~~~~~

Evidence integrity and provenance tools for SAVVYDFIR-MCP.

Tools
-----
- ``verify_integrity`` - Verifies hash integrity of an evidence image by running
  ``ewfverify`` (for EWF/E01 images) via SleuthKitRunner.  Returns a structured
  :class:`~sift_mcp.models.artifacts.IntegrityResult` dict.

- ``get_provenance`` - Retrieves the full execution chain for a finding ID from
  ``audit.jsonl`` via :meth:`~sift_mcp.audit.AuditLogger.get_execution_chain`.
  Useful for establishing chain-of-custody documentation.

Design pattern
--------------
Module-level ``_runner``, ``_state``, and ``_audit`` singletons are set by
calling :func:`init_tools` at server startup.  Each tool function validates
its inputs, delegates to the runner, parses the output into Pydantic models,
creates :class:`~sift_mcp.models.finding.Finding` records in state, and
returns a plain ``dict`` (not a Pydantic object) so FastMCP can serialise it.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from sift_mcp.models.artifacts import IntegrityResult
from sift_mcp.models.finding import EvidenceKind, Finding, FindingStatus

if TYPE_CHECKING:
    from sift_mcp.audit import AuditLogger
    from sift_mcp.runners.sleuthkit import SleuthKitRunner
    from sift_mcp.state import CaseStateManager


__all__ = [
    "init_tools",
    "verify_integrity",
    "get_provenance",
]


# ---------------------------------------------------------------------------
# Module-level singletons - set via init_tools()
# ---------------------------------------------------------------------------

_runner: Optional["SleuthKitRunner"] = None
_state: Optional["CaseStateManager"] = None
_audit: Optional["AuditLogger"] = None


def init_tools(
    state_manager: "CaseStateManager",
    audit_logger: "AuditLogger",
    runner: Optional["SleuthKitRunner"] = None,
) -> None:
    """Inject dependencies into this module's singleton slots.

    Must be called once at MCP server startup before any tool function is
    invoked.

    Parameters
    ----------
    state_manager:
        The initialised :class:`~sift_mcp.state.CaseStateManager` for this
        case.
    audit_logger:
        The :class:`~sift_mcp.audit.AuditLogger` for this case.
    runner:
        Optional pre-built :class:`~sift_mcp.runners.sleuthkit.SleuthKitRunner`.
        When ``None`` a new runner is created with the supplied audit_logger.
    """
    global _runner, _state, _audit
    _state = state_manager
    _audit = audit_logger
    if runner is not None:
        _runner = runner
    else:
        from sift_mcp.runners.sleuthkit import SleuthKitRunner
        _runner = SleuthKitRunner(
            audit_logger=audit_logger,
            state_manager=state_manager,
        )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_HASH_RE = re.compile(
    r"(?:md5|sha[-_ ]?1|sha[-_ ]?256)\s*[:\s=]+\s*([0-9a-fA-F]{32,64})",
    re.IGNORECASE,
)

_STORED_RE = re.compile(
    r"(?:stored|expected|calculated|acquisition)\s*(?:md5|sha[-_ ]?1|sha[-_ ]?256)?\s*[:\s=]+\s*([0-9a-fA-F]{32,64})",
    re.IGNORECASE,
)

_COMPUTED_RE = re.compile(
    r"(?:calculated|computed|verification|media)\s*(?:md5|sha[-_ ]?1|sha[-_ ]?256)?\s*[:\s=]+\s*([0-9a-fA-F]{32,64})",
    re.IGNORECASE,
)

_VERIFIED_RE = re.compile(
    r"ewfverify:\s*(verification|integrity)\s*passed",
    re.IGNORECASE,
)

_FAILED_RE = re.compile(
    r"ewfverify:\s*(verification|integrity|checksum)\s*(failed|mismatch)",
    re.IGNORECASE,
)


def _parse_ewfverify_output(
    stdout: str, image_path: str, exit_code: int
) -> IntegrityResult:
    """Parse ``ewfverify`` stdout into an :class:`IntegrityResult`.

    ``ewfverify`` output format varies slightly across libewf versions but
    always contains lines like::

        MD5 hash stored in file:    d41d8cd98f00b204e9800998ecf8427e
        MD5 hash calculated over data: d41d8cd98f00b204e9800998ecf8427e

    Or (newer versions)::

        ewfverify: MD5 hash verification passed.

    Parameters
    ----------
    stdout:
        Full stdout from the ``ewfverify`` process.
    image_path:
        Absolute path to the image file (recorded verbatim in the result).
    exit_code:
        Process exit code - 0 means verified OK, non-zero means mismatch or
        error.

    Returns
    -------
    IntegrityResult
        Parsed result.  If hashes cannot be extracted from the output, the
        ``computed_hash`` field is set to ``"<unparseable>"`` and ``verified``
        reflects the exit code.
    """
    stored_hash: Optional[str] = None
    computed_hash: str = "<unparseable>"
    algorithm: str = "md5"

    # Determine algorithm from output
    if re.search(r"sha[-_ ]?256", stdout, re.IGNORECASE):
        algorithm = "sha256"
    elif re.search(r"sha[-_ ]?1", stdout, re.IGNORECASE):
        algorithm = "sha1"
    else:
        algorithm = "md5"

    # Look for stored (acquisition) hash
    for line in stdout.splitlines():
        line_l = line.lower()

        # Stored / acquisition hash
        if any(k in line_l for k in ("stored in file", "acquisition", "expected")):
            m = _HASH_RE.search(line)
            if m:
                stored_hash = m.group(1).lower()

        # Computed / verification hash
        if any(k in line_l for k in ("calculated over", "computed", "verification hash", "media")):
            m = _HASH_RE.search(line)
            if m:
                computed_hash = m.group(1).lower()

    # If we still haven't found a computed hash, try any hash on the last
    # non-empty line (some versions print a single summary line)
    if computed_hash == "<unparseable>":
        hashes = _HASH_RE.findall(stdout)
        if hashes:
            computed_hash = hashes[-1].lower()
            if stored_hash is None and len(hashes) >= 2:
                stored_hash = hashes[0].lower()

    # Determine verified status
    if exit_code == 0:
        verified = True
    elif _VERIFIED_RE.search(stdout):
        verified = True
    else:
        verified = not bool(_FAILED_RE.search(stdout)) and exit_code == 0

    # If stored matches computed we know it's verified regardless of exit code
    if stored_hash and computed_hash != "<unparseable>":
        verified = stored_hash == computed_hash

    return IntegrityResult(
        image_path=image_path,
        stored_hash=stored_hash,
        computed_hash=computed_hash,
        algorithm=algorithm,  # type: ignore[arg-type]
        verified=verified,
        verification_time=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Tool: verify_integrity
# ---------------------------------------------------------------------------


def verify_integrity(image_path: str) -> dict[str, Any]:
    """Verify the cryptographic integrity of an evidence image.

    Wraps ``ewfverify`` (from **libewf-tools**, available on SIFT Workstation)
    to confirm that the stored acquisition hash in an EnCase/EWF ``.E01``
    image still matches a freshly computed hash over the image data.

    For non-EWF images (raw ``.dd``, ``.raw``) the runner will fall back to
    ``sha256sum`` if ``ewfverify`` reports an unsupported format.

    Forensic significance
    ----------------------
    This tool MUST be the first call in any investigation.  A mismatch means
    the evidence may have been modified after acquisition, which invalidates
    the chain of custody.

    Parameters
    ----------
    image_path:
        Absolute path to the evidence image file.  For split EWF images pass
        only the first segment (``disk.E01``).

    Returns
    -------
    dict
        Keys:

        ``tool_name``       - ``"evidence.verify_integrity"``
        ``status``          - ``"success"`` or ``"error"``
        ``data``            - List containing a single :class:`IntegrityResult`
                              dict (or empty on error).
        ``findings_created`` - List of F-NNN finding IDs created.
        ``execution_id``    - E-NNN audit trail ID.
        ``raw_command``     - The command that was executed.
        ``verified``        - Top-level bool for quick inspection.
        ``error_message``   - Present only when ``status == "error"``.
        ``stderr``          - Present only when ``status == "error"``.
    """
    tool = "evidence.verify_integrity"
    if _runner is None or _state is None or _audit is None:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "Tools not initialised. Call init_tools() first.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    if not image_path or not image_path.strip():
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": "image_path must be a non-empty string.",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": None,
        }

    try:
        result = _runner.ewfverify(image_path=image_path, tool_name=tool)
    except Exception as exc:
        return {
            "tool_name": tool,
            "status": "error",
            "error_message": f"Runner error: {exc}",
            "data": [],
            "findings_created": [],
            "execution_id": None,
            "raw_command": str(exc),
        }

    # Parse output into IntegrityResult
    integrity = _parse_ewfverify_output(
        stdout=result.stdout,
        image_path=image_path,
        exit_code=result.exit_code,
    )

    # Determine finding type and description
    # Fix: CTF/training images often have no stored acquisition hash.
    # In that case return a neutral UNVERIFIABLE result, not a false COMPROMISED finding.
    no_stored_hash = not integrity.stored_hash or integrity.stored_hash in (
        "N/A", "<unparseable>", "none", "")

    if integrity.verified:
        finding_type = "other"
        description = (
            f"Image integrity verified: {image_path}. "
            f"Computed {integrity.algorithm.upper()} hash {integrity.computed_hash} "
            f"matches stored hash {integrity.stored_hash}. "
            "Evidence chain-of-custody is intact."
        )
        confidence = 0.99
    elif no_stored_hash:
        # No acquisition hash in image - cannot verify, but not a failure
        finding_type = "other"
        description = (
            f"Image integrity unverifiable for {image_path}. "
            f"No stored acquisition hash present in image metadata. "
            f"Computed {integrity.algorithm.upper()} hash: {integrity.computed_hash}. "
            "This is normal for training/CTF images. Proceed with investigation."
        )
        confidence = 0.5
    else:
        finding_type = "defense_evasion"
        description = (
            f"Image integrity FAILED for {image_path}. "
            f"Stored hash: {integrity.stored_hash}, "
            f"Computed hash: {integrity.computed_hash}. "
            "The evidence image may have been modified after acquisition."
        )
        confidence = 0.99

    # Build and store finding
    finding = Finding(
        case_id=_state.case_id,
        finding_type=finding_type,
        artifact_type="disk",
        artifact_path=image_path,
        tool_name=tool,
        execution_id=result.execution_id,
        iteration=_audit.current_iteration,
        evidence_kind=EvidenceKind.OBSERVATION,
        finding_status=FindingStatus.ACTIVE,
        confidence=confidence,
        description=description,
        supporting_indicators=[
            f"computed_hash={integrity.computed_hash}",
            f"stored_hash={integrity.stored_hash or 'none'}",
            f"algorithm={integrity.algorithm}",
            f"verified={integrity.verified}",
        ],
    )

    finding_id = _state.add_finding(finding.model_dump(mode="json"))

    return {
        "tool_name": "evidence.verify_integrity",
        "status": "success",
        "data": [integrity.model_dump(mode="json")],
        "findings_created": [finding_id],
        "execution_id": result.execution_id,
        "raw_command": result.command_line,
        "verified": integrity.verified,
    }


# ---------------------------------------------------------------------------
# Tool: get_provenance
# ---------------------------------------------------------------------------


def get_provenance(finding_id: str) -> dict[str, Any]:
    """Retrieve the full execution chain for a finding.

    Reads ``audit.jsonl`` to find every tool invocation that contributed to
    producing the specified finding.  The execution chain enables a human
    reviewer to independently verify every step of the analysis.

    Chain-of-custody interpretation
    --------------------------------
    The returned chain contains both ``started`` and ``completed`` entries.
    If a ``started`` entry exists without a matching ``completed`` entry, the
    execution was interrupted (server crash or timeout).

    Parameters
    ----------
    finding_id:
        A finding ID in ``F-NNN`` format (e.g. ``"F-003"``).

    Returns
    -------
    dict
        Keys:

        ``tool_name``      - ``"evidence.get_provenance"``
        ``status``         - ``"success"`` or ``"error"``
        ``finding_id``     - The queried finding ID.
        ``execution_chain`` - List of audit entry dicts from ``audit.jsonl``.
        ``chain_length``   - Number of entries in the chain.
        ``error_message``  - Present only when ``status == "error"``.
    """
    if _audit is None:
        return {
            "tool_name": "evidence.get_provenance",
            "status": "error",
            "error_message": "Tools not initialised. Call init_tools() first.",
            "finding_id": finding_id,
            "execution_chain": [],
            "chain_length": 0,
        }

    if not finding_id or not re.match(r"^F-\d{3,}$", finding_id):
        return {
            "tool_name": "evidence.get_provenance",
            "status": "error",
            "error_message": (
                f"Invalid finding_id {finding_id!r}. "
                "Must be in F-NNN format (e.g. 'F-001')."
            ),
            "finding_id": finding_id,
            "execution_chain": [],
            "chain_length": 0,
        }

    finding_detail: Optional[dict[str, Any]] = None
    if _state is not None:
        try:
            finding_detail = _state.get_finding(finding_id)
        except Exception:
            pass  # Non-fatal; omit finding detail

    try:
        chain = _audit.get_execution_chain(finding_id)
    except FileNotFoundError:
        if finding_detail is None:
            return {
                "tool_name": "evidence.get_provenance",
                "status": "error",
                "error_message": (
                    f"Audit log not found: {_audit.output_path}. "
                    "Has any tool been executed yet?"
                ),
                "finding_id": finding_id,
                "execution_chain": [],
                "chain_length": 0,
            }
        chain = []
    except Exception as exc:
        return {
            "tool_name": "evidence.get_provenance",
            "status": "error",
            "error_message": f"Failed to read audit log: {exc}",
            "finding_id": finding_id,
            "execution_chain": [],
            "chain_length": 0,
        }

    legacy_unsealed = False
    if not chain:
        legacy_unsealed = finding_detail is not None
    else:
        legacy_unsealed = any(not entry.get("entry_hash") for entry in chain)

    return {
        "tool_name": "evidence.get_provenance",
        "status": "success",
        "finding_id": finding_id,
        "execution_chain": chain,
        "chain_length": len(chain),
        "finding_detail": finding_detail,
        "legacy_unsealed": legacy_unsealed,
    }
