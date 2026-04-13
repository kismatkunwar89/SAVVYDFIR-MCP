"""
case.py — Case-level data models for SAVVYDFIR-MCP.

Defines the authoritative representations of a forensic case:
  - DiskImage / MemoryDump: evidence-source descriptors
  - TimeWindow: optional investigative time-range filter
  - CaseManifest: the investigative brief handed to the agent
  - CaseState: the mutable, single-source-of-truth for a running investigation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal, Optional

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from sift_mcp.models.finding import Finding
    from sift_mcp.models.execution import Execution


# ---------------------------------------------------------------------------
# Evidence-source descriptors
# ---------------------------------------------------------------------------


class DiskImage(BaseModel):
    """Descriptor for a single acquired disk image.

    Attributes:
        path: Absolute filesystem path to the image file (E01, raw, dd, AFF).
        host: Hostname or asset-tag of the machine the image was acquired from.
        image_type: Acquisition format — determines which tools can parse it
                    (e.g. ewfmount for E01, loop-mount for raw/dd).
    """

    path: str = Field(..., description="Absolute path to the disk image file.")
    host: str = Field(
        ..., description="Hostname or asset tag of the source machine."
    )
    image_type: Literal["E01", "raw", "dd", "AFF"] = Field(
        ..., description="Acquisition format; governs mount strategy."
    )


class MemoryDump(BaseModel):
    """Descriptor for a single raw memory acquisition.

    Attributes:
        path: Absolute filesystem path to the memory dump file.
        host: Hostname or asset-tag of the machine the dump was acquired from.
        profile: Optional Volatility symbol table / profile string.  When
                 omitted the agent should run ``windows.info`` to determine it.
    """

    path: str = Field(..., description="Absolute path to the memory dump file.")
    host: str = Field(
        ..., description="Hostname or asset tag of the source machine."
    )
    profile: Optional[str] = Field(
        None,
        description=(
            "Volatility 3 symbol table or profile string "
            "(e.g. 'windows.Win10x64_19041').  Auto-detected when absent."
        ),
    )


# ---------------------------------------------------------------------------
# Time-window helper
# ---------------------------------------------------------------------------


class TimeWindow(BaseModel):
    """An inclusive UTC time range used to focus timeline queries.

    Attributes:
        start: Earliest event timestamp of interest (UTC).
        end:   Latest event timestamp of interest (UTC).
    """

    start: datetime = Field(..., description="Start of the investigative window (UTC).")
    end: datetime = Field(..., description="End of the investigative window (UTC).")


# ---------------------------------------------------------------------------
# Case manifest (the investigative brief)
# ---------------------------------------------------------------------------


class CaseManifest(BaseModel):
    """Defines a forensic case for the autonomous agent to investigate.

    The manifest is immutable once a case is opened.  All mutable state lives
    in ``CaseState``.

    Attributes:
        case_id:            Unique identifier for the case (e.g. 'CASE-2026-001').
        disk_images:        List of disk image descriptors to analyse.
        memory_dumps:       List of memory dump descriptors to analyse.
        target_time_window: Optional UTC time range to focus the investigation.
        known_iocs:         Pre-known indicators of compromise (IPs, hashes,
                            domain names, file names) to seed the first pass.
        investigation_goal: Natural-language statement of the primary
                            investigative objective.
        max_iterations:     Maximum number of triage iterations the agent may
                            execute before stopping (1–10, default 4).
    """

    case_id: str = Field(
        ...,
        description="Unique case identifier, e.g. 'CASE-2026-001'.",
        min_length=1,
    )
    disk_images: list[DiskImage] = Field(
        default_factory=list,
        description="Disk image evidence sources to examine.",
    )
    memory_dumps: list[MemoryDump] = Field(
        default_factory=list,
        description="Memory dump evidence sources to examine.",
    )
    target_time_window: Optional[TimeWindow] = Field(
        None,
        description="UTC time range of interest; None means no restriction.",
    )
    known_iocs: list[str] = Field(
        default_factory=list,
        description=(
            "Pre-known indicators of compromise (IPs, hashes, hostnames, "
            "file names) that seed the first iteration."
        ),
    )
    investigation_goal: str = Field(
        ...,
        description=(
            "Natural-language statement of the primary investigative objective, "
            "e.g. 'Determine initial access vector and establish attacker dwell time'."
        ),
        min_length=10,
    )
    max_iterations: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Maximum triage iterations before the agent halts (1–10).",
    )


# ---------------------------------------------------------------------------
# Case state (mutable single source of truth)
# ---------------------------------------------------------------------------


class CaseState(BaseModel):
    """Authoritative, mutable state for a running or completed investigation.

    Written to ``<case_dir>/state.json`` after every tool execution.  The
    agent reads this file at the start of each iteration to resume correctly.

    Attributes:
        case_id:               Matches ``CaseManifest.case_id``.
        manifest:              The immutable investigative brief.
        status:                Lifecycle status of the investigation.
        findings:              All ``Finding`` records produced so far.
        executions:            All ``Execution`` records in chronological order.
        current_iteration:     Which triage iteration is currently running
                               (starts at 1).
        open_questions:        Agent-generated list of unresolved questions that
                               should drive the next iteration.
        started_at:            UTC timestamp when the investigation began.
        completed_at:          UTC timestamp when the investigation concluded
                               (None while in progress).
        integrity_hash_start:  SHA-256 of all evidence files at case-open time
                               (ensures no spoliation occurred mid-investigation).
        integrity_hash_end:    SHA-256 of all evidence files at case-close time.
    """

    case_id: str = Field(..., description="Matches CaseManifest.case_id.")
    manifest: CaseManifest = Field(..., description="The immutable investigative brief.")
    status: Literal["in_progress", "completed", "max_iterations_reached"] = Field(
        default="in_progress",
        description="Lifecycle status of the investigation.",
    )
    findings: list["Finding"] = Field(
        default_factory=list,
        description="All Finding records produced by the agent, in creation order.",
    )
    executions: list["Execution"] = Field(
        default_factory=list,
        description="All Execution records in chronological order.",
    )
    current_iteration: int = Field(
        default=1,
        ge=1,
        description="Which triage iteration is currently active (starts at 1).",
    )
    open_questions: list[str] = Field(
        default_factory=list,
        description=(
            "Agent-generated unresolved questions that guide the next iteration."
        ),
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when the investigation was opened.",
    )
    completed_at: Optional[datetime] = Field(
        None,
        description="UTC timestamp when the investigation concluded (None if ongoing).",
    )
    integrity_hash_start: Optional[str] = Field(
        None,
        description="SHA-256 digest of all evidence files at case-open time.",
    )
    integrity_hash_end: Optional[str] = Field(
        None,
        description="SHA-256 digest of all evidence files at case-close time.",
    )
