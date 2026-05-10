"""
sigma.py — Universal anomaly detection and analysis models for SAVVYDFIR-MCP.

These models are case-agnostic: they describe universal forensic patterns
(e.g. orphan processes, RFC1918 exclusion, SI<FN timestomping) without
referencing any specific IPs, usernames, or filenames.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class ArtifactHit(BaseModel):
    """A single anomalous artifact detected by sigma_scan().

    Attributes:
        detector:       Which anomaly detector fired.
        severity:       Forensic severity of this hit.
        description:    Human-readable explanation of the anomaly.
        artifact_type:  The broad evidence domain.
        artifact_path:  Path to the source evidence.
        raw_data:       The raw record that triggered the detection.
        mitre_technique: ATT&CK technique ID if applicable.
        mitre_tactic:   ATT&CK tactic ID if applicable.
        pivot_suggestion: Recommended next investigation step.
    """

    detector: str = Field(
        ..., description="Anomaly detector that produced this hit."
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(
        ..., description="Forensic severity."
    )
    description: str = Field(
        ..., min_length=10, description="Human-readable anomaly description."
    )
    artifact_type: Literal["process", "network", "mft", "evtx", "persistence", "yara"] = Field(
        ..., description="Evidence domain."
    )
    artifact_path: Optional[str] = Field(
        None, description="Path to the source evidence file."
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict, description="Raw record that triggered detection."
    )
    mitre_technique: Optional[str] = Field(
        None, description="ATT&CK technique ID, e.g. 'T1055.001'."
    )
    mitre_tactic: Optional[str] = Field(
        None, description="ATT&CK tactic ID, e.g. 'TA0005'."
    )
    pivot_suggestion: Optional[str] = Field(
        None, description="Recommended next investigation step."
    )
    next_pivot: Optional[dict[str, Any]] = Field(
        None,
        description="Structured recommended next pivot: {tool, args, human_readable}.",
    )


class ToolResult(BaseModel):
    """Universal wrapper returned by every MCP tool.

    Attributes:
        status:         'ok' or 'error'.
        tool:           MCP tool name that produced this result.
        execution_id:   E-NNN audit trail reference.
        message:        Human-readable summary.
        data:           Tool-specific structured output.
        error:          Error message if status == 'error'.
        duration_seconds: Wall-clock execution time.
    """

    status: Literal["ok", "error"] = Field(
        ..., description="Result status: 'ok' or 'error'."
    )
    tool: str = Field(
        ..., description="MCP tool name that produced this result."
    )
    execution_id: Optional[str] = Field(
        None, description="E-NNN audit trail reference."
    )
    message: str = Field(
        default="", description="Human-readable summary."
    )
    data: dict[str, Any] = Field(
        default_factory=dict, description="Tool-specific structured output."
    )
    error: Optional[str] = Field(
        None, description="Error message if status is 'error'."
    )
    duration_seconds: Optional[float] = Field(
        None, description="Wall-clock execution time in seconds."
    )


class SigmaScanResult(BaseModel):
    """Output of sigma_scan() — universal anomaly detection across all artifacts.

    Attributes:
        case_id:            Parent case identifier.
        hits:               List of ArtifactHit records.
        total_hits:         Total anomaly count.
        critical_count:     CRITICAL severity hits.
        high_count:         HIGH severity hits.
        detectors_run:      List of detector names that were executed.
        scanned_at:         UTC timestamp of scan completion.
        summary_markdown:   Pre-formatted markdown summary for agent consumption.
    """

    case_id: str = Field(..., description="Parent case identifier.")
    hits: list[ArtifactHit] = Field(
        default_factory=list, description="Anomalies detected."
    )
    total_hits: int = Field(default=0, ge=0, description="Total anomaly count.")
    critical_count: int = Field(default=0, ge=0, description="CRITICAL hits.")
    high_count: int = Field(default=0, ge=0, description="HIGH hits.")
    detectors_run: list[str] = Field(
        default_factory=list, description="Detector names that ran."
    )
    detector_warnings: list[dict[str, Any]] = Field(
        default_factory=list, description="Soft-fail, budget, or data-gap warnings."
    )
    detector_timings: dict[str, float] = Field(
        default_factory=dict, description="Wall-clock seconds per detector."
    )
    actionable_leads: list[dict[str, Any]] = Field(
        default_factory=list, description="Renderable leads derived from detector hits."
    )
    anti_forensics_warnings: list[dict[str, Any]] = Field(
        default_factory=list, description="Detected evidence-loss or anti-forensics warnings."
    )
    data_gaps: list[dict[str, Any]] = Field(
        default_factory=list, description="Artifact/data gaps discovered during detection."
    )
    scanned_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC scan completion time.",
    )
    summary_markdown: str = Field(
        default="", description="Pre-formatted markdown summary."
    )


class AnalysisResult(BaseModel):
    """Output of run_analysis() — Pandas-based data analysis.

    Attributes:
        query:          The analysis query that was executed.
        result_table:   Tabulated result string.
        row_count:      Number of rows in the result.
        columns:        Column names in the result.
        insights:       Auto-generated analytical insights.
        data_source:    Path to the input data file.
    """

    query: str = Field(..., description="Analysis query that was executed.")
    result_table: str = Field(
        default="", description="Tabulated result string."
    )
    row_count: int = Field(default=0, ge=0, description="Rows in result.")
    columns: list[str] = Field(
        default_factory=list, description="Column names."
    )
    insights: list[str] = Field(
        default_factory=list, description="Auto-generated analytical insights."
    )
    data_source: Optional[str] = Field(
        None, description="Path to the input data file."
    )
