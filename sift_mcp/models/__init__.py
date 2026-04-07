"""
sift_mcp.models — Public model API for SAVVYDFIR-MCP.

Import any model directly from this package:

    from sift_mcp.models import (
        CaseManifest, CaseState, Finding, Execution, CorrelationReport, ...
    )
"""

# Case models
from sift_mcp.models.case import (
    CaseManifest,
    CaseState,
    DiskImage,
    MemoryDump,
    TimeWindow,
)

# Finding models
from sift_mcp.models.finding import (
    EvidenceKind,
    Finding,
    FindingStatus,
)

# Execution / correction models
from sift_mcp.models.execution import (
    CorrectionEvent,
    Execution,
)

# Artifact response models
from sift_mcp.models.artifacts import (
    AmcacheRecord,
    CorrelationReport,
    DeletedFile,
    DiscrepancyAlert,
    DllRecord,
    EventRecord,
    InjectionIndicator,
    IntegrityResult,
    MftEntry,
    NetworkArtifact,
    PrefetchRecord,
    ProcessRecord,
    ProfileResult,
    RegistryRunKey,
    TimelineEvent,
)

# Sigma / universal anomaly detection models
from sift_mcp.models.sigma import (
    AnalysisResult,
    ArtifactHit,
    SigmaScanResult,
    ToolResult,
)

__all__ = [
    # Case
    "CaseManifest",
    "CaseState",
    "DiskImage",
    "MemoryDump",
    "TimeWindow",
    # Finding
    "EvidenceKind",
    "Finding",
    "FindingStatus",
    # Execution / correction
    "CorrectionEvent",
    "Execution",
    # Artifacts — memory
    "ProcessRecord",
    "InjectionIndicator",
    "DllRecord",
    "NetworkArtifact",
    # Artifacts — disk
    "PrefetchRecord",
    "AmcacheRecord",
    "RegistryRunKey",
    "EventRecord",
    "TimelineEvent",
    "DeletedFile",
    "MftEntry",
    # Integrity / profiling
    "IntegrityResult",
    "ProfileResult",
    # Correlation engine
    "DiscrepancyAlert",
    "CorrelationReport",
    # Sigma / analysis
    "ArtifactHit",
    "ToolResult",
    "SigmaScanResult",
    "AnalysisResult",
]
