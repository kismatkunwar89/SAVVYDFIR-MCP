"""Authoritative MCP tool-domain catalog used for integration-ready metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

ALLOWED_TOOL_DOMAINS = {
    "evidence",
    "disk",
    "memory",
    "timeline",
    "yara",
    "correlation",
    "state",
    "graph",
    "detection",
    "lifecycle",
    "mounting",
    "analysis",
}

ALLOWED_ARTIFACT_FAMILIES = {
    "disk",
    "memory",
    "registry",
    "event_logs",
    "timeline",
    "network",
    "file_system",
    "state",
    "reporting",
}

ALLOWED_RESULT_KINDS = {
    "artifact",
    "finding_candidates",
    "correlation",
    "state",
    "report",
    "graph",
    "mount",
    "analysis",
    "integrity",
}


@dataclass(frozen=True)
class ToolCatalogEntry:
    tool_name: str
    tool_domain: str
    artifact_families: tuple[str, ...]
    result_kind: str
    query_tool: Optional[str] = None

    @property
    def mcp_name(self) -> str:
        return self.tool_name.rsplit(".", 1)[-1]

    def to_dict(self) -> dict[str, Any]:
        data = {
            "tool_name": self.tool_name,
            "tool_domain": self.tool_domain,
            "artifact_families": list(self.artifact_families),
            "result_kind": self.result_kind,
        }
        if self.query_tool:
            data["query_tool"] = self.query_tool
        return data


def _entry(
    tool_name: str,
    tool_domain: str,
    artifact_families: tuple[str, ...],
    result_kind: str,
    *,
    query_tool: Optional[str] = None,
) -> ToolCatalogEntry:
    return ToolCatalogEntry(
        tool_name=tool_name,
        tool_domain=tool_domain,
        artifact_families=artifact_families,
        result_kind=result_kind,
        query_tool=query_tool,
    )


TOOL_CATALOG: dict[str, ToolCatalogEntry] = {
    "evidence.verify_integrity": _entry(
        "evidence.verify_integrity", "evidence", ("disk",), "integrity"
    ),
    "evidence.get_provenance": _entry(
        "evidence.get_provenance", "evidence", ("state", "reporting"), "integrity"
    ),
    "disk.extract_prefetch": _entry(
        "disk.extract_prefetch", "disk", ("disk", "file_system"), "artifact"
    ),
    "disk.get_amcache": _entry(
        "disk.get_amcache", "disk", ("disk", "registry", "file_system"), "artifact"
    ),
    "disk.extract_mft_timeline": _entry(
        "disk.extract_mft_timeline", "disk", ("disk", "file_system", "timeline"), "artifact"
    ),
    "disk.list_deleted_files": _entry(
        "disk.list_deleted_files", "disk", ("disk", "file_system"), "artifact"
    ),
    "disk.summarize_evtx": _entry(
        "disk.summarize_evtx", "disk", ("disk", "event_logs"), "artifact"
    ),
    "disk.extract_registry_run_keys": _entry(
        "disk.extract_registry_run_keys", "disk", ("disk", "registry"), "artifact"
    ),
    "disk.extract_windows_artifacts": _entry(
        "disk.extract_windows_artifacts",
        "disk",
        ("disk", "event_logs", "registry", "file_system"),
        "artifact",
    ),
    "disk.classify_missing_artifact": _entry(
        "disk.classify_missing_artifact",
        "disk",
        ("disk", "event_logs", "state", "reporting"),
        "analysis",
    ),
    "memory.detect_profile": _entry(
        "memory.detect_profile", "memory", ("memory",), "artifact"
    ),
    "memory.list_processes": _entry(
        "memory.list_processes", "memory", ("memory",), "finding_candidates"
    ),
    "memory.scan_processes": _entry(
        "memory.scan_processes", "memory", ("memory",), "finding_candidates"
    ),
    "memory.scan_network": _entry(
        "memory.scan_network", "memory", ("memory", "network"), "finding_candidates"
    ),
    "memory.detect_injection": _entry(
        "memory.detect_injection", "memory", ("memory",), "finding_candidates"
    ),
    "memory.list_dlls": _entry(
        "memory.list_dlls", "memory", ("memory", "file_system"), "artifact"
    ),
    "timeline.build_timeline": _entry(
        "timeline.build_timeline",
        "timeline",
        ("timeline",),
        "artifact",
        query_tool="query_timeline",
    ),
    "timeline.query_timeline": _entry(
        "timeline.query_timeline",
        "timeline",
        ("timeline", "file_system", "event_logs"),
        "artifact",
    ),
    "yara.scan_files": _entry(
        "yara.scan_files", "yara", ("disk", "file_system"), "finding_candidates"
    ),
    "yara.scan_memory": _entry(
        "yara.scan_memory", "yara", ("memory",), "finding_candidates"
    ),
    "correlation.compare_disk_and_memory": _entry(
        "correlation.compare_disk_and_memory",
        "correlation",
        ("disk", "memory"),
        "correlation",
    ),
    "correlation.flag_discrepancy": _entry(
        "correlation.flag_discrepancy",
        "correlation",
        ("disk", "memory", "state"),
        "correlation",
    ),
    "state.read_state": _entry("state.read_state", "state", ("state",), "state"),
    "state.get_finding": _entry("state.get_finding", "state", ("state",), "state"),
    "state.get_findings": _entry("state.get_findings", "state", ("state",), "state"),
    "state.export_trace": _entry(
        "state.export_trace", "state", ("state", "reporting"), "state"
    ),
    "state.describe_tool_catalog": _entry(
        "state.describe_tool_catalog", "state", ("state",), "state"
    ),
    "state.record_analysis_lane": _entry(
        "state.record_analysis_lane", "state", ("state", "reporting"), "state"
    ),
    "state.get_investigation_gates": _entry(
        "state.get_investigation_gates", "state", ("state", "reporting"), "state"
    ),
    "graph.generate_graph": _entry(
        "graph.generate_graph", "graph", ("state", "reporting"), "graph"
    ),
    "graph.serve_graph": _entry(
        "graph.serve_graph", "graph", ("reporting",), "graph"
    ),
    "graph.merge_host_graphs": _entry(
        "graph.merge_host_graphs", "graph", ("state", "reporting"), "graph"
    ),
    "graph.build_reports_index": _entry(
        "graph.build_reports_index", "graph", ("state", "reporting"), "graph"
    ),
    "detection.sigma_hunt": _entry(
        "detection.sigma_hunt",
        "detection",
        ("event_logs", "registry", "file_system", "network", "memory"),
        "finding_candidates",
        query_tool="query_sigma_results",
    ),
    "detection.query_sigma_results": _entry(
        "detection.query_sigma_results",
        "detection",
        ("event_logs", "reporting"),
        "artifact",
    ),
    "detection.analyze_vss": _entry(
        "detection.analyze_vss", "detection", ("disk", "file_system"), "artifact"
    ),
    "detection.extract_pca": _entry(
        "detection.extract_pca", "detection", ("disk", "registry"), "artifact"
    ),
    "detection.extract_shimcache": _entry(
        "detection.extract_shimcache", "detection", ("disk", "registry"), "artifact"
    ),
    "detection.extract_srum": _entry(
        "detection.extract_srum", "detection", ("disk", "registry", "network"), "artifact"
    ),
    "detection.sigma_scan": _entry(
        "detection.sigma_scan",
        "detection",
        ("state", "event_logs", "registry", "file_system", "memory", "network"),
        "finding_candidates",
    ),
    "lifecycle.start_investigation": _entry(
        "lifecycle.start_investigation", "lifecycle", ("state",), "state"
    ),
    "lifecycle.environment_preflight": _entry(
        "lifecycle.environment_preflight", "lifecycle", ("state", "reporting"), "analysis"
    ),
    "lifecycle.add_finding": _entry(
        "lifecycle.add_finding", "lifecycle", ("state",), "state"
    ),
    "lifecycle.coverage_report": _entry(
        "lifecycle.coverage_report", "lifecycle", ("state", "reporting"), "report"
    ),
    "lifecycle.generate_report": _entry(
        "lifecycle.generate_report", "lifecycle", ("state", "reporting"), "report"
    ),
    "mounting.mount_image": _entry(
        "mounting.mount_image", "mounting", ("disk",), "mount"
    ),
    "mounting.load_memory": _entry(
        "mounting.load_memory", "mounting", ("memory",), "mount"
    ),
    "analysis.run_analysis": _entry(
        "analysis.run_analysis", "analysis", ("state", "reporting"), "analysis"
    ),
}

_SUFFIX_INDEX: dict[str, str] = {
    entry.mcp_name: entry.tool_name for entry in TOOL_CATALOG.values()
}


def iter_catalog_entries() -> list[ToolCatalogEntry]:
    return [TOOL_CATALOG[name] for name in sorted(TOOL_CATALOG)]


def get_tool_catalog_entry(tool_name: Any) -> Optional[ToolCatalogEntry]:
    text = str(tool_name).strip() if tool_name is not None else ""
    if not text:
        return None
    entry = TOOL_CATALOG.get(text)
    if entry is not None:
        return entry
    return TOOL_CATALOG.get(_SUFFIX_INDEX.get(text, ""))


def tool_domain_for(tool_name: Any) -> Optional[str]:
    entry = get_tool_catalog_entry(tool_name)
    return entry.tool_domain if entry is not None else None


def artifact_families_for(tool_name: Any) -> list[str]:
    entry = get_tool_catalog_entry(tool_name)
    return list(entry.artifact_families) if entry is not None else []


def result_kind_for(tool_name: Any) -> Optional[str]:
    entry = get_tool_catalog_entry(tool_name)
    return entry.result_kind if entry is not None else None


def domain_metadata_for_tool(tool_name: Any) -> Optional[dict[str, Any]]:
    entry = get_tool_catalog_entry(tool_name)
    if entry is None:
        return None
    return {
        "tool_domain": entry.tool_domain,
        "artifact_families": list(entry.artifact_families),
        "result_kind": entry.result_kind,
    }


def group_tool_catalog(*, domain: Optional[str] = None) -> dict[str, list[dict[str, Any]]]:
    selected_domain = str(domain).strip().lower() if domain else None
    if selected_domain and selected_domain not in ALLOWED_TOOL_DOMAINS:
        raise ValueError(f"Unsupported domain filter {domain!r}.")

    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in iter_catalog_entries():
        if selected_domain and entry.tool_domain != selected_domain:
            continue
        grouped.setdefault(entry.tool_domain, []).append(entry.to_dict())
    return grouped


def validate_tool_catalog(expected_mcp_names: Optional[Iterable[str]] = None) -> list[str]:
    issues: list[str] = []
    seen_tool_names: set[str] = set()
    seen_mcp_names: set[str] = set()
    for entry in iter_catalog_entries():
        if entry.tool_name in seen_tool_names:
            issues.append(f"Duplicate tool_name {entry.tool_name}.")
        seen_tool_names.add(entry.tool_name)

        if entry.mcp_name in seen_mcp_names:
            issues.append(f"Duplicate MCP tool suffix {entry.mcp_name}.")
        seen_mcp_names.add(entry.mcp_name)

        if entry.tool_domain not in ALLOWED_TOOL_DOMAINS:
            issues.append(
                f"{entry.tool_name} has unsupported tool_domain {entry.tool_domain!r}."
            )
        if entry.result_kind not in ALLOWED_RESULT_KINDS:
            issues.append(
                f"{entry.tool_name} has unsupported result_kind {entry.result_kind!r}."
            )
        for artifact_family in entry.artifact_families:
            if artifact_family not in ALLOWED_ARTIFACT_FAMILIES:
                issues.append(
                    f"{entry.tool_name} has unsupported artifact family {artifact_family!r}."
                )

    if expected_mcp_names is not None:
        expected = {str(name).strip() for name in expected_mcp_names if str(name).strip()}
        actual = {entry.mcp_name for entry in TOOL_CATALOG.values()}
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            issues.append(f"Catalog missing MCP tools: {', '.join(missing)}.")
        if extra:
            issues.append(f"Catalog has extra MCP tools: {', '.join(extra)}.")
    return issues


__all__ = [
    "ALLOWED_ARTIFACT_FAMILIES",
    "ALLOWED_RESULT_KINDS",
    "ALLOWED_TOOL_DOMAINS",
    "TOOL_CATALOG",
    "ToolCatalogEntry",
    "artifact_families_for",
    "domain_metadata_for_tool",
    "get_tool_catalog_entry",
    "group_tool_catalog",
    "iter_catalog_entries",
    "result_kind_for",
    "tool_domain_for",
    "validate_tool_catalog",
]
