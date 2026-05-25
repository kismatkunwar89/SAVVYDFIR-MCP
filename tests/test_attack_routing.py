"""Unit tests for ATT&CK technique routing module (Phase D.1).

Tests:
- YAML parsing and schema validation
- Python API (load_routing_catalog, get_technique_routing, list_techniques)
- MCP resource handlers (list_attack_techniques, get_attack_technique_routing)
- Content coverage (5 initial techniques: T1566.001, T1059.001, T1003.001, T1021.001, T1070.001)
"""

import json
import pytest
from pathlib import Path

# Python API tests
def test_routing_yaml_exists():
    """attack_routing.yaml must exist in sift_mcp/routing/."""
    from sift_mcp.routing import ROUTING_YAML_PATH
    assert ROUTING_YAML_PATH.exists(), f"Missing {ROUTING_YAML_PATH}"


def test_load_routing_catalog_parses():
    """load_routing_catalog() must parse valid YAML and return dict."""
    from sift_mcp.routing import load_routing_catalog
    catalog = load_routing_catalog()
    assert isinstance(catalog, dict), "Catalog must be a dictionary"
    assert len(catalog) >= 5, "Must have at least 5 techniques (initial coverage)"


def test_catalog_schema_all_techniques():
    """Every technique entry must have required fields with correct types."""
    from sift_mcp.routing import load_routing_catalog
    catalog = load_routing_catalog()

    required_fields = {
        "name": str,
        "tactics": list,
        "required_artifacts": list,
        "corroboration_sources": (list, dict),  # Can be list or dict
        "detection_notes": str,
    }

    for tid, entry in catalog.items():
        assert tid.startswith("T"), f"{tid} must start with 'T'"
        for field, expected_type in required_fields.items():
            assert field in entry, f"{tid} missing '{field}'"
            if isinstance(expected_type, tuple):
                assert isinstance(entry[field], expected_type), \
                    f"{tid}.{field} must be one of {expected_type}, got {type(entry[field])}"
            else:
                assert isinstance(entry[field], expected_type), \
                    f"{tid}.{field} must be {expected_type}, got {type(entry[field])}"


def test_initial_coverage_techniques():
    """Catalog must include 5 initial techniques from plan."""
    from sift_mcp.routing import list_techniques
    techniques = list_techniques()

    initial = ["T1566.001", "T1059.001", "T1003.001", "T1021.001", "T1070.001"]
    for tid in initial:
        assert tid in techniques, f"Missing initial technique {tid}"


def test_get_technique_routing_valid():
    """get_technique_routing() must return details for valid technique."""
    from sift_mcp.routing import get_technique_routing

    routing = get_technique_routing("T1003.001")
    assert routing is not None, "T1003.001 must exist"
    assert routing["name"] == "OS Credential Dumping: LSASS Memory"
    assert "TA0006" in routing["tactics"], "T1003.001 must map to TA0006"
    assert "disk.summarize_evtx" in routing["required_artifacts"]
    assert "memory.detect_injection" in routing["required_artifacts"]


def test_get_technique_routing_invalid():
    """get_technique_routing() must return None for unknown technique."""
    from sift_mcp.routing import get_technique_routing

    routing = get_technique_routing("T9999.999")
    assert routing is None, "Unknown technique must return None"


def test_list_techniques_sorted():
    """list_techniques() must return sorted list of technique IDs."""
    from sift_mcp.routing import list_techniques

    techniques = list_techniques()
    assert isinstance(techniques, list)
    assert all(isinstance(t, str) for t in techniques)
    assert techniques == sorted(techniques), "Must be sorted"


# MCP resource handler tests (require fastmcp — skip locally, run on remote)
def test_list_attack_techniques_resource():
    """MCP resource attack_routing://techniques must return JSON technique list."""
    try:
        from sift_mcp.server import list_attack_techniques
    except ModuleNotFoundError:
        pytest.skip("fastmcp not available (local test environment)")

    result = list_attack_techniques()
    data = json.loads(result)

    assert "techniques" in data, "Must have 'techniques' key"
    assert "count" in data, "Must have 'count' key"
    assert isinstance(data["techniques"], list)
    assert data["count"] >= 5, "Must have at least 5 techniques"
    assert "T1003.001" in data["techniques"]


def test_get_attack_technique_routing_resource_valid():
    """MCP resource attack_routing://technique/{tid} must return JSON routing details."""
    try:
        from sift_mcp.server import get_attack_technique_routing
    except ModuleNotFoundError:
        pytest.skip("fastmcp not available (local test environment)")

    result = get_attack_technique_routing("T1003.001")
    data = json.loads(result)

    assert "error" not in data, f"Unexpected error: {data.get('error')}"
    assert data["technique_id"] == "T1003.001"
    assert data["name"] == "OS Credential Dumping: LSASS Memory"
    assert "tactics" in data
    assert "required_artifacts" in data
    assert "corroboration_sources" in data
    assert "detection_notes" in data


def test_get_attack_technique_routing_resource_invalid():
    """MCP resource must return error JSON for unknown technique."""
    try:
        from sift_mcp.server import get_attack_technique_routing
    except ModuleNotFoundError:
        pytest.skip("fastmcp not available (local test environment)")

    result = get_attack_technique_routing("T9999.999")
    data = json.loads(result)

    assert "error" in data, "Must have 'error' key for unknown technique"
    assert "not found" in data["error"].lower()


def test_required_artifacts_are_valid_mcp_tools():
    """All required_artifacts must reference real MCP tools from TOOL_CATALOG."""
    from sift_mcp.routing import load_routing_catalog
    from sift_mcp.tool_catalog import TOOL_CATALOG

    catalog = load_routing_catalog()
    valid_tools = set(TOOL_CATALOG.keys())

    for tid, entry in catalog.items():
        for artifact in entry["required_artifacts"]:
            assert artifact in valid_tools, \
                f"{tid} references unknown tool '{artifact}' (not in TOOL_CATALOG)"


def test_tactics_are_valid_attack_ids():
    """All tactics must be valid ATT&CK tactic IDs (TA0001-TA0014)."""
    from sift_mcp.routing import load_routing_catalog

    catalog = load_routing_catalog()
    valid_tactics = {f"TA{str(i).zfill(4)}" for i in range(1, 15)}

    for tid, entry in catalog.items():
        for tactic in entry["tactics"]:
            assert tactic in valid_tactics, \
                f"{tid} has invalid tactic '{tactic}' (must be TA0001-TA0014)"


def test_no_duplicate_technique_ids():
    """YAML must not have duplicate technique IDs."""
    from sift_mcp.routing import load_routing_catalog

    catalog = load_routing_catalog()
    technique_ids = list(catalog.keys())

    assert len(technique_ids) == len(set(technique_ids)), \
        "Duplicate technique IDs in catalog"


def test_corroboration_sources_not_empty():
    """Every technique must have at least one corroboration source."""
    from sift_mcp.routing import load_routing_catalog

    catalog = load_routing_catalog()

    for tid, entry in catalog.items():
        sources = entry["corroboration_sources"]
        if isinstance(sources, list):
            assert len(sources) > 0, f"{tid} has empty corroboration_sources list"
        elif isinstance(sources, dict):
            assert len(sources) > 0, f"{tid} has empty corroboration_sources dict"


def test_detection_notes_minimum_length():
    """Detection notes must be substantive (>100 chars)."""
    from sift_mcp.routing import load_routing_catalog

    catalog = load_routing_catalog()

    for tid, entry in catalog.items():
        notes = entry["detection_notes"]
        assert len(notes.strip()) > 100, \
            f"{tid} detection_notes too short ({len(notes)} chars, need >100)"


class TestAttackRoutingIntegration:
    """Integration tests for ATT&CK routing in investigation workflow."""

    def test_routing_t1003_credential_dumping(self):
        """T1003.001 routing must cover full credential dumping detection surface."""
        from sift_mcp.routing import get_technique_routing

        routing = get_technique_routing("T1003.001")
        assert routing is not None

        # Must cover all 3 pillars: filesystem, memory, registry
        artifacts = routing["required_artifacts"]
        assert any("evtx" in a for a in artifacts), "Missing EVTX coverage"
        assert any("memory" in a for a in artifacts), "Missing memory coverage"
        assert any("mft" in a or "registry" in a for a in artifacts), "Missing filesystem coverage"

        # Must include injection detection (reflective PE common in mimikatz)
        assert "memory.detect_injection" in artifacts

    def test_routing_t1070_log_clearing(self):
        """T1070.001 routing must include VSS analysis for log recovery."""
        from sift_mcp.routing import get_technique_routing

        routing = get_technique_routing("T1070.001")
        assert routing is not None

        # Must include VSS for shadow copy log recovery
        artifacts = routing["required_artifacts"]
        assert "detection.analyze_vss" in artifacts, \
            "T1070.001 must include analyze_vss for shadow copy recovery"

        # Detection notes must mention EID 1102
        notes = routing["detection_notes"].lower()
        assert "1102" in notes, "Must mention EID 1102 (log cleared event)"

    def test_routing_t1059_powershell(self):
        """T1059.001 routing must cover PowerShell abuse patterns."""
        from sift_mcp.routing import get_technique_routing

        routing = get_technique_routing("T1059.001")
        assert routing is not None

        # Must cover EVTX script block logging
        corroboration = str(routing["corroboration_sources"]).lower()
        assert "4104" in corroboration, "Must mention EID 4104 (script block logging)"

        # Must include SRUM for exfil quantification
        artifacts = routing["required_artifacts"]
        assert "detection.extract_srum" in artifacts, \
            "Must include SRUM for PowerShell exfil quantification"
