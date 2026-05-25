"""ATT&CK technique routing for case-agnostic investigation planning.

Exposes MCP Resources for browsable ATT&CK technique mappings via:
- attack_routing://techniques (list all techniques)
- attack_routing://technique/{tid} (get specific technique details)

Also provides Python API for programmatic access.
"""

from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "load_routing_catalog",
    "get_technique_routing",
    "list_techniques",
    "ROUTING_YAML_PATH",
]

ROUTING_YAML_PATH = Path(__file__).parent / "attack_routing.yaml"


def load_routing_catalog() -> dict[str, Any]:
    """Load the full ATT&CK routing catalog from YAML.

    Returns
    -------
    dict[str, Any]
        Dictionary keyed by technique ID (e.g., 'T1003.001') with values
        containing name, tactics, required_artifacts, corroboration_sources,
        and detection_notes.

    Raises
    ------
    FileNotFoundError
        If attack_routing.yaml is missing.
    yaml.YAMLError
        If YAML is malformed.
    """
    if not ROUTING_YAML_PATH.exists():
        raise FileNotFoundError(
            f"ATT&CK routing catalog not found: {ROUTING_YAML_PATH}"
        )

    with ROUTING_YAML_PATH.open("r", encoding="utf-8") as f:
        catalog = yaml.safe_load(f)

    if not isinstance(catalog, dict):
        raise ValueError("attack_routing.yaml must contain a top-level dictionary")

    return catalog


def get_technique_routing(technique_id: str) -> Optional[dict[str, Any]]:
    """Get routing details for a specific ATT&CK technique.

    Parameters
    ----------
    technique_id : str
        ATT&CK technique ID (e.g., 'T1003.001')

    Returns
    -------
    Optional[dict[str, Any]]
        Technique routing details if found, None otherwise.
        Dictionary contains: name, tactics, required_artifacts,
        corroboration_sources, detection_notes.
    """
    catalog = load_routing_catalog()
    return catalog.get(technique_id)


def list_techniques() -> list[str]:
    """List all ATT&CK technique IDs in the routing catalog.

    Returns
    -------
    list[str]
        Sorted list of technique IDs (e.g., ['T1003.001', 'T1021.001', ...])
    """
    catalog = load_routing_catalog()
    return sorted(catalog.keys())
