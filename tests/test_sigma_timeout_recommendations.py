"""Regression tests for Tier-B1: sigma_hunt timeout recommended_next_calls.

design review 2026-05-19 (MEDIUM-HIGH): on chainsaw full-directory
timeout, sigma_hunt MUST return a ranked recommended_next_calls list
based on EVTX inventory. System.evtx is FIRST (EID 7045 service install
— central corroboration that was missed in Run-10).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_sigma_hunt_source_carries_recommended_next_calls():
    """Source-text guard: sigma_hunt must construct recommended_next_calls
    in the timeout-fallback branch."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def sigma_hunt(")
    assert func_idx > 0
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 60000]

    assert "recommended_next_calls" in body, (
        "sigma_hunt must build recommended_next_calls on timeout fallback "
        "per design review Tier-B1."
    )
    assert "directory_timeout" in body, (
        "recommendation list must gate on fallback_reason == 'directory_timeout'."
    )
    assert "evtx_inventory" in body, (
        "Recommendations must be inventory-aware (read from "
        "artifact_coverage.evtx_inventory)."
    )


def test_sigma_hunt_ranks_system_evtx_first():
    """Per review sign-off, System.evtx must rank first because EID 7045
    service install was the Run-10 miss."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def sigma_hunt(")
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 60000]

    # Find the ranking list — System should appear before Sysmon
    ranking_idx = body.find("_ranking = [")
    assert ranking_idx > 0, "ranking list missing"
    ranking_block = body[ranking_idx:ranking_idx + 2500]

    system_pos = ranking_block.find('"system"')
    sysmon_pos = ranking_block.find('"microsoft-windows-sysmon')
    powershell_pos = ranking_block.find('"microsoft-windows-powershell')

    assert 0 < system_pos < sysmon_pos, (
        f"System.evtx must rank FIRST in recommended_next_calls. "
        f"system at {system_pos}, sysmon at {sysmon_pos}."
    )
    assert sysmon_pos < powershell_pos, "Sysmon must rank before PowerShell."
    # EID 7045 must be mentioned as a reason
    assert "EID 7045" in ranking_block, (
        "System.evtx ranking reason must reference EID 7045 service install — "
        "that's the Run-10 miss the recommendation exists to prevent."
    )


def test_recommendation_uses_canonical_response_shape():
    """recommended_next_calls must follow the {tool, arguments, reason}
    pattern from start_investigation.next_required_tools — for shape
    consistency across the response surface."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def sigma_hunt(")
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 60000]

    # The append should use the {tool, arguments, reason} keys
    append_idx = body.find("recommended_next_calls.append({")
    assert append_idx > 0
    append_block = body[append_idx:append_idx + 600]
    for key in ('"tool":', '"arguments":', '"reason":'):
        assert key in append_block, (
            f"recommended_next_calls entries must include {key} for shape "
            f"consistency with start_investigation.next_required_tools."
        )


def test_recommendation_only_fires_on_directory_timeout():
    """Non-timeout sigma_hunt runs (full-dir success or single-file path)
    must NOT emit recommended_next_calls — only directory_timeout fallback."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def sigma_hunt(")
    end = src.find("\n@mcp.tool()\n", func_idx + 1)
    body = src[func_idx:end if end > 0 else func_idx + 60000]

    # The guard must check both fallback_applied AND fallback_reason
    guard_idx = body.find(
        'if fallback_applied and fallback_reason == "directory_timeout"'
    )
    assert guard_idx > 0, (
        "Recommendation list must be gated by `fallback_applied and "
        "fallback_reason == \"directory_timeout\"` — not emitted on "
        "non-timeout runs."
    )
