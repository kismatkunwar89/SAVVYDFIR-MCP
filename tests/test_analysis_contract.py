"""Regression tests for the analysis contract.

Run-9 lesson: extraction without analysis is half a run. The previous run
ran all 15 mandatory tools cleanly but made ZERO run_analysis calls and
spawned ZERO specialists — producing 552 ACTIVE / 2 CONFIRMED instead of
Run-8's 8 CONFIRMED. Root cause: when I slimmed workflow_contract for
token efficiency, I dropped the explicit instruction telling the agent to
drill into csv_paths via run_analysis or specialist subagents.

These tests lock in:
  1. start_investigation's workflow_contract includes an analysis_contract
     section with rule + specialist_routing + fallback_if_agent_unavailable
  2. PostToolUse hook fires on EVERY artifact-producing tool to remind
     the agent to analyze before moving on
  3. The hook emits a directive containing "run_analysis" or the
     matching specialist agent name (@*-analyst)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_workflow_contract_includes_analysis_contract():
    """start_investigation's workflow_contract MUST include an
    analysis_contract field with the run_analysis / specialist mandate.
    Without this, agents extract data and move on without analyzing it."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    # Find workflow_contract dict
    idx = src.find('"workflow_contract":')
    assert idx > 0, "workflow_contract missing from start_investigation"
    # Slice forward to find the end of this dict
    end = src.find('"existing_case_state_detected"', idx)
    block = src[idx:end] if end > 0 else src[idx:idx + 3000]
    assert '"analysis_contract"' in block, (
        "workflow_contract MUST include analysis_contract. Without explicit "
        "instructions to use run_analysis() / specialist subagents after each "
        "extraction, the agent runs all tools but never drills into the CSVs "
        "— Run-9 produced 552 ACTIVE / 2 CONFIRMED for exactly this reason."
    )
    # Critical keywords must be present in the contract
    for keyword in ("run_analysis", "specialist_routing", "@mft-analyst",
                    "@evtx-analyst", "fallback_if_agent_unavailable"):
        assert keyword in block, (
            f"analysis_contract missing '{keyword}' — that's part of the "
            f"explicit guidance that tells the agent how to drill in."
        )


def test_post_hook_fires_on_all_extraction_tools():
    """Every artifact-producing tool must be in the PostToolUse matcher
    so the analysis-contract nudge fires for each csv_path response."""
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    post_hooks = settings.get("hooks", {}).get("PostToolUse", [])
    matchers = [h.get("matcher", "") for h in post_hooks]
    matcher_str = "|".join(matchers)
    # All Phase-2 extractors that produce csv_path must be matched
    required = (
        "extract_mft_timeline", "extract_usn_journal", "summarize_evtx",
        "extract_prefetch", "get_amcache", "extract_shimcache",
        "extract_registry_run_keys", "extract_srum", "sigma_hunt",
    )
    for tool in required:
        assert f"mcp__savvydfir__{tool}" in matcher_str, (
            f"PostToolUse matcher missing mcp__savvydfir__{tool}. "
            f"Without it, the analysis-contract nudge won't fire after "
            f"{tool} runs, and the agent will move to the next extraction "
            f"without analyzing this one's csv_path."
        )


def test_post_hook_emits_analysis_directive_for_extract_mft():
    """Behavior: simulate extract_mft_timeline response with csv_path,
    verify the hook directs the agent to either run_analysis or spawn
    @mft-analyst."""
    event = {
        "tool_name": "mcp__savvydfir__extract_mft_timeline",
        "cwd": str(ROOT),
        "tool_input": {"case_id": "TEST"},
        "tool_result": {
            "data": {
                "status": "success",
                "csv_path": "/cases/TEST/artifacts/mft/mft.csv",
                "total_records": 301363,
            },
        },
    }
    r = subprocess.run(
        ["python3", str(ROOT / ".claude" / "hooks" / "workflow-enforce-post.py")],
        input=json.dumps(event),
        capture_output=True, text=True, timeout=15,
        env={**os.environ},
    )
    assert r.stdout.strip(), "PostToolUse hook must emit directive"
    out = json.loads(r.stdout)
    ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
    # Must mention both options: run_analysis OR specialist
    assert "run_analysis" in ctx, f"directive must mention run_analysis. Got: {ctx[:200]}"
    assert "@mft-analyst" in ctx, f"directive must mention @mft-analyst. Got: {ctx[:200]}"
    # Must explain the consequence
    assert "ACTIVE" in ctx or "CONFIRMED" in ctx or "stacking" in ctx, (
        f"directive must explain WHY (extraction-without-analysis leaves "
        f"findings as ACTIVE observations). Got: {ctx[:300]}"
    )


def test_post_hook_emits_directive_for_sigma_hunt():
    """sigma_hunt → @sigma-analyst with output_path."""
    event = {
        "tool_name": "mcp__savvydfir__sigma_hunt",
        "cwd": str(ROOT),
        "tool_input": {"case_id": "TEST"},
        "tool_result": {
            "data": {
                "status": "success",
                "output_path": "/cases/TEST/artifacts/sigma/hits.json",
                "hits_total": 31123,
            },
        },
    }
    r = subprocess.run(
        ["python3", str(ROOT / ".claude" / "hooks" / "workflow-enforce-post.py")],
        input=json.dumps(event),
        capture_output=True, text=True, timeout=15,
        env={**os.environ},
    )
    assert r.stdout.strip()
    out = json.loads(r.stdout)
    ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
    assert "@sigma-analyst" in ctx
    assert "run_analysis" in ctx


def test_post_hook_silent_when_no_csv_in_response():
    """If the tool's response has no csv_path/output_path (e.g. an
    artifact_absent case), the hook should NOT emit the
    analyze-the-csv directive — there's no CSV to analyze."""
    event = {
        "tool_name": "mcp__savvydfir__extract_shimcache",
        "cwd": str(ROOT),
        "tool_input": {},
        "tool_result": {
            "data": {"status": "artifact_absent", "artifact_name": "SYSTEM_hive"},
        },
    }
    r = subprocess.run(
        ["python3", str(ROOT / ".claude" / "hooks" / "workflow-enforce-post.py")],
        input=json.dumps(event),
        capture_output=True, text=True, timeout=15,
        env={**os.environ},
    )
    # Hook should not emit the run_analysis directive when there's no CSV
    # (it may emit OTHER directives, but not the "analyze this csv now" one).
    out_text = r.stdout.lower()
    assert "run_analysis(data_path=" not in out_text, (
        "Hook must not nudge run_analysis when the response has no CSV. "
        "Got: " + r.stdout[:300]
    )
