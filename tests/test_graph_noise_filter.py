"""Regression test for graph noise filter.

Run-8 lesson: the investigation graph hit 555 nodes / 564 edges because
every finding (including 500+ raw Sigma rule hits) became its own node.
The filter excludes:
  - raw_detector_hit findings from sigma_hunt (except per-severity rollups)
  - findings with confidence < 0.80 AND status NOT IN (CONFIRMED, PROBABLE)
    AND no MITRE ATT&CK tag

Without this, the graph drowns the real attack chain.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _make_finding(fid: str, **kwargs):
    base = {
        "finding_id": fid,
        "evidence_kind": "observation",
        "finding_kind": "validated",
        "finding_status": "ACTIVE",
        "finding_type": "test_finding",
        "tool_name": "test_tool",
        "confidence": 1.0,
        "description": "test",
        "supporting_indicators": [],
        "contradicted_by": [],
        "corroborated_by": [],
        "related_finding_ids": [],
        "artifact_type": "disk",
        "artifact_path": "/test",
        "execution_id": "E-001",
    }
    base.update(kwargs)
    return base


def test_filter_drops_raw_sigma_hits_keeps_severity_summaries():
    """Per-rule sigma hits (finding_kind='raw_detector_hit', tool='sigma_hunt',
    no 'severity bucket' marker in description) must be dropped. The
    per-severity summary findings (which describe a bucket of hits)
    must be kept."""
    from investigation_graph import GraphBuilder
    builder = GraphBuilder()
    # 1 raw per-rule hit (should be dropped)
    raw_hit = _make_finding(
        "F-001",
        finding_kind="raw_detector_hit",
        tool_name="sigma_hunt",
        description="Rule 'Suspicious WMIC Command' fired",
        confidence=0.5,
    )
    # 1 per-severity summary (should be kept)
    severity_summary = _make_finding(
        "F-002",
        finding_kind="raw_detector_hit",
        tool_name="sigma_hunt",
        description="Sigma severity bucket [HIGH]: 192 rule hits in JSON",
        confidence=0.88,
    )
    # 1 normal validated finding (should be kept)
    validated = _make_finding(
        "F-003",
        finding_kind="validated",
        confidence=1.0,
        mitre_technique="T1219",
    )
    builder.build(
        state={"case_id": "TEST", "findings": [raw_hit, severity_summary, validated]},
        audit_entries=[],
    )
    node_ids = {n["id"] for n in builder.nodes}
    assert "F-001" not in node_ids, "raw per-rule sigma hit must be filtered out"
    assert "F-002" in node_ids, "per-severity summary finding must be kept"
    assert "F-003" in node_ids, "validated MITRE-tagged finding must be kept"
    meta = builder._graph_meta
    assert meta["suppressed_low_signal"] == 1
    assert meta["graphed_findings"] == 2


def test_filter_drops_low_confidence_observations_without_attck():
    """A finding with confidence < 0.80, status != CONFIRMED/PROBABLE,
    and no MITRE technique must be dropped — it's noise."""
    from investigation_graph import GraphBuilder
    builder = GraphBuilder()
    low_conf_no_attck = _make_finding(
        "F-100",
        confidence=0.55,
        finding_status="ACTIVE",
        mitre_technique="",
    )
    # Same low conf but WITH ATT&CK tag → keep (analyst flagged it)
    low_conf_with_attck = _make_finding(
        "F-101",
        confidence=0.55,
        finding_status="ACTIVE",
        mitre_technique="T1041",
    )
    # Low conf but PROBABLE status → keep
    low_conf_probable = _make_finding(
        "F-102",
        confidence=0.55,
        finding_status="PROBABLE",
    )
    builder.build(
        state={"case_id": "TEST", "findings": [low_conf_no_attck, low_conf_with_attck, low_conf_probable]},
        audit_entries=[],
    )
    node_ids = {n["id"] for n in builder.nodes}
    assert "F-100" not in node_ids, "low-conf no-ATT&CK must be filtered"
    assert "F-101" in node_ids, "low-conf with ATT&CK kept"
    assert "F-102" in node_ids, "PROBABLE status overrides low-conf filter"


def test_filter_does_not_remove_confirmed_findings_regardless_of_confidence():
    """CONFIRMED findings are kept even at low confidence — that's the
    whole point of corroboration."""
    from investigation_graph import GraphBuilder
    builder = GraphBuilder()
    confirmed_low_conf = _make_finding(
        "F-200",
        confidence=0.30,
        finding_status="CONFIRMED",
        mitre_technique="",
    )
    builder.build(
        state={"case_id": "TEST", "findings": [confirmed_low_conf]},
        audit_entries=[],
    )
    node_ids = {n["id"] for n in builder.nodes}
    assert "F-200" in node_ids


def test_graph_bounded_with_realistic_finding_mix():
    """Synthesize a Run-8-like finding mix (500 sigma raws + 30 validated)
    and assert the graph stays bounded under 80 finding nodes — preventing
    regression to the 555-node noise level."""
    from investigation_graph import GraphBuilder
    findings = []
    # 500 raw sigma hits — should all be dropped
    for i in range(500):
        findings.append(_make_finding(
            f"F-S{i:03d}",
            finding_kind="raw_detector_hit",
            tool_name="sigma_hunt",
            description=f"Rule {i} fired",
            confidence=0.5,
        ))
    # 5 per-severity rollups — kept
    for sev, count in (("INFO", 31119), ("LOW", 4), ("MEDIUM", 192), ("HIGH", 4), ("CRITICAL", 0)):
        if count > 0:
            findings.append(_make_finding(
                f"F-SEV-{sev}",
                finding_kind="raw_detector_hit",
                tool_name="sigma_hunt",
                description=f"Sigma severity bucket [{sev}]: {count} rule hits",
                confidence=0.88,
            ))
    # 30 validated findings with ATT&CK — all kept
    for i in range(30):
        findings.append(_make_finding(
            f"F-V{i:03d}",
            finding_kind="validated",
            confidence=1.0,
            mitre_technique=f"T10{i:02d}",
        ))
    builder = GraphBuilder()
    builder.build(state={"case_id": "TEST", "findings": findings}, audit_entries=[])
    # Total nodes = case + evidence-sources + filtered findings.
    # Filtered findings should be 4 severity rollups + 30 validated = 34.
    finding_nodes = [n for n in builder.nodes if n.get("type") == "finding"]
    assert len(finding_nodes) <= 80, (
        f"Graph noise filter regressed — {len(finding_nodes)} finding nodes "
        f"from 535-finding input. Run-8 had 555 nodes; this regression check "
        f"keeps the graph well-bounded."
    )
    meta = builder._graph_meta
    assert meta["suppressed_low_signal"] == 500, (
        f"Expected 500 raw sigma hits suppressed; got {meta['suppressed_low_signal']}"
    )
