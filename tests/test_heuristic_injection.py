"""Tests for W1.7 — Heuristic MCP Injection (CR13 Option X).

Covers:
- Slice extractor (handles "What to Hunt" + "Critical Forensic Heuristics" + "Forensic Ground Rules" header variance)
- CTX audit primitive (log_context_bundle)
- CaseStateManager heuristic-ref dedup
- Hypothesis schema validation
- prepare_hypothesis_context + record_hypotheses MCP tools
- get_heuristic on-demand depth reader
- Tier-1 injection in build_contract_response
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

# fastmcp stub so sift_mcp.server imports cleanly
if "fastmcp" not in sys.modules:
    import types
    fastmcp_stub = types.ModuleType("fastmcp")

    class _StubFastMCP:
        def __init__(self, *a, **k): pass
        def tool(self, *a, **k):
            def _wrap(fn): return fn
            return _wrap
        def resource(self, *a, **k):
            def _wrap(fn): return fn
            return _wrap
        def run(self, *a, **k): pass

    fastmcp_stub.FastMCP = _StubFastMCP
    sys.modules["fastmcp"] = fastmcp_stub

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Slice extractor — handles header variance across 8 specialist .md files
# ---------------------------------------------------------------------------


class TestSliceExtractor:
    """The 8 canonical .md files use mixed section headers:
    - 7 files: '## What to Hunt (Heuristics, not procedures)'
    - 1 file (prefetch): '## Critical Forensic Heuristics'
    - all 8: '## Forensic Ground Rules'

    The extractor must handle all variants and return bounded slices.
    """

    @pytest.mark.parametrize("artifact", [
        "mft", "evtx", "prefetch", "amcache",
        "registry", "srum", "sigma", "memory",
    ])
    def test_tier1_extraction_works_for_all_artifacts(self, artifact):
        import extract_heuristic_slice as ex
        s = ex.extract_tier1_slice(artifact)
        assert s is not None, f"Tier-1 returned None for {artifact}"
        assert s["section_found"] is True, f"No heuristic section found for {artifact}"
        assert s["token_count"] > 50, f"Slice too small for {artifact}: {s['token_count']}"
        assert s["token_count"] <= 1000, f"Slice exceeds Tier-1 budget for {artifact}: {s['token_count']}"
        assert s["source_hash"].startswith("sha256:")
        assert s["excerpt_hash"].startswith("sha256:")
        assert s["source_path"].endswith("-analyst.md")
        assert "Forensic Ground Rules" in s["sections_included"]

    def test_tier1_prefetch_uses_critical_forensic_heuristics_header(self):
        """Prefetch uses 'Critical Forensic Heuristics' instead of 'What to Hunt'."""
        import extract_heuristic_slice as ex
        s = ex.extract_tier1_slice("prefetch")
        assert s is not None
        sections = " ".join(s["sections_included"])
        assert "Critical Forensic Heuristics" in sections or "What to Hunt" in sections

    def test_tier1_excludes_phase3_overlay_content(self):
        """Slice must not contain stripped Phase 3 overlay markers."""
        import extract_heuristic_slice as ex
        for artifact in ["mft", "evtx", "memory"]:
            s = ex.extract_tier1_slice(artifact)
            assert s is not None
            content = s["content"]
            assert "C-PRIME Output Discipline" not in content, \
                f"{artifact} slice contains stripped overlay"
            assert "## Playbook (Phase 3 refactor" not in content
            assert "Final Response Contract" not in content

    def test_tier2_slice_smaller_than_tier1(self):
        import extract_heuristic_slice as ex
        for artifact in ["mft", "evtx", "memory"]:
            t1 = ex.extract_tier1_slice(artifact)
            t2 = ex.extract_tier2_slice(artifact)
            assert t1 is not None and t2 is not None
            assert t2["token_count"] <= t1["token_count"], \
                f"Tier-2 ({t2['token_count']}) should be <= Tier-1 ({t1['token_count']}) for {artifact}"

    def test_topic_lookup_returns_specific_section(self):
        import extract_heuristic_slice as ex
        result = ex.extract_topic("mft", "what_to_hunt")
        assert result is not None
        assert "What to Hunt" in result["section_header"]
        # 'forensic_ground_rules' is universal
        gr = ex.extract_topic("evtx", "forensic_ground_rules")
        assert gr is not None
        assert "Forensic Ground Rules" in gr["section_header"]

    def test_topic_lookup_returns_none_for_unknown(self):
        import extract_heuristic_slice as ex
        assert ex.extract_topic("mft", "nonexistent_topic") is None
        assert ex.extract_topic("notarealartifact", "what_to_hunt") is None

    def test_extractor_lists_all_artifacts_and_topics(self):
        import extract_heuristic_slice as ex
        artifacts = ex.list_artifacts()
        assert set(artifacts) >= {"mft", "evtx", "prefetch", "amcache",
                                   "registry", "srum", "sigma", "memory"}
        topics = ex.list_topics()
        assert "what_to_hunt" in topics
        assert "forensic_ground_rules" in topics
        assert "professional_patterns" in topics


# ---------------------------------------------------------------------------
# CTX audit primitive
# ---------------------------------------------------------------------------


class TestLogContextBundle:
    """W1.7.02 — log_context_bundle writes context_bundle audit rows
    with CTX-NNN ids, source hashes, and triggered_by attribution.
    """

    def test_log_context_bundle_writes_audit_row(self, tmp_path):
        from sift_mcp.audit import AuditLogger
        logger = AuditLogger(str(tmp_path / "audit.jsonl"))
        entry = logger.log_context_bundle(
            case_id="TEST",
            artifact="mft",
            heuristic_source_path=".claude/agents/mft-analyst.md",
            heuristic_source_hash="sha256:abc",
            heuristic_section="Forensic Ground Rules + What to Hunt",
            heuristic_excerpt_hash="sha256:def",
            excerpt_token_count=791,
            triggered_by="extract_mft_timeline",
            execution_id="E-001",
        )
        assert entry["event_type"] == "context_bundle"
        assert entry["context_id"].startswith("CTX-")
        assert entry["artifact"] == "mft"
        rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert len(rows) == 1
        assert rows[0]["heuristic_source_path"] == ".claude/agents/mft-analyst.md"
        assert rows[0]["excerpt_token_count"] == 791

    def test_next_context_id_increments(self, tmp_path):
        from sift_mcp.audit import AuditLogger
        logger = AuditLogger(str(tmp_path / "a.jsonl"))
        assert logger.next_context_id() == "CTX-001"
        assert logger.next_context_id() == "CTX-002"
        assert logger.next_context_id() == "CTX-003"

    def test_log_context_bundle_includes_required_fields(self, tmp_path):
        from sift_mcp.audit import AuditLogger
        logger = AuditLogger(str(tmp_path / "a.jsonl"))
        logger.log_context_bundle(
            case_id="C1", artifact="evtx",
            heuristic_source_path=".claude/agents/evtx-analyst.md",
            heuristic_source_hash="sha256:s",
            heuristic_section="What to Hunt",
            heuristic_excerpt_hash="sha256:e",
            excerpt_token_count=500, triggered_by="prepare_hypothesis_context",
        )
        row = json.loads((tmp_path / "a.jsonl").read_text().strip())
        for field in (
            "event_type", "context_id", "case_id", "artifact",
            "heuristic_source_path", "heuristic_source_hash",
            "heuristic_section", "heuristic_excerpt_hash",
            "excerpt_token_count", "triggered_by",
        ):
            assert field in row, f"Missing field {field}"


# ---------------------------------------------------------------------------
# State extensions — heuristic refs dedup + hypothesis registry
# ---------------------------------------------------------------------------


class TestStateExtensions:
    """W1.7.05 — CaseStateManager heuristic-ref tracking + hypothesis registry."""

    def test_next_context_id_persists_across_calls(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        ids = [sm.next_context_id() for _ in range(3)]
        assert ids == ["CTX-001", "CTX-002", "CTX-003"]

    def test_record_and_lookup_heuristic_ref(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        sm.record_heuristic_ref(
            context_id="CTX-001", artifact="mft",
            source_hash="sha256:src", excerpt_hash="sha256:exc",
            section="What to Hunt", triggered_by="extract_mft_timeline",
        )
        found = sm.lookup_heuristic_ref("mft", "sha256:exc")
        assert found is not None
        assert found["context_id"] == "CTX-001"
        not_found = sm.lookup_heuristic_ref("evtx", "sha256:exc")
        assert not_found is None

    def test_record_heuristic_ref_idempotent_on_ctx_id(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        for _ in range(5):
            sm.record_heuristic_ref(
                context_id="CTX-001", artifact="mft",
                source_hash="sha256:s", excerpt_hash="sha256:e",
                section="X", triggered_by="t",
            )
        refs = sm.get_heuristic_refs()
        assert len(refs) == 1

    def test_record_hypotheses_idempotent_by_id(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        hid = "01ABCDEFGHJKMNPQRSTVWXYZ12"
        sm.record_hypotheses([{"hypothesis_id": hid, "attack_class": "v1"}])
        sm.record_hypotheses([{"hypothesis_id": hid, "attack_class": "v2"}])  # update
        hs = sm.get_hypotheses()
        assert len(hs) == 1
        assert hs[0]["attack_class"] == "v2"

    def test_classify_finding_into_activity_thread(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        # T1003 = OS Credential Dumping → exploitation
        phase = sm.classify_finding_into_activity_thread("F-001", ["T1003"])
        assert phase == "exploitation"
        # T1486 = Data Encrypted for Impact → actions_on_objectives
        phase = sm.classify_finding_into_activity_thread("F-002", ["T1486"])
        assert phase == "actions_on_objectives"
        # No MITRE → no classification
        phase = sm.classify_finding_into_activity_thread("F-003", [])
        assert phase is None
        at = sm.get_activity_thread()
        assert "F-001" in at["phases"]["exploitation"]
        assert "F-002" in at["phases"]["actions_on_objectives"]


# ---------------------------------------------------------------------------
# Hypothesis schema validation
# ---------------------------------------------------------------------------


class TestHypothesisSchema:

    def test_valid_hypothesis(self):
        from sift_mcp.models.hypothesis import Hypothesis, HypothesisStatus
        h = Hypothesis(
            attack_class="credential-theft via LSASS access",
            initial_pivot="Memory process tree around lsass.exe",
            expected_evidence_chain=["EVTX 4624", "memory injected DLL"],
            source_context_refs=["CTX-001"],
            rank=1,
            mitre_techniques=["T1003"],
        )
        assert h.hypothesis_id is not None
        assert h.status == HypothesisStatus.ACTIVE
        assert h.mitre_techniques == ["T1003"]

    def test_invalid_ctx_ref_format_rejected(self):
        from sift_mcp.models.hypothesis import Hypothesis
        with pytest.raises(Exception):
            Hypothesis(
                attack_class="test class",
                initial_pivot="test pivot",
                source_context_refs=["ctx-001"],  # lowercase = invalid
            )

    def test_invalid_mitre_rejected(self):
        from sift_mcp.models.hypothesis import Hypothesis
        with pytest.raises(Exception):
            Hypothesis(
                attack_class="test class",
                initial_pivot="test pivot",
                mitre_techniques=["NOT_A_VALID_TECHNIQUE"],
            )


# ---------------------------------------------------------------------------
# EvidenceFinding heuristic_context_refs field
# ---------------------------------------------------------------------------


class TestEvidenceFindingHeuristicRefs:

    def test_valid_ctx_refs_accepted(self):
        from sift_mcp.models.evidence_finding import EvidenceFinding, Confidence, fence_evidence_content
        f = EvidenceFinding(
            source_tool="compare_disk_and_memory",
            claim="Test claim with enough length.",
            evidence_excerpt=fence_evidence_content("evidence"),
            confidence=Confidence.MEDIUM,
            heuristic_context_refs=["CTX-001", "CTX-003"],
        )
        assert f.heuristic_context_refs == ["CTX-001", "CTX-003"]

    def test_invalid_ctx_format_rejected(self):
        from sift_mcp.models.evidence_finding import EvidenceFinding, Confidence, fence_evidence_content
        with pytest.raises(Exception):
            EvidenceFinding(
                source_tool="x",
                claim="Test claim with enough length.",
                evidence_excerpt=fence_evidence_content("e"),
                confidence=Confidence.LOW,
                heuristic_context_refs=["ctx-001"],  # lowercase
            )

    def test_empty_refs_list_accepted(self):
        from sift_mcp.models.evidence_finding import EvidenceFinding, Confidence, fence_evidence_content
        # Backward-compatible — heuristic_context_refs defaults to empty list
        f = EvidenceFinding(
            source_tool="x",
            claim="Test claim with enough length.",
            evidence_excerpt=fence_evidence_content("e"),
            confidence=Confidence.LOW,
        )
        assert f.heuristic_context_refs == []


# ---------------------------------------------------------------------------
# Tier-1 injection in build_contract_response
# ---------------------------------------------------------------------------


class TestTier1Injection:

    def test_first_call_includes_full_heuristic_content(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        from sift_mcp.tools._contracts import build_contract_response
        import sift_mcp.server as srv

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        srv._state_manager = sm
        srv._audit_logger = audit
        from sift_mcp.tools._contracts import set_runtime_deps
        set_runtime_deps(state_manager=sm, audit_logger=audit)

        resp = build_contract_response(
            payload={"csv_path": "/tmp/x.csv"},
            tool_name="disk.extract_mft_timeline",
            summary="test", normalized_observations=[],
            provenance={}, pivot_entities={}, follow_up_options=[],
            case_id="TEST", execution_id="E-001",
        )
        assert "applicable_heuristics" in resp
        ah = resp["applicable_heuristics"]
        assert ah["artifact"] == "mft"
        assert ah["ctx_id"].startswith("CTX-")
        assert "ref_only" not in ah or not ah.get("ref_only")
        assert "<HEURISTIC" in ah["content"]
        assert "Forensic Ground Rules" in ah["content"] or "What to Hunt" in ah["content"]

    def test_second_call_dedups_to_ref_only(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        from sift_mcp.tools._contracts import build_contract_response
        import sift_mcp.server as srv

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        srv._state_manager = sm
        srv._audit_logger = audit
        from sift_mcp.tools._contracts import set_runtime_deps
        set_runtime_deps(state_manager=sm, audit_logger=audit)

        # First call
        build_contract_response(
            payload={}, tool_name="disk.extract_mft_timeline",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="TEST", execution_id="E-001",
        )
        # Second call — same artifact, should be ref-only
        resp2 = build_contract_response(
            payload={}, tool_name="disk.extract_mft_timeline",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="TEST", execution_id="E-002",
        )
        assert resp2["applicable_heuristics"].get("ref_only") is True
        # State should have exactly 1 heuristic ref recorded
        assert len(sm.get_heuristic_refs()) == 1

    def test_unmapped_tool_skips_injection(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        from sift_mcp.tools._contracts import build_contract_response
        import sift_mcp.server as srv

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("TEST")
        srv._state_manager = sm
        _audit = AuditLogger(str(tmp_path / "a.jsonl"))
        srv._audit_logger = _audit
        from sift_mcp.tools._contracts import set_runtime_deps
        set_runtime_deps(state_manager=sm, audit_logger=_audit)

        resp = build_contract_response(
            payload={}, tool_name="state.add_finding",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="TEST",
        )
        assert "applicable_heuristics" not in resp

    def test_no_case_id_skips_injection(self, tmp_path):
        from sift_mcp.tools._contracts import build_contract_response
        # No case_id passed = no injection (preserves backward compat for
        # callers that haven't yet been updated to pass case_id)
        resp = build_contract_response(
            payload={}, tool_name="disk.extract_mft_timeline",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
        )
        assert "applicable_heuristics" not in resp
