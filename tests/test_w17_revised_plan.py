"""Tests for the W1.7 CR-revised plan (2026-05-23) — full bug-fix landing.

Covers:
- BUG-1 wiring tripwire: every build_contract_response caller passes case_id=
- BUG-1 behavioral integration: contract-tool response contains applicable_heuristics
- BUG-1 coverage completeness: every _HEURISTIC_ARTIFACT_FOR_TOOL key is injection-capable
- Activity-thread classification fires from CaseStateManager.add_finding
- Activity-thread MITRE field normalization (singular + list)
- Hypothesis gate: triage no-op, evidence trigger, env-var escape hatch
"""
from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

# fastmcp stub
if "fastmcp" not in sys.modules:
    import types
    fastmcp_stub = types.ModuleType("fastmcp")

    class _Stub:
        def __init__(self, *a, **k): pass
        def tool(self, *a, **k):
            def _w(fn): return fn
            return _w
        def resource(self, *a, **k):
            def _w(fn): return fn
            return _w
        def run(self, *a, **k): pass

    fastmcp_stub.FastMCP = _Stub
    sys.modules["fastmcp"] = fastmcp_stub

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class TestBug1WiringTripwire:
    """Every build_contract_response() call in disk.py / memory.py must pass
    case_id= so Tier-1 heuristic injection actually fires. AST-level check.
    """

    @pytest.mark.parametrize("filename", ["sift_mcp/tools/disk.py", "sift_mcp/tools/memory.py"])
    def test_every_build_contract_response_call_passes_case_id(self, filename):
        path = ROOT / filename
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                if name != "build_contract_response":
                    continue
                kwargs = {kw.arg for kw in node.keywords if kw.arg}
                if "case_id" not in kwargs:
                    violations.append(
                        f"{filename}:{node.lineno} missing case_id="
                    )
        assert violations == [], (
            f"build_contract_response calls without case_id= would silently "
            f"skip W1.7 heuristic injection: {violations}"
        )


class TestBug1BehavioralIntegration:
    """End-to-end: a contract-tool response should contain applicable_heuristics
    when case_id + execution_id are supplied + state is loaded.
    """

    def _setup_state(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        from sift_mcp.tools._contracts import set_runtime_deps

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("BUG1-INTEG-TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        # W1.7 Run-2 fix: register via the production DI path, not srv singleton patching.
        # The lazy `from sift_mcp.server import _state_manager` was deleted by review review.
        set_runtime_deps(state_manager=sm, audit_logger=audit)
        return sm, audit

    def test_contract_response_injects_heuristics_for_mft(self, tmp_path):
        from sift_mcp.tools._contracts import build_contract_response
        sm, audit = self._setup_state(tmp_path)
        resp = build_contract_response(
            payload={"csv_path": "/tmp/mft.csv", "execution_id": "E-001"},
            tool_name="disk.extract_mft_timeline",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="BUG1-INTEG-TEST",
            execution_id="E-001",
        )
        assert "applicable_heuristics" in resp, "MFT contract response missing injection"
        ah = resp["applicable_heuristics"]
        assert ah["artifact"] == "mft"
        assert ah["ctx_id"].startswith("CTX-")
        assert "<HEURISTIC" in ah["content"]

    def test_contract_response_injects_heuristics_for_detect_injection(self, tmp_path):
        from sift_mcp.tools._contracts import build_contract_response
        sm, audit = self._setup_state(tmp_path)
        resp = build_contract_response(
            payload={"execution_id": "E-002"},
            tool_name="memory.detect_injection",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="BUG1-INTEG-TEST",
            execution_id="E-002",
        )
        assert "applicable_heuristics" in resp
        assert resp["applicable_heuristics"]["artifact"] == "memory"

    def test_audit_jsonl_records_context_bundle(self, tmp_path):
        """Run-2 BUG-4 tripwire (review review 2026-05-24): assert audit
        AND state record together — the original Run-1 test only checked
        audit, exactly why BUG-4 shipped to production. Audit-without-state
        means CTX provenance is broken even though it looks fine.
        """
        from sift_mcp.tools._contracts import build_contract_response
        import json
        sm, audit = self._setup_state(tmp_path)
        build_contract_response(
            payload={"execution_id": "E-003"},
            tool_name="disk.extract_mft_timeline",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="BUG1-INTEG-TEST",
            execution_id="E-003",
        )
        audit_lines = (tmp_path / "a.jsonl").read_text().splitlines()
        ctx_rows = [
            json.loads(l) for l in audit_lines
            if json.loads(l).get("event_type") == "context_bundle"
        ]
        assert len(ctx_rows) >= 1
        assert ctx_rows[0]["artifact"] == "mft"
        assert ctx_rows[0]["context_id"].startswith("CTX-")
        # PARITY assertion — BUG-4 regression tripwire
        state_refs = sm.get_heuristic_refs()
        assert len(state_refs) >= 1, (
            "BUG-4 regression: audit context_bundle row written but "
            "state.heuristic_refs_loaded is empty. State write was lost."
        )
        # CTX must match between audit + state
        audit_ctx_ids = {r["context_id"] for r in ctx_rows}
        state_ctx_ids = {r["context_id"] for r in state_refs}
        assert audit_ctx_ids == state_ctx_ids, (
            f"CTX parity broken: audit has {audit_ctx_ids}, state has {state_ctx_ids}"
        )


class TestBug4ParityRegression:
    """Run-2 review 2026-05-24 (Q3 D): unit doubles + 1 integration test
    proving CONTRACT-path injection writes BOTH audit and state. This is the
    test BUG-4 needed before shipping.
    """

    def test_unit_doubles_parity(self):
        """Unit: register fake state/audit deps via set_runtime_deps, call
        build_contract_response, assert one CTX allocation, one audit row,
        one state ref, same CTX. Second call same artifact → ref_only=True,
        ref count still 1.
        """
        from sift_mcp.tools._contracts import (
            build_contract_response,
            set_runtime_deps,
        )

        # Fake state + audit doubles
        class FakeState:
            def __init__(self):
                self.refs = []
                self.counter = 0
                self.case_id = "DOUBLES-TEST"
            def next_context_id(self):
                self.counter += 1
                return f"CTX-{self.counter:03d}"
            def lookup_heuristic_ref(self, artifact, excerpt_hash):
                for r in self.refs:
                    if r["artifact"] == artifact and r["excerpt_hash"] == excerpt_hash:
                        return r
                return None
            def record_heuristic_ref(self, **kwargs):
                self.refs.append(kwargs)

        class FakeAudit:
            def __init__(self):
                self.rows = []
            def log_context_bundle(self, **kwargs):
                self.rows.append(kwargs)

        fake_state = FakeState()
        fake_audit = FakeAudit()
        set_runtime_deps(state_manager=fake_state, audit_logger=fake_audit)
        try:
            # First call — should allocate CTX-001
            r1 = build_contract_response(
                payload={"execution_id": "E-001"},
                tool_name="disk.extract_mft_timeline",
                summary="t", normalized_observations=[], provenance={},
                pivot_entities={}, follow_up_options=[],
                case_id="DOUBLES-TEST",
                execution_id="E-001",
            )
            assert "applicable_heuristics" in r1
            assert r1["applicable_heuristics"]["ctx_id"] == "CTX-001"
            assert len(fake_state.refs) == 1, "state ref not recorded"
            assert len(fake_audit.rows) == 1, "audit row not recorded"
            assert fake_state.refs[0]["context_id"] == fake_audit.rows[0]["context_id"]

            # Second call same artifact — ref_only, NO new CTX, NO new audit row
            r2 = build_contract_response(
                payload={"execution_id": "E-002"},
                tool_name="disk.extract_mft_timeline",
                summary="t", normalized_observations=[], provenance={},
                pivot_entities={}, follow_up_options=[],
                case_id="DOUBLES-TEST",
                execution_id="E-002",
            )
            assert r2["applicable_heuristics"]["ref_only"] is True
            assert r2["applicable_heuristics"]["ctx_id"] == "CTX-001"  # same as first
            assert len(fake_state.refs) == 1, "dedup broken: extra state write"
            assert len(fake_audit.rows) == 1, "dedup broken: extra audit row"
        finally:
            # Restore — don't leak fakes into other tests
            set_runtime_deps(state_manager=None, audit_logger=None)

    def test_integration_real_singleton_parity(self, tmp_path):
        """Integration: simulate init_all_tools path → register the real
        CaseStateManager + AuditLogger, call build_contract_response,
        assert audit COUNT == heuristic_refs_loaded COUNT, monotonic CTX,
        WITHOUT patching srv._state_manager (the way the production gap was
        previously hidden by tests).
        """
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        from sift_mcp.tools._contracts import (
            build_contract_response,
            set_runtime_deps,
        )

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("PARITY-TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        set_runtime_deps(state_manager=sm, audit_logger=audit)
        try:
            tools_artifacts = [
                ("disk.extract_mft_timeline", "mft"),
                ("disk.extract_prefetch", "prefetch"),
                ("disk.get_amcache", "amcache"),
                ("disk.summarize_evtx", "evtx"),
                ("disk.extract_registry_run_keys", "registry"),
            ]
            for i, (tool, art) in enumerate(tools_artifacts, start=1):
                resp = build_contract_response(
                    payload={"execution_id": f"E-{i:03d}"},
                    tool_name=tool,
                    summary="t", normalized_observations=[], provenance={},
                    pivot_entities={}, follow_up_options=[],
                    case_id="PARITY-TEST",
                    execution_id=f"E-{i:03d}",
                )
                assert "applicable_heuristics" in resp, f"injection skipped for {tool}"
                assert resp["applicable_heuristics"]["artifact"] == art

            # PARITY: audit count == state count
            import json as _json
            audit_ctx_rows = [
                _json.loads(l) for l in (tmp_path / "a.jsonl").read_text().splitlines()
                if _json.loads(l).get("event_type") == "context_bundle"
            ]
            state_refs = sm.get_heuristic_refs()
            assert len(audit_ctx_rows) == len(state_refs), (
                f"PARITY BROKEN: {len(audit_ctx_rows)} audit rows vs "
                f"{len(state_refs)} state refs — this is the Run-2 BUG-4 symptom"
            )
            # Monotonic CTX
            ctx_ids = [r["context_id"] for r in state_refs]
            for i, cid in enumerate(ctx_ids, start=1):
                assert cid == f"CTX-{i:03d}", (
                    f"BUG-5 regression: CTX ids not monotonic. Got {ctx_ids}"
                )
            # No collision — each artifact has its own unique CTX
            artifacts_per_ctx = {r["context_id"]: r["artifact"] for r in state_refs}
            assert len(set(artifacts_per_ctx.values())) == len(artifacts_per_ctx), (
                f"BUG-5: CTX collision — same ctx_id assigned to different artifacts: "
                f"{artifacts_per_ctx}"
            )
        finally:
            set_runtime_deps(state_manager=None, audit_logger=None)

    def test_missing_deps_emits_visible_diagnostic(self, tmp_path):
        """review mandate (review Q1 fail-visible): missing runtime deps must
        produce applicable_heuristics_skipped_reason, NOT silent skip.
        """
        from sift_mcp.tools._contracts import (
            build_contract_response,
            set_runtime_deps,
        )
        set_runtime_deps(state_manager=None, audit_logger=None)  # ensure unregistered
        resp = build_contract_response(
            payload={"execution_id": "E-001"},
            tool_name="disk.extract_mft_timeline",
            summary="t", normalized_observations=[], provenance={},
            pivot_entities={}, follow_up_options=[],
            case_id="MISSING-DEPS-TEST",
            execution_id="E-001",
        )
        assert "applicable_heuristics" not in resp
        assert "applicable_heuristics_skipped_reason" in resp, (
            "Missing deps must be fail-visible, not silently skipped"
        )
        assert "missing_runtime_deps" in resp["applicable_heuristics_skipped_reason"]


class TestRun3MCPContractFixes:
    """Run-3 review 2026-05-24 (design review): MCP contract bugs that
    caused 0 CONFIRMED in Run 3 despite agent calling synthesis tools.

    BUG-7: submit_finding/add_finding missing corroborated_by param
    BUG-8: find_temporal_clusters function existed but not registered as MCP tool
    Step 4: confirmed_eligibility response field for instant self-correction
    """

    def test_submit_finding_accepts_corroborated_by(self):
        import inspect
        import sift_mcp.server as srv
        sig = inspect.signature(srv.submit_finding)
        assert "corroborated_by" in sig.parameters, (
            "BUG-7 regression: submit_finding must accept corroborated_by"
        )

    def test_add_finding_accepts_corroborated_by(self):
        import inspect
        import sift_mcp.server as srv
        sig = inspect.signature(srv.add_finding)
        assert "corroborated_by" in sig.parameters, (
            "BUG-7 regression: add_finding must accept corroborated_by for parity"
        )

    def test_find_temporal_clusters_registered_as_mcp_tool(self):
        import sift_mcp.server as srv
        assert hasattr(srv, "find_temporal_clusters"), (
            "BUG-8 regression: find_temporal_clusters not exposed as MCP tool. "
            "Run-3 agent searched ToolSearch, got 'no match', closed synthesis "
            "lane with finding_ids=[]"
        )
        # Verify catalog also registered
        from sift_mcp.tool_catalog import TOOL_CATALOG
        assert "correlation.find_temporal_clusters" in TOOL_CATALOG, (
            "find_temporal_clusters in server but not in tool_catalog — describe_tool_catalog won't surface it"
        )

    def test_corroborated_by_persists_via_submit_finding(self, tmp_path):
        import sift_mcp.server as srv
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("CORR-TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        srv._state_manager = sm
        srv._audit_logger = audit

        sm.add_execution({"execution_id": "E-001", "tool_name": "t", "iteration": 1, "command_line": "x", "parameters": {}})
        f1 = sm.add_finding({
            "case_id": "CORR-TEST", "finding_type": "ioc", "artifact_type": "disk",
            "artifact_path": "/x", "tool_name": "t", "execution_id": "E-001",
            "iteration": 1, "evidence_kind": "observation", "confidence": 0.7,
            "description": "Source finding for corroboration regression test suite",
        })
        result = srv.submit_finding(
            case_id="CORR-TEST", lane_id="synthesis_corroboration",
            assigned_agent="main-agent", finding_type="ioc",
            artifact_type="correlation", evidence_kind="inference",
            description="Synthesis finding citing source",
            confidence=0.85, source_execution_id="E-001",
            corroborated_by=[f1],
        )
        assert result["status"] == "ok"
        assert result["finding"].get("corroborated_by") == [f1]

    def test_confirmed_eligibility_in_response_when_high_confidence(self, tmp_path):
        import sift_mcp.server as srv
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("ELIG-TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        srv._state_manager = sm
        srv._audit_logger = audit

        sm.add_execution({"execution_id": "E-001", "tool_name": "t", "iteration": 1, "command_line": "x", "parameters": {}})
        result = srv.submit_finding(
            case_id="ELIG-TEST", lane_id="memory",
            assigned_agent="main-agent", finding_type="ioc",
            artifact_type="memory", evidence_kind="observation",
            artifact_path="/evidence/memory.img",
            description="High-confidence finding submitted without A2 alternative-hypothesis fields",
            confidence=0.9, source_execution_id="E-001",
            status="CONFIRMED",  # but missing alt-hypothesis
        )
        assert "confirmed_eligibility" in result
        elig = result["confirmed_eligibility"]
        assert elig["eligible"] is False
        # Should list specific missing fields
        missing_str = " ".join(elig["missing"])
        assert "disposition" in missing_str or "alternative_hypothesis" in missing_str

    def test_confirmed_eligibility_eligible_when_complete(self, tmp_path):
        import sift_mcp.server as srv
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("ELIG-OK")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        srv._state_manager = sm
        srv._audit_logger = audit

        sm.add_execution({"execution_id": "E-001", "tool_name": "t", "iteration": 1, "command_line": "x", "parameters": {}})
        f1 = sm.add_finding({"case_id": "ELIG-OK", "finding_type": "ioc", "artifact_type": "disk", "artifact_path": "/x", "tool_name": "t", "execution_id": "E-001", "iteration": 1, "evidence_kind": "observation", "confidence": 0.7, "description": "First source finding for eligibility test"})
        f2 = sm.add_finding({"case_id": "ELIG-OK", "finding_type": "ioc", "artifact_type": "disk", "artifact_path": "/y", "tool_name": "t", "execution_id": "E-001", "iteration": 1, "evidence_kind": "observation", "confidence": 0.7, "description": "Second source finding for eligibility test"})
        result = srv.submit_finding(
            case_id="ELIG-OK", lane_id="synthesis_corroboration",
            assigned_agent="main-agent", finding_type="persistence",
            artifact_type="correlation", evidence_kind="inference",
            description="Complete synthesis finding with full A2 bundle",
            confidence=0.9, source_execution_id="E-001",
            status="CONFIRMED",
            corroborated_by=[f1, f2],
            alternative_hypothesis="Benign explanation",
            evidence_against_it=["Observation that rules out benign"],
            disposition="ruled_out",
        )
        elig = result["confirmed_eligibility"]
        assert elig["eligible"] is True, f"Should be eligible but: {elig}"
        assert result["finding"]["finding_status"] == "CONFIRMED"


class TestHypothesisGateSurvivesAllowPartial:
    """Q4 (design review): hypothesis gate must fire even when
    generate_report is called with allow_partial=True. Run 2's failure
    mode was the agent escaping via allow_partial=True to bypass a
    stuck synthesis delegate, which silently disabled all quality gates
    including hypothesis formation.
    """

    def test_hypothesis_gate_fires_under_allow_partial(self, tmp_path, unbypass_hypothesis_gate):
        """End-to-end: allow_partial=True with meaningful evidence + zero
        hypotheses → generate_report_payload returns needs_hypothesis, NOT
        a finalized report.
        """
        from sift_mcp.state import CaseStateManager
        from sift_mcp.reporting import generate_report_payload

        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("PARTIAL-TEST")
        # Seed meaningful evidence: 30 findings, 1 CONFIRMED
        sm.add_execution({"execution_id": "E-001", "tool_name": "t", "iteration": 1, "command_line": "x", "parameters": {}})
        for i in range(30):
            sm.add_finding({
                "case_id": "PARTIAL-TEST",
                "finding_type": "ioc",
                "artifact_type": "disk",
                "artifact_path": "/x.csv",
                "tool_name": "t",
                "execution_id": "E-001",
                "iteration": 1,
                "evidence_kind": "observation",
                "confidence": 0.9 if i == 0 else 0.7,
                "finding_status": "CONFIRMED" if i == 0 else "ACTIVE",
                "description": f"Test partial-mode finding number {i} for hypothesis gate",
            })

        report_dir = tmp_path / "reports" / "PARTIAL-TEST"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "graph.json").write_text("{}", encoding="utf-8")
        result = generate_report_payload(
            case_id="PARTIAL-TEST",
            state_manager=sm,
            sigma_scan_fn=lambda case_id: {"status": "ok", "total_hits": 5, "critical_count": 0, "high_count": 0, "summary_markdown": ""},
            coverage_fn=lambda case_id: {"covered_tactics": [], "uncovered_tactics": [], "coverage_percent": 0.0, "suggested_next_tools": {}},
            reports_root=str(tmp_path / "reports"),
            delegate_path=str(tmp_path / "no_delegate.json"),
            allow_partial=True,  # <-- key: agent's emergency escape
        )
        # Per Q4 review: hypothesis gate runs even under allow_partial
        assert result.get("status") == "needs_hypothesis", (
            f"Q4 regression: allow_partial=True bypassed hypothesis gate. Got: {result.get('status')}"
        )


class TestBug1CoverageCompleteness:
    """Every key in _HEURISTIC_ARTIFACT_FOR_TOOL must be injection-capable
    via EITHER the contract path OR the centralized finalize path.

    Verification approach (per design review): unit-level capability check —
    confirm _resolve_heuristic_artifact returns non-None for each mapped key
    and the underlying extract_tier1_slice returns valid content for each
    mapped artifact. This validates the MAP is wired, not that each specific
    tool produces CTX in a real run (some tools only fire when invoked).
    """

    def test_every_mapped_tool_resolves_to_an_artifact(self):
        from sift_mcp.tools._contracts import (
            _HEURISTIC_ARTIFACT_FOR_TOOL,
            _resolve_heuristic_artifact,
        )
        unresolved = []
        for tool_name, expected_artifact in _HEURISTIC_ARTIFACT_FOR_TOOL.items():
            resolved = _resolve_heuristic_artifact(tool_name)
            if resolved != expected_artifact:
                unresolved.append(f"{tool_name} → expected {expected_artifact}, got {resolved}")
        assert unresolved == [], f"Mapping resolution gaps: {unresolved}"

    def test_every_mapped_artifact_has_extractable_slice(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import extract_heuristic_slice as ex
        from sift_mcp.tools._contracts import _HEURISTIC_ARTIFACT_FOR_TOOL
        artifacts = set(_HEURISTIC_ARTIFACT_FOR_TOOL.values())
        gaps = []
        for art in artifacts:
            try:
                slc = ex.extract_tier1_slice(art)
                if not slc or not slc.get("section_found"):
                    gaps.append(art)
            except Exception as e:
                gaps.append(f"{art} (exc: {e})")
        assert gaps == [], f"Mapped artifacts without extractable Tier-1 slice: {gaps}"

    def test_finalize_tool_response_has_injection_call(self):
        """Server.py:_finalize_tool_response must invoke _attach_heuristic_slice
        so the 11 non-contract tools also get heuristics. AST-level guarantee
        independent of runtime state.
        """
        src = (ROOT / "sift_mcp" / "server.py").read_text(encoding="utf-8")
        # Find the _finalize_tool_response function body
        m = re.search(
            r"def _finalize_tool_response\(.*?\n(.*?)(?=^def |\Z)",
            src, re.DOTALL | re.MULTILINE,
        )
        assert m, "_finalize_tool_response not found in server.py"
        body = m.group(1)
        assert "_attach_heuristic_slice" in body, (
            "_finalize_tool_response must call _attach_heuristic_slice "
            "so the 11 non-contract tools get Tier-1 heuristic injection"
        )
        assert "state_manager=_state_manager" in body, (
            "Centralized injection must pass state_manager as dep (review guard d)"
        )
        assert "audit_logger=_audit_logger" in body, (
            "Centralized injection must pass audit_logger as dep (review guard d)"
        )


class TestActivityThreadAutoClassification:
    """activity_thread.phases must populate when CaseStateManager.add_finding
    receives a finding with MITRE techniques. Catches the Run-1 wiring gap.
    """

    def test_add_finding_with_mitre_list_classifies_into_thread(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("AT-TEST")
        sm.add_execution({
            "execution_id": "E-001",
            "tool_name": "test",
            "iteration": 1,
            "command_line": "x",
            "parameters": {},
        })
        fid = sm.add_finding({
            "case_id": "AT-TEST",
            "finding_type": "ioc",
            "artifact_type": "disk",
            "artifact_path": "/x.csv",
            "tool_name": "test",
            "execution_id": "E-001",
            "iteration": 1,
            "evidence_kind": "observation",
            "confidence": 0.7,
            "description": "Test finding with MITRE list",
            "mitre_techniques": ["T1003"],
        })
        at = sm.get_activity_thread()
        assert fid in at["phases"].get("exploitation", []), \
            f"add_finding did not classify T1003 → exploitation; got {at['phases']}"

    def test_add_finding_with_singular_mitre_technique_normalized(self, tmp_path):
        """Legacy Finding model uses singular `mitre_technique` (string).
        Per review: the normalizer must accept BOTH conventions or classification
        silently no-ops on most extraction-tool findings.
        """
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("AT-TEST")
        sm.add_execution({"execution_id": "E-001", "tool_name": "test", "iteration": 1, "command_line": "x", "parameters": {}})
        fid = sm.add_finding({
            "case_id": "AT-TEST",
            "finding_type": "ioc",
            "artifact_type": "disk",
            "artifact_path": "/x.csv",
            "tool_name": "test",
            "execution_id": "E-001",
            "iteration": 1,
            "evidence_kind": "observation",
            "confidence": 0.7,
            "description": "Test legacy singular field",
            "mitre_technique": "T1041",  # singular legacy field
        })
        at = sm.get_activity_thread()
        assert fid in at["phases"].get("actions_on_objectives", []), \
            f"singular mitre_technique not normalized; got {at['phases']}"

    def test_update_finding_reclassifies_when_mitre_added(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("AT-TEST")
        sm.add_execution({"execution_id": "E-001", "tool_name": "test", "iteration": 1, "command_line": "x", "parameters": {}})
        fid = sm.add_finding({
            "case_id": "AT-TEST",
            "finding_type": "ioc",
            "artifact_type": "disk",
            "artifact_path": "/x.csv",
            "tool_name": "test",
            "execution_id": "E-001",
            "iteration": 1,
            "evidence_kind": "observation",
            "confidence": 0.7,
            "description": "no mitre initially",
        })
        at = sm.get_activity_thread()
        assert all(fid not in v for v in at["phases"].values())
        # Now add MITRE — should classify on update
        sm.update_finding(fid, mitre_techniques=["T1486"])  # ransomware → actions
        at = sm.get_activity_thread()
        assert fid in at["phases"].get("actions_on_objectives", [])


class TestHypothesisGate:

    def _stub_state(self, tmp_path, hypotheses=None):
        from sift_mcp.state import CaseStateManager
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("HG-TEST")
        if hypotheses:
            sm.record_hypotheses(hypotheses)
        return sm

    def test_below_threshold_is_noop(self, tmp_path, unbypass_hypothesis_gate):
        from sift_mcp.reporting import evaluate_hypothesis_gate
        sm = self._stub_state(tmp_path)
        result = evaluate_hypothesis_gate(
            case_id="HG-TEST",
            state_manager=sm,
            findings_count=5,
            confirmed_count=0,
            sigma_result=None,
        )
        assert result["status"] == "ok"
        assert result["reason"] == "below_evidence_threshold"

    def test_confirmed_finding_triggers_gate_when_no_hypotheses(self, tmp_path, unbypass_hypothesis_gate):
        from sift_mcp.reporting import evaluate_hypothesis_gate
        sm = self._stub_state(tmp_path)
        result = evaluate_hypothesis_gate(
            case_id="HG-TEST",
            state_manager=sm,
            findings_count=571,
            confirmed_count=7,
            sigma_result={"status": "ok", "total_hits": 12},
        )
        assert result["status"] == "needs_hypothesis"
        assert result["next_required_tool"] == "prepare_hypothesis_context"
        assert "record_hypotheses" in result["next_required_tool_chain"]
        assert result["allow_partial_hint"] is True

    def test_findings_threshold_triggers_when_no_confirmed(self, tmp_path, unbypass_hypothesis_gate):
        from sift_mcp.reporting import evaluate_hypothesis_gate
        sm = self._stub_state(tmp_path)
        result = evaluate_hypothesis_gate(
            case_id="HG-TEST",
            state_manager=sm,
            findings_count=30,
            confirmed_count=0,
            sigma_result=None,
        )
        assert result["status"] == "needs_hypothesis"

    def test_hypotheses_recorded_passes_gate(self, tmp_path, unbypass_hypothesis_gate):
        from sift_mcp.reporting import evaluate_hypothesis_gate
        sm = self._stub_state(tmp_path, hypotheses=[{
            "hypothesis_id": "01ABCDEFGHJKMNPQRSTVWXYZ12",
            "attack_class": "test",
            "initial_pivot": "test pivot",
            "expected_evidence_chain": ["x"],
            "rank": 1,
        }])
        result = evaluate_hypothesis_gate(
            case_id="HG-TEST",
            state_manager=sm,
            findings_count=571,
            confirmed_count=7,
            sigma_result=None,
        )
        assert result["status"] == "ok"
        assert result["hypothesis_count"] == 1

    def test_env_var_escape_hatch_bypasses(self, tmp_path, monkeypatch):
        from sift_mcp.reporting import evaluate_hypothesis_gate
        monkeypatch.setenv("SAVVYDFIR_SKIP_HYPOTHESIS_GATE", "1")
        sm = self._stub_state(tmp_path)
        result = evaluate_hypothesis_gate(
            case_id="HG-TEST",
            state_manager=sm,
            findings_count=571,
            confirmed_count=7,
            sigma_result=None,
        )
        assert result["status"] == "ok"
        assert result["reason"] == "bypassed_via_env_var"
        assert result["bypass_audited"] is True

    def test_env_var_not_set_does_not_bypass(self, tmp_path, monkeypatch, unbypass_hypothesis_gate):
        from sift_mcp.reporting import evaluate_hypothesis_gate
        monkeypatch.delenv("SAVVYDFIR_SKIP_HYPOTHESIS_GATE", raising=False)
        sm = self._stub_state(tmp_path)
        result = evaluate_hypothesis_gate(
            case_id="HG-TEST",
            state_manager=sm,
            findings_count=571,
            confirmed_count=7,
            sigma_result=None,
        )
        assert result["status"] == "needs_hypothesis"


class TestAttachHeuristicSliceGuards:
    """All 4 guards on _attach_heuristic_slice (per design review review)."""

    def _setup(self, tmp_path):
        from sift_mcp.state import CaseStateManager
        from sift_mcp.audit import AuditLogger
        sm = CaseStateManager(state_path=str(tmp_path / "s.json"))
        sm.load("AHS-TEST")
        audit = AuditLogger(str(tmp_path / "a.jsonl"))
        return sm, audit

    def test_guard_a_already_present_skips(self, tmp_path):
        from sift_mcp.tools._contracts import _attach_heuristic_slice
        sm, audit = self._setup(tmp_path)
        resp = {"applicable_heuristics": {"artifact": "mft", "ctx_id": "CTX-999", "ref_only": True}}
        _attach_heuristic_slice(
            resp, tool_name="disk.extract_mft_timeline",
            case_id="AHS-TEST", execution_id="E-001",
            state_manager=sm, audit_logger=audit,
        )
        # Must not overwrite — still CTX-999, not a new one
        assert resp["applicable_heuristics"]["ctx_id"] == "CTX-999"

    def test_guard_b_no_execution_id_skips(self, tmp_path):
        from sift_mcp.tools._contracts import _attach_heuristic_slice
        sm, audit = self._setup(tmp_path)
        resp = {}
        _attach_heuristic_slice(
            resp, tool_name="disk.extract_mft_timeline",
            case_id="AHS-TEST", execution_id="",
            state_manager=sm, audit_logger=audit,
        )
        assert "applicable_heuristics" not in resp

    def test_guard_b_e000_execution_id_skips(self, tmp_path):
        from sift_mcp.tools._contracts import _attach_heuristic_slice
        sm, audit = self._setup(tmp_path)
        resp = {}
        _attach_heuristic_slice(
            resp, tool_name="disk.extract_mft_timeline",
            case_id="AHS-TEST", execution_id="E-000",
            state_manager=sm, audit_logger=audit,
        )
        assert "applicable_heuristics" not in resp

    def test_guard_c_unmapped_tool_skips(self, tmp_path):
        from sift_mcp.tools._contracts import _attach_heuristic_slice
        sm, audit = self._setup(tmp_path)
        resp = {}
        _attach_heuristic_slice(
            resp, tool_name="state.add_finding",
            case_id="AHS-TEST", execution_id="E-001",
            state_manager=sm, audit_logger=audit,
        )
        assert "applicable_heuristics" not in resp

    def test_guard_d_unknown_case_id_skips(self, tmp_path):
        from sift_mcp.tools._contracts import _attach_heuristic_slice
        sm, audit = self._setup(tmp_path)
        resp = {}
        _attach_heuristic_slice(
            resp, tool_name="disk.extract_mft_timeline",
            case_id="unknown", execution_id="E-001",
            state_manager=sm, audit_logger=audit,
        )
        assert "applicable_heuristics" not in resp

    def test_guard_e_injected_deps_avoid_server_import(self, tmp_path):
        """When state_manager/audit_logger are passed directly, no lazy
        import from sift_mcp.server should be needed (circular-import risk).
        """
        from sift_mcp.tools._contracts import _attach_heuristic_slice
        sm, audit = self._setup(tmp_path)
        resp = {}
        # Should succeed end-to-end without touching server module
        _attach_heuristic_slice(
            resp, tool_name="disk.extract_mft_timeline",
            case_id="AHS-TEST", execution_id="E-001",
            state_manager=sm, audit_logger=audit,
        )
        assert "applicable_heuristics" in resp
        assert resp["applicable_heuristics"]["artifact"] == "mft"
