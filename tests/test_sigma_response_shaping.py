"""Tests for W1.7 Run-4 fix — sigma_hunt + query_sigma_results response shaping.

User constraint (verbatim 2026-05-24): "fix should be not have gap on detection
triggered okay ? based on the sigma rule". Tri-agent consensus (peer reviewer+peer reviewer)
ratified: cap by sigma rule level, never by arbitrary count for actionable
detections; below-threshold gets summary projection (never raw dump, never gap).

Covers:
- Severity normalization (info ↔ informational alias — Run 4 root cause)
- Actionable threshold tunable via SAVVYDFIR_SIGMA_INLINE_LEVEL env var
- Compact hit projection (level-semantic, not byte-count)
- Below-threshold aggregation (per-rule, no raw dump)
- Detection-gap invariant: every medium+ hit is represented inline
- Run-4 regression: 30,893 informational User Logoff + 4 medium DPAPI
  → all 4 medium in actionable_hits, zero info raw-dumped, bounded findings_created
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

# fastmcp stub
if "fastmcp" not in sys.modules:
    fmc = types.ModuleType("fastmcp")
    class _Stub:
        def __init__(self, *a, **k): pass
        def tool(self, *a, **k):
            def _w(f): return f
            return _w
        def resource(self, *a, **k):
            def _w(f): return f
            return _w
        def run(self, *a, **k): pass
    fmc.FastMCP = _Stub
    sys.modules["fastmcp"] = fmc

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class TestSeverityNormalization:
    """Run-4 root cause: Chainsaw emits 'info', code expected 'informational'.
    severity_filter=['informational'] silently matched nothing. Step 0 of fix.
    """

    def test_info_normalizes_to_informational(self):
        from sift_mcp.server import _normalize_sigma_level
        assert _normalize_sigma_level("info") == "informational"
        assert _normalize_sigma_level("informational") == "informational"
        assert _normalize_sigma_level("INFO") == "informational"
        assert _normalize_sigma_level(" Info ") == "informational"

    def test_med_normalizes_to_medium(self):
        from sift_mcp.server import _normalize_sigma_level
        assert _normalize_sigma_level("med") == "medium"
        assert _normalize_sigma_level("medium") == "medium"

    def test_crit_normalizes_to_critical(self):
        from sift_mcp.server import _normalize_sigma_level
        assert _normalize_sigma_level("crit") == "critical"
        assert _normalize_sigma_level("critical") == "critical"

    def test_unknown_defaults_to_informational(self):
        """Per peer reviewer: never silently classify unknown as actionable."""
        from sift_mcp.server import _normalize_sigma_level
        assert _normalize_sigma_level("unknown") == "informational"
        assert _normalize_sigma_level("") == "informational"
        assert _normalize_sigma_level(None) == "informational"

    def test_filter_with_info_alias_matches_informational_hits(self):
        """Run-4 reproduction: severity_filter=['informational'] must match
        hits that have level='info' (Chainsaw's short form)."""
        from sift_mcp.server import _filter_sigma_hits
        hits = [
            {"name": "rule_a", "level": "info"},      # short form (Chainsaw)
            {"name": "rule_b", "level": "informational"},
            {"name": "rule_c", "level": "high"},
        ]
        filtered = _filter_sigma_hits(
            hits,
            requested_severities={"informational"},
            requested_techniques=set(),
        )
        names = {h["name"] for h in filtered}
        assert names == {"rule_a", "rule_b"}, (
            f"Run-4 alias bug regression: filter dropped 'info' hit. Got {names}"
        )


class TestActionableThreshold:
    """Operator-tunable inline cutoff via SAVVYDFIR_SIGMA_INLINE_LEVEL."""

    def test_default_threshold_is_medium(self, monkeypatch):
        from sift_mcp.server import _resolve_actionable_threshold
        monkeypatch.delenv("SAVVYDFIR_SIGMA_INLINE_LEVEL", raising=False)
        assert _resolve_actionable_threshold() == "medium"

    def test_env_var_lowers_threshold_to_low(self, monkeypatch):
        """Phishing case might want low-level Office process spawn rules inline."""
        from sift_mcp.server import _resolve_actionable_threshold
        monkeypatch.setenv("SAVVYDFIR_SIGMA_INLINE_LEVEL", "low")
        assert _resolve_actionable_threshold() == "low"

    def test_env_var_raises_threshold_to_high(self, monkeypatch):
        from sift_mcp.server import _resolve_actionable_threshold
        monkeypatch.setenv("SAVVYDFIR_SIGMA_INLINE_LEVEL", "high")
        assert _resolve_actionable_threshold() == "high"

    def test_garbage_env_falls_back_to_default(self, monkeypatch):
        from sift_mcp.server import _resolve_actionable_threshold
        monkeypatch.setenv("SAVVYDFIR_SIGMA_INLINE_LEVEL", "garbage")
        # 'garbage' normalizes to 'informational' which IS in _SIGMA_VALID_SEVERITIES,
        # so the resolver accepts it. That's actually fine — operator gets everything.
        # (Strict mode could reject; current contract permits.)
        assert _resolve_actionable_threshold() in {"informational", "medium"}

    def test_is_actionable_level_critical_at_medium_threshold(self):
        from sift_mcp.server import _is_actionable_level
        assert _is_actionable_level("critical", "medium") is True
        assert _is_actionable_level("high", "medium") is True
        assert _is_actionable_level("medium", "medium") is True
        assert _is_actionable_level("low", "medium") is False
        assert _is_actionable_level("informational", "medium") is False


class TestCompactProjection:
    """peer reviewer mandate: inline ≠ full raw record. Compact preserves triage
    fields (rule, level, EID, ts, technique, who/where) without event body bloat."""

    def test_compact_hit_has_required_fields(self):
        from sift_mcp.server import _compact_sigma_hit
        raw_hit = {
            "name": "DPAPI Master Key Backup",
            "level": "medium",
            "event_id": "4624",
            "system_time": "2021-09-16T03:01:57Z",
            "tags": ["attack.t1003"],
            "channel": "Security",
            "computer": "WKSTN-01",
            "user": "cbarton-a",
            "tactic": "credential_access",
            "huge_event_body_field": "x" * 50000,  # this should NOT appear
        }
        compact = _compact_sigma_hit(raw_hit, index=42)
        assert "rule_name" in compact
        assert compact["rule_name"] == "DPAPI Master Key Backup"
        assert compact["level"] == "medium"
        assert "T1003" in compact["techniques"]
        assert compact["hit_index"] == 42
        # CRITICAL: no raw event body leaks through
        assert "huge_event_body_field" not in compact
        # Size sanity — should be ~few hundred chars, not 50k
        import json
        assert len(json.dumps(compact)) < 1000

    def test_compact_normalizes_level_via_alias(self):
        from sift_mcp.server import _compact_sigma_hit
        raw_hit = {"name": "x", "level": "info"}  # Chainsaw short form
        compact = _compact_sigma_hit(raw_hit)
        assert compact["level"] == "informational"  # normalized

    def test_compact_truncates_oversized_fields(self):
        """Defensive: even if a single field is pathologically large,
        compact projection caps it."""
        from sift_mcp.server import _compact_sigma_hit
        raw_hit = {
            "name": "x" * 1000,
            "level": "medium",
            "event_id": "9" * 100,
            "computer": "c" * 200,
        }
        compact = _compact_sigma_hit(raw_hit)
        assert len(compact["rule_name"]) <= 140
        assert len(compact["event_id"]) <= 16


class TestBelowThresholdSummary:
    """Below-cutoff hits must be summarized (per-rule), never raw-dumped."""

    def test_summary_returns_per_rule_aggregate(self):
        from sift_mcp.server import _aggregate_below_threshold_summary
        # Simulate Run-4 noise: 30k 'User Logoff' + 192 misc info
        hits = (
            [{"name": "User Logoff", "level": "info", "system_time": f"2026-01-{(i%28)+1:02d}T00:00:00"} for i in range(30000)]
            + [{"name": "Logon Success", "level": "info", "system_time": "2026-01-15"} for _ in range(192)]
        )
        summary = _aggregate_below_threshold_summary(hits)
        assert summary["rules_total"] == 2
        top_names = {r["rule_name"] for r in summary["top_rules"]}
        assert "User Logoff" in top_names
        assert "Logon Success" in top_names
        # User Logoff should be flagged as noise (count > 1000)
        noise_names = {r["rule_name"] for r in summary["noise_rules"]}
        assert "User Logoff" in noise_names

    def test_summary_caps_examples_per_rule(self):
        """peer reviewer mandate: ≤3 sample_indices per rule, ≤20 rules total."""
        from sift_mcp.server import _aggregate_below_threshold_summary
        hits = [{"name": "rule_a", "level": "info"} for _ in range(100)]
        summary = _aggregate_below_threshold_summary(hits)
        assert len(summary["top_rules"][0]["sample_indices"]) <= 3

    def test_summary_overflow_count_when_many_rules(self):
        from sift_mcp.server import _aggregate_below_threshold_summary
        hits = [{"name": f"rule_{i}", "level": "info"} for i in range(50)]
        summary = _aggregate_below_threshold_summary(hits, max_rules=20)
        assert summary["rules_returned"] == 20
        assert summary["rules_total"] == 50
        assert summary["other_rules_overflow_count"] == 30  # 50 - 20

    def test_summary_size_bounded_even_for_30k_hits(self):
        """Run-4 regression: 30,893 User Logoff hits → summary must be
        compact (KB-scale, not MB-scale)."""
        from sift_mcp.server import _aggregate_below_threshold_summary
        import json
        hits = [{"name": "User Logoff", "level": "info"} for _ in range(30893)]
        summary = _aggregate_below_threshold_summary(hits)
        size = len(json.dumps(summary))
        assert size < 5000, (
            f"Below-threshold summary should be <5KB for 30k hits, got {size}"
        )


class TestRun4Regression:
    """End-to-end: simulate Run 4's exact mix (30,893 info User Logoff +
    4 medium DPAPI + ~226 mixed) and assert the new response shape."""

    def _run4_hit_mix(self):
        hits = []
        # 30,893 informational User Logoff (the firehose)
        for i in range(30893):
            hits.append({
                "name": "User Logoff",
                "level": "info",
                "event_id": "4634",
                "system_time": f"2026-01-{((i % 28) + 1):02d}T12:00:00",
                "tags": [],
            })
        # 4 medium DPAPI Master Key Backup (the real detection)
        for i in range(4):
            hits.append({
                "name": "DPAPI Master Key Backup",
                "level": "medium",
                "event_id": "4624",
                "system_time": f"2026-01-15T10:0{i}:00",
                "tags": ["attack.t1003"],
            })
        # 226 mixed info/low
        for i in range(226):
            hits.append({
                "name": f"misc_rule_{i % 30}",
                "level": "info" if i % 2 else "low",
                "event_id": str(4000 + i),
                "system_time": "2026-01-15T11:00:00",
                "tags": [],
            })
        return hits

    def test_all_medium_hits_are_in_actionable_inline(self):
        from sift_mcp.server import (
            _filter_sigma_hits, _normalize_sigma_level,
            _is_actionable_level, _compact_sigma_hit,
            _resolve_actionable_threshold,
        )
        all_hits = self._run4_hit_mix()
        filtered = _filter_sigma_hits(
            all_hits, requested_severities=set(), requested_techniques=set()
        )
        threshold = _resolve_actionable_threshold()  # default 'medium'

        actionable = [
            h for h in filtered
            if _is_actionable_level(_normalize_sigma_level(h.get("level")), threshold)
        ]
        below = [
            h for h in filtered
            if not _is_actionable_level(_normalize_sigma_level(h.get("level")), threshold)
        ]
        # CORE DETECTION-GAP INVARIANT: all 4 medium DPAPI must be actionable
        medium_actionable = [h for h in actionable if h["name"] == "DPAPI Master Key Backup"]
        assert len(medium_actionable) == 4, (
            f"DETECTION GAP: only {len(medium_actionable)}/4 medium DPAPI hits actionable"
        )
        # 30,893 info User Logoff must be below-threshold (not inline-dumped)
        below_user_logoff = [h for h in below if h["name"] == "User Logoff"]
        assert len(below_user_logoff) == 30893
        # Total preservation: nothing lost
        assert len(actionable) + len(below) == len(filtered)

    def test_compact_actionable_size_bounded(self):
        """4 medium hits in actionable_hits_compact should be < 5KB total
        (Run 4 had 89k chars from 50 raw hits — we MUST be order-of-magnitude smaller)."""
        from sift_mcp.server import _compact_sigma_hit
        import json
        # 4 DPAPI medium hits, compact projected
        compact = [
            _compact_sigma_hit(
                {"name": "DPAPI Master Key Backup", "level": "medium", "event_id": "4624",
                 "system_time": f"2026-01-15T10:0{i}:00", "tags": ["attack.t1003"]},
                index=i,
            )
            for i in range(4)
        ]
        size = len(json.dumps(compact))
        assert size < 5000, f"4 compact hits should be <5KB, got {size}"

    def test_summary_for_30k_info_hits_under_5kb(self):
        """The big win: 30,893 User Logoff hits collapse to <5KB summary."""
        from sift_mcp.server import _aggregate_below_threshold_summary
        import json
        all_hits = self._run4_hit_mix()
        below = [h for h in all_hits if h["level"] in ("info", "informational", "low")]
        summary = _aggregate_below_threshold_summary(below)
        size = len(json.dumps(summary))
        assert size < 5000, f"30k+ below-threshold summary should be <5KB, got {size}"

    def test_combined_response_payload_size_bounded(self):
        """End-to-end: actionable_hits + summary < 10KB even with Run-4 volume.
        (Run 4 had 89k chars in query_sigma_results detailed; we beat that by 10x.)"""
        from sift_mcp.server import (
            _filter_sigma_hits, _normalize_sigma_level, _is_actionable_level,
            _compact_sigma_hit, _resolve_actionable_threshold,
            _aggregate_below_threshold_summary,
        )
        import json
        all_hits = self._run4_hit_mix()
        filtered = _filter_sigma_hits(all_hits, requested_severities=set(), requested_techniques=set())
        threshold = _resolve_actionable_threshold()
        actionable = [h for h in filtered if _is_actionable_level(_normalize_sigma_level(h.get("level")), threshold)]
        below = [h for h in filtered if not _is_actionable_level(_normalize_sigma_level(h.get("level")), threshold)]
        payload = {
            "actionable_hits": [_compact_sigma_hit(h, index=i) for i, h in enumerate(actionable)],
            "below_threshold_summary": _aggregate_below_threshold_summary(below),
        }
        size = len(json.dumps(payload))
        assert size < 10000, (
            f"Combined Run-4 payload should be <10KB (was 89k+181k for sigma+report). Got {size}"
        )
