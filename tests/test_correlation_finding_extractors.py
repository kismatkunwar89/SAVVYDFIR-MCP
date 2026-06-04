"""Regression: correlation extractors must read finding DICTS (P1 #1/#2, 2026-06-03).

Before the fix, checks 7-10 and find_temporal_clusters passed a finding *dict* to
_extract_path_candidate(value: str) / _extract_timestamp_indicator(indicators: list).
Both silently returned None, so:
  - compare_disk_and_memory checks 7-10 never fired (USN timestomp, shimcache/amcache,
    event-log-clearing), and
  - find_temporal_clusters produced 0 clusters on W1.7 main-agent findings (which carry
    event-time in supporting_indicators free-text, not the structured columns).
Additionally, timestamp_observed/timestamp are ISO strings in state.json, so the
clustering math (datetime + timedelta) would crash if they were used raw.
"""

import unittest
from datetime import datetime, timezone

from sift_mcp.tools import correlation as c


class CoerceAndParseTests(unittest.TestCase):
    def test_coerce_none(self):
        self.assertIsNone(c._coerce_datetime(None))
        self.assertIsNone(c._coerce_datetime(""))

    def test_coerce_naive_string_to_utc(self):
        dt = c._coerce_datetime("2026-05-24T03:01:58")
        self.assertEqual(dt, datetime(2026, 5, 24, 3, 1, 58, tzinfo=timezone.utc))

    def test_coerce_z_and_offset(self):
        self.assertEqual(
            c._coerce_datetime("2026-05-24T03:01:58Z"),
            datetime(2026, 5, 24, 3, 1, 58, tzinfo=timezone.utc),
        )

    def test_coerce_passthrough_datetime_naive(self):
        dt = c._coerce_datetime(datetime(2026, 1, 1, 0, 0, 0))
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parse_embedded_timestamp(self):
        dt = c._parse_any_timestamp("Security log cleared at 2026-05-24 03:01:58 UTC")
        self.assertEqual(dt, datetime(2026, 5, 24, 3, 1, 58, tzinfo=timezone.utc))

    def test_parse_no_timestamp(self):
        self.assertIsNone(c._parse_any_timestamp("no time here"))


class FindingExtractorTests(unittest.TestCase):
    def test_finding_path_from_indicator(self):
        f = {"supporting_indicators": ["executable: C:\\Users\\Public\\evil.exe"]}
        self.assertEqual(c._finding_path(f), "C:\\Users\\Public\\evil.exe")

    def test_finding_path_from_artifact_path(self):
        f = {"supporting_indicators": [], "artifact_path": "/mnt/disk/Windows/foo.exe"}
        self.assertEqual(c._finding_path(f), "/mnt/disk/Windows/foo.exe")

    def test_finding_path_dict_safe(self):
        self.assertIsNone(c._finding_path({}))
        self.assertIsNone(c._finding_path("not a dict"))

    def test_finding_timestamp_structured_first(self):
        f = {"timestamp_observed": "2026-03-03T12:00:00", "supporting_indicators": []}
        self.assertEqual(
            c._finding_timestamp(f),
            datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc),
        )

    def test_finding_timestamp_prefix(self):
        f = {"supporting_indicators": ["si_modified: 2026-05-24T03:01:58"]}
        self.assertEqual(
            c._finding_timestamp(f, "si_modified:"),
            datetime(2026, 5, 24, 3, 1, 58, tzinfo=timezone.utc),
        )

    def test_finding_timestamp_any_indicator_fallback(self):
        f = {"supporting_indicators": ["arbitrary note 2026-01-02 10:00:00 ok"]}
        self.assertEqual(
            c._finding_timestamp(f),
            datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc),
        )

    def test_finding_timestamp_dict_safe(self):
        self.assertIsNone(c._finding_timestamp({}))
        self.assertIsNone(c._finding_timestamp("not a dict"))


class FindTemporalClustersMainAgentTests(unittest.TestCase):
    """End-to-end: clustering works on free-text main-agent findings and never
    crashes on string timestamps."""

    def setUp(self):
        # Minimal fake state manager exposing get_findings().
        ts = "2026-05-24T03:01:5"

        class _FakeState:
            def get_findings(self_inner):
                return [
                    {"finding_id": "F-001", "artifact_type": "mft_entry",
                     "supporting_indicators": [f"si_created: {ts}8"],
                     "description": "file drop"},
                    {"finding_id": "F-002", "artifact_type": "prefetch",
                     "supporting_indicators": [f"FirstExecutionTime {ts}9"],
                     "description": "exec"},
                    {"finding_id": "F-003", "artifact_type": "registry",
                     "timestamp_observed": f"{ts}8",
                     "supporting_indicators": [],
                     "description": "run key"},
                ]

        self._orig = c._state_mgr
        c._state_mgr = _FakeState()

    def tearDown(self):
        c._state_mgr = self._orig

    def test_clusters_main_agent_findings(self):
        out = c.find_temporal_clusters(
            "CASE-X", window_seconds=300, min_sources=2, min_events=3
        )
        self.assertNotEqual(out.get("status"), "error", out)
        self.assertGreaterEqual(out.get("cluster_count", 0), 1,
                                "3 sources within 2s must form a cluster")


class FineSourceFamilyClusterTests(unittest.TestCase):
    """G1 fix (2026-06-04): cluster diversity must key on FINE source_family, so a
    burst of disk findings from different extractors registers as multiple sources
    instead of collapsing into one coarse 'disk' bucket (the 0-clusters defect)."""

    def setUp(self):
        ts = "2026-05-24T03:01:5"
        # All artifact_type='disk' (coarse) but THREE different extractors.
        # Old code: sources={'disk'} -> 1 -> no cluster. New: {mft,evtx,registry}.
        findings = [
            {"finding_id": "F-1", "artifact_type": "disk",
             "tool_name": "disk.extract_mft_timeline", "timestamp_observed": f"{ts}1"},
            {"finding_id": "F-2", "artifact_type": "disk",
             "tool_name": "disk.summarize_evtx", "timestamp_observed": f"{ts}2"},
            {"finding_id": "F-3", "artifact_type": "disk",
             "tool_name": "disk.extract_registry_run_keys", "timestamp_observed": f"{ts}3"},
        ]

        class _Fake:
            def get_findings(self_inner):
                return findings

        self._orig = c._state_mgr
        c._state_mgr = _Fake()

    def tearDown(self):
        c._state_mgr = self._orig

    def test_coarse_disk_burst_now_clusters(self):
        out = c.find_temporal_clusters("CASE-Y", window_seconds=300,
                                       min_sources=2, min_events=3)
        self.assertEqual(out.get("cluster_count"), 1,
                         "3 distinct disk extractors must form 1 cluster (fine source_family)")
        diag = out.get("diagnostics", {})
        self.assertEqual(diag["coarse_artifact_type_histogram"], {"disk": 3})
        self.assertEqual(set(diag["source_histogram"]), {"mft", "evtx", "registry"})

    def test_diagnostics_present_even_when_zero_clusters(self):
        # single family -> 0 clusters, but diagnostics must explain why
        class _One:
            def get_findings(self_inner):
                return [
                    {"finding_id": f"F-{i}", "artifact_type": "disk",
                     "tool_name": "disk.extract_mft_timeline",
                     "timestamp_observed": f"2026-05-24T03:01:0{i}"} for i in range(3)
                ]
        c._state_mgr = _One()
        out = c.find_temporal_clusters("CASE-Z", min_sources=2, min_events=3)
        self.assertEqual(out["cluster_count"], 0)
        self.assertEqual(out["diagnostics"]["source_histogram"], {"mft": 3})


class CorrelationExclusionTests(unittest.TestCase):
    """Synthesis ('correlation') findings must not satisfy min_sources alone -
    they re-describe already-counted sources (peer reviewer constraint)."""

    def setUp(self):
        ts = "2026-05-24T03:01:0"
        findings = [
            {"finding_id": "F-1", "artifact_type": "correlation",
             "tool_name": "correlation.compare_disk_and_memory", "timestamp_observed": f"{ts}1"},
            {"finding_id": "F-2", "artifact_type": "correlation",
             "tool_name": "correlation.compare_disk_and_memory", "timestamp_observed": f"{ts}2"},
            {"finding_id": "F-3", "artifact_type": "disk",
             "tool_name": "disk.extract_mft_timeline", "timestamp_observed": f"{ts}3"},
        ]

        class _Fake:
            def get_findings(self_inner):
                return findings

        self._orig = c._state_mgr
        c._state_mgr = _Fake()

    def tearDown(self):
        c._state_mgr = self._orig

    def test_correlation_findings_excluded_from_diversity(self):
        out = c.find_temporal_clusters("CASE-C", min_sources=2, min_events=3)
        # only 'mft' counts as a source -> 1 source -> no cluster
        self.assertEqual(out.get("cluster_count"), 0,
                         "correlation summaries must not inflate source diversity")


if __name__ == "__main__":
    unittest.main()
