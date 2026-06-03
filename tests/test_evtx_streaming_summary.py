"""Tests for the memory-bounded streaming EVTX summary (review 2026-06-02).

summarize_evtx OOM-killed the MCP server when an agent requested a broad --inc
EID set (PowerShell 4104/4103) that produced a 2.4 GB / 2.38M-row CSV, because
the legacy path materialized the whole CSV into list[dict] + list[EventRecord].

The fix streams the CSV in one pass, retaining only bounded aggregates + a head
sample. These tests prove:
  1. EQUIVALENCE - the streaming path produces byte-identical depth (counts,
     histogram, compact_unique pivots, normalized sample, evidence excerpt,
     process paths) to the legacy materialized path on the same CSV.
  2. BOUNDED - on a CSV far larger than the sample cap with huge 4104
     ScriptBlockText payloads, total_records still counts every row, the
     retained sample is capped, and wide fields are dropped/truncated.
  3. STRUCTURAL - summarize_evtx no longer calls _read_csv / _build_evtx_records
     (regression guard against re-introducing the full-materialization OOM).
"""

import csv
import inspect
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sift_mcp.tools import disk
from sift_mcp.tools._contracts import compact_unique


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _varied_rows() -> list[dict[str, str]]:
    """A representative mix: 3 channels, several EIDs, 4688 process paths,
    varied computers/SIDs, blank fields - exercises every pivot dimension."""
    rows: list[dict[str, str]] = []
    channels = ["Security", "System", "Microsoft-Windows-PowerShell/Operational"]
    for i in range(30):
        ch = channels[i % len(channels)]
        eid = [4624, 4688, 7045, 4104, 1102][i % 5]
        row = {
            "EventId": str(eid),
            "Channel": ch,
            "TimeCreated": f"2020-11-14T01:02:{i % 60:02d}.000000Z",
            "Computer": f"HOST-{i % 4}",
            "UserSID": f"S-1-5-21-{i % 3}",
            "Provider": "Prov-A",
            "Level": "Information",
            "PayloadData1": f"message body {i}",
        }
        if eid == 4688:
            row["NewProcessName"] = f"C:\\Windows\\System32\\proc{i % 5}.exe"
            row["CommandLine"] = f"proc{i % 5}.exe --flag {i}"
        rows.append(row)
    return rows


class EvtxStreamingEquivalenceTest(unittest.TestCase):
    def _legacy(self, csv_path: str):
        rows = disk._read_csv(csv_path)
        records, _ = disk._build_evtx_records(
            rows,
            evtx_dir="/evtx",
            channel=None,
            tool="disk.summarize_evtx",
            execution_id="E-legacy",
            create_findings=False,
        )
        channel_counts: dict[str, int] = {}
        for rec in records:
            channel_counts[rec.channel] = channel_counts.get(rec.channel, 0) + 1
        normalized = [
            {
                "event_id": r.event_id,
                "channel": r.channel,
                "timestamp": disk._dt_to_iso(r.timestamp),
                "computer": r.computer,
                "provider": r.provider,
            }
            for r in records[:20]
        ]
        excerpt = next((r.message_summary for r in records if r.message_summary), None)
        pivots = {
            "event_ids": compact_unique(r.event_id for r in records),
            "channels": compact_unique(r.channel for r in records),
            "computers": compact_unique(r.computer for r in records),
            "user_sids": compact_unique(r.user_sid for r in records),
            "process_paths": compact_unique(disk._extract_evtx_process_paths(records)),
        }
        return len(records), channel_counts, normalized, excerpt, pivots

    def test_streaming_matches_legacy_depth(self):
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "evtx_timeline.csv")
            _write_csv(Path(csv_path), _varied_rows())

            legacy_total, legacy_counts, legacy_norm, legacy_excerpt, legacy_pivots = self._legacy(csv_path)

            stream = disk._stream_evtx_summary(csv_path, channel=None)
            norm, pivots = disk._evtx_contract_inputs(stream)

            self.assertEqual(stream["total_records"], legacy_total)
            self.assertEqual(stream["channel_counts"], legacy_counts)
            self.assertEqual(norm, legacy_norm)
            self.assertEqual(stream["evidence_excerpt"], legacy_excerpt)
            self.assertEqual(pivots, legacy_pivots)
            # process paths must actually be found (guards against a no-op test)
            self.assertTrue(pivots["process_paths"])

    def test_channel_filter_matches_legacy(self):
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "evtx_timeline.csv")
            rows = _varied_rows()
            _write_csv(Path(csv_path), rows)
            legacy_matched, legacy_counts, _, _, legacy_pivots = self._legacy_filtered(csv_path, "Security")
            stream = disk._stream_evtx_summary(csv_path, channel="Security")
            _, pivots = disk._evtx_contract_inputs(stream)
            # matched_records == the legacy channel-filtered record count
            self.assertEqual(stream["matched_records"], legacy_matched)
            # total_records == raw CSV rows (matches csv_path), NOT the filtered count
            self.assertEqual(stream["total_records"], len(rows))
            self.assertEqual(stream["raw_rows"], len(rows))
            self.assertGreater(stream["total_records"], stream["matched_records"])
            self.assertEqual(stream["channel_counts"], legacy_counts)
            self.assertEqual(pivots, legacy_pivots)
            self.assertEqual(set(stream["channel_counts"]), {"Security"})

    def test_channel_none_raw_equals_matched(self):
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "evtx_timeline.csv")
            rows = _varied_rows()
            _write_csv(Path(csv_path), rows)
            stream = disk._stream_evtx_summary(csv_path, channel=None)
            # With no channel filter raw == matched == total == every CSV row
            self.assertEqual(stream["total_records"], len(rows))
            self.assertEqual(stream["raw_rows"], len(rows))
            self.assertEqual(stream["matched_records"], len(rows))

    def _legacy_filtered(self, csv_path: str, channel: str):
        rows = disk._read_csv(csv_path)
        records, _ = disk._build_evtx_records(
            rows, evtx_dir="/evtx", channel=channel,
            tool="disk.summarize_evtx", execution_id="E-x", create_findings=False,
        )
        counts: dict[str, int] = {}
        for rec in records:
            counts[rec.channel] = counts.get(rec.channel, 0) + 1
        pivots = {
            "event_ids": compact_unique(r.event_id for r in records),
            "channels": compact_unique(r.channel for r in records),
            "computers": compact_unique(r.computer for r in records),
            "user_sids": compact_unique(r.user_sid for r in records),
            "process_paths": compact_unique(disk._extract_evtx_process_paths(records)),
        }
        return len(records), counts, None, None, pivots


class EvtxStreamingBoundedTest(unittest.TestCase):
    def test_large_csv_is_bounded_and_wide_fields_truncated(self):
        n = disk._EVTX_SAMPLE_CAP + 250  # exceed the sample cap
        big_script = "X" * (disk._EVTX_WIDE_FIELD_MAX_CHARS * 8)  # huge 4104 payload
        rows = []
        for i in range(n):
            rows.append({
                "EventId": "4104",
                "Channel": "Microsoft-Windows-PowerShell/Operational",
                "TimeCreated": "2020-11-14T01:00:00.0000000+00:00",
                "Computer": "HOST-0",
                "UserSID": "S-1-5-21-0",
                "PayloadData1": f"scriptblock {i}",
                "ScriptBlockText": big_script,
            })
        with TemporaryDirectory() as tmp:
            csv_path = str(Path(tmp) / "evtx_timeline.csv")
            _write_csv(Path(csv_path), rows)
            stream = disk._stream_evtx_summary(csv_path, channel=None)

            # total counts EVERY row (depth preserved)...
            self.assertEqual(stream["total_records"], n)
            self.assertEqual(stream["raw_rows"], n)
            self.assertEqual(stream["matched_records"], n)
            # matched > sample cap => the response's data_truncated will be True
            # (matched_records > records_count); inline data can never be mistaken
            # for the full set.
            self.assertGreater(stream["matched_records"], disk._EVTX_SAMPLE_CAP)
            # ...but the retained sample is hard-capped (memory bounded)
            self.assertEqual(len(stream["sample"]), disk._EVTX_SAMPLE_CAP)
            # wide ScriptBlockText is dropped from every retained sample record
            for rec in stream["sample"]:
                for key, value in rec.extra_fields.items():
                    kn = key.lower().replace(" ", "").replace("_", "")
                    self.assertNotIn(kn, disk._EVTX_WIDE_FIELD_DROP)
                    self.assertLessEqual(
                        len(value),
                        disk._EVTX_WIDE_FIELD_MAX_CHARS + len("...[truncated]"),
                    )
            # histogram still reflects all rows
            self.assertEqual(
                stream["channel_counts"]["Microsoft-Windows-PowerShell/Operational"], n
            )

    def test_empty_and_missing_csv(self):
        with TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "nope.csv")
            self.assertEqual(disk._stream_evtx_summary(missing)["total_records"], 0)
            empty = Path(tmp) / "empty.csv"
            empty.write_text("")
            self.assertEqual(disk._stream_evtx_summary(str(empty))["total_records"], 0)


class EvtxStructuralGuardTest(unittest.TestCase):
    def test_summarize_evtx_does_not_materialize_csv(self):
        src = inspect.getsource(disk.summarize_evtx)
        self.assertNotIn("_read_csv(", src,
                         "summarize_evtx must stream, never _read_csv the full CSV")
        self.assertNotIn("_build_evtx_records(", src,
                         "summarize_evtx must not materialize all EventRecords")
        self.assertIn("_stream_evtx_summary(", src)


if __name__ == "__main__":
    unittest.main()
