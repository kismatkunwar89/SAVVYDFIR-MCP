"""Tests for per-lane delegate queue system."""

import json
import os
import tempfile
import unittest
from pathlib import Path

# Import from scripts directory
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from delegate_queue import (
    enqueue_delegate,
    get_pending_delegate,
    mark_delegate_processed,
    is_tool_already_queued,
    get_queue_status,
)


class DelegateQueueTests(unittest.TestCase):
    """Tests for delegate queue operations."""

    def setUp(self):
        """Set up test environment with temp queue file."""
        self.temp_dir = tempfile.mkdtemp()
        self.queue_path = Path(self.temp_dir) / "delegate_queue.json"
        os.environ["SAVVYDFIR_DELEGATE_QUEUE_PATH"] = str(self.queue_path)

    def tearDown(self):
        """Clean up temp files."""
        if self.queue_path.exists():
            self.queue_path.unlink()
        os.rmdir(self.temp_dir)
        os.environ.pop("SAVVYDFIR_DELEGATE_QUEUE_PATH", None)

    def test_enqueue_single_delegate(self):
        """Test enqueueing a single delegate."""
        delegate = {
            "tool": "summarize_evtx",
            "subagent_type": "evtx-analyst",
            "prompt": "Analyze EVTX logs",
        }
        enqueue_delegate("event_auth", delegate)

        # Verify queue file was created
        self.assertTrue(self.queue_path.exists())

        # Verify delegate was added
        pending = get_pending_delegate("event_auth")
        self.assertIsNotNone(pending)
        self.assertEqual(pending["tool"], "summarize_evtx")
        self.assertEqual(pending["subagent_type"], "evtx-analyst")

    def test_enqueue_multiple_delegates_same_lane(self):
        """Test enqueueing multiple delegates to the same lane."""
        delegate1 = {"tool": "extract_mft_timeline", "subagent_type": "mft-analyst"}
        delegate2 = {"tool": "sigma_hunt", "subagent_type": "sigma-analyst"}

        enqueue_delegate("timeline_correlation", delegate1)
        enqueue_delegate("timeline_correlation", delegate2)

        # First pending should be delegate1
        pending = get_pending_delegate("timeline_correlation")
        self.assertEqual(pending["tool"], "extract_mft_timeline")

        # Verify both are in queue
        with open(self.queue_path) as f:
            queue = json.load(f)
        self.assertEqual(len(queue["timeline_correlation"]), 2)

    def test_enqueue_multiple_delegates_different_lanes(self):
        """Test enqueueing delegates to different lanes."""
        delegate1 = {"tool": "summarize_evtx", "subagent_type": "evtx-analyst"}
        delegate2 = {"tool": "extract_mft_timeline", "subagent_type": "mft-analyst"}
        delegate3 = {"tool": "extract_prefetch", "subagent_type": "prefetch-analyst"}

        enqueue_delegate("event_auth", delegate1)
        enqueue_delegate("timeline_correlation", delegate2)
        enqueue_delegate("disk_execution_persistence", delegate3)

        # Verify all lanes have delegates
        with open(self.queue_path) as f:
            queue = json.load(f)
        self.assertIn("event_auth", queue)
        self.assertIn("timeline_correlation", queue)
        self.assertIn("disk_execution_persistence", queue)

    def test_get_pending_delegate_prioritized(self):
        """Test that get_pending_delegate returns highest-priority lane."""
        # Enqueue in reverse priority order
        enqueue_delegate("memory", {"tool": "detect_injection"})
        enqueue_delegate("timeline_correlation", {"tool": "extract_mft_timeline"})
        enqueue_delegate("event_auth", {"tool": "summarize_evtx"})

        # Should return event_auth (highest priority)
        pending = get_pending_delegate()
        self.assertEqual(pending["lane_id"], "event_auth")
        self.assertEqual(pending["tool"], "summarize_evtx")

    def test_mark_delegate_processed_removes_from_queue(self):
        """Test that marking processed removes delegate from queue."""
        delegate1 = {"tool": "extract_mft_timeline", "subagent_type": "mft-analyst"}
        delegate2 = {"tool": "sigma_hunt", "subagent_type": "sigma-analyst"}

        enqueue_delegate("timeline_correlation", delegate1)
        enqueue_delegate("timeline_correlation", delegate2)

        # Process first delegate
        mark_delegate_processed("timeline_correlation")

        # Second delegate should now be pending
        pending = get_pending_delegate("timeline_correlation")
        self.assertEqual(pending["tool"], "sigma_hunt")

        # Process second delegate
        mark_delegate_processed("timeline_correlation")

        # Queue should be empty
        pending = get_pending_delegate("timeline_correlation")
        self.assertIsNone(pending)

    def test_is_tool_already_queued(self):
        """Test duplicate tool detection in same lane."""
        delegate = {"tool": "summarize_evtx", "subagent_type": "evtx-analyst"}
        enqueue_delegate("event_auth", delegate)

        # Should detect duplicate
        self.assertTrue(is_tool_already_queued("event_auth", "summarize_evtx"))

        # Different tool in same lane should not match
        self.assertFalse(is_tool_already_queued("event_auth", "hayabusa_hunt"))

        # Same tool in different lane should not match
        self.assertFalse(is_tool_already_queued("timeline_correlation", "summarize_evtx"))

    def test_is_tool_already_queued_with_mcp_prefix(self):
        """Test tool matching handles MCP prefix normalization."""
        delegate = {"tool": "mcp__savvydfir__summarize_evtx", "subagent_type": "evtx-analyst"}
        enqueue_delegate("event_auth", delegate)

        # Should match without prefix
        self.assertTrue(is_tool_already_queued("event_auth", "summarize_evtx"))

        # Should match with different prefix variations
        self.assertTrue(is_tool_already_queued("event_auth", "mcp__savvydfir__summarize_evtx"))

    def test_get_queue_status(self):
        """Test queue status reporting."""
        enqueue_delegate("event_auth", {"tool": "summarize_evtx"})
        enqueue_delegate("event_auth", {"tool": "hayabusa_hunt"})
        enqueue_delegate("timeline_correlation", {"tool": "extract_mft_timeline"})

        status = get_queue_status()
        self.assertEqual(status["total_pending"], 3)
        self.assertEqual(status["per_lane"]["event_auth"], 2)
        self.assertEqual(status["per_lane"]["timeline_correlation"], 1)
        self.assertIn("event_auth", status["lanes_with_work"])
        self.assertIn("timeline_correlation", status["lanes_with_work"])

    def test_empty_queue_returns_none(self):
        """Test that empty queue returns None for pending delegate."""
        pending = get_pending_delegate()
        self.assertIsNone(pending)

        pending = get_pending_delegate("event_auth")
        self.assertIsNone(pending)

    def test_queue_survives_empty_lanes(self):
        """Test that empty lanes are cleaned up on write."""
        enqueue_delegate("event_auth", {"tool": "summarize_evtx"})
        mark_delegate_processed("event_auth")

        # Queue file should still exist but event_auth lane should be removed
        with open(self.queue_path) as f:
            queue = json.load(f)
        self.assertNotIn("event_auth", queue)


if __name__ == "__main__":
    unittest.main()
