"""Regression tests for the Run-12 defect package (design review 2026-05-20).

Three defects:
  DEFECT-2 — Phantom delegate regeneration when multiple specialists progress
             the same lane (timeline_correlation). Fix: deterministic
             delegate_key + queue lookup before re-enqueue.
  DEFECT-3 — generate_report blocks on stale delegates whose lane is already
             satisfied. Fix: walk per-lane queue, dismiss same-actor stale
             entries (and different-actor entries that have ledger path_b
             allowance). review distinguished these from phantom Path A
             completions, which MUST stay blocking.
  DEFECT-1 — Specialist .md files now carry a JSON-only contract block at
             the top with lane-specific budgets and cross-artifact carve-outs
             for corroboration-analyst + timeline-analyst.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# DEFECT-2 — delegate_key + idempotent enqueue
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_queue(monkeypatch, tmp_path):
    queue_path = tmp_path / "queue.json"
    monkeypatch.setenv("SAVVYDFIR_DELEGATE_QUEUE_PATH", str(queue_path))
    for mod in ("delegate_queue", "delegation_ledger"):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegate_queue  # noqa: F401
    return delegate_queue, queue_path


def test_compute_delegate_key_deterministic(fresh_queue):
    dq, _ = fresh_queue
    k1 = dq.compute_delegate_key("CASE-A", "memory", "memory-analyst", 1)
    k2 = dq.compute_delegate_key("CASE-A", "memory", "memory-analyst", 1)
    assert k1 == k2, "delegate_key must be deterministic for same inputs"
    # Different case → different key (case namespacing per review)
    k_other = dq.compute_delegate_key("CASE-B", "memory", "memory-analyst", 1)
    assert k1 != k_other
    # Different iteration → different key (allows fresh dispatch on retry)
    k_iter = dq.compute_delegate_key("CASE-A", "memory", "memory-analyst", 2)
    assert k1 != k_iter
    # Specialist normalization: @memory-analyst == memory-analyst
    k_at = dq.compute_delegate_key("CASE-A", "memory", "@memory-analyst", 1)
    assert k1 == k_at


def test_legacy_delegate_backfills_fields(fresh_queue):
    """Old queue entries without delegate_key/status/retry_count get
    fields backfilled by _read_queue on first read."""
    dq, queue_path = fresh_queue
    legacy = {
        "memory": [{
            "subagent_type": "memory-analyst",
            "lane_id": "memory",
            "case_id": "CASE-A",
            "tool": "list_dlls",
            "processed": False,
            "created_at": "2026-05-19T01:00:00.000Z",
        }]
    }
    queue_path.write_text(json.dumps(legacy), encoding="utf-8")
    queue = dq._read_queue()
    entry = queue["memory"][0]
    assert "delegate_key" in entry and entry["delegate_key"]
    assert entry["status"] == "pending"
    assert entry["retry_count"] == 0


def test_legacy_processed_true_translates_to_status_processed(fresh_queue):
    dq, queue_path = fresh_queue
    legacy = {
        "memory": [{
            "subagent_type": "memory-analyst",
            "lane_id": "memory",
            "case_id": "CASE-A",
            "processed": True,
        }]
    }
    queue_path.write_text(json.dumps(legacy), encoding="utf-8")
    queue = dq._read_queue()
    assert queue["memory"][0]["status"] == "processed"


def test_find_existing_by_key_filters_status(fresh_queue):
    dq, _ = fresh_queue
    dq.enqueue_delegate("memory", {
        "case_id": "CASE-A", "lane_id": "memory",
        "subagent_type": "memory-analyst",
    })
    queue = dq._read_queue()
    key = queue["memory"][0]["delegate_key"]
    # Default search returns pending entry
    found = dq.find_existing_by_key(key, statuses={"pending"})
    assert found is not None
    assert found["delegate_key"] == key
    # Status filter excludes the pending entry
    not_found = dq.find_existing_by_key(key, statuses={"processed"})
    assert not_found is None


def test_mark_delegate_stale_is_idempotent(fresh_queue):
    dq, _ = fresh_queue
    dq.enqueue_delegate("memory", {
        "case_id": "CASE-A", "lane_id": "memory",
        "subagent_type": "memory-analyst",
    })
    queue = dq._read_queue()
    key = queue["memory"][0]["delegate_key"]

    first = dq.mark_delegate_stale(key, reason="lane_satisfied_after_delegate_created")
    assert first is not None
    assert first["status"] == "stale_dismissed"
    assert first["processed_reason"] == "lane_satisfied_after_delegate_created"

    # Second call must NOT raise and must NOT corrupt state.
    second = dq.mark_delegate_stale(key, reason="lane_satisfied_after_delegate_created")
    assert second is not None
    assert second["status"] == "stale_dismissed"


def test_all_pending_delegates_excludes_terminal_statuses(fresh_queue):
    dq, _ = fresh_queue
    dq.enqueue_delegate("memory", {
        "case_id": "CASE-A", "lane_id": "memory",
        "subagent_type": "memory-analyst",
    })
    dq.enqueue_delegate("event_auth", {
        "case_id": "CASE-A", "lane_id": "event_auth",
        "subagent_type": "evtx-analyst",
    })
    queue = dq._read_queue()
    mem_key = queue["memory"][0]["delegate_key"]
    dq.mark_delegate_stale(mem_key)

    pending = dq.all_pending_delegates()
    lane_ids = {p["lane_id"] for p in pending}
    assert lane_ids == {"event_auth"}, (
        f"Stale entries must be excluded from pending; got {lane_ids}"
    )


def test_dispatch_source_skips_pending_redispatch():
    """Source-text guard: _dispatch_corroboration_if_ready must consult the
    delegate_key/find_existing_by_key path before enqueueing."""
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    func_idx = src.find("def _dispatch_corroboration_if_ready(")
    end = src.find("\ndef _lane_status_from_state(", func_idx)
    body = src[func_idx:end if end > 0 else func_idx + 12000]
    assert "compute_delegate_key" in body, (
        "_dispatch_corroboration_if_ready must compute the deterministic "
        "delegate_key per DEFECT-2."
    )
    assert "find_existing_by_key" in body, (
        "_dispatch_corroboration_if_ready must consult the queue for "
        "existing matching delegates per DEFECT-2."
    )
    assert "skip_redispatch_pending_delegate" in body
    assert "skip_redispatch_lane_already_corroborated" in body
    assert "skip_redispatch_prereqs_incomplete" in body


# ---------------------------------------------------------------------------
# DEFECT-3 — stale-delegate filter in reporting.py
# ---------------------------------------------------------------------------

def test_dismiss_stale_same_actor(fresh_queue, monkeypatch, tmp_path):
    """A delegate for memory-analyst on lane=memory, where the lane has
    been recorded by memory-analyst AFTER the delegate was queued, must
    be dismissed via delegate_satisfied_by_lane_record."""
    dq, _ = fresh_queue
    # Set up isolated ledger
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(tmp_path / "session.json"))
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("test-sess-1")

    dq.enqueue_delegate("memory", {
        "case_id": "CASE-A", "lane_id": "memory",
        "subagent_type": "memory-analyst",
        "created_at": "2026-05-20T16:00:00.000Z",
    })

    # Fake state manager with a lane satisfied by memory-analyst AFTER
    # the delegate was queued.
    class FakeState:
        def load(self, case_id): pass
        def get_analysis_lanes(self):
            return [{
                "lane_id": "memory",
                "status": "COMPLETE",
                "assigned_agent": "memory-analyst",
                "updated_at": "2026-05-20T16:30:00.000Z",
            }]

    from sift_mcp.reporting import _dismiss_stale_delegates
    dismissed, blocking = _dismiss_stale_delegates("CASE-A", FakeState())
    assert len(dismissed) == 1
    assert dismissed[0]["lane_id"] == "memory"
    assert dismissed[0]["event"] == "delegate_satisfied_by_lane_record"
    assert blocking == []


def test_dismiss_stale_different_actor_without_path_b_allowance_stays_blocking(
    fresh_queue, monkeypatch, tmp_path
):
    """If a delegate for evtx-analyst is satisfied by main-agent (Path B)
    but the ledger has NO path_b_would_allow row, the delegate MUST stay
    blocking. This is the phantom-Path-A case review insisted on."""
    dq, _ = fresh_queue
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(tmp_path / "session.json"))
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("test-sess-2")

    dq.enqueue_delegate("event_auth", {
        "case_id": "CASE-A", "lane_id": "event_auth",
        "subagent_type": "evtx-analyst",
        "created_at": "2026-05-20T16:00:00.000Z",
    })

    class FakeState:
        def load(self, case_id): pass
        def get_analysis_lanes(self):
            return [{
                "lane_id": "event_auth",
                "status": "COMPLETE",
                "assigned_agent": "main-agent",  # Path B claim
                "updated_at": "2026-05-20T16:30:00.000Z",
            }]

    from sift_mcp.reporting import _dismiss_stale_delegates
    dismissed, blocking = _dismiss_stale_delegates("CASE-A", FakeState())
    assert dismissed == [], (
        "Phantom Path A (different-actor satisfaction without ledger "
        "allowance) must NOT be dismissed. This would silently bless the "
        "agent skipping Task."
    )
    assert len(blocking) == 1


def test_dismiss_stale_different_actor_with_path_b_allowance(
    fresh_queue, monkeypatch, tmp_path
):
    """If a delegate is satisfied by a different actor AND the ledger has
    a path_b_would_allow row for the lane, dismiss it as Path B allowance."""
    dq, _ = fresh_queue
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(tmp_path / "session.json"))
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("test-sess-3")
    # Pre-record the Path B allowance row
    delegation_ledger.append_row(
        "path_b_would_allow",
        lane_id="event_auth",
        specialist="evtx-analyst",
        decision_basis="failed_task_outcome_recorded",
    )

    dq.enqueue_delegate("event_auth", {
        "case_id": "CASE-A", "lane_id": "event_auth",
        "subagent_type": "evtx-analyst",
        "created_at": "2026-05-20T16:00:00.000Z",
    })

    class FakeState:
        def load(self, case_id): pass
        def get_analysis_lanes(self):
            return [{
                "lane_id": "event_auth",
                "status": "COMPLETE_WITH_GAPS",
                "assigned_agent": "main-agent",
                "updated_at": "2026-05-20T16:30:00.000Z",
            }]

    from sift_mcp.reporting import _dismiss_stale_delegates
    dismissed, blocking = _dismiss_stale_delegates("CASE-A", FakeState())
    assert len(dismissed) == 1
    assert dismissed[0]["event"] == "delegate_satisfied_by_path_b_allowance"
    assert blocking == []


def test_dismiss_stale_lane_not_yet_complete_stays_blocking(
    fresh_queue, monkeypatch, tmp_path
):
    """If the lane is still PENDING/in-progress, the delegate is NOT stale."""
    dq, _ = fresh_queue
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(tmp_path / "session.json"))
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("test-sess-4")

    dq.enqueue_delegate("memory", {
        "case_id": "CASE-A", "lane_id": "memory",
        "subagent_type": "memory-analyst",
        "created_at": "2026-05-20T16:00:00.000Z",
    })

    class FakeState:
        def load(self, case_id): pass
        def get_analysis_lanes(self):
            return [{
                "lane_id": "memory",
                "status": "PENDING",
                "assigned_agent": "memory-analyst",
            }]

    from sift_mcp.reporting import _dismiss_stale_delegates
    dismissed, blocking = _dismiss_stale_delegates("CASE-A", FakeState())
    assert dismissed == []
    assert len(blocking) == 1


def test_dismiss_stale_lane_recorded_before_delegate_stays_blocking(
    fresh_queue, monkeypatch, tmp_path
):
    """If the lane was completed BEFORE the delegate was queued, it can't
    be the satisfaction of THAT delegate — keep blocking."""
    dq, _ = fresh_queue
    monkeypatch.setenv("SAVVYDFIR_DELEGATION_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("SAVVYDFIR_SESSION_POINTER", str(tmp_path / "session.json"))
    for mod in ("delegation_ledger",):
        if mod in sys.modules:
            del sys.modules[mod]
    import delegation_ledger
    delegation_ledger.write_session_pointer("test-sess-5")

    dq.enqueue_delegate("memory", {
        "case_id": "CASE-A", "lane_id": "memory",
        "subagent_type": "memory-analyst",
        "created_at": "2026-05-20T16:30:00.000Z",  # LATER than lane
    })

    class FakeState:
        def load(self, case_id): pass
        def get_analysis_lanes(self):
            return [{
                "lane_id": "memory",
                "status": "COMPLETE",
                "assigned_agent": "memory-analyst",
                "updated_at": "2026-05-20T16:00:00.000Z",  # EARLIER than delegate
            }]

    from sift_mcp.reporting import _dismiss_stale_delegates
    dismissed, blocking = _dismiss_stale_delegates("CASE-A", FakeState())
    assert dismissed == [], (
        "Lane completed before delegate was queued cannot satisfy the delegate."
    )
    assert len(blocking) == 1


def test_reporting_source_uses_dismiss_helper():
    """Source-text guard: generate_report_payload calls _dismiss_stale_delegates
    before the legacy single-file delegate check."""
    src = (ROOT / "sift_mcp" / "reporting.py").read_text()
    fn_idx = src.find("def generate_report_payload(")
    assert fn_idx > 0
    next_fn = src.find("\ndef ", fn_idx + 1)
    body = src[fn_idx:next_fn if next_fn > 0 else fn_idx + 20000]
    assert "_dismiss_stale_delegates" in body
    assert "stale_delegates_dismissed" in body, (
        "Response payload must surface dismissed entries to the operator."
    )


# ---------------------------------------------------------------------------
# DEFECT-1 — Specialist .md JSON-only contract
# ---------------------------------------------------------------------------

_PHASE3_OVERLAY_SKIP_REASON = (
    "W1.2 (2026-05-23, the design plan): "
    "Phase 3 overlay (C-PRIME + Playbook + Final Response Contract) "
    "was stripped from specialist .md files. Specialists now exist as "
    "forensic-heuristic knowledge bases ('Heuristics, not procedures') "
    "consumed inline by the main agent, not as Task subagents with "
    "JSON contract returns. See DECISION-2026-05-23-branch-triage.md."
)


@pytest.mark.skip(reason=_PHASE3_OVERLAY_SKIP_REASON)
@pytest.mark.parametrize("specialist", [
    "amcache-analyst",
    "browser-analyst",
    "corroboration-analyst",
    "evtx-analyst",
    "memory-analyst",
    "mft-analyst",
    "prefetch-analyst",
    "registry-analyst",
    "sigma-analyst",
    "srum-analyst",
    "timeline-analyst",
])
def test_specialist_has_json_only_contract(specialist):
    path = ROOT / ".claude" / "agents" / f"{specialist}.md"
    text = path.read_text(encoding="utf-8")
    assert "Final Response Contract" in text, (
        f"{specialist}: missing Final Response Contract section"
    )
    assert "Return EXACTLY ONE JSON object" in text
    assert "Required Response Schema" in text
    # Lane-specific budget
    assert "Hard call budget:" in text


@pytest.mark.skip(reason=_PHASE3_OVERLAY_SKIP_REASON)
def test_corroboration_analyst_has_cross_artifact_carveout():
    """review insisted corroboration-analyst MUST NOT have the
    'don't inspect unrelated artifacts' restriction."""
    text = (ROOT / ".claude" / "agents" / "corroboration-analyst.md").read_text()
    assert "Cross-artifact analysis is REQUIRED" in text, (
        "corroboration-analyst's cross-artifact carve-out is missing"
    )


@pytest.mark.skip(reason=_PHASE3_OVERLAY_SKIP_REASON)
def test_timeline_analyst_has_cross_artifact_carveout():
    """Same carve-out for timeline-analyst."""
    text = (ROOT / ".claude" / "agents" / "timeline-analyst.md").read_text()
    assert "Cross-artifact analysis is REQUIRED" in text


@pytest.mark.skip(reason=_PHASE3_OVERLAY_SKIP_REASON)
def test_non_cross_artifact_specialists_keep_scope_restriction():
    """The 9 single-artifact specialists must still tell the model NOT to
    wander outside their lane."""
    for specialist in ("mft-analyst", "evtx-analyst", "prefetch-analyst",
                       "amcache-analyst", "registry-analyst", "srum-analyst",
                       "sigma-analyst", "memory-analyst", "browser-analyst"):
        text = (ROOT / ".claude" / "agents" / f"{specialist}.md").read_text()
        assert "Do not inspect unrelated artifacts" in text, (
            f"{specialist}: missing scope restriction"
        )
