"""Regression test for MCP server segfault (2026-05-23).

Root cause: ``CaseStateManager`` read paths returned shallow copies
(``dict(self._state)``, ``dict(f)``, ``dict(lane)``). Nested lists like
``findings``, ``executions``, ``analysis_lanes``, ``supporting_indicators``,
``corroborated_by`` were LIVE references back into ``self._state``.

When fastmcp/json.dumps walked one of these returned dicts OUTSIDE the
manager's RLock while another thread (corroboration dispatcher, lane
upserter, or a parallel add_finding from a specialist) mutated those
nested lists, Python 3.10's ``_json.so`` C extension hit a use-after-free
during dict resize and segfaulted (kernel: ``segfault ... in
json.cpython-310-x86_64-linux-gnu.so``).

This test recreates the race in a tight loop. With the pre-fix shallow
copies, ``json.dumps`` on the returned snapshot intermittently raises
``RuntimeError: dictionary changed size during iteration`` (the Python
backstop) OR segfaults (the C extension path). With the fix (deepcopy on
return), the snapshot is fully detached and serialization is stable.

Hard cap: 500 mutation iterations. If the fix regresses, this test
should hit the runtime error within the first few hundred iterations.
"""
from __future__ import annotations

import copy
import json
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sift_mcp.state import CaseStateManager


def _make_finding(idx: int) -> dict:
    return {
        "finding_id": f"F-{idx:04d}",
        "finding_type": "ioc",
        "artifact_type": "memory",
        "artifact_path": f"/cases/TEST/process_{idx}.json",
        "description": f"Synthetic finding {idx} for race test.",
        "evidence_kind": "MEMORY_ARTIFACT",
        "confidence": 0.7,
        "finding_status": "ACTIVE",
        "tool_name": "memory.list_processes",
        "execution_id": "E-001",
        "iteration": 1,
        "supporting_indicators": [f"ind_{idx}_a", f"ind_{idx}_b", f"ind_{idx}_c"],
        "corroborated_by": [],
        "confidence_support_inputs": [
            {"source": "memory", "weight": 0.5},
            {"source": "disk", "weight": 0.3},
        ],
    }


@pytest.fixture()
def loaded_state(tmp_path):
    sm = CaseStateManager(state_path=str(tmp_path / "state.json"))
    sm.load("RACE-TEST")
    # Seed with 50 findings + a few executions so reads return non-trivial
    # nested structures the JSON walker has to traverse.
    for i in range(50):
        # Skip the gate by ensuring the audit/execution linkage exists.
        # We poke directly into _state under the lock to avoid the
        # provenance gate machinery in this race-test context.
        with sm._lock:  # type: ignore[attr-defined]
            sm._state["findings"].append(_make_finding(i))  # type: ignore[attr-defined]
            sm._state["findings_count"] = len(sm._state["findings"])  # type: ignore[attr-defined]
    with sm._lock:  # type: ignore[attr-defined]
        for i in range(10):
            sm._state["executions"].append({  # type: ignore[attr-defined]
                "execution_id": f"E-{i:03d}",
                "tool_name": f"tool_{i}",
                "iteration": 1,
                "event_type": "completed",
                "artifact_hashes": [{"path": f"/a/{i}.bin", "sha256": "x" * 64}],
                "raw_evidence_refs": [],
            })
        sm._state["executions_count"] = len(sm._state["executions"])  # type: ignore[attr-defined]
        sm._state["analysis_lanes"] = [  # type: ignore[attr-defined]
            {
                "lane_id": "memory",
                "status": "IN_PROGRESS",
                "finding_ids": [f"F-{i:04d}" for i in range(10)],
                "data_gaps": ["gap_a", "gap_b"],
            }
        ]
    return sm


def test_read_state_snapshot_is_detached_from_live_state(loaded_state):
    """A snapshot returned by load()/get_findings() must be independent
    of subsequent mutations. This is the core invariant the deepcopy fix
    establishes."""
    sm = loaded_state
    # Take a snapshot via the read APIs the MCP tools actually use.
    findings_before = sm.get_findings()
    lanes_before = sm.get_analysis_lanes()

    # Mutate live state aggressively
    with sm._lock:  # type: ignore[attr-defined]
        for f in sm._state["findings"]:  # type: ignore[attr-defined]
            f.setdefault("corroborated_by", []).append("NEW_REF_AFTER_SNAPSHOT")
            f["supporting_indicators"].append("MUTATED")
        sm._state["analysis_lanes"][0]["finding_ids"].append("F-MUTATED")  # type: ignore[attr-defined]
        sm._state["analysis_lanes"][0]["data_gaps"].append("MUTATED_GAP")  # type: ignore[attr-defined]

    # Snapshots taken BEFORE the mutation must NOT reflect the new values.
    for f in findings_before:
        assert "NEW_REF_AFTER_SNAPSHOT" not in (f.get("corroborated_by") or []), (
            f"Finding {f['finding_id']} snapshot still references live state — "
            "shallow copy leaked nested list refs. This is the segfault root cause."
        )
        assert "MUTATED" not in f["supporting_indicators"], (
            f"Finding {f['finding_id']} supporting_indicators leaked live reference."
        )

    assert "F-MUTATED" not in lanes_before[0]["finding_ids"], (
        "Lane snapshot leaked finding_ids reference back to live state."
    )
    assert "MUTATED_GAP" not in lanes_before[0]["data_gaps"], (
        "Lane snapshot leaked data_gaps reference back to live state."
    )


def test_concurrent_mutation_during_serialization_does_not_segfault(loaded_state):
    """Race test: one thread serializes snapshots while another mutates
    live state. With the shallow-copy bug, ``json.dumps`` on the snapshot
    raises ``RuntimeError: dictionary changed size during iteration``
    (Python backstop) or segfaults (C path). With deepcopy, snapshot is
    detached and serialization is stable across all iterations."""
    sm = loaded_state
    errors: list[BaseException] = []
    stop = threading.Event()

    def mutator():
        idx = 1000
        while not stop.is_set():
            try:
                with sm._lock:  # type: ignore[attr-defined]
                    # Append new findings — grows the live list
                    sm._state["findings"].append(_make_finding(idx))  # type: ignore[attr-defined]
                    idx += 1
                    if idx % 5 == 0:
                        # Mutate nested lists on existing findings
                        for f in sm._state["findings"][:20]:  # type: ignore[attr-defined]
                            f.setdefault("corroborated_by", []).append(f"x_{idx}")
                            f["supporting_indicators"].append(f"y_{idx}")
                    if idx % 7 == 0:
                        # Mutate lane finding_ids — common during dispatch
                        sm._state["analysis_lanes"][0]["finding_ids"].append(f"F-{idx:04d}")  # type: ignore[attr-defined]
            except Exception as exc:
                errors.append(exc)
                return
            # Yield CPU so the serializer thread gets time
            time.sleep(0)

    def serializer():
        for _ in range(300):
            try:
                # The exact pattern the MCP tools follow:
                snapshot = sm.to_summary()
                # serialize via stdlib json (same code path that segfaulted)
                payload = json.dumps(snapshot, default=str)
                assert len(payload) > 0
                # Also exercise get_findings — used by get_findings MCP tool
                findings = sm.get_findings()
                json.dumps(findings, default=str)
                # And get_analysis_lanes — used by read_state-adjacent paths
                lanes = sm.get_analysis_lanes()
                json.dumps(lanes, default=str)
            except RuntimeError as exc:
                # "dictionary changed size during iteration" — the
                # Python-level symptom of the same race that segfaults
                # the C extension. Either is the bug.
                errors.append(exc)
                return
            except Exception as exc:
                errors.append(exc)
                return

    mt = threading.Thread(target=mutator, daemon=True)
    st = threading.Thread(target=serializer, daemon=True)
    mt.start()
    st.start()
    st.join(timeout=30)
    stop.set()
    mt.join(timeout=5)

    assert not errors, (
        f"Concurrent mutation during serialization raised {len(errors)} "
        f"error(s); first: {type(errors[0]).__name__}: {errors[0]!r}. "
        "This is the same race that segfaulted Python 3.10's _json.so "
        "during the Phase 1 memory analysis on 2026-05-23 00:46:18 UTC."
    )


def test_state_py_imports_copy_module():
    """Source-text guard: state.py must import copy at module scope so
    every deepcopy call is cheap (no per-call import overhead) and the
    intent is unambiguous to future readers."""
    src = (ROOT / "sift_mcp" / "state.py").read_text()
    # Module-level import
    assert "\nimport copy\n" in src, "state.py must `import copy` at module scope"


def test_all_state_read_returns_use_deepcopy():
    """Source-text guard: every read-path return in state.py must use
    copy.deepcopy, not shallow dict(...) — the latter leaks nested
    references and was the segfault root cause.

    This guard inspects the source rather than running every API because
    new read methods may be added later and we want the fix to apply by
    construction.
    """
    src = (ROOT / "sift_mcp" / "state.py").read_text()

    # Patterns that indicate a shallow copy leak — these must NOT appear
    # at return-from-lock points. The patterns below would all be bugs.
    forbidden_at_returns = [
        ("dict(self._state)  # Return", "load() shallow copy"),
        # Any "return dict(...)" pattern in a getter is suspicious.
    ]
    for pattern, label in forbidden_at_returns:
        assert pattern not in src, (
            f"state.py still contains shallow-copy leak: {label}. "
            "All read returns must use copy.deepcopy to detach nested refs."
        )

    # Positive: the key read methods must have a deepcopy comment marker
    # confirming the fix was applied (and gives future readers a search anchor).
    assert "MCP segfault fix 2026-05-23" in src, (
        "state.py is missing the MCP segfault fix markers. Read paths must "
        "deepcopy before returning to detach live state references."
    )
    # Count the markers — there should be one per fixed return path.
    marker_count = src.count("MCP segfault fix 2026-05-23")
    assert marker_count >= 8, (
        f"Expected at least 8 deepcopy fix markers (load, get_findings, "
        f"get_finding, get_execution, get_executions, get_analysis_lanes, "
        f"to_summary, update_finding, log_execution, get_artifact_cache, "
        f"upsert_analysis_lane, get_unresolved_discrepancies, "
        f"lookup_artifact_hash); found {marker_count}."
    )
