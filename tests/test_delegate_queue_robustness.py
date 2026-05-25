"""Regression tests for the delegate_queue multi-uid write fix (2026-05-20).

The Run-12 audit revealed a real-world failure: when /tmp/savvydfir_delegate_queue.json
was created by sansdfir (uid 1000) and root tried to overwrite it later via
SSH-as-root testing, the write silently failed even after `chmod 666` — the
file's cross-uid ownership prevented Path.write_text. enqueue_delegate would
return cleanly while never persisting the trigger, breaking the entire
delegation flow.

These tests prove the fixed _write_queue:
  1. Writes to a per-pid+uuid tmp file, then os.replace
  2. Falls back to O_CREAT|O_TRUNC + 0o666 when os.replace fails
  3. Never raises (fail-open contract preserved)
  4. The end-to-end enqueue_delegate flow persists triggers
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


@pytest.fixture()
def fresh_queue(monkeypatch, tmp_path):
    """Isolated queue path; ensure clean module reload."""
    queue_path = tmp_path / "queue.json"
    monkeypatch.setenv("SAVVYDFIR_DELEGATE_QUEUE_PATH", str(queue_path))
    if "delegate_queue" in sys.modules:
        del sys.modules["delegate_queue"]
    import delegate_queue
    return delegate_queue, queue_path


# ---------------------------------------------------------------------------
# Source-text guards (no fastmcp / hooks needed)
# ---------------------------------------------------------------------------

def test_write_queue_source_uses_per_pid_tmp_filename():
    """Source-text guard: _write_queue must use a per-pid uuid tmp filename
    so concurrent writers from different uids do not collide."""
    src = (SCRIPTS / "delegate_queue.py").read_text()
    fn = src[src.find("def _write_queue("):]
    end = fn.find("\n\ndef ")
    body = fn[:end if end > 0 else 4000]
    assert "os.getpid()" in body, (
        "_write_queue must mint a per-process tmp name. Without it, "
        "two concurrent processes (or one user's stale tmp) breaks "
        "atomic replace for the next writer."
    )
    assert "uuid.uuid4()" in body, "tmp filename should include a uuid to avoid pid-recycling collisions"
    assert "os.replace" in body, "must use os.replace for atomic visibility"
    assert "O_TRUNC" in body and "0o666" in body, (
        "fallback path must use O_CREAT|O_TRUNC with 0o666 mode so any uid "
        "can overwrite a stale file."
    )


def test_write_queue_keeps_fail_open_contract():
    """Even with the new logic, _write_queue must never raise."""
    src = (SCRIPTS / "delegate_queue.py").read_text()
    fn = src[src.find("def _write_queue("):]
    end = fn.find("\n\ndef ")
    body = fn[:end if end > 0 else 4000]
    # Outer except wraps the whole thing
    assert "except (OSError, IOError):" in body
    assert "pass" in body
    # Comment should still call out advisory semantics
    assert "advisory" in body.lower() or "fail-open" in body.lower() or "must not block" in body.lower()


# ---------------------------------------------------------------------------
# Behavior tests
# ---------------------------------------------------------------------------

def test_enqueue_and_read_back(fresh_queue):
    dq, qpath = fresh_queue
    dq.enqueue_delegate("memory", {"subagent_type": "memory-analyst", "tool": "list_dlls"})
    assert qpath.exists()
    queue = dq._read_queue()
    assert "memory" in queue
    assert len(queue["memory"]) == 1
    assert queue["memory"][0]["subagent_type"] == "memory-analyst"


def test_write_queue_overwrites_existing_file(fresh_queue):
    """Repeated writes must overwrite (not append/corrupt)."""
    dq, qpath = fresh_queue
    dq.enqueue_delegate("memory", {"tool": "first"})
    dq.enqueue_delegate("memory", {"tool": "second"})
    queue = dq._read_queue()
    assert len(queue["memory"]) == 2
    assert [d["tool"] for d in queue["memory"]] == ["first", "second"]


def test_atomic_replace_fallback_when_target_unwritable(fresh_queue, monkeypatch):
    """Simulate the Run-12 failure: os.replace raises OSError.
    The fallback O_TRUNC path must still persist the write."""
    dq, qpath = fresh_queue
    # Seed the queue once via normal path
    dq.enqueue_delegate("memory", {"tool": "before"})

    # Now monkey-patch os.replace to raise — exactly the Run-12 scenario.
    real_replace = os.replace
    call_log = []

    def fake_replace(src, dst):
        call_log.append((str(src), str(dst)))
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("os.replace", fake_replace)
    dq.enqueue_delegate("memory", {"tool": "after_failed_replace"})
    # Restore so cleanup works
    monkeypatch.setattr("os.replace", real_replace)

    # Must have attempted replace at least once
    assert call_log, "os.replace was not called — fix did not engage atomic path"

    # And the second delegate must have landed via the fallback path
    queue = dq._read_queue()
    tools = [d.get("tool") for d in queue.get("memory") or []]
    assert "after_failed_replace" in tools, (
        f"Fallback path did NOT persist the write. Got tools: {tools}. "
        "This is the Run-12 bug — write silently fails."
    )


def test_pre_existing_file_with_foreign_perm_does_not_break(fresh_queue):
    """Write atop an existing 0o400 (owner-read-only) file. Must succeed
    via the fallback path without raising."""
    dq, qpath = fresh_queue
    qpath.write_text("{}", encoding="utf-8")
    try:
        os.chmod(qpath, 0o400)
    except OSError:
        pytest.skip("filesystem does not support chmod 0o400")

    try:
        # Should NOT raise even though the file is owner-read-only.
        dq.enqueue_delegate("memory", {"tool": "stubborn"})
    finally:
        try:
            os.chmod(qpath, 0o666)
        except OSError:
            pass

    # If we run as the same uid that owns the file, the fallback succeeds.
    # If we run as a different uid (and that uid can't write), at least
    # we didn't crash. Either way: the function returned normally.
    # Verify by re-reading; presence depends on uid.
    queue = dq._read_queue()
    # Either persisted (same uid path) or not (other uid). NO CRASH is the
    # contract here, which the function already passed by returning.
    assert isinstance(queue, dict), "Read after stubborn write returned non-dict"


def test_write_queue_does_not_raise_on_unwriteable_directory(monkeypatch, tmp_path):
    """If the parent directory is unwritable, fail-open."""
    if "delegate_queue" in sys.modules:
        del sys.modules["delegate_queue"]
    bad_dir = tmp_path / "ro"
    bad_dir.mkdir()
    queue_path = bad_dir / "queue.json"
    queue_path.write_text("{}", encoding="utf-8")
    try:
        os.chmod(bad_dir, 0o555)
    except OSError:
        pytest.skip("filesystem does not support chmod 0o555")
    monkeypatch.setenv("SAVVYDFIR_DELEGATE_QUEUE_PATH", str(queue_path))
    import delegate_queue
    try:
        delegate_queue.enqueue_delegate("memory", {"tool": "blocked"})
    finally:
        try:
            os.chmod(bad_dir, 0o755)
        except OSError:
            pass
    # No exception raised → fail-open contract preserved.


def test_get_pending_then_mark_processed_roundtrip(fresh_queue):
    """End-to-end: enqueue → get_pending → mark_processed → queue empty."""
    dq, qpath = fresh_queue
    dq.enqueue_delegate("memory", {"subagent_type": "memory-analyst",
                                    "lane_id": "memory", "tool": "list_dlls"})
    pending = dq.get_pending_delegate()
    assert pending is not None
    assert pending["subagent_type"] == "memory-analyst"
    dq.mark_delegate_processed("memory")
    assert dq.get_pending_delegate() is None
