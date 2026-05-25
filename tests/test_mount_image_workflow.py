"""Regression tests for mount_image SleuthKit-direct workflow guidance.

Fresh-user lesson from Run-8/9: when an EWF image can't be NTFS-mounted
and only SleuthKit-direct access is available, the next disk tool must
be extract_windows_artifacts — calling extract_mft_timeline, summarize_evtx,
get_amcache, extract_registry_run_keys, extract_shimcache, extract_srum,
or extract_usn_journal FIRST will fail with "file not found" because
those tools default to /mnt/disk/<path> which doesn't exist.

mount_image's response must:
  1. Carry next_required_tool = "extract_windows_artifacts" so hooks +
     the LLM see the unambiguous next step
  2. Carry next_required_tool_args with the device path + offset
  3. Include the explicit MANDATORY directive in note text
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_mount_image_tsk_direct_response_shape_source_check():
    """Source-text guard: mount_image's tsk_direct branch must emit:
      - next_required_tool: "extract_windows_artifacts"
      - next_required_tool_args (dict with image_path, tsk_device_path, partition_offset_sectors)
      - explicit MANDATORY directive in the note
    """
    src = (ROOT / "sift_mcp" / "server.py").read_text()
    # Find the tsk_direct branch in mount_image
    idx = src.find('"mount_status": "tsk_direct"')
    assert idx > 0, "tsk_direct branch not found in mount_image"
    # Slice to the closing of this dict literal
    block_end = src.find("})", idx)
    block = src[idx:block_end] if block_end > 0 else src[idx:idx + 2500]

    assert '"next_required_tool": "extract_windows_artifacts"' in block, (
        "mount_image tsk_direct branch must set next_required_tool to "
        "'extract_windows_artifacts' — fresh users need an unambiguous "
        "next step, not just a note."
    )
    assert "next_required_tool_args" in block, (
        "mount_image tsk_direct branch must carry next_required_tool_args "
        "with the device/offset so the agent can call extract_windows_artifacts "
        "with the correct arguments without parsing the note text."
    )
    assert "MANDATORY next: call extract_windows_artifacts" in block, (
        "mount_image tsk_direct note must contain the explicit MANDATORY "
        "directive so an agent that ignores structured fields still sees "
        "the requirement in plain prose."
    )


def test_workflow_post_hook_handles_mount_image():
    """PostToolUse hook must run on mount_image (in addition to summarize_evtx,
    sigma_hunt, compare_disk_and_memory) so the SleuthKit-direct nudge fires."""
    import json
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    post_hooks = settings.get("hooks", {}).get("PostToolUse", [])
    matchers = [h.get("matcher", "") for h in post_hooks]
    assert any("mcp__savvydfir__mount_image" in m for m in matchers), (
        f"PostToolUse hook must match mcp__savvydfir__mount_image so the "
        f"SleuthKit-direct directive fires after mount_image returns. "
        f"Current matchers: {matchers}"
    )


def test_workflow_post_hook_emits_extract_windows_artifacts_for_tsk_direct():
    """Behavior test: simulate a mount_image tsk_direct result and verify
    the PostToolUse hook emits the extract_windows_artifacts directive."""
    import json, subprocess, os
    event = {
        "tool_name": "mcp__savvydfir__mount_image",
        "cwd": str(ROOT),
        "tool_input": {"image_path": "/evidence/disk/test.E01"},
        "tool_result": {
            "data": {
                "access_mode": "sleuthkit_direct",
                "mount_status": "tsk_direct",
                "tsk_device_path": "/mnt/evidence/ewf1",
                "next_tools": {
                    "device_path": "/mnt/evidence/ewf1",
                    "partition_offset_sectors": 0,
                },
            },
        },
    }
    r = subprocess.run(
        ["python3", str(ROOT / ".claude" / "hooks" / "workflow-enforce-post.py")],
        input=json.dumps(event),
        capture_output=True, text=True, timeout=15,
        env={**os.environ},
    )
    assert r.stdout.strip(), "hook must emit a directive for tsk_direct"
    out = json.loads(r.stdout)
    ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
    assert "extract_windows_artifacts" in ctx, (
        f"PostToolUse must direct the agent to extract_windows_artifacts. "
        f"Got: {ctx[:200]}"
    )
    assert "BEFORE any other disk tool" in ctx or "Stage raw artifacts" in ctx, (
        f"directive must explain the BEFORE-ordering requirement: {ctx[:200]}"
    )


def test_workflow_post_hook_silent_for_normal_mount():
    """Negative behavior test: if mount_image returns a normal NTFS mount
    (no tsk_direct), the hook should NOT inject the extract_windows_artifacts
    directive — it's only for SleuthKit-direct access mode."""
    import json, subprocess, os
    event = {
        "tool_name": "mcp__savvydfir__mount_image",
        "cwd": str(ROOT),
        "tool_input": {},
        "tool_result": {
            "data": {
                "mount_path": "/mnt/disk",
                "mount_status": "mounted",
                "access_mode": "ntfs_read_only",
            },
        },
    }
    r = subprocess.run(
        ["python3", str(ROOT / ".claude" / "hooks" / "workflow-enforce-post.py")],
        input=json.dumps(event),
        capture_output=True, text=True, timeout=15,
        env={**os.environ},
    )
    # No directive expected for normal mount path
    assert not r.stdout.strip() or "extract_windows_artifacts" not in r.stdout, (
        f"Hook should not nudge extract_windows_artifacts for a normal NTFS "
        f"mount. Got: {r.stdout[:200]}"
    )
