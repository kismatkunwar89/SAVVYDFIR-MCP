#!/usr/bin/env python3
"""SessionStart hook: verify SIFT/DFIR prerequisites before investigation begins.

Fails fast if a tool the investigation will need is missing, instead of
having the parent agent discover it mid-run with a confusing error.

Checks (all optional — missing prerequisites do not BLOCK the session, they
only WARN, because Claude Code sessions are used for tasks beyond DFIR):
 1. dotnet (for EZ Tools)
 2. chainsaw (for sigma_hunt)
 3. python3 (for SrumECmd, validate_run.py, log2timeline)
 4. /evidence/ directory readable (skip warning if not present — non-DFIR session)
 5. case-templates/manifest.json schema-valid (if present, must validate)

Exit code 0 always — warnings go to stderr, blocking is reserved for the
Stop hook where we have actual investigation state to assess.
"""
import json
import os
import shutil
import sys
from pathlib import Path


# Resolve the project being worked on from CWD, not the hook's location.
# The hook may be installed in ~/.claude/ but check the actual project root.
REPO_ROOT = Path.cwd()


def _check_tool(name: str) -> tuple[bool, str]:
    path = shutil.which(name)
    if path:
        return True, f"{name} → {path}"
    return False, f"{name} not on PATH"


def _check_manifest(repo_root: Path) -> tuple[bool, str]:
    """If case-templates/manifest.json exists, must pass schema."""
    manifest_path = repo_root / "case-templates" / "manifest.json"
    if not manifest_path.is_file():
        return True, "case-templates/manifest.json not present (non-DFIR session)"
    try:
        sys.path.insert(0, str(repo_root))
        from sift_mcp.models.case import CaseManifest  # noqa: WPS433
        with manifest_path.open(encoding="utf-8") as fh:
            CaseManifest(**json.load(fh))
        return True, "manifest schema valid"
    except Exception as exc:
        return False, f"manifest validation FAILED: {type(exc).__name__}: {exc}"


def _check_evidence(repo_root: Path) -> tuple[bool, str]:
    """If /evidence/ exists, must be readable."""
    if not Path("/evidence").is_dir():
        return True, "/evidence/ not mounted (non-DFIR session)"
    if not os.access("/evidence", os.R_OK):
        return False, "/evidence/ present but not readable"
    return True, "/evidence/ readable"


def _record_session_for_ledger(stdin_payload: dict, repo_root: Path) -> None:
    """Phase 3a: record this session's identifier so PostToolUse and
    workflow-enforce hooks can correlate ledger rows by session_id.

    Also emit ``task_unavailable_session`` if Task / Agent is missing
    from the allowlist — that marker authorizes Path B for every
    specialist lane in this session (and ONLY this session).
    """
    # Diagnostic trace — verify SessionStart hook is invoked.
    try:
        from datetime import datetime as _dt, timezone as _tz
        import os as _os
        ts = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        path = _os.environ.get("SAVVYDFIR_HOOK_DEBUG_LOG", "/tmp/savvydfir_hook_debug.log")
        sid = stdin_payload.get("session_id") or stdin_payload.get("sessionId") or "?"
        fd = _os.open(path, _os.O_WRONLY | _os.O_APPEND | _os.O_CREAT, 0o666)
        try:
            _os.write(fd, f"{ts} SessionStart sid={sid!r} stdin_keys={sorted(stdin_payload.keys())}\n".encode("utf-8"))
        finally:
            _os.close(fd)
        try:
            _os.chmod(path, 0o666)
        except OSError:
            pass
    except Exception:
        pass

    session_id = stdin_payload.get("session_id") or stdin_payload.get("sessionId")
    if not isinstance(session_id, str) or not session_id:
        return

    scripts_dir = repo_root / "scripts"
    if scripts_dir.is_dir() and str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    try:
        from delegation_ledger import (  # type: ignore  # noqa: WPS433
            append_row,
            write_session_pointer,
        )
    except Exception:
        return

    cwd = stdin_payload.get("cwd") or str(Path.cwd())
    write_session_pointer(session_id, cwd=cwd)

    # Detect Task-tool availability from the most authoritative signal
    # we can read at SessionStart: the project's .claude/settings.json
    # allowlist. The Claude Code CLI may augment via --allowedTools at
    # invocation time, but if the settings already declare Agent / Task,
    # subagent dispatch should be permitted.
    task_available = True
    try:
        settings_path = repo_root / ".claude" / "settings.json"
        if settings_path.is_file():
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            allow = (
                (settings.get("permissions") or {}).get("allow")
                or settings.get("allowedTools")
                or settings.get("allowed-tools")
                or []
            )
            allow_str = " ".join(map(str, allow)) if isinstance(allow, list) else str(allow)
            if "Agent" not in allow_str and "Task" not in allow_str:
                task_available = False
    except Exception:
        # Fail open — assume Task is available; per-lane attempts will
        # disprove it via task_outcome rows.
        task_available = True

    if not task_available:
        append_row(
            "task_unavailable_session",
            session_id=session_id,
            decision_basis="Agent/Task not present in .claude/settings.json allow list",
        )


def main() -> None:
    # Read SessionStart payload (carries session_id, transcript_path, cwd)
    stdin_payload: dict = {}
    try:
        raw = sys.stdin.read()
        if raw:
            stdin_payload = json.loads(raw)
    except Exception:
        stdin_payload = {}

    # Phase 3a observation-only delegation-ledger pointer + task-availability marker
    try:
        _record_session_for_ledger(stdin_payload, REPO_ROOT)
    except Exception as exc:
        print(f"[session-start] WARN ledger pointer failed: {exc}", file=sys.stderr)

    checks = [
        ("dotnet", _check_tool("dotnet")),
        ("chainsaw", _check_tool("chainsaw")),
        ("python3", _check_tool("python3")),
        ("evidence", _check_evidence(REPO_ROOT)),
        ("manifest", _check_manifest(REPO_ROOT)),
    ]

    warnings: list[str] = []
    for name, (ok, msg) in checks:
        if ok:
            print(f"[session-start] OK  {name}: {msg}", file=sys.stderr)
        else:
            print(f"[session-start] WARN {name}: {msg}", file=sys.stderr)
            warnings.append(f"{name}: {msg}")

    # Schema-valid manifest is the only HARD prerequisite — if it's bad,
    # the run will fail immediately when start_investigation is called.
    manifest_ok = checks[-1][1][0]
    if not manifest_ok:
        # Block the session start with a clear reason.
        print(
            json.dumps({
                "decision": "block",
                "reason": (
                    "SessionStart prerequisites failed: "
                    + checks[-1][1][1]
                    + ". Fix case-templates/manifest.json before running."
                ),
            })
        )
        return

    # Tool warnings are surfaced via stderr but do not block.
    # Most non-DFIR sessions don't need chainsaw/dotnet/evidence.
    print(json.dumps({"decision": "approve"}))


if __name__ == "__main__":
    main()
