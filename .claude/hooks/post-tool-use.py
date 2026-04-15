#!/usr/bin/env python3
"""Compatibility wrapper for the canonical SAVVYDFIR PostToolUse dispatcher.

Catches all exceptions to prevent hook noise — a failing dispatcher must
never block the investigation session.
"""

from __future__ import annotations

import sys
import runpy
from pathlib import Path


def main() -> None:
    try:
        repo_root = Path(__file__).resolve().parents[2]
        runpy.run_path(str(repo_root / "scripts" /
                       "agent_trigger.py"), run_name="__main__")
    except Exception:
        # Silently absorb errors — the hook must never block the session.
        # The agent_trigger.py main() already handles most cases; this
        # catches import errors, runpy failures, etc.
        pass


if __name__ == "__main__":
    main()
