#!/usr/bin/env python3
"""Compatibility wrapper for the canonical SAVVYDFIR PostToolUse dispatcher."""

from __future__ import annotations

import runpy
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    runpy.run_path(str(repo_root / "scripts" / "agent_trigger.py"), run_name="__main__")


if __name__ == "__main__":
    main()
