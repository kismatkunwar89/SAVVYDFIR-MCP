#!/usr/bin/env python3
"""Strip the Phase 3 playbook overlay from specialist .md files.

Phase 3 refactor (2026-05-22) added a prescriptive playbook on top of
the user's original heuristic content, violating the user's explicit
design intent ("Heuristics, not procedures"). This script restores
the original design by removing the Phase 3 overlay.

What gets stripped (per file):
  - C-PRIME Output Discipline (## C-PRIME Output Discipline)
  - Playbook (## Playbook (Phase 3 refactor - ))
  - Numbered QUERY sections (### QUERY 1, ### QUERY 2, ...)
  - Final Response Contract (## Final Response Contract (MANDATORY))

What gets preserved (per file):
  - Frontmatter (lines 1-12)
  - File title (# ...)
  - All user-authored heuristic content from "## Forensic Ground Rules"
    onwards, OR if that header is missing, from the first "## " heading
    that is NOT in the strip-list

A short new intro is inserted between the title and heuristic content
explaining the file is reference context (not a procedural playbook).

(PLAN-FIND-EVIL-HACKATHON-2026-05-23.md Section 5.3).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / ".claude" / "agents"

# Files to process (the 8 artifact specialists that received Phase 3 overlay)
TARGET_FILES = [
    "mft-analyst.md",
    "evtx-analyst.md",
    "prefetch-analyst.md",
    "amcache-analyst.md",
    "registry-analyst.md",
    "srum-analyst.md",
    "sigma-analyst.md",
    "memory-analyst.md",
]

# Headings that mark the start of the user's preserved heuristic content.
# The script keeps from the FIRST occurrence of any of these onwards.
PRESERVE_FROM_HEADINGS = [
    "## Forensic Ground Rules",
    "## Critical Forensic Distinction",  # amcache has this before Forensic Ground Rules
]

# Headings that are part of the Phase 3 overlay (strip everything between the
# title and the first preserve heading).
PHASE3_HEADINGS = [
    "## C-PRIME Output Discipline",
    "## Playbook (Phase 3 refactor",
    "## Final Response Contract",
]

INTRO_TEMPLATE = """## How this file is used

This is a **forensic-heuristic knowledge base**, not a procedural playbook.
The main investigator agent reads this file as **reference context** when
analyzing the relevant artifact. Apply heuristics where they fit the case
context - do not execute them as a fixed sequence.

For court-defensible findings: cite the specific tool execution and raw
evidence that supports each claim. Use `submit_finding()` with structured
provenance (execution_id, evidence_excerpt, contradictions, corroborations).

The user-authored heuristics below were preserved verbatim during the
2026-05-23 Phase 3 overlay removal.

"""


def find_preserve_start(lines: list[str]) -> int:
    """Return the 0-indexed line where the preserved heuristic content starts.

    Looks for the first occurrence of any header in PRESERVE_FROM_HEADINGS.
    Returns -1 if none found (file should not be stripped).
    """
    for i, line in enumerate(lines):
        for heading in PRESERVE_FROM_HEADINGS:
            if line.strip().startswith(heading):
                return i
    return -1


def find_frontmatter_end(lines: list[str]) -> int:
    """Return the 0-indexed line of the closing --- of the frontmatter."""
    if not lines or lines[0].strip() != "---":
        return -1
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return i
    return -1


def find_title_line(lines: list[str], frontmatter_end: int) -> int:
    """Return the 0-indexed line of the # Title header after frontmatter."""
    for i in range(frontmatter_end + 1, len(lines)):
        if lines[i].startswith("# ") and not lines[i].startswith("## "):
            return i
    return -1


def process_file(file_path: Path) -> tuple[bool, str]:
    """Strip Phase 3 overlay from a single specialist .md file.

    Returns (changed, message).
    """
    if not file_path.exists():
        return False, f"NOT FOUND: {file_path.name}"

    original_text = file_path.read_text(encoding="utf-8")
    lines = original_text.splitlines(keepends=True)

    frontmatter_end = find_frontmatter_end(lines)
    if frontmatter_end < 0:
        return False, f"NO FRONTMATTER: {file_path.name}"

    title_line = find_title_line(lines, frontmatter_end)
    if title_line < 0:
        return False, f"NO # TITLE: {file_path.name}"

    preserve_start = find_preserve_start(lines)
    if preserve_start < 0:
        return False, f"NO PRESERVE-FROM HEADING: {file_path.name} (skipped — no heuristic content found)"

    # Sanity check: preserve_start must be AFTER title_line
    if preserve_start <= title_line:
        return False, f"PRESERVE BEFORE TITLE: {file_path.name} (line ordering anomaly)"

    # Verify we're actually removing Phase 3 overlay (not stripping accidentally)
    stripped_region = "".join(lines[title_line + 1:preserve_start])
    has_phase3 = any(h in stripped_region for h in PHASE3_HEADINGS)
    if not has_phase3:
        return False, f"NO PHASE 3 MARKERS: {file_path.name} (already clean? skipping)"

    # Build the new file content
    new_lines = []
    new_lines.extend(lines[:title_line + 1])    # frontmatter + title
    new_lines.append("\n")                       # blank line after title
    new_lines.append(INTRO_TEMPLATE)
    new_lines.extend(lines[preserve_start:])    # heuristic content + below

    new_text = "".join(new_lines)

    # Only write if content actually changed
    if new_text == original_text:
        return False, f"NO CHANGE: {file_path.name}"

    # Backup the original (one-time backup, only if backup doesn't exist)
    backup_path = file_path.with_suffix(".md.phase3-backup")
    if not backup_path.exists():
        backup_path.write_text(original_text, encoding="utf-8")

    file_path.write_text(new_text, encoding="utf-8")

    before_lines = len(lines)
    after_lines = len(new_lines)
    removed = before_lines - after_lines
    return True, f"STRIPPED: {file_path.name} ({before_lines} → {after_lines} lines, removed {removed})"


def main() -> int:
    if not AGENTS_DIR.is_dir():
        print(f"ERROR: agents dir not found: {AGENTS_DIR}", file=sys.stderr)
        return 1

    print("Phase 3 overlay strip — preserving user-authored heuristic content")
    print(f"Target dir: {AGENTS_DIR}")
    print()

    changed_count = 0
    error_count = 0
    for filename in TARGET_FILES:
        file_path = AGENTS_DIR / filename
        changed, message = process_file(file_path)
        print(f"  {message}")
        if changed:
            changed_count += 1
        elif "NOT FOUND" in message or "NO FRONTMATTER" in message or "NO # TITLE" in message:
            error_count += 1

    print()
    print(f"Summary: {changed_count} files stripped, {error_count} errors, "
          f"{len(TARGET_FILES) - changed_count - error_count} skipped (already clean)")
    print()
    print("Backups created at *.md.phase3-backup (per-file, idempotent).")
    print("To restore: cp <file>.md.phase3-backup <file>.md")

    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
