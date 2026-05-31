"""extract_heuristic_slice.py - Read canonical heuristic .md files and return
bounded slices for MCP injection (W1.7 Option X).

Used by:
- sift_mcp/tools/_contracts.py::build_contract_response (Tier-1 per-artifact injection)
- sift_mcp/server.py::prepare_hypothesis_context (Tier-2 hypothesis context bundle)
- sift_mcp/server.py::get_heuristic (Tier-3 on-demand depth reader)

The .md files at .claude/agents/<artifact>-analyst.md are CANONICAL forensic
heuristic knowledge bases authored by the user. They use a mix of section
headers - this module handles the variance and produces deterministic,
hashable, audit-citable slices.

Header inventory (verified across 8 artifact files):
- All 8: "## Forensic Ground Rules"
- 7/8:   "## What to Hunt (Heuristics, not procedures)"
- 1/8 (prefetch): "## Critical Forensic Heuristics"
- 6/8:   "## Professional Patterns (from ...)"
- All 8: "## Output Format", "## Query Pattern", "## Systematic Coverage Pattern"
  (workflow sections - NOT in the heuristic slice; agent already knows pattern)

CTX audit chain (court-grade provenance):
    finding → execution_id → CTX-NNN → source_path + source_hash + section + excerpt_hash

(CR13).
"""
from __future__ import annotations

import functools
import hashlib
import re
from pathlib import Path
from typing import Any, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / ".claude" / "agents"

# Section header candidates that constitute the "heuristic" portion of each .md.
# Ordered by priority - the slice extractor walks this list and concatenates
# matching sections in declaration order. "What to Hunt" and "Critical Forensic
# Heuristics" are the primary heuristic surfaces; "Forensic Ground Rules" is
# always included as the framing preamble.
HEURISTIC_SECTION_HEADERS: list[str] = [
    "## Forensic Ground Rules",
    "## What to Hunt (Heuristics, not procedures)",
    "## Critical Forensic Heuristics",
    "## Critical Forensic Distinction",
    # "Professional Patterns" is depth-only - included by get_heuristic on demand,
    # NOT in the Tier-1 / Tier-2 slice (would blow budget).
]

# All sections that could be requested via get_heuristic(artifact, topic).
# Maps topic identifier → section header substring.
TOPIC_REGISTRY: dict[str, str] = {
    "forensic_ground_rules": "Forensic Ground Rules",
    "what_to_hunt": "What to Hunt",
    "critical_heuristics": "Critical Forensic Heuristics",
    "critical_distinction": "Critical Forensic Distinction",
    "professional_patterns": "Professional Patterns",
    "query_pattern": "Query Pattern",
    "systematic_coverage": "Systematic Coverage Pattern",
    "output_format": "Output Format",
}

# Artifact name → canonical .md file mapping. The 8 artifact specialists that
# carry forensic-heuristic knowledge for the FIND EVIL! hackathon.
ARTIFACT_FILE_MAP: dict[str, str] = {
    "mft": "mft-analyst.md",
    "evtx": "evtx-analyst.md",
    "prefetch": "prefetch-analyst.md",
    "amcache": "amcache-analyst.md",
    "registry": "registry-analyst.md",
    "srum": "srum-analyst.md",
    "sigma": "sigma-analyst.md",
    "memory": "memory-analyst.md",
}

# Tier-1 injection budget (per-artifact, post-csv_path). Tokens roughly = chars/4.
TIER1_MAX_CHARS = 3200      # ~800 tokens
TIER2_MAX_CHARS = 2400      # ~600 tokens per artifact slice in hypothesis bundle
TIER3_MAX_CHARS = 1800      # ~450 tokens for targeted topic lookups


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    """Stable SHA-256 of text, returned as 'sha256:<hex>'."""
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _approx_token_count(text: str) -> int:
    """Approximate token count (~4 chars / token for English+code mix)."""
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# File access (cached by mtime-invalidated path read)
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=32)
def _read_md_file(path: str, mtime: float) -> tuple[str, str]:
    """Read .md file content + compute source hash. Cached by (path, mtime).

    The mtime in the cache key forces a re-read when the file changes,
    preventing stale slices from breaking the audit chain.
    """
    text = Path(path).read_text(encoding="utf-8")
    return text, _sha256(text)


def _load_artifact_md(artifact: str) -> Optional[tuple[Path, str, str]]:
    """Resolve an artifact name to (path, text, source_hash) or None."""
    filename = ARTIFACT_FILE_MAP.get(artifact.lower())
    if not filename:
        return None
    path = AGENTS_DIR / filename
    if not path.exists():
        return None
    text, src_hash = _read_md_file(str(path), path.stat().st_mtime)
    return path, text, src_hash


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------

_HEADER_PATTERN = re.compile(r"^(##+ )", re.MULTILINE)


def _extract_sections(text: str) -> dict[str, str]:
    """Parse the .md text into a {header: content} dict.

    Header keys preserve the full original heading line (without leading '## ').
    Content includes everything from after the header line up to (but not
    including) the next same-level-or-higher header.
    """
    sections: dict[str, str] = {}
    lines = text.splitlines()
    current_header: Optional[str] = None
    current_buf: list[str] = []

    for line in lines:
        # Only treat '## ' (level-2) as section boundaries; ignore '### ' etc.
        if line.startswith("## "):
            if current_header is not None:
                sections[current_header] = "\n".join(current_buf).strip()
            current_header = line[3:].strip()
            current_buf = []
        else:
            if current_header is not None:
                current_buf.append(line)

    if current_header is not None:
        sections[current_header] = "\n".join(current_buf).strip()

    return sections


def _find_section_by_substring(
    sections: dict[str, str], needle: str
) -> Optional[tuple[str, str]]:
    """Find first section whose header contains needle (case-insensitive)."""
    needle_lower = needle.lower()
    for header, content in sections.items():
        if needle_lower in header.lower():
            return header, content
    return None


# ---------------------------------------------------------------------------
# Public API - three tiers of slice extraction
# ---------------------------------------------------------------------------

def extract_tier1_slice(artifact: str) -> Optional[dict[str, Any]]:
    """Tier-1: post-`csv_path` per-artifact slice (~800 tokens).

    Used by build_contract_response() to inject heuristics with the extraction
    response. Single call per (case_id, artifact, lane) - caching is the
    caller's responsibility (state.heuristic_refs_loaded).

    Returns dict with:
        - artifact: artifact name (e.g., 'mft')
        - source_path: relative path string (audit citation)
        - source_hash: sha256:<hex> of full canonical .md file
        - sections_included: list of section headers actually included
        - content: assembled slice text, capped to TIER1_MAX_CHARS
        - excerpt_hash: sha256:<hex> of content
        - token_count: approximate token count
        - section_found: True if at least one heuristic section matched
    """
    loaded = _load_artifact_md(artifact)
    if loaded is None:
        return None
    path, text, src_hash = loaded
    sections = _extract_sections(text)

    parts: list[str] = []
    headers_included: list[str] = []
    chars_remaining = TIER1_MAX_CHARS

    for needle in HEURISTIC_SECTION_HEADERS:
        # The headers in HEURISTIC_SECTION_HEADERS still include '## ' prefix.
        # Strip it for substring matching against section_extract keys.
        cleaned_needle = needle.removeprefix("## ").strip()
        match = _find_section_by_substring(sections, cleaned_needle)
        if not match:
            continue
        header, content = match
        if not content:
            continue
        block = f"## {header}\n{content}"
        if len(block) > chars_remaining:
            block = block[:chars_remaining].rsplit("\n", 1)[0] + "\n[...truncated]"
        parts.append(block)
        headers_included.append(header)
        chars_remaining -= len(block) + 2  # +2 for the joiner newlines
        if chars_remaining <= 100:
            break

    assembled = "\n\n".join(parts).strip()

    return {
        "artifact": artifact.lower(),
        "source_path": str(path.relative_to(REPO_ROOT)),
        "source_hash": src_hash,
        "sections_included": headers_included,
        "content": assembled,
        "excerpt_hash": _sha256(assembled) if assembled else None,
        "token_count": _approx_token_count(assembled),
        "section_found": bool(headers_included),
    }


def extract_tier2_slice(artifact: str) -> Optional[dict[str, Any]]:
    """Tier-2: hypothesis-bundle per-artifact slice (~600 tokens).

    Used by prepare_hypothesis_context() - tighter than Tier-1 to allow
    multiple artifacts in a single bundle. Includes ONLY 'Forensic Ground
    Rules' + 'What to Hunt' (or equivalent), drops Distinction blocks.
    """
    loaded = _load_artifact_md(artifact)
    if loaded is None:
        return None
    path, text, src_hash = loaded
    sections = _extract_sections(text)

    parts: list[str] = []
    headers_included: list[str] = []
    chars_remaining = TIER2_MAX_CHARS

    # Tighter set than Tier-1: ground rules + What-to-Hunt only
    tier2_priorities = [
        "Forensic Ground Rules",
        "What to Hunt",
        "Critical Forensic Heuristics",
    ]

    for needle in tier2_priorities:
        match = _find_section_by_substring(sections, needle)
        if not match:
            continue
        header, content = match
        if not content or header in headers_included:
            continue
        block = f"## {header}\n{content}"
        if len(block) > chars_remaining:
            block = block[:chars_remaining].rsplit("\n", 1)[0] + "\n[...truncated]"
        parts.append(block)
        headers_included.append(header)
        chars_remaining -= len(block) + 2
        if chars_remaining <= 100:
            break

    assembled = "\n\n".join(parts).strip()

    return {
        "artifact": artifact.lower(),
        "source_path": str(path.relative_to(REPO_ROOT)),
        "source_hash": src_hash,
        "sections_included": headers_included,
        "content": assembled,
        "excerpt_hash": _sha256(assembled) if assembled else None,
        "token_count": _approx_token_count(assembled),
        "section_found": bool(headers_included),
    }


def extract_topic(artifact: str, topic: str) -> Optional[dict[str, Any]]:
    """Tier-3: on-demand topic-specific slice (~450 tokens).

    Used by get_heuristic(artifact, topic) for pivot-loop drill-down.
    Topic must be a key in TOPIC_REGISTRY (e.g., 'professional_patterns',
    'what_to_hunt', 'forensic_ground_rules'). Returns the corresponding
    section if it exists in the artifact's .md.
    """
    loaded = _load_artifact_md(artifact)
    if loaded is None:
        return None
    path, text, src_hash = loaded
    sections = _extract_sections(text)

    needle = TOPIC_REGISTRY.get(topic.lower())
    if not needle:
        return None

    match = _find_section_by_substring(sections, needle)
    if not match:
        return None
    header, content = match
    if not content:
        return None

    block = f"## {header}\n{content}"
    if len(block) > TIER3_MAX_CHARS:
        block = block[:TIER3_MAX_CHARS].rsplit("\n", 1)[0] + "\n[...truncated]"

    return {
        "artifact": artifact.lower(),
        "topic": topic.lower(),
        "source_path": str(path.relative_to(REPO_ROOT)),
        "source_hash": src_hash,
        "section_header": header,
        "content": block.strip(),
        "excerpt_hash": _sha256(block),
        "token_count": _approx_token_count(block),
    }


def list_artifacts() -> list[str]:
    """Return list of artifact names with available .md files."""
    return [a for a in ARTIFACT_FILE_MAP if (AGENTS_DIR / ARTIFACT_FILE_MAP[a]).exists()]


def list_topics() -> list[str]:
    """Return list of valid topic names for get_heuristic."""
    return list(TOPIC_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Self-test (run as script for quick verification)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Available artifacts:", list_artifacts())
    print("Available topics:", list_topics())
    print()
    for artifact in list_artifacts():
        slice_data = extract_tier1_slice(artifact)
        if slice_data is None:
            print(f"  {artifact:10s} - FAILED to load")
            continue
        print(f"  {artifact:10s} - sections={slice_data['sections_included']!r}, "
              f"tokens={slice_data['token_count']}, found={slice_data['section_found']}")
