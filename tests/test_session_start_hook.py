"""SessionStart hook (C.2) — verify prerequisites without false-blocking.

The hook MUST:
- Approve when manifest is schema-valid (other tools may be missing — warn only).
- Block when manifest is present but schema-invalid (prevents bad-start runs).
- Approve when no manifest is present (non-DFIR session — don't block other work).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / ".claude" / "hooks" / "session-start.py"


def _run_hook(cwd: Path) -> tuple[int, dict, str]:
    """Invoke session-start.py with empty stdin; returns (exitcode, parsed-decision, stderr)."""
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input="",
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )
    decision: dict = {}
    if proc.stdout.strip():
        try:
            decision = json.loads(proc.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            pass
    return proc.returncode, decision, proc.stderr


class SessionStartHookTests(unittest.TestCase):
    def test_no_manifest_approves(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, decision, _ = _run_hook(Path(td))
            self.assertEqual(code, 0)
            self.assertEqual(decision.get("decision"), "approve")

    def test_valid_manifest_approves(self) -> None:
        # Run from repo root — the bundled manifest is schema-valid.
        code, decision, _ = _run_hook(REPO)
        self.assertEqual(code, 0)
        self.assertEqual(decision.get("decision"), "approve")

    def test_invalid_manifest_blocks(self) -> None:
        """Manifest with max_iterations=99 (> le=10) must block."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "case-templates").mkdir()
            (Path(td) / "case-templates" / "manifest.json").write_text(
                json.dumps({
                    "case_id": "X",
                    "mode": "blind",
                    "investigation_goal": "test",
                    "disk_images": [],
                    "memory_dumps": [],
                    "known_iocs": [],
                    "max_iterations": 99,  # violates schema le=10
                })
            )
            code, decision, stderr = _run_hook(Path(td))
            self.assertEqual(decision.get("decision"), "block",
                             f"invalid manifest must block; got {decision} / {stderr}")
            self.assertIn("manifest", decision.get("reason", "").lower())


if __name__ == "__main__":
    unittest.main()
