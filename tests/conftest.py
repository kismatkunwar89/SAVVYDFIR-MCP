"""conftest.py — ensure the tests/ directory is on sys.path for bare-module imports."""
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


# W1.7 (Run 2 review 2026-05-24, Q4): hypothesis gate now fires even under
# allow_partial=True. Most pre-W1.7 tests assume allow_partial bypasses ALL
# gates and don't seed hypotheses. Default-bypass the gate via env var so
# legacy tests keep passing; tests that EXERCISE the gate (in
# test_w17_revised_plan.py::TestHypothesisGate*) clear the env var via the
# `unbypass_hypothesis_gate` fixture below.
@pytest.fixture(autouse=True)
def _default_skip_hypothesis_gate(monkeypatch):
    monkeypatch.setenv("SAVVYDFIR_SKIP_HYPOTHESIS_GATE", "1")


@pytest.fixture
def unbypass_hypothesis_gate(monkeypatch):
    """Tests that exercise the hypothesis-gate firing path opt-in to this
    fixture to clear the env-var bypass and let the gate evaluate normally.
    """
    monkeypatch.delenv("SAVVYDFIR_SKIP_HYPOTHESIS_GATE", raising=False)
