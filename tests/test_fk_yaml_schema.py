"""Schema integrity gate for forensic-knowledge YAMLs.

Why this exists: `_load_fk` / `load_fk_slice` return ``{}`` on a malformed or
missing YAML, so a broken community contribution would ship with **no forensic
envelope and no runtime error** - a silent failure. This test makes that failure
loud at PR time. It runs under the existing ``pytest tests/`` (see CONTRIBUTING).

It only asserts what is genuinely required (parses to a non-empty mapping with an
``artifact:`` key matching the filename) so it never false-fails on a valid file
that legitimately omits optional sections.
"""
from pathlib import Path

import pytest
import yaml

_FK_DIR = Path(__file__).resolve().parent.parent / "data" / "forensic-knowledge" / "artifacts"
_FK_YAMLS = sorted(_FK_DIR.glob("*/*.yaml"))


def test_fk_yamls_present():
    assert _FK_YAMLS, f"no forensic-knowledge YAMLs found under {_FK_DIR}"


@pytest.mark.parametrize("path", _FK_YAMLS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_fk_yaml_parses_and_artifact_matches_filename(path: Path):
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # malformed YAML -> silent {} at runtime
        pytest.fail(f"{path} is not valid YAML: {exc}")

    assert isinstance(data, dict) and data, f"{path} must parse to a non-empty mapping"
    assert "artifact" in data, f"{path} is missing the required top-level 'artifact:' key"
    artifact = data["artifact"]
    assert isinstance(artifact, str) and artifact.strip(), (
        f"{path} 'artifact' must be a non-empty string"
    )
    assert artifact == path.stem, (
        f"{path} declares 'artifact: {artifact}' but the loader resolves by filename - "
        f"it must equal the filename stem '{path.stem}'"
    )
