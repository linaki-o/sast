"""Integrity checks for the fixtures of the repository.

The example project and the benchmark corpus are used as ground truth by
several tests.  If one of those files is edited by accident the results
become meaningless, so their checksums are pinned here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

FIXTURES = {
    "examples/sample_project/src/utils.c": "b2b1b3d0339e654f47ccbe29f42def90694ab93391d027bea3310f6967672622",
    "examples/sample_project/src/features.c": "39eeaf0aa11f3c8421cb7ee1dda4ad35906d164e3db6e6e02d1449c5df2c8e62",
    "examples/sample_project/src/buffer.cpp": "907a2f7de7cd41c9685945001d68acf08be6154a6338722a8b164481e9ebde9e",
    "examples/sample_project/tests/test_utils.py": "dfef0edce95f587b8f9324c653139934e4534b30cf06b383d848cb97d0c78dd2",
    "examples/sample_project/requirements/requirements.yaml": "5bde0b3a99afea134a114b507e973cd4672de4fb9b20755b6951a156a84ca624",
    "examples/sample_project/sast.yaml": "16ebd538115f1d0f603a31e142801ad5c18aa459cb779c15abc100c8d54d8bc2",
    "benchmarks/corpus/security.c": "a8a83a0899f6e82a314e6e1e55adf7d309a77ecc179bba2d7d9fc13faa31d838",
    "benchmarks/corpus/quality.c": "35947c05b7ae1183f3036eef1bdf3a60b3242ae6eec11b5cd2994ff719ec32c0",
    "benchmarks/corpus/standards.c": "f2757216338246e3f1e39e1a401d8049c5ac3f16ed9f8fba307b7e11c5d65fa2",
    "benchmarks/corpus/cxx.cpp": "11a38d4f6b612d926095ef3b510211a37ff05f579545c4c3212a0c65858257b7",
    "benchmarks/corpus/clean.c": "278bf0287bffc5ee0f9a72bea703fa2328fbae92916e3ce2bf05e407b6fc2236",
    "benchmarks/corpus/manifest.yaml": "69c2a12e04adefc2842df8e98d5984387e573b15021ebed5b9c2ce289e19c9cc",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("relative", sorted(FIXTURES))
def test_fixture_is_unchanged(relative: str):
    path = ROOT / relative
    assert path.is_file(), f"missing fixture: {relative}"
    expected = FIXTURES[relative]
    if not expected:
        pytest.skip(f"no checksum pinned for {relative}")
    assert digest(path) == expected, f"{relative} was modified"


def test_example_sources_keep_their_planted_defects():
    """The example project must keep the defects the rules are checked against."""
    buffer = (ROOT / "examples/sample_project/src/buffer.cpp").read_text(encoding="utf-8")
    assert "while (i >= 0)" in buffer
    assert "unsigned int i = 0;" in buffer
