"""Tests for the manifest checks in verify.py.

Without these checks, a mutant that its baseline also fails would count as
caught, and a typo in a config would silently test nothing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location("verify", Path(__file__).parent.parent / "verify.py")
assert _SPEC and _SPEC.loader
verify = importlib.util.module_from_spec(_SPEC)
sys.modules["verify"] = verify
_SPEC.loader.exec_module(verify)

MODEL = """
module m {
  const N: int
  const BUG: str
  pure val BUGS: Set[str] = Set(
    "none",
    "dropRow",
  )
  var x: int
  val safe: bool = x >= 0
  val other: bool = true
}
"""


def manifest(**overrides: object) -> dict[str, object]:
    """Return a valid manifest for MODEL, with overrides."""
    data: dict[str, object] = {
        "model": "model.qnt",
        "module": "m",
        "invariants": ["safe", "other"],
        "defaults": {"N": "2", "BUG": '"none"'},
        "configs": {"base": {}, "faulty": {"skip": ["safe"], "why": "a fault breaks it"}},
        "mutants": {"dropRow": {"base": "base", "caught_by": "safe"}},
    }
    data.update(overrides)
    return data


def test_valid_manifest_loads() -> None:
    m = verify.validate(Path("x"), manifest(), MODEL)
    assert m.consts == frozenset({"N", "BUG"})
    assert m.bugs == frozenset({"none", "dropRow"})


def test_mutant_caught_by_invariant_that_base_skips_is_refused() -> None:
    data = manifest(mutants={"dropRow": {"base": "faulty", "caught_by": "safe"}})
    with pytest.raises(verify.ManifestError, match="proves nothing"):
        verify.validate(Path("x"), data, MODEL)


def test_mutant_caught_by_invariant_that_base_violates_as_limit_is_refused() -> None:
    data = manifest(limits=[{"config": "base", "invariant": "safe", "why": "limit"}])
    with pytest.raises(verify.ManifestError, match="proves nothing"):
        verify.validate(Path("x"), data, MODEL)


def test_config_that_misses_a_const_is_refused() -> None:
    data = manifest(defaults={"BUG": '"none"'})
    with pytest.raises(verify.ManifestError, match="does not bind"):
        verify.validate(Path("x"), data, MODEL)


def test_bug_value_without_mutant_is_refused() -> None:
    data = manifest(mutants={})
    with pytest.raises(verify.ManifestError, match="no mutant"):
        verify.validate(Path("x"), data, MODEL)


def test_unknown_invariant_name_is_refused() -> None:
    data = manifest(invariants=["safe", "typo"])
    with pytest.raises(verify.ManifestError, match="not a val"):
        verify.validate(Path("x"), data, MODEL)


def test_skip_without_reason_is_refused() -> None:
    data = manifest(configs={"base": {}, "faulty": {"skip": ["safe"]}})
    with pytest.raises(verify.ManifestError, match="no `why`"):
        verify.validate(Path("x"), data, MODEL)


def test_limit_invariant_is_not_checked_as_must_hold() -> None:
    data = manifest(limits=[{"config": "faulty", "invariant": "other", "why": "limit"}])
    m = verify.validate(Path("x"), data, MODEL)
    assert verify.skipped(m, "faulty") == {"safe", "other"}
