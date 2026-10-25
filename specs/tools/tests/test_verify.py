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


def test_open_mutant_without_reason_is_refused() -> None:
    data = manifest(mutants={"dropRow": {"base": "base", "caught_by": "safe", "open": True}})
    with pytest.raises(verify.ManifestError, match="no `why`"):
        verify.validate(Path("x"), data, MODEL)


def test_open_mutant_check_expects_the_invariant_to_hold() -> None:
    mutants = {"dropRow": {"base": "base", "caught_by": "safe", "open": True, "why": "gap"}}
    data = manifest(mutants=mutants, tests="t.qnt", test_module="t")
    m = verify.validate(Path("x"), data, MODEL)
    checks = [c for c in verify.plan(m, "full", None) if "dropRow" in c.label]
    assert len(checks) == 1
    assert checks[0].expect_pass is True
    assert checks[0].label.startswith("OPEN")


def test_tests_mutant_without_named_test_is_refused() -> None:
    data = manifest(mutants={"dropRow": {"base": "base", "caught_by": "tests"}})
    with pytest.raises(verify.ManifestError, match="names no `test`"):
        verify.validate(Path("x"), data, MODEL)


def test_tests_mutant_must_fail_its_test_and_pass_the_others(tmp_path: Path) -> None:
    (tmp_path / "model.qnt").write_text(MODEL)
    (tmp_path / "t.qnt").write_text('import m(N = 2, BUG = "none").* from "./model"\n')
    (tmp_path / "_gen").mkdir()
    mutants = {"dropRow": {"base": "base", "caught_by": "tests", "test": "keepsRowTest"}}
    data = manifest(mutants=mutants, tests="t.qnt", test_module="t")
    m = verify.validate(tmp_path, data, MODEL)
    checks = verify.mutant_test_checks(m)
    assert [c.expect_pass for c in checks] == [False, True]
    assert checks[0].argv[-2:] == ("--match", "^keepsRowTest$")
    assert 'BUG = "dropRow"' in (tmp_path / "_gen" / "t_dropRow.qnt").read_text()


def test_check_only_limits_the_invariants_of_a_config() -> None:
    configs = {"base": {}, "faulty": {"skip": ["safe"], "why": "x"}, "big": {"check_only": ["safe"], "why": "slow"}}
    m = verify.validate(Path("x"), manifest(configs=configs), MODEL)
    assert verify.skipped(m, "big") == {"other"}


def test_mutant_caught_by_invariant_outside_check_only_is_refused() -> None:
    configs = {"base": {}, "faulty": {"skip": ["safe"], "why": "x"}, "big": {"check_only": ["other"], "why": "slow"}}
    data = manifest(configs=configs, mutants={"dropRow": {"base": "big", "caught_by": "safe"}})
    with pytest.raises(verify.ManifestError, match="proves nothing"):
        verify.validate(Path("x"), data, MODEL)


# Captured from quint 0.33.0 `quint run --verbosity 1`.
FAILED_BATCH = """[violation] Found an issue (26ms at 731 traces/second).
  \u274c appliedHeld
  \u274c caughtUpState
Use --seed=0x48d9c565d4610c18 --backend=rust to reproduce.
error: Invariant violated
"""
PASSED_WITH_WITNESSES = """[ok] No violation found (45ms at 4444 traces/second).
Witnesses:
wEdit was witnessed in 200 trace(s) out of 200 explored (100.00%)
wPushKnown was witnessed in 0 trace(s) out of 200 explored (0.00%)
Use --seed=0x7c32db3b1d9f113a --backend=rust to reproduce.
"""


def test_batched_run_reports_each_violated_invariant() -> None:
    assert verify.violated(FAILED_BATCH) == ["appliedHeld", "caughtUpState"]
    assert verify.violated(PASSED_WITH_WITNESSES) == []


def test_witness_counts_include_zero() -> None:
    assert verify.witness_counts(PASSED_WITH_WITNESSES) == {"wEdit": 200, "wPushKnown": 0}


def test_full_tier_batches_the_invariants_of_each_config() -> None:
    data = manifest(tests="t.qnt", test_module="t", limits=[{"config": "base", "invariant": "other", "why": "x"}])
    m = verify.validate(Path("x"), data, MODEL)
    runs = [c for c in verify.plan(m, "full", None) if c.label.startswith(("base:", "faulty:"))]
    # base checks "safe" only ("other" is its limit). faulty skips "safe" and checks "other".
    assert [(c.label.split(":")[0], c.invariants) for c in runs] == [("base", ("safe",)), ("faulty", ("other",))]
    assert runs[0].argv[runs[0].argv.index("--invariants") + 1] == "safe"
