"""Tests for the manifest checks in verify.py.

Without these checks, a mutant that its baseline also fails would count as
caught, and a typo in a config would silently test nothing.
"""

from __future__ import annotations

import importlib.util
import shutil
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


# Captured from TLC 2026.10.25 through quint 0.33.0.
TLC_DONE = "394837 states generated, 10716 distinct states found, 0 states left on queue.\n"
TLC_EMPTY = "Finished computing initial states: 0 distinct states generated at 2026-10-25.\n"


def test_tlc_states_counts_a_finished_run_only() -> None:
    assert verify.tlc_states(TLC_DONE) == 10716
    assert verify.tlc_states(TLC_EMPTY) == 0
    assert verify.tlc_states("12048 states generated, 621 distinct states found, 350 states left on queue.") == 0


def test_exhaustive_entry_needs_a_reason_and_known_names() -> None:
    data = manifest(exhaustive=[{"config": "base", "invariants": ["typo"], "mutants": ["nope"]}])
    with pytest.raises(verify.ManifestError) as err:
        verify.validate(Path("x"), data, MODEL)
    msg = str(err.value)
    assert "no `why`" in msg and "unknown invariant 'typo'" in msg and "unknown mutant 'nope'" in msg


def test_exhaustive_design_run_needs_states_and_mutant_run_must_fail() -> None:
    ex = [{"config": "base", "invariants": ["safe"], "mutants": ["dropRow"], "why": "small"}]
    m = verify.validate(Path("x"), manifest(exhaustive=ex), MODEL)
    design, mutant = verify.exhaustive_checks(m)
    assert design.expect_pass and design.min_states == 2 and "--backend" in design.argv
    assert not mutant.expect_pass and mutant.argv[mutant.argv.index("--main") + 1] == "x_base_dropRow"


# ---- Fail-closed classification --------------------------------------------
# Outputs captured from quint 0.33.0 (Apalache 0.62.1, TLC 2026.10.25). Without
# classification, a runtime error, a parse error or a missing file exits 1 like
# a real catch, so a broken mutant check would count as "caught".

RUN_VIOLATION = """[violation] Found an issue (10ms at 1800 traces/second).
  \u274c small
Use --seed=0x3d8ecfad87d99433 --backend=rust to reproduce.
error: Invariant violated
"""
RUN_OK = """[ok] No violation found (8ms at 6250 traces/second).
Use --seed=0xad4b9ed6c77f352a --backend=rust to reproduce.
"""
RUN_RUNTIME_ERROR = """[error] Runtime error (8ms at 0 traces/second).

 Error [QNT503]: Division by zero

  at /private/tmp/qf/m.qnt:8:20

Use --seed=0x43c63128bfedc69d --backend=rust to reproduce.
error: Runtime error
"""
RUN_PARSE_ERROR = "\n Error [QNT000]: mismatched input '<EOF>'\n\nerror: parsing failed\n"
RUN_UNKNOWN_INVARIANT = "error: [QNT404] Name 'nope' not found\nerror: Argument error\n"
RUN_MISSING_FILE = "error: file missing.qnt does not exist\n"

TEST_ASSERT = """
  t
    1) badTest failed after 1 test(s)

  1 failed

  1) badTest:
       Error [QNT508]: Assertion failed
        at /private/tmp/qf/t.qnt:3:43
    Use --seed=0x29ab9a4c5152a869 --match=badTest to repeat.

error: Tests failed
"""
TEST_FAIL_METHOD = TEST_ASSERT.replace("badTest", "failTest").replace(
    "QNT508]: Assertion failed", "QNT511]: Test failTest returned false"
)
TEST_DIV_ZERO = TEST_ASSERT.replace("QNT508]: Assertion failed", "QNT503]: Division by zero")
TEST_MIXED = """
  t
    ok goodTest passed 1 test(s)
    1) badTest failed after 1 test(s)
    2) boomTest failed after 1 test(s)

  1 passing (13ms)
  2 failed

  1) badTest:
       Error [QNT508]: Assertion failed
  2) boomTest:
       Error [QNT503]: Division by zero

error: Tests failed
"""
TEST_PASS = "\n  t\n    ok goodTest passed 1 test(s)\n\n  1 passing (6ms)\n"
TEST_NONE_MATCHED = "\n  t\n\n"

TLC_VIOLATION = """Computing initial states...
Error: Invariant q_inv is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
i_m_x = 0

4 states generated, 4 distinct states found, 0 states left on queue.

[violation] Found an issue (252ms).
error: found a counterexample
"""
TLC_RUNTIME_ERROR = """Computing initial states...
Error: The second argument of \\div is 0.
Error: The error occurred when TLC was evaluating the nested

[failure] TLC encountered an error (239ms).
error: TLC error (see output above)
"""
TLC_OK = """Model checking completed. No error has been found.
12 states generated, 11 distinct states found, 0 states left on queue.

[ok] No violation found (245ms).
"""
APALACHE_OK = "The outcome is: NoError\n[ok] No violation found (2790ms).\n"
APALACHE_VIOLATION = "The outcome is: Error\n[violation] Found an issue (3071ms).\n  \u274c small\nerror: found a counterexample\n"


def check(backend: str, *, expect_pass: bool, catches: str = "", **kw: object) -> object:
    """Return a Check for one backend, with a dummy argv."""
    return verify.Check(
        "c", ("quint",), Path("."), expect_pass, backend=backend, catches=catches, **kw
    )


@pytest.mark.parametrize(
    ("output", "rc"),
    [
        (RUN_RUNTIME_ERROR, 1),
        (RUN_PARSE_ERROR, 1),
        (RUN_UNKNOWN_INVARIANT, 1),
        (RUN_MISSING_FILE, 1),
        (RUN_OK, 1),
        ("", -9),
        (RUN_VIOLATION, -9),
        (RUN_VIOLATION.replace("small", "other"), 1),
        (RUN_VIOLATION.replace("[violation]", "[ok]"), 1),
    ],
    ids=["runtime", "parse", "unknown-inv", "missing-file", "ok-but-rc1", "signal",
         "violation-but-signal", "wrong-invariant", "no-violation-line"],
)
def test_sampled_run_expecting_violation_rejects_everything_but_the_named_invariant(
    output: str, rc: int
) -> None:
    assert verify.failure_reason(check("run", expect_pass=False, catches="small"), rc, output)


def test_sampled_run_named_violation_is_accepted() -> None:
    c = check("run", expect_pass=False, catches="small")
    assert verify.failure_reason(c, 1, RUN_VIOLATION) is None


def test_sampled_run_accepts_a_violation_among_several_only_if_named_one_is_in_it() -> None:
    c = check("run", expect_pass=False, catches="appliedHeld")
    assert verify.failure_reason(c, 1, FAILED_BATCH) is None
    assert verify.failure_reason(check("run", expect_pass=False, catches="noFork"), 1, FAILED_BATCH)


@pytest.mark.parametrize(
    ("output", "rc"),
    [(RUN_OK, 0), (PASSED_WITH_WITNESSES, 0)],
)
def test_sampled_run_expecting_pass_needs_the_ok_marker(output: str, rc: int) -> None:
    assert verify.failure_reason(check("run", expect_pass=True), rc, output) is None


@pytest.mark.parametrize(
    ("output", "rc"),
    [("", 0), (RUN_VIOLATION, 1), (RUN_RUNTIME_ERROR, 1), (RUN_OK, 1), (RUN_VIOLATION, 0)],
    ids=["no-marker", "violation", "runtime", "ok-but-rc1", "violation-but-rc0"],
)
def test_sampled_run_expecting_pass_rejects_missing_marker_and_failures(
    output: str, rc: int
) -> None:
    assert verify.failure_reason(check("run", expect_pass=True), rc, output)


def test_a_scripted_test_failure_must_be_the_named_test_failing_an_assertion() -> None:
    c = check("test", expect_pass=False, catches="badTest")
    assert verify.failure_reason(c, 1, TEST_ASSERT) is None
    c = check("test", expect_pass=False, catches="failTest")
    assert verify.failure_reason(c, 1, TEST_FAIL_METHOD) is None


@pytest.mark.parametrize(
    ("output", "rc"),
    [
        (TEST_DIV_ZERO, 1),
        (TEST_MIXED, 1),
        (TEST_PASS, 0),
        (TEST_NONE_MATCHED, 0),
        (RUN_PARSE_ERROR, 1),
        (RUN_MISSING_FILE, 1),
        (TEST_ASSERT, -9),
        (TEST_ASSERT.replace("badTest", "otherTest"), 1),
    ],
    ids=["runtime-error-in-test", "other-test-also-fails", "passes", "nothing-matched",
         "parse", "missing-file", "signal", "wrong-test"],
)
def test_scripted_test_catch_rejects_errors_other_failures_and_wrong_test(
    output: str, rc: int
) -> None:
    assert verify.failure_reason(check("test", expect_pass=False, catches="badTest"), rc, output)


@pytest.mark.parametrize(
    ("output", "rc"),
    [(TEST_NONE_MATCHED, 0), (TEST_ASSERT, 1), (TEST_MIXED, 1), (RUN_PARSE_ERROR, 1), ("", 0)],
    ids=["no-tests-ran", "failure", "mixed", "parse", "empty"],
)
def test_scripted_tests_expected_to_pass_must_run_at_least_one_and_fail_none(
    output: str, rc: int
) -> None:
    assert verify.failure_reason(check("test", expect_pass=True), rc, output)


def test_scripted_tests_expected_to_pass_are_accepted() -> None:
    assert verify.failure_reason(check("test", expect_pass=True), 0, TEST_PASS) is None


def test_only_an_explicit_test_remainder_can_accept_an_empty_module_report() -> None:
    argv = ("quint", "test", "t.qnt", "--main", "t", "--match", "^(?!badTest$).*Test$")
    remainder = verify.Check("others", argv, Path("."), True, backend="test", excluded_test="badTest")
    assert verify.failure_reason(remainder, 0, TEST_NONE_MATCHED) is None
    for output, rc in [("", 0), ("otherModule", 0), (TEST_DIV_ZERO, 1), (TEST_NONE_MATCHED, -9)]:
        assert verify.failure_reason(remainder, rc, output)
    ordinary = verify.Check("suite", argv, Path("."), True, backend="test")
    assert verify.failure_reason(ordinary, 0, TEST_NONE_MATCHED)


def test_remainder_metadata_cannot_allow_a_selector_that_skips_other_tests() -> None:
    with pytest.raises(ValueError, match="exclude only its named test"):
        verify.Check(
            "others", ("quint", "test", "t.qnt", "--main", "t", "--match", "nothing"),
            Path("."), True, backend="test", excluded_test="badTest",
        )


def test_tlc_catch_needs_the_invariant_violation_and_not_a_tlc_error() -> None:
    c = check("tlc", expect_pass=False, invariants=("small",))
    assert verify.failure_reason(c, 1, TLC_VIOLATION) is None
    assert verify.failure_reason(c, 1, TLC_RUNTIME_ERROR)
    assert verify.failure_reason(c, 1, RUN_PARSE_ERROR)
    assert verify.failure_reason(c, 1, RUN_MISSING_FILE)
    assert verify.failure_reason(c, -9, TLC_VIOLATION)
    assert verify.failure_reason(c, 0, TLC_OK)


def test_tlc_pass_needs_completion_marker_and_enough_states() -> None:
    c = check("tlc", expect_pass=True, min_states=2)
    assert verify.failure_reason(c, 0, TLC_OK) is None
    assert verify.failure_reason(c, 0, "[ok] No violation found (1ms).\n")
    assert verify.failure_reason(c, 0, TLC_OK.replace("11 distinct", "1 distinct"))
    assert verify.failure_reason(c, 1, TLC_VIOLATION)


def test_apalache_pass_needs_the_no_error_outcome() -> None:
    c = check("apalache", expect_pass=True)
    assert verify.failure_reason(c, 0, APALACHE_OK) is None
    assert verify.failure_reason(c, 0, "[ok] No violation found (1ms).\n")
    assert verify.failure_reason(c, 1, APALACHE_VIOLATION)


def test_exit_code_only_check_cannot_expect_failure() -> None:
    with pytest.raises(ValueError, match="names the failure"):
        verify.Check("c", ("quint",), Path("."), False)


def test_exit_code_only_check_passes_on_zero_only() -> None:
    c = verify.Check("typecheck", ("quint",), Path("."), True)
    assert verify.failure_reason(c, 0, "") is None
    assert verify.failure_reason(c, 1, "") and verify.failure_reason(c, -9, "")


def test_every_check_that_expects_failure_names_what_must_fail() -> None:
    data = manifest(
        tests="t.qnt", test_module="t",
        limits=[{"config": "base", "invariant": "other", "why": "x"}],
        exhaustive=[{"config": "base", "invariants": ["safe"], "mutants": ["dropRow"], "why": "s"}],
    )
    m = verify.validate(Path("x"), data, MODEL)
    failing = [c for c in [*verify.plan(m, "full", None), *verify.exhaustive_checks(m)] if not c.expect_pass]
    assert {c.label.split()[0] for c in failing} == {"limit", "mutant", "tlc"}
    for c in failing:
        assert c.backend in {"run", "tlc"}
        if c.backend == "run":
            assert c.catches in c.argv[c.argv.index("--invariants") + 1 :]
            # quint 0.33.0 prints no invariant name for a single invariant.
            assert len(c.argv[c.argv.index("--invariants") + 1 : c.argv.index("--max-samples")]) == 2


def test_scripted_mutant_checks_name_the_test_and_use_the_test_backend(tmp_path: Path) -> None:
    (tmp_path / "model.qnt").write_text(MODEL)
    (tmp_path / "t.qnt").write_text('import m(N = 2, BUG = "none").* from "./model"\n')
    (tmp_path / "_gen").mkdir()
    mutants = {"dropRow": {"base": "base", "caught_by": "tests", "test": "keepsRowTest"}}
    m = verify.validate(tmp_path, manifest(mutants=mutants, tests="t.qnt", test_module="t"), MODEL)
    caught, others = verify.mutant_test_checks(m)
    assert (caught.backend, caught.catches) == ("test", "keepsRowTest")
    assert others.backend == "test" and others.expect_pass


# Real subprocess boundary: execute() must give the verdict of failure_reason.

def test_execute_does_not_count_a_killed_process_as_a_catch() -> None:
    c = verify.Check("c", ("sh", "-c", "kill -9 $$"), Path("."), False, backend="run", catches="small")
    _, good, output = verify.execute(c)
    assert not good and "FAIL" in output


def test_execute_does_not_count_a_missing_executable_as_a_catch() -> None:
    c = verify.Check("c", ("no-such-binary-xyz",), Path("."), False, backend="run", catches="small")
    _, good, _ = verify.execute(c)
    assert not good


HAS_QUINT = shutil.which("quint") is not None
QUINT_MODEL = """module m {
  const LIM: int
  var x: int
  action init = x' = 0
  action step = x' = if (x < LIM) x + 1 else x
  val small: bool = x < 3
  val inRange: bool = x >= 0
  val boom: bool = 1 / (x - x) == 0
}
"""
QUINT_TESTS = """module t {
  import m(LIM = 10).* from "./m"
  run goodTest = init.then(step).then(all { assert(x == 1), step })
  run badTest = init.then(step).then(all { assert(x == 5), step })
  run boomTest = init.then(all { assert(1 / (x - x) == 0), step })
}
"""


@pytest.fixture
def quint_dir(tmp_path: Path) -> Path:
    """Return a directory with a small real model, instance and tests."""
    (tmp_path / "m.qnt").write_text(QUINT_MODEL)
    (tmp_path / "i.qnt").write_text('module i { import m(LIM = 10).* from "./m" }\n')
    (tmp_path / "t.qnt").write_text(QUINT_TESTS)
    return tmp_path


def run_check(cwd: Path, backend: str, argv: tuple[str, ...], *, expect_pass: bool, catches: str = "") -> bool:
    c = verify.Check("c", ("quint", *argv), cwd, expect_pass, backend=backend, catches=catches)
    return verify.execute(c)[1]


@pytest.mark.skipif(not HAS_QUINT, reason="quint is not installed")
class TestRealQuint:
    """Run the pinned quint. Without these, the captured outputs could drift unseen."""

    def sampled(self, d: Path, inv: str, main: str = "i", file: str = "i.qnt") -> tuple[str, ...]:
        # run_argv pads a single invariant so that quint names the violated one.
        return ("run", file, "--main", main, "--invariants", inv, "true", "--max-samples", "50",
                "--max-steps", "10", "--verbosity", "1")

    def test_named_invariant_violation_is_a_catch(self, quint_dir: Path) -> None:
        assert run_check(quint_dir, "run", self.sampled(quint_dir, "small"), expect_pass=False, catches="small")

    def test_wrong_invariant_is_not_a_catch(self, quint_dir: Path) -> None:
        assert not run_check(quint_dir, "run", self.sampled(quint_dir, "small"), expect_pass=False, catches="inRange")

    def test_division_by_zero_in_invariant_is_not_a_catch(self, quint_dir: Path) -> None:
        assert not run_check(quint_dir, "run", self.sampled(quint_dir, "boom"), expect_pass=False, catches="boom")

    def test_unknown_invariant_missing_file_and_unknown_main_are_not_catches(self, quint_dir: Path) -> None:
        for argv in (self.sampled(quint_dir, "nope"), self.sampled(quint_dir, "small", file="gone.qnt"),
                     self.sampled(quint_dir, "small", main="zz")):
            assert not run_check(quint_dir, "run", argv, expect_pass=False, catches="small")

    def test_parse_error_is_not_a_catch(self, quint_dir: Path) -> None:
        (quint_dir / "i.qnt").write_text("module i { val a: int = \n")
        assert not run_check(quint_dir, "run", self.sampled(quint_dir, "small"), expect_pass=False, catches="small")

    def test_holding_invariant_passes_and_violated_one_does_not(self, quint_dir: Path) -> None:
        assert run_check(quint_dir, "run", self.sampled(quint_dir, "inRange"), expect_pass=True)
        assert not run_check(quint_dir, "run", self.sampled(quint_dir, "small"), expect_pass=True)

    def test_named_assertion_failure_is_a_catch(self, quint_dir: Path) -> None:
        argv = ("test", "t.qnt", "--main", "t", "--match", "^badTest$")
        assert run_check(quint_dir, "test", argv, expect_pass=False, catches="badTest")
        assert not run_check(quint_dir, "test", argv, expect_pass=False, catches="goodTest")

    def test_runtime_error_in_test_is_not_a_catch(self, quint_dir: Path) -> None:
        argv = ("test", "t.qnt", "--main", "t", "--match", "^boomTest$")
        assert not run_check(quint_dir, "test", argv, expect_pass=False, catches="boomTest")

    def test_test_that_matches_nothing_is_neither_a_catch_nor_a_pass(self, quint_dir: Path) -> None:
        argv = ("test", "t.qnt", "--main", "t", "--match", "^absentTest$")
        assert not run_check(quint_dir, "test", argv, expect_pass=False, catches="absentTest")
        assert not run_check(quint_dir, "test", argv, expect_pass=True)

    def test_the_other_tests_check_fails_if_another_test_also_fails(self, quint_dir: Path) -> None:
        argv = ("test", "t.qnt", "--main", "t", "--match", "^(?!badTest$).*Test$")
        assert not run_check(quint_dir, "test", argv, expect_pass=True)
        argv = ("test", "t.qnt", "--main", "t", "--match", "^goodTest$")
        assert run_check(quint_dir, "test", argv, expect_pass=True)

    def test_one_test_module_has_a_valid_empty_remainder(self, quint_dir: Path) -> None:
        (quint_dir / "only.qnt").write_text(
            'module only { import m(LIM = 10).* from "./m"\n'
            'run badTest = init.then(all { assert(x == 99), step }) }\n'
        )
        argv = ("quint", "test", "only.qnt", "--main", "only", "--match", "^(?!badTest$).*Test$")
        remainder = verify.Check(
            "others", argv, quint_dir, True, backend="test", excluded_test="badTest"
        )
        assert verify.execute(remainder)[1]
        ordinary = verify.Check("suite", argv, quint_dir, True, backend="test")
        assert not verify.execute(ordinary)[1]

    def test_run_argv_names_a_single_violated_invariant(self, quint_dir: Path) -> None:
        argv = verify.run_argv("i", ["small"], 50, 10, None)
        (quint_dir / "_gen").mkdir()
        (quint_dir / "_gen" / "i.qnt").write_text('module i { import m(LIM = 10).* from "../m" }\n')
        c = verify.Check("c", argv, quint_dir, False, backend="run", catches="small")
        assert verify.execute(c)[1]


@pytest.mark.skipif(not HAS_QUINT or shutil.which("java") is None, reason="quint or java is missing")
class TestRealTlc:
    def argv(self, inv: str, main: str = "i") -> tuple[str, ...]:
        return ("verify", "i.qnt", "--main", main, "--backend", "tlc", "--invariants", inv, "--max-steps", "5")

    def test_violation_is_a_catch_and_runtime_error_is_not(self, quint_dir: Path) -> None:
        assert run_check(quint_dir, "tlc", self.argv("small"), expect_pass=False)
        assert not run_check(quint_dir, "tlc", self.argv("boom"), expect_pass=False)
        assert not run_check(quint_dir, "tlc", self.argv("nope"), expect_pass=False)
        assert not run_check(quint_dir, "tlc", self.argv("small", main="zz"), expect_pass=False)

    def test_complete_run_passes_and_violation_does_not(self, quint_dir: Path) -> None:
        assert run_check(quint_dir, "tlc", self.argv("inRange"), expect_pass=True)
        assert not run_check(quint_dir, "tlc", self.argv("small"), expect_pass=True)
