"""Tests for proverif.py.

Without these checks, a changed ProVerif verdict, a dropped query or a
"cannot be proved" result could pass as a green run of `make verify-crypto`.
The output strings are lines that ProVerif 2.05 printed for the enrollment model.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location("proverif", Path(__file__).parent.parent / "proverif.py")
assert _SPEC and _SPEC.loader
proverif = importlib.util.module_from_spec(_SPEC)
sys.modules["proverif"] = proverif
_SPEC.loader.exec_module(proverif)

DESIGN_OUTPUT = """\
-- Query inj-event(TAppends(s_2,kt_2,kn_2,m)) ==> inj-event(NConfirms(s_2,kt_2,kn_2,m)) in process 1.
Completing...
RESULT inj-event(TAppends(s_2,kt_2,kn_2,m)) ==> inj-event(NConfirms(s_2,kt_2,kn_2,m)) is true.
RESULT event(NAccepts(s_2,kt_2,kn_2,m,r_2)) ==> event(TSignsCp(kt_2,r_2)) is true.
RESULT not attacker(appk[]) is true.
RESULT not event(TAppends(s_2,kt_2,kn_2,m)) is false.
"""

FLAW_OUTPUT = """\
RESULT inj-event(TAppends(s_2,kt_2,kn_2,m)) ==> inj-event(NConfirms(s_2,kt_2,kn_2,m)) is false.
RESULT (even event(TAppends(s_2,kt_2,kn_2,m)) ==> event(NConfirms(s_2,kt_2,kn_2,m)) is false.)
RESULT not attacker(appk[]) is false.
RESULT not event(NAccepts(s_2,kt_2,kn_2,m,r_2)) cannot be proved.
"""

EXPECTED = {
    "inj-event(TAppends": "true",
    "==> event(TSignsCp": "true",
    "not attacker(appk": "true",
    "not event(TAppends": "reachable",
}


def fails(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith("FAIL")]


def test_parser_reads_each_verdict() -> None:
    results = proverif.parse_output(DESIGN_OUTPUT + FLAW_OUTPUT)
    assert [r.verdict for r in results] == ["true", "true", "true", "false", "false", "false", "unproved"]


def test_parser_skips_the_even_line_of_a_failed_injective_query() -> None:
    results = proverif.parse_output(FLAW_OUTPUT)
    assert len(results) == 3
    assert not any(r.query.startswith("(even") for r in results)


def test_parser_ignores_prose_lines() -> None:
    assert proverif.parse_output("Completing...\n-- Query not attacker(appk[]) in process 1.\n") == []


def test_matching_results_pass() -> None:
    lines = proverif.compare("enrollment.pv", proverif.parse_output(DESIGN_OUTPUT), EXPECTED)
    assert fails(lines) == []
    assert len(lines) == 4


def test_reachable_means_a_false_not_event_query() -> None:
    out = "RESULT not event(TAppends(s_2,kt_2,kn_2,m)) is true.\n"
    lines = proverif.compare("f.pv", proverif.parse_output(out), {"not event(TAppends": "reachable"})
    assert any("got true, expected reachable" in line for line in fails(lines))


def test_reachable_accepts_a_false_conjunction_query() -> None:
    out = "RESULT not (event(TokenIssued(u_6,d_3)) && event(HonestUser(u_6))) is false.\n"
    lines = proverif.compare("f.pv", proverif.parse_output(out), {"not (event(TokenIssued": "reachable"})
    assert fails(lines) == []


def test_model_dirs_finds_each_directory_with_an_expectation(tmp_path: Path) -> None:
    for name in ("b", "a", "c"):
        (tmp_path / name).mkdir()
    (tmp_path / "a" / "expect.toml").write_text("")
    (tmp_path / "b" / "expect.toml").write_text("")
    assert proverif.model_dirs(tmp_path) == [tmp_path / "a", tmp_path / "b"]


def test_reachable_does_not_accept_a_false_security_query() -> None:
    out = "RESULT not attacker(appk[]) is false.\n"
    lines = proverif.compare("f.pv", proverif.parse_output(out), {"not attacker(appk": "reachable"})
    assert fails(lines)


def test_a_flipped_verdict_is_a_mismatch() -> None:
    lines = proverif.compare("flaw.pv", proverif.parse_output(FLAW_OUTPUT), EXPECTED)
    failed = fails(lines)
    assert any("inj-event(TAppends" in line and "got false, expected true" in line for line in failed)
    assert any("not attacker(appk" in line and "got false" in line for line in failed)


def test_an_unexpected_cannot_be_proved_fails() -> None:
    expected = {**EXPECTED, "not event(NAccepts": "reachable"}
    lines = proverif.compare("flaw.pv", proverif.parse_output(FLAW_OUTPUT), expected)
    assert any("not event(NAccepts" in line and "cannot be proved" in line for line in fails(lines))


def test_an_expected_unproved_result_passes() -> None:
    out = "RESULT not event(NAccepts(s_2,kt_2,kn_2,m,r_2)) cannot be proved.\n"
    lines = proverif.compare("f.pv", proverif.parse_output(out), {"not event(NAccepts": "unproved"})
    assert fails(lines) == []


def test_a_missing_query_fails() -> None:
    out = DESIGN_OUTPUT.replace("RESULT not attacker(appk[]) is true.\n", "")
    lines = proverif.compare("enrollment.pv", proverif.parse_output(out), EXPECTED)
    assert any("not attacker(appk" in line and "missing" in line for line in fails(lines))


def test_a_query_with_no_expectation_fails() -> None:
    lines = proverif.compare("enrollment.pv", proverif.parse_output(DESIGN_OUTPUT), {"not attacker(appk": "true"})
    assert len([line for line in fails(lines) if "matches no key" in line]) == 3


def test_a_query_that_two_keys_match_fails() -> None:
    expected = {"inj-event": "true", "inj-event(TAppends": "true"}
    out = "RESULT inj-event(TAppends(s_2)) ==> inj-event(NConfirms(s_2)) is true.\n"
    lines = proverif.compare("f.pv", proverif.parse_output(out), expected)
    assert any("matches 2 keys" in line for line in fails(lines))


def test_missing_proverif_exits_2(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(proverif.shutil, "which", lambda name: None)
    assert proverif.main([]) == 2
    assert "eval $(opam env)" in capsys.readouterr().err


def test_check_directory_flags_a_pv_file_with_no_expectation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "expect.toml").write_text('["a.pv"]\n"not attacker(appk" = "true"\n')
    (tmp_path / "a.pv").write_text("")
    (tmp_path / "b.pv").write_text("")
    monkeypatch.setattr(proverif, "run_proverif", lambda d, f, t: (0, "RESULT not attacker(appk[]) is true.\n"))
    assert proverif.check_directory(tmp_path, 10) == 1


def test_check_directory_passes_when_everything_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "expect.toml").write_text('["a.pv"]\n"not attacker(appk" = "true"\n')
    (tmp_path / "a.pv").write_text("")
    monkeypatch.setattr(proverif, "run_proverif", lambda d, f, t: (0, "RESULT not attacker(appk[]) is true.\n"))
    assert proverif.check_directory(tmp_path, 10) == 0


def test_a_proverif_failure_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "expect.toml").write_text('["a.pv"]\n"not attacker(appk" = "true"\n')
    (tmp_path / "a.pv").write_text("")
    monkeypatch.setattr(proverif, "run_proverif", lambda d, f, t: (2, "Error: syntax error\n"))
    assert proverif.check_directory(tmp_path, 10) == 1
