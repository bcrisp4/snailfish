"""Tests for rules.py.

Without these checks, a design change could skip the models, a typo in a rule
tag could hide a rule, and a citation of a deleted rule would pass.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location("rules", Path(__file__).parent.parent / "rules.py")
assert _SPEC and _SPEC.loader
rules = importlib.util.module_from_spec(_SPEC)
sys.modules["rules"] = rules
_SPEC.loader.exec_module(rules)

DESIGN = """# Design

Intro prose.

- A prose bullet with no tag.

Delivery rules.

- The engine must commit. [DLV-1]
- The app must write the row. [DLV-2]

1. A numbered step. [ENR-1]
"""


def make_repo(tmp_path: Path, design: str = DESIGN, model: str = "// [DLV-1]\n// [DLV-2]\n", coverage: str = '[not_modelled]\n"ENR-1" = "later"\n') -> Path:
    """Write a minimal repo layout and return its root."""
    (tmp_path / "specs" / "m").mkdir(parents=True)
    (tmp_path / "DESIGN.md").write_text(design)
    (tmp_path / "specs" / "m" / "model.qnt").write_text(model)
    (tmp_path / "specs" / "coverage.toml").write_text(coverage)
    return tmp_path


def test_consistent_repo_passes(tmp_path: Path) -> None:
    assert rules.check(make_repo(tmp_path)) == []


def test_duplicate_id_fails(tmp_path: Path) -> None:
    design = DESIGN + "- Another rule. [DLV-2]\n"
    errors = rules.check(make_repo(tmp_path, design=design))
    assert any("duplicate" in e and "DLV-2" in e for e in errors)


@pytest.mark.parametrize("tag", ["DLV-0", "DLV-01", "XYZ-1", "DLV-x", "dlv-1"])
def test_malformed_id_fails(tmp_path: Path, tag: str) -> None:
    errors = rules.check(make_repo(tmp_path, design=DESIGN + f"- A rule. [{tag}]\n"))
    assert any("malformed" in e for e in errors)


def test_tag_in_the_middle_of_a_line_fails(tmp_path: Path) -> None:
    errors = rules.check(make_repo(tmp_path, design=DESIGN + "- A rule [DLV-3] with trailing text.\n"))
    assert any("must end a list item" in e for e in errors)


def test_uncited_rule_fails(tmp_path: Path) -> None:
    errors = rules.check(make_repo(tmp_path, model="// [DLV-1]\n"))
    assert any("[DLV-2]" in e and "not cited" in e for e in errors)


def test_not_modelled_rule_needs_no_citation(tmp_path: Path) -> None:
    coverage = '[not_modelled]\n"ENR-1" = "later"\n"DLV-2" = "not yet"\n'
    assert rules.check(make_repo(tmp_path, model="// [DLV-1]\n", coverage=coverage)) == []


def test_unknown_cited_id_fails(tmp_path: Path) -> None:
    errors = rules.check(make_repo(tmp_path, model="// [DLV-1]\n// [DLV-2]\n// [DLV-9]\n"))
    assert any("unknown rule ID [DLV-9]" in e for e in errors)


def test_unknown_coverage_id_fails(tmp_path: Path) -> None:
    coverage = '[not_modelled]\n"ENR-1" = "later"\n"STO-4" = "gone"\n'
    errors = rules.check(make_repo(tmp_path, coverage=coverage))
    assert any("unknown rule ID [STO-4]" in e for e in errors)


def test_empty_reason_fails(tmp_path: Path) -> None:
    errors = rules.check(make_repo(tmp_path, coverage='[not_modelled]\n"ENR-1" = ""\n'))
    assert any("empty reason" in e for e in errors)


def test_cited_and_not_modelled_fails(tmp_path: Path) -> None:
    coverage = '[not_modelled]\n"ENR-1" = "later"\n"DLV-1" = "stale"\n'
    errors = rules.check(make_repo(tmp_path, coverage=coverage))
    assert any("[DLV-1]" in e and "also listed" in e for e in errors)


def test_citation_outside_a_comment_does_not_count(tmp_path: Path) -> None:
    errors = rules.check(make_repo(tmp_path, model='val s = "[DLV-1]"\n// [DLV-2]\n'))
    assert any("[DLV-1]" in e and "not cited" in e for e in errors)


def test_tags_inside_code_fences_are_ignored(tmp_path: Path) -> None:
    design = DESIGN + "\n```\n- sample [DLV-1]\n```\n"
    assert rules.check(make_repo(tmp_path, design=design)) == []


def test_list_prints_text_without_tag(tmp_path: Path) -> None:
    parsed, errors = rules.parse_rules(DESIGN)
    assert errors == []
    assert [(r.rule_id, r.text) for r in parsed] == [
        ("DLV-1", "The engine must commit."),
        ("DLV-2", "The app must write the row."),
        ("ENR-1", "A numbered step."),
    ]


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repo with one commit that holds a consistent layout."""
    root = make_repo(tmp_path)
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    return root


def edit_rule(root: Path) -> None:
    design = (root / "DESIGN.md").read_text().replace("must commit.", "must commit twice.")
    (root / "DESIGN.md").write_text(design)


def test_drift_none_when_nothing_changed(repo: Path) -> None:
    assert rules.drift(repo, "main") == []


def test_drift_fails_when_rule_changes_alone(repo: Path) -> None:
    edit_rule(repo)
    errors = rules.drift(repo, "main")
    assert len(errors) == 1 and "DLV-1" in errors[0] and "DLV-2" not in errors[0]


def test_drift_fails_for_a_committed_rule_change(repo: Path) -> None:
    edit_rule(repo)
    git(repo, "commit", "-q", "-am", "design only")
    assert rules.drift(repo, "main~1")


def test_drift_passes_when_a_model_changes_too(repo: Path) -> None:
    edit_rule(repo)
    (repo / "specs" / "m" / "model.qnt").write_text("// [DLV-1]\n// [DLV-2]\n// updated\n")
    assert rules.drift(repo, "main") == []


def test_drift_passes_when_a_new_model_file_is_untracked(repo: Path) -> None:
    edit_rule(repo)
    (repo / "specs" / "m" / "test.qnt").write_text("// [DLV-1]\n")
    assert rules.drift(repo, "main") == []


def test_drift_ignores_a_change_to_prose(repo: Path) -> None:
    design = (repo / "DESIGN.md").read_text().replace("Intro prose.", "Other prose.")
    (repo / "DESIGN.md").write_text(design)
    assert rules.drift(repo, "main") == []


def test_drift_fails_for_a_new_rule(repo: Path) -> None:
    (repo / "DESIGN.md").write_text((repo / "DESIGN.md").read_text() + "- A new rule. [DLV-3]\n")
    errors = rules.drift(repo, "main")
    assert errors and "DLV-3" in errors[0]


def test_drift_fails_for_a_removed_rule(repo: Path) -> None:
    design = (repo / "DESIGN.md").read_text().replace("- The app must write the row. [DLV-2]\n", "")
    (repo / "DESIGN.md").write_text(design)
    errors = rules.drift(repo, "main")
    assert errors and "DLV-2" in errors[0]


def test_drift_cli_exit_codes(repo: Path) -> None:
    assert rules.main(["--root", str(repo), "drift", "--base", "main"]) == 0
    edit_rule(repo)
    assert rules.main(["--root", str(repo), "drift", "--base", "main"]) == 1
