#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Keep the rule IDs of DESIGN.md and the Quint models in step.

DESIGN.md tags each normative rule bullet with an ID at the end of the line,
for example `[DLV-3]`. A model cites the rules that it encodes in a comment,
for example `// [DLV-3]`. A rule that no model encodes is listed in
specs/coverage.toml under `not_modelled`, with a reason.

Subcommands:
    list: print each rule ID with the first 80 characters of its rule.
    check: fail if an ID is duplicated, malformed, uncited, unknown or listed twice.
    drift: fail if a rule line changed since a git ref and no model file changed.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PREFIXES = ("DLV", "MRG", "LOG", "CMP", "ENR", "FRK", "WIR", "VER", "STO")
VALID_ID = re.compile(rf"^(?:{'|'.join(PREFIXES)})-[1-9][0-9]*$")
# Anything that looks like a rule tag, valid or not.
TAG_LIKE = re.compile(r"\[([A-Za-z]{2,5}-[0-9A-Za-z]+)\]")
RULE_LINE = re.compile(r"^(?:- |\d+\. )")
CITE = re.compile(r"\[([A-Z]{3}-[0-9]+)\]")
# Files whose change counts as a model change for the drift check.
MODEL_FILES = re.compile(r"^specs/(?:[^/]+/(?:model\.qnt|test\.qnt|checks\.toml)|coverage\.toml)$")


@dataclasses.dataclass(frozen=True)
class Rule:
    """One tagged rule line of DESIGN.md.

    Attributes:
        rule_id: The tag text without brackets, for example "DLV-3".
        line: The full line of DESIGN.md, tag included.
        number: The 1-based line number.
    """

    rule_id: str
    line: str
    number: int

    @property
    def text(self) -> str:
        """Return the rule text without its list marker and without the tag."""
        body = re.sub(r"^(?:- |\d+\. )", "", self.line)
        return body[: body.rfind("[")].rstrip()


def parse_rules(design: str) -> tuple[list[Rule], list[str]]:
    """Find the tagged rule lines of a DESIGN.md text.

    Args:
        design: The text of DESIGN.md.

    Returns:
        The rules in document order, and a list of error messages for tags
        that are malformed or not at the end of a list item.
    """
    rules: list[Rule] = []
    errors: list[str] = []
    in_fence = False
    for number, line in enumerate(design.splitlines(), start=1):
        if line.startswith("```"):
            in_fence = not in_fence
        if in_fence:
            continue
        tags = TAG_LIKE.findall(line)
        if not tags:
            continue
        if len(tags) > 1:
            errors.append(f"DESIGN.md:{number}: more than one tag on a line: {tags}")
            continue
        tag = tags[0]
        if not VALID_ID.match(tag):
            errors.append(f"DESIGN.md:{number}: malformed rule ID [{tag}]")
        elif not RULE_LINE.match(line) or not line.endswith(f" [{tag}]"):
            errors.append(f"DESIGN.md:{number}: [{tag}] must end a list item")
        else:
            rules.append(Rule(tag, line, number))
    return rules, errors


def cited_ids(root: Path) -> dict[str, list[str]]:
    """Find the rule IDs that model and test files cite in comments.

    Args:
        root: The repo root.

    Returns:
        A map from ID to the "file:line" places that cite it.
    """
    found: dict[str, list[str]] = {}
    files = sorted((root / "specs").glob("*/model.qnt")) + sorted((root / "specs").glob("*/test.qnt"))
    for path in files:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if "//" not in line:
                continue
            comment = line.split("//", 1)[1]
            for rule_id in CITE.findall(comment):
                found.setdefault(rule_id, []).append(f"{path.relative_to(root)}:{number}")
    return found


def load_not_modelled(root: Path) -> dict[str, str]:
    """Read the not_modelled table of specs/coverage.toml.

    Args:
        root: The repo root.

    Returns:
        A map from rule ID to the reason.
    """
    path = root / "specs" / "coverage.toml"
    if not path.exists():
        return {}
    table = tomllib.loads(path.read_text()).get("not_modelled", {})
    return {str(k): str(v) for k, v in table.items()}


def check(root: Path) -> list[str]:
    """Check that DESIGN.md rule IDs and the models agree.

    Args:
        root: The repo root.

    Returns:
        The error messages. An empty list means that the check passes.
    """
    rules, errors = parse_rules((root / "DESIGN.md").read_text())
    seen: dict[str, int] = {}
    for rule in rules:
        if rule.rule_id in seen:
            errors.append(f"DESIGN.md:{rule.number}: duplicate rule ID [{rule.rule_id}] (first at line {seen[rule.rule_id]})")
        seen.setdefault(rule.rule_id, rule.number)
    known = set(seen)
    cited = cited_ids(root)
    not_modelled = load_not_modelled(root)
    for rule_id in seen:
        if rule_id not in cited and rule_id not in not_modelled:
            errors.append(f"[{rule_id}] is not cited in a model and not listed in specs/coverage.toml")
        if rule_id in cited and rule_id in not_modelled:
            errors.append(f"[{rule_id}] is cited in {cited[rule_id][0]} and also listed in specs/coverage.toml")
    for rule_id, places in cited.items():
        if rule_id not in known:
            errors.append(f"{places[0]}: cites unknown rule ID [{rule_id}]")
    for rule_id, reason in not_modelled.items():
        if rule_id not in known:
            errors.append(f"specs/coverage.toml: unknown rule ID [{rule_id}]")
        if not reason.strip():
            errors.append(f"specs/coverage.toml: [{rule_id}] has an empty reason")
    return errors


def git(root: Path, *args: str) -> str:
    """Run git in the repo and return stdout.

    Args:
        root: The repo root.
        *args: The git arguments.

    Returns:
        The standard output.

    Raises:
        RuntimeError: If git fails.
    """
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def drift(root: Path, base: str) -> list[str]:
    """Find rule lines that changed since a ref while no model file changed.

    The comparison is between the ref and the working tree, so it covers
    commits and uncommitted edits.

    Args:
        root: The repo root.
        base: The git ref to compare with.

    Returns:
        The error messages. An empty list means that there is no drift.
    """
    try:
        old_text = git(root, "show", f"{base}:DESIGN.md")
    except RuntimeError:
        old_text = ""
    old = {r.rule_id: r.line for r in parse_rules(old_text)[0]}
    new = {r.rule_id: r.line for r in parse_rules((root / "DESIGN.md").read_text())[0]}
    changed = sorted(i for i in old.keys() | new.keys() if old.get(i) != new.get(i))
    if not changed:
        return []
    names = git(root, "diff", "--name-only", base, "--", "specs").splitlines()
    names += git(root, "ls-files", "--others", "--exclude-standard", "--", "specs").splitlines()
    if any(MODEL_FILES.match(n) for n in names):
        return []
    return [f"rule changed since {base} and no model, test, manifest or coverage file changed: " + ", ".join(changed)]


def cmd_list(root: Path) -> int:
    """Print each rule ID with the start of its text."""
    rules, errors = parse_rules((root / "DESIGN.md").read_text())
    for rule in rules:
        print(f"{rule.rule_id}\t{rule.text[:80]}")
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def report(errors: list[str], ok: str) -> int:
    """Print errors, or a success line, and return the exit code."""
    for error in errors:
        print(f"FAIL {error}", file=sys.stderr)
    if not errors:
        print(ok)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    """Run the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repo root")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="print each rule ID with its first 80 characters")
    sub.add_parser("check", help="check IDs, citations and specs/coverage.toml")
    drift_parser = sub.add_parser("drift", help="fail if a rule changed and no model changed")
    drift_parser.add_argument("--base", default="main", help="git ref to compare with (default: main)")
    args = parser.parse_args(argv)
    root: Path = args.root
    if args.command == "list":
        return cmd_list(root)
    if args.command == "check":
        count = len(parse_rules((root / "DESIGN.md").read_text())[0])
        return report(check(root), f"ok: {count} rule IDs")
    return report(drift(root, args.base), f"ok: no rule drift since {args.base}")


if __name__ == "__main__":
    sys.exit(main())
