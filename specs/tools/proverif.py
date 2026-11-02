#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run the ProVerif models of specs/ and compare each result to expect.toml.

Each directory of specs/ with an expect.toml is a ProVerif model.

ProVerif 2.05 must be on PATH. Run `eval $(opam env)` first.
Exit codes: 0 all results match, 1 a mismatch, a missing or extra query, an
unexpected "cannot be proved" or a ProVerif failure, 2 ProVerif is missing.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import shutil
import subprocess
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = "lib.pvl"
RESULT = re.compile(r"^RESULT (?P<query>.+?) (?P<verdict>is true|is false|cannot be proved)\.$")
EXPECTED_VALUES = ("true", "false", "reachable", "unproved")
MISSING_MESSAGE = "proverif not found on PATH. Run `eval $(opam env)` and try again."


@dataclasses.dataclass(frozen=True)
class Result:
    """One RESULT line of ProVerif.

    Attributes:
        query: The query text as ProVerif prints it.
        verdict: One of "true", "false" or "unproved".
    """

    query: str
    verdict: str


def parse_output(text: str) -> list[Result]:
    """Parse the RESULT lines of ProVerif output.

    A failed `inj-event` query also prints a second line for the plain event
    query. That line starts with "RESULT (even" and the first line already
    holds the verdict, so the parser skips it.

    Args:
        text: The stdout of proverif.

    Returns:
        One Result for each primary RESULT line, in order.
    """
    results: list[Result] = []
    for line in text.splitlines():
        if not line.startswith("RESULT ") or line.startswith("RESULT (even"):
            continue
        match = RESULT.match(line.strip())
        if match is None:
            continue
        verdict = {"is true": "true", "is false": "false", "cannot be proved": "unproved"}[match["verdict"]]
        results.append(Result(match["query"], verdict))
    return results


def is_reachability(query: str) -> bool:
    """Return True if the query is a `not event(X)` or `not (event(X) && ...)` reachability query."""
    return query.startswith(("not event(", "not (event("))


def model_dirs(root: Path) -> list[Path]:
    """Return each directory of `root` that holds an expect.toml, in name order."""
    return sorted(p.parent for p in root.glob("*/expect.toml"))


def compare(file: str, results: list[Result], expected: dict[str, str]) -> list[str]:
    """Compare the results of one file with its expectations.

    Each result must match exactly one expectation key by substring. Each key
    must match exactly one result. "reachable" means that ProVerif reports a
    `not event(X)` query as false.

    Args:
        file: The file name, for messages.
        results: The parsed results.
        expected: A map from query substring to "true", "false", "reachable" or "unproved".

    Returns:
        One line for each query, "ok" or "FAIL". A line that starts with "FAIL" is an error.
    """
    lines: list[str] = []
    matched: dict[str, int] = {key: 0 for key in expected}
    for result in results:
        keys = [key for key in expected if key in result.query]
        for key in keys:
            matched[key] += 1
        if len(keys) != 1:
            reason = "matches no key in expect.toml" if not keys else f"matches {len(keys)} keys in expect.toml"
            lines.append(f"FAIL {file}: {result.query}: {reason}")
            continue
        want = expected[keys[0]]
        if want not in EXPECTED_VALUES:
            lines.append(f"FAIL {file}: {keys[0]}: bad expected value {want!r}")
            continue
        if want == "reachable":
            good = is_reachability(result.query) and result.verdict == "false"
            want_text = "reachable (not event is false)"
        else:
            good = result.verdict == want
            want_text = want
        if good:
            lines.append(f"ok   {file}: {keys[0]}: {want_text}")
        elif result.verdict == "unproved":
            lines.append(f"FAIL {file}: {keys[0]}: cannot be proved, expected {want_text}")
        else:
            lines.append(f"FAIL {file}: {keys[0]}: got {result.verdict}, expected {want_text}")
    for key, count in matched.items():
        if count == 0:
            lines.append(f"FAIL {file}: {key}: query missing from ProVerif output")
    return lines


def run_proverif(directory: Path, file: str, timeout: int) -> tuple[int, str]:
    """Run proverif on one file.

    Args:
        directory: The directory that holds lib.pvl and the file.
        file: The .pv file name.
        timeout: Seconds before the run is stopped.

    Returns:
        The exit code and the stdout. A timeout returns exit code 124.
    """
    try:
        proc = subprocess.run(
            ["proverif", "-lib", LIB, file], cwd=directory, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    return proc.returncode, proc.stdout + proc.stderr


def check_directory(directory: Path, timeout: int) -> int:
    """Run every file of expect.toml and print one line for each query.

    Args:
        directory: The model directory.
        timeout: Seconds for each ProVerif run.

    Returns:
        The exit code of the tool.
    """
    expect = tomllib.loads((directory / "expect.toml").read_text())
    files = list(expect)
    on_disk = sorted(p.name for p in directory.glob("*.pv"))
    failed = False
    for name in on_disk:
        if name not in expect:
            print(f"FAIL {name}: file is not in expect.toml")
            failed = True
    with ThreadPoolExecutor(max_workers=4) as pool:
        runs = list(pool.map(lambda f: run_proverif(directory, f, timeout), files))
    for name, (code, output) in zip(files, runs, strict=True):
        if code == 124:
            print(f"FAIL {name}: proverif timed out after {timeout} s")
            failed = True
            continue
        results = parse_output(output)
        if code != 0 or not results:
            print(f"FAIL {name}: proverif exit code {code}, {len(results)} results")
            print("\n".join(output.splitlines()[-5:]))
            failed = True
            continue
        lines = compare(name, results, {k: str(v) for k, v in expect[name].items()})
        print("\n".join(lines))
        failed = failed or any(line.startswith("FAIL") for line in lines)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    """Run the tool.

    Args:
        argv: The arguments. None means sys.argv.

    Returns:
        The exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, help="one model directory with lib.pvl and expect.toml (default: each one)")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds for each ProVerif run")
    args = parser.parse_args(argv)
    if shutil.which("proverif") is None:
        print(MISSING_MESSAGE, file=sys.stderr)
        return 2
    dirs = [args.dir] if args.dir else model_dirs(ROOT)
    if not dirs:
        print(f"FAIL no expect.toml in {ROOT}")
        return 1
    codes = [check_directory(d, args.timeout) for d in dirs]
    return max(codes)


if __name__ == "__main__":
    sys.exit(main())
