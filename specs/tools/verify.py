#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run the Quint checks for each model in specs/.

Each model lives in specs/<name>/ with a model.qnt, a test.qnt and a
checks.toml manifest. This script generates one module file for each config and
each mutant, then runs the checks that the manifest lists.

Tiers:
    fast: typecheck, scenario tests, and short sampled runs. For iteration.
    full: every config, limit, mutant and witness, with full sampling.
    deep: quint verify (Apalache) on the [deep] invariants. Bounded, exhaustive.

A pass in the fast and full tiers is sampled evidence, not a proof. A pass in
the deep tier is exhaustive up to the step bound only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

SPECS = Path(__file__).resolve().parent.parent
TIERS = frozenset({"fast", "full", "deep"})
# Sampling effort per tier: (samples, steps).
EFFORT = {"fast": (2000, 30), "full": (20000, 50)}
GEN_DIR = "_gen"


class ManifestError(Exception):
    """A checks.toml file is not consistent with its model."""


@dataclasses.dataclass(frozen=True)
class Check:
    """One quint invocation and the result that it must give.

    Attributes:
        label: Text for the report.
        argv: The quint command line.
        cwd: The directory to run in.
        expect_pass: True if the command must exit 0, False if it must fail.
    """

    label: str
    argv: tuple[str, ...]
    cwd: Path
    expect_pass: bool


@dataclasses.dataclass(frozen=True)
class Manifest:
    """A validated checks.toml file.

    Attributes:
        path: The model directory.
        data: The parsed TOML.
        consts: The const names that model.qnt declares.
        invariants: The `val` names in model.qnt.
        bugs: The BUG values that model.qnt allows.
    """

    path: Path
    data: dict[str, Any]
    consts: frozenset[str]
    invariants: frozenset[str]
    bugs: frozenset[str]

    @property
    def name(self) -> str:
        """Return the model name (the directory name)."""
        return self.path.name


def parse_model(source: str) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Extract the consts, vals and BUG values that a model declares.

    Args:
        source: The text of model.qnt.

    Returns:
        The const names, the val names and the BUG values.
    """
    consts = frozenset(re.findall(r"^\s*const\s+(\w+)\s*:", source, re.MULTILINE))
    vals = frozenset(re.findall(r"^\s*val\s+(\w+)\s*:", source, re.MULTILINE))
    bugs: frozenset[str] = frozenset()
    match = re.search(r"pure val BUGS: Set\[str\] = Set\((.*?)\n\s*\)", source, re.DOTALL)
    if match:
        bugs = frozenset(re.findall(r'"(\w+)"', match.group(1)))
    return consts, vals, bugs


def validate(path: Path, data: dict[str, Any], source: str) -> Manifest:
    """Check that a manifest is consistent with its model.

    The checks stop the class of mistake where a mutant is caught by an
    invariant that its baseline also fails, so the catch proves nothing.

    Args:
        path: The model directory.
        data: The parsed checks.toml.
        source: The text of model.qnt.

    Returns:
        The validated manifest.

    Raises:
        ManifestError: If the manifest refers to an unknown name, binds the
            consts incompletely, or lets a mutant be caught by an invariant
            that its baseline does not check.
    """
    consts, vals, bugs = parse_model(source)
    errors: list[str] = []
    configs: dict[str, dict[str, Any]] = data.get("configs", {})
    defaults: dict[str, str] = data.get("defaults", {})
    invariants: list[str] = data.get("invariants", [])

    for inv in invariants:
        if inv not in vals:
            errors.append(f"invariant {inv!r} is not a val in the model")
    for name, cfg in configs.items():
        bound = set(defaults) | {k for k in cfg if k not in ("skip", "why")}
        missing = consts - bound
        extra = bound - consts
        if missing:
            errors.append(f"config {name!r} does not bind {sorted(missing)}")
        if extra:
            errors.append(f"config {name!r} binds unknown consts {sorted(extra)}")
        for inv in cfg.get("skip", []):
            if inv not in invariants:
                errors.append(f"config {name!r} skips unknown invariant {inv!r}")
        if cfg.get("skip") and not cfg.get("why"):
            errors.append(f"config {name!r} skips invariants with no `why`")
    for limit in data.get("limits", []):
        if limit["config"] not in configs:
            errors.append(f"limit refers to unknown config {limit['config']!r}")
        if limit["invariant"] not in vals:
            errors.append(f"limit refers to unknown invariant {limit['invariant']!r}")
        if not limit.get("why"):
            errors.append(f"limit {limit['config']}/{limit['invariant']} has no `why`")
    for name, mut in data.get("mutants", {}).items():
        if bugs and name not in bugs:
            errors.append(f"mutant {name!r} is not a BUG value in the model")
        base = mut.get("base")
        if base not in configs:
            errors.append(f"mutant {name!r} has unknown base {base!r}")
            continue
        caught = mut.get("caught_by")
        if caught == "tests":
            continue
        if caught not in invariants:
            errors.append(f"mutant {name!r} is caught by unknown invariant {caught!r}")
        elif caught in configs[base].get("skip", []) or any(
            lim["config"] == base and lim["invariant"] == caught for lim in data.get("limits", [])
        ):
            errors.append(
                f"mutant {name!r} is caught by {caught!r}, which its base {base!r}"
                " skips: the catch proves nothing"
            )
    for name in data.get("witness_configs", []):
        if name not in configs:
            errors.append(f"witness config {name!r} is unknown")
    deep = data.get("deep")
    if deep:
        if deep.get("config") not in configs:
            errors.append(f"deep config {deep.get('config')!r} is unknown")
        for inv in deep.get("invariants", []):
            if inv not in invariants:
                errors.append(f"deep invariant {inv!r} is unknown")
    if bugs:
        untested = bugs - {"none"} - set(data.get("mutants", {}))
        if untested:
            errors.append(f"BUG values with no mutant: {sorted(untested)}")
    if errors:
        raise ManifestError(f"{path / 'checks.toml'}:\n  " + "\n  ".join(errors))
    return Manifest(path, data, consts, vals, bugs)


def instance_source(m: Manifest, module: str, bindings: dict[str, str]) -> str:
    """Return the Quint source of one instance module.

    Args:
        m: The manifest.
        module: The name of the instance module.
        bindings: The const values, as Quint expressions.

    Returns:
        The text of a .qnt file with one module.
    """
    args = ", ".join(f"{k} = {v}" for k, v in sorted(bindings.items()))
    model = m.data["model"].removesuffix(".qnt")
    return (
        f"// Generated by specs/tools/verify.py from checks.toml. Do not edit.\n"
        f"module {module} {{\n"
        f"  import {m.data['module']}({args}).* from \"../{model}\"\n"
        f"}}\n"
    )


def bindings_for(m: Manifest, config: str, bug: str | None = None) -> dict[str, str]:
    """Return the const bindings of a config, with an optional BUG override."""
    cfg = {k: v for k, v in m.data["configs"][config].items() if k not in ("skip", "why")}
    out = {**m.data.get("defaults", {}), **cfg}
    if bug is not None:
        out["BUG"] = f'"{bug}"'
    return out


def generate(m: Manifest) -> Path:
    """Write one module file for each config and each mutant.

    Returns:
        The directory of the generated files.
    """
    gen = m.path / GEN_DIR
    shutil.rmtree(gen, ignore_errors=True)
    gen.mkdir()
    for name in m.data["configs"]:
        (gen / f"{name}.qnt").write_text(instance_source(m, name, bindings_for(m, name)))
    for name, mut in m.data.get("mutants", {}).items():
        module = f"m_{name}"
        src = instance_source(m, module, bindings_for(m, mut["base"], bug=name))
        (gen / f"{module}.qnt").write_text(src)
    return gen


def run_argv(module: str, invariant: str, samples: int, steps: int, seed: str | None) -> tuple[str, ...]:
    """Return the argv of one sampled quint run."""
    argv = [
        "quint", "run", f"{GEN_DIR}/{module}.qnt", "--main", module,
        "--invariant", invariant, "--max-samples", str(samples),
        "--max-steps", str(steps), "--verbosity", "0",
    ]
    if seed:
        argv += ["--seed", seed]
    return tuple(argv)


def skipped(m: Manifest, config: str) -> set[str]:
    """Return the invariants that a config does not check.

    A config skips each invariant in its `skip` list and each invariant that a
    limit says it violates. The limit check then requires the violation.
    """
    limits = {lim["invariant"] for lim in m.data.get("limits", []) if lim["config"] == config}
    return set(m.data["configs"][config].get("skip", [])) | limits


def plan(m: Manifest, tier: str, seed: str | None) -> list[Check]:
    """Return the checks of one tier, in the order of the report."""
    checks: list[Check] = []
    d = m.data
    cwd = m.path
    if tier == "deep":
        deep = d["deep"]
        for inv in deep["invariants"]:
            argv = (
                "quint", "verify", f"{GEN_DIR}/{deep['config']}.qnt",
                "--main", deep["config"], "--invariant", inv,
                "--max-steps", str(deep["max_steps"]),
            )
            checks.append(Check(f"verify {deep['config']} {inv} (<= {deep['max_steps']} steps)", argv, cwd, True))
        return checks

    samples, steps = EFFORT[tier]
    checks.append(Check("typecheck model", ("quint", "typecheck", d["model"]), cwd, True))
    checks.append(Check(
        "scenario tests",
        ("quint", "test", d["tests"], "--main", d["test_module"]), cwd, True,
    ))
    configs = list(d["configs"]) if tier == "full" else [d.get("fast_config", next(iter(d["configs"])))]
    for name in configs:
        skip = skipped(m, name)
        for inv in d["invariants"]:
            if inv not in skip:
                checks.append(Check(f"{name} {inv}", run_argv(name, inv, samples, steps, seed), cwd, True))
    if tier == "fast":
        return checks
    for limit in d.get("limits", []):
        checks.append(Check(
            f"limit {limit['config']} {limit['invariant']} is violated ({limit['why']})",
            run_argv(limit["config"], limit["invariant"], samples, steps, seed), cwd, False,
        ))
    for name, mut in d.get("mutants", {}).items():
        if mut["caught_by"] == "tests":
            continue
        checks.append(Check(
            f"mutant {name} caught by {mut['caught_by']}",
            run_argv(f"m_{name}", mut["caught_by"], samples, steps, seed), cwd, False,
        ))
    return checks


def mutant_test_checks(m: Manifest) -> list[Check]:
    """Return a check that runs the scenario tests with the BUG of each "tests" mutant."""
    checks: list[Check] = []
    tests = (m.path / m.data["tests"]).read_text()
    for name, mut in m.data.get("mutants", {}).items():
        if mut["caught_by"] != "tests":
            continue
        patched = tests.replace('BUG = "none"', f'BUG = "{name}"').replace(
            f'from "./{m.data["model"].removesuffix(".qnt")}"',
            f'from "../{m.data["model"].removesuffix(".qnt")}"',
        )
        if patched == tests:
            raise ManifestError(f"{m.data['tests']} binds no BUG = \"none\" to replace")
        path = m.path / GEN_DIR / f"t_{name}.qnt"
        path.write_text(patched)
        checks.append(Check(
            f"mutant {name} caught by scenario tests",
            ("quint", "test", f"{GEN_DIR}/{path.name}", "--main", m.data["test_module"]),
            m.path, False,
        ))
    return checks


def witness_report(m: Manifest, samples: int, seed: str | None) -> list[tuple[str, int]]:
    """Return each witness with the number of traces that reached it."""
    source = (m.path / m.data["model"]).read_text()
    witnesses = re.findall(r"^\s*val (w[A-Z]\w*)\s*:", source, re.MULTILINE)
    totals = dict.fromkeys(witnesses, 0)
    for config in m.data.get("witness_configs", []):
        argv = [
            "quint", "run", f"{GEN_DIR}/{config}.qnt", "--main", config,
            "--invariant", "true", "--max-samples", str(samples),
            "--max-steps", str(m.data.get("witness_steps", 50)), "--witnesses", *witnesses,
        ]
        if seed:
            argv += ["--seed", seed]
        out = subprocess.run(argv, cwd=m.path, capture_output=True, text=True, check=False).stdout
        for w, n in re.findall(r"^(\w+) was witnessed in (\d+) trace", out, re.MULTILINE):
            totals[w] += int(n)
    return sorted(totals.items())


def execute(check: Check) -> tuple[Check, bool, str]:
    """Run one check. Return the check, its verdict and the tail of its output."""
    proc = subprocess.run(check.argv, cwd=check.cwd, capture_output=True, text=True, check=False)
    passed = proc.returncode == 0
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-5:]
    return check, passed == check.expect_pass, "\n".join(tail)


def run_model(m: Manifest, tier: str, jobs: int, seed: str | None) -> bool:
    """Run every check of one tier for one model. Print a report. Return True if all pass."""
    generate(m)
    checks = plan(m, tier, seed)
    if tier == "full":
        checks += mutant_test_checks(m)
    print(f"== {m.name} ({tier})")
    ok = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for check, good, tail in pool.map(execute, checks):
            print(f"  {'ok  ' if good else 'FAIL'}  {check.label}")
            if not good:
                ok = False
                print("        " + " ".join(check.argv))
                print("        " + tail.replace("\n", "\n        "))
    if tier == "full":
        for w, n in witness_report(m, EFFORT["full"][0], seed):
            good = n > 0
            ok = ok and good
            print(f"  {'ok  ' if good else 'FAIL'}  witness {w} ({n} traces)")
    return ok


def load(path: Path) -> Manifest:
    """Load and validate the manifest of one model directory."""
    data = tomllib.loads((path / "checks.toml").read_text())
    return validate(path, data, (path / data["model"]).read_text())


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the checks and return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tier", choices=sorted(TIERS))
    parser.add_argument("models", nargs="*", help="model directories in specs/ (default: all)")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--seed", help="seed for every sampled run, to repeat a result")
    args = parser.parse_args(argv)
    if shutil.which("quint") is None:
        print("quint is not on PATH. Run `mise install` in the repo root.", file=sys.stderr)
        return 2
    names = args.models or sorted(p.parent.name for p in SPECS.glob("*/checks.toml"))
    try:
        manifests = [load(SPECS / n) for n in names]
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 2
    # Apalache runs one server, so deep checks run one at a time.
    jobs = 1 if args.tier == "deep" else args.jobs
    ok = all([run_model(m, args.tier, jobs, args.seed) for m in manifests])
    effort = "bounded exhaustive" if args.tier == "deep" else "sampled, not a proof"
    print(f"\n{'ALL CHECKS PASSED' if ok else 'CHECKS FAILED'} ({args.tier}: {effort})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
