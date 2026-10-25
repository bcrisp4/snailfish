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
# Keys of a [configs.*] table that are not consts of the model.
CONFIG_KEYS = frozenset({"skip", "why", "check_only"})


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
        invariants: The invariants of a batched run, for the report.
    """

    label: str
    argv: tuple[str, ...]
    cwd: Path
    expect_pass: bool
    invariants: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Manifest:
    """A validated checks.toml file.

    Attributes:
        path: The model directory.
        data: The parsed TOML.
        consts: The const names that model.qnt declares.
        invariants: The `val` names in model.qnt.
        bugs: The BUG values that model.qnt allows.
        witnesses: The witness names (`val w<Upper>...`) of model.qnt.
    """

    path: Path
    data: dict[str, Any]
    consts: frozenset[str]
    invariants: frozenset[str]
    bugs: frozenset[str]
    witnesses: tuple[str, ...] = ()

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
        bound = set(defaults) | {k for k in cfg if k not in CONFIG_KEYS}
        for inv in cfg.get("check_only", []):
            if inv not in invariants:
                errors.append(f"config {name!r} checks unknown invariant {inv!r}")
        if "check_only" in cfg and not cfg.get("why"):
            errors.append(f"config {name!r} has `check_only` with no `why`")
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
        if mut.get("open") and not mut.get("why"):
            errors.append(f"open mutant {name!r} has no `why`")
        if caught == "tests":
            module = mut.get("test_module")
            if module and module not in [data.get("test_module"), *data.get("test_modules", [])]:
                errors.append(f"mutant {name!r} names unknown test module {module!r}")
            if not mut.get("test"):
                errors.append(
                    f"mutant {name!r} is caught by tests but names no `test`: any failing"
                    " test would count, also one that fails for another reason"
                )
            continue
        if caught not in invariants:
            errors.append(f"mutant {name!r} is caught by unknown invariant {caught!r}")
        elif caught in configs[base].get("skip", []) or (
            "check_only" in configs[base] and caught not in configs[base]["check_only"]
        ) or any(
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
    witnesses = tuple(re.findall(r"^\s*val (w[A-Z]\w*)\s*:", source, re.MULTILINE))
    return Manifest(path, data, consts, vals, bugs, witnesses)


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
    cfg = {k: v for k, v in m.data["configs"][config].items() if k not in CONFIG_KEYS}
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


def run_argv(
    module: str, invariants: list[str], samples: int, steps: int, seed: str | None,
    witnesses: list[str] | None = None,
) -> tuple[str, ...]:
    """Return the argv of one sampled quint run.

    One run checks every invariant in `invariants` on each state of each
    trace, and counts each witness. It costs about the same as a run with one
    invariant, because trace generation dominates. Verbosity 1 prints the name
    of each violated invariant and the witness counts.
    """
    argv = [
        "quint", "run", f"{GEN_DIR}/{module}.qnt", "--main", module,
        "--invariants", *invariants, "--max-samples", str(samples),
        "--max-steps", str(steps), "--verbosity", "1",
    ]
    if witnesses:
        argv += ["--witnesses", *witnesses]
    if seed:
        argv += ["--seed", seed]
    return tuple(argv)

def skipped(m: Manifest, config: str) -> set[str]:
    """Return the invariants that a config does not check.

    A config skips each invariant in its `skip` list and each invariant that a
    limit says it violates. The limit check then requires the violation.
    """
    cfg = m.data["configs"][config]
    limits = {lim["invariant"] for lim in m.data.get("limits", []) if lim["config"] == config}
    skip = set(cfg.get("skip", [])) | limits
    if "check_only" in cfg:
        skip |= set(m.data["invariants"]) - set(cfg["check_only"])
    return skip


def plan(m: Manifest, tier: str, seed: str | None) -> list[Check]:
    """Return the checks of one tier, in the order of the report."""
    checks: list[Check] = []
    d = m.data
    cwd = m.path
    if tier == "deep":
        deep = d["deep"]
        argv = (
            "quint", "verify", f"{GEN_DIR}/{deep['config']}.qnt",
            "--main", deep["config"], "--invariants", *deep["invariants"],
            "--max-steps", str(deep["max_steps"]),
        )
        label = f"verify {deep['config']}: {', '.join(deep['invariants'])} (<= {deep['max_steps']} steps)"
        checks.append(Check(label, argv, cwd, True, tuple(deep["invariants"])))
        return checks

    samples, steps = EFFORT[tier]
    checks.append(Check("typecheck model", ("quint", "typecheck", d["model"]), cwd, True))
    for module in test_modules(m):
        checks.append(Check(
            f"scenario tests ({module})",
            ("quint", "test", d["tests"], "--main", module), cwd, True,
        ))
    configs = list(d["configs"]) if tier == "full" else [d.get("fast_config", next(iter(d["configs"])))]
    witnesses = witness_names(m) if tier == "full" else []
    for name in configs:
        skip = skipped(m, name)
        invs = [inv for inv in d["invariants"] if inv not in skip]
        with_w = witnesses if name in d.get("witness_configs", []) else []
        if not invs and not with_w:
            continue
        # A witness config reports its witness counts with the steps that
        # witness_steps sets. The invariants then run with those steps too.
        run_steps = d.get("witness_steps", steps) if with_w else steps
        checks.append(Check(
            f"{name}: {len(invs)} invariants" + (f", {len(with_w)} witnesses" if with_w else ""),
            run_argv(name, invs or ["true"], samples, max(steps, run_steps), seed, with_w),
            cwd, True, tuple(invs),
        ))
    if tier == "fast":
        return checks
    for limit in d.get("limits", []):
        checks.append(Check(
            f"limit {limit['config']} {limit['invariant']} is violated ({limit['why']})",
            run_argv(limit["config"], [limit["invariant"]], samples, steps, seed), cwd, False,
        ))
    for name, mut in d.get("mutants", {}).items():
        if mut["caught_by"] == "tests":
            continue
        # An open mutant is a known gap: no check catches it yet. Its check
        # expects the invariant to hold. If the invariant starts to fail, the
        # check fails, so the manifest must move the mutant out of `open`.
        is_open = bool(mut.get("open"))
        label = (
            f"OPEN mutant {name} not caught by {mut['caught_by']} ({mut['why']})"
            if is_open else f"mutant {name} caught by {mut['caught_by']}"
        )
        checks.append(Check(
            label, run_argv(f"m_{name}", [mut["caught_by"]], samples, steps, seed), cwd, is_open,
        ))
    return checks


def test_modules(m: Manifest) -> list[str]:
    """Return the test modules: `test_module`, then each extra one in `test_modules`."""
    extra = [t for t in m.data.get("test_modules", []) if t != m.data["test_module"]]
    return [m.data["test_module"], *extra]


def mutant_test_checks(m: Manifest) -> list[Check]:
    """Return checks that run the scenario tests with the BUG of each "tests" mutant.

    The named test must fail under the mutant, and each other test must still
    pass. If another test also failed, the mutant would break the test set for
    a reason that the named test does not check, so the catch would prove less.
    """
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
        module = mut.get("test_module", m.data["test_module"])
        base = ("quint", "test", f"{GEN_DIR}/{path.name}", "--main", module)
        test = mut["test"]
        checks.append(Check(
            f"mutant {name} caught by test {test}", (*base, "--match", f"^{test}$"), m.path, False,
        ))
        checks.append(Check(
            f"mutant {name}: the other tests still pass",
            (*base, "--match", f"^(?!{test}$).*Test$"), m.path, True,
        ))
    return checks


def witness_names(m: Manifest) -> list[str]:
    """Return the witnesses of a model: each `val w<Upper>...`."""
    return list(m.witnesses)


def witness_counts(output: str) -> dict[str, int]:
    """Parse "<w> was witnessed in N trace(s)" lines of a quint run."""
    return {w: int(n) for w, n in re.findall(r"^(\w+) was witnessed in (\d+) trace", output, re.MULTILINE)}


def violated(output: str) -> list[str]:
    """Parse the names of the violated invariants of a batched quint run."""
    return re.findall(r"^\s*❌ (\w+)", output, re.MULTILINE)

def execute(check: Check) -> tuple[Check, bool, str]:
    """Run one check. Return the check, its verdict and its full output."""
    proc = subprocess.run(check.argv, cwd=check.cwd, capture_output=True, text=True, check=False)
    return check, (proc.returncode == 0) == check.expect_pass, proc.stdout + proc.stderr

def run_model(m: Manifest, tier: str, jobs: int, seed: str | None) -> bool:
    """Run every check of one tier for one model. Print a report. Return True if all pass."""
    generate(m)
    checks = plan(m, tier, seed)
    if tier == "full":
        checks += mutant_test_checks(m)
    print(f"== {m.name} ({tier})")
    ok = True
    totals: dict[str, int] = dict.fromkeys(witness_names(m) if tier == "full" else [], 0)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for check, good, output in pool.map(execute, checks):
            for w, n in witness_counts(output).items():
                totals[w] = totals.get(w, 0) + n
            print(f"  {'ok  ' if good else 'FAIL'}  {check.label}")
            if not good:
                ok = False
                bad = violated(output)
                if check.invariants and bad:
                    print(f"        violated: {', '.join(bad)}")
                print("        " + " ".join(check.argv))
                tail = output.strip().splitlines()[-5:]
                print("        " + "\n        ".join(tail))
    for w, n in sorted(totals.items()):
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
    parser.add_argument(
        "--samples", type=int,
        help="traces for each sampled run (default: 2000 fast, 20000 full). CI uses fewer to fit its time limit",
    )
    args = parser.parse_args(argv)
    if args.samples:
        for tier in EFFORT:
            EFFORT[tier] = (args.samples, EFFORT[tier][1])
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
