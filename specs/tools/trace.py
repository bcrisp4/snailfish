#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Print a Quint counterexample with only the changed fields of each state.

A full ITF trace is long, because each state repeats every variable. This tool
prints state 0 in full and then, for each later state, only the fields that
changed. Use it to read a violation fast.

Usage:
    specs/tools/trace.py repro MODEL CONFIG INVARIANT [--steps N] [--seed S]
    specs/tools/trace.py show TRACE.itf.json [--hide PREFIX ...]

`repro` runs `verify.py`'s generated config, writes the trace to
specs/MODEL/_gen/CONFIG.INVARIANT.itf.json and prints it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

SPECS = Path(__file__).resolve().parent.parent


def decode(value: Any) -> Any:
    """Convert an ITF JSON value into plain Python values.

    Sets become sorted lists, maps become dicts with string keys, and variants
    become "Tag" or "Tag(value)".
    """
    if isinstance(value, dict):
        if "#bigint" in value:
            return int(value["#bigint"])
        if "#set" in value:
            return sorted((decode(v) for v in value["#set"]), key=str)
        if "#map" in value:
            return {str(decode(k)): decode(v) for k, v in value["#map"]}
        if "#tup" in value:
            return tuple(decode(v) for v in value["#tup"])
        if "tag" in value:
            inner = value.get("value")
            if inner in ({"#tup": []}, None):
                return value["tag"]
            return f"{value['tag']}({decode(inner)})"
        return {k: decode(v) for k, v in value.items() if not k.startswith("#")}
    if isinstance(value, list):
        return [decode(v) for v in value]
    return value


def flatten(record: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts (records and maps) into dotted keys.

    A list or a scalar stays one field, so a set or a log prints on one line.
    """
    out: dict[str, Any] = {}
    for key, value in record.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            out.update(flatten(value, f"{name}."))
        else:
            out[name] = value
    return out


def states(trace: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the decoded and flattened states of an ITF trace."""
    result = []
    for raw in trace["states"]:
        plain = {k.split("::")[-1]: decode(v) for k, v in raw.items() if not k.startswith("#")}
        result.append(flatten(plain))
    return result


def show(path: Path, hide: list[str]) -> None:
    """Print a trace as state 0 and then the changes of each state."""
    previous: dict[str, Any] = {}
    for i, state in enumerate(states(json.loads(path.read_text()))):
        changed = {
            k: v for k, v in state.items()
            if previous.get(k) != v and not any(k.startswith(h) for h in hide)
        }
        if i == 0:
            print("[0] initial state")
            for k, v in sorted(changed.items()):
                print(f"      {k} = {v}")
        elif changed:
            print(f"[{i}]")
            for k, v in sorted(changed.items()):
                print(f"      {k} = {v}")
        else:
            print(f"[{i}] (no change)")
        previous = state


def repro(model: str, config: str, invariant: str, steps: int, seed: str | None) -> int:
    """Run one config until the invariant fails, then print the trace."""
    root = SPECS / model
    gen = root / "_gen" / f"{config}.qnt"
    if not gen.exists():
        print(f"{gen} does not exist. Run `specs/tools/verify.py fast {model}` first.", file=sys.stderr)
        return 2
    out = root / "_gen" / f"{config}.{invariant}.itf.json"
    argv = [
        "quint", "run", str(gen.relative_to(root)), "--main", config, "--invariant", invariant,
        "--max-steps", str(steps), "--max-samples", "50000", "--out-itf", str(out.relative_to(root)),
        "--verbosity", "1",
    ]
    if seed:
        argv += ["--seed", seed]
    proc = subprocess.run(argv, cwd=root, capture_output=True, text=True, check=False)
    print(proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else proc.stderr.strip())
    if proc.returncode == 0:
        print(f"No violation of {invariant} in {config}.")
        return 0
    show(out, hide=["env.events", "env.changes."])
    return 1


def main() -> int:
    """Parse arguments and run the chosen command."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("repro", help="find and print a counterexample")
    r.add_argument("model")
    r.add_argument("config")
    r.add_argument("invariant")
    r.add_argument("--steps", type=int, default=50)
    r.add_argument("--seed")
    s = sub.add_parser("show", help="print an ITF trace file")
    s.add_argument("path", type=Path)
    s.add_argument("--hide", nargs="*", default=[])
    args = parser.parse_args()
    if args.cmd == "show":
        show(args.path, args.hide)
        return 0
    return repro(args.model, args.config, args.invariant, args.steps, args.seed)


if __name__ == "__main__":
    sys.exit(main())
