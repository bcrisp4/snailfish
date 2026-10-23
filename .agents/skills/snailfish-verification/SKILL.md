---
name: snailfish-verification
description: >
  The Snailfish verification workflow: Quint models in specs/, the checks.toml
  manifests, verify.py tiers, trace.py, mutants and known limits, and the Quint
  pitfalls found in this repo. Use before you add or change a Quint model, a
  DESIGN.md protocol rule, or a check, and when you read a counterexample. For
  Quint syntax use quint-lang. For a new model from scratch use quint-modeling.
---

# Snailfish verification

This skill holds the project rules. The quint-lang and quint-modeling skills hold the general Quint rules. If they disagree, this skill wins for this repo.

## Workflow for a protocol change

1. Read `specs/<model>/README.md` for the coverage map and the known limits.
2. Change `model.qnt` first. Then change `DESIGN.md`. The model is the source of truth.
3. If you add a rule, add a BUG value that breaks it, and a mutant in `checks.toml`.
4. Run `make verify-fast` after each edit. It takes seconds.
5. Run `make verify` before you commit. Run `make verify-deep` if a deep invariant changed.
6. Update the model README: coverage, findings, limits and "Not covered".

## Rules for checks

- A mutant must fail an invariant that its baseline passes. `verify.py` refuses a manifest that breaks this, because the catch then proves nothing.
- A known limit is a `[[limits]]` entry with a `why`. The check requires the violation. If a limit starts to hold, find out why before you delete it.
- Each witness (`val w*`) must be reached. Zero traces means a dead action or an over-strong guard.
- If sampling cannot reach a path, set `caught_by = "tests"` and write a scripted test in `test.qnt`. Do not raise the step count until it passes by luck.
- Report results with their scope: "sampled, 20000 traces x 50 steps" or "bounded exhaustive, 8 steps". Never "proven".

## Read a counterexample

1. Run `mise exec -- uv run --script specs/tools/trace.py repro <model> <config> <invariant>`.
2. Read the changed fields of each state. Name the action of each step from the change.
3. Decide: a real design gap, a known limit, or a model error. Ask Ben if it is a design gap.
4. If it is a design gap, record it in the model README as a finding with an ID and a repro command.

## Quint pitfalls in this repo

| Pitfall | Fix |
| --- | --- |
| A config module cannot use a sum-type constructor of the spec in its import (QNT099). | Bind such consts as strings, for example `BUG: str` and `FAULTS: Set[str]`. |
| A `.fail()` step in the middle of a `run` test leaves the state unset (QNT502). | Use `.fail()` only as the last step. In the middle, `.expect()` the guard predicate instead. |
| A `def` cannot assign state (QNT200). | Use `action` for a helper that assigns `x'`. |
| Apalache refuses a file with many instance modules ("String value length exceeds the maximum"). | Keep one instance module per file. `verify.py` generates them in `_gen/`. |
| `quint run` does not report a deadlock. A short trace is the only sign. | Watch the trace length. Add a witness for the end state you expect. |
| A `nondet x = S.oneOf()` with an empty `S` disables the action. | Put the guard `S != Set()` first, or pass the value as an action argument. |
| `Map.set(k, v)` on a missing key is undefined. | Use `put`, or pre-populate the map in `init`. |
| Ghost state (`env`) that a fault destroys must not count as "held". | Keep ghost sets for "stored", "exposed" and "reverted", and define invariants on them. |

## Tools

| Command | Purpose |
| --- | --- |
| `make verify-fast` | Typecheck, tests, short sampling of `fast_config`. |
| `make verify` | Every config, limit, mutant and witness. Also the runner tests. |
| `make verify-deep` | `quint verify` on `[deep]` invariants. |
| `specs/tools/trace.py repro` | Find and print a counterexample. |
| `specs/tools/trace.py show` | Print an ITF trace file. |
