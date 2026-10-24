# Quint specs

These Quint models check parts of `DESIGN.md`. Each model is executable. The fast and full tiers sample traces with `quint run`, so a pass is evidence, not a proof. The deep tier runs `quint verify` (Apalache), which is exhaustive up to a step bound.

## Layout

| Path | Content |
| --- | --- |
| `<model>/model.qnt` | The model. One module, with all consts unbound. |
| `<model>/test.qnt` | Scenario tests (`quint test`). |
| `<model>/checks.toml` | Configs, invariants, known limits, mutants and witnesses. |
| `<model>/README.md` | Coverage map, findings and the cases that the model leaves out. |
| `<model>/_gen/` | Generated config modules and traces. Not committed. |
| `tools/verify.py` | Runs the checks of each tier for each model. |
| `tools/trace.py` | Finds and prints a counterexample with only the changed fields. |
| `tools/rules.py` | Checks the rule IDs of `DESIGN.md` against the model citations and `coverage.toml`. Finds rule changes with no change in `specs/`. |
| `coverage.toml` | The rules that no model encodes yet, each with a reason. |

## Rule IDs

Each normative rule in `DESIGN.md` ends with an ID tag, for example `[DLV-3]`. A model cites the rules that it encodes in a comment, for example `// [DLV-3]`. A rule with no citation is listed in `coverage.toml` under `not_modelled`.

1. Run `mise exec -- uv run --script specs/tools/rules.py list` to see the rules.
2. Run `make verify-fast`. It runs `rules.py check`.
3. Run `make verify-drift` before you commit a design change. It fails if a rule changed and nothing in `specs/` changed since `main`.

## Models

| Model | Scope |
| --- | --- |
| [delivery](delivery/README.md) | Outbox, enqueue, push, pull, app DB restore, engine state loss, relay rollback, repair, restore hold. |
| [spacelog](spacelog/README.md) | Genesis, grants, removal with key rotation, the base rule, a malicious relay (fork, forge, reorder). |

## Run the checks

1. Run `mise install` in the repo root, once. It installs quint, Java and Python.
2. Run `make verify-fast` while you change a model. It takes about 3 seconds.
3. Run `make verify` before you commit. It takes about 6 minutes.
4. Run `make verify-deep` after a change to a deep invariant. It takes about 5 minutes.
5. To repeat a sampled result, add the seed: `mise exec -- uv run --script specs/tools/verify.py full --seed 0x1234`.

## Read a counterexample

1. Run `make verify-fast` once, so that `_gen/` exists.
2. Run `mise exec -- uv run --script specs/tools/trace.py repro delivery silentOnly refusedNotStored`.
3. Read the trace. State 0 is in full. Each later state shows only the fields that changed.

## Add a model

1. Create `specs/<model>/` with `model.qnt`, `test.qnt`, `checks.toml` and `README.md`. Copy the shape of `delivery/`.
2. In `model.qnt`, declare `const BUG: str` and a `BUGS` set. Each BUG value except "none" is one deliberate design violation.
3. In `checks.toml`, add each config, each known limit with its reason, and each mutant with its baseline and the invariant that must catch it.
4. Run `make verify`. `verify.py` refuses a manifest that has a BUG value with no mutant, or a mutant whose catch its baseline also fails.

## Rules for checks

- A mutant must fail an invariant that its baseline passes. If not, the catch proves nothing.
- A known limit must fail. If it holds, the model changed or the limit is gone: update the manifest and the README.
- Each witness must be reached in at least one trace. A witness at 0 traces shows a dead action.
- If sampling cannot reach a mutant, set `caught_by = "tests"` and add a scenario test that the mutant fails.
