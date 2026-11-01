# Quint specs

These models check parts of `DESIGN.md`. Each model README states its assumptions and exclusions.

The fast and full Quint tiers sample traces. Apalache checks every trace up to a step bound. TLC checks every reachable state of selected finite configurations.

ProVerif checks enrollment and sign-in queries for unbounded sessions under its symbolic attacker assumptions. None of these results establishes Rust conformance.

## Layout

| Path | Content |
| --- | --- |
| `<model>/model.qnt` | The model. One module, with all consts unbound. |
| `<model>/test.qnt` | Scenario tests (`quint test`). |
| `<model>/checks.toml` | Configs, invariants, known limits, mutants and witnesses. |
| `<model>/README.md` | Coverage map, findings and the cases that the model leaves out. |
| `<model>/_gen/` | Generated config modules and traces. Not committed. |
| `tools/verify.py` | Runs the checks of each tier for each model. One `quint run` checks all invariants of a config and counts its witnesses. |
| `tools/trace.py` | Finds and prints a counterexample with only the changed fields. |
| `tools/proverif.py` | Runs the ProVerif files of each directory with an `expect.toml` (`enrollment/`, `signin/`) and compares each query with it. |
| `tools/rules.py` | Checks the rule IDs of `DESIGN.md` against the model citations (`.qnt`, `.pv` and `.pvl` files) and `coverage.toml`. Finds rule changes with no change in `specs/`. |
| `coverage.toml` | The rules that no model encodes yet, each with a reason. |
| [conformance.md](conformance.md) | Required model-to-Rust scenario tests, observable results, and persistence tests. |

## Rule IDs

Each normative rule in `DESIGN.md` ends with an ID tag, for example `[DLV-3]`. A model cites its rules in comments.

`coverage.toml` lists rules with no model citation. A citation can cover part of a rule. It does not establish complete coverage.

The rule check verifies references, not semantics. The drift check requires a relevant file change, not a correct model update.

1. Run `mise exec -- uv run --script specs/tools/rules.py list` to see the rules.
2. Run `make verify-fast`. It runs `rules.py check`.
3. Run `make verify-drift BASE=<base>` before a design merge. A changed rule requires a model, scenario, manifest, or coverage change.

## Models

| Model | Scope |
| --- | --- |
| [delivery](delivery/README.md) | Outbox, enqueue, push, pull, app DB restore, engine state loss, relay rollback, repair, restore hold. |
| [spacelog](spacelog/README.md) | Genesis, grants, removal, key rotation, malicious relay behaviour, and bounded invalid records from compromised keys. |
| [epochs](epochs/README.md) | Epoch retries, deduplication, removal during a hold, and security-record repair after relay restore. |
| [enrollment](enrollment/README.md) | ProVerif (symbolic, Dolev-Yao): numeric comparison, commit before reveal, signed confirmation, grant and checkpoint, app key sealing. Run with `make verify-crypto`. |
| [signin](signin/README.md) | ProVerif (symbolic, Dolev-Yao): invite links, passkey sign-in, the PKCE code, the setup token bound to the device key, and tenant isolation. Run with `make verify-crypto`. |
| [quota](quota/README.md) | Space quota refusal, the outbox after a refusal, fetches and security records at a full quota. |

## Exclusions

These rules have no model. Real-path tests check them instead. `coverage.toml` lists each one.

| Rule | Reason | Tests |
| --- | --- | --- |
| The WebAuthn ceremony (DESIGN.md "Interfaces") | The `webauthn-rs` crate does the registration and the assertion checks. A model of the ceremony would check that crate, not this design. `specs/signin` treats a passkey as an ideal signature. | `crates/relay/tests/user.rs` passkey tests with a software authenticator |
| [USR-2] A new invite link removes the old passkeys and sessions | One storage transaction with no protocol state. | `crates/relay/tests/user.rs` |
| [USR-7] Origin, anti-CSRF token and cookie rules | Browser rules of the user page. The HTML and the browser are outside every model. | `crates/relay/tests/user.rs`, `demo/tests/test_users.py` |
| [USR-8] Webhook host allowlist and address checks | A DNS and socket rule of the relay, with no shared state. | `crates/relay/src/webhook.rs` tests, `demo/tests/test_users.py` |
| [QTA-5] The space count limit | One check in space creation. | `crates/relay/tests/user.rs` |
| The user page HTML | Presentation only. Each write goes through a route that the tests above check. | `demo/tests/test_users.py` |

## Run the checks

1. Run `mise install` in the repo root, once. It installs quint, Java and Python.
2. Run `make verify-fast MODEL=<model>` while you change a model. It takes seconds.
3. Run `make verify MODEL=<model>` before you merge. AGENTS.md "When to run what" gives the times.
4. Run `make verify-deep MODEL=<model>` after a change to a deep invariant.
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

## Assurance boundaries

| Evidence | What it does not establish |
| --- | --- |
| A scenario test | Correctness for all interleavings or all input values. |
| A sampled invariant check | Absence of a counterexample outside the sampled traces. |
| An Apalache result | Safety beyond its step bound or outside its configuration. |
| A TLC result | Safety for more devices, records, faults, or other configurations. |
| A ProVerif result | Security of real cryptographic code, code-guess probabilities, or excluded state transitions. |

The model READMEs define their fault domains. The epochs model checks selected delivery/security interactions, not the complete product of both models.

Rust property tests, Kani harnesses, and fuzz targets check implementation properties within their own input domains.

For protocol implementation changes, follow [Model-to-Rust conformance](conformance.md). Report model evidence and implementation evidence separately.

## CI

Each pull request and push to `main` runs Rust checks, runner tests, workflow lint, every model tier, ProVerif, and Kani.

CI discovers Quint models through `specs/*/checks.toml`. Full CI checks sample 5,000 traces per check, not the local default of 20,000.

The `mutants` job runs cargo-mutants in 8 shards: the changed Rust code for a pull request or push, and every mutant nightly. Nightly jobs also run longer fuzz checks. The workflow does not use path filters.

`make verify-workflows` checks workflow syntax, expressions, and action inputs with pinned actionlint.

GitHub branch protection must require the verification jobs before merge. A workflow file alone does not prevent a merge after failed checks.

GitHub execution and branch protection remain unverified.
