# AGENTS.md

## Verification

Verification is mandatory. A change is not complete until its checks pass.

Quint models in `specs/` are the source of truth for protocol behaviour. Tests cannot find the crash and interleaving bugs that a model checker finds. Before you change a model or a check, load the `snailfish-verification` skill.

| Before you change | Do this first | Then run |
| --- | --- | --- |
| A protocol rule in `DESIGN.md` | Change the Quint model | `make verify` |
| A Quint model or `checks.toml` | Read `specs/<model>/README.md` | `make verify-fast` while you work, `make verify` before you commit |
| A deep invariant (`[deep]` in `checks.toml`) | Run `make verify` | `make verify-deep` |
| Rust code | Write `proptest` tests and Kani harnesses | `cargo test`, `cargo kani` |
| A Rust parser or decoder | Add a `cargo-fuzz` target | `cargo fuzz run <target>` for at least 5 minutes |
| Rust tests | Run the mutants of the changed crate | `cargo mutants -p <crate>` |

- Run `mise install` once. It installs quint, Java (for Apalache) and Python at the pinned versions.
- Do not change code to differ from a model. If the model is wrong, change the model first, because the code must follow the model.
- If you add an invariant, add a mutant that breaks it. A mutant that survives shows a vacuous invariant.
- Each public function in the `protocol` crate must have a Kani harness, because the relay and the engine both trust it.
- Each parser of untrusted bytes (envelopes, payloads, stubs, ITF, request headers) must have a `cargo-fuzz` target, because the relay parses input from any caller.
- A surviving `cargo-mutants` mutant needs a new test or an entry in `.cargo/mutants.toml` with a reason. Do not raise the timeout to hide it.
- Property-based tests must check behaviour, for example the merge contract and parser round trips. Do not write tests that copy the implementation.
- Report each result with its scope. A sampled pass is not a proof. A deep pass is exhaustive only up to its step bound.
