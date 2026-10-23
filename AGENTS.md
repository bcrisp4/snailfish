# AGENTS.md

## Verification

Verification is mandatory. A change is not complete until its checks pass.

Quint models in `specs/` are the source of truth for protocol behaviour. Tests cannot find the crash and interleaving bugs that a model checker finds. See `specs/README.md`.

| Before you change | Do this first | Then run |
| --- | --- | --- |
| A protocol rule in `DESIGN.md` | Change the Quint model | `specs/check.sh` |
| A Quint model | Read `specs/README.md` | `specs/check.sh` |
| Rust code | Write property-based tests (`proptest`) and Kani harnesses | `cargo test` and `cargo kani` |

- Do not change code to differ from a model. If the model is wrong, change the model first, because the code must follow the model.
- If you add an invariant, add a mutant that breaks it. A mutant that survives shows a vacuous invariant.
- Each public function in the `protocol` crate must have a Kani harness, because the relay and the engine both trust it.
- Property-based tests must check behaviour, for example the merge contract and parser round trips. Do not write tests that copy the implementation.
- A sampled `quint run` pass is not a proof. Report it as sampled.
