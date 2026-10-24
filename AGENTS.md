# AGENTS.md

## Verification

Verification is mandatory. A change is not complete until its checks pass.

Quint models in `specs/` are the source of truth for protocol behaviour. Tests cannot find the crash and interleaving bugs that a model checker finds. Before you change a model or a check, load the `snailfish-verification` skill.

| Before you change | Do this first | Then run |
| --- | --- | --- |
| A protocol rule in `DESIGN.md` | Change the Quint model | `make verify` |
| A rule in `DESIGN.md` | Keep its `[ID]` tag. Cite it in the model, or list it in `specs/coverage.toml` | `make verify-drift` |
| A Quint model or `checks.toml` | Read `specs/<model>/README.md` | `make verify-fast` while you work, `make verify` before you commit |
| A deep invariant (`[deep]` in `checks.toml`) | Run `make verify` | `make verify-deep` |
| Rust code | Write `proptest` tests and Kani harnesses | `make check` for each commit, `make rust-kani` before a merge |
| A Rust parser or decoder | Add a `cargo-fuzz` target and seeds in `fuzz/seeds/` | `make rust-fuzz` (5 minutes for each target) |
| Rust tests | Run the mutants of the changed crate | `make rust-mutants` |
| A wire format | Write the section of `PROTOCOL.md` with its test vectors first | `make check` |
| A Rust dependency | Check the licence and the advisories | `make rust-deny` |

- Run `mise install` once. It installs every tool at its pinned version. Do not use `cargo install`, `brew` or `npm -g` for dev tools, because the versions then drift. ProVerif is the exception: `opam install proverif`, then `eval $(opam env)`.
- `make check` is the gate for each commit. It runs Rust lint, tests and licences, and the fast Quint tier.
- Do not change code to differ from a model. If the model is wrong, change the model first, because the code must follow the model.
- If you add an invariant, add a mutant that breaks it. A mutant that survives shows a vacuous invariant.
- Each public function in the `protocol` crate must have a Kani harness, because the relay and the engine both trust it. If CBMC runs out of memory, shrink the harness (concrete lengths, `assert!` not `assert_eq!`) and record the bound in a comment. Do not delete the harness.
- Each parser of untrusted bytes (envelopes, payloads, stubs, ITF, request headers) must have a `cargo-fuzz` target, because the relay parses input from any caller.
- A surviving `cargo-mutants` mutant needs a new test or an entry in `.cargo/mutants.toml` with a reason. Do not raise the timeout to hide it.
- Property-based tests must check behaviour, for example the merge contract and parser round trips. Do not write tests that copy the implementation.
- Report each result with its scope. A sampled pass is not a proof. A deep pass is exhaustive only up to its step bound.
