# AGENTS.md

## Verification

Verification is mandatory. A change is not complete until the checks for its kind of change pass. The models in `specs/` are the source of truth for protocol behaviour. If code and a model disagree, fix the code, or change the model first and then the code.

Run `mise install` once. It pins every tool. Do not use `cargo install`, `brew` or `npm -g` for dev tools. ProVerif is the exception: `opam install proverif`, then `eval $(opam env)`.

### When to run what

| When | Run | Time |
| --- | --- | --- |
| After each edit to a model | `make verify-fast MODEL=<model>` | 10 s |
| Before each commit | `make check`: Rust lint, tests and licences, rule IDs, fast Quint | 1 min |
| Before a merge that touches `specs/`, `DESIGN.md` or `crates/protocol` | `make verify MODEL=<model>` for each changed model, then `make verify-drift` and `make rust-kani` | delivery 1 min, spacelog 19 min, Kani 2 min |
| Before a merge that touches `specs/enrollment` | `make verify-crypto` | 5 s |
| Before a merge that changes shared tooling (`specs/tools/`, `Makefile`) | `make verify` (all models and ProVerif) | 19 min |
| Before a merge that changes a `[deep]` invariant | `make verify-deep MODEL=<model>` | 5 min |
| Before a merge that changes a parser | `make rust-fuzz` | 5 min per target |
| Before a merge that changes Rust code | `make rust-mutants-diff`: mutants in the changed code only | 10 s now |

Models, each with a `README.md` of its scope and limits:

- `delivery` (Quint): outbox, sync, app and engine restore, relay rollback and repair.
- `spacelog` (Quint): grants, removal and key rotation, the base rule, a malicious relay.
- `enrollment` (ProVerif): the device pairing protocol against a network attacker.

### What to add for each change

| You change | First | Then add |
| --- | --- | --- |
| A protocol rule in `DESIGN.md` | Load the `snailfish-verification` skill. Change the model. | A `BUG` value and a mutant that the rule's invariant catches. Keep the rule's `[ID]` tag, and cite it in the model or in `specs/coverage.toml`. |
| A rule that no model covers yet | Load the `quint-modeling` skill | A new model in `specs/<name>/`. Copy the shape of `specs/delivery/`. |
| Enrollment, removal or key sealing | Change `specs/enrollment/*.pv` | A broken variant `.pv` file and its lines in `expect.toml`. |
| A wire format | Write its `PROTOCOL.md` section with test vectors | The vectors as unit tests. |
| A function in `crates/protocol` | Find the model rule that it implements | A `proptest` of its property, a Kani harness, and the rule `[ID]` in a comment. |
| A parser of untrusted bytes | | A `cargo-fuzz` target with seeds in `fuzz/seeds/`. |
| Engine or relay logic | Find the model action that it implements | A test of the same scenario as the model's `test.qnt`. |
| A dependency | | Nothing new: `make check` runs `cargo deny`. |

### Rules

- A new invariant needs a mutant that breaks it, and the mutant's baseline must pass that invariant. If a mutant changes no verdict, make the baseline larger (more devices) or add a scripted test. A small baseline hid four mutants once (spacelog finding S1).
- If Kani runs out of memory, shrink the harness and record the bound in a comment. Do not delete it.
- A surviving `cargo-mutants` mutant needs a test, or an entry in `.cargo/mutants.toml` with a reason.
- Tests check behaviour. Do not write a test that copies the implementation.
- Report each result with its scope: "sampled", "bounded to N steps", or "for unbounded sessions (ProVerif)". Never "proven".
