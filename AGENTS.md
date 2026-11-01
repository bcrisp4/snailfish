# AGENTS.md

## Verification

The models in `specs/` define protocol behaviour. If Rust and a model disagree, resolve the disagreement before the merge.

Run `mise install` once. Use the pinned tools, not `cargo install`, `brew`, or `npm -g`. ProVerif uses `opam install proverif.2.05`.

### Before a change

| Change | Read first | Required evidence and reason |
| --- | --- | --- |
| A protocol rule or model | `.agents/skills/snailfish-verification/SKILL.md`, the model README, `checks.toml`, and relevant `test.qnt` scenarios | Change the model before the protocol text or Rust. The model defines the required behaviour. |
| A rule that no model covers | `.agents/skills/quint-modeling/SKILL.md`, `specs/README.md` | Add a model or record an explicit exclusion. A rule citation alone does not establish coverage. |
| Protocol, engine, or relay Rust logic | `specs/conformance.md`, the relevant model actions and named scenarios | Add a real-path Rust test of the same scenario, with model path, scenario name, and rule IDs. Model results do not verify Rust behaviour. |
| A function in `crates/protocol` | The model rule and `PROTOCOL.md` section | Add a property test and bounded Kani harness. Cite the rule ID. These checks address different input domains. |
| Enrollment, removal, or key sealing | `specs/enrollment/README.md`, `lib.pvl`, and `expect.toml` | Update the security model and a broken variant. A symbolic security result depends on its attacker assumptions. |
| Sign-in, invite links, the setup token, or tenant selection | `specs/signin/README.md`, `lib.pvl`, and `expect.toml` | Update the security model and a broken variant. Tenant isolation depends on these rules. |
| A wire format or untrusted parser | `PROTOCOL.md`, `vectors/README.md`, existing vectors and fuzz seeds | Write the format, then change `tools/vectorgen` (Go), then the Rust. Add a seeded fuzz target for each parser. Two implementations from one spec catch misreadings that one cannot. Models omit byte-level faults. |
| The user page: its HTML, `APP_JS` or headers in `crates/relay/src/core/user.rs` | `PROTOCOL.md` 12.4 and `demo/tests/test_browser.py` | Extend the Chromium test for each new page flow. The software browsers (`softbrowser.py`, `tests/common/passkey.rs`) skip CSP, `Referrer-Policy` and the browser `Origin` rule. They passed two faults that broke every form and the native approval. |
| The binding API (`crates/bindings`) | `crates/engine/src/codec.rs`, `bindings/python/tests`, `bindings/swift/Tests` | Put logic in `snailfish-engine`, not in the binding. Run the shared vectors in each binding, because a marshalling fault passes the Rust tests. |
| Verification tools or CI | `specs/README.md`, the runner tests, and `.github/workflows/verify.yml` | Reject tool errors and incomplete runs. An expected counterexample must identify the intended property. |

### After a change

| When | Run | Reason |
| --- | --- | --- |
| After each model edit | `make verify-fast MODEL=<model>` | Typechecks and scenarios expose model errors before longer checks. |
| Before each commit | `make check` | Rust checks, runner tests, workflow lint, rule IDs, and fast model checks form the local gate. |
| Before a merge with model or protocol changes | `make verify MODEL=<model>` and `make verify-deep MODEL=<model>` for each affected model | Sampling and exhaustive finite configurations provide different evidence. |
| Before a merge with a tagged design-rule change | `make verify-drift BASE=<base>` | A changed rule requires a model, scenario, manifest, or coverage change. |
| Before a merge with shared-tool or CI changes | `make verify` and `make verify-deep` | Shared tools can invalidate results for every model and backend. |
| Before a merge with enrollment or sign-in model changes | `make verify-crypto` | Every design and broken-variant query must match its expectation. |
| Before each push with Rust changes | `make rust-mutants-diff BASE=@{push}` (`BASE=main` for a branch with no push) | This tests only the new commits, in minutes. A survivor found in CI costs a 30 to 60 minute round. |
| Before a merge with Rust changes | `make rust-kani` and the CI `mutants` job | Bounded harnesses and fault-sensitive tests check the implementation. The CI job tests every mutant in the branch diff, so a local branch-wide run repeats it. |
| Before a merge with parser changes | `make rust-fuzz` | Arbitrary bytes exercise parser failure paths. |
| Before a merge with format, vector or binding changes | `make test-swift` on macOS | Linux has no Xcode, so `make check` skips the Swift binding. CI runs it in the `swift` job. |
| After a change to the user page or `APP_JS` | `make test-browser` | Chromium with a virtual WebAuthn authenticator runs the page script against a relay process. The first run downloads the Chromium build that `demo/uv.lock` pins, through Playwright. `make check` runs it too. |
| Before a merge with engine, relay storage or demo changes | `make test-powerloss` | A SIGKILL of a VM finds a missing fsync that a process crash cannot find. `make check` runs only the process crash tests (`make test-demo`). |
| Before a merge with `Dockerfile` or relay dependency changes | `docker build .` and the `image` CI job | The static musl and vendored OpenSSL build fails only in the container. |
| After a change to `PROTOCOL.md` bytes | `make vectors`, then `make vectors-check` | Go `crypto/hpke` takes no fixed ephemeral key, so a regeneration changes every `sealed` value. Regenerate only for a format change. |

`BASE` is the target branch for a pull request, or the previous commit for a direct push. The default is `main`.

Each model README states its scope and exclusions. `specs/README.md` describes the verification tiers and their limits.

### Verification speed

Each Rust test runs once for each mutant, and a branch can have 700 or more mutants. One added second in the test suite adds about 12 minutes of total test time to such a run.

| Rule | Reason |
| --- | --- |
| On macOS, run `make mutants-ramdisk` once before a mutants run. | Each SQLite commit in the tests waits for an `F_FULLFSYNC`. On a RAM disk the workspace tests take 6 s, not 45 s. |
| Start a branch-wide mutants run only after the code stops changing. | A new push makes a running run out of date. |
| A Rust test must not sleep, poll a wall clock or start a `cargo` build. If a test must, exclude it in the nextest `mutants` profile (`.config/nextest.toml`) and exclude the mutants that only it catches. | The mutants run repeats the cost for each mutant. |
| A loop over independent items (fuzz targets, models, harnesses) runs the items in parallel, up to the core or memory limit. | A serial loop uses one core of many. |
| A new CI job that builds Rust uses `Swatinem/rust-cache`. A new CI job must not take longer than the `mutants` job. | The slowest job sets the time to a result. |
| Do not make a check faster by a reduction of its coverage (cases, bounds, configs or mutants) unless the user approves it. | A faster check that finds fewer faults is a weaker check. |

### Result requirements

| Requirement | Reason |
| --- | --- |
| A new invariant needs a mutant that breaks it and a baseline that passes it. | An unchanged verdict can hide an inadequate configuration. Increase the domain or add a named scenario. |
| A known limit must reproduce its counterexample. Each required witness must occur. | A green result can otherwise describe an unreachable state or a missing failure path. |
| If Kani exceeds available memory, reduce the harness and record its bound. Do not delete the harness. | Resource failure is not a counterexample or a successful check. |
| A surviving Rust mutant needs a behavioural test or a justified `.cargo/mutants.toml` entry. | A surviving fault leaves the associated behaviour unverified. |
| Report sampled traces, step bounds, finite configurations, and ProVerif assumptions explicitly. | No result covers inputs or behaviours outside its scope. Never report the system as "proven". |

### Test requirements

Before a new test, lint rule, or alert, identify the concrete production failure that it detects.

Test observable behaviour, boundaries, and failure modes. Mock external boundaries only. Use real databases for persistence scenarios.

Do not copy the implementation into the expected result. Do not add tests that detect harmless refactors or assert mock calls alone.

A skipped test leaves its obligation unverified. Do not weaken a check to obtain a green result.
