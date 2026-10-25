# Model-to-Rust conformance

The models define protocol behaviour. Rust tests must check that the implementation follows the same scenarios through its public interfaces.

These tests check specific executions. They do not establish equivalence for every execution or extend a model beyond its documented assumptions.

## Before Rust implementation

1. Read the model README, the relevant actions, and the scenario tests in `specs/<model>/test.qnt`.
2. Select the rule IDs and the model scenario for the behaviour that the Rust change implements.
3. If no scenario covers the behaviour, add one to the model before the Rust change.
4. If the model excludes the behaviour, document the gap instead of a model-conformance claim.
5. Select the public results and persistent state that the Rust test will compare with the model scenario.

The comparison must use the model's abstraction. A model change ID can represent a signed Rust envelope with fixed test keys and payload bytes.

A model log position can represent the position that the Rust API returns. Byte-level format tests remain separate and use `PROTOCOL.md` vectors.

## Required test evidence

| Evidence | Requirement | Reason |
| --- | --- | --- |
| Model reference | Cite the model path, named scenario, and rule IDs in the test. | A scenario name identifies the required behaviour after a model change. |
| Real execution | Execute the ordered scenario through the real Rust API. | A second implementation of the model does not check the production code. |
| Observable results | Assert return values, refusals, emitted requests, and relevant persistent state at the scenario boundaries. | A final-state assertion can miss a wrong intermediate result. |
| Independent expectations | Use explicit expected outcomes from the model scenario. | Expectations derived from the Rust implementation cannot detect the same error in that implementation. |
| Failure sensitivity | Demonstrate that a corresponding Rust fault makes the test fail. | A test that cannot detect the relevant fault provides no conformance evidence. |

For example, an engine test can cite `specs/delivery/test.qnt::notRepairedMarkTest` and its rule IDs.

The test must execute the restore, engine state loss, fetch, and hold-release sequence through real interfaces.

Its assertions must check the repair status and the warning before release, not a private implementation flag.

## Persistent state and external boundaries

1. Use real temporary databases and files for persistence scenarios.
2. For a crash or restart, create a new Rust instance from the surviving files.
3. For a restore, replace the relevant files with the backup that the scenario specifies.
4. Control network delivery, clocks, and process failure at their external boundaries.
5. If the implementation disagrees with the model, resolve the disagreement before the merge.

A persistence test must not simulate durability through a mocked database. It must not reconstruct state that a real restart cannot recover.

A relay test must check the stored log through its public interface. A client test must check the state that an application can observe.

## Adoption

Named Rust tests can cover model scenarios before a generic trace exporter exists.

Do not add an empty conformance framework before the Rust interfaces exist.

For each implementation change, add or extend the relevant test. Reuse an existing test if it checks the same obligation.

A future trace-replay adapter can reduce duplicate scenario definitions. It must execute the production API and compare the same observable state.

## Verification

1. Run `make verify-fast MODEL=<model>` after each model edit.
2. Run `make rust-test` after the Rust test and implementation changes.
3. Run `make rust-mutants-diff BASE=<base>` for the changed Rust code.
4. Run the additional checks in `AGENTS.md` for the affected paths.
5. Report the model bounds and the Rust scenarios separately.

If a corresponding mutant survives, add a behavioural assertion or document an equivalent mutant under the existing mutation policy.

A skipped test leaves its obligation unverified. A model result alone does not verify the Rust implementation.
