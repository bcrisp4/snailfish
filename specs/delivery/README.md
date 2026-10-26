# Delivery model

`model.qnt` models the delivery rules, repair sessions and the restore hold (DESIGN.md "App integration", "Space log" and T7). `checks.toml` lists the configs, known limits and mutants. `test.qnt` holds the scenario tests.

## Coverage

| DESIGN.md rule | Model |
| --- | --- |
| Edit and outbox row in one transaction | `edit`, mutant `editSplitTxn` |
| `enqueue_many` after each commit and at startup, no effect if known [DLV-5] | `enqueue`, mutant `appDropsRowOnEnqueue`. A `change_id` with other bytes in `refused` is not encoded (see Not covered). |
| Batches in `enqueue_many` and `changes_after` | One action for each row. A batch in one transaction allows fewer interleavings, so a safe result for single rows also holds for batches. |
| Retry sends the stored envelope. The relay returns the original position. [DLV-7] | `push` with a lost response, mutant `relayNoDedupe` |
| Same `change_id` and record hash: `Known`. Same `change_id`, other record hash: `Conflict`. Both come before the size and base checks. [WIR-6] | `verdict`, `push`, mutant `relayConflictAppends`, test `pushConflictTest` |
| On `Conflict` the engine treats the change as stored, and keeps the envelope until the verified log holds the `change_id`. [DLV-6] [DLV-8] | `push`, `applyFetch`, mutant `conflictRefuses`, test `conflictTreatedAsStoredTest` |
| Engine keeps an own envelope until the verified log holds it | `applyFetch`, mutant `engineDropsOnAccept` |
| Known `change_id` check before other refusals | `verdict`, mutant `sizeBeforeDedupe` |
| Permanent refusal: `degraded`, the app reverts or splits | `push`, `resolveRefused` |
| Pull in one transaction, own edits not applied again | `pull`, mutant `pullSplitTxn` |
| App DB restore | `backupApp`, `restoreApp` |
| `ResetRequired`: delete synced data, apply outbox rows again | `handleReset`, mutant `resetDropsOutbox` |
| Engine state loss with the keys kept (T14) | `loseEngine` |
| Signed base refused if not in the relay log | `verdict` (`BadBase`) |
| Repair session after a rollback | `repair`, mutant `noRepair` |
| Restore hold. Only the user or the relay operator ends it. | `restoreRelay`, `reportStatus`, `releaseHold` (after every device reports), `releaseHoldEarly` (before), mutant `noHold` |
| Fork detection stops sync | `fetchConflict`, mutant `adoptFork` |

## Invariants

| Name | Property |
| --- | --- |
| `noDoubleApply` | Each device applies each change once. A relay that appends a known `change_id` with another record hash breaks it. |
| `noLostChange` | A change that `enqueue` stored, and that no app reverted, stays where sync can deliver it. |
| `noLostChangeWeak` | `noLostChange` for changes that no engine state loss touched. |
| `appliedHeld` | A change in an app state is never only in that app state. |
| `caughtUpState` | A caught-up device holds the relay changes and its own pending edits, and nothing else. |
| `refusedNotStored` | No log holds a change that an app reverted after a refusal. An engine that refuses on `Conflict` breaks it. |
| `noStuckDevice` | A device that fetched to the relay head, with no hold, can pull or reset. |
| `noSilentLoss` | No hold ends without a warning while the release loses a change. |
| `noFork` | Running devices never hold conflicting verified logs. |

## Results

`make verify MODEL=delivery` passes in about 1 minute. The sampled checks found no violation of the invariants that must hold, in any config. Each mutant fails at least one invariant. Each witness is reached in at least one trace.

The checks also confirm three known limits. Each one fails on purpose:

1. A silent relay rollback, or an early hold release, can fork the log. The devices then stop with `fork` (T7 limit).
2. An engine state loss and a second fault can lose a change. Each fault destroys one copy.
3. A silent rollback, or an early hold release, can let a repair session return a change that an app already reverted after a refusal (F1). Configs: `faultyRelay`, `earlyReleaseOnly`, `silentOnly`.

### Exhaustive results (TLC)

`make verify-deep MODEL=delivery` runs TLC on four finite configurations. Each result covers every reachable state, not larger configurations.

| Configuration | Scope | Mutant checks |
| --- | --- | --- |
| `tinyCrash` | Two devices and two changes, without restore faults. | Split transactions, duplicate append, and an early outbox deletion. |
| `tinyAppRestore` | Two devices and two changes, with one app restore. | No additional mutants. |
| `tinyRecovery` | One device and one change, with at most two relay-restore or engine-loss faults. | Missing repair, missing reset, and a hold release without a required warning. |
| `tinyConflict` | Two devices and two changes, with one engine state loss. The engine encrypts a change again, so the relay answers `Conflict`. | A relay that appends after `Conflict`, and an engine that refuses on `Conflict`. |

The `tinyRecovery` baseline visits 1,437 distinct states. It includes repair, status reports, and warned hold release.

The `tinyConflict` baseline visits 138,724 distinct states and takes about 9 seconds. Mutant `relayConflictAppends` fails after 4,649 states and `conflictRefuses` after 1,147 states. `tinyCrash` visits 10,716 states and `tinyAppRestore` visits 240,712.

Its weak loss property excludes changes that an engine state loss exposes. It does not promise recovery after both surviving copies disappear.

## Record hashes

A log entry is a record hash: an int that holds the change ID and a counter `gen` of the engine state losses of the device (`entry = id + MAX_IDS * gen`). `enqueue` signs a new record with the current `gen`, so an engine that lost its state and enqueues the change again sends another record hash with the same `change_id`. The relay compares the `change_id` and then the record hash. The ID of an entry is `rid(entry)`.

## Findings fixed in DESIGN.md

| ID | Fix | Check |
| --- | --- | --- |
| F1 | No design change. The restore hold prevents it after a restore, if the release comes after every device reports. The text of T7 names the case. A silent rollback or an earlier release remains a limit. | `refusedNotStored`, configs `faultyRelay`, `earlyReleaseOnly`, `silentOnly` |
| F2 | `changes_after` raises `ResetRequired` if the applied position is after the end of a log that the engine fetched to the relay head, with no hold. After two faults, the reset deletes the changes that only the app DB holds. DESIGN.md states this. | `resetRequired`, `noStuckDevice`, mutant `noAheadReset`, test `aheadOfLogResetTest` |
| F3 | A device with a new engine state file reports it until the hold ends, also after a fetch. The user page marks it "not repaired" and warns before a release. The warning does not prevent the loss. It makes the loss visible. | `noSilentLoss`, mutants `releaseIgnoresFresh` and `freshClearsOnFetch`, test `notRepairedMarkTest` |
| F4 | `enqueue_many` does not check the size limit. The relay checks the known `change_id` first. | `enqueue`, `refusedNotStored`, mutant `enqueueChecksSize` |
| F5 | The Delivery row says "if no second fault occurs". | `noLostChange` limit 2 |

Mutant `freshClearsOnFetch` needs a restore, an engine state loss and a fetch, in that order, during one hold. Random sampling seldom finds this path. `checks.toml` sets `caught_by = "tests"` for it, so `verify.py` runs the scenario tests with its `BUG`, and `notRepairedMarkTest` catches this one.

## Not covered

- Security records, epochs, the base rule for security records, enrollment and removal.
- Log compaction: snapshots, stubs, accept records and `is_covered`.
- Fork repair (export, import, enroll again).
- A malicious relay. The relay in this model is honest, but it can lose data.
- The bytes of a change. The content of a `change_id` is fixed, so the model does not encode the "same `change_id` with different bytes" refusal in `enqueue_many` [DLV-5], and it does not encode a `Conflict` whose record holds other content. In the design the engine marks such a change as refused, reports `degraded` and the app reverts or splits it, as for a size refusal ([DLV-6]). The `Conflict` case with the same content is encoded. Rust tests `enqueue_dedupes_and_refuses_other_bytes` and `conflict_with_other_bytes_is_refused` check the two cases with other content.
- The position in the `Known` and `Conflict` replies, and the fetch of the record at that position. The model treats the fetch as always showing the same content.
- Security records during a restore hold. The relay accepts them, but the model has no security records.
- The snapshot acceptance rules from review D. They need a compaction model.
- Liveness. The model checks safety only.
- The configs bind the `BUG` and `FAULTS` consts as strings. A sum type is not possible, because a config module that imports the spec cannot use a constructor of that spec in its own import (Quint error QNT099).

## Rust conformance (M2)

Each row names the model scenario and the Rust test that runs it through the public API (specs/conformance.md). The results above do not verify these tests, and these tests do not verify other interleavings.

| Scenario in `test.qnt` | Rules | Rust test |
| --- | --- | --- |
| `retryAfterLostResponseTest` | [DLV-7] [DLV-8] [WIR-6] | `crates/engine/src/tests.rs::retry_after_lost_response`, `crates/relay/tests/core.rs::retry_after_lost_response_is_known_at_the_same_position` |
| `pushConflictTest`, `conflictTreatedAsStoredTest` | [WIR-6] [DLV-6] [DLV-8] | `crates/engine/src/tests.rs::conflict_with_same_bytes_is_stored`, `crates/relay/tests/core.rs::same_change_id_other_hash_is_conflict_and_log_is_unchanged` |
| `knownBeforeSizeTest` | [WIR-6] [DLV-5] [DLV-7] | `crates/relay/tests/core.rs::known_is_answered_before_the_size_limit`, and the lower limit in `conflict_with_same_bytes_is_stored` |
| `enqueueAfterLossTest` | [DLV-5] [DLV-7] (F4) | `crates/engine/src/tests.rs::enqueue_after_engine_loss_is_not_refused_for_size` |
| `refusedAtPushTest` | [DLV-9] | `crates/engine/src/tests.rs::permanent_refusal_is_degraded_and_reported_again` |
| `badBaseTest` | [LOG-6] | `crates/relay/tests/core.rs::base_not_in_log_is_bad_base_and_stores_nothing` |
| `offlineEditsConvergeTest` | [DLV-2] [DLV-10] [DLV-11] [MRG-1] | `crates/engine/src/tests.rs::offline_edits_converge`, `demo/tests/test_acceptance.py::test_two_devices_in_two_orders_converge` |
| `restoredOwnEditReturnsTest` | [DLV-8] [DLV-11] | `crates/engine/src/tests.rs::restored_own_edit_returns`, `demo/tests/test_crash.py::test_app_database_restore_gives_back_own_edit` |
| `restoredPositionReplaysTest` | [DLV-10] [DLV-11] | `crates/engine/src/tests.rs::restored_position_replays` |
| `aheadOfLogResetTest` (the reset condition only) | [DLV-12] | `crates/engine/src/tests.rs::reset_required_on_wrong_digest_or_ahead_of_log` |
| Mutant `engineDropsOnAccept` | [DLV-8] | `crates/engine/src/tests.rs::stored_answer_keeps_the_envelope_until_a_fetch` |
| Mutants `editSplitTxn`, `pullSplitTxn`, `appDropsRowOnEnqueue` | [DLV-2] [DLV-11] | `demo/tests/test_crash.py`: a process crash at each crash point of push and pull, and an app database restore. `make test-powerloss` adds a VM power loss. |

Each Rust test above fails with the corresponding fault in the Rust or Python code: `conflictRefuses`, `engineDropsOnAccept`, a conflict with other bytes treated as stored, `pullSplitTxn` and `appDropsRowOnEnqueue` were checked by hand. `make rust-mutants-diff` checks the Rust code by mutation.

M2 has no restore hold, repair session, fork repair or snapshot. Scenarios `relayRestoreRepairTest`, `forkStopsTest`, `notRepairedMarkTest`, `resetRequiredTest` and `refusedSplitTest` have no Rust test yet. A shorter relay log stops the M2 engine with `stopped: fork` (`shorter_relay_log_stops_and_proxy_page_pauses`), where M3 repairs it.

## When to update

If a delivery rule in `DESIGN.md` changes, change `model.qnt` first and run `make verify MODEL=delivery`. Then change the design text.
