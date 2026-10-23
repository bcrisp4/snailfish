# Quint specs

These Quint models check parts of `DESIGN.md`. Each model is executable. A check is a sampled simulation with `quint run`. A pass is evidence, not a proof.

## Files

| File | Content |
| --- | --- |
| `delivery.qnt` | Model of the delivery rules, repair sessions and the restore hold. Also the configs. |
| `delivery_test.qnt` | Scenario tests (`quint test`). |
| `delivery_mutants.qnt` | One config for each deliberate design violation, and two baseline configs. |
| `check.sh` | Runs every check. Exits 0 only if every check passes. |

## Run the checks

1. Install Quint 0.33 or later: `brew install quint`.
2. Run `specs/check.sh`. It takes about 4 minutes on an M5 Max.
3. To change the effort, set `SAMPLES` (default 20000) and `STEPS` (default 50).
4. To repeat a run, set `SEED`.

## Delivery model

### Coverage

| DESIGN.md rule | Model |
| --- | --- |
| Edit and outbox row in one transaction | `edit`, mutant `editSplitTxn` |
| `enqueue_many` after each commit and at startup, no effect if known, a known `change_id` with other bytes in `refused` | `enqueue`, mutant `appDropsRowOnEnqueue` |
| Batches in `enqueue_many` and `changes_after` | One action for each row. A batch in one transaction allows fewer interleavings, so a safe result for single rows also holds for batches. |
| Retry sends the stored envelope. The relay returns the original position. | `push` with a lost response, mutant `relayNoDedupe` |
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

### Invariants

| Name | Property |
| --- | --- |
| `noDoubleApply` | Each device applies each change once. |
| `noLostChange` | A change that `enqueue` stored, and that no app reverted, stays where sync can deliver it. |
| `noLostChangeWeak` | `noLostChange` for changes that no engine state loss touched. |
| `appliedHeld` | A change in an app state is never only in that app state. |
| `caughtUpState` | A caught-up device holds the relay changes and its own pending edits, and nothing else. |
| `refusedNotStored` | No log holds a change that an app reverted after a refusal. |
| `noStuckDevice` | A device that fetched to the relay head, with no hold, can pull or reset. |
| `noSilentLoss` | No hold ends without a warning while the release loses a change. |
| `noFork` | Running devices never hold conflicting verified logs. |

### Results

`check.sh` passes. The sampled checks found no violation of the invariants that must hold, in any config. Each mutant fails at least one invariant. Each witness is reached in at least one trace.

The checks also confirm three known limits. Each one fails on purpose:

1. A silent relay rollback, or an early hold release, can fork the log. The devices then stop with `fork` (T7 limit).
2. An engine state loss and a second fault can lose a change. Each fault destroys one copy.
3. A silent rollback, or an early hold release, can let a repair session return a change that an app already reverted after a refusal (F1). Configs: `faultyRelay`, `earlyReleaseOnly`, `silentOnly`.

### Findings fixed in DESIGN.md

| ID | Fix | Check |
| --- | --- | --- |
| F1 | No design change. The restore hold prevents it after a restore, if the release comes after every device reports. The text of T7 names the case. A silent rollback or an earlier release remains a limit. | `refusedNotStored`, configs `faultyRelay`, `earlyReleaseOnly`, `silentOnly` |
| F2 | `changes_after` raises `ResetRequired` if the applied position is after the end of a log that the engine fetched to the relay head, with no hold. After two faults, the reset deletes the changes that only the app DB holds. DESIGN.md states this. | `resetRequired`, `noStuckDevice`, mutant `noAheadReset`, test `aheadOfLogResetTest` |
| F3 | A device with a new engine state file reports it until the hold ends, also after a fetch. The user page marks it "not repaired" and warns before a release. The warning does not prevent the loss. It makes the loss visible. | `noSilentLoss`, mutants `releaseIgnoresFresh` and `freshClearsOnFetch`, test `notRepairedMarkTest` |
| F4 | `enqueue_many` does not check the size limit. The relay checks the known `change_id` first. | `enqueue`, `refusedNotStored`, mutant `enqueueChecksSize` |
| F5 | The Delivery row says "if no second fault occurs". | `noLostChange` limit 2 |

Mutant `freshClearsOnFetch` needs a restore, an engine state loss and a fetch, in that order, during one hold. Random sampling seldom finds this path. `check.sh` therefore also runs the scenario tests with the `BUG` of each mutant, and `notRepairedMarkTest` catches this one.

### Not covered

- Security records, epochs, the base rule for security records, enrollment and removal.
- Log compaction: snapshots, stubs, accept records and `is_covered`.
- Fork repair (export, import, enroll again).
- A malicious relay. The relay in this model is honest, but it can lose data.
- The bytes of a change, so the "same `change_id` with different bytes" refusal in `enqueue_many`.
- Security records during a restore hold. The relay accepts them, but the model has no security records.
- The snapshot acceptance rules from review D. They need a compaction model.
- Liveness. The model checks safety only.
- Quint configs bind the `BUG` and `FAULTS` consts as strings. A sum type is not possible, because a config module that imports the spec cannot use a constructor of that spec in its own import (Quint error QNT099).

### When to update

If a delivery rule in `DESIGN.md` changes, change `delivery.qnt` first and run `check.sh`. Then change the design text.
