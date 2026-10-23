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
| `enqueue_many` after each commit and at startup, no effect if known, a change over the limit in `refused` | `enqueue`, mutant `appDropsRowOnEnqueue` |
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
| `refusedNotStored` | No device can get a change that the relay refused for ever. |
| `noFork` | Running devices never hold conflicting verified logs. |

### Results

`check.sh` passes. The sampled checks found no violation of the invariants that must hold, in any config. Each mutant fails at least one invariant. Each witness is reached in at least one trace.

The checks also confirm four known limits. Each one fails on purpose:

1. A silent relay rollback, or an early hold release, can fork the log. The devices then stop with `fork` (T7 limit).
2. An engine state loss and a second fault can lose a change. Each fault destroys one copy.
3. A silent rollback, or an early hold release, can make the relay refuse a change for ever that another device still holds (finding F1).
4. After an engine state loss, `enqueue_many` can refuse a change for ever that the relay already stores (finding F4).

### Findings for DESIGN.md

F1. Permanent refusal after a silent rollback. The relay stores change C. Then the operator lowers the size limit. A storage fault rolls the relay back, so the relay no longer knows C. The author sends C again, and the relay refuses it for ever. The author reverts C. Another device holds C in its verified log and repairs the log, so the other devices apply C. The devices diverge without notice. A restore hold prevents this case, if the release comes after every device reports. A release before that allows it. Trace: `quint run specs/delivery.qnt --main faultyRelay --invariant refusedNotStored`.

F2. Applied position after the end of the log. An engine state loss and a relay restore leave the app applied position after the end of a fully fetched log. No rule applies: `changes_after` has no change to return, and `ResetRequired` needs a different digest at the applied position. The app state holds a lost change until the log grows. Witness: `wAheadOfLog`.

F3. Restore hold after an engine state loss. A device with a new engine state file reports a verified tip of 0. The user page then shows that device as reported. Its app DB can hold changes that only the lost engine file and the old relay held. If the user releases the hold, those changes are lost. The user page does not mark this case. This is the two-fault case of limit 2.

F4. `enqueue_many` refuses a stored change after an engine state loss. The relay stores change C, and then the operator lowers the size limit. The engine state file of the author is lost. The app calls `enqueue_many` for its outbox row C again. The new engine does not know C, so it puts C in the `refused` list. The app then reverts or splits C, but the other devices apply C. The cause is the review D rule that `enqueue_many` checks the size limit locally. The relay checks the known `change_id` first, but the engine does not ask the relay. Trace: `quint run specs/delivery.qnt --main engineLoss --invariant refusedNotStored`.

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
