# Fork repair model

`model.qnt` models the fork repair procedure of DESIGN.md "Fork repair" ([FRK-1] to [FRK-8]), its limit after compaction ([CMP-21]), and the deletion marker ([LOG-13]). `checks.toml` lists the configs and mutants. `test.qnt` holds the scenario tests.

## Abstractions

- One space, three devices, all active from the genesis record. Grants, epochs, keys and signatures are outside this model (specs/spacelog).
- A log entry is a change or a snapshot with a unique `cid`, which stands for its entry hash. Prefix equality of cids stands for digest equality. A stub keeps its cid ([CMP-1]).
- A change carries a content. A re-sent change keeps its cid and its content. The app state is a set of contents (the merge contract).
- The relay forks once: branch 1 starts as a copy of branch 0, and the relay shows each device one branch. A device that the relay moves to the other branch finds the conflict at its next fetch ([FRK-1]).
- The export file is the verified log of the source at the export ([FRK-3]). The deletion empties the relay and sets the marker ([FRK-4]). The import puts the export file on the relay as the only branch and removes the marker ([FRK-5]). The import session, its chunks and its checks are relay rules (PROTOCOL.md 10.13).
- Enrollment again is one action: a new verified log equal to the relay log, an empty engine outbox, and the app outbox rows enqueued again ([FRK-6], [DLV-2]). The checkpoint is specs/enrollment.
- A snapshot holds the app state of its author. Acceptance is outside this model (specs/compaction): a device can replace its changes before the last snapshot with stubs after its app applied its log ([CMP-13]).
- Each app DB transaction and each engine transaction is one atomic action. Free interleaving models a crash between any two of them.

## Coverage

| DESIGN.md rule | Model |
| --- | --- |
| The engine stops at a conflict [FRK-1] | `fetch` (`stopped: fork`), witness `wFork` |
| The user selects the source, the source exports [FRK-2] [FRK-3] | `exportLog` |
| Deletion and its marker [FRK-4] [LOG-13] | `delete`, `fetch` (`stopped: deleted`), mutant `uploadAfterDelete`, test `deletedThenImportedTest` |
| Import removes the marker [FRK-5] | `importLog`, invariant `noResurrect` |
| Enrollment again with a new state file [FRK-6] | `reenroll` |
| The comparison of the old state file with the new log [FRK-7] (finding F1) | `recover`, `dropOld`, mutant `skipOld` |
| Outbox rows with the old change ID, then ResetRequired [FRK-8] | `recover`, `reset`, mutants `freshIds`, `noReset`, tests `repairTest`, `recoverTwiceTest`, `resetNeededTest` |
| Limit after compaction [CMP-21] | `compact`, limit `snapshots`/`noLostChange`, test `forkrepairTestSnap::stubLimitTest` |
| A device on the source branch repairs the imported log [LOG-10] | `fetch`, witness `wRepairAfterImport` |

## Invariants

| Name | Property |
| --- | --- |
| `noLostChange` | Each content that an app wrote is in a relay branch, in full in a device log or a snapshot, in an outbox, or in the old state file of its author. |
| `noDoubleApply` | No device applies a content twice since its last reset. |
| `noResurrect` | After a deletion, only the import of the export file makes the space exist, and the relay log extends the export. |

`converged` is a scenario property: every device runs on the imported log, has applied it, has empty outboxes and the same app state. `repairTest` reaches it.

## Findings

| ID | Finding | Change |
| --- | --- | --- |
| F1 | The app can delete the old state file before the comparison, and so lose each own change that only the old file holds. The sampled check found it in the `tiny` and `honest` configs. | [FRK-7]: the app keeps the old state file until its outbox holds each change of the comparison. `dropOld` requires the recovery. |

## Model bounds

- Sampled: 20,000 traces of up to 50 steps for each of `honest`, `snapshots` and `tiny` (5,000 in CI).
- Apalache: `tiny` (2 devices, 3 IDs) to 6 steps.
- TLC: every reachable state of `tiny`. The 4 mutants fail there.

## Known limits

| Limit | Config |
| --- | --- |
| [CMP-21] An own change that a snapshot on the losing branch covers is only a stub in the old state file. The comparison cannot give it back. | `snapshots`, invariant `noLostChange` |

## Not covered

- The device keys after enrollment again: the old device IDs stay active in the log, and the user removes them (13.2). specs/spacelog covers removal.
- The order of the import transaction and the rename ([STO-6]). Rust: crates/relay import tests.
- The head and expiry checks of the deletion statement. Rust: crates/relay delete tests.
- Forks with more than two branches, or a second fork during the repair.
