# Compaction model

`model.qnt` models log compaction: snapshots, accept records, the frontier, the usable snapshot, and stubs on the relay and on each device (DESIGN.md "Log compaction", [LOG-11], [DLV-12]). `checks.toml` lists the configs and mutants. `test.qnt` holds the scenario tests.

## Abstractions

- One space. Devices 1 and 2 are active from the genesis record. Devices 3 and 4 join through grants: a new device, or a full recovery with the recovery key (S5). A grant seals epoch 1 and the needed epochs ([CMP-20]), because each engine opens the key of epoch 1 as its app key.
- `canon` is the log in full (ghost state). The relay log and each device log are prefixes of it with their own stub marks. The model has no fork: a rollback puts the space on hold, and only a repair to the full log ends the hold. specs/delivery and specs/epochs model forks and holds.
- A change is an int id. The app state is a set of ids (merge contract). A snapshot holds the app state of its author.
- The applied position is the position of the last applied change, or the state position of an imported snapshot ([CMP-10]).
- A stub keeps the kind and the change id of its record. Device and relay code reads no other field of a stub ([CMP-1]).
- A fetch reads to the relay head in one action (see "Fetch and stubs").
- A repair is one action: start, chunks and finish. specs/delivery models the session rules.
- Each entry caches the active devices, the epoch and the usable snapshot of the log that ends at it, because the full computation is slow in the simulator. The usable snapshot is a function of the log content, and a stub never changes it. The invariants compute the usable snapshot in full (`usableFull`), so a BUG value that changes the cache cannot hide from them.

## Coverage

| DESIGN.md rule | Model |
| --- | --- |
| Stub fields [CMP-1] | `Entry.stub`, `stubValid`, `isCovered` read only the kind and the change id of a stub |
| State position before the record [CMP-3] | `valid`, `writeSnapshot` (statePos is the applied position) |
| Author active at the snapshot position [CMP-4] | `valid`, mutant `validNeedsActiveNow`, test `removalTest` |
| Accept after the app applies past the state position, and only if it decrypts [CMP-5] | `accept`, mutants `acceptUnreadable`, `acceptEarly`, test `unreadableTest` |
| Accepted at the first position with an accept from each active device [CMP-6] | `accepted`, mutants `compactBeforeAccept`, `acceptCountsNow`, tests `blockedTest`, `newDeviceTest` |
| A removal ends a block [CMP-7] [CMP-9] | `remove`, test `removalTest`, witness `wCompactAfterRemoval` |
| Frontier and usable snapshot [CMP-8] [CMP-10] | `usableFull`, test `removalTest` |
| What the usable snapshot covers [CMP-11] (finding C1) | `covers` |
| Relay stubs after acceptance [CMP-12] | `relayCompact` |
| Engine stubs after its own accept [CMP-13] (finding C5) | `deviceCompact` |
| `is_covered` [CMP-14] | `isCovered`, `reset`, mutant `resetKeepsCovered`, test `offlineResetTest` |
| Stub check [CMP-15] (finding C2) | `stubValid`, `fetch`, invariants `stubsCovered`, `noMissingRecords` |
| ResetRequired and the import [CMP-16] [DLV-12] (findings C3, C4) | `resetRequired`, `reset`, mutants `resetOnStubOnly` (test `compactionTestLate::resetBeforeFrontierTest`), `resetDropsOutbox`, tests `newDeviceTest`, `snapshotStubNoResetTest` |
| Repair with stubs [CMP-17] [LOG-11] | `rollback`, `repair`, mutant `repairNoCoverCheck`, tests `repairStubsTest`, `badRepairTest` |
| Snapshot reserve [CMP-18] | `writeSnapshot`, `accept`, mutant `snapshotNoReserve`, test `quotaTest` |
| Stubs outside the quota [CMP-19] | `used`, mutant `stubsCount`, test `quotaTest` |
| Security and accept records stay in full, grants seal the needed keys [CMP-20] | `covers`, `neededWith`, `sealFor`, mutants `stubSecurity`, `stubAccept`, `sealCurrentOnly`, tests `sealNeededTest`, `sealDropsOldTest` |
| Snapshot only with an empty outbox | `writeSnapshot`, mutant `snapshotWithOutbox` |

## Invariants

| Name | Property |
| --- | --- |
| `appConsistent` | The app state of each device is the changes up to its applied position and its outbox rows. |
| `noDoubleApply` | No device applies a change twice. |
| `outboxPending` | No outbox row names a change at or before the applied position. |
| `stubsCovered` | Each stub on the relay and on each device passes the stub check. |
| `noMissingRecords` | No engine stops with `missing records`. |
| `securityFull` | No security record or accept record is a stub. |
| `usableReadable` | The usable snapshot decrypts. |
| `readsNeeded` | Each active device holds the key of each record that the usable snapshot does not cover, and no device pulls a change that it cannot decrypt. |
| `noNeedlessReset` | A device with no lost state never gets ResetRequired. |
| `noLostChange` | A change is in the log or in an outbox, unless an app DB restore or a fire destroyed it before the push. |
| `withinQuota` | The relay stores within the quota and the reserve. |
| `noStuckDevice` | A device never waits on a change stub that it cannot reset past. |

## Findings

| ID | Finding | Change |
| --- | --- | --- |
| C1 | An older snapshot at the frontier state position stays in full for ever, with its epoch key. | [CMP-11] also covers each other snapshot at the frontier state position with a lower log position. |
| C2 | A device cannot check a snapshot stub against the frontier: the stub has no state position. | [CMP-15]: a snapshot stub is valid if a usable snapshot exists at another position. |
| C3 | A snapshot stub after the applied position forces a reset that no device needs. | Covered by C4. |
| C4 | A new device pulls changes before the frontier that it holds no key for, because no stub follows yet. Repro: mutant `resetOnStubOnly`, `make verify MODEL=compaction`. | [DLV-12], [CMP-16]: ResetRequired if the applied position is before the frontier. |
| C5 | The applied-position condition of [CMP-13] follows from the own accept. | None. Mutant dropped as equivalent. |

## Fetch and stubs

A fetch page can hold stubs before the snapshot record that covers them, for example the first page of a new device. The model fetches to the head in one action, so the engine must check stubs only after the fetch reaches the relay head. Rust: the engine fetch test with a page limit below the stub count.

## Results

`make verify MODEL=compaction` passes in about 70 seconds: 8 configs, 20,000 traces of up to 50 steps each (sampled, not a proof). Two scenario modules: `compactionTest` and `compactionTestLate`. Each mutant fails its invariant or its named test. Each witness is reached.

## Not covered

- Forks and fork repair after compaction ([CMP-21], FRK rules): M9.
- The byte-level stub hash, the snapshot size limit and the state digest: Rust and the vectors.
- The app functions `export_state`, `import_state` and `can_import` ([CMP-2]): `can_import` is the readable flag.
- Restore holds with security records during the hold: specs/epochs.
- More than one repair session, chunks and expiry: specs/delivery.
- The user page marker ([CMP-7]): presentation.
- A stolen device that fills the snapshot reserve before the block (decision D4): a known availability limit, not modelled.
