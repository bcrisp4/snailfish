# Protocol level model

`model.qnt` models the protocol levels of one space: the level of each device, the space write level, and the write level of each new record (DESIGN.md "Versioning", [VER-6] to [VER-10]). `checks.toml` lists the configs and mutants. `test.qnt` holds the scenario tests.

## Abstractions

- A level is an int from 1 to `TOP`. The set of record versions of each level is a table in `crates/protocol`, not part of the model.
- Each record carries `wl`, the write level that its author wrote it at.
- A device engine supports the levels up to `max`. `update` raises it. `downgrade` lowers it: a reinstall of an older engine that keeps its keys.
- The relay is honest and runs the shared check `valid` against the state after the record before it ([LOG-8]). A record that a device signed on an old view gets the verdict of the current relay state. `specs/spacelog` checks a malicious relay, bases and signatures.
- A removal is an epoch record with one removed device. Keys and epochs are out of scope.

## Coverage

| Rule | Model element | Scenario |
| --- | --- | --- |
| [VER-6] (part) | `max`, `TOP` | all |
| [VER-7] | `grant` holds the level of the new engine. `announce` states a new level. A device record must raise the level of its device. | `raiseAfterUpdatesTest`, `downgradeRefusedTest` |
| [VER-8] | `raise` and the `LevelRec` check: every active device at or above the new level | `raiseAfterUpdatesTest`, `removalUnblocksRaiseTest`, `grantRaceTest` |
| [VER-9] (part) | `wl` of each record, and the check `wl >= level` | `lowLevelRefusedTest` |
| [VER-10] (part) | A removal ends a block of a raise | `removalThenRaiseTest` |

## Invariants

| Name | Property | Mutants |
| --- | --- | --- |
| `levelSupported` | Each active device of the relay log states a level at or above the write level. | `grantBelowLevel`, `levelIgnoresDevices`, `deviceLevelDown` |
| `recordsAtLevel` | Each record after the genesis record is written at the write level of the log before it, or above. | `lowLevelAccepted` |

The reference function `refLevel` reads the relay log only. It does not call `valid`.

## Results

| Tier | Scope |
| --- | --- |
| Fast | Scenario tests and 2,000 sampled traces of up to 30 steps on `bounded`. |
| Full | 20,000 sampled traces per check, up to 50 steps, on `bounded` (3 devices, `TOP` 2, 7 records) and `tiny`. Four mutants and six witnesses. |
| Apalache | Both invariants on `tiny` up to 8 steps. |
| TLC | Both invariants on every reachable state of `tiny` (2 devices, 5 records). Three mutants must produce a counterexample. |

`grantBelowLevel` needs a third device, so TLC on `tiny` does not list it. The sampled tier catches it on `bounded`.

## Not covered

- The set of record versions of each level. `crates/protocol` holds the table, and its tests use a synthetic level 2.
- A repair upload of a lost record at its old position ([VER-9] exception). `specs/epochs` and `specs/delivery` cover repair.
- The user page list of the devices that block a raise ([VER-10]). It is presentation of the device levels.
- [VER-11] (relay too old). It is an engine check of `GET /v1/info`.
- A malicious relay, signatures and bases (`specs/spacelog`).
- Liveness.

## Commands

1. Run `make verify-fast MODEL=levels` after each model edit.
2. Run `make verify MODEL=levels` for the full sampled checks.
3. Run `make verify-deep MODEL=levels` for Apalache and TLC.
