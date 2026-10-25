# Space log model

`model.qnt` models the security state of the space log: genesis, grants, epoch records (removal and key rotation), the signed base rule, the relay that orders appends, and client verification of the log. It covers DESIGN.md "Space log", the record table, "Enrollment" steps 8 and 9, threats T7 and T8, and closed issues C34, C35, C47 and C48. `checks.toml` lists the configs, limits and mutants. `test.qnt` holds the scenario tests.

## Abstractions

- A key is an opaque int. A device key is the device ID. The recovery key is `RK` (0).
- A signature is a record in the ghost set `env.signed`. Only the author adds a record to it. A malicious relay can offer a record that is not in the set, and the verifier then finds no signature.
- A digest is the list of record IDs, folded to an int. IDs are unique, so equal digests mean equal prefixes.
- The shared `protocol` crate is the pure function `check`. The relay and each device call it. A malicious relay does not.
- The relay holds up to two branches. An honest relay uses branch 0. A malicious relay can copy a prefix to branch 1 and serve any branch to any device.
- A change record carries only its author and its epoch number.

The model is plain Quint, not Choreo. The relay is one shared log that every device reads, not a message exchange between devices. `verify.py` also generates one config module per file, and Choreo adds nothing to that.

## Coverage

| Rule | Model element |
| --- | --- |
| [LOG-1] [LOG-2] [LOG-7] [LOG-8] [LOG-9] | `check`, the shared verifier of the relay and the devices |
| [LOG-5] | `dig`, prefix digests in checkpoints |
| [LOG-6] | `bpos` and `bdig` of each record, `baseOk` |
| [LOG-2] [LOG-8] | `authorOk`, `stateOk` |
| [LOG-9] | `relayVerdict`, `relayAppend`, `relayRefuse` |
| [ENR-8] [ENR-9] (partly) | `sendCheckpoint`, `fetchOne` with the checkpoint check |

`specs/coverage.toml` lists the LOG rules that the model does not encode (hashes, repair sessions, deletion and the restore hold).

## Configs

| Config | Fault class |
| --- | --- |
| `honest` | An honest relay. |
| `forkRelay` | The relay serves two valid branches. |
| `forgeRelay` | The relay offers records with no signature. |
| `reorderRelay` | The relay appends records in any order, also when `check` refuses them. |
| `thief` | A device that the attacker controls ignores its own removal. |
| `honest4` | An honest relay with 4 devices. The baseline of the base-rule and key mutants. |

## Invariants

| Name | Property |
| --- | --- |
| `authorActive` | A record from a device after its removal is never in a verified log. |
| `noKeyToRemoved` | No record in a verified log seals a key to a removed device. |
| `removedKeyIsolation` | The key of an epoch record reaches no removed device through any signed record, also a refused one. |
| `baseRule` | A security record in a verified log has its base at or after the last security record. |
| `activeSetDeterministic` | The state of a device is a function of its verified log. |
| `grantAuthorized` | Each grant in a verified log is signed by an active device or the recovery key. |
| `forkStops` | A device that sees a conflicting record stops. |
| `baseInOwnLog` | The base of each record in a verified log is in that log. |
| `writeEpochCurrent` | An honest device writes a change with the epoch of its verified log. |
| `relayLogValid` | The log of an honest relay verifies from the genesis record. |
| `logChangeEpoch` | Each change in a verified log has the epoch of the state before it. |
| `noFork` | Running honest devices never hold incomparable verified logs. |
| `noStaleChangeStored` | The relay never stores a change with an epoch below a stored epoch record. |

## Results

`verify.py full spacelog` passes in 19 minutes on an M5 Max (sampled, 20 000 traces of 50 steps, not a proof). It covers every invariant in each config, 2 known limits, 14 caught mutants and 18 witnesses. The 4-device baseline `honest4` takes about 16 of the 19 minutes. `verify.py deep spacelog` passes: `authorActive`, `noKeyToRemoved`, `baseRule` and `activeSetDeterministic` on `honest`, for every trace of up to 8 steps (bounded exhaustive). 8 steps reach a genesis, one grant, one checkpoint and a few fetches, so the deep tier does not reach the S1 paths.

Known limits. Each one must fail:

1. `forkRelay noFork`. T7: a malicious relay serves two valid branches. Neither device sees a conflict until it fetches a record whose base is not in its log.
2. `forkRelay noStaleChangeStored`. T8: a relay that withholds an epoch record from a stayed device can store that device's change under the old epoch.

## Findings

S1 (fixed). Four mutants (`noBaseRule`, `relayNoBaseRule`, `grantFromRemoved`, `resignReusesKey`) at first changed no verdict in any run. The cause was the check set, not the design. With 2 devices, each pair of security records fails another check before the base rule: a second removal of the same device, or a removal whose list of devices that stay is out of date after a grant. A removed honest device never signs, so `grantFromRemoved` needs a thief. Fix:

- The baseline `honest4` has 4 devices. Two grants for two new devices on one base are then both valid except for the base rule. Sampling catches `noBaseRule` and `relayNoBaseRule` in seconds.
- `thiefGrantTest` (thief config) catches `grantFromRemoved`. `resignTest` (4 devices) catches `resignReusesKey`. Each test passes on the design and fails under its mutant, and the other tests still pass.

Lesson: a mutant baseline must be large enough for the bug to change a verdict.

## Not covered

- Recovery records, protocol levels, the device record and the level record.
- Repair sessions, deletion and the restore hold (the delivery model has those).
- Log compaction: snapshots, stubs and accept records.
- Key secrecy as such. The model tracks which keys each record seals to which devices.
- Hashes and the exact digest chain.
- Liveness.
