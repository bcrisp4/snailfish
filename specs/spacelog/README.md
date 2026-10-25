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
| `compromisedHonest` | A compromised key signs bounded record templates. The honest relay must refuse invalid records. |
| `compromisedReorder` | A malicious relay stores those signed records. Honest clients must reject invalid records. |

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
| `grantSealsAllKeys` | A verified grant seals exactly the keys from its preceding prefix. |
| `epochSequential` | A verified rotation advances the epoch by one. |
| `noSelfRemoval` | A verified rotation does not remove its own author. |
| `grantSubjectNew` | A verified grant does not grant an active device again. |

## Results

The full tier samples 20,000 traces of up to 50 steps per check. It includes 17 mutants, 22 witnesses, and two known limits.

Each configuration checks its declared invariants, with explicit skips and the documented `honest4` subset. Sampling does not establish absence of other counterexamples.

Apalache checks `authorActive`, `noKeyToRemoved`, `baseRule`, and `activeSetDeterministic` on `honest`, up to eight steps.

That bound reaches initial enrollment but not the longer S1 paths. The TLC configurations check selected longer executions within finite domains.

Known limits. Each one must fail:

1. `forkRelay noFork`. T7: a malicious relay serves two valid branches. Neither device sees a conflict until it fetches a record whose base is not in its log.
2. `forkRelay noStaleChangeStored`. T8: a relay that withholds an epoch record from a stayed device can store that device's change under the old epoch.

### Exhaustive results (TLC)

The deep tier runs TLC on `tinyHonest`, `tinyHonest4`, `tinyThief`, `tinyFork`, and `tinyCompromised`.

Each baseline must complete its reachable state graph. Each listed mutant must produce an invariant counterexample on the same configuration.

`tinyCompromised` has two devices, three records, and two adversary actions. It checks signed invalid templates with one honest client.

Each action chooses its own parameters. Unrelated nondeterministic choices do not multiply every transition's enumeration cost.

## Compromised-key inputs

`signInvalid` bypasses `selfOk`. Its generation guards do not call `check`, `stateOk`, or other verifier predicates.

The action uses a key in `BAD` to sign one of five bounded templates on a relay branch.

The templates include missing grant keys, an epoch skip, self-removal, an invalid base digest, and a grant for an active device.

The last template can also produce a valid grant. Prefix-based properties judge each record where a verifier accepts it, not where the attacker created it.

The independent field invariants use reference prefix functions. They do not read the attacker tags or call the verifier.

Named scenarios check honest-relay refusal and client rejection after malicious-relay storage. Four additional mutants remove the corresponding field checks.

This is a bounded template attacker, not arbitrary control of every record field. An authorised key holder can still disclose keys it already knows.

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
