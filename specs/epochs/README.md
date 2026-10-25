# Epoch retries and relay recovery

This model checks interactions between epoch changes, pending change envelopes, relay restore, and repair.

It uses a shared relay log and two devices. Each device holds a verified log and at most one pending change envelope.

The initial trusted prefix represents an existing space with both devices enrolled at epoch 1. It abstracts the genesis and grant records.

## Coverage

| Rule | Model behaviour | Scenario |
| --- | --- | --- |
| `[DLV-7]` | A known change ID precedes an epoch refusal. A normal retry retains its envelope. | `knownRetryAfterRotationTest` |
| `[DLV-7]` | An unknown old-epoch change receives a refusal before re-encryption on a verified newer prefix. | `unknownRetryAfterRotationTest` |
| `[LOG-8]`, `[LOG-9]` | Each accepted change obeys the author and epoch state before its position. | `removedAuthorRefusedTest` |
| `[LOG-10]` | Repair restores the complete verified suffix, including removal records. | `repairRetainsRotationTest` |
| `[LOG-14]` | A hold refuses changes but permits a removal. | `removalDuringHoldCanForkTest` |
| `[LOG-15]` | A restored prefix and a security append can produce conflicting branches before a device detects the conflict. | `removalDuringHoldCanForkTest` |

The model uses a stable change ID and a separate envelope ID. Re-encryption changes the envelope, epoch, and signed base, not the change ID.

A compromised device-2 key can sign change metadata for the current public epoch. This does not give it the current app key.

The relay must reject a removed author even if the signature and public epoch metadata are correct.

## Properties

| Invariant | Requirement | Mutants |
| --- | --- | --- |
| `knownIdFirst` | An epoch refusal implies that the relay does not hold the change ID. | `epochBeforeDedupe` |
| `repairComplete` | A successful repair reproduces the full verified log that the device supplies. | `repairDropsRotation` |
| `relayAuthorised` | Each relay record obeys the preceding prefix's author, epoch, base, and duplicate-ID rules. | `ignoreRemoval`, `ignoreEpoch` |
| `holdBlocksChanges` | A change cannot append during a hold. | `ignoreHold` |

The prefix property does not call the relay verdict function. Repair completeness checks the operation's result against the complete supplied prefix.

The eight required witnesses include removal during a hold, security-record repair, old-envelope deduplication, stale refusal, re-encrypted append, and conflict detection.

## Known limit

`noFork` does not hold. A removal during a restore hold can conflict with a lost change from another verified branch.

Both devices can remain unaware until a fetch reveals the conflict. The scenario checks that the affected device stops at that point.

A rollback can restore a prefix in which a removed device remains active. Authorisation against that prefix does not establish global revocation.

`checks.toml` requires the fork counterexample on both configurations. It does not treat this limit as a safety guarantee.

## Verification scope

| Tier | Scope |
| --- | --- |
| Fast | Scenario tests and 2,000 sampled traces of up to 30 steps on `bounded`. |
| Full | 20,000 sampled traces per check, up to 50 steps. Both configurations, two limits, five mutants, and eight witnesses. |
| Apalache | All four safety properties up to four steps on `tiny`. This is a bounded cross-check. |
| TLC | All four safety properties on every reachable state of `tiny`. Each of the five mutants must produce a counterexample. |

`bounded` permits four new record envelopes. `tiny` permits three. Both permit one removal and one relay restore.

TLC visits 55,302 distinct states for the unmodified `tiny` configuration. The complete state graph has depth 16.

The TLC result covers longer sequences than the Apalache step bound, but only within the finite `tiny` domain.

## Exclusions

- Signatures, hashes, payload bytes, and key secrecy remain ideal abstractions. Envelope IDs represent immutable signed bytes.
- The model omits enrollment, additional removals, grants, compaction, app database state, and engine state loss.
- The relay follows the protocol except for prefix restore. Spacelog checks client verification against a malicious relay.
- A security append is atomic. Repair is atomic and omits chunks, staging expiry, and interrupted sessions.
- Operator release does not require every device to report. Delivery checks reports, fresh engine state, and release warnings.

The initial trusted prefix, device keys, and envelope-ID counter survive relay restore. These assumptions do not describe whole-machine backup restore.

This model checks safety, not eventual delivery. It does not establish equivalence with the delivery or spacelog model, or with Rust code.

## Commands

1. Run `make verify-fast MODEL=epochs` after each model edit.
2. Run `make verify MODEL=epochs` for full sampled checks.
3. Run `make verify-deep MODEL=epochs` for Apalache and TLC.

For Rust implementation, follow [Model-to-Rust conformance](../conformance.md). Run the named scenarios through real interfaces and compare observable state.
