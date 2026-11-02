# Removal model (ProVerif)

ProVerif checks the symbolic security of key rotation after a removal and after a recovery key replacement (DESIGN.md "Space log" record table, T8 and T9). The tool pin is ProVerif 2.05 via `opam install proverif`.

## Files

| File | Content |
| --- | --- |
| `lib.pvl` | Types, crypto functions, processes `T` and `S`, the queries and the variant switch. |
| `removal.pv` | The design: `process System(vNone)`. |
| `<variant>.pv` | One deliberate flaw each. Each file is one line: `process System(vX)`. |
| `expect.toml` | The expected result of each query in each file. |

## What is modelled

1. The attacker holds the private keys of the stolen device X, the epoch 1 app key that X held (T8), and the private keys of the first recovery key R0 (T9).
2. `T` makes a new recovery key R1. It sends a recovery record that R0 signs, with the possession proof of R1 and the old key sealed to R1.
3. `T` then sends an epoch record that removes X. It holds a new app key, its commitment, and key sets to S, to T and to the current recovery key R1. `T` signs it.
4. `S` verifies the recovery record (R0 signature and the possession proof), then the epoch record (the signature of T, and a recovery key set that names R1). `S` opens its key set, checks the commitment and encrypts new data with the new key.

## Attacker model

- Dolev-Yao. The network and the relay are the attacker, for an unbounded number of sessions.
- X-Wing is an ideal KEM. Ed25519 is an ideal signature. The commitment is a hash with no inverse.

## Queries and results for the design

| Query | Result | Meaning |
| --- | --- | --- |
| `event(TRotates(k)) && attacker(k)` | true (never both) | The removed device and the stolen recovery key never learn a key that T rotates to. |
| `not attacker(sdata)` | true | The data that S encrypts after the rotation stays secret. |
| `event(SAccepts(k)) ==> event(TRotates(k))` | true | S uses only a key that T rotated to. |
| `not event(TRotates)`, `not event(SAccepts)` | reachable | A full honest run exists. |

## Variants

| File | Flaw | Attack | Queries that fail |
| --- | --- | --- | --- |
| `seal_to_removed.pv` | The epoch record seals the new key to X. | X opens its key set. | key secrecy, `sdata` |
| `seal_to_old_recovery.pv` | The epoch record seals the new key to R0, not R1. | The holder of the stolen recovery key opens the key set (T9). | key secrecy, `sdata` |
| `epoch_unsigned.pv` | S accepts an epoch record without the signature of T. | The attacker sends an epoch record with its own key sealed to S, and reads the new data. | `sdata`, `SAccepts ==> TRotates` |

A variant in which S skips the possession proof check broke no query. The attacker holds R0, so it can sign any recovery record with or without the proof. The proof protects against a recovery record that names a key that nobody holds, which is a liveness fault, not a secrecy fault. `crates/protocol` checks the proof in the parser.

## Limits

- No state. "Current" recovery key and "active" device are fixed by the process order: S reads one recovery record and then one epoch record. The relay order, the base rule and the block decide which records come first (`specs/spacelog`).
- An epoch record that X signs before the block is out of scope. `specs/spacelog` checks that the relay and each engine refuse every record from X after the removal (T8).
- Old ciphertext stays readable to X and to the holder of R0 (T8, T9). The model does not query it.
- No probability and no timing.
- X-Wing and Ed25519 are ideal. Hybrid or combiner flaws are out of scope.

## Rust conformance (M7)

| Model case | Rust tests |
| --- | --- |
| `seal_to_removed.pv`: the new key reaches only the devices that stay | `crates/protocol` space tests (epoch key sets), `crates/engine/src/tests.rs` removal tests |
| `seal_to_old_recovery.pv`: the recovery key set names the current recovery ID | `crates/protocol` space tests (epoch after a recovery record) |
| `epoch_unsigned.pv`: the epoch signature and the commitment check | `crates/protocol` space tests, `crates/engine/src/tests.rs` epoch key commitment test |

## Run

1. Run `eval $(opam env)` once in the shell.
2. Run `make verify-crypto` from the repo root.
