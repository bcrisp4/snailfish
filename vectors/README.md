# Shared test vectors

The `protocol` crate, the sync engine, the Python binding and the Swift binding read the same files. A vector that fails in one of them fails CI (DESIGN.md "Crypto boundary").

| File | Source | Content |
| --- | --- | --- |
| `protocol.json` | `tools/vectorgen` (Go) | One valid space log with every record type of `PROTOCOL.md` section 6, envelope variants, frames, IDs, key sets, change ciphertexts and recovery keys |
| `strict-json.json` | `tools/vectorgen` (Go) | Payloads that `PROTOCOL.md` section 3 accepts or refuses, one case for each rule, and the section 6 rules for `sign` keys, recovery proofs and epoch records |
| `recovery-key.json` | `tools/vectorgen` (Go) | Valid and invalid recovery key text forms (`PROTOCOL.md` section 9) |
| `third_party/cctv-ed25519.json` | C2SP CCTV, commit `50a8ecf2a220f4c8bdc4f085789b8e85c26829e7`, BSD-3-Clause (`third_party/CCTV-LICENSE`) | The 914 Ed25519 edge-case vectors |
| `third_party/hpke-rfc9180.json` | `cfrg/draft-irtf-cfrg-hpke` commit `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb` | RFC 9180 vector for base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 |
| `third_party/hpke-pq.json` | `hpkewg/hpke-pq` commit `6433c8fce0b8b749dfc86c1095081a88698ccfab` | `draft-ietf-hpke-pq` vector for MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305 |

## Independence

The Go generator uses the Go standard library (`crypto/ed25519`, `crypto/sha256`, `crypto/hkdf` and `crypto/hpke`), `golang.org/x/crypto/chacha20poly1305` and `filippo.io/edwards25519`. The last one checks that a `sign` key is canonical and not of small order. It does not call Rust. The Rust code therefore checks its output against a second implementation of `PROTOCOL.md`.

Go `crypto/hpke` takes no fixed ephemeral key, so each run makes new `sealed` bytes. The committed files are the reference. Run the generator only after a format change.

## Regenerate and check

1. Run `make vectors`. It runs `go run ./tools/vectorgen -out vectors`.
2. Run `make vectors-check`. Go reads the committed files and checks each value again. It also opens the key sets that Rust seals. The Rust test writes them to the file in `RUST_SEALED`, and the Makefile deletes the old file first.
3. Run `make rust-test`. The Rust tests read every file in this directory.

## Format of `protocol.json`

All byte strings are lowercase hex, unless the field name ends in `_b64` or is a payload or envelope string.

```text
{
  "version": 1,
  "frames":   [ { "parts": [hex, ...], "frame": hex } ],
  "devices":  [ { "name", "sign_seed", "seal_seed", "sign_pk", "seal_pk", "id" } ],
  "recovery": [ { "name", "secret", "display", "sign_seed", "seal_seed", "sign_pk", "seal_pk", "id" } ],
  "log": {
    "log_id": "l_...", "app": "com.example.tasks", "digest0": hex,
    "app_keys": { "1": hex, "2": hex },
    "commitments": { "1": hex, "2": hex },
    "entries": [ {
        "position": n, "name": str, "payload_type": str,
        "payload": str,            the exact payload bytes as a UTF-8 string
        "envelope": str,           the canonical envelope JSON
        "signer": str,             the name of the device or recovery key in "devices" or "recovery"
        "sig": hex, "record_hash": hex, "change_id": hex or "", "entry_hash": hex, "digest": hex
    } ]
  },
  "statements": [ { "name", "payload_type", "payload", "envelope", "signer", "sig", "record_hash" } ],
  "key_sets": [ { "entry": position, "index": n, "to": id, "epochs": [n], "info": hex, "plaintext": hex } ],
  "ciphertexts": [ { "entry": position, "aad": hex, "nonce": hex, "plaintext": hex } ],
  "envelopes": [ { "name", "envelope": str, "valid": bool, "record_hash": hex or "" } ]
}
```

- `log.entries` is one valid log: genesis, grant, change, snapshot, accept, device, level, epoch (removal), change in epoch 2, recovery. Each record has the correct base.
- `envelopes` holds variants of the change at position 3: URL-safe base64, no padding, another `keyid`, no `keyid`, unknown fields with any JSON value (`1.5e3`, `-0`, 9007199254740993, a nested object), an unknown field in the `signatures` entry, extra whitespace, and invalid cases (two signatures, no signature, a duplicate key at the top level, in the `signatures` entry or in a nested unknown object, a 63-byte signature, an empty payload). A valid variant has the record hash of position 3.
- `key_sets` names each key set by its log position and its index in `keys`. `plaintext` is the expected content after `Open`.

## Format of `strict-json.json`

```text
{ "version": 1, "cases": [ { "name", "rule", "payload_type", "payload": str or null, "payload_hex": hex or null, "valid": bool } ] }
```

- `rule` is the rule number of `PROTOCOL.md` section 3, or `"6.2"` for a field rule of section 6.
- Section 6 cases break one rule each. They cover a non-canonical or small-order `sign` key, a bad recovery proof, a device in both `removed` and `stay`, and an epoch record with two key sets to recovery IDs.
- `payload_hex` holds the bytes of a case that is not valid UTF-8. Then `payload` is null.

## Format of `recovery-key.json`

```text
{ "version": 1, "valid": [ { "text", "secret": hex } ], "invalid": [ { "name", "text" } ] }
```
