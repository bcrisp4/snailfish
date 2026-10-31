# Shared test vectors

The `protocol` crate, the sync engine, the Python binding and the Swift binding read the same files. A vector that fails in one of them fails CI (DESIGN.md "Crypto boundary").

| File | Source | Content |
| --- | --- | --- |
| `protocol.json` | `tools/vectorgen` (Go) | One valid space log with every record type of `PROTOCOL.md` section 6, envelope variants, frames, IDs, key sets, change ciphertexts and recovery keys |
| `strict-json.json` | `tools/vectorgen` (Go) | Payloads that `PROTOCOL.md` section 3 accepts or refuses, one case for each rule, and the section 6 rules for `sign` keys, recovery proofs and epoch records |
| `recovery-key.json` | `tools/vectorgen` (Go) | Valid and invalid recovery key text forms (`PROTOCOL.md` section 9) |
| `http.json` | `tools/vectorgen` (Go) | Request signatures (`PROTOCOL.md` section 8) and append and fetch results of the HTTP API (section 10) |
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

## Format of `http.json`

All times are Unix seconds. Byte strings are lowercase hex, unless the field is a header value, a JSON body string or a signature base.

```text
{
  "version": 1,
  "authority": "sync.example.net",    the configured relay authority
  "now": n,                           the relay time for every case
  "limits": { the limits object of PROTOCOL.md 10.4 },  small values, so a too large case stays small
  "used_nonces": [ [keyid, nonce hex] ],                 nonces that the tenant file holds before each case
  "tenant": "t_...", "log_id": "l_...",
  "devices": [ { "name", "sign_seed", "id" } ],     A, B and C of protocol.json
  "signed": [ {
      "name", "signer": device name,
      "method", "authority", "path", "query",         query without "?", "" for none
      "body": str,                                    the exact body bytes as UTF-8
      "created": n, "expires": n, "nonce": hex,
      "content_digest": str, "signature_params": str, "signature_base": str,
      "sig": hex,
      "headers": [ [name, value] ]                    the four headers of section 8.1, in that order
  } ],
  "invalid": [ {
      "name", "signer": device name or "",
      "method", "path", "query", "body": str,
      "headers": [ [name, value] ],
      "error": code                                   the code of PROTOCOL.md 10.3 that the relay returns
  } ],
  "space": {
      "genesis": envelope str, "genesis_digest": hex,
      "log": [ { "position", "envelope": str, "record_hash": hex, "digest": hex } ]   positions 1..n after setup
  },
  "append": [ {
      "name", "signer": device name,
      "body": str,                                    the append request body of section 10.6
      "results": [ { "status", "position": n or null, "error": code or null } ],
      "head": { "position", "digest": hex }
  } ],
  "append_hold": [ same form as "append" ],         each case starts from space.log with the space on restore hold
  "fetch": [ {
      "name", "after", "limit",
      "hold": bool,                                   the relay state, and the `hold` value that the response must hold. The response must hold the field.
      "positions": [n], "head": n, "has_more": bool
  } ],
  "status": [ {
      "name", "signer": device name, "hold": bool,    hold: the relay state before the case
      "body": str,                                    the status report body of section 10.8
      "response": { "hold": bool } or null,           null if the relay returns an error
      "error": code or null,
      "tip_in_log": bool or null                      the relay reads the tip as "reported" (10.8). null if no report is stored.
  } ],
  "repair": [ {
      "name", "log_prefix": n, "hold": bool,          the relay log is positions 1..log_prefix of space.log
      "steps": [ {
          "route": "start" or "chunk" or "finish",
          "signer": device name,
          "at": n,                                    the relay time and the request created time of this step
          "body": str,                                "{{session}}" stands for the session of the last start that returned 201 in this case
          "status": n,                                the HTTP status
          "next": n or null, "head": { "position", "digest": hex } or null,
          "error": code or null
      } ],
      "log": [ record_hash hex ]                     the record hashes of the relay log after the last step, from position 1
  } ]
}
```

- Each `signed` case verifies with the `sign_seed` public key of its signer. `headers` are the exact header values.
- Each `invalid` case breaks one check of `PROTOCOL.md` 8.6. The relay returns `error` for it. The space has the devices of `space.log` as active devices.
- `space.log` is the log of the space before each `append` case: genesis (recovery key R1, first device A), a change by A, a grant to B by A, and a change by B. Each `append` case starts from this log, so the cases are independent.
- `append` covers a new change, an exact retry (`known`), the same `change_id` with another record hash (`conflict`), a second copy in one request, a bad base, a base at or after the new position, an author that differs from the request signer (a record by C that A sends), another log ID, an unsupported type, a wrong epoch, a too large change, a grant of an active device, and one request with mixed results.
- `append` also covers the base rule for security records ([LOG-7]): a grant whose base is before the last security record is `stale_base`, and a grant whose base is after the last security record but before a change is `stored`.
- `append_hold` covers a change (`on_hold`), an exact retry of a stored change (`known`), a grant (`stored`) and a grant with a stale base (`stale_base`) during a hold ([LOG-14]).
- `fetch` lists the positions that a fetch returns from `space.log`, and the `hold` field of the response.
- `status` covers a report during a hold with a tip in the log, a tip after the head, a tip with another digest, a report without a hold, and malformed bodies.
- `repair` covers a repair in one start, in a start and chunks, a repair during a hold, a signer whose grant is only in the request entries ([LOG-12]), a signer that is active nowhere, a wrong base, a gap in the positions, an entry with a bad signature, a stub ([LOG-11]), a wrong tip, a second device during a session (`repair_busy`), a restart by the same device, a session after expiry, a finish after expiry, a chunk from another device, an unknown session, a known `change_id` in the entries, a wrong base with a signer whose grant is in the entries, a body at and over the repair allowance, and a malformed start.
