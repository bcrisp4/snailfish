# Snailfish protocol

Status: draft for M1. This file gives the exact bytes of the protocol (DESIGN.md "Wire format", [WIR-1] to [WIR-9]). DESIGN.md gives the rules and the reasons. If the two differ, change the Quint model first, then DESIGN.md, then this file, then `tools/vectorgen`, then the Rust code.

Before the first public release, formats can change without notice, and the vectors are regenerated (DESIGN.md "Versioning").

| Section | Status | Implementation | Vectors |
| --- | --- | --- | --- |
| 1. Signature input (PAE) | Done | `snailfish_protocol::pae` | DSSE 1.0.2 vector in `pae.rs` tests |
| 2. Common encodings | Done | `snailfish_protocol::encoding` | `vectors/protocol.json` |
| 3. Strict payload JSON | Done | `snailfish_protocol::strict` | `vectors/strict-json.json` |
| 4. Envelope JSON | Done | `snailfish_protocol::envelope` | `vectors/protocol.json` |
| 5. Record hash, entry hash and log digest | Done | `snailfish_protocol::hash` | `vectors/protocol.json` |
| 6. Record payloads | Done | `snailfish_protocol::records` | `vectors/protocol.json`, `vectors/strict-json.json` |
| 7. Signatures and keys | Done | `snailfish_protocol::sig`, `snailfish_protocol::keys` | `vectors/third_party/`, `vectors/protocol.json` |
| 8. Request signatures | To do (M2) | | RFC 9421 |
| 9. Recovery key encoding | Done | `snailfish_protocol::recovery` | `vectors/protocol.json`, `vectors/recovery-key.json` |

`vectors/README.md` describes each vector file and the programs that make and check them.

## 1. Signature input (PAE)

The signature input of each signed record is the DSSE v1 pre-authentication encoding of the payload type and the exact payload bytes.

```text
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
SP              = 0x20
LEN(s)          = ASCII decimal byte length of s, no leading zeros
```

- `type` is the UTF-8 payload type, for example `snailfish.change.v1`.
- `body` is the payload bytes as the envelope carries them. Nothing re-encodes them.
- The encoding is injective. Two different `(type, body)` pairs never give the same bytes.

Vector (DSSE protocol 1.0.2):

```text
type = http://example.com/HelloWorld
body = hello world
PAE  = DSSEv1 29 http://example.com/HelloWorld 11 hello world
```

Checks in the code: the DSSE vector, a proptest round trip and injectivity check (sampled), three Kani harnesses (bounded), the fuzz target `pae_decode`, and `cargo-mutants` with no missed mutants.

## 2. Common encodings

### 2.1 Frame

Each hash input, HKDF `info` value, HPKE `info` value, AEAD associated data and possession proof in this file is a frame. A frame is a list of byte strings.

```text
frame(x1, ..., xn) = u64be(len(x1)) || x1 || ... || u64be(len(xn)) || xn
u64be(n)           = n as 8 bytes, big-endian
```

- The first part of each frame is a label: an ASCII string such as `snailfish.entry-hash.v1`. The label separates the uses of one primitive.
- An integer part is `u64be(n)`. The frame then holds it as an 8-byte part with its own length prefix.
- The encoding is injective. Two different lists never give the same bytes.

Vector: `frame("ab", "")` is `0000000000000002 6162 0000000000000000` in hex (spaces for clarity only).

### 2.2 Identifiers

Each identifier has a text form with a prefix and lowercase hex. A reader refuses uppercase hex, a wrong prefix and a wrong length.

| Identifier | Bytes | Text form | Source |
| --- | --- | --- | --- |
| Log ID | 16 | `l_` + 32 hex digits | 128 random bits from the first device |
| Change ID | 16 | `c_` + 32 hex digits | 128 random bits from `new_change_id` |
| Device ID | 32 | `d_` + 64 hex digits | `SHA-256(frame("snailfish.device-id.v1", sign_pk, seal_pk))` |
| Recovery ID | 32 | `r_` + 64 hex digits | `SHA-256(frame("snailfish.recovery-id.v1", sign_pk, seal_pk))` |

- `sign_pk` is the 32-byte Ed25519 public key. `seal_pk` is the 1,216-byte X-Wing public key.
- A device ID or a recovery ID names both keys, so an ID cannot name a different key (DESIGN.md "Cryptography").
- In a frame, an identifier is its bytes, not its text form.

### 2.3 Binary fields

A binary field in a payload is standard base64 (RFC 4648 section 4) with padding. A reader refuses the URL-safe alphabet, missing or extra padding, non-zero trailing bits, whitespace and line breaks. Each byte string therefore has exactly one text form in a payload.

The envelope is not signed, so section 4 gives a looser rule for its fields.

### 2.4 Integers

Each integer in a payload is a JSON integer from 0 to 2^53 - 1, unless the field table gives a smaller range. Section 3 gives the parser rules.

## 3. Strict payload JSON

A signed payload is one UTF-8 JSON object (RFC 8259). The reader refuses a payload that breaks one of these rules. It then applies no state change ([WIR-4]).

1. The bytes are valid UTF-8, with no byte order mark.
2. The top-level value is an object.
3. No object holds the same key twice. The reader compares keys after it decodes the escapes, so `"a"` and `"\u0061"` are the same key.
4. Each number is an integer in the range from -(2^53 - 1) to 2^53 - 1. A number with a fraction or an exponent is refused, also `1.0`, `1e2` and `-0`.
5. Each string holds valid Unicode. An escaped lone surrogate, for example `"\ud800"`, is refused.
6. The object holds each required field of its payload type and no other field. Section 6 lists the fields. No field is optional, and no field is `null`.
7. Each field has the type and the range that section 6 gives.
8. Nothing follows the top-level object except JSON whitespace.

- The reader accepts JSON whitespace between tokens and any key order. The signature covers the exact bytes, so a layout choice cannot change the meaning.
- A writer emits the fields in the order of the section 6 tables, with no whitespace. The vectors use this form. A reader must not depend on it.
- `vectors/strict-json.json` holds a valid base payload and one case for each rule.

## 4. Envelope JSON

Each signed record travels in one DSSE v1 envelope.

```json
{"payloadType":"snailfish.change.v1","payload":"<base64>","signatures":[{"keyid":"d_3fa8...","sig":"<base64>"}]}
```

Rules:

- `payloadType` is the payload type string. `payload` is the base64 of the exact payload bytes. `signatures` is a list with exactly one entry ([LOG-2]).
- `sig` is the base64 of a 64-byte Ed25519 signature over `PAE(payloadType, payload bytes)` ([WIR-1]).
- `keyid` is optional and can hold any string. A verifier ignores it and uses the `author` field of the payload ([LOG-2]). A writer sets it to the author ID.
- The envelope is unsigned. A reader accepts the standard and the URL-safe base64 alphabets, with or without padding, as DSSE allows. It refuses a duplicate key at any depth.
- A reader ignores each unknown envelope field and each unknown field of the `signatures` entry, with any JSON value ([VER-13]). The integer rule of section 3 does not apply to the envelope, so a number such as `1.5e3` in an unknown field is valid. A reader refuses a number outside the IEEE 754 binary64 range, for example `1e999`, because common JSON libraries refuse it.
- A writer emits the three fields in the order above, with standard base64 with padding and no whitespace.
- The record hash covers the decoded bytes, so a change of the envelope layout does not change it ([WIR-3]).

## 5. Record hash, entry hash and log digest

```text
record_hash  = SHA-256(frame("snailfish.record-hash.v1", payload_type, payload, sig))
entry_hash   = SHA-256(frame("snailfish.entry-hash.v1", payload_type, change_id, record_hash))
digest(0)    = SHA-256(frame("snailfish.log-root.v1", log_id))
digest(n)    = SHA-256(frame("snailfish.log-digest.v1", digest(n-1), u64be(n), entry_hash(n)))
```

- `payload_type` is the UTF-8 payload type. `payload` is the decoded payload bytes. `sig` is the decoded 64-byte signature ([LOG-3]).
- `change_id` is the 16 bytes of the change ID of a `snailfish.change.v1` record. It is the empty string for every other type ([LOG-4]).
- A stub holds the payload type, the change ID and the record hash, so a device computes the entry hash of a stub with the same formula ([CMP-1]).
- `n` is the log position, from 1. `log_id` is the 16 bytes of the log ID ([LOG-5]).

## 6. Record payloads

### 6.1 Common fields

Each log record payload starts with these fields.

| Field | Type | Content |
| --- | --- | --- |
| `log` | log ID text | The log of the record |
| `author` | device ID or recovery ID text | The key that signs the record ([LOG-2]) |
| `base` | position object | The last entry that the author verified ([LOG-6]) |

Shared objects:

| Object | Fields |
| --- | --- |
| position | `position` (integer), `digest` (32-byte binary): a log position and the log digest at that position |
| keys | `sign` (32-byte binary Ed25519 public key), `seal` (1,216-byte binary X-Wing public key) |
| device | `id` (device ID text), `sign`, `seal` (as in keys), `name` (string of 1 to 128 UTF-8 bytes), `level` (integer from 1 to 65535) |
| key set | `to` (device ID or recovery ID text), `epochs` (list of integers from 1), `sealed` (binary): see section 7.3 |
| snapshot reference | `position` (integer from 1), `hash` (32-byte binary record hash) |

- In a device object, `id` must equal the device ID of `sign` and `seal`.
- In a key set, `epochs` is not empty and strictly increases.
- A list of key sets is sorted by the 32 decoded ID bytes of `to`, with no duplicate. The `d_` or `r_` prefix does not take part in the order.
- A list of device IDs is sorted by its 32 decoded ID bytes, with no duplicate.
- Each `sign` key is a canonical Ed25519 public key that is not of small order (section 7.1). A parser refuses a record with another `sign` value.
- The base of a genesis record is position 0 with `digest(0)`. The base of each other record has a position from 1 ([LOG-6]).

### 6.2 Record types

The fields of each type follow the common fields, in this order.

| Payload type | Author | Fields after `log`, `author`, `base` |
| --- | --- | --- |
| `snailfish.genesis.v1` | recovery ID | `app` (string of 1 to 255 bytes), `recovery` (keys), `level` (integer from 1 to 65535, the first space write level), `device` (device), `epoch` (integer, must be 1), `commitment` (32-byte binary), `keys` (list of 2 key sets: the first device and the recovery ID, each with epochs `[1]`) |
| `snailfish.grant.v1` | device ID or recovery ID | `device` (device), `keys` (one key set to the new device) |
| `snailfish.epoch.v1` | device ID or recovery ID | `epoch` (integer from 2), `removed` (list of device IDs), `stay` (list of device IDs, not empty), `commitment` (32-byte binary), `keys` (one key set to each device in `stay` and one to the current recovery ID, each with epochs `[epoch]`) |
| `snailfish.recovery.v1` | recovery ID | `recovery` (keys), `proof` (64-byte binary), `keys` (one key set to the new recovery ID) |
| `snailfish.device.v1` | device ID | `level` (integer from 1 to 65535) |
| `snailfish.level.v1` | device ID | `level` (integer from 1 to 65535) |
| `snailfish.change.v1` | device ID | `epoch` (integer from 1), `change_id` (change ID text), `ciphertext` (binary of at least 40 bytes) |
| `snailfish.snapshot.v1` | device ID | `epoch` (integer from 1), `state` (position), `ciphertext` (binary of at least 40 bytes) |
| `snailfish.accept.v1` | device ID | `snapshot` (snapshot reference), `applied` (position) |

- In a genesis record, `author` must equal the recovery ID of `recovery`. A verifier can therefore find the author key in the record itself ([WIR-2]).
- `proof` is an Ed25519 signature by the new recovery signing key over `frame("snailfish.recovery-proof.v1", log_id, new_sign_pk, new_seal_pk)`. A parser refuses a recovery record whose proof does not verify, because the record holds every input of the check.
- In an epoch record, no device ID is in both `removed` and `stay`. The record has exactly one key set to a recovery ID. A parser cannot know the current recovery ID, so the space state check confirms it ([LOG-8]).
- `commitment` is `SHA-256(frame("snailfish.key-commitment.v1", log_id, u64be(epoch), key))` for the 32-byte app key of the epoch.
- Level 1 is the set of the `v1` types of this file.

### 6.3 Signed statements that are not log records

These statements use the same envelope and signature input. They have no `base` field.

| Payload type | Author | Fields |
| --- | --- | --- |
| `snailfish.checkpoint.v1` | device ID | `log`, `author`, `position` (integer from 1), `digest` (32-byte binary) |
| `snailfish.delete.v1` | device ID or recovery ID | `log`, `author`, `head` (position), `expires` (integer, Unix time in seconds) ([LOG-13]) |

### 6.4 Unknown payload types

| Payload type | Class | Verdict |
| --- | --- | --- |
| A type in the tables above | known | Parse with the rules of this section |
| Other `snailfish.change.*` and `snailfish.snapshot.*` types | unknown content | Parse failure: the engine skips the record and reports `degraded` ([VER-5], [DLV-13]) |
| Other `snailfish.accept.*` types | unknown accept | `stopped: update required` ([VER-5]) |
| Each other type | unknown security record | `stopped: update required` ([VER-4]) |

## 7. Signatures and keys

### 7.1 Ed25519

- Each signature is Ed25519 (RFC 8032) with `verify_strict` of `ed25519-dalek`. It refuses small-order public keys, small-order R values and non-canonical R values.
- A verifier also refuses a public key whose bytes differ from the canonical encoding of the decoded point, and a public key of small order.
- A device signing key is 32 random bytes from the operating system CSPRNG.
- `vectors/third_party/cctv-ed25519.json` holds the 914 C2SP CCTV vectors. A vector verifies only if its flags are a subset of `low_order_component_A` and `low_order_component_R`.

### 7.2 App keys

- An app key is 32 random bytes. Each epoch has one app key.
- A change and a snapshot use XChaCha20-Poly1305 with the app key of their epoch and a random 24-byte nonce.
- `ciphertext` is `nonce || AEAD output`. The AEAD output is the encrypted bytes with the 16-byte tag at the end.

| Payload type | Associated data |
| --- | --- |
| `snailfish.change.v1` | `frame("snailfish.change.v1", log_id, u64be(epoch), change_id, author_device_id)` |
| `snailfish.snapshot.v1` | `frame("snailfish.snapshot.v1", log_id, u64be(epoch), author_device_id, u64be(state.position), state.digest)` |

A relay therefore cannot present a ciphertext with other routing fields (DESIGN.md "Cryptography").

### 7.3 Key sets

A key set holds the app keys of one or more epochs, sealed to one recipient.

| Parameter | Value |
| --- | --- |
| HPKE mode | base (0x00) |
| KEM | MLKEM768-X25519, X-Wing (0x647A) |
| KDF | HKDF-SHA256 (0x0001) |
| AEAD | ChaCha20Poly1305 (0x0003) |
| `info` | `frame("snailfish.keyset.v1", log_id, recipient_id, u64be(e1), ..., u64be(ek))` |
| `aad` | empty |
| plaintext | `key(e1) || ... || key(ek)`, 32 bytes for each epoch in `epochs` |
| `sealed` | `enc || ciphertext`: the 1,120-byte encapsulation, then the 32k + 16 bytes of the one HPKE `Seal` |

- `recipient_id` is the 32 bytes of the device ID or recovery ID in `to`.
- After it opens a key set, a device computes the commitment of each key and checks it against the genesis or epoch record of that epoch.
- An X-Wing private key is a 32-byte seed. For a device, the seed is 32 random bytes. The public key comes from the seed as `draft-connolly-cfrg-xwing-kem` defines.
- `vectors/third_party/hpke-rfc9180.json` and `vectors/third_party/hpke-pq.json` check the `hpke` crate. The Go standard library `crypto/hpke` opens the key sets in `vectors/protocol.json`.

## 8. Request signatures

To do in M2: RFC 9421 HTTP Message Signatures with Ed25519.

## 9. Recovery key encoding

The recovery secret is 16 random bytes.

```text
check   = first 4 bytes of SHA-256(frame("snailfish.recovery-check.v1", secret))
symbols = Crockford base32 of (secret || check), 20 bytes, most significant bit first
display = the 32 symbols in 8 groups of 4, joined with "-"
```

Example form: `0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ`.

A reader:

1. Removes each `-` and each space.
2. Changes lowercase letters to uppercase.
3. Reads `O` as `0`, and `I` and `L` as `1`.
4. Refuses each other symbol outside `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, for example `U`.
5. Refuses a result that is not 32 symbols, or a check that does not match.

Key derivation (HKDF-SHA256, RFC 5869):

```text
prk       = HKDF-Extract(salt = "snailfish.recovery.v1", ikm = secret)
sign_seed = HKDF-Expand(prk, "snailfish.recovery.sign.v1", 32)
seal_seed = HKDF-Expand(prk, "snailfish.recovery.seal.v1", 32)
```

- `sign_seed` is the Ed25519 signing key. `seal_seed` is the X-Wing private key seed (section 7.3).
- `vectors/recovery-key.json` holds valid and invalid text forms.
