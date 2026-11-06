# Snailfish protocol

Status: draft for M7. This file gives the exact bytes of the protocol (DESIGN.md "Wire format", [WIR-1] to [WIR-9]). DESIGN.md gives the rules and the reasons. If the two differ, change the Quint model first, then DESIGN.md, then this file, then `tools/vectorgen`, then the Rust code.

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
| 8. Request signatures | Done | `snailfish_protocol::request` | `vectors/http.json` |
| 9. Recovery key encoding | Done | `snailfish_protocol::recovery` | `vectors/protocol.json`, `vectors/recovery-key.json` |
| 10. HTTP API | Done (M7 routes) | `snailfish_protocol::wire`, `snailfish-relay` | `vectors/http.json` |
| 11. Enrollment | Done | `snailfish_protocol::enroll`, `snailfish-engine` | `vectors/enroll.json`, `vectors/http.json` |
| 12. User and setup surface | Done | `snailfish_protocol::setup`, `snailfish-relay`, `snailfish-engine` | `vectors/http.json` |
| 13. Removal and recovery | Done | `snailfish_protocol::space`, `snailfish-engine`, `snailfish-relay` | `vectors/http.json` |

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
| Session ID | 16 | `e_` + 32 hex digits | 128 random bits from the device that shows the enrollment code (section 11) |
| Invite token | 32 | `it_` + 64 hex digits | 256 random bits from the relay (section 12.1) |
| Authorization code | 32 | `ac_` + 64 hex digits | 256 random bits from the relay (section 12.2) |
| Setup token | 32 | `st_` + 64 hex digits | 256 random bits from the relay (section 12.3) |

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
| `snailfish.snapshot.v1` | device ID | `epoch` (integer from 1), `state` (position, from 1), `ciphertext` (binary of at least 40 bytes) |
| `snailfish.accept.v1` | device ID | `snapshot` (snapshot reference), `applied` (position) |

- In a genesis record, `author` must equal the recovery ID of `recovery`. A verifier can therefore find the author key in the record itself ([WIR-2]).
- `proof` is an Ed25519 signature by the new recovery signing key over `frame("snailfish.recovery-proof.v1", log_id, new_sign_pk, new_seal_pk)`. A parser refuses a recovery record whose proof does not verify, because the record holds every input of the check.
- In an epoch record, no device ID is in both `removed` and `stay`. The record has exactly one key set to a recovery ID. A parser cannot know the current recovery ID, so the space state check confirms it ([LOG-8]).
- An epoch record with an empty `removed` list is a rotation with no removal. A recovery key replacement appends one (section 13.3).
- `commitment` is `SHA-256(frame("snailfish.key-commitment.v1", log_id, u64be(epoch), key))` for the 32-byte app key of the epoch.
- Level 1 is the set of the `v1` types of this file. A record type is valid at a write level if the set of that level holds it ([VER-6], [VER-9]).
- A grant and a device record state the highest level of the device engine ([VER-7]).

### 6.3 Signed statements that are not log records

These statements use the same envelope and signature input. They have no `base` field.

| Payload type | Author | Fields |
| --- | --- | --- |
| `snailfish.checkpoint.v1` | device ID | `log`, `author`, `position` (integer from 1), `digest` (32-byte binary) |
| `snailfish.delete.v1` | device ID or recovery ID | `log`, `author`, `head` (position), `expires` (integer, Unix time in seconds) ([LOG-13], 10.12) |
| `snailfish.confirm.v1` | the device in `device` | `session` (session ID text), `trusted` (device ID text), `device` (device), `trusted_nonce` (32-byte binary), `new_nonce` (32-byte binary) |

- A checkpoint states the log digest at `position`. The trusted device signs it during enrollment ([ENR-8], section 11).
- A confirmation is the signed confirmation of the new device ([ENR-7], section 11). It has no `log` and no `author` field: the new device does not know the log yet, and `device.sign` is the signing key.

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

Each request on the sync surface carries an RFC 9421 HTTP message signature with Ed25519 (DESIGN.md "Cryptography", T5). Only `GET /v1/health` and `GET /v1/info` have no signature. This section fixes one form of RFC 9421. A reader refuses each other form, also a form that RFC 9421 allows.

### 8.1 Headers

A signed request has these four headers. Each header occurs once.

| Header | Value |
| --- | --- |
| `content-digest` | `sha-256=:` + base64 of SHA-256 of the body bytes + `:` (RFC 9530). The body of a `GET` is empty. |
| `signature-input` | `sf=` + the signature parameters (8.2) |
| `signature` | `sf=:` + base64 of the 64-byte Ed25519 signature + `:` |
| `snailfish-authority` | The authority that the signature covers (8.3) |

- Base64 in these headers is standard base64 with padding (RFC 4648 section 4). A reader refuses each other form.
- A header name is case-insensitive. A header value is case-sensitive.

### 8.2 Signature parameters

The signature parameters are one line in exactly this form, with no whitespace except the single spaces in the component list:

```text
("@method" "@authority" "@path" "@query" "content-digest");created=C;expires=E;nonce="N";keyid="K";alg="ed25519";tag="snailfish.request.v1"
```

| Parameter | Rule |
| --- | --- |
| component list | Exactly these five components, in this order |
| `created` | Unix time in seconds, from the corrected device clock (8.5). A decimal integer from 1 to 2^53 - 1 with no leading zero. |
| `expires` | `created + 300` or less, and more than `created`. Same integer form. |
| `nonce` | 16 random bytes from the operating system CSPRNG, as 32 lowercase hex digits |
| `keyid` | The device ID text of the signer (section 2.2). On `GET .../entries` and `POST .../append`, also the current recovery ID of the space (10.2, section 13.4). |
| `alg` | `ed25519` |
| `tag` | `snailfish.request.v1`. It separates request signatures from other uses of a key. |

The `signature-input` header is `sf=` followed by this line. The label is `sf`. A header with another label, a second label or a parameter in another order is refused.

### 8.3 Component values

| Component | Value |
| --- | --- |
| `@method` | The HTTP method in uppercase, for example `POST` |
| `@authority` | The host in lowercase, then `:` and the port if the port is not the default port of the scheme. For example `sync.example.net` or `relay.example.ts.net:8443`. |
| `@path` | The path of the request target, exactly as sent, without the query. It starts with `/`. |
| `@query` | `?` and the query of the request target exactly as sent. `?` alone if the target has no query (RFC 9421 section 2.2.7). |
| `content-digest` | The value of the `content-digest` header |

- The engine takes the authority from the relay URL. The host app must not follow redirects (DESIGN.md "App integration").
- The relay URL is `https://` or `http://` and the authority, with no path. The relay serves the routes of section 10 at the root, and the signature covers `@path` as sent, so a proxy that adds or removes a path prefix breaks each signature.
- The relay uses the authority that the relay operator configures, not the `Host` or `X-Forwarded-Host` header. It does not start without this setting.
- The engine also sends the authority in `snailfish-authority`. The signature covers the value through `@authority`, so this header only lets the relay report a distinct error (8.6).

### 8.4 Signature base

The signature base is the RFC 9421 section 2.5 form. It is six lines joined with one LF (0x0A), with no LF after the last line:

```text
"@method": <@method>
"@authority": <@authority>
"@path": <@path>
"@query": <@query>
"content-digest": <content-digest>
"@signature-params": <the line of 8.2>
```

The signature is Ed25519 (RFC 8032) over the signature base bytes, with the device signing key. The relay verifies it with `verify_strict` and the key rules of section 7.1.

Example:

```text
"@method": GET
"@authority": sync.example.net
"@path": /v1/t/t_00112233445566778899aabbccddeeff/s/l_00112233445566778899aabbccddeeff/entries
"@query": ?after=0&limit=500
"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
"@signature-params": ("@method" "@authority" "@path" "@query" "content-digest");created=1767225600;expires=1767225900;nonce="000102030405060708090a0b0c0d0e0f";keyid="d_...";alg="ed25519";tag="snailfish.request.v1"
```

`vectors/http.json` holds complete examples.

### 8.5 Relay time and clock correction

Each relay response carries the header `snailfish-time`: the relay time in Unix seconds, as a decimal integer ([WIR-7]). Error responses and the unsigned routes carry it too.

- The engine keeps `offset = relay time - device time` from the last response with a valid `snailfish-time`.
- The engine sets `created` to the device time plus `offset`, and `expires` to `created + 300`.
- The engine reads `snailfish-time` from the `GET /v1/info` response at the start of each sync, so the first signed request of a sync uses a fresh offset.

### 8.6 Relay checks

The relay checks a signed request in this order. It returns the first error (section 10.3).

1. If `snailfish-authority` is present and differs from the configured authority, return `wrong_authority`.
2. If a header of 8.1 is missing, occurs twice or breaks its form, return `bad_signature`. A `signature-input` whose `expires` is not after `created`, or is more than 300 seconds after it, breaks its form.
3. If `expires` is before the relay time, or `created` is more than 60 seconds after the relay time, return `expired`.
4. If `content-digest` differs from the digest of the body, return `bad_digest`.
5. If the tenant file blocks the device of `keyid` (12.4), return `blocked`. The relay reads the tenant file before it opens the space file ([STO-12]).
6. If `keyid` names a device that an epoch record removed from the space (10.2), return `removed`.
7. If `keyid` names no device that is active in the space (10.2), and it is not the current recovery ID on a route that accepts it (8.2), return `unknown_device`.
8. If the signature does not verify over the signature base of 8.4, return `bad_signature`.
9. If the tenant file holds the pair (`keyid`, `nonce`), return `nonce_reused`. Otherwise store the pair with `expires`.

- The relay keeps each nonce in the tenant file until its `expires` time, so a restart does not allow a replay (T5). It deletes expired nonces.
- The relay stores a nonce only after the signature verifies, so a party without the key cannot use up nonces.
- Steps 3 to 7 run before the signature check. The errors of steps 3 and 4 tell an unauthenticated caller only facts that the request itself holds. Steps 5 to 7 tell a caller who knows the tenant handle and the log ID whether a device ID is blocked, removed or active in the space. The tenant handle has 128 random bits ([STO-10]), so only a party that already holds it can ask.
- For `PUT /v1/t/{tenant}/s/{log}`, step 7 takes the device key from the genesis record in the body. The relay therefore runs steps 1 to 4 before it parses the body (10.5).
- For the repair routes, step 7 also accepts a device that the staged entries or the request entries make active (10.9, [LOG-12]). The relay therefore runs steps 1 to 4, parses the body and runs the chain check before steps 5 to 7.
- A recovery ID is in no machine group, so step 5 never blocks it.
- A request that fails a check changes no stored state, except the nonce of step 7.

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

## 10. HTTP API

This section gives the sync and setup surface routes of M9. Later milestones add routes under the same prefix ([VER-12]). Section 12 gives the user surface. Bodies are UTF-8 JSON with `content-type: application/json`. Binary fields are standard base64 with padding.

- The relay refuses a request body, or an object inside it, with a field that this section does not name (`bad_request`). The relay is upgraded before the engines ([VER-11]), so a newer engine never meets an older relay. The envelopes inside a body follow the looser rule of section 4.
- The engine ignores unknown fields in a response body ([VER-13]).
- The relay refuses a request on a route of this section that sends the session cookie `sf_session` of 12.4 (`bad_request`, [USR-7]). These routes take no browser session. This check runs before every other check of the route.
- The relay splits each `cookie` header value at `;` and removes the spaces around each part. The cookie name is the text before the first `=`. The relay ignores each other cookie, for example a cookie that a proxy sets and an HTTP client sends back.
- The bodies of 10.11 and 12.3 follow the strict JSON rules of section 3: no duplicate key, and integers only.

### 10.1 Routes

| Method | Path | Signed | Result |
| --- | --- | --- | --- |
| `GET` | `/v1/health` | No | `200` with `{"status":"ok"}` |
| `GET` | `/v1/info` | No | `200` with the info object (10.4) ([WIR-8]) |
| `POST` | `/v1/setup/token` | Yes, by the device of the keys in the body | Exchange an authorization code for a setup token (12.3) |
| `PUT` | `/v1/t/{tenant}/s/{log}` | Yes, by the device of the genesis record | Create the space with its genesis record and a setup token (10.5) |
| `POST` | `/v1/t/{tenant}/s/{log}/append` | Yes, by an active device | Append records (10.6) |
| `GET` | `/v1/t/{tenant}/s/{log}/entries?after={n}&limit={m}` | Yes, by an active device | Fetch entries after position `n` (10.7) |
| `POST` | `/v1/t/{tenant}/s/{log}/status` | Yes, by an active device | Report the verified tip during a restore hold (10.8) |
| `POST` | `/v1/t/{tenant}/s/{log}/device-status` | Yes, by an active device | Report the sync status of the device (10.11) |
| `POST` | `/v1/t/{tenant}/s/{log}/repair` | Yes, by a device that is active in the log or in the request entries | Start a repair session with the first chunk (10.9) |
| `POST` | `/v1/t/{tenant}/s/{log}/repair/chunk` | Yes, by the device of the session | Add a chunk to the repair session (10.9) |
| `POST` | `/v1/t/{tenant}/s/{log}/repair/finish` | Yes, by the device of the session | Move the staged entries into the log (10.9) |
| `POST` | `/v1/t/{tenant}/s/{log}/delete` | Yes, by an active device, or by the current recovery ID with a setup token | Delete the space (10.12) |
| `POST` | `/v1/t/{tenant}/s/{log}/import` | Yes, by the device of the setup token in the body | Start an import session with the first chunk (10.13) |
| `POST` | `/v1/t/{tenant}/s/{log}/import/chunk` | Yes, by the device of the session | Add a chunk to the import session (10.13) |
| `POST` | `/v1/t/{tenant}/s/{log}/import/finish` | Yes, by the device of the session if it is active at the tip, or by the current recovery ID at the tip | Make the space from the staged entries (10.13) |
| `POST` | `/v1/t/{tenant}/s/{log}/enroll` | Yes, by an active device | Open an enrollment session (10.10) |
| `GET` | `/v1/t/{tenant}/s/{log}/enroll/{session}` | Yes, by the device that opened the session | Read the session (10.10) |
| `POST` | `/v1/t/{tenant}/s/{log}/enroll/{session}` | Yes, by the device that opened the session | Write a message of the trusted device (10.10) |
| `GET` | `/v1/e/{session}` | No. The session ID is the credential. | Read the session (10.10) |
| `POST` | `/v1/e/{session}` | No. The session ID is the credential. | Write a message of the new device (10.10) |

- `{tenant}` is the tenant handle: `t_` and 32 lowercase hex digits (128 bits, [STO-10]).
- `{log}` is the log ID text (section 2.2).
- `{session}` is the session ID text (section 2.2).
- The relay finds the tenant only through the handle, and the space only through the space index of the tenant file ([STO-3]).
- Space creation and import need a device signature and a setup token ([USR-6]). A deletion by the recovery key needs a setup token ([LOG-13]).
- The relay limits the request rate for each IP address on `GET /v1/e/{session}`, `POST /v1/e/{session}` and `POST /v1/setup/token` (12.6).

### 10.2 Active devices

The space state after a log entry has these parts ([LOG-8]). Each record is judged against the state after the entry before it.

| Part | Rule |
| --- | --- |
| Active devices | The genesis record and each grant add a device. An epoch record removes each device in `removed`. A removed device never becomes active again. |
| Removed devices | Each device that an epoch record names in `removed`. |
| Current epoch | 1 after the genesis record. Each epoch record sets it to its `epoch`. |
| Current recovery ID | The recovery ID of the genesis record. Each recovery record sets it to the recovery ID of its `recovery` keys. |
| Device level | The `level` of the device object in the genesis record or the grant. A device record of that device sets it to its `level`. |
| Write level | The `level` of the genesis record. Each level record sets it to its `level`. |

The device of a genesis record signs the `PUT` request that creates the space.

A security record is a record of a type outside the `snailfish.change`, `snailfish.snapshot` and `snailfish.accept` families ([VER-5]). The genesis record, each grant, epoch, recovery, device and level record are security records.

### 10.3 Errors

Each error response has an HTTP status and this body:

```json
{"error":"<code>","message":"<text>"}
```

`message` is for people and has no fixed form. A reader uses `error` only.

| Code | HTTP status | Cause | Engine status |
| --- | --- | --- | --- |
| `bad_request` | 400 | The body, the query or the log ID breaks this section, or the relay cannot read the body | `paused: relay unavailable` |
| `bad_digest` | 400 | `content-digest` differs from the body | `paused: relay unavailable` |
| `bad_signature` | 401 | A signature header breaks section 8, or the signature does not verify | `paused: relay unavailable` |
| `expired` | 401 | The request is outside its time window (8.6 step 3) | Correct the clock offset and send again once, then `stopped: clock skew` |
| `nonce_reused` | 401 | The nonce was used before | `paused: relay unavailable` |
| `timeout` | 408 | The request did not end within the relay time limit. An append can still commit after this answer. | `paused: relay unavailable` |
| `bad_setup` | 403 | The authorization code is unknown, used, expired, or bound to another challenge or redirect URI (12.3), or the setup token is unknown, expired, or bound to another device or tenant (10.5) | Token exchange: the sign-in fails, and the app starts it again. Space creation: `stopped: setup failed`. The app signs in again and gives the engine the new setup token. |
| `blocked` | 403 | The user blocked the device of `keyid`, or a machine group that holds it, on the user page (8.6 step 5) | `paused: blocked` |
| `removed` | 403 | An epoch record removed the device of `keyid` (8.6 step 6) | `stopped: removed` |
| `unknown_device` | 403 | `keyid` names no active device of the space | `paused: relay unavailable`. On a fetch, if the verified log holds the grant of the device, the engine starts a repair first ([LOG-12], 10.9). |
| `unknown_tenant` | 404 | No tenant has the handle | `paused: relay unavailable` |
| `unknown_space` | 404 | The tenant has no space with the log ID | `paused: relay unavailable` |
| `deleted` | 410 | The tenant has no space with the log ID and holds a deletion marker for it ([LOG-13]). The relay returns it in place of `unknown_space`, and for a `PUT` of the log ID. | `stopped: deleted`. The engine sends no request for the space until the app opens it again. |
| `not_found` | 404 | No route has the path | `paused: relay unavailable` |
| `space_exists` | 409 | `PUT` with another genesis record for an existing log ID | `stopped: fork` |
| `unknown_session` | 404 | The relay holds no session with the ID that has not expired, or the session belongs to another device or space (10.10) | Enrollment: a new device that shows the session writes `new.hello` again until its own 10 minutes end. Each other device fails the enrollment. |
| `session_exists` | 409 | An open request names a session ID that the relay holds for another device or space (10.10) | The enrollment fails |
| `bad_step` | 409 | An enrollment message that is not the next message of the session (10.10) | The enrollment fails |
| `session_closed` | 409 | An enrollment message after the session ended (10.10) | The enrollment fails |
| `repair_busy` | 409 | Another device holds a repair session of the space that has not expired (10.9) | `paused: relay unavailable` |
| `bad_head` | 409 | The `head` of a deletion statement is not an entry of the relay log (10.12) | The engine fetches and signs the deletion again |
| `bad_import` | 409 | An import request that does not continue its session (10.13) | The import fails. The app starts it again. |
| `bad_repair` | 409 | The repair request does not continue the session: see 10.9 | `paused: relay unavailable`. The engine starts a new session at the next sync. For a repair from the position before the own grant ([LOG-12]), this code and `unknown_device`: `paused: repair needs another device`. |
| `invalid_record` | 422 | The genesis record of a `PUT` breaks 10.5, or a repair entry fails the chain check of 10.9 | `stopped: fork` |
| `uncovered_stub` | 422 | A repair entry is a stub that no usable snapshot of the staged range covers ([LOG-11]) | `stopped: fork` |
| `too_large` | 413 | The body is larger than `max_request_bytes`, or a repair body is larger than `max_request_bytes` + 1,024 bytes (10.9) | `degraded` |
| `rate_limited` | 429 | The IP address sent too many requests to a limited route (12.6) | `paused: relay unavailable`. A new device in enrollment waits and sends again. |
| `wrong_authority` | 421 | `snailfish-authority` differs from the relay configuration (8.6 step 1) | `paused: relay authority` |
| `internal` | 500 | A relay failure | `paused: relay unavailable` |
| `backup_running` | 503 | `PUT`, a deletion or an import request while `snailfish-relay backup` runs ([STO-8]) | `paused: relay unavailable` |
| `space_limit` | 507 | `PUT` or import of a new space when the tenant holds the most spaces that its configuration allows ([QTA-5]) | `stopped: setup failed`. The app tells the user to ask the relay operator. |
| `quota` | 507 | An import whose records do not fit the space quota and the reserves (10.13) | The import fails. The app tells the user to ask the relay operator. |

A response that is not JSON, or JSON without a string `error`, is a fault outside the relay, for example a proxy page. The engine reports `paused: relay unavailable`.

The append refusals of 10.6 are results inside a `200` response, not error responses.

### 10.4 `GET /v1/info`

```json
{"levels":[1],"limits":{"max_request_bytes":25165824,"max_change_bytes":65536,"max_snapshot_bytes":16777216,"max_append_envelopes":100,"max_fetch_entries":500},"time":1767225600}
```

| Field | Content |
| --- | --- |
| `levels` | The protocol levels that the relay accepts ([VER-6], [VER-11]) |
| `limits.max_request_bytes` | The largest request body, except for the repair allowance of 10.9. It is at least 4/3 x `max_snapshot_bytes` + 65,536, so one append body holds a snapshot of the largest size in base64 |
| `limits.max_change_bytes` | The largest decoded payload of a change record |
| `limits.max_snapshot_bytes` | The largest decoded payload of a snapshot record ([CMP-3]) |
| `limits.max_append_envelopes` | The most envelopes in one append request, and the most entries in one repair request |
| `limits.max_fetch_entries` | The most entries in one fetch response |
| `time` | The relay time, as in `snailfish-time` |

### 10.5 `PUT /v1/t/{tenant}/s/{log}`

Request body: `{"genesis":<envelope>,"setup":"st_..."}`. `setup` is the setup token of section 12.3. A body that is not this object, with a duplicate or unknown field or a malformed `setup`, gets `bad_request`. A `genesis` value that breaks section 4 or 6 gets `invalid_record`.

The relay runs 8.6 steps 1 to 4, then parses the body. It checks the genesis record: the envelope (section 4), the payload (section 6), the signature by the recovery key of the record, and `log` equal to `{log}`. The request signer must be the device of the record (8.6 steps 7 to 9). Then:

1. If the space exists with the same genesis record hash, return `200`. This is an exact retry, and the relay does not check the setup token.
2. If the space exists with another genesis record, return `space_exists`. If the tenant file holds a deletion marker for `{log}`, return `deleted` ([LOG-13]).
3. If the relay holds no setup token with the value of `setup`, or the token expired (relay time at or after its expiry), if the device ID of the token differs from the request `keyid`, or if the tenant of the token is not the tenant of `{tenant}`, return `bad_setup` ([USR-6]).
4. If the tenant holds the most spaces that its configuration allows, return `space_limit` ([QTA-5]).
5. If `snailfish-relay backup` runs, return `backup_running`.
6. Create the space file, with the genesis record at position 1.

A setup token works for each `PUT` of its device until it expires, so a lost response can be sent again.

The device that made the space holds its genesis record from the setup. If position 1 of the relay log has another record hash, the engine stops with `stopped: fork`.

| Result | Status | Body |
| --- | --- | --- |
| Created | 201 | `{"position":1,"digest":"<base64>"}` |
| The space exists with the same genesis record hash | 200 | `{"position":1,"digest":"<base64>"}`. This is an exact retry. |
| The space exists with another genesis record | 409 | Error `space_exists` |
| The setup token is not valid for the request | 403 | Error `bad_setup` |
| The tenant holds its most spaces | 507 | Error `space_limit` |
| The record is not valid | 422 | `{"error":"invalid_record","message":"..."}` |
| `snailfish-relay backup` runs | 503 | Error `backup_running`. The relay creates no space file. |

### 10.6 `POST /v1/t/{tenant}/s/{log}/append`

Request body: `{"envelopes":[<envelope>, ...]}`, with 1 to `max_append_envelopes` envelopes. An envelope is a JSON object in the form of section 4.

The relay checks and appends the envelopes in list order, in one transaction in the space file ([STO-11]). Each envelope gets one result. A refusal of one envelope does not stop the others. The response is `200`:

```json
{"results":[{"status":"stored","position":7},{"status":"known","position":3},{"status":"conflict","position":4},{"status":"refused","error":"bad_base"},{"status":"refused","error":"quota"}],"head":{"position":7,"digest":"<base64>"}}
```

The request `keyid` is an active device, or the current recovery ID of the space (section 13.4).

The relay checks each envelope in this order:

1. If the envelope or the payload breaks section 4 or 6, the result is `refused` with `invalid_record`.
2. If the log holds a change with the same `change_id` and the same record hash, in full or as a stub, the result is `known` with its position. If the record hash differs, the result is `conflict` with the position of the stored change ([WIR-6]). The relay checks this before every other refusal, so a stored change is never refused ([DLV-5], [DLV-7]).
3. If the space is on restore hold and the record is not a security record (10.2), the result is `refused` with `on_hold` ([LOG-14]).
4. If the decoded payload of a change is larger than `max_change_bytes`, or the decoded payload of a snapshot is larger than `max_snapshot_bytes`, the result is `refused` with `too_large`.
5. If `log` differs from `{log}`, the result is `refused` with `invalid_record`.
6. If `author` is a device ID that differs from the request `keyid`, the result is `refused` with `not_author`.
7. If `author` is a device ID that is not an active device, or a recovery ID that is not the current recovery ID of the space (10.2), the result is `refused` with `not_active`. For a device ID, step 6 and 8.6 step 7 make this step unreachable on the relay, except for a request by the recovery ID.
8. If the signature does not verify with the signing key of `author` (section 7.1), the result is `refused` with `invalid_record`. The signing key of the current recovery ID is the `recovery.sign` key of the genesis record or of the last recovery record.
9. If the base is not position 1 or later, or not before the new position, or its digest differs from the log digest at that position, the result is `refused` with `bad_base` ([LOG-6]).
10. If the record is a security record and the log holds a security record after its base, the result is `refused` with `stale_base` ([LOG-7]). Changes after the base do not cause this refusal.
11. If the set of the write level does not hold the record type (section 6.2), the result is `refused` with `unsupported` ([VER-9]). A level record or a device record with a level above the highest level of the relay is also `unsupported`.
12. If a change or a snapshot names an epoch other than the current epoch, the result is `refused` with `wrong_epoch`.
13. If the record breaks the state rule of its type, the result is `refused` with `invalid_record`:
    - A grant names a device that is active or removed, or a level below the write level, or its key set does not hold each needed epoch (14.5), or it holds an epoch above the current epoch.
    - An epoch record: `epoch` is not the current epoch plus 1, a device in `removed` is not active, `removed` holds the author, `stay` differs from the active devices without `removed`, or the key set to a recovery ID is not to the current recovery ID.
    - A recovery record: the new recovery ID is the current recovery ID or an earlier one, or its key set does not hold each needed epoch (14.5), or it holds an epoch above the current epoch.
    - A snapshot: the state position is not before the new position, or `state.digest` differs from the log digest at the state position ([CMP-3]).
    - An accept record: the log does not hold a snapshot record, in full or as a stub, at `snapshot.position` with the record hash `snapshot.hash`, or `applied` is after the base position, or `applied.digest` differs from the log digest at `applied.position`. An applied position of 0 has `digest(0)`.
    - A device record: `level` is not above the device level of the author.
    - A level record: `level` is not above the write level, or an active device has a device level below `level` ([VER-8]).
14. If the record is a security record, and the stored security record bytes of the space plus the byte length of its envelope JSON exceed the security record reserve, the result is `refused` with `reserve` ([STO-15]). The reserve is 16 MiB (16,777,216 bytes) by default. The relay operator can raise it.
15. If the record is a security record, and the request `keyid` sent 10 security records that the relay stored in this space in the current relay day, the result is `refused` with `security_limit` ([STO-15]). A relay day is the relay time divided by 86,400, rounded down.
16. If the record is a change, and the stored bytes of the space plus the byte length of its envelope JSON exceed the space quota, the result is `refused` with `quota` ([QTA-1]). If the record is a snapshot or an accept record, the limit is the space quota plus the snapshot reserve of 14.6 ([CMP-18]). The byte length of an envelope is the length of its JSON text exactly as the request holds it, which is also the text that the relay stores (10.7). The stored bytes are the sum of these lengths for every change, snapshot and accept record that the log holds in full, also a record that an earlier envelope of the same request stored. Security records and stubs do not count, and this step never refuses a security record ([QTA-3], [CMP-19]).
17. Otherwise the relay appends the record at the next position. Positions are dense ([LOG-1]). The relay stores the log digest of the new entry (section 5). The result is `stored` with the position.

After the last envelope, in the same transaction, the relay replaces each record that the usable snapshot covers with a stub (14.4, [CMP-12]).

- `head` is the last position and its log digest after the transaction.
- A known envelope earlier in the same request counts: a second copy in one request is `known`.
- `bad_base`, `stale_base`, `on_hold`, `quota`, `reserve`, `security_limit` and `wrong_epoch` are transient. Each other refusal is permanent for that envelope ([DLV-9]).
- After `reserve` or `security_limit`, the engine keeps the record and reports `paused: relay unavailable` (T10). It sends the record again at the next sync.
- After `wrong_epoch` for an own change, the engine fetches. If the verified epoch is above the epoch of the change, the engine encrypts the change again with the current key and the same `change_id`, signs it on the verified head and sends it ([DLV-7]). Step 2 runs before step 12, so the relay does not hold the old envelope.
- After `quota`, the engine keeps the envelope in its outbox, reports `paused: quota`, and sends it again at each later sync ([QTA-4]). The relay serves fetches at a full quota ([QTA-2]).
- After `on_hold`, the engine keeps the envelope in its outbox and reports `paused: restore hold`. It sends the envelope again after the hold ends.
- After `stale_base`, the engine fetches and checks the space state again ([LOG-7]). If the verified log holds a grant for the device of a refused grant, the engine drops the refused grant. Otherwise, if the active devices equal the list that the user confirmed, the engine signs the grant again with a new base. Otherwise it asks the user to confirm again. A grant that the recovery key signed needs the recovery key again, so the engine always asks for it.
- The engine applies steps 5 and 7 to 13 to each fetched record, with the highest level of the engine in step 11. A snapshot that fails the size limit of step 4 is valid, but the engine does not import it and reports `degraded`. A fetched record that fails one of them stops the engine with `stopped: fork` ([FRK-1]). The engine verifies the signature (step 8) before it changes any state for the record ([WIR-2]).
- The engine splits its envelopes into requests that fit `max_append_envelopes` and `max_request_bytes`. A change whose append body alone is larger than `max_request_bytes` is refused for ever with `too_large`, and the engine does not send it ([DLV-9]).

### 10.7 `GET /v1/t/{tenant}/s/{log}/entries`

The request `keyid` is an active device, or the current recovery ID of the space (section 13.4).

Query: `after` (integer from 0) and `limit` (integer from 1 to `max_fetch_entries`). Both are required, in this order, as decimal integers with no leading zero.

```json
{"entries":[{"position":1,"envelope":{"payloadType":"...","payload":"...","signatures":[{"keyid":"...","sig":"..."}]}},{"position":12,"stub":{"type":"snailfish.change.v1","change_id":"c_...","hash":"<base64>"}}],"head":{"position":12,"digest":"<base64>"},"has_more":false,"hold":false}
```

- `entries` holds the entries from position `after + 1`, in position order, with no gap, at most `limit` entries.
- An entry holds the stored envelope in full, or a stub (section 14). A stub has `type`, `change_id` (only for a change) and `hash`, the record hash ([CMP-1]).
- The relay sends each envelope object as it stored it. The record hash does not depend on the layout ([WIR-3]).
- `head` is the last position of the log and its log digest. `has_more` is true if the log holds entries after the last entry of the response.
- `hold` is true while the space is on restore hold ([LOG-14]). The relay always sends `hold`. A reader treats a missing `hold` as false.
- If `after` is the head position or later, `entries` is empty. The engine compares `head` with its verified log:

| Relay `head` | Engine action |
| --- | --- |
| After the verified head | Fetch the next page |
| Equal to the verified head, same digest | Caught up |
| Before the verified head, and the digest equals the verified digest at that position | Repair session (10.9, [LOG-10]) |
| Any other digest | `stopped: fork` ([FRK-1]) |

### 10.8 `POST /v1/t/{tenant}/s/{log}/status`

Request body:

```json
{"tip":{"position":12,"digest":"<base64>"},"fresh":true}
```

| Field | Content |
| --- | --- |
| `tip` | The verified head of the device: position (integer from 0) and log digest. Position 0 has `digest(0)`. |
| `fresh` | True if the engine state file of the device is new since the last fetch that reached the relay head with no hold ([LOG-14], F3 in `specs/delivery/README.md`) |

The response is `200` with `{"hold":true}` or `{"hold":false}`.

- During a restore hold, the engine sends a status report in each sync, after the repair session and before the append requests.
- During a hold, the relay stores the report for the device and the relay time. A new report replaces the tip of the device. The `fresh` mark of a device stays until the hold ends, also if a later report has `fresh` false.
- When the relay reads the reports, for example for `snailfish-relay hold-status`, it reads a stored tip as "reported" if the log holds the tip position with the same digest at that time. A tip at position 0 with `digest(0)` is reported. A tip after the head means that the device did not repair yet. A later repair by another device can make a stored tip "reported".
- Without a hold, the relay stores nothing and answers `{"hold":false}`. A body that breaks this section gets `bad_request` also without a hold.
- A fetch does not end the `fresh` mark. The engine clears its `fresh` flag only after a fetch that reaches the relay head with `hold` false.

### 10.9 Repair session

A device repairs the log if the relay log ends before its verified head and the relay head digest equals the verified digest at that position ([LOG-10]). The device uploads its copies of the lost entries, in position order, in chunks. The relay keeps them in a staging table in the space file, outside the space quota, and moves them into the log after the last chunk ([LOG-11]).

An entry has the form of a fetch entry (10.7): `{"position":n,"envelope":<envelope>}` or `{"position":n,"stub":<stub>}`.

Start: `POST /v1/t/{tenant}/s/{log}/repair`

```json
{"base":{"position":4,"digest":"<base64>"},"entries":[{"position":5,"envelope":{...}},{"position":6,"envelope":{...}}]}
```

Chunk: `POST /v1/t/{tenant}/s/{log}/repair/chunk`

```json
{"session":"00112233445566778899aabbccddeeff","entries":[{"position":7,"envelope":{...}}]}
```

Finish: `POST /v1/t/{tenant}/s/{log}/repair/finish`

```json
{"session":"00112233445566778899aabbccddeeff","tip":{"position":7,"digest":"<base64>"}}
```

| Route | Result | Body |
| --- | --- | --- |
| Start | 201 | `{"session":"<32 hex digits>","next":7}` |
| Chunk | 200 | `{"next":8}` |
| Finish | 200 | `{"head":{"position":7,"digest":"<base64>"}}` |

- `entries` holds 1 to `max_append_envelopes` entries.
- A repair body is at most `max_request_bytes` + 1,024 bytes. The engine fills a chunk up to `max_request_bytes`, and sends an entry that does not fit alone. The allowance covers the wrapper of one entry, because each envelope fit in an append body before.
- `session` is 16 random bytes from the relay, as 32 lowercase hex digits. `next` is the position after the last staged entry.
- A space has at most one repair session. A start replaces a session of the same device, and a session that expired. The relay deletes the staged entries of a replaced session.
- A session expires 86,400 seconds after its start or its last chunk: at a relay time of that time + 86,400 or later.

The relay checks the body size first, as for every route (10.3 `too_large`). Then it checks a start request in this order:

1. 8.6 steps 1 to 4.
2. If the body breaks this section, return `bad_request`.
3. If the base equals the relay head (position and digest), run the chain check, entry by entry, until the first failure. Otherwise no entry passes. Each entry must have the next position after the base or after the entry before it. An envelope must pass steps 1, 2, 5 and 7 to 13 of 10.6 against the log and the entries before it, with step 2 as for a fetched record: a known `change_id` fails the check. The size limit of step 4 and the hold of step 3 do not apply, because the record was in the log before. A stub of a change or a snapshot passes this step: the relay computes its entry hash and digest from the stub fields. A stub of each other type fails with `uncovered_stub`. The finish checks each staged stub ([LOG-11]).
4. 8.6 steps 5 to 9. Step 7 accepts a device that is active in the log or in the entries that passed step 3 ([LOG-12]).
5. If the base differs from the relay head (position or digest), return `bad_repair`.
6. If another device holds a session that has not expired, return `repair_busy`.
7. If an entry failed step 3, return the error of that entry: `invalid_record`, `uncovered_stub`, or `bad_repair` for a wrong position.
8. Otherwise create the session and stage the entries.

A chunk request uses the same order. In step 3, the chain continues the staged entries of the named session if the relay holds that session and the relay head did not change since its start. Otherwise no entry passes. Step 4 also accepts a device that the staged entries of the named session make active, also if the session expired or belongs to another device. Step 5 is: if the session is unknown or expired, if the request signer is not the device of the session, or if the relay head changed since the start, return `bad_repair`. Step 6 does not apply. The first entry must have the position `next`.

A finish request runs 8.6 steps 1 to 4, returns `bad_request` for a body that breaks this section, and runs 8.6 steps 5 to 9 with the keys of the log and the staged entries of the named session. Then:

1. If the session is unknown or expired, if the request signer is not the device of the session, or if the relay head changed since the start, return `bad_repair`.
2. If `tip` differs from the last staged entry (position or digest), return `bad_repair`.
3. If a staged stub fails the stub check of 14.3 against the log with the staged entries, return `uncovered_stub` ([LOG-11], [CMP-17]).

4. Move the staged entries into the log in one transaction, end the session and delete its staged entries. Then replace each covered record with a stub (14.4). The response holds the new head.

- A request that fails a check changes no stored state, except the nonce of 8.6 step 9.
- The chain check runs before the request signature check, so a caller that knows the tenant handle and the log ID can make the relay verify up to `max_append_envelopes` record signatures for one request. The tenant handle has 128 random bits ([STO-10]).
- A security record that a device appends during a hold moves the head and ends each repair session with `bad_repair`. The next fetch of the repairing device then finds an entry that conflicts with its verified log, and the engine stops with `stopped: fork` (DESIGN.md T7 limit, `specs/epochs/test.qnt::removalDuringHoldCanForkTest`).
- The relay accepts repair sessions during a restore hold ([LOG-14]).
- The finish request names the tip, so the relay moves the entries only if they end at the verified head of the device ([LOG-10]).
- If a chunk response is lost, the next chunk gets `bad_repair`, and the engine starts a new session.

A device whose grant is only in the lost range gets `unknown_device` on a fetch, so it cannot read the relay head ([LOG-12]). If its verified log holds its own grant at position g, the engine starts a repair with the base `g - 1` and its digest, and the entries from g to the verified head. If the relay head is another position, the chain check of start step 3 passes no entry, so the relay answers `unknown_device` (step 4) or `bad_repair` (step 5). The engine then reports `paused: repair needs another device`. A device that is active in the relay log must then repair it.

If the verified log holds no grant of the device, for example after a relay restore before the first fetch of a new device, the engine reports `paused: relay unavailable`. The device must enroll again.

### 10.10 Enrollment session

An enrollment session is a mailbox on the relay for the messages of section 11 ([ENR-1] to [ENR-8]). The trusted device opens it on its signed route and so binds it to its tenant and its space ([ENR-2]). The new device has no key that the relay knows. It uses the session ID as its only credential.

Open: `POST /v1/t/{tenant}/s/{log}/enroll`

```json
{"session":"e_00112233445566778899aabbccddeeff"}
```

| Result | Status | Body |
| --- | --- | --- |
| Opened | 201 | `{"expires":1767226200}` |
| The relay holds the session for the same device and space | 200 | `{"expires":1767226200}`, the stored value. This is an exact retry, also when the session is done or cancelled. |
| The relay holds the session for another device or space | 409 | Error `session_exists` |

The relay checks an open request in this order: 8.6 steps 1 to 4, `bad_request` for a body that breaks this section, 8.6 steps 5 to 9, then the session ID.

- `expires` is the relay time of the open plus 600 seconds. At a relay time of `expires` or later, the session does not exist for any route, and each route returns `unknown_session`. The relay deletes expired sessions.
- A session works once. A session ID cannot be opened again before it expires, and a session takes one message for each step.

Messages. Each session has six message slots. They take a message in this order:

| Order | Slot | Writer | Body of the write request |
| --- | --- | --- | --- |
| 1 | `new.hello` | new device | `{"hello":{"device":<device object>}}` |
| 2 | `trusted.hello` | trusted device | `{"hello":{"keys":<keys object>,"commitment":"<base64>"}}` |
| 3 | `new.nonce` | new device | `{"nonce":"<base64>"}` |
| 4 | `trusted.nonce` | trusted device | `{"nonce":"<base64>"}` |
| 5 | `new.confirm` | new device | `{"confirm":<envelope>}` |
| 6 | `trusted.done` | trusted device | `{"done":{"tenant":"t_...","checkpoint":<envelope>}}` |

- Either writer can also send `{"cancel":true}`.
- The new-device route accepts only `hello`, `nonce`, `confirm` and `cancel` bodies of the new device. The trusted route accepts only `hello`, `nonce`, `done` and `cancel` bodies of the trusted device. Each other body breaks this section.
- The device and keys objects are the objects of section 6.1, with the same rules. `commitment` and each nonce are 32-byte binary values.
- A body with a duplicate key at any depth breaks this section, as for an envelope (section 4). A device refuses such a session object too.
- `confirm` holds a `snailfish.confirm.v1` envelope, and `checkpoint` a `snailfish.checkpoint.v1` envelope (section 6.3). The relay checks only the envelope form of section 4, not the `payloadType` or the payload. The devices check the content (section 11).
- `tenant` must equal `{tenant}` of the request path. Otherwise the body breaks this section. The session belongs to the space of the path (step 4), so the check needs no session.

The new device writes with `POST /v1/e/{session}`, and the trusted device with `POST /v1/t/{tenant}/s/{log}/enroll/{session}`. The relay checks a write in this order:

1. For the trusted route: 8.6 steps 1 to 4.
2. If the body breaks this section, return `bad_request`.
3. For the trusted route: 8.6 steps 5 to 9.
4. If the relay holds no session with the ID that has not expired, return `unknown_session`. For the trusted route, also return `unknown_session` if the session belongs to another device or space.
5. If the slot of the message holds the same JSON value, return `200` with the session object. This is an exact retry, also after the session is done or cancelled. A cancel by either writer when the session is cancelled is also an exact retry.
6. If the session is done or cancelled, return `session_closed`.
7. If the message is a cancel, mark the session cancelled. Otherwise, if its slot is not the next empty slot of the order, return `bad_step`.
8. Store the message. A `done` message marks the session done. The response is `200` with the session object.

Read: `GET /v1/e/{session}`, or the signed `GET /v1/t/{tenant}/s/{log}/enroll/{session}`. The relay checks a read with steps 1, 3 and 4 above. The response is `200` with the session object:

```json
{"session":"e_...","expires":1767226200,"state":"open","new":{"hello":{...},"nonce":"<base64>"},"trusted":{"hello":{...}}}
```

| Field | Content |
| --- | --- |
| `state` | `open`, `done` or `cancelled` |
| `new`, `trusted` | An object with each slot of that writer that holds a message: `hello`, `nonce`, and `confirm` or `done`. The relay always sends both fields, as `{}` for a writer with no message. It sends each message as it stored it. |

- An exact retry compares the parsed JSON values, so a retry with another key order or other whitespace is an exact retry.
- The unsigned routes send only the session object. It holds the tenant handle and the log ID after the `done` message.
- The session ID has 128 random bits, and the QR code and the typed code hold no secret (T6).

Limits:

- A party that knows the session ID can read the session until it expires, so it can learn the tenant handle and the log ID. It can then ask 8.6 step 7 whether a device ID is active. Each request still needs a device signature, so it can do nothing else with them (T11).
- A party that knows the session ID can write a slot of the new device before the new device does, or cancel the session. A device that is active in another space on the relay can also open a scanned session ID first (`session_exists`). In each case the codes differ, or the session takes no more messages, and the enrollment fails. The user starts a new session.

### 10.11 `POST /v1/t/{tenant}/s/{log}/device-status`

The engine sends its status after each sync, as the last request of the sync (DESIGN.md "Monitoring and alerting" item 6). The user page shows it (section 12.4).

- A sync that a refusal stops also sends the report, if the device stays active in the space: a fork, or `too_large`. After any other refusal, the relay would refuse the report too.
- The engine skips a report that equals its last accepted report, if that report is less than 3600 seconds old in corrected time (8.5). The stall rule (DESIGN.md "Monitoring and alerting" item 7) reads the report time, so an idle device still reports once an hour.

Request body:

```json
{"state":"ok","outbox":2,"oldest":1767225000,"applied":12,"epoch":1}
```

| Field | Content |
| --- | --- |
| `state` | The sync status text of the engine, for example `ok`, `degraded` or `paused: quota`. 1 to 64 bytes of printable ASCII (0x20 to 0x7E). |
| `outbox` | The number of own changes that the engine holds and the verified log does not hold yet |
| `oldest` | The relay time of the oldest of these changes, in Unix seconds, from the corrected device clock (8.5). `null` if `outbox` is 0. |
| `applied` | The position of the applied position that the app gave in its last `changes_after` call (DESIGN.md "App integration"), an integer from 0. The engine keeps it in its state file. 0 before the first call. |
| `epoch` | The current epoch of the device, an integer from 1 |

The response is `200` with `{}`.

- The relay runs 8.6 steps 1 to 4, returns `bad_request` for a body that breaks this section, and runs 8.6 steps 5 to 9.
- `oldest` is `null` exactly when `outbox` is 0. Otherwise the body breaks this section.
- The relay stores the last report of each device in the tenant file, with the relay time of the report. A new report replaces the old one.
- The relay also takes reports during a restore hold.

### 10.12 `POST /v1/t/{tenant}/s/{log}/delete`

A trusted device or the recovery key deletes the space on the relay ([LOG-13]). The deletion removes the relay copy only. Devices keep their logs, and an import (10.13) makes the space again.

Request body from a device: `{"statement":<envelope>}`. From the recovery key: `{"statement":<envelope>,"setup":"st_..."}`, with the setup token of 12.3. `statement` is a `snailfish.delete.v1` statement (6.3).

The relay checks a deletion in this order:

1. 8.6 steps 1 to 4.
2. If the body breaks this section, return `bad_request`. A body from a device ID `keyid` with `setup`, or from a recovery ID `keyid` without `setup`, breaks this section.
3. 8.6 steps 5 to 9. Step 7 accepts the current recovery ID.
4. If `statement` breaks section 4 or 6, if it is not a `snailfish.delete.v1` statement, if its `log` differs from `{log}`, if its `author` differs from `keyid`, or if its signature does not verify with the signing key of `author`, return `invalid_record`.
5. For a recovery ID: if the relay holds no setup token with the value of `setup`, if the token expired, or if the tenant of the token is not the tenant of `{tenant}`, return `bad_setup`. The token can name any device of the tenant, because the recovery key signs the request.
6. If `head.position` is after the relay head, or the log digest at `head.position` differs from `head.digest`, return `bad_head`. Position 0 with `digest(0)` is an entry of each log.
7. If `expires` is at or before the relay time, or more than 600 seconds after it, return `expired`.
8. If `snailfish-relay backup` runs, return `backup_running`.
9. In one transaction in the tenant file, write the deletion marker of `{log}`, and delete its row in the space index, its restore hold, its hold reports and its device status rows. Then delete the space file and its WAL files ([STO-5]).

The response is `200` with `{"deleted":true}`.

- After the deletion, each route of the log ID returns `deleted` (10.3), and a `PUT` of the log ID returns `deleted` (10.5). An import of the log ID removes the marker.
- The engine signs `head` with its verified head. After a fork, the verified head of a device can be outside the relay log. The device then signs the last position that it shares with the relay, the relay operator deletes the space with `snailfish-relay space delete`, or the user moves to another relay (DESIGN.md "Fork repair").
- `expires` limits the time in which a copy of the statement can delete the space. The request nonce stops an exact replay.

### 10.13 Import session

A device or the recovery key imports an export file (section 15) into a space that the relay does not hold, on the same relay after a deletion or on another relay ([FRK-5]). The device uploads the entries in position order from position 1, in chunks, as in a repair session (10.9). The relay writes them into a temporary space file, and makes the space only at the finish ([STO-6]).

Start: `POST /v1/t/{tenant}/s/{log}/import`

```json
{"setup":"st_...","device":{"sign":"<base64>","seal":"<base64>"},"entries":[{"position":1,"envelope":{...}},{"position":2,"envelope":{...}}]}
```

Chunk: `POST /v1/t/{tenant}/s/{log}/import/chunk`

```json
{"session":"00112233445566778899aabbccddeeff","entries":[{"position":3,"stub":{...}}]}
```

Finish: `POST /v1/t/{tenant}/s/{log}/import/finish`

```json
{"session":"00112233445566778899aabbccddeeff","tip":{"position":3,"digest":"<base64>"}}
```

| Route | Result | Body |
| --- | --- | --- |
| Start | 201 | `{"session":"<32 hex digits>","next":3}` |
| Chunk | 200 | `{"next":4}` |
| Finish | 201 | `{"head":{"position":3,"digest":"<base64>"}}` |

- `entries` holds 1 to `max_append_envelopes` entries in the form of 10.9. The body size rule of 10.9 applies.
- `session` is 16 random bytes from the relay. `next` is the position after the last staged entry. A session expires 86,400 seconds after its start or its last chunk.
- A tenant has at most one import session for each log ID. A start replaces an older session of the same log ID, and deletes its temporary file.
- `device` is the keys object (6.1) of the device that signs the start and each chunk. Its device ID must be the device of the setup token. The relay verifies these requests with its `sign` key, because the staged entries can grant the device only at a later position.

The relay checks a start request in this order:

1. 8.6 steps 1 to 4.
2. If the body breaks this section, return `bad_request`.
3. If the device ID of `device` differs from `keyid`, return `bad_request`. If the relay holds no setup token with the value of `setup`, if the token expired, if the device ID of the token differs from `keyid`, or if the tenant of the token is not the tenant of `{tenant}`, return `bad_setup`.
4. 8.6 steps 5, 8 and 9, with the `sign` key of `device`.
5. If the tenant holds a space with the log ID, return `space_exists`. If the tenant holds the most spaces that its configuration allows, return `space_limit`. If `snailfish-relay backup` runs, return `backup_running`.
6. Run the chain check from position 0 with `digest(0)` of `{log}` and an empty space state. Position 1 must hold a genesis record that passes the checks of 10.5, with `log` equal to `{log}`. Each later entry passes the repair chain check of 10.9 start step 3 against the entries before it. A security record also passes 10.6 step 14 against the entries before it, and a change, a snapshot or an accept record passes 10.6 step 16 with the quota of the tenant. 10.6 step 15 does not apply, because the records were stored before. If an entry fails, return `invalid_record`, `uncovered_stub`, `bad_import` for a wrong position, or `quota` for steps 14 and 16.
7. Create the temporary space file and the session, and stage the entries.

A chunk request uses the same order without steps 3 and 5. Before step 4: if the session is unknown or expired, return `bad_import`. In step 4, the relay uses the device and the `sign` key of the named session, so each other `keyid` gets `unknown_device`. The first entry must have the position `next`, and the chain continues the staged entries.

A finish request runs 8.6 steps 1 to 4, returns `bad_request` for a body that breaks this section, and then:

1. If the session is unknown or expired, return `bad_import`.
2. 8.6 steps 5, 8 and 9. The signer is the device of the session if it is active at the tip of the staged entries, or the current recovery ID at that tip. Each other `keyid` gets `unknown_device`.
3. If `tip` differs from the last staged entry (position or digest), return `bad_import`.
4. If a staged stub fails the stub check of 14.3 against the staged entries, return `uncovered_stub`.
5. If the tenant holds a space with the log ID, return `space_exists`. If the tenant holds the most spaces that its configuration allows, return `space_limit`. If `snailfish-relay backup` runs, return `backup_running`.
6. In one transaction in the tenant file, add the space index row with the app ID of the genesis record, remove the deletion marker of the log ID, and delete the session. Then rename the temporary file to its space file name ([STO-6]). The space is not on restore hold.

- A request that fails a check changes no stored state, except the nonce of 8.6 step 9.
- An import ends no repair session and no enrollment session, because the relay holds no space with the log ID during the import.
- The relay does not replace covered records with stubs at the finish. A covered record of the file stays in full until the next append or repair.
- After the finish, the source device syncs as before. Each other device of a fork repair enrolls again ([FRK-6]). For a move to another relay, each other device signs in on the new relay and syncs with its own state file, because its verified log is the same.

## 11. Enrollment

This section gives the transcript of DESIGN.md "Enrollment" ([ENR-1] to [ENR-9]). `specs/enrollment/` checks it in a symbolic model.

### 11.1 Session code and payload

One device makes a session ID of 16 random bytes and shows it. Either device can show it ([ENR-1]).

```text
check   = first 4 bytes of SHA-256(frame("snailfish.enroll-check.v1", session))
symbols = Crockford base32 of (session || check), 20 bytes, most significant bit first
display = the 32 symbols in 8 groups of 4, joined with "-"
payload = "snailfish-enroll-v1" SP role SP relay_url SP symbols
```

- The typed code is `display`. A reader of the typed code follows the five reader steps of section 9, with this check.
- The QR code holds the payload. `role` is `t` if the trusted device shows it and `n` if the new device shows it. `relay_url` is `http://` or `https://` and the authority of section 8.3: the host in lowercase, and the port only if it is not the default port of the scheme, with no path, no trailing `/`, no query and no user part. `symbols` has no `-`.
- A payload reader refuses another first part, another role, a relay URL that breaks the rule above, or a part count other than 4. It reads `symbols` with the reader steps of section 9, so lowercase symbols are valid.
- The device that reads a payload refuses it if `role` names its own role. A trusted device also refuses a payload with another relay URL than its own.
- A device that reads a typed code uses its own relay URL.

### 11.2 Transcript

`t_id` is the device ID of the trusted device, and `n_id` the device ID of the new device (section 2.2). Each nonce is 32 random bytes from the operating system CSPRNG.

```text
commitment = SHA-256(frame("snailfish.enroll-commit.v1", session, "trusted", t_id, "new", n_id, t_nonce))
digits     = SHA-256(frame("snailfish.enroll-code.v1", session, "trusted", t_id, "new", n_id, t_nonce, n_nonce))
n          = the first 8 bytes of digits, read as an unsigned big-endian integer
code       = n mod 1000000, as 6 decimal digits with leading zeros
```

`session` is the 16 bytes of the session ID. `"trusted"` and `"new"` are the role labels, as ASCII parts of the frame.

| Step | Device | Action |
| --- | --- | --- |
| 1 | Shows the code | Makes the session ID ([ENR-1]). |
| 2 | Trusted | Opens the session on its signed route (10.10, [ENR-2]). A trusted device that shows the code shows it only after the open, so a new device that reads it finds the session. |
| 3 | New | Writes `new.hello` with its device object: keys, name and highest protocol level ([ENR-3]). |
| 4 | Trusted | Reads `new.hello`. If the level is below the space write level, cancels and asks the user to update the new device. If the device is active, cancels. Otherwise makes `t_nonce` and writes `trusted.hello` with its keys and the commitment ([ENR-3], [ENR-4]). |
| 5 | New | Reads `trusted.hello`, makes `n_nonce` and writes `new.nonce` ([ENR-5]). |
| 6 | Trusted | Reads `new.nonce` and writes `trusted.nonce` with `t_nonce` ([ENR-6]). |
| 7 | New | Reads `trusted.nonce` and computes the commitment. If it differs from `trusted.hello`, cancels. |
| 8 | Both | Show the code. The user compares the codes on both devices. If the user reports a mismatch on either device, that device cancels ([ENR-7]). |
| 9 | New | After the user confirms the match, writes `new.confirm` with a `snailfish.confirm.v1` envelope that it signs ([ENR-7]). |
| 10 | Trusted | After the user confirms the match, reads `new.confirm` and checks it (below). Appends the grant with the [LOG-7] retry of 10.6, fetches until the verified log holds the grant, signs a checkpoint at its verified head, and writes `trusted.done` with the checkpoint and its tenant handle ([ENR-8]). |
| 11 | New | Reads `trusted.done` and checks the checkpoint (below). Then it creates its engine state and fetches the log ([ENR-9]). |

The trusted device accepts a confirmation only if:

- the envelope and the payload follow sections 4 and 6.3, and the signature verifies with `device.sign`,
- `session` is the session ID, `trusted` is `t_id`, and `device` equals the device object of `new.hello`, field by field,
- `trusted_nonce` is `t_nonce` and `new_nonce` is the value of `new.nonce`.

The grant names the device object of `new.hello`. The trusted device signs it with its device key, or with the recovery key that the user types (DESIGN.md "Space log"). The key set seals the keys of each epoch to the new device (section 7.3).

The new device accepts `trusted.done` only if the checkpoint envelope and payload follow sections 4 and 6.3, `author` is `t_id`, and the signature verifies with the signing key of `trusted.hello`. The `log` of the checkpoint names the space, and `tenant` the tenant handle.

The new device then verifies the log from position 1 ([ENR-9]). It uploads nothing, and sends no status report or repair request, until each check passes:

- each entry up to the checkpoint position passes the checks of 10.6,
- the log digest at the checkpoint position equals the checkpoint `digest`,
- the log up to the checkpoint position holds a grant for `n_id` with the device object of `new.hello`,
- `t_id` is active at the checkpoint position.

If a check fails, the engine stops with `stopped: fork`. After the checks pass, the engine opens its key set from the grant and checks each key against its commitment (section 7.3).

- Neither device uses data from the session before the user confirms the match (T6).
- A session takes one message for each slot, so a relay that substitutes keys gets one guess at the code for each session. The trusted device commits to its nonce before the new device sends its nonce, so a relay cannot choose a nonce that makes the two codes equal.
- The code reduction `mod 1000000` has a bias below 2^-44 for each value.

## 12. User and setup surface

The relay serves the user page and the native sign-in under `/u/` (DESIGN.md "Interfaces", [USR-1] to [USR-8]). The page is HTML for a browser, so this section fixes its security rules and its JSON routes, not its HTML. The setup routes of section 10 (`POST /v1/setup/token`, `PUT /v1/t/{tenant}/s/{log}`) take the setup token of 12.3.

### 12.1 Invite links

`snailfish-relay user add <name>` creates a user and its tenant. `snailfish-relay user invite <name>` makes a new link for a user. Each prints the link:

```text
<origin>/u/invite#it_<64 hex digits>
```

- `<origin>` is the configured user page origin (12.4). The token is in the fragment, so a browser does not send it in a request line or a `Referer` header. The script of the invite page reads it.
- The relay stores SHA-256 of the 32 token bytes, the user ID and the expiry time, the relay time of the command plus 604,800 seconds ([USR-1]).
- A user has at most one invite. A new link replaces the old one. It also removes every passkey, every browser session, every authorization code and every setup token of the user, in the same transaction ([USR-2]).
- A link works once: the registration that uses it deletes it, in the transaction that stores the passkey.

### 12.2 Native sign-in: authorization code

The app opens the system browser at:

```text
<origin>/u/authorize?response_type=code&code_challenge=<challenge>&code_challenge_method=S256&redirect_uri=<uri>&state=<state>
```

| Parameter | Rule |
| --- | --- |
| `response_type` | `code` |
| `code_challenge` | `BASE64URL(SHA-256(ASCII(code_verifier)))`, without padding: 43 characters (RFC 7636 section 4.2). The last character carries no non-zero trailing bits, so each 32-byte hash has one form. |
| `code_challenge_method` | `S256` |
| `redirect_uri` | A redirect URI of the form below, percent-encoded as a query value. The relay decodes the value once, checks the decoded URI and stores the decoded URI. |
| `state` | 1 to 128 characters of `A-Z a-z 0-9 - . _ ~`, chosen by the app |

- The relay decodes each name and value as `application/x-www-form-urlencoded`: `+` is a space and `%XX` is a byte.
- Each parameter occurs once, in any order. The relay refuses another parameter, a missing parameter and a value that breaks its rule. It then shows an error page and does not redirect, because the redirect URI is not checked.
- `code_verifier` is 43 to 128 characters of `A-Z a-z 0-9 - . _ ~` (RFC 7636 section 4.1). The engine makes it from 32 random bytes in base64url without padding.

A redirect URI is at most 512 bytes, with no query, no fragment and no user part, in one of these forms (RFC 8252 section 7):

| Form | Rule |
| --- | --- |
| Loopback | `http://127.0.0.1:<port><path>` or `http://[::1]:<port><path>`. `<port>` is a decimal from 1 to 65535 with no leading zero. `<path>` starts with `/`. |
| Private-use scheme | `<scheme>:/<path>`. `<scheme>` is lowercase `a-z 0-9 + - .`, starts with a letter and holds at least one `.`, for example `com.example.tasks:/callback`. `<path>` does not start with `/`, so the URI has no authority part. `<path>` can be empty. |

`<path>` holds only the characters `A-Z a-z 0-9 - . _ ~ / %`, and each `%` starts a percent-encoded byte with two uppercase hex digits.

If the browser has no session, the page asks the user to sign in first (12.4). With a session, the page shows the request and an "Allow" button. The button sends `POST /u/authorize` with the five parameters and `csrf` as form fields, under the write rules of 12.4. The relay then:

1. Makes an authorization code and stores SHA-256 of its 32 bytes with the user ID, the challenge, the redirect URI and the expiry time, the relay time plus 60 seconds ([USR-4]).
2. Answers `303` with `Location: <redirect_uri>?code=ac_<64 hex digits>&state=<state>`.

### 12.3 Setup token

`POST /v1/setup/token` exchanges the code for a setup token. The device of the keys in the body signs the request (section 8).

```json
{"code":"ac_...","code_verifier":"...","redirect_uri":"...","device":{"sign":"<base64>","seal":"<base64>"}}
```

`device` is a keys object (section 6.1). The response is `200`:

```json
{"token":"st_...","tenant":"t_...","expires":1767226200,"spaces":[{"log":"l_...","app":"com.example.tasks"}]}
```

`spaces` lists each space of the tenant with its log ID and app ID, in log ID order. A device uses it to find the space of its app before it makes a new space (section 13.4). The engine reads a missing `spaces` as an empty list ([VER-13]).

The relay checks a token request in this order:

1. 8.6 steps 1 to 4.
2. If the body breaks this section, return `bad_request`. A `code_verifier` or a `redirect_uri` that breaks the form of 12.2 breaks this section.
3. 8.6 steps 7 to 9. Step 7 accepts only the device ID of `device`. Step 9 keeps the nonce in `directory.db`, because the request names no tenant.
4. If the relay holds no code with the value of `code`, or the code is used or expired (relay time at or after its expiry), return `bad_setup`.
5. If `redirect_uri` differs byte for byte from the decoded redirect URI that the relay stored for the code, or `BASE64URL(SHA-256(ASCII(code_verifier)))` differs from its challenge, return `bad_setup`.
6. Mark the code as used, and store SHA-256 of the 32 setup token bytes with the user ID, the device ID and the expiry time, the relay time plus 600 seconds ([USR-5]). Both writes are one transaction.

- `tenant` is the tenant handle of the user of the code ([USR-3]). This is how a first device gets its tenant handle.
- A code works once. If the response is lost, the app starts the sign-in again.
- The relay never selects a tenant from a value of the request: the user of the code selects it ([USR-3]).

### 12.4 User page routes

The relay configuration sets the origin of the user page, for example `https://sync.example.net`. Its default is `https://` and the configured authority. The WebAuthn relying party ID is the host of the origin, so the host must be a domain name, not an IP address.

| Method | Path | Session | Content |
| --- | --- | --- | --- |
| `GET` | `/u/` | Yes | Spaces, devices with their status, machine groups, blocks, open security actions, usage against quota, passkeys, restore holds and the webhook |
| `GET` | `/u/signin`, `/u/invite` | No | Pages |
| `GET` | `/u/authorize` | Optional | Without a session, the sign-in page. With a session, the request and the "Allow" form with the anti-CSRF token (12.2). |
| `GET` | `/u/app.js` | No | The script of the WebAuthn calls |
| `GET` | `/u/export?log=<log ID>` | Yes | The export file of a space of the tenant (section 15), as `application/x-ndjson` with `content-disposition: attachment` |
| `POST` | `/u/signin/start`, `/u/signin/finish` | No | Passkey sign-in. The start body is `{"name":"<user name>"}`. |
| `POST` | `/u/invite/start`, `/u/invite/finish` | No | Passkey registration with an invite token |
| `POST` | `/u/passkeys/start`, `/u/passkeys/finish` | Yes | Register one more passkey |
| `POST` | `/u/authorize` | Yes | Approve a native sign-in (12.2) |
| `POST` | `/u/signout` | Yes | End the session |
| `POST` | `/u/groups`, `/u/groups/delete`, `/u/groups/members` | Yes | Create a machine group, delete one, add or remove a device |
| `POST` | `/u/hold/release` | Yes | Release the restore hold of a space |
| `POST` | `/u/block`, `/u/unblock` | Yes | Block or unblock one device or one machine group: form fields `kind` (`device` or `group`) and `id` (the device ID text or the group number) |
| `POST` | `/u/webhook`, `/u/webhook/test` | Yes | Set or clear the webhook URL, send a test message |
| `POST` | `/u/tenant/delete` | Yes | Delete the tenant and the user, if the tenant has no space |

Sessions:

- A session ID is 16 random bytes. The cookie is `sf_session=<32 hex digits>.<64 hex digits>`: the ID, then HMAC-SHA256 with `session.key` over `frame("snailfish.session.v1", id)`.
- The cookie has the attributes `Path=/u; HttpOnly; SameSite=Strict; Max-Age=43200`, and `Secure` if the origin is `https`.
- Each page has `Referrer-Policy: same-origin`. Under `no-referrer`, a browser sends `Origin: null` with a form `POST`, and write rule 2 refuses each form of the page.
- The `Content-Security-Policy` of each page has `form-action 'self'`. A browser checks that directive also on the redirect after a form `POST`, so the approval page of 12.2 adds the source of its redirect URI: `http://127.0.0.1:<port>`, `http://[::1]:<port>`, or `<scheme>:`.
- The relay stores SHA-256 of the session ID with the user ID and the expiry time, the relay time of the sign-in plus 43,200 seconds. The session selects the user, and the user selects the tenant ([USR-3]).
- The anti-CSRF token of a session is the lowercase hex of HMAC-SHA256 with `session.key` over `frame("snailfish.csrf.v1", id)`.

Write rules ([USR-7]):

1. If a `/u/` request has a `signature` or `signature-input` header, return `bad_request`. A user route takes no device signature.
2. If a `POST` has no `origin` header, or its value differs from the configured origin, return `bad_origin`.
3. If a route needs a session and the request has no valid, unexpired session cookie, return `signed_out`.
4. If a route needs a session and the `csrf` form field, or the `snailfish-csrf` header of a JSON route, differs from the anti-CSRF token of the session, return `bad_csrf`.

- A form body is `application/x-www-form-urlencoded`. Each field of the route occurs once, and the relay refuses another field (`bad_request`). The JSON routes follow the strict body rule of section 10.
- The JSON of the WebAuthn routes is the JSON of the `webauthn-rs` crate, version 0.5, which the browser API takes and returns. A start response also holds `ceremony`, 16 random bytes as 32 hex digits, which the finish request names. The relay keeps a ceremony in memory for 300 seconds. It keeps at most 16,384 ceremonies. If it holds that many, a new ceremony replaces the oldest one.
- A `GET` of a page without a valid session shows the sign-in page.
- Limit: a sign-in start tells the caller whether a user name has a passkey, because the options name its credentials. The rate limit of 12.6 slows a search for names.
- A device in a machine group is a device ID that is active in a space of the tenant. A group name is 1 to 64 UTF-8 bytes.
- A block names a device ID that is active in a space of the tenant, or a machine group. A block of a group blocks each device that the group holds, also a device that the user adds later. A block stays after a removal. An unblock removes the row only ([STO-12]).
- "Blocks compaction" ([CMP-7]): for the valid snapshot in full at the highest position that is not accepted (14.1), the page marks each active device that has no accept record that counts for it. The user can update or remove that device.
- Open security actions (DESIGN.md "Monitoring and alerting" item 10): a blocked device that is still active in a space, a device with a device level below the highest relay level ([VER-10]), and, after an epoch record, each device that stays and whose last report names an older epoch. The relay sends one webhook message for each new action (12.5).

| Code | HTTP status | Cause |
| --- | --- | --- |
| `bad_origin` | 403 | Write rule 2 |
| `signed_out` | 401 | Write rule 3 |
| `bad_csrf` | 403 | Write rule 4 |
| `bad_invite` | 403 | The invite token is unknown, used or expired |
| `bad_passkey` | 403 | The WebAuthn response does not verify, or the ceremony is unknown or expired |
| `bad_webhook` | 400 | The webhook URL breaks 12.5 |
| `not_empty` | 409 | A tenant delete while the tenant has a space |
| `not_found` | 404 | An export of a log ID that the tenant does not hold |

### 12.5 Webhooks

A webhook URL is at most 512 bytes ([USR-8]): `https://` or `http://`, a host, an optional `:<port>`, and a target that starts with `/`.

- The host is a lowercase domain name of `a-z 0-9 - .`, an IPv4 literal, or an IPv6 literal in brackets in its shortest lowercase form (RFC 5952).
- `<port>` is a decimal from 1 to 65535 with no leading zero. The default is 443 for `https` and 80 for `http`.
- The target is a path with an optional query. It holds only bytes from 0x21 to 0x7E, except `# " < > \ ^ ` { | }`. So the URL has no fragment. The host part has no `@`, so the URL has no user part.

- The relay operator sets an allowlist of hosts. An empty allowlist turns webhooks off. The host of the URL must be in the allowlist, in the same form. An IPv6 entry of the allowlist has no brackets.
- The relay resolves the host each time it sends, and connects only to an address that it checked. It refuses a restricted address, unless the allowlist names that address as a literal. The restricted IPv4 ranges are `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (shared address space, also the Tailscale range), `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15` and `224.0.0.0/3` (multicast, reserved and broadcast). The restricted IPv6 ranges are `::/128`, `::1/128`, `fc00::/7`, `fe80::/10` and `ff00::/8`. An IPv6 address that holds an IPv4 address follows the IPv4 rule: `::ffff:0:0/96` (mapped), `::/96` (compatible), `64:ff9b::/96` (NAT64) and `2002::/16` (6to4, the IPv4 address in bits 16 to 47).
- The relay checks a URL when the user sets it, and again at each send.

The relay sends `POST` with `content-type: application/json` and this body:

```json
{"text":"Snailfish: device \"Sam's phone\" in com.example.tasks is stalled: no sync for 7 days."}
```

- The body holds only `text`, a string. Slack incoming webhooks accept this form.
- The JSON writer keeps non-ASCII characters as UTF-8. It escapes `"`, `\`, LF as `\n`, CR as `\r`, TAB as `\t`, and each other control character as `\u` and 4 lowercase hex digits.
- The relay sends a message for a stalled device, for a space at 80% of its quota and for an open security action (DESIGN.md "Monitoring and alerting" items 7, 9 and 10), once for each case until the case ends.
- The relay follows no redirect, waits at most 10 seconds for the DNS lookup and the exchange together, and reads at most 4 KiB of the response. A `2xx` status is a success.

### 12.6 Rate limit

The relay limits the requests of each IP address to the routes `GET /v1/e/{session}`, `POST /v1/e/{session}`, `POST /v1/setup/token`, `POST /u/signin/start`, `POST /u/signin/finish`, `POST /u/invite/start` and `POST /u/invite/finish`.

- The limit is a token bucket for each address: 120 requests, filled at 2 requests each second. A request with no token gets `rate_limited`.
- The address is the peer address of the TCP connection. An IPv6 address counts as its /64 prefix, because one host usually holds a whole /64. An IPv4-mapped IPv6 address counts as its IPv4 address.
- If the peer address is an address that `--trusted-proxy` lists, the address is the last entry of the last `X-Forwarded-For` header. If that header is missing or its last entry is not an IP address, the relay uses the peer address. The relay ignores `X-Forwarded-For` from every other peer, because a client can set it.
- Without `--trusted-proxy`, all clients behind a reverse proxy share the address of the proxy.

## 13. Removal and recovery

This section gives the engine procedures for a removal, a recovery key replacement and a full recovery (DESIGN.md S4, S5, T8, T9). They use only the records of section 6 and the routes of section 10.

### 13.1 Epoch keys

- The engine opens the key of each epoch from the key set to its own device: in the genesis record or its grant for the epochs up to its grant, and in each later epoch record. It checks each key against the commitment of the genesis or epoch record of that epoch (section 7.3).
- An epoch record that removes the own device stops the engine with `stopped: removed`. The engine keeps the keys that it holds. It reads no later record.
- A new change uses the key of the current epoch of the verified log.
- A grant seals the keys of each needed epoch (14.5) to the new device (10.6 step 13).

### 13.2 Removal

1. The engine shows the active devices with their names. The user selects the devices to remove. The other active devices stay.
2. The engine stores the confirmed lists: `removed` and `stay`.
3. At the next sync, if the active devices of the verified log equal `removed` plus `stay`, the engine makes a new 32-byte app key. It signs an epoch record on the verified head. The record seals the key to each device in `stay` and to the current recovery ID.
4. If the active devices differ, the engine asks the user to confirm again ([LOG-7]). It signs nothing until the user confirms.
5. After `stale_base`, the engine fetches and goes to step 3. It always makes a new key, because the refused record sealed the old key to its recipients.
6. After the epoch record is in the verified log, the engine writes new changes with the new key.

The engine signs the record with its own device key, or with the recovery key if the user types it. An epoch record by the recovery key needs the recovery key again after `stale_base`.

### 13.3 Recovery key replacement

1. The app asks the engine for a new recovery key. The engine makes 16 random bytes and returns the display form of section 9. The engine keeps no copy.
2. The app shows the key. The user writes it down and types it back. The app compares the typed copy.
3. The user types the current recovery key. The app gives the engine the current key and the new key.
4. The engine derives both key pairs (section 9). It signs a recovery record with the current recovery key. The record holds the new recovery keys, the possession proof, and one key set to the new recovery ID with each needed epoch (14.5).
5. After the recovery record is in the verified log, the engine signs a rotation: an epoch record with an empty `removed` list, by its own device key. T9 needs this rotation, because the holder of the old key can open each earlier key set.
6. After `stale_base` or `not_active` for the recovery record, the engine drops it and asks for the current recovery key again. `not_active` means that another recovery record came first and retired the key that signed this one.

### 13.4 Full recovery

A full recovery adds a device to a space that has no trusted device left (S5).

1. The user signs in on the new device (12.2). The setup token response names the tenant handle and the spaces of the tenant (12.3).
2. If a space has the app ID of the app, the app asks for the recovery key of that space. It does not make a new space.
3. The engine derives the recovery keys. It fetches the log from position 0 with requests that the recovery ID signs (8.2). It verifies each record from the genesis record. It has no checkpoint, so it cannot detect a log that the relay cut short (T7).
4. If the current recovery ID of the verified log differs from the derived recovery ID, the engine stops with an error that the app shows as a wrong recovery key. The relay refuses each request of a recovery ID that is not current with `unknown_device`.
5. The engine opens the key of each epoch from the key sets to the recovery ID: in the genesis record, in each epoch record, and in the last recovery record. The key of an epoch that only covered records use can be missing (14.5).
6. The engine signs a grant for its own device with the recovery key, on the verified head, and appends it in a request that the recovery ID signs. After `stale_base`, it fetches and signs again.
7. After the grant is in the verified log, the device is active. The engine forgets the recovery key. The user removes the old devices with the procedure of 13.2.

The app then imports the usable snapshot through `ResetRequired` (14.7). Edits that never reached the relay are lost (S5).

## 14. Compaction

This section gives the exact compaction rules (DESIGN.md "Log compaction", `specs/compaction`). The relay and every engine compute them from the log content only, so they reach the same result ([CMP-6]).

### 14.1 Usable snapshot

The rules use the space state of 10.2. "Active at position q" means active after the entry at q.

1. A snapshot record at position p is valid if the relay stored it: its author was active at p - 1 ([CMP-4]) and it passed 10.6 step 13. A later removal does not change this.
2. An accept record at position r counts for the snapshot at p if its `snapshot.position` is p, r is after p, and its `applied.position` is at or after the state position of the snapshot.
3. The snapshot at p is accepted if a position q after p exists where each device that is active at q has an accept record that counts for p at a position from p + 1 to q ([CMP-6]).
4. The frontier is the highest state position of an accepted snapshot that the log holds in full. 0 means no frontier ([CMP-8]).
5. The usable snapshot is the accepted snapshot in full with the frontier as its state position, and the highest position of those.

A stub of a snapshot is never usable, because the relay makes a stub only of a covered snapshot (14.2).

### 14.2 Covered records

The usable snapshot at position u, with the frontier f, covers ([CMP-11]):

- each change record at a position at or before f,
- each other snapshot record with a state position below f,
- each other snapshot record with the state position f at a position before u.

It never covers a security record or an accept record ([CMP-20]).

### 14.3 Stub check

An engine checks each stub of its verified log after a fetch reaches the relay head (`has_more` false), because a page can hold stubs before the snapshot that covers them ([CMP-15]).

- A change stub is valid if the log has a frontier and the stub position is at or before it.
- A snapshot stub is valid if the log has a usable snapshot at another position. A stub holds no state position, so this is the only check that a device can make.
- Each other stub is invalid.

An invalid stub stops the engine with `stopped: missing records`. Until a stub passes the check, `changes_after` returns no change, because the stub can hide a lost change.

### 14.4 Stubs on the relay

After an append request or a repair finish, in the same transaction, the relay replaces each covered record (14.2) with a stub ([CMP-12]). It keeps the position, the payload type, the change ID and the record hash, and deletes the envelope. The log digests do not change. After the commit, the relay runs `VACUUM` and then `PRAGMA wal_checkpoint(TRUNCATE)` on the space file ([STO-2], [STO-13]).

The operator path (`snailfish-relay` status output) reports the stub count and the stub bytes of each space ([CMP-19]). The stub bytes are the byte length of the stub JSON of 10.7.

### 14.5 Needed epochs

The needed epochs at position n are the current epoch after the entry at n - 1, and the epoch of each change and snapshot record before n that the usable snapshot of the log up to n - 1 does not cover ([CMP-20]). A grant or a recovery record at n must hold a key set with each needed epoch, and no epoch above the current epoch (10.6 step 13). A key set with more epochs is valid, because an accept record between the base of the record and its position can move the frontier.

The engine seals the needed epochs of its verified head, and epoch 1, because it opens the key of epoch 1 as its app key and checks it against the commitment of the genesis record.

### 14.6 Snapshot reserve

The snapshot reserve is 2 x (`max_snapshot_bytes` + 65,536) bytes. A snapshot or an accept record can take the stored bytes of the space up to the space quota plus the reserve. A change stops at the space quota (10.6 step 16, [CMP-18]).

### 14.7 Engine

- `snapshot_due` is true if the verified log holds 1,000 changes, or 1,048,576 bytes of change ciphertext, after the state position of the newest valid snapshot (position 0 if none), or an epoch record with a non-empty `removed` list after that snapshot ([CMP-9]). An engine with a non-empty outbox, or a stopped or paused engine, gives false.
- `write_snapshot(applied, state)` encrypts the state with the current key and the AAD of 7.2, with the applied position as `state`, and appends the record. If the payload would be larger than `max_snapshot_bytes`, or its append body larger than `max_request_bytes`, the engine writes nothing, reports `degraded` and returns false ([CMP-3]).
- `unchecked_snapshots` gives each valid snapshot in full that is not accepted, with a state position at or after the frontier, that the app applied past, that decrypts, and that the engine has not checked. A snapshot that does not decrypt is reported as `degraded` once ([CMP-5]).
- `accept_snapshot(position, ok)` appends an accept record with the app applied position if `ok` is true, and marks the snapshot as checked in both cases ([CMP-5]).
- `usable_snapshot` decrypts the usable snapshot. `genesis_base` is position 0 with `digest(0)`. `is_covered(change_id)` is true if the verified log holds the change ID, in full or as a stub, at or before the frontier ([CMP-14]).
- `changes_after(applied)` raises `ResetRequired` if the applied position is before the frontier ([CMP-16], [DLV-12]).
- After `changes_after` with an applied position at or after the frontier, if the verified log holds an own accept record that counts for the usable snapshot, the engine replaces its covered records with stubs ([CMP-13]).

## 15. Export file

An export file holds a space log as envelopes and stubs (DESIGN.md "Data retention", [FRK-3]). It holds no key and no plaintext, so a user can store it anywhere. An engine writes it from its verified log, and the user page writes it from the relay log. The import session of 10.13 reads it.

The file is UTF-8 text in JSON Lines form. Each line is one JSON object and ends with LF. The file has no empty line.

Line 1 is the header:

```json
{"type":"snailfish.export.v1","log":"l_...","app":"com.example.tasks","head":{"position":3,"digest":"<base64>"}}
```

Each later line is one entry in the form of a fetch entry (10.7), in position order from position 1 to `head.position`, with no gap:

```json
{"position":1,"envelope":{"payloadType":"snailfish.genesis.v1","payload":"...","signatures":[{"keyid":"...","sig":"..."}]}}
{"position":2,"stub":{"type":"snailfish.change.v1","change_id":"c_...","hash":"<base64>"}}
```

A reader refuses the file if:

- the header breaks the strict rules of section 3, has a field that this section does not name, or `type` is not `snailfish.export.v1`,
- an entry line breaks the form of a fetch entry, or its position is not the next position,
- position 1 does not hold a genesis record with the `log` and `app` of the header,
- the log digest after the last entry differs from `head.digest`, or the last position differs from `head.position`,
- the file has a line after the last entry, or the last line has no LF.

- A reader that checks the digests also checks each envelope as in section 4 and the stub form of 10.7. The relay runs the full chain check at the import (10.13). An engine checks the file before it uploads it, so a damaged file fails before the upload starts.
- The writer sends each envelope as the log holds it. The record hash does not depend on the layout ([WIR-3]).

