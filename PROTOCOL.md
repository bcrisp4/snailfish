# Snailfish protocol

Status: draft for M2. This file gives the exact bytes of the protocol (DESIGN.md "Wire format", [WIR-1] to [WIR-9]). DESIGN.md gives the rules and the reasons. If the two differ, change the Quint model first, then DESIGN.md, then this file, then `tools/vectorgen`, then the Rust code.

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
| 10. HTTP API | Done (M2 routes) | `snailfish_protocol::wire`, `snailfish-relay` | `vectors/http.json` |

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
| `keyid` | The device ID text of the signer (section 2.2) |
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
5. If `keyid` names no device that is active in the space (10.2), return `unknown_device`.
6. If the signature does not verify over the signature base of 8.4, return `bad_signature`.
7. If the tenant file holds the pair (`keyid`, `nonce`), return `nonce_reused`. Otherwise store the pair with `expires`.

- The relay keeps each nonce in the tenant file until its `expires` time, so a restart does not allow a replay (T5). It deletes expired nonces.
- The relay stores a nonce only after the signature verifies, so a party without the key cannot use up nonces.
- Steps 3 to 5 run before the signature check. The errors of steps 3 and 4 tell an unauthenticated caller only facts that the request itself holds. Step 5 tells a caller who knows the tenant handle and the log ID whether a device ID is active in the space. The tenant handle has 128 random bits ([STO-10]), so only a party that already holds it can ask.
- For `PUT /v1/t/{tenant}/s/{log}`, step 5 takes the device key from the genesis record in the body. The relay therefore runs steps 1 to 4 before it parses the body (10.5).
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

This section gives the sync surface routes of M2. Later milestones add routes under the same prefix ([VER-12]). Bodies are UTF-8 JSON with `content-type: application/json`. Binary fields are standard base64 with padding.

### 10.1 Routes

| Method | Path | Signed | Result |
| --- | --- | --- | --- |
| `GET` | `/v1/health` | No | `200` with `{"status":"ok"}` |
| `GET` | `/v1/info` | No | `200` with the info object (10.4) ([WIR-8]) |
| `PUT` | `/v1/t/{tenant}/s/{log}` | Yes, by the device of the genesis record | Create the space with its genesis record (10.5) |
| `POST` | `/v1/t/{tenant}/s/{log}/append` | Yes, by an active device | Append records (10.6) |
| `GET` | `/v1/t/{tenant}/s/{log}/entries?after={n}&limit={m}` | Yes, by an active device | Fetch entries after position `n` (10.7) |

- `{tenant}` is the tenant handle: `t_` and 32 lowercase hex digits (128 bits, [STO-10]).
- `{log}` is the log ID text (section 2.2).
- The relay finds the tenant only through the handle, and the space only through the space index of the tenant file ([STO-3]).
- M2 creates a space with a device signature only. M5 adds the setup token of the setup surface.

### 10.2 Active devices

A device is active in a space if the genesis record or a grant at a position in the log names it ([LOG-8]). M2 has no removal, so a device stays active. The device of a genesis record signs the `PUT` request that creates the space.

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
| `unknown_device` | 403 | `keyid` names no active device of the space | `paused: relay unavailable` |
| `unknown_tenant` | 404 | No tenant has the handle | `paused: relay unavailable` |
| `unknown_space` | 404 | The tenant has no space with the log ID | `paused: relay unavailable` |
| `not_found` | 404 | No route has the path | `paused: relay unavailable` |
| `space_exists` | 409 | `PUT` with another genesis record for an existing log ID | `stopped: fork` |
| `invalid_record` | 422 | The genesis record of a `PUT` breaks 10.5 | `stopped: fork` |
| `too_large` | 413 | The body is larger than `max_request_bytes` | `degraded` |
| `wrong_authority` | 421 | `snailfish-authority` differs from the relay configuration (8.6 step 1) | `paused: relay authority` |
| `internal` | 500 | A relay failure | `paused: relay unavailable` |

A response that is not JSON, or JSON without a string `error`, is a fault outside the relay, for example a proxy page. The engine reports `paused: relay unavailable`.

### 10.4 `GET /v1/info`

```json
{"levels":[1],"limits":{"max_request_bytes":4194304,"max_change_bytes":65536,"max_snapshot_bytes":16777216,"max_append_envelopes":100,"max_fetch_entries":500},"time":1767225600}
```

| Field | Content |
| --- | --- |
| `levels` | The protocol levels that the relay accepts ([VER-6], [VER-11]) |
| `limits.max_request_bytes` | The largest request body |
| `limits.max_change_bytes` | The largest decoded payload of a change record |
| `limits.max_snapshot_bytes` | The largest decoded payload of a snapshot record ([CMP-3]) |
| `limits.max_append_envelopes` | The most envelopes in one append request |
| `limits.max_fetch_entries` | The most entries in one fetch response |
| `time` | The relay time, as in `snailfish-time` |

### 10.5 `PUT /v1/t/{tenant}/s/{log}`

Request body: `{"genesis":<envelope>}`.

The relay runs 8.6 steps 1 to 4, then parses the body. It checks the genesis record: the envelope (section 4), the payload (section 6), the signature by the recovery key of the record, and `log` equal to `{log}`. The request signer must be the device of the record (8.6 steps 5 to 7). The relay then creates the space file, with the genesis record at position 1.

The device that made the space holds its genesis record from the setup. If position 1 of the relay log has another record hash, the engine stops with `stopped: fork`.

| Result | Status | Body |
| --- | --- | --- |
| Created | 201 | `{"position":1,"digest":"<base64>"}` |
| The space exists with the same genesis record hash | 200 | `{"position":1,"digest":"<base64>"}`. This is an exact retry. |
| The space exists with another genesis record | 409 | Error `space_exists` |
| The record is not valid | 422 | `{"error":"invalid_record","message":"..."}` |

### 10.6 `POST /v1/t/{tenant}/s/{log}/append`

Request body: `{"envelopes":[<envelope>, ...]}`, with 1 to `max_append_envelopes` envelopes. An envelope is a JSON object in the form of section 4.

The relay checks and appends the envelopes in list order, in one transaction in the space file ([STO-11]). Each envelope gets one result. A refusal of one envelope does not stop the others. The response is `200`:

```json
{"results":[{"status":"stored","position":7},{"status":"known","position":3},{"status":"conflict","position":4},{"status":"refused","error":"bad_base"}],"head":{"position":7,"digest":"<base64>"}}
```

The relay checks each envelope in this order:

1. If the envelope or the payload breaks section 4 or 6, the result is `refused` with `invalid_record`.
2. If the log holds a change with the same `change_id` and the same record hash, the result is `known` with its position. If the record hash differs, the result is `conflict` with the position of the stored change ([WIR-6]). The relay checks this before every other refusal, so a stored change is never refused ([DLV-5], [DLV-7]).
3. If the decoded payload of a change is larger than `max_change_bytes`, the result is `refused` with `too_large`.
4. If `log` differs from `{log}`, the result is `refused` with `invalid_record`.
5. If `author` differs from the request `keyid`, the result is `refused` with `not_author`.
6. If `author` is not an active device, the result is `refused` with `not_active`. Step 5 and 8.6 step 5 make this step unreachable on the relay. The engine applies steps 4 and 6 to 11 to each fetched record.
7. If the signature does not verify with the signing key of `author` (section 7.1), the result is `refused` with `invalid_record`.
8. If the base is not position 1 or later, or not before the new position, or its digest differs from the log digest at that position, the result is `refused` with `bad_base` ([LOG-6]).
9. If the record type is not `snailfish.change.v1` or `snailfish.grant.v1`, the result is `refused` with `unsupported`. M2 accepts only these two types.
10. If a change names an epoch other than the current epoch (1 in M2), the result is `refused` with `wrong_epoch`.
11. If a grant names a device that is already active, or a level below the space write level, the result is `refused` with `invalid_record`.
12. Otherwise the relay appends the record at the next position. Positions are dense ([LOG-1]). The relay stores the log digest of the new entry (section 5). The result is `stored` with the position.

- `head` is the last position and its log digest after the transaction.
- A known envelope earlier in the same request counts: a second copy in one request is `known`.
- `bad_base` is transient. Each other refusal is permanent for that envelope ([DLV-9]).
- The engine splits its envelopes into requests that fit `max_append_envelopes` and `max_request_bytes`. A change whose append body alone is larger than `max_request_bytes` is refused for ever with `too_large`, and the engine does not send it ([DLV-9]).

### 10.7 `GET /v1/t/{tenant}/s/{log}/entries`

Query: `after` (integer from 0) and `limit` (integer from 1 to `max_fetch_entries`). Both are required, in this order, as decimal integers with no leading zero.

```json
{"entries":[{"position":1,"envelope":{"payloadType":"...","payload":"...","signatures":[{"keyid":"...","sig":"..."}]}},{"position":12,"stub":{"type":"snailfish.change.v1","change_id":"c_...","hash":"<base64>"}}],"head":{"position":12,"digest":"<base64>"},"has_more":false}
```

- `entries` holds the entries from position `after + 1`, in position order, with no gap, at most `limit` entries.
- An entry holds the stored envelope in full, or a stub. M2 has no compaction, so the M2 relay sends no stubs. A stub has `type`, `change_id` (only for a change) and `hash`, the record hash ([CMP-1]).
- The relay sends each envelope object as it stored it. The record hash does not depend on the layout ([WIR-3]).
- `head` is the last position of the log and its log digest. `has_more` is true if the log holds entries after the last entry of the response.
- If `after` is the head position or later, `entries` is empty. The engine compares `head` with its verified log.
