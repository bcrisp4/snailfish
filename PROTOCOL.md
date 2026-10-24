# Snailfish protocol

Status: draft for M1. This file gives the exact bytes of the protocol (DESIGN.md "Wire format", [WIR-1] to [WIR-9]). DESIGN.md gives the rules and the reasons. If the two differ, change the Quint model first, then DESIGN.md, then this file.

Each section says where its test vectors live and which crate implements it. A section with the status "to do" has no implementation yet.

| Section | Status | Implementation | Vectors |
| --- | --- | --- | --- |
| 1. Signature input (PAE) | Done | `snailfish_protocol::pae` | DSSE 1.0.2 vector in `pae.rs` tests |
| 2. Envelope JSON | To do | | |
| 3. Strict payload JSON | To do | | |
| 4. Record hash and entry hash | To do | | |
| 5. Log digest | To do | | |
| 6. Record payloads | To do | | |
| 7. Key derivation and sealing | To do | | RFC 9180, `draft-ietf-hpke-pq` |
| 8. Request signatures | To do | | RFC 9421 |
| 9. Recovery key encoding | To do | | |

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

## 2 to 9

To do in M1. Write each section before its code, with its vectors, in this order: 3, 2, 4, 5, 6, 8, 7, 9. Strict JSON comes first, because every record depends on it.
