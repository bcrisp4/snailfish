//! The writer form of record payloads (`PROTOCOL.md` section 3): the fields
//! in the order of the section 6 tables, with no whitespace.
//!
//! A reader must not depend on this form. The vector test
//! `writer_gives_go_payload_bytes` checks it against the Go payloads.

use crate::encoding::{Hash32, encode_b64, encode_id};
use crate::records::{Author, Device, KeySet, Keys, Position};

fn author_text(a: &Author) -> String {
    match a {
        Author::Device(id) => encode_id("d_", id),
        Author::Recovery(id) => encode_id("r_", id),
    }
}

fn string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

fn position(p: &Position) -> String {
    format!(
        r#"{{"position":{},"digest":"{}"}}"#,
        p.position,
        encode_b64(&p.digest)
    )
}

fn keys(k: &Keys) -> String {
    format!(
        r#""sign":"{}","seal":"{}""#,
        encode_b64(&k.sign),
        encode_b64(&k.seal[..])
    )
}

fn device(d: &Device) -> String {
    format!(
        r#"{{"id":"{}",{},"name":{},"level":{}}}"#,
        encode_id("d_", &d.id),
        keys(&d.keys),
        string(&d.name),
        d.level
    )
}

fn key_sets(sets: &[KeySet]) -> String {
    let items: Vec<String> = sets
        .iter()
        .map(|k| {
            let epochs: Vec<String> = k.epochs.iter().map(u64::to_string).collect();
            format!(
                r#"{{"to":"{}","epochs":[{}],"sealed":"{}"}}"#,
                author_text(&k.to),
                epochs.join(","),
                encode_b64(&k.sealed)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn common(log: &[u8; 16], author: &Author, base: &Position) -> String {
    format!(
        r#""log":"{}","author":"{}","base":{}"#,
        encode_id("l_", log),
        author_text(author),
        position(base)
    )
}

/// The fields of a genesis record after the common fields.
pub struct Genesis<'a> {
    /// The app ID.
    pub app: &'a str,
    /// The recovery public keys.
    pub recovery: &'a Keys,
    /// The first space write level.
    pub level: u64,
    /// The first device.
    pub device: &'a Device,
    /// The epoch 1 key commitment.
    pub commitment: &'a Hash32,
    /// The key sets to the device and to the recovery ID, sorted by ID.
    pub keys: &'a [KeySet],
}

/// A `snailfish.genesis.v1` payload. The author is the recovery ID and the
/// base is position 0 with `digest(0)`.
#[must_use]
pub fn genesis(log: &[u8; 16], author: &Author, base: &Position, g: &Genesis<'_>) -> Vec<u8> {
    format!(
        r#"{{{},"app":{},"recovery":{{{}}},"level":{},"device":{},"epoch":1,"commitment":"{}","keys":{}}}"#,
        common(log, author, base),
        string(g.app),
        keys(g.recovery),
        g.level,
        device(g.device),
        encode_b64(g.commitment),
        key_sets(g.keys)
    )
    .into_bytes()
}

/// A `snailfish.grant.v1` payload.
#[must_use]
pub fn grant(
    log: &[u8; 16],
    author: &Author,
    base: &Position,
    new_device: &Device,
    key_set: &KeySet,
) -> Vec<u8> {
    format!(
        r#"{{{},"device":{},"keys":{}}}"#,
        common(log, author, base),
        device(new_device),
        key_sets(std::slice::from_ref(key_set))
    )
    .into_bytes()
}

/// A `snailfish.change.v1` payload.
#[must_use]
pub fn change(
    log: &[u8; 16],
    author: &Hash32,
    base: &Position,
    epoch: u64,
    change_id: &[u8; 16],
    ciphertext: &[u8],
) -> Vec<u8> {
    format!(
        r#"{{{},"epoch":{},"change_id":"{}","ciphertext":"{}"}}"#,
        common(log, &Author::Device(*author), base),
        epoch,
        encode_id("c_", change_id),
        encode_b64(ciphertext)
    )
    .into_bytes()
}

// No Kani harness: each function formats strings and base64, which CBMC
// cannot finish with symbolic lengths. The vector test and the parser
// round trip below cover the writers.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{Body, parse_payload};
    use proptest::prelude::*;

    proptest! {
        /// A written change parses back to the same fields.
        #[test]
        fn change_round_trip(
            log in any::<[u8; 16]>(),
            author in any::<[u8; 32]>(),
            pos in 1u64..(1 << 53),
            digest in any::<[u8; 32]>(),
            epoch in 1u64..(1 << 53),
            cid in any::<[u8; 16]>(),
            ct in proptest::collection::vec(any::<u8>(), 40..80),
        ) {
            let base = Position { position: pos, digest };
            let p = change(&log, &author, &base, epoch, &cid, &ct);
            let r = parse_payload("snailfish.change.v1", &p).unwrap();
            prop_assert_eq!(r.log, log);
            prop_assert_eq!(r.author, Author::Device(author));
            prop_assert_eq!(r.base, base);
            prop_assert_eq!(r.body, Body::Change { epoch, change_id: cid, ciphertext: ct });
        }
    }
}
