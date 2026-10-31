//! The chain check of a repair request (`PROTOCOL.md` 10.9) against the Go
//! log in `vectors/protocol.json` ([LOG-1], [LOG-10], [LOG-11], [LOG-12]).
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::encoding::decode_id;
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::repair::{ChainError, Item, check_chain};
use snailfish_protocol::space::{MemorySpace, Refusal, SpaceView, check_genesis};

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/protocol.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn env(v: &Value, n: usize) -> Envelope {
    Envelope::parse(
        v["log"]["entries"][n.checked_sub(1).unwrap()]["envelope"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap()
}

fn digest(v: &Value, n: usize) -> [u8; 32] {
    hex::decode(
        v["log"]["entries"][n.checked_sub(1).unwrap()]["digest"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn device_id(v: &Value, name: &str) -> [u8; 32] {
    let d = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap();
    decode_id::<32>(d["id"].as_str().unwrap(), "d_").unwrap()
}

/// A relay log that a restore cut to the genesis record.
fn genesis_only(v: &Value) -> MemorySpace {
    let log = decode_id::<16>(v["log"]["log_id"].as_str().unwrap(), "l_").unwrap();
    let mut s = MemorySpace::new(log);
    s.apply(&check_genesis(&env(v, 1), &log, None).unwrap());
    s
}

/// [LOG-10] [LOG-12]: the lost grant to B (2) and change by A (3) pass on
/// the restored log, with the Go digests. The passed grant makes B active,
/// so the relay can accept a request that B signs. The log does not change.
#[test]
fn lost_entries_pass_and_activate_their_grant() {
    let v = vectors();
    let s = genesis_only(&v);
    let (e2, e3) = (env(&v, 2), env(&v, 3));
    let chain = check_chain(&s, &[2, 3], &[Item::Envelope(&e2), Item::Envelope(&e3)]);
    assert!(chain.failure.is_none());
    let got: Vec<(u64, [u8; 32])> = chain
        .accepted
        .iter()
        .map(|a| (a.position, a.digest))
        .collect();
    assert_eq!(got, [(2, digest(&v, 2)), (3, digest(&v, 3))]);
    assert_eq!(
        chain.accepted[0].new_device.map(|d| d.0),
        Some(device_id(&v, "B"))
    );
    assert_eq!(s.head(), 1);
}

/// The check stops at the first failure and keeps the passed prefix
/// (`PROTOCOL.md` 10.9 start step 3): a gap, a stub ([LOG-11]), an invalid
/// envelope, a bad signature, and a change that the log already holds.
#[test]
fn first_failure_stops_the_check() {
    let v = vectors();
    let s = genesis_only(&v);
    let (e2, e3) = (env(&v, 2), env(&v, 3));

    let gap = check_chain(&s, &[2, 4], &[Item::Envelope(&e2), Item::Envelope(&e3)]);
    assert_eq!(gap.accepted.len(), 1);
    assert_eq!(gap.failure, Some((1, ChainError::Position)));
    let first = check_chain(&s, &[3], &[Item::Envelope(&e3)]);
    assert_eq!(first.failure, Some((0, ChainError::Position)));

    let stub = check_chain(&s, &[2, 3], &[Item::Envelope(&e2), Item::Stub]);
    assert_eq!(stub.failure, Some((1, ChainError::Stub)));
    assert_eq!(stub.failure.unwrap().1.code(), "uncovered_stub");

    let bad = check_chain(&s, &[2], &[Item::Invalid]);
    assert!(matches!(
        bad.failure,
        Some((0, ChainError::Invalid(Refusal::InvalidRecord(_))))
    ));

    let mut forged = e2.clone();
    forged.sig[0] ^= 1;
    let sig = check_chain(&s, &[2], &[Item::Envelope(&forged)]);
    assert_eq!(sig.accepted, [] as [snailfish_protocol::space::Accepted; 0]);
    assert!(matches!(
        sig.failure,
        Some((0, ChainError::Invalid(Refusal::InvalidRecord(_))))
    ));

    // The change at 3 again at position 4: the log never holds a change_id twice.
    let twice = check_chain(
        &s,
        &[2, 3, 4],
        &[
            Item::Envelope(&e2),
            Item::Envelope(&e3),
            Item::Envelope(&e3),
        ],
    );
    assert_eq!(twice.accepted.len(), 2);
    assert_eq!(
        twice.failure,
        Some((2, ChainError::Invalid(Refusal::DuplicateChange)))
    );
}
