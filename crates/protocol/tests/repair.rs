//! The chain check of a repair request (`PROTOCOL.md` 10.9) against the Go
//! log in `vectors/protocol.json` ([LOG-1], [LOG-10], [LOG-11], [LOG-12]).
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::encoding::decode_id;
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::repair::{ChainError, Item, check_chain};
use snailfish_protocol::space::{MemorySpace, Overlay, Refusal, SpaceView, check_genesis};

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

/// A view with a write level, an epoch and a last security record that a
/// genesis-only log cannot have, so the overlay must read them from it.
struct Shifted(MemorySpace);

impl SpaceView for Shifted {
    fn log_id(&self) -> [u8; 16] {
        self.0.log_id()
    }
    fn head(&self) -> u64 {
        self.0.head()
    }
    fn digest_at(&self, p: u64) -> Option<[u8; 32]> {
        self.0.digest_at(p)
    }
    fn device_key(&self, id: &[u8; 32]) -> Option<[u8; 32]> {
        self.0.device_key(id)
    }
    fn change(&self, c: &[u8; 16]) -> Option<(u64, [u8; 32])> {
        self.0.change(c)
    }
    fn write_level(&self) -> u64 {
        3
    }
    fn epoch(&self) -> u64 {
        2
    }
    fn last_security(&self) -> u64 {
        7
    }
}

/// The overlay reads the space state of the log until an added record
/// changes it: the write level and the epoch, and the last security record
/// until an added security record ([LOG-7], [LOG-8]).
#[test]
fn overlay_reads_the_log_state_until_an_added_record_changes_it() {
    let v = vectors();
    let inner = Shifted(genesis_only(&v));
    let mut over = Overlay::new(&inner);
    assert_eq!(
        (over.write_level(), over.epoch(), over.last_security()),
        (3, 2, 7)
    );
    let (e2, e3) = (env(&v, 2), env(&v, 3));
    let chain = check_chain(
        &genesis_only(&v),
        &[2, 3],
        &[Item::Envelope(&e2), Item::Envelope(&e3)],
    );
    let mut added = chain.accepted.into_iter();
    over.apply(added.next().unwrap());
    assert_eq!(over.last_security(), 2, "the grant at 2");
    over.apply(added.next().unwrap());
    assert_eq!(over.last_security(), 2, "a change is not a security record");
    assert_eq!(over.head(), 3);
}
