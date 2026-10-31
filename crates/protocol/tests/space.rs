//! The space-state check of `space` against the Go log in
//! `vectors/protocol.json` (`PROTOCOL.md` 10.5 and 10.6, [LOG-1], [LOG-6],
//! [LOG-8], [WIR-6]).
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::encoding::decode_id;
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::space::{
    Accepted, MemorySpace, Mode, Refusal, Verdict, check_append, check_genesis,
};

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

fn device(v: &Value, name: &str) -> ([u8; 32], SecretKey) {
    let d = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap();
    let id = decode_id::<32>(d["id"].as_str().unwrap(), "d_").unwrap();
    let seed: [u8; 32] = hex::decode(d["sign_seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (id, SecretKey::from_seed(&seed))
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

fn relay(signer: [u8; 32]) -> Mode {
    Mode::Relay {
        signer,
        max_change_bytes: 65536,
    }
}

fn stored(v: Verdict) -> Accepted {
    match v {
        Verdict::Store(a) => *a,
        other => panic!("expected Store, got {other:?}"),
    }
}

/// The genesis record, the grant to B and the change by A: positions 1 to 3
/// of the Go log.
fn setup(v: &Value) -> MemorySpace {
    let log = decode_id::<16>(v["log"]["log_id"].as_str().unwrap(), "l_").unwrap();
    let (a, _) = device(v, "A");
    let mut s = MemorySpace::new(log);
    let g = check_genesis(&env(v, 1), &log, Some(&a)).unwrap();
    assert_eq!(g.digest, digest(v, 1));
    s.apply(&g);
    for n in [2, 3] {
        let acc = stored(check_append(&s, &env(v, n), relay(a)));
        assert_eq!(
            (acc.position, acc.digest),
            (u64::try_from(n).unwrap(), digest(v, n))
        );
        s.apply(&acc);
    }
    s
}

#[test]
fn go_log_gives_the_same_positions_and_digests() {
    let v = vectors();
    let s = setup(&v);
    let (b, _) = device(&v, "B");
    assert!(s.devices.contains_key(&b), "the grant makes B active");
}

/// [WIR-6]: an exact retry is Known, the same `change_id` with another
/// signature is a Conflict, and both name position 3. The relay checks this
/// before the base and the author (10.6 step 2).
#[test]
fn known_and_conflict_name_the_original_position() {
    let v = vectors();
    let s = setup(&v);
    let (a, ka) = device(&v, "A");
    let (c, _) = device(&v, "C");
    let e3 = env(&v, 3);
    assert_eq!(check_append(&s, &e3, relay(a)), Verdict::Known(3));
    assert_eq!(check_append(&s, &e3, relay(c)), Verdict::Known(3));
    // Ed25519 is deterministic, so another signature needs other bytes: a
    // payload with extra whitespace has the same change_id.
    let mut payload = e3.payload.clone();
    payload.push(b' ');
    let other = Envelope {
        sig: ka.sign_record(&e3.payload_type, &payload),
        payload,
        payload_type: e3.payload_type.clone(),
    };
    assert_eq!(check_append(&s, &other, relay(a)), Verdict::Conflict(3));
    // The engine treats a second copy of a `change_id` in a fetched log as a relay fault.
    assert_eq!(
        check_append(&s, &e3, Mode::Verify),
        Verdict::Refused(Refusal::DuplicateChange)
    );
}

/// [LOG-8]: the grant to C at position 8 has a base at position 7, so it is
/// refused on a log with head 3. C is not active, so a record by C is refused.
#[test]
fn refusals_follow_the_protocol_order() {
    let v = vectors();
    let s = setup(&v);
    let (a, _) = device(&v, "A");
    let (b, _) = device(&v, "B");
    // Position 10 is a change by B in epoch 2 with a base at 9.
    let e10 = env(&v, 10);
    assert_eq!(
        check_append(&s, &e10, relay(a)),
        Verdict::Refused(Refusal::NotAuthor)
    );
    assert_eq!(
        check_append(&s, &e10, relay(b)),
        Verdict::Refused(Refusal::BadBase)
    );
    // Snapshot by B with a base inside the log: unsupported in M2.
    assert_eq!(
        check_append(&s, &env(&v, 4), relay(b)),
        Verdict::Refused(Refusal::Unsupported)
    );
    // A grant of B again.
    assert!(matches!(
        check_append(&s, &env(&v, 2), relay(a)),
        Verdict::Refused(Refusal::InvalidRecord(_))
    ));
    // The genesis record after position 1 has base 0.
    assert!(matches!(
        check_append(&s, &env(&v, 1), relay(a)),
        Verdict::Refused(_)
    ));
    // A too large change.
    let small = Mode::Relay {
        signer: a,
        max_change_bytes: 10,
    };
    let mut s2 = s.clone();
    s2.changes.clear();
    assert_eq!(
        check_append(&s2, &env(&v, 3), small),
        Verdict::Refused(Refusal::TooLarge)
    );
    // A flipped signature bit.
    let mut bad = env(&v, 3);
    bad.sig[0] ^= 1;
    assert!(matches!(
        check_append(&s2, &bad, relay(a)),
        Verdict::Refused(Refusal::InvalidRecord(_))
    ));
}

#[test]
fn genesis_check_refuses_other_logs_signers_and_types() {
    let v = vectors();
    let log = decode_id::<16>(v["log"]["log_id"].as_str().unwrap(), "l_").unwrap();
    let (b, _) = device(&v, "B");
    let g = env(&v, 1);
    assert!(check_genesis(&g, &log, None).is_ok());
    assert_eq!(check_genesis(&g, &log, Some(&b)), Err(Refusal::NotAuthor));
    assert!(check_genesis(&g, &[0; 16], None).is_err());
    assert!(check_genesis(&env(&v, 2), &log, None).is_err());
    let mut bad = g;
    bad.sig[5] ^= 1;
    assert!(check_genesis(&bad, &log, None).is_err());
}

/// The writer gives the exact Go payload bytes of the genesis record, the
/// grant and the change (`PROTOCOL.md` section 3 writer form).
#[test]
fn writer_gives_go_payload_bytes() {
    use snailfish_protocol::records::{Body, parse_payload};
    use snailfish_protocol::write;
    let v = vectors();
    for n in [1, 2, 3, 10] {
        let e = env(&v, n);
        let r = parse_payload(&e.payload_type, &e.payload).unwrap();
        let out = match &r.body {
            Body::Genesis {
                app,
                recovery,
                level,
                device,
                commitment,
                keys,
                ..
            } => write::genesis(
                &r.log,
                &r.author,
                &r.base,
                &write::Genesis {
                    app,
                    recovery,
                    level: *level,
                    device,
                    commitment,
                    keys,
                },
            ),
            Body::Grant { device, keys } => {
                write::grant(&r.log, &r.author, &r.base, device, &keys[0])
            }
            Body::Change {
                epoch,
                change_id,
                ciphertext,
            } => write::change(
                &r.log,
                r.author.id(),
                &r.base,
                *epoch,
                change_id,
                ciphertext,
            ),
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            String::from_utf8(out).unwrap(),
            String::from_utf8(e.payload).unwrap(),
            "entry {n}"
        );
    }
}

/// The genesis record of the Go log, rewritten with write level `level` and
/// signed by recovery key R1.
fn genesis_at_level(v: &Value, level: u64) -> Envelope {
    use snailfish_protocol::records::{Body, parse_payload};
    use snailfish_protocol::write;
    let e = env(v, 1);
    let r = parse_payload(&e.payload_type, &e.payload).unwrap();
    let Body::Genesis {
        app,
        recovery,
        device,
        commitment,
        keys,
        ..
    } = &r.body
    else {
        panic!("entry 1 is a genesis record");
    };
    let payload = write::genesis(
        &r.log,
        &r.author,
        &r.base,
        &write::Genesis {
            app,
            recovery,
            level,
            device,
            commitment,
            keys,
        },
    );
    let seed: [u8; 32] = hex::decode(v["recovery"][0]["sign_seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = SecretKey::from_seed(&seed).sign_record(&e.payload_type, &payload);
    Envelope {
        payload_type: e.payload_type,
        payload,
        sig,
    }
}

/// A grant of device B with device level `level`, by A, on top of `head`.
fn grant_b(v: &Value, level: u64, head: (u64, [u8; 32])) -> Envelope {
    use snailfish_protocol::records::{Author, Body, Position, parse_payload};
    use snailfish_protocol::write;
    let e = env(v, 2);
    let r = parse_payload(&e.payload_type, &e.payload).unwrap();
    let (a, ka) = device(v, "A");
    let Body::Grant { device: dev, keys } = &r.body else {
        panic!("entry 2 is a grant record");
    };
    let mut new_device = dev.clone();
    new_device.level = level;
    let payload = write::grant(
        &r.log,
        &Author::Device(a),
        &Position {
            position: head.0,
            digest: head.1,
        },
        &new_device,
        &keys[0],
    );
    let sig = ka.sign_record(&e.payload_type, &payload);
    Envelope {
        payload_type: e.payload_type,
        payload,
        sig,
    }
}

/// [VER-7] The write level of the space comes from the genesis record. A
/// grant of a device below that level is refused, and a device at the level
/// is accepted. Without this, a relay would let a device that cannot read the
/// future record formats join the space.
#[test]
fn grant_below_the_genesis_write_level_is_refused() {
    let v = vectors();
    let log = decode_id::<16>(v["log"]["log_id"].as_str().unwrap(), "l_").unwrap();
    let (a, _) = device(&v, "A");
    let mut s = MemorySpace::new(log);
    let g = check_genesis(&genesis_at_level(&v, 2), &log, Some(&a)).unwrap();
    s.apply(&g);
    assert_eq!(s.level, 2);
    let head = (1, g.digest);
    match check_append(&s, &grant_b(&v, 1, head), relay(a)) {
        Verdict::Refused(Refusal::InvalidRecord(why)) => assert!(why.contains("write level")),
        other => panic!("expected invalid_record, got {other:?}"),
    }
    stored(check_append(&s, &grant_b(&v, 2, head), relay(a)));
}

/// [DLV-5] A change of exactly `max_change_bytes` is stored. One byte more is
/// `too_large`. Without this, a relay would refuse changes at the limit that
/// the engine is allowed to send, or store changes above it.
#[test]
fn change_size_limit_is_inclusive() {
    use snailfish_protocol::records::Position;
    use snailfish_protocol::write;
    let v = vectors();
    let space = setup(&v);
    let (a, ka) = device(&v, "A");
    let payload = write::change(
        &space.log_id,
        &a,
        &Position {
            position: 3,
            digest: digest(&v, 3),
        },
        1,
        &[0x77; 16],
        &[9; 100],
    );
    let ty = "snailfish.change.v1";
    let env = Envelope {
        payload_type: ty.to_owned(),
        sig: ka.sign_record(ty, &payload),
        payload,
    };
    let at = |max| Mode::Relay {
        signer: a,
        max_change_bytes: max,
    };
    stored(check_append(&space, &env, at(env.payload.len())));
    assert_eq!(
        check_append(&space, &env, at(env.payload.len() - 1)),
        Verdict::Refused(Refusal::TooLarge)
    );
}
