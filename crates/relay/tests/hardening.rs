//! Boundaries and failure paths of the core through real SQLite files:
//! limits, path safety, write level and clean-up after a failed create.

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{Fx, error_code, s};
use rusqlite::Connection;
use snailfish_protocol::encoding::{encode_b64, encode_id};
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::records::{Author, Body, Position, parse_payload};
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::space::check_genesis;
use snailfish_protocol::wire::{self, AppendResult};
use snailfish_protocol::write;
use snailfish_relay::core::{Relay, Response, system_time};

/// The genesis envelope of `http.json` with write level `level`, signed by
/// the recovery key R1 of `protocol.json`.
fn genesis_at_level(fx: &Fx, level: u64) -> Envelope {
    let old = Envelope::parse(s(&fx.h["space"]["genesis"]).as_bytes()).unwrap();
    let r = parse_payload(&old.payload_type, &old.payload).unwrap();
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
    let seed: [u8; 32] = hex::decode(s(
        &common::load("protocol.json")["recovery"][0]["sign_seed"],
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let sig = SecretKey::from_seed(&seed).sign_record(&old.payload_type, &payload);
    Envelope {
        payload_type: old.payload_type,
        payload,
        sig,
    }
}

/// The grant to B of `http.json`, with device level `level`, by A on top of
/// position 1 with `digest`.
fn grant_b(fx: &Fx, level: u64, digest: [u8; 32]) -> String {
    let old = Envelope::parse(s(&fx.log_entry(3)["envelope"]).as_bytes()).unwrap();
    let r = parse_payload(&old.payload_type, &old.payload).unwrap();
    let Body::Grant { device, keys } = &r.body else {
        panic!("entry 3 is a grant record");
    };
    let mut device = device.clone();
    device.level = level;
    let (ka, a, a_text) = fx.key("A");
    let payload = write::grant(
        &r.log,
        &Author::Device(a),
        &Position {
            position: 1,
            digest,
        },
        &device,
        &keys[0],
    );
    let sig = ka.sign_record(&old.payload_type, &payload);
    Envelope {
        payload_type: old.payload_type,
        payload,
        sig,
    }
    .to_json(&a_text)
}

fn put_genesis(fx: &Fx, genesis: &Envelope) -> Response {
    let r = parse_payload(&genesis.payload_type, &genesis.payload).unwrap();
    let json = genesis.to_json(&encode_id("r_", r.author.id()));
    let path = fx.space_path(fx.tenant(), fx.log());
    fx.relay
        .handle(&fx.signed("PUT", &path, "", &wire::genesis_body(&json), "A"))
}

fn space_conn(fx: &Fx) -> Connection {
    Connection::open(fx.space_file(fx.tenant())).unwrap()
}

/// [VER-7] The space write level comes from the genesis record, and a grant
/// below it is refused. Without this, a device that cannot read the record
/// formats of the space would join it, or the relay would store another level
/// than the record names.
#[test]
fn write_level_is_stored_and_refuses_a_lower_device_level() {
    let fx = Fx::new();
    let genesis = genesis_at_level(&fx, 2);
    let acc = check_genesis(&genesis, &fx.log_id(), None).unwrap();
    assert_eq!(put_genesis(&fx, &genesis).status, 201);
    let level: i64 = space_conn(&fx)
        .query_row("SELECT write_level FROM space", [], |r| r.get(0))
        .unwrap();
    assert_eq!(level, 2);
    let low = grant_b(&fx, 1, acc.digest);
    assert_eq!(
        fx.append(fx.tenant(), "A", &[low]).1,
        [AppendResult::Refused("invalid_record".into())]
    );
    let ok = grant_b(&fx, 2, acc.digest);
    assert_eq!(
        fx.append(fx.tenant(), "A", &[ok]).1,
        [AppendResult::Stored(2)]
    );
}

/// [DLV-5] A change of exactly `max_change_bytes` is stored. One byte less
/// as the limit gives `too_large`. Without this, the relay would refuse
/// changes at the limit that `GET /v1/info` allows, or store larger ones.
#[test]
fn change_size_limit_is_inclusive() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    let env = fx.change("B", 4, [0x21; 16], 60, 7);
    let len = Envelope::parse(env.as_bytes()).unwrap().payload.len() as u64;
    let mut limits = common::limits_of(&fx.h);
    limits.max_change_bytes = len - 1;
    fx.restart(limits);
    assert_eq!(
        fx.append(fx.tenant(), "B", std::slice::from_ref(&env)).1,
        [AppendResult::Refused("too_large".into())]
    );
    limits.max_change_bytes = len;
    fx.restart(limits);
    assert_eq!(
        fx.append(fx.tenant(), "B", &[env]).1,
        [AppendResult::Stored(5)]
    );
}

/// [DLV-5] A body of exactly `max_request_bytes` passes the size guard. One
/// byte more is `413 too_large`. Without this, the relay would refuse the
/// largest body that `GET /v1/info` allows, or read a body of any size.
#[test]
fn request_size_limit_is_inclusive() {
    let mut limits = common::limits_of(&common::load("http.json"));
    limits.max_request_bytes = 100;
    let fx = Fx::with(s(&common::load("http.json")["authority"]), limits);
    let path = fx.space_path(fx.tenant(), fx.log());
    let put = |n: usize| {
        let mut r = fx.signed("PUT", &path, "", b"", "A");
        r.body = vec![b'x'; n];
        fx.relay.handle(&r)
    };
    let at = put(100);
    assert_ne!(at.status, 413, "{}", error_code(&at));
    let over = put(101);
    assert_eq!(
        (over.status, error_code(&over).as_str()),
        (413, "too_large")
    );
}

/// Rename a tenant directory and its directory entry to `name`.
fn rename_tenant_dir(fx: &Fx, name: &str) {
    let dir = fx.tenant_db(fx.tenant()).parent().unwrap().to_path_buf();
    let to = dir.parent().unwrap().join(name);
    std::fs::rename(&dir, &to).unwrap();
    let d = Connection::open(fx.dir.path().join("directory.db")).unwrap();
    d.execute("UPDATE tenants SET tenant_id = ?1", [name])
        .unwrap();
}

/// [STO-3] A tenant ID or space file name from a database that is not 32 or
/// 26 lowercase letters or digits is never a path. Without this, a damaged
/// row such as `../x` would make the relay open a file outside the tenant.
#[test]
fn unsafe_tenant_and_space_names_are_refused_when_found_in_the_index() {
    // The renamed directory exists, so only the name check can refuse it.
    for bad in ["{}Z", "{}", "{}aa"] {
        let fx = Fx::new();
        fx.setup_space(fx.tenant());
        assert_eq!(fx.fetch(fx.tenant(), 0, 10).status, 200);
        let id = fx
            .tenant_db(fx.tenant())
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let name = match bad {
            "{}Z" => format!("{}Z", &id[..31]),
            "{}" => id[..31].to_owned(),
            _ => format!("{id}aa"),
        };
        rename_tenant_dir(&fx, &name);
        let r = fx.fetch(fx.tenant(), 0, 10);
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (500, "internal"),
            "{name}"
        );
    }
    for bad in ["upper", "short", "long"] {
        let fx = Fx::new();
        fx.setup_space(fx.tenant());
        let file = fx.space_file(fx.tenant());
        let stem = file.file_stem().unwrap().to_str().unwrap().to_owned();
        let name = match bad {
            "upper" => format!("{}Z", &stem[..25]),
            "short" => stem[..25].to_owned(),
            _ => format!("{stem}aa"),
        };
        std::fs::rename(&file, file.with_file_name(format!("{name}.db"))).unwrap();
        let t = Connection::open(fx.tenant_db(fx.tenant())).unwrap();
        t.execute("UPDATE spaces SET file_name = ?1", [&name])
            .unwrap();
        drop(t);
        let r = fx.fetch(fx.tenant(), 0, 10);
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (500, "internal"),
            "{name}"
        );
    }
}

/// [STO-3] A handle that is not `t_` and 32 lowercase hex digits makes no
/// tenant. Without this, a bad handle would be stored in the directory.
#[test]
fn malformed_handle_creates_no_tenant() {
    let fx = Fx::new();
    for h in [
        "",
        "t_",
        "t_0000000000000000000000000000000A",
        "t_000000000000000000000000000000002",
        "x_00000000000000000000000000000002",
    ] {
        assert!(fx.relay.add_user_with_handle("lee", h).is_err(), "{h}");
    }
    let tenants = std::fs::read_dir(fx.dir.path().join("tenants"))
        .unwrap()
        .count();
    assert_eq!(tenants, 1, "only the tenant of the fixture exists");
    assert!(fx.relay.add_user("lee").is_ok(), "the name was not used");
}

/// A failed create of a space leaves no file. Without this, each retry of a
/// failed PUT would leave an orphan database file on the disk.
#[test]
fn failed_space_create_removes_its_file() {
    let fx = Fx::new();
    // A row of a deleted space with the same log ID makes the index insert fail
    // after the space file exists.
    {
        let t = Connection::open(fx.tenant_db(fx.tenant())).unwrap();
        t.execute(
            "INSERT INTO spaces (log_id, file_name, app_id, status) VALUES (?1, 'gone', 'x', 'deleted')",
            [fx.log()],
        )
        .unwrap();
    }
    let r = fx.put_genesis(fx.tenant());
    assert_eq!((r.status, error_code(&r).as_str()), (500, "internal"));
    let spaces = fx.tenant_db(fx.tenant()).parent().unwrap().join("spaces");
    let left: Vec<_> = std::fs::read_dir(spaces).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

/// The authority is a lowercase host with an optional port. Without this, a
/// relay with `Host:8080/x` or `a@b` would verify signatures against an
/// authority that no client can send.
#[test]
fn bad_authority_is_refused_at_start() {
    for bad in ["", "Example.com", "a b", "a\tb", "a/b", "a@b"] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snailfish_relay::core::Config::new(dir.path(), bad);
        assert!(Relay::open(cfg).is_err(), "{bad:?}");
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = snailfish_relay::core::Config::new(dir.path(), "relay.example.ts.net:8443");
    assert!(Relay::open(cfg).is_ok());
}

/// A database error during a check fails the append. Without this, a
/// damaged row would make the relay answer `refused` or `stored` from a
/// view that silently read nothing.
#[test]
fn storage_error_in_a_check_fails_the_append_with_500() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let first = fx.change("B", 4, [0x31; 16], 60, 7);
    assert_eq!(
        fx.append(fx.tenant(), "B", &[first]).1,
        [AppendResult::Stored(5)]
    );
    space_conn(&fx)
        .execute(
            "UPDATE entries SET record_hash = x'00' WHERE position = 5",
            [],
        )
        .unwrap();
    // Same change ID, base that is not in the log: with a healthy view the
    // answer is a 200 with `bad_base`. The unreadable stored row must win.
    let digest = encode_b64(&[0; 32]);
    let again = fx.change_on("B", 99, &digest, [0x31; 16], 60, 7);
    let r = fx.relay.handle(&fx.signed(
        "POST",
        &format!("{}/append", fx.space_path(fx.tenant(), fx.log())),
        "",
        &wire::append_body(&[again]),
        "B",
    ));
    assert_eq!((r.status, error_code(&r).as_str()), (500, "internal"));
}

/// Without this, a constant clock would make every request look expired or
/// every nonce live forever.
#[test]
fn system_time_follows_the_wall_clock() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(system_time().abs_diff(now) <= 5);
}
