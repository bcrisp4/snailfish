//! Space deletion and import on the relay (`PROTOCOL.md` 10.12 and 10.13,
//! [LOG-13], [FRK-4], [FRK-5], [STO-5], [STO-6]). The model scenario is
//! `specs/forkrepair/test.qnt::deletedThenImportedTest` and `repairTest`.
#![cfg(test)]

mod common;

use common::{Fx, error_code, keys_of};
use snailfish_protocol::delete::DELETE_TYPE;
use snailfish_protocol::encoding::encode_b64;
use snailfish_protocol::envelope::write_json;
use snailfish_protocol::records::{Author, Position};
use snailfish_protocol::wire::{self, FetchEntry, Head, OutEntry, RepairFinish};
use snailfish_protocol::write;

/// Each entry of the relay log, as an export file holds it.
fn log_entries(fx: &Fx) -> (Vec<(u64, OutEntry)>, Head) {
    let r = fx.fetch(fx.tenant(), 0, 500);
    assert_eq!(r.status, 200);
    let f = wire::parse_fetch(&r.body).unwrap();
    let out = f
        .entries
        .into_iter()
        .map(|(p, e)| match e {
            FetchEntry::Envelope(raw) => (p, OutEntry::Envelope(raw.json)),
            FetchEntry::Stub(st) => (p, OutEntry::Stub(st)),
        })
        .collect();
    (out, f.head)
}

fn statement(fx: &Fx, signer: &str, head: Position, expires: u64) -> String {
    let (sk, id, text) = fx.key(signer);
    let author = if text.starts_with("r_") {
        Author::Recovery(id)
    } else {
        Author::Device(id)
    };
    let p = write::delete(&fx.log_id(), &author, &head, expires);
    write_json(DELETE_TYPE, &p, &sk.sign_record(DELETE_TYPE, &p), &text)
}

fn now(fx: &Fx) -> u64 {
    fx.now.load(std::sync::atomic::Ordering::SeqCst)
}

fn relay_head(fx: &Fx) -> Position {
    let h = fx.head(fx.tenant());
    Position {
        position: h.position,
        digest: h.digest,
    }
}

fn delete(
    fx: &Fx,
    signer: &str,
    stmt: &str,
    setup: Option<&[u8; 32]>,
) -> snailfish_relay::core::Response {
    fx.post(
        fx.tenant(),
        "delete",
        &wire::delete_body(stmt, setup),
        signer,
    )
}

fn import_path(fx: &Fx, tail: &str) -> String {
    format!("{}/import{tail}", fx.space_path(fx.tenant(), fx.log()))
}

/// Upload `entries` in chunks of `chunk` entries, signed by `signer` with a
/// setup token of `signer`. Returns the finish response.
fn import(
    fx: &Fx,
    signer: &str,
    entries: &[(u64, OutEntry)],
    chunk: usize,
    tip: Head,
) -> snailfish_relay::core::Response {
    let token = fx.setup_token("sam", signer);
    let mut parts = entries.chunks(chunk);
    let first = parts.next().unwrap();
    let body = wire::import_start_body(&token, &keys_of(signer), first).unwrap();
    let r = fx
        .relay
        .handle(&fx.signed("POST", &import_path(fx, ""), "", &body, signer));
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let (session, mut next) = wire::parse_repair_started(&r.body).unwrap();
    for part in parts {
        assert_eq!(part[0].0, next);
        let body = wire::repair_chunk_body(&session, part).unwrap();
        let r = fx
            .relay
            .handle(&fx.signed("POST", &import_path(fx, "/chunk"), "", &body, signer));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        next = wire::parse_repair_next(&r.body).unwrap();
    }
    let body = wire::repair_finish_body(&RepairFinish { session, tip });
    fx.relay
        .handle(&fx.signed("POST", &import_path(fx, "/finish"), "", &body, signer))
}

/// [LOG-13] [FRK-4] [STO-5]: a device deletes the space. The file is gone,
/// each route of the log ID answers `deleted`, and a `PUT` of the log ID
/// cannot make it again (`deletedThenImportedTest`).
#[test]
fn deletion_removes_the_space_and_blocks_its_log_id() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let file = fx.space_file(fx.tenant());
    let stmt = statement(&fx, "A", relay_head(&fx), now(&fx) + 60);
    let r = delete(&fx, "A", &stmt, None);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(!file.exists());
    let r = fx.fetch(fx.tenant(), 0, 10);
    assert_eq!((r.status, error_code(&r).as_str()), (410, "deleted"));
    let r = fx.put_genesis(fx.tenant());
    assert_eq!((r.status, error_code(&r).as_str()), (410, "deleted"));
    let r = delete(&fx, "A", &stmt, None);
    assert_eq!((r.status, error_code(&r).as_str()), (410, "deleted"));
}

/// A deletion case: statement, signer, setup token, status and code.
type Case<'a> = (String, &'a str, Option<[u8; 32]>, u16, &'a str);

/// 10.12 steps 2 to 7: each refusal leaves the space in place.
#[test]
fn deletion_refusals_keep_the_space() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let head = relay_head(&fx);
    let t = now(&fx);
    // An older entry of the relay log is a valid head (step 6).
    let old = Position {
        position: 1,
        digest: fx.h["space"]["log"][0]["digest"]
            .as_str()
            .map(|d| hex::decode(d).unwrap().try_into().unwrap())
            .unwrap(),
    };
    let cases: Vec<Case<'_>> = vec![
        // A head after the relay head, and a wrong digest.
        (
            statement(
                &fx,
                "A",
                Position {
                    position: head.position + 1,
                    ..head
                },
                t + 60,
            ),
            "A",
            None,
            409,
            "bad_head",
        ),
        (
            statement(
                &fx,
                "A",
                Position {
                    digest: [9; 32],
                    ..head
                },
                t + 60,
            ),
            "A",
            None,
            409,
            "bad_head",
        ),
        // Outside the window of 600 seconds.
        (statement(&fx, "A", head, t), "A", None, 401, "expired"),
        (
            statement(&fx, "A", head, t + 601),
            "A",
            None,
            401,
            "expired",
        ),
        // The statement author is not the request signer.
        (
            statement(&fx, "B", head, t + 60),
            "A",
            None,
            422,
            "invalid_record",
        ),
        // A device sends no setup token, the recovery key needs one.
        (
            statement(&fx, "A", head, t + 60),
            "A",
            Some(fx.setup_token("sam", "A")),
            400,
            "bad_request",
        ),
        (
            statement(&fx, "R1", head, t + 60),
            "R1",
            None,
            400,
            "bad_request",
        ),
    ];
    for (stmt, signer, setup, status, code) in cases {
        let r = delete(&fx, signer, &stmt, setup.as_ref());
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (status, code),
            "{signer}"
        );
        assert!(fx.space_file(fx.tenant()).exists());
    }
    let r = delete(&fx, "A", &statement(&fx, "A", old, t + 600), None);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

/// [LOG-13]: the recovery key deletes the space with a setup token of the
/// tenant, which can name any device of the user.
#[test]
fn recovery_key_deletes_with_a_setup_token() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let token = fx.setup_token("sam", "C");
    let stmt = statement(&fx, "R1", relay_head(&fx), now(&fx) + 60);
    let r = delete(&fx, "R1", &stmt, Some(&token));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = fx.fetch(fx.tenant(), 0, 10);
    assert_eq!(error_code(&r), "deleted");
}

/// [FRK-5] [STO-6]: an import of the export file after a deletion makes
/// the same log again and removes the marker. The chunks continue one
/// session (`deletedThenImportedTest`).
#[test]
fn import_after_deletion_restores_the_log() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let (entries, head) = log_entries(&fx);
    let r = delete(
        &fx,
        "A",
        &statement(&fx, "A", relay_head(&fx), now(&fx) + 60),
        None,
    );
    assert_eq!(r.status, 200);
    let r = import(&fx, "A", &entries, 1, head);
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(wire::parse_repair_finished(&r.body).unwrap(), head);
    let (again, h2) = log_entries(&fx);
    assert_eq!((again, h2), (entries, head));
    // The marker is gone: the space accepts a new change.
    let change = fx.change_on(
        "A",
        head.position,
        &encode_b64(&head.digest),
        [9; 16],
        40,
        1,
    );
    let (status, results, _) = fx.append(fx.tenant(), "A", &[change]);
    assert_eq!(status, 200);
    assert!(
        matches!(results[0], wire::AppendResult::Stored(_)),
        "{results:?}"
    );
}

/// [FRK-5]: the import also goes to another relay, where the log ID was
/// never known.
#[test]
fn import_moves_the_log_to_another_relay() {
    let old = Fx::new();
    old.setup_space(old.tenant());
    let (entries, head) = log_entries(&old);
    let new = Fx::new();
    let r = import(&new, "B", &entries, 1, head);
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(log_entries(&new), (entries, head));
}

/// 10.13: the refusals of an import, each with no space made.
#[test]
fn import_refusals() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let (entries, head) = log_entries(&fx);
    // Start step 5: the space exists.
    let token = fx.setup_token("sam", "A");
    let body = wire::import_start_body(&token, &keys_of("A"), &entries[..1]).unwrap();
    let r = fx
        .relay
        .handle(&fx.signed("POST", &import_path(&fx, ""), "", &body, "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (409, "space_exists"));

    let other = Fx::new();
    // Start step 3: the token names another device, and `device` is not the keyid.
    let token_b = other.setup_token("sam", "B");
    let body = wire::import_start_body(&token_b, &keys_of("A"), &entries[..1]).unwrap();
    let r = other
        .relay
        .handle(&other.signed("POST", &import_path(&other, ""), "", &body, "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
    let body = wire::import_start_body(&token_b, &keys_of("A"), &entries[..1]).unwrap();
    let r = other
        .relay
        .handle(&other.signed("POST", &import_path(&other, ""), "", &body, "B"));
    assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_request"));
    // Start step 6: a damaged entry.
    let mut bad = entries.clone();
    if let OutEntry::Envelope(j) = &mut bad[1].1 {
        *j = j.replacen("\"payload\":\"", "\"payload\":\"AA", 1);
    }
    let token_a = other.setup_token("sam", "A");
    let body = wire::import_start_body(&token_a, &keys_of("A"), &bad[..2]).unwrap();
    let r = other
        .relay
        .handle(&other.signed("POST", &import_path(&other, ""), "", &body, "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (422, "invalid_record"));
    // Finish step 3: a wrong tip.
    let r = import(
        &other,
        "A",
        &entries,
        1,
        Head {
            position: head.position,
            digest: [1; 32],
        },
    );
    assert_eq!((r.status, error_code(&r).as_str()), (409, "bad_import"));
    let r = other.fetch(other.tenant(), 0, 10);
    assert_eq!(error_code(&r), "unknown_space");
    let spaces = other
        .tenant_db(other.tenant())
        .parent()
        .unwrap()
        .join("spaces");
    let names: Vec<String> = std::fs::read_dir(&spaces)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().all(|n| std::path::Path::new(n)
            .extension()
            .is_none_or(|e| e != "db")),
        "{names:?}"
    );
}

/// [QTA-1]: an import whose changes do not fit the space quota is refused,
/// so an import cannot pass the quota.
#[test]
fn import_over_quota_is_refused() {
    let src = Fx::new();
    src.setup_space(src.tenant());
    let mut head = log_entries(&src).1;
    for n in 0..4u8 {
        let c = src.change_on(
            "A",
            head.position,
            &encode_b64(&head.digest),
            [n + 1; 16],
            60,
            n,
        );
        let (_, res, h) = src.append(src.tenant(), "A", &[c]);
        assert!(matches!(res[0], wire::AppendResult::Stored(_)), "{res:?}");
        head = h;
    }
    let (entries, _) = log_entries(&src);
    let mut dst = Fx::new();
    let used = src.usage(src.tenant());
    dst.reopen_with(|c| c.quotas.space_bytes = used - 1);
    let token = dst.setup_token("sam", "A");
    let body = wire::import_start_body(&token, &keys_of("A"), &entries[..1]).unwrap();
    let r = dst
        .relay
        .handle(&dst.signed("POST", &import_path(&dst, ""), "", &body, "A"));
    assert_eq!(r.status, 201);
    let (session, _) = wire::parse_repair_started(&r.body).unwrap();
    let mut refused = None;
    for e in &entries[1..] {
        let body = wire::repair_chunk_body(&session, std::slice::from_ref(e)).unwrap();
        let r = dst
            .relay
            .handle(&dst.signed("POST", &import_path(&dst, "/chunk"), "", &body, "A"));
        if r.status != 200 {
            refused = Some((e.0, r.status, error_code(&r)));
            break;
        }
    }
    assert_eq!(
        refused,
        Some((entries.last().unwrap().0, 507, "quota".to_owned()))
    );
}

/// [STO-6]: a restart deletes each import session and its temporary file,
/// and finishes the rename of an imported space whose index row exists.
#[test]
fn restart_cleans_import_sessions_and_finishes_renames() {
    let mut fx = Fx::new();
    let src = Fx::new();
    src.setup_space(src.tenant());
    let (entries, head) = log_entries(&src);
    let token = fx.setup_token("sam", "A");
    let body = wire::import_start_body(&token, &keys_of("A"), &entries[..1]).unwrap();
    let r = fx
        .relay
        .handle(&fx.signed("POST", &import_path(&fx, ""), "", &body, "A"));
    assert_eq!(r.status, 201);
    let (session, _) = wire::parse_repair_started(&r.body).unwrap();
    let spaces = fx.tenant_db(fx.tenant()).parent().unwrap().join("spaces");
    let count = |suffix: &str| {
        std::fs::read_dir(&spaces)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(suffix)
            })
            .count()
    };
    assert_eq!(count(".import"), 1);
    let limits = common::limits_of(&fx.h);
    fx.restart(limits);
    assert_eq!(count(".import"), 0);
    let body = wire::repair_chunk_body(&session, &entries[1..2]).unwrap();
    let r = fx
        .relay
        .handle(&fx.signed("POST", &import_path(&fx, "/chunk"), "", &body, "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (409, "bad_import"));

    // A crash after the tenant transaction and before the rename.
    assert_eq!(import(&fx, "A", &entries, 1, head).status, 201);
    let file = fx.space_file(fx.tenant());
    std::fs::rename(&file, file.with_extension("import")).unwrap();
    fx.restart(limits);
    assert!(file.exists());
    assert_eq!(log_entries(&fx).1, head);
}

/// [STO-5]: a space file that the index does not name and whose log ID has
/// a deletion marker goes at startup.
#[test]
fn restart_deletes_a_marked_space_file() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    let file = fx.space_file(fx.tenant());
    let keep = file.with_extension("keep");
    std::fs::copy(&file, &keep).unwrap();
    let r = delete(
        &fx,
        "A",
        &statement(&fx, "A", relay_head(&fx), now(&fx) + 60),
        None,
    );
    assert_eq!(r.status, 200);
    // The file is back, as after a crash between the commit and the unlink.
    std::fs::rename(&keep, &file).unwrap();
    fx.restart(common::limits_of(&fx.h));
    assert!(!file.exists());
}

/// DESIGN.md "User roles": the relay operator deletes a space with a
/// command and no statement. The marker stays, as for a device deletion.
#[test]
fn operator_deletes_a_space() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    assert!(fx.relay.operator_delete("sam", fx.log()).unwrap());
    assert!(!fx.relay.operator_delete("sam", fx.log()).unwrap());
    let r = fx.fetch(fx.tenant(), 0, 10);
    assert_eq!(error_code(&r), "deleted");
    assert!(fx.relay.operator_delete("nobody", fx.log()).is_err());
}
