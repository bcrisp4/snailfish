//! Space deletion, import and export (`PROTOCOL.md` 10.12, 10.13 and
//! section 15, [LOG-13], [FRK-4], [FRK-5], [STO-5], [STO-6]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use snailfish_protocol::delete;
use snailfish_protocol::encoding::{Hash32, decode_id, encode_id};
use snailfish_protocol::export;
use snailfish_protocol::hash::digest0;
use snailfish_protocol::keys;
use snailfish_protocol::records::{Author, Body};
use snailfish_protocol::space::{Staged, check_genesis};
use snailfish_protocol::wire::{self, Head, OutEntry, RepairItem};

use super::{
    ApiError, ApiResult, Budget, REPAIR_ALLOWANCE, Relay, Request, SESSION_SECONDS, Signers,
    SqlView, Tenant, api, chain_result, compact, current_recovery, from_i64, load_devices,
    load_removed, load_staged_devices, move_staged, no_signer, peek_keyid, random, read_head,
    remove_db_files, run_chain, safe_name, security_state, stage, staged_stubs_valid, staged_tip,
    to_i64, user,
};
use crate::store::{self, Kind, StoreError};

/// The suffix of a temporary space file of an import session ([STO-6]).
const IMPORT_SUFFIX: &str = "import";

fn bad_import(why: &str) -> ApiError {
    api(409, "bad_import", why)
}

/// An import session row of the tenant file (10.13).
struct ImportSession {
    session: [u8; 16],
    device: Hash32,
    key: [u8; 32],
    file_name: String,
    last: u64,
}

/// An import session row as stored: session, device, key, file, last.
type ImportRow = (Vec<u8>, Vec<u8>, Vec<u8>, String, i64);

fn read_import(tc: &Connection, log: &str) -> Result<Option<ImportSession>, StoreError> {
    let row: Option<ImportRow> = tc
        .query_row(
            "SELECT session, device_id, sign_key, file_name, last FROM imports WHERE log_id = ?1",
            params![log],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((s, d, k, f, last)) = row else {
        return Ok(None);
    };
    let bad = || StoreError::Corrupt("an import session row is malformed");
    if !safe_name(&f, 26) {
        return Err(bad());
    }
    Ok(Some(ImportSession {
        session: s.try_into().map_err(|_| bad())?,
        device: d.try_into().map_err(|_| bad())?,
        key: k.try_into().map_err(|_| bad())?,
        file_name: f,
        last: from_i64(last)?,
    }))
}

fn space_path(tenant: &Tenant, name: &str, suffix: &str) -> PathBuf {
    tenant.dir.join("spaces").join(format!("{name}.{suffix}"))
}

/// The error of a log ID that the tenant does not hold: `deleted` if the
/// tenant file holds its deletion marker ([LOG-13]), else `unknown_space`.
pub(super) fn missing_space(tc: &Connection, log: &str) -> ApiError {
    match has_marker(tc, log) {
        Ok(true) => api(410, "deleted", "the space is deleted"),
        Ok(false) => api(
            404,
            "unknown_space",
            "the tenant has no space with this log ID",
        ),
        Err(e) => e.into(),
    }
}

pub(super) fn has_marker(tc: &Connection, log: &str) -> Result<bool, StoreError> {
    Ok(tc
        .query_row(
            "SELECT 1 FROM deletion_markers WHERE log_id = ?1",
            params![log],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// The log digest at `position`: position 0 has `digest(0)`.
fn digest_at(
    c: &Connection,
    log_id: &[u8; 16],
    position: u64,
) -> Result<Option<Hash32>, StoreError> {
    if position == 0 {
        return Ok(Some(digest0(log_id)));
    }
    let d: Option<Vec<u8>> = c
        .query_row(
            "SELECT digest FROM entries WHERE position = ?1",
            params![to_i64(position)?],
            |r| r.get(0),
        )
        .optional()?;
    d.map(|d| Hash32::try_from(d).map_err(|_| StoreError::Corrupt("a digest is malformed")))
        .transpose()
}

/// Write the deletion marker and drop the index row and the per-space rows
/// of the tenant file in one transaction, then delete the space file
/// ([STO-5]).
pub(super) fn delete_space_files(
    tenant: &Tenant,
    log: &str,
    path: &Path,
) -> Result<(), StoreError> {
    let mut tc = store::open(&tenant.db(), Kind::Tenant, false)?;
    let tx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT OR IGNORE INTO deletion_markers (log_id) VALUES (?1)",
        params![log],
    )?;
    for table in ["spaces", "holds", "hold_reports", "device_status"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE log_id = ?1"),
            params![log],
        )?;
    }
    tx.commit()?;
    remove_db_files(path);
    Ok(())
}

/// The quota budget of the staged log of an import (10.13 start step 6):
/// 10.6 steps 14 and 16 against the records before it, without the daily
/// limit of step 15. The `usage` and `security_usage` rows of the temporary
/// file hold the running totals, so a chunk reads no earlier entry.
fn import_budget(
    c: &Connection,
    quota: u64,
    snapshot_limit: u64,
    reserve: u64,
) -> Result<Budget, StoreError> {
    let used = from_i64(c.query_row("SELECT bytes FROM usage WHERE id = 1", [], |r| r.get(0))?)?;
    let security = from_i64(c.query_row(
        "SELECT bytes FROM security_usage WHERE id = 1",
        [],
        |r| r.get(0),
    )?)?;
    Ok(Budget {
        used,
        security,
        today: 0,
        quota,
        snapshot_limit,
        reserve,
        daily: false,
    })
}

/// Keep the running totals of an import for the next chunk. The finish
/// computes both again from the log ([QTA-1]).
fn save_import_budget(c: &Connection, b: &Budget) -> Result<(), StoreError> {
    c.execute(
        "UPDATE usage SET bytes = ?1 WHERE id = 1",
        params![to_i64(b.used)?],
    )?;
    c.execute(
        "UPDATE security_usage SET bytes = ?1 WHERE id = 1",
        params![to_i64(b.security)?],
    )?;
    Ok(())
}

impl Relay {
    // ------------------------------------------------------------- delete

    /// `POST /v1/t/{tenant}/s/{log}/delete` (10.12, [LOG-13]).
    pub(super) fn delete_space(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        self.guard(req)?;
        let signer = peek_keyid(req);
        let sp = self.open_space(tenant, log, signer.as_ref())?;
        // Step 1: 8.6 steps 1 to 4.
        match self.verify(req, now, no_signer) {
            Err(e) if e.code != "unknown_device" => return Err(e),
            _ => {}
        }
        // Step 2.
        let body = wire::parse_delete(&req.body).map_err(|e| api(400, "bad_request", e.0))?;
        let recovery = signer.is_some_and(|(_, r)| r);
        if body.setup.is_some() != recovery {
            return Err(api(
                400,
                "bad_request",
                "a deletion by the recovery key has a setup token, and a deletion by a device has none",
            ));
        }
        // Step 3: 8.6 steps 5 to 9.
        let keys = load_devices(&sp.conn)?;
        let removed = load_removed(&sp.conn)?;
        let current = if recovery {
            current_recovery(&sp.conn)?
        } else {
            None
        };
        let signers = Signers {
            keys: &keys,
            removed: &removed,
            blocked: sp.blocked,
            recovery: current,
        };
        let v = self.verify(req, now, |id, r| signers.key(id, r))?;
        Self::claim_nonce(&sp.tenant, &v, now)?;
        // Step 4.
        let key = signers.key(&v.keyid, v.recovery)?;
        let author = if v.recovery {
            Author::Recovery(v.keyid)
        } else {
            Author::Device(v.keyid)
        };
        let raw = body.statement.map_err(|e| api(422, "invalid_record", e))?;
        let d = delete::check_statement(&raw.envelope, &sp.log_id, &author, &key)
            .map_err(|e| api(422, "invalid_record", e))?;
        // Step 5.
        if let Some(t) = &body.setup {
            self.check_setup_tenant(&sp.tenant, t, None, now)?;
        }
        // Step 6.
        let head = read_head(&sp.conn)?;
        if !delete::head_ok(
            &d.head,
            head.position,
            digest_at(&sp.conn, &sp.log_id, d.head.position)?,
        ) {
            return Err(api(
                409,
                "bad_head",
                "the head is not an entry of the relay log",
            ));
        }
        // Step 7.
        if !delete::expiry_ok(d.expires, now) {
            return Err(api(
                401,
                "expired",
                "the statement is outside its time window",
            ));
        }
        // Step 8 ([STO-8]).
        let _backup = self.backup_shared()?;
        // Step 9.
        let tc = store::open(&sp.tenant.db(), Kind::Tenant, false)?;
        let path =
            Self::space_file(&sp.tenant, &tc, log)?.ok_or_else(|| missing_space(&tc, log))?;
        drop(tc);
        drop(sp.conn);
        delete_space_files(&sp.tenant, log, &path)?;
        Ok((200, wire::deleted_body()))
    }

    /// 10.12 step 5: a setup token of the tenant that has not expired. With
    /// `device`, the token must also name that device (10.5 step 3).
    pub(super) fn check_setup_tenant(
        &self,
        tenant: &Tenant,
        token: &[u8; 32],
        device: Option<&Hash32>,
        now: u64,
    ) -> ApiResult<()> {
        match device {
            Some(d) => self.check_setup(tenant, token, d, now),
            None => self.check_setup_any_device(tenant, token, now),
        }
    }

    // ------------------------------------------------------------- import

    /// `POST /v1/t/{tenant}/s/{log}/import`, `.../import/chunk` and
    /// `.../import/finish` (10.13, [FRK-5], [STO-6]).
    pub(super) fn import(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
        route: super::RepairRoute,
    ) -> ApiResult<(u16, Vec<u8>)> {
        let limits = &self.cfg.limits;
        self.guard_max(
            req,
            limits.max_request_bytes.saturating_add(REPAIR_ALLOWANCE),
        )?;
        let tenant = self.tenant(tenant)?;
        match self.verify(req, now, no_signer) {
            Err(e) if e.code != "unknown_device" => return Err(e),
            _ => {}
        }
        let log_id = decode_id::<16>(log, "l_")
            .map_err(|_| api(400, "bad_request", "the log ID is malformed"))?;
        match route {
            super::RepairRoute::Start => self.import_start(req, now, &tenant, log, &log_id),
            super::RepairRoute::Chunk => self.import_chunk(req, now, &tenant, log, &log_id),
            super::RepairRoute::Finish => self.import_finish(req, now, &tenant, log),
        }
    }

    fn quota_of(&self, tenant: &Tenant) -> Result<(u64, u64, u64), StoreError> {
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let quota = user::limits(&tc, &self.cfg.quotas)?.space_bytes;
        let snapshot_limit = quota.saturating_add(compact::snapshot_reserve(
            self.cfg.limits.max_snapshot_bytes,
        ));
        Ok((quota, snapshot_limit, self.cfg.security_reserve))
    }

    /// 10.13 start step 5: no space with the log ID, room for one more
    /// space, and no backup. Returns the backup lock.
    fn import_room(&self, tenant: &Tenant, log: &str) -> ApiResult<std::fs::File> {
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        self.room(tenant, &tc, log)?;
        self.backup_shared()
    }

    /// No space with the log ID and room for one more space, read through
    /// `tc`.
    fn room(&self, tenant: &Tenant, tc: &Connection, log: &str) -> ApiResult<()> {
        if Self::space_file(tenant, tc, log)?.is_some() {
            return Err(api(
                409,
                "space_exists",
                "the tenant holds a space with this log ID",
            ));
        }
        let spaces: i64 = tc.query_row(
            "SELECT count(*) FROM spaces WHERE status = 'active'",
            [],
            |r| r.get(0),
        )?;
        if from_i64(spaces)? >= user::limits(tc, &self.cfg.quotas)?.max_spaces {
            return Err(api(
                507,
                "space_limit",
                "the tenant holds the most spaces that its configuration allows",
            ));
        }
        Ok(())
    }

    fn import_start(
        &self,
        req: &Request,
        now: u64,
        tenant: &Tenant,
        log: &str,
        log_id: &[u8; 16],
    ) -> ApiResult<(u16, Vec<u8>)> {
        let limits = &self.cfg.limits;
        let body = wire::parse_import_start(&req.body, limits.max_append_envelopes)
            .map_err(|e| api(400, "bad_request", e.0))?;
        // Step 3.
        let device = keys::device_id(&body.device.sign, &body.device.seal);
        if peek_keyid(req).is_some_and(|(id, r)| r || id != device) {
            return Err(api(
                400,
                "bad_request",
                "device names another key than the request keyid",
            ));
        }
        self.check_setup(tenant, &body.setup, &device, now)?;
        // Step 4: 8.6 steps 5, 8 and 9 with the key of `device`.
        let blocked = {
            let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
            user::is_blocked(&tc, &encode_id("d_", &device))?
        };
        let one = BTreeMap::from([(device, body.device.sign)]);
        let none = BTreeSet::new();
        let signers = Signers {
            keys: &one,
            removed: &none,
            blocked,
            recovery: None,
        };
        let v = self.verify(req, now, |id, r| signers.key(id, r))?;
        Self::claim_nonce(tenant, &v, now)?;
        // Step 5.
        let _backup = self.import_room(tenant, log)?;
        // Step 6: the genesis record of 10.5 at position 1, then the chain.
        let (first, rest) = body
            .entries
            .split_first()
            .ok_or_else(|| api(400, "bad_request", "the start holds no entry"))?;
        let genesis = match first {
            (1, RepairItem::Envelope(raw)) => raw,
            (1, _) => {
                return Err(api(
                    422,
                    "invalid_record",
                    "position 1 must be a genesis envelope",
                ));
            }
            _ => return Err(bad_import("the first entry must have position 1")),
        };
        let acc = check_genesis(&genesis.envelope, log_id, None)
            .map_err(|r| api(422, "invalid_record", r.to_string()))?;
        let Body::Genesis { app, .. } = &acc.record.body else {
            return Err(api(
                422,
                "invalid_record",
                "position 1 must be a genesis record",
            ));
        };
        let app = app.clone();
        // Step 7. A start replaces an older session of the log ID with its
        // temporary file.
        let name = data_encoding::BASE32_NOPAD
            .encode(&random::<16>()?)
            .to_ascii_lowercase();
        let tmp = space_path(tenant, &name, IMPORT_SUFFIX);
        let made = (|| -> ApiResult<u64> {
            Self::create_space_file(&tmp, log_id, &app, &acc, &genesis.json)?;
            self.stage_import(tenant, &tmp, log_id, rest)
        })();
        let next = match made {
            Ok(n) => n,
            Err(e) => {
                remove_db_files(&tmp);
                return Err(e);
            }
        };
        let session = random::<16>()?;
        let mut tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let tx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_import(&tx, log)?;
        let saved = tx
            .execute(
                "INSERT INTO imports (log_id, session, device_id, sign_key, file_name, last)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (log_id) DO UPDATE SET session = excluded.session,
                   device_id = excluded.device_id, sign_key = excluded.sign_key,
                   file_name = excluded.file_name, last = excluded.last",
                params![
                    log,
                    session.as_slice(),
                    device.as_slice(),
                    body.device.sign.as_slice(),
                    name,
                    to_i64(now)?
                ],
            )
            .map_err(StoreError::from)
            .and_then(|_| tx.commit().map_err(StoreError::from));
        if let Err(e) = saved {
            remove_db_files(&tmp);
            return Err(e.into());
        }
        if let Some(o) = old {
            remove_db_files(&space_path(tenant, &o.file_name, IMPORT_SUFFIX));
        }
        Ok((201, wire::repair_started_body(&session, next)))
    }

    /// Check `entries` against the staged log of the temporary file and
    /// stage them (10.13 start step 6). Returns the next position.
    fn stage_import(
        &self,
        tenant: &Tenant,
        tmp: &Path,
        log_id: &[u8; 16],
        entries: &[(u64, RepairItem)],
    ) -> ApiResult<u64> {
        let mut c = store::open(tmp, Kind::Space, false)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head = staged_tip(&tx)?.map_or_else(|| read_head(&tx), Ok)?;
        if entries.is_empty() {
            return Ok(head.position.saturating_add(1));
        }
        if entries.first().map(|e| e.0) != head.position.checked_add(1) {
            return Err(bad_import("an entry is not at the next position"));
        }
        let chain = {
            let view = SqlView::new(&tx, *log_id, true);
            let c = run_chain(&view, entries);
            view.take_error()?;
            c
        };
        chain_result(&chain).map_err(|e| {
            if e.code == "bad_repair" {
                bad_import("an entry is not at the next position")
            } else {
                e
            }
        })?;
        let (quota, snapshot_limit, reserve) = self.quota_of(tenant)?;
        let mut budget = import_budget(&tx, quota, snapshot_limit, reserve)?;
        for (s, (_, item)) in chain.accepted.iter().zip(entries) {
            if let (Staged::Full(a), RepairItem::Envelope(raw)) = (s, item) {
                let len = raw.json.len() as u64;
                if budget.refusal(&a.record, len).is_some() {
                    return Err(api(
                        507,
                        "quota",
                        "the import does not fit the space quota and the reserves",
                    ));
                }
                budget.take(&a.record, len);
            }
        }
        let next = stage(&tx, &chain.accepted, entries)?;
        save_import_budget(&tx, &budget)?;
        tx.commit()?;
        Ok(next)
    }

    /// The live import session of `log`, or `bad_import`.
    fn live_import(
        tenant: &Tenant,
        log: &str,
        session: &[u8; 16],
        now: u64,
    ) -> ApiResult<ImportSession> {
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        read_import(&tc, log)?
            .filter(|x| &x.session == session && now < x.last.saturating_add(SESSION_SECONDS))
            .ok_or_else(|| bad_import("no live import session has this ID"))
    }

    fn session_signers_blocked(tenant: &Tenant, device: &Hash32) -> Result<bool, StoreError> {
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        user::is_blocked(&tc, &encode_id("d_", device))
    }

    fn import_chunk(
        &self,
        req: &Request,
        now: u64,
        tenant: &Tenant,
        log: &str,
        log_id: &[u8; 16],
    ) -> ApiResult<(u16, Vec<u8>)> {
        let body = wire::parse_repair_chunk(&req.body, self.cfg.limits.max_append_envelopes)
            .map_err(|e| api(400, "bad_request", e.0))?;
        let x = Self::live_import(tenant, log, &body.session, now)?;
        let one = BTreeMap::from([(x.device, x.key)]);
        let none = BTreeSet::new();
        let signers = Signers {
            keys: &one,
            removed: &none,
            blocked: Self::session_signers_blocked(tenant, &x.device)?,
            recovery: None,
        };
        let v = self.verify(req, now, |id, r| signers.key(id, r))?;
        Self::claim_nonce(tenant, &v, now)?;
        let tmp = space_path(tenant, &x.file_name, IMPORT_SUFFIX);
        let next = self.stage_import(tenant, &tmp, log_id, &body.entries)?;
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        tc.execute(
            "UPDATE imports SET last = ?1 WHERE log_id = ?2 AND session = ?3",
            params![to_i64(now)?, log, x.session.as_slice()],
        )?;
        Ok((200, wire::repair_next_body(next)))
    }

    fn import_finish(
        &self,
        req: &Request,
        now: u64,
        tenant: &Tenant,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        let body =
            wire::parse_repair_finish(&req.body).map_err(|e| api(400, "bad_request", e.0))?;
        // Step 1.
        let x = Self::live_import(tenant, log, &body.session, now)?;
        let tmp = space_path(tenant, &x.file_name, IMPORT_SUFFIX);
        let mut c = store::open(&tmp, Kind::Space, false)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Step 3 before step 2: the signer check reads the space state at
        // the tip, and a wrong tip changes no state either way.
        let tip = staged_tip(&tx)?.map_or_else(|| read_head(&tx), Ok)?;
        if tip != body.tip {
            return Err(bad_import("the tip is not the last staged entry"));
        }
        // Step 2: the session device if it is active at the tip, or the
        // current recovery ID at the tip.
        let mut active = load_devices(&tx)?;
        active.extend(load_staged_devices(&tx)?);
        let state = security_state(&tx, true)?;
        let removed: BTreeSet<Hash32> = state.removed.iter().copied().collect();
        let keys: BTreeMap<Hash32, [u8; 32]> = active
            .get(&x.device)
            .filter(|_| !removed.contains(&x.device))
            .map(|k| BTreeMap::from([(x.device, *k)]))
            .unwrap_or_default();
        let signers = Signers {
            keys: &keys,
            removed: &removed,
            blocked: Self::session_signers_blocked(tenant, &x.device)?,
            recovery: state.recovery,
        };
        let v = self.verify(req, now, |id, r| signers.key(id, r))?;
        Self::claim_nonce(tenant, &v, now)?;
        // Step 4 ([CMP-17]).
        if !staged_stubs_valid(&tx)? {
            return Err(api(
                422,
                "uncovered_stub",
                "no usable snapshot of the staged log covers a staged stub",
            ));
        }
        // Step 5.
        let _backup = self.backup_shared()?;
        let app: String =
            tx.query_row("SELECT app_id FROM space WHERE id = 1", [], |r| r.get(0))?;
        move_staged(&tx, &x.session, tip.position, now)?;
        tx.commit()?;
        // A WAL file belongs to its file name, so the rename needs an empty
        // WAL and a closed connection.
        c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        drop(c);
        // Step 6: the room check, the index row, the marker and the session
        // in one tenant transaction, then the rename ([STO-6]). The check
        // and the index row share the write lock, so a concurrent `PUT` or
        // finish cannot pass the check between them ([QTA-5]). A refused
        // finish keeps the session: the moved file has an empty staging
        // table, so a later finish moves nothing and succeeds.
        let mut tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let ttx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.room(tenant, &ttx, log)?;
        ttx.execute(
            "INSERT INTO spaces (log_id, file_name, app_id, status) VALUES (?1, ?2, ?3, 'active')",
            params![log, x.file_name, app],
        )?;
        ttx.execute(
            "DELETE FROM deletion_markers WHERE log_id = ?1",
            params![log],
        )?;
        ttx.execute("DELETE FROM imports WHERE log_id = ?1", params![log])?;
        ttx.commit()?;
        finish_rename(tenant, &x.file_name)?;
        Ok((201, wire::repair_finished_body(&tip)))
    }

    /// `snailfish-relay space delete`: the relay operator deletes a space
    /// of a user without a statement (DESIGN.md "User roles", [LOG-13]).
    /// Returns false if the user holds no space with the log ID.
    ///
    /// # Errors
    ///
    /// [`OpenError::UnknownUser`], `backup_running` as a storage error, or
    /// a storage failure.
    pub fn operator_delete(&self, user: &str, log: &str) -> Result<bool, super::OpenError> {
        let d = self.directory()?;
        let id: Option<String> = d
            .query_row(
                "SELECT tenant_id FROM users WHERE name = ?1",
                params![user],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::from)?;
        let tenant = self.tenant_by_id(id.ok_or(super::OpenError::UnknownUser)?)?;
        let _backup = self
            .backup_shared()
            .map_err(|_| StoreError::Corrupt("snailfish-relay backup runs: try again later"))?;
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let Some(path) = Self::space_file(&tenant, &tc, log)
            .map_err(|_| StoreError::Corrupt("a space file name is malformed"))?
        else {
            return Ok(false);
        };
        drop(tc);
        delete_space_files(&tenant, log, &path)?;
        Ok(true)
    }

    // ------------------------------------------------------------- export

    /// The export file of a space of `tenant` (section 15), from the relay
    /// log. `None` if the tenant holds no space with the log ID.
    pub(super) fn export_file(tenant: &Tenant, log: &str) -> ApiResult<Option<Vec<u8>>> {
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let Some(path) = Self::space_file(tenant, &tc, log)? else {
            return Ok(None);
        };
        drop(tc);
        let c = store::open(&path, Kind::Space, false)?;
        Ok(Some(export_space(&c)?))
    }
}

/// The export file of an open space file (section 15).
pub(crate) fn export_space(c: &Connection) -> Result<Vec<u8>, StoreError> {
    let (log_id, app): (Vec<u8>, String) =
        c.query_row("SELECT log_id, app_id FROM space WHERE id = 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let log_id: [u8; 16] = log_id
        .try_into()
        .map_err(|_| StoreError::Corrupt("a space file holds a malformed log ID"))?;
    // One read transaction, so the head and the entries agree.
    let tx = c.unchecked_transaction()?;
    let head = read_head(&tx)?;
    let mut entries = Vec::new();
    {
        let mut st = tx.prepare(
            "SELECT position, payload_type, change_id, record_hash, envelope FROM entries
             WHERE position <= ?1 ORDER BY position",
        )?;
        let mut q = st.query(params![to_i64(head.position)?])?;
        while let Some(r) = q.next()? {
            let position = from_i64(r.get(0)?)?;
            let envelope: String = r.get(4)?;
            let e = if envelope.is_empty() {
                compact::stub_of(r.get(1)?, r.get(2)?, r.get(3)?)?
            } else {
                OutEntry::Envelope(envelope)
            };
            entries.push((position, e));
        }
    }
    tx.finish()?;
    let header = export::Header {
        log_id,
        app,
        head: Head {
            position: head.position,
            digest: head.digest,
        },
    };
    export::write(&header, &entries)
        .map_err(|_| StoreError::Corrupt("a stored envelope is not JSON"))
}

fn finish_rename(tenant: &Tenant, name: &str) -> Result<(), StoreError> {
    std::fs::rename(
        space_path(tenant, name, IMPORT_SUFFIX),
        space_path(tenant, name, "db"),
    )?;
    for s in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(
            tenant
                .dir
                .join("spaces")
                .join(format!("{name}.{IMPORT_SUFFIX}{s}")),
        );
    }
    Ok(())
}

/// The log ID of the space file at `p`, or `None` if the file has no
/// readable space row.
fn file_log(p: &Path) -> Option<String> {
    let c = store::open(p, Kind::Space, false).ok()?;
    let log_id: Vec<u8> = c
        .query_row("SELECT log_id FROM space WHERE id = 1", [], |r| r.get(0))
        .ok()?;
    Some(encode_id("l_", &<[u8; 16]>::try_from(log_id).ok()?))
}

/// The startup work of one tenant directory ([STO-5], [STO-6]): delete the
/// files of each import session, finish the rename of an imported space
/// whose index row exists, and delete each space file that is not in the
/// index and has a deletion marker.
pub(super) fn sweep_tenant(tenant: &Tenant) -> Result<(), StoreError> {
    let mut tc = store::open(&tenant.db(), Kind::Tenant, false)?;
    let tx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut stale = Vec::new();
    {
        let mut st = tx.prepare("SELECT file_name FROM imports")?;
        let mut q = st.query([])?;
        while let Some(r) = q.next()? {
            let f: String = r.get(0)?;
            if safe_name(&f, 26) {
                stale.push(f);
            }
        }
    }
    tx.execute("DELETE FROM imports", [])?;
    tx.commit()?;
    for f in stale {
        remove_db_files(&space_path(tenant, &f, IMPORT_SUFFIX));
    }
    let mut indexed = BTreeSet::new();
    {
        let mut st = tc.prepare("SELECT file_name FROM spaces")?;
        let mut q = st.query([])?;
        while let Some(r) = q.next()? {
            indexed.insert(r.get::<_, String>(0)?);
        }
    }
    let dir = tenant.dir.join("spaces");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(());
    };
    for e in rd {
        let p = e?.path();
        let Some(file) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stem) = file.strip_suffix(&format!(".{IMPORT_SUFFIX}")) {
            if indexed.contains(stem) && !space_path(tenant, stem, "db").exists() {
                finish_rename(tenant, stem)?;
            } else if safe_name(stem, 26) {
                remove_db_files(&p);
            }
        } else if let Some(stem) = file.strip_suffix(".db")
            && safe_name(stem, 26)
            && !indexed.contains(stem)
        {
            // A file with no readable log ID stays: a `PUT` that stopped
            // before its space row leaves one. It must not stop the start.
            if let Some(log) = file_log(&p)
                && has_marker(&tc, &log)?
            {
                remove_db_files(&p);
            }
        }
    }
    Ok(())
}
