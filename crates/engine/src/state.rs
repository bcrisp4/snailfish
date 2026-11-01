//! The engine state file: the outbox and the verified log ([DLV-1],
//! [DLV-5], [DLV-8], [DLV-10], [DLV-12]).
//!
//! Each public operation is one SQLite transaction, so a crash at any point
//! leaves the state of the last commit (`specs/delivery/model.qnt`: each
//! engine transaction is one atomic action).

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use snailfish_protocol::encoding::{Hash32, hash_frame};
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::hash::digest0;
use snailfish_protocol::keys;
use snailfish_protocol::records::{Body, Position};
use snailfish_protocol::space::{Accepted, SpaceView};
use snailfish_protocol::{envelope, write};

use crate::{
    Applied, Change, Engine, EngineError, EnqueueResult, OutboxRow, SCHEMA_VERSION, refuse_newer,
};

/// The state of an outbox row.
pub(crate) const PENDING: &str = "pending";
pub(crate) const REFUSED: &str = "refused";

/// Open the state file with the durable settings and the schema, and bind
/// it to one log and one device.
pub(crate) fn open(db: &Connection, log_id: &[u8; 16], device: &Hash32) -> Result<(), EngineError> {
    // [VER-15]: refuse a file from a newer engine before the first write.
    // The journal mode change below writes the file header.
    refuse_newer(db)?;
    // [DLV-1]: WAL with synchronous=FULL, and fullfsync on Apple platforms,
    // so that a commit survives a power loss.
    db.pragma_update(None, "journal_mode", "WAL")?;
    db.pragma_update(None, "synchronous", "FULL")?;
    if cfg!(target_vendor = "apple") {
        db.pragma_update(None, "fullfsync", "ON")?;
        db.pragma_update(None, "checkpoint_fullfsync", "ON")?;
    }
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    migrate(db)?;
    let bound: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row("SELECT log_id, device_id FROM meta", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    match bound {
        None => {
            db.execute(
                // A new state file is fresh until a fetch reaches the relay
                // head with no hold ([LOG-14], PROTOCOL.md 10.8).
                "INSERT INTO meta (id, log_id, device_id, caught_up, fresh) VALUES (1, ?1, ?2, 0, 1)",
                params![&log_id[..], &device[..]],
            )?;
        }
        Some((l, d)) if l == log_id && d == device => {}
        Some(_) => {
            return Err(EngineError::Invalid(
                "the state file belongs to another space or device".into(),
            ));
        }
    }
    Ok(())
}

fn migrate(db: &Connection) -> Result<(), EngineError> {
    let found = refuse_newer(db)?;
    if found < 1 {
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE relay_info (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL);
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
    }
    if found < 2 {
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE meta (
               id INTEGER PRIMARY KEY CHECK (id = 1),
               log_id BLOB NOT NULL,
               device_id BLOB NOT NULL,
               caught_up INTEGER NOT NULL
             );
             CREATE TABLE outbox (
               seq INTEGER PRIMARY KEY AUTOINCREMENT,
               change_id BLOB NOT NULL UNIQUE,
               content_hash BLOB NOT NULL,
               ciphertext BLOB NOT NULL,
               envelope TEXT,
               state TEXT NOT NULL,
               cause TEXT
             );
             CREATE TABLE log (
               position INTEGER PRIMARY KEY,
               payload_type TEXT NOT NULL,
               change_id BLOB UNIQUE,
               record_hash BLOB NOT NULL,
               digest BLOB NOT NULL,
               envelope TEXT NOT NULL,
               content_hash BLOB
             );
             CREATE TABLE devices (id BLOB PRIMARY KEY, sign BLOB NOT NULL);
             CREATE TABLE space (id INTEGER PRIMARY KEY CHECK (id = 1), level INTEGER NOT NULL);
             CREATE TABLE setup (
               seq INTEGER PRIMARY KEY,
               record_hash BLOB NOT NULL UNIQUE,
               envelope TEXT NOT NULL
             );
             PRAGMA user_version = 2;
             COMMIT;",
        )?;
    }
    if found < 3 {
        // A file from before M3 is not new: its engine already fetched.
        db.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE meta ADD COLUMN fresh INTEGER NOT NULL DEFAULT 0;
             CREATE TABLE repairs (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               first INTEGER NOT NULL,
               tip INTEGER NOT NULL
             );
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }
    if found < 4 {
        // M4: the grants of an enrollment, and the checkpoint that a new
        // device checks before it uploads anything ([ENR-9]).
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE grants (
               device_id BLOB PRIMARY KEY,
               device TEXT NOT NULL,
               confirmed TEXT NOT NULL,
               by_recovery INTEGER NOT NULL,
               envelope TEXT,
               state TEXT NOT NULL
             );
             CREATE TABLE enrollment (
               id INTEGER PRIMARY KEY CHECK (id = 1),
               position INTEGER NOT NULL,
               digest BLOB NOT NULL,
               trusted BLOB NOT NULL,
               device TEXT NOT NULL
             );
             PRAGMA user_version = 4;
             COMMIT;",
        )?;
    }
    const { assert!(SCHEMA_VERSION == 4) };
    Ok(())
}

/// The hash of app change bytes. The engine compares it to find a known
/// `change_id` with other bytes ([DLV-5], [DLV-6]). It is local state, not
/// a protocol value.
pub(crate) fn content_hash(bytes: &[u8]) -> Hash32 {
    hash_frame(&[b"snailfish.engine.content.v1", bytes])
}

/// The verified log head: position and digest.
pub(crate) fn head(db: &Connection, log_id: &[u8; 16]) -> Result<(u64, Hash32), EngineError> {
    let row: Option<(i64, Vec<u8>)> = db
        .query_row(
            "SELECT position, digest FROM log ORDER BY position DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok((0, digest0(log_id))),
        Some((p, d)) => Ok((to_u64(p)?, to_hash(&d)?)),
    }
}

fn to_u64(n: i64) -> Result<u64, EngineError> {
    u64::try_from(n).map_err(|_| EngineError::Storage("negative position".into()))
}

fn to_i64(n: u64) -> Result<i64, EngineError> {
    i64::try_from(n).map_err(|_| EngineError::Storage("position out of range".into()))
}

fn to_hash(b: &[u8]) -> Result<Hash32, EngineError> {
    b.try_into()
        .map_err(|_| EngineError::Storage("a stored hash is not 32 bytes".into()))
}

pub(crate) fn outbox_len(db: &Connection) -> Result<u64, EngineError> {
    let n: i64 = db.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?;
    to_u64(n)
}

/// Sign the change of an outbox row with the current verified head as the
/// base. The engine signs each row once: a retry sends the same envelope
/// ([DLV-7]).
fn sign_change(e: &Engine, base: &Position, change_id: &[u8; 16], ciphertext: &[u8]) -> String {
    let payload = write::change(&e.log_id, &e.device_id, base, 1, change_id, ciphertext);
    let sig = e.sign.sign_record("snailfish.change.v1", &payload);
    envelope::write_json("snailfish.change.v1", &payload, &sig, &e.device())
}

impl Engine {
    fn device(&self) -> String {
        self.device_id()
    }
}

pub(crate) fn enqueue(e: &mut Engine, rows: &[OutboxRow]) -> Result<EnqueueResult, EngineError> {
    let mut parsed = Vec::with_capacity(rows.len());
    for r in rows {
        let cid: [u8; 16] = r
            .change_id
            .as_slice()
            .try_into()
            .map_err(|_| EngineError::Invalid("a change_id must be 16 bytes".into()))?;
        parsed.push((cid, r));
    }
    let base = e.base()?;
    let log_id = e.log_id;
    let device = e.device_id;
    let app_key = e.app_key.ok_or_else(|| {
        EngineError::Invalid(
            "the engine has no app key yet: the enrollment check has not passed".into(),
        )
    })?;
    // Encrypt and sign before the transaction: the CSPRNG and the
    // signature need no database state.
    let mut prepared = Vec::with_capacity(parsed.len());
    for (cid, r) in &parsed {
        let aad = keys::change_aad(&log_id, 1, cid, &device);
        let ct = keys::encrypt(&app_key, &aad, &r.change_bytes).map_err(|_| EngineError::Random)?;
        let env = (base.position >= 1).then(|| sign_change(e, &base, cid, &ct));
        prepared.push((*cid, content_hash(&r.change_bytes), ct, env));
    }
    let tx = Transaction::new_unchecked(&e.db, TransactionBehavior::Immediate)?;
    let mut out = EnqueueResult {
        stored: Vec::new(),
        refused: Vec::new(),
    };
    for (cid, hash, ct, env) in prepared {
        let in_outbox: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT content_hash, state FROM outbox WHERE change_id = ?1",
                [&cid[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let in_log: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT content_hash FROM log WHERE change_id = ?1",
                [&cid[..]],
                |r| r.get(0),
            )
            .optional()?;
        match (in_outbox, in_log) {
            (Some((h, state)), _) => {
                if h != hash || state == REFUSED {
                    out.refused.push(cid.to_vec());
                }
            }
            (None, Some(h)) => {
                if h.as_deref() != Some(&hash[..]) {
                    out.refused.push(cid.to_vec());
                }
            }
            (None, None) => {
                tx.execute(
                    "INSERT INTO outbox (change_id, content_hash, ciphertext, envelope, state)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![&cid[..], &hash[..], ct, env, PENDING],
                )?;
                out.stored.push(cid.to_vec());
            }
        }
    }
    tx.commit()?;
    Ok(out)
}

/// One outbox row: seq, change ID, ciphertext and the signed envelope.
type OutboxItem = (i64, Vec<u8>, Vec<u8>, Option<String>);

/// One outbox envelope to push.
pub(crate) struct Pending {
    pub change_id: [u8; 16],
    pub envelope: String,
}

/// The pending outbox envelopes in enqueue order. A row that the engine
/// could not sign at enqueue (no verified log yet) is signed now, once,
/// with the current verified head as its base.
pub(crate) fn pending(e: &mut Engine, max: usize) -> Result<Vec<Pending>, EngineError> {
    let base = e.base()?;
    let tx = Transaction::new_unchecked(&e.db, TransactionBehavior::Immediate)?;
    let rows: Vec<OutboxItem> = {
        let mut st = tx.prepare(
            "SELECT seq, change_id, ciphertext, envelope FROM outbox
             WHERE state = ?1 ORDER BY seq LIMIT ?2",
        )?;
        st.query_map(
            params![PENDING, i64::try_from(max).unwrap_or(i64::MAX)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?
        .collect::<Result<_, _>>()?
    };
    let mut out = Vec::with_capacity(rows.len());
    for (seq, cid, ct, env) in rows {
        let cid: [u8; 16] = cid
            .try_into()
            .map_err(|_| EngineError::Storage("a stored change_id is not 16 bytes".into()))?;
        let env = if let Some(env) = env {
            env
        } else {
            // Sync pushes only after a fetch to the relay head, and the
            // genesis record is at position 1, so the base is never 0 here
            // ([LOG-6]).
            if base.position == 0 {
                return Err(EngineError::Invalid(
                    "a change needs a verified log before the push".into(),
                ));
            }
            let env = sign_change(e, &base, &cid, &ct);
            tx.execute(
                "UPDATE outbox SET envelope = ?1 WHERE seq = ?2",
                params![env, seq],
            )?;
            env
        };
        out.push(Pending {
            change_id: cid,
            envelope: env,
        });
    }
    tx.commit()?;
    Ok(out)
}

/// The relay refused an envelope for ever ([DLV-9]).
pub(crate) fn refuse(
    db: &Connection,
    change_id: &[u8; 16],
    cause: &str,
) -> Result<(), EngineError> {
    db.execute(
        "UPDATE outbox SET state = ?1, cause = ?2 WHERE change_id = ?3",
        params![REFUSED, cause, &change_id[..]],
    )?;
    Ok(())
}

/// The first cause of a refused outbox row, if any.
pub(crate) fn refused_cause(db: &Connection) -> Result<Option<String>, EngineError> {
    Ok(db
        .query_row(
            "SELECT cause FROM outbox WHERE state = ?1 ORDER BY seq LIMIT 1",
            [REFUSED],
            |r| r.get(0),
        )
        .optional()?)
}

/// True if the state file is new since the last fetch that reached the
/// relay head with no hold ([LOG-14]).
pub(crate) fn fresh(db: &Connection) -> Result<bool, EngineError> {
    Ok(db.query_row("SELECT fresh FROM meta", [], |r| r.get::<_, i64>(0))? != 0)
}

pub(crate) fn clear_fresh(db: &Connection) -> Result<(), EngineError> {
    db.execute("UPDATE meta SET fresh = 0", [])?;
    Ok(())
}

/// The verified entries from `first` to `last`, as stored envelope text.
pub(crate) fn log_range(
    db: &Connection,
    first: u64,
    last: u64,
) -> Result<Vec<(u64, String)>, EngineError> {
    let mut st = db.prepare(
        "SELECT position, envelope FROM log WHERE position BETWEEN ?1 AND ?2 ORDER BY position",
    )?;
    let rows = st.query_map([to_i64(first)?, to_i64(last)?], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
    })?;
    rows.map(|r| {
        let (p, e) = r?;
        Ok((to_u64(p)?, e))
    })
    .collect()
}

/// The verified digest at a position, outside a transaction.
pub(crate) fn verified_digest(
    db: &Connection,
    log_id: &[u8; 16],
    position: u64,
) -> Result<Option<Hash32>, EngineError> {
    digest_at(db, log_id, position)
}

/// Record a finished repair for the app (S6).
pub(crate) fn add_repair(db: &Connection, first: u64, tip: u64) -> Result<(), EngineError> {
    db.execute(
        "INSERT INTO repairs (first, tip) VALUES (?1, ?2)",
        [to_i64(first)?, to_i64(tip)?],
    )?;
    Ok(())
}

/// Take the recorded repairs, oldest first, in one transaction.
pub(crate) fn take_repairs(db: &Connection) -> Result<Vec<(u64, u64)>, EngineError> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let out = {
        let mut st = tx.prepare("SELECT first, tip FROM repairs ORDER BY id")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
        rows.map(|r| {
            let (a, b) = r?;
            Ok((to_u64(a)?, to_u64(b)?))
        })
        .collect::<Result<Vec<_>, EngineError>>()?
    };
    tx.execute("DELETE FROM repairs", [])?;
    tx.commit()?;
    Ok(out)
}

pub(crate) fn set_caught_up(db: &Connection, v: bool) -> Result<(), EngineError> {
    db.execute("UPDATE meta SET caught_up = ?1", [i64::from(v)])?;
    Ok(())
}

/// A view of the verified log inside one transaction.
pub(crate) struct DbSpace<'a> {
    pub tx: &'a Transaction<'a>,
    pub log_id: [u8; 16],
}

impl SpaceView for DbSpace<'_> {
    fn log_id(&self) -> [u8; 16] {
        self.log_id
    }
    fn head(&self) -> u64 {
        head(self.tx, &self.log_id).map_or(0, |h| h.0)
    }
    fn digest_at(&self, position: u64) -> Option<Hash32> {
        digest_at(self.tx, &self.log_id, position).ok().flatten()
    }
    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.tx
            .query_row("SELECT sign FROM devices WHERE id = ?1", [&id[..]], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|b| b.try_into().ok())
    }
    fn recovery_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.tx
            .query_row("SELECT envelope FROM log WHERE position = 1", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|g| snailfish_protocol::space::genesis_recovery_of(&g))
            .filter(|(r, _)| r == id)
            .map(|(_, k)| k)
    }
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)> {
        self.tx
            .query_row(
                "SELECT position, record_hash FROM log WHERE change_id = ?1",
                [&change_id[..]],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|(p, h)| Some((u64::try_from(p).ok()?, h.try_into().ok()?)))
    }
    fn write_level(&self) -> u64 {
        self.tx
            .query_row("SELECT level FROM space", [], |r| r.get::<_, i64>(0))
            .ok()
            .and_then(|l| u64::try_from(l).ok())
            .unwrap_or(1)
    }
    fn epoch(&self) -> u64 {
        1
    }
    fn last_security(&self) -> u64 {
        // Fail closed: on a read error every security record is stale, so
        // the fetch stops instead of accepting a record that [LOG-7] refuses.
        self.tx
            .query_row(
                &format!("SELECT COALESCE(MAX(position), 0) FROM log WHERE {NOT_SECURITY}"),
                [],
                |r| r.get::<_, i64>(0),
            )
            .ok()
            .and_then(|p| u64::try_from(p).ok())
            .unwrap_or(u64::MAX)
    }
}

/// An SQL condition: the row is a security record ([VER-5], [LOG-7]).
const NOT_SECURITY: &str = "payload_type NOT LIKE 'snailfish.change.%' \
     AND payload_type NOT LIKE 'snailfish.snapshot.%' \
     AND payload_type NOT LIKE 'snailfish.accept.%'";

fn digest_at(
    db: &Connection,
    log_id: &[u8; 16],
    position: u64,
) -> Result<Option<Hash32>, EngineError> {
    if position == 0 {
        return Ok(Some(digest0(log_id)));
    }
    let d: Option<Vec<u8>> = db
        .query_row(
            "SELECT digest FROM log WHERE position = ?1",
            [to_i64(position)?],
            |r| r.get(0),
        )
        .optional()?;
    d.map(|d| to_hash(&d)).transpose()
}

/// What the app must learn after a fetched entry.
pub(crate) enum Own {
    /// Not an own change.
    No,
    /// An own change with the same bytes: the outbox row is gone ([DLV-8]).
    Stored,
    /// An own `change_id` with other bytes ([DLV-6]).
    Conflict,
}

/// Store one verified entry. The caller checked it with the space-state
/// check against the same transaction. An own change leaves the outbox
/// only now, when the verified log holds it ([DLV-8]).
pub(crate) fn store_entry(
    tx: &Transaction<'_>,
    env: &Envelope,
    json: &str,
    a: &Accepted,
    content: Option<Hash32>,
) -> Result<Own, EngineError> {
    let cid = a.record.change_id().map(|c| c.to_vec());
    tx.execute(
        "INSERT INTO log (position, payload_type, change_id, record_hash, digest, envelope, content_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            to_i64(a.position)?,
            env.payload_type,
            cid,
            &a.record_hash[..],
            &a.digest[..],
            json,
            content.map(|c| c.to_vec()),
        ],
    )?;
    if let Some((id, key)) = a.new_device {
        tx.execute(
            "INSERT INTO devices (id, sign) VALUES (?1, ?2)",
            params![&id[..], &key[..]],
        )?;
    }
    if let Body::Genesis { level, .. } = a.record.body {
        tx.execute(
            "INSERT INTO space (id, level) VALUES (1, ?1)",
            [to_i64(level)?],
        )?;
    }
    let Some(cid) = cid else {
        return Ok(Own::No);
    };
    let row: Option<Vec<u8>> = tx
        .query_row(
            "SELECT content_hash FROM outbox WHERE change_id = ?1",
            [&cid],
            |r| r.get(0),
        )
        .optional()?;
    match row {
        None => Ok(Own::No),
        Some(h) if Some(h.as_slice()) == content.as_ref().map(|c| &c[..]) => {
            tx.execute("DELETE FROM outbox WHERE change_id = ?1", [&cid])?;
            Ok(Own::Stored)
        }
        Some(_) => {
            tx.execute(
                "UPDATE outbox SET state = ?1, cause = 'conflict' WHERE change_id = ?2",
                params![REFUSED, &cid],
            )?;
            Ok(Own::Conflict)
        }
    }
}

pub(crate) fn changes_after(
    e: &Engine,
    applied: &Applied,
    max: usize,
) -> Result<Vec<Change>, EngineError> {
    let tx = Transaction::new_unchecked(&e.db, TransactionBehavior::Deferred)?;
    let (head_pos, _) = head(&tx, &e.log_id)?;
    if applied.position > head_pos {
        // [DLV-12], F2: after the end of a log that the engine fetched to the
        // relay head. M2 has no restore hold.
        let caught_up: i64 = tx.query_row("SELECT caught_up FROM meta", [], |r| r.get(0))?;
        return if caught_up == 1 {
            Err(EngineError::ResetRequired)
        } else {
            Ok(Vec::new())
        };
    }
    if digest_at(&tx, &e.log_id, applied.position)? != Some(applied.digest) {
        return Err(EngineError::ResetRequired);
    }
    let mut st = tx.prepare(
        "SELECT position, digest, envelope, change_id FROM log
         WHERE position > ?1 AND change_id IS NOT NULL AND content_hash IS NOT NULL
         ORDER BY position LIMIT ?2",
    )?;
    let rows: Vec<(i64, Vec<u8>, String, Vec<u8>)> = st
        .query_map(
            params![
                to_i64(applied.position)?,
                i64::try_from(max).unwrap_or(i64::MAX)
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for (pos, digest, json, cid) in rows {
        let env = Envelope::parse(json.as_bytes())
            .map_err(|e| EngineError::Storage(format!("stored envelope: {e}")))?;
        let bytes = decrypt_change(e, &env)
            .ok_or_else(|| EngineError::Storage("a stored change does not decrypt".into()))?;
        out.push(Change {
            position: to_u64(pos)?,
            digest: to_hash(&digest)?,
            change_id: cid,
            change_bytes: bytes,
        });
    }
    Ok(out)
}

/// Decrypt a change record with the app key ([DLV-13]: `None` if it does
/// not decrypt).
pub(crate) fn decrypt_change(e: &Engine, env: &Envelope) -> Option<Vec<u8>> {
    let r = snailfish_protocol::records::parse_payload(&env.payload_type, &env.payload).ok()?;
    let Body::Change {
        epoch,
        change_id,
        ciphertext,
    } = &r.body
    else {
        return None;
    };
    let aad = keys::change_aad(&r.log, *epoch, change_id, r.author.id());
    keys::decrypt(e.app_key.as_ref()?, &aad, ciphertext).ok()
}

/// Store the setup record of a new space: the genesis record at seq 1.
/// Sync uploads it and deletes it when the verified log holds it.
pub(crate) fn add_setup(db: &Connection, envelopes: &[String]) -> Result<(), EngineError> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    for (i, json) in envelopes.iter().enumerate() {
        let env = Envelope::parse(json.as_bytes())
            .map_err(|e| EngineError::Invalid(format!("setup record: {e}")))?;
        tx.execute(
            "INSERT OR IGNORE INTO setup (seq, record_hash, envelope) VALUES (?1, ?2, ?3)",
            params![
                i64::try_from(i).unwrap_or(i64::MAX).saturating_add(1),
                &env.record_hash()[..],
                json
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// The genesis record of the setup, if the verified log does not hold it.
pub(crate) fn setup_genesis(db: &Connection) -> Result<Option<String>, EngineError> {
    Ok(db
        .query_row("SELECT envelope FROM setup WHERE seq = 1", [], |r| r.get(0))
        .optional()?)
}

/// The record hash of the setup genesis record, if the verified log does
/// not hold it.
pub(crate) fn setup_genesis_hash(db: &Connection) -> Result<Option<Hash32>, EngineError> {
    let h: Option<Vec<u8>> = db
        .query_row("SELECT record_hash FROM setup WHERE seq = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    h.map(|h| {
        Hash32::try_from(h)
            .map_err(|_| EngineError::Storage("a stored record hash is not 32 bytes".into()))
    })
    .transpose()
}

/// Delete a setup record that the verified log now holds.
pub(crate) fn drop_setup(tx: &Transaction<'_>, record_hash: &Hash32) -> Result<(), EngineError> {
    tx.execute(
        "DELETE FROM setup WHERE record_hash = ?1",
        [&record_hash[..]],
    )?;
    Ok(())
}

// ---------------------------------------------------------------- M4

/// The send state of a grant in the grant outbox ([LOG-7]).
pub(crate) const GRANT_SEND: &str = "send";
/// The relay refused the grant with `stale_base`. The next sync checks the
/// space state again before it signs again.
pub(crate) const GRANT_STALE: &str = "stale";
/// A grant or a removal arrived, or the recovery key signed the grant: the
/// user must confirm again.
pub(crate) const GRANT_CONFIRM: &str = "confirm";

/// One grant of the grant outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantRow {
    pub device_id: Hash32,
    pub device: String,
    pub confirmed: String,
    pub by_recovery: bool,
    pub envelope: Option<String>,
    pub state: String,
}

/// The active devices of the verified log as the sorted, comma-joined
/// device ID texts: the list that the user confirms ([LOG-7]).
pub(crate) fn device_list(db: &Connection) -> Result<String, EngineError> {
    let mut st = db.prepare("SELECT id FROM devices ORDER BY id")?;
    let ids: Vec<Vec<u8>> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(ids
        .iter()
        .map(|i| snailfish_protocol::encoding::encode_id("d_", i))
        .collect::<Vec<_>>()
        .join(","))
}

/// True if the device is active in the verified log.
pub(crate) fn is_active(db: &Connection, id: &Hash32) -> Result<bool, EngineError> {
    Ok(db
        .query_row("SELECT 1 FROM devices WHERE id = ?1", [&id[..]], |_| Ok(()))
        .optional()?
        .is_some())
}

pub(crate) fn put_grant(db: &Connection, g: &GrantRow) -> Result<(), EngineError> {
    db.execute(
        "INSERT INTO grants (device_id, device, confirmed, by_recovery, envelope, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (device_id) DO UPDATE SET device = excluded.device,
           confirmed = excluded.confirmed, by_recovery = excluded.by_recovery,
           envelope = excluded.envelope, state = excluded.state",
        params![
            &g.device_id[..],
            g.device,
            g.confirmed,
            i64::from(g.by_recovery),
            g.envelope,
            g.state
        ],
    )?;
    Ok(())
}

pub(crate) fn grants(db: &Connection) -> Result<Vec<GrantRow>, EngineError> {
    let mut st = db.prepare(
        "SELECT device_id, device, confirmed, by_recovery, envelope, state FROM grants ORDER BY device_id",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            GrantRow {
                device_id: [0; 32],
                device: r.get(1)?,
                confirmed: r.get(2)?,
                by_recovery: r.get::<_, i64>(3)? != 0,
                envelope: r.get(4)?,
                state: r.get(5)?,
            },
        ))
    })?;
    rows.map(|r| {
        let (id, mut g) = r?;
        g.device_id = to_hash(&id)?;
        Ok(g)
    })
    .collect()
}

pub(crate) fn set_grant_state(
    db: &Connection,
    id: &Hash32,
    state: &str,
) -> Result<(), EngineError> {
    db.execute(
        "UPDATE grants SET state = ?2 WHERE device_id = ?1",
        params![&id[..], state],
    )?;
    Ok(())
}

pub(crate) fn drop_grant(db: &Connection, id: &Hash32) -> Result<(), EngineError> {
    db.execute("DELETE FROM grants WHERE device_id = ?1", [&id[..]])?;
    Ok(())
}

/// The checkpoint of an enrollment that the new device has not checked yet
/// ([ENR-9]): position, digest, the trusted device and the device object
/// of `new.hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingCheckpoint {
    pub position: u64,
    pub digest: Hash32,
    pub trusted: Hash32,
    pub device: String,
}

pub(crate) fn set_checkpoint(db: &Connection, c: &PendingCheckpoint) -> Result<(), EngineError> {
    db.execute(
        "INSERT OR REPLACE INTO enrollment (id, position, digest, trusted, device)
         VALUES (1, ?1, ?2, ?3, ?4)",
        params![to_i64(c.position)?, &c.digest[..], &c.trusted[..], c.device],
    )?;
    Ok(())
}

pub(crate) fn checkpoint(db: &Connection) -> Result<Option<PendingCheckpoint>, EngineError> {
    let row: Option<(i64, Vec<u8>, Vec<u8>, String)> = db
        .query_row(
            "SELECT position, digest, trusted, device FROM enrollment WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    row.map(|(p, d, t, device)| {
        Ok(PendingCheckpoint {
            position: to_u64(p)?,
            digest: to_hash(&d)?,
            trusted: to_hash(&t)?,
            device,
        })
    })
    .transpose()
}

pub(crate) fn clear_checkpoint(db: &Connection) -> Result<(), EngineError> {
    db.execute("DELETE FROM enrollment", [])?;
    Ok(())
}

/// The position of the record that makes `id` active: the genesis record
/// or a grant. `None` if the verified log does not name it.
pub(crate) fn activation(
    db: &Connection,
    id: &Hash32,
) -> Result<Option<(u64, String)>, EngineError> {
    let mut st = db.prepare(
        "SELECT position, envelope FROM log
         WHERE payload_type IN ('snailfish.genesis.v1', 'snailfish.grant.v1') ORDER BY position",
    )?;
    let rows: Vec<(i64, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (p, json) in rows {
        let Ok(env) = Envelope::parse(json.as_bytes()) else {
            continue;
        };
        let Ok(r) = snailfish_protocol::records::parse_payload(&env.payload_type, &env.payload)
        else {
            continue;
        };
        let (Body::Genesis { device, .. } | Body::Grant { device, .. }) = &r.body else {
            continue;
        };
        if &device.id == id {
            return Ok(Some((to_u64(p)?, json)));
        }
    }
    Ok(None)
}

/// Set the content hash of each change that the engine stored before it
/// had the app key, for example during an enrollment ([DLV-13]). Returns
/// the position of the first change that does not decrypt.
pub(crate) fn fill_content(e: &Engine) -> Result<Option<u64>, EngineError> {
    let tx = Transaction::new_unchecked(&e.db, TransactionBehavior::Immediate)?;
    let rows: Vec<(i64, String)> = {
        let mut st = tx.prepare(
            "SELECT position, envelope FROM log
             WHERE change_id IS NOT NULL AND content_hash IS NULL ORDER BY position",
        )?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    let mut failed = None;
    for (p, json) in rows {
        let env = Envelope::parse(json.as_bytes())
            .map_err(|err| EngineError::Storage(format!("stored envelope: {err}")))?;
        match decrypt_change(e, &env) {
            Some(b) => {
                tx.execute(
                    "UPDATE log SET content_hash = ?2 WHERE position = ?1",
                    params![p, &content_hash(&b)[..]],
                )?;
            }
            None => {
                failed = failed.or(Some(to_u64(p)?));
            }
        }
    }
    tx.commit()?;
    Ok(failed)
}
