//! Log compaction in the engine (`PROTOCOL.md` 14.7, DESIGN.md "Log
//! compaction", `specs/compaction/model.qnt`).
//!
//! A stub keeps its `log` row with an empty `envelope`, as on the relay:
//! the digest chain and the known `change_id` checks work unchanged
//! ([CMP-1]). A snapshot or an accept record that the engine signs waits in
//! the `records` table until a fetch shows its record hash in the verified
//! log, as the setup record does.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use snailfish_protocol::compaction::{self, Compaction};
use snailfish_protocol::encoding::Hash32;
use snailfish_protocol::envelope::{self, Envelope};
use snailfish_protocol::keys;
use snailfish_protocol::records::{Body, Position, parse_payload};
use snailfish_protocol::write;

use crate::{Applied, Engine, EngineError, Snapshot, Status};

/// `snapshot_due` after this many changes after the last snapshot (14.7).
pub const SNAPSHOT_CHANGES: u64 = 1000;
/// `snapshot_due` after this many bytes of change envelopes after the last
/// snapshot (14.7).
pub const SNAPSHOT_BYTES: u64 = 1 << 20;

fn storage(e: impl std::fmt::Display) -> EngineError {
    EngineError::Storage(e.to_string())
}

fn to_i64(n: u64) -> Result<i64, EngineError> {
    i64::try_from(n).map_err(|_| storage("position out of range"))
}

fn to_u64(n: i64) -> Result<u64, EngineError> {
    u64::try_from(n).map_err(|_| storage("negative position"))
}

/// The compaction state of the verified log (`PROTOCOL.md` 14.1).
pub(crate) fn compaction_state(db: &Connection) -> Result<Compaction, EngineError> {
    let rows: Vec<(i64, String)> = {
        let mut st = db.prepare(&format!(
            "SELECT position, envelope FROM log WHERE {} ORDER BY position",
            compaction::replay_sql()
        ))?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for (p, e) in &rows {
        parsed.push((to_u64(*p)?, e.as_str()));
    }
    let (mut cmp, starts) = compaction::replay(parsed).map_err(storage)?;
    for (i, (epoch, start)) in starts.iter().enumerate() {
        let end = starts
            .get(i.saturating_add(1))
            .map_or(Ok(i64::MAX), |(_, p)| to_i64(*p))?;
        let last: Option<i64> = db.query_row(
            "SELECT MAX(position) FROM log WHERE payload_type = 'snailfish.change.v1'
             AND position >= ?1 AND position < ?2",
            params![to_i64(*start)?, end],
            |r| r.get(0),
        )?;
        if let Some(l) = last {
            cmp.last_change.insert(*epoch, to_u64(l)?);
        }
    }
    Ok(cmp)
}

/// Replace each covered record of the verified log with a stub ([CMP-13]).
pub(crate) fn stub_covered(tx: &Connection, c: &Compaction) -> Result<u64, EngineError> {
    let f = c.frontier();
    if f == 0 {
        return Ok(0);
    }
    let snaps = serde_json::to_string(&c.covered_snapshots()).map_err(storage)?;
    let n = tx.execute(
        "UPDATE log SET envelope = '' WHERE envelope != ''
         AND ((payload_type = 'snailfish.change.v1' AND position <= ?1)
              OR position IN (SELECT value FROM json_each(?2)))",
        params![to_i64(f)?, snaps],
    )?;
    Ok(n as u64)
}

/// The stub check of 14.3 for each stub from position `from` ([CMP-15]).
/// Returns the first invalid stub.
pub(crate) fn invalid_stub(db: &Connection, from: u64) -> Result<Option<u64>, EngineError> {
    let c = compaction_state(db)?;
    let mut st = db.prepare(
        "SELECT position, payload_type FROM log WHERE envelope = '' AND position >= ?1
         ORDER BY position",
    )?;
    let rows: Vec<(i64, String)> = st
        .query_map([to_i64(from)?], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (p, t) in rows {
        let p = to_u64(p)?;
        if !c.stub_valid(t == "snailfish.change.v1", p) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// The first stub position that a fetch stored and the engine has not
/// checked yet.
pub(crate) fn stubs_from(db: &Connection) -> Result<Option<u64>, EngineError> {
    let v: Option<i64> = db.query_row("SELECT stubs_from FROM meta", [], |r| r.get(0))?;
    v.map(to_u64).transpose()
}

pub(crate) fn set_stubs_from(db: &Connection, from: Option<u64>) -> Result<(), EngineError> {
    db.execute(
        "UPDATE meta SET stubs_from = ?1",
        [from.map(to_i64).transpose()?],
    )?;
    Ok(())
}

/// Delete a pending snapshot or accept record that the verified log now
/// holds.
pub(crate) fn drop_record(tx: &Connection, record_hash: &Hash32) -> Result<(), EngineError> {
    tx.execute(
        "DELETE FROM records WHERE record_hash = ?1",
        [&record_hash[..]],
    )?;
    Ok(())
}

/// The pending snapshot and accept records, by record hash, in the order
/// that the engine signed them.
pub(crate) fn pending_records(db: &Connection) -> Result<Vec<(Hash32, String)>, EngineError> {
    let mut st = db.prepare("SELECT record_hash, envelope FROM records ORDER BY seq")?;
    let rows: Vec<(Vec<u8>, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|(h, e)| {
            Ok((
                Hash32::try_from(h).map_err(|_| storage("a record hash"))?,
                e,
            ))
        })
        .collect()
}

/// The relay refused a pending record for ever: drop it.
pub(crate) fn refuse_record(db: &Connection, record_hash: &Hash32) -> Result<(), EngineError> {
    drop_record(db, record_hash)
}

/// The decrypted state of the snapshot at `position`, or `None` if it does
/// not decrypt ([CMP-5]).
fn decrypt_snapshot(e: &Engine, env: &Envelope) -> Option<(Position, Vec<u8>)> {
    let r = parse_payload(&env.payload_type, &env.payload).ok()?;
    let Body::Snapshot {
        epoch,
        state,
        ciphertext,
    } = &r.body
    else {
        return None;
    };
    let aad = keys::snapshot_aad(&r.log, *epoch, r.author.id(), state.position, &state.digest);
    let key = e.epoch_key(*epoch).ok()??;
    let bytes = keys::decrypt(&key, &aad, ciphertext).ok()?;
    Some((*state, bytes))
}

fn stored_envelope(db: &Connection, position: u64) -> Result<Option<Envelope>, EngineError> {
    let json: Option<String> = db
        .query_row(
            "SELECT envelope FROM log WHERE position = ?1 AND envelope != ''",
            [to_i64(position)?],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|j| Envelope::parse(j.as_bytes()).map_err(storage))
        .transpose()
}

fn applied_position(db: &Connection) -> Result<u64, EngineError> {
    let a: i64 = db.query_row("SELECT applied FROM meta", [], |r| r.get(0))?;
    to_u64(a)
}

impl Engine {
    /// True if the app should write a snapshot (`PROTOCOL.md` 14.7): 1,000
    /// changes or 1 MiB of change envelopes after the state position of the
    /// newest snapshot, or a removal after it ([CMP-9]). False while the
    /// engine outbox holds a change or a pending snapshot.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn snapshot_due(&self) -> Result<bool, EngineError> {
        let busy: i64 = self.db.query_row(
            "SELECT (SELECT count(*) FROM outbox WHERE state != ?1) + (SELECT count(*) FROM records)",
            [crate::state::REFUSED],
            |r| r.get(0),
        )?;
        if busy > 0
            || matches!(
                self.status,
                Status::Fork { .. } | Status::MissingRecords | Status::Removed
            )
        {
            return Ok(false);
        }
        let c = compaction_state(&self.db)?;
        let (last_pos, last_state) = c
            .snapshots
            .iter()
            .next_back()
            .map_or((0, 0), |(p, s)| (*p, s.state));
        let (n, bytes): (i64, i64) = self.db.query_row(
            "SELECT count(*), COALESCE(SUM(length(CAST(envelope AS BLOB))), 0) FROM log
             WHERE payload_type = 'snailfish.change.v1' AND position > ?1",
            [to_i64(last_state)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let epochs: Vec<i64> = {
            let mut st = self.db.prepare(
                "SELECT position FROM log WHERE payload_type = 'snailfish.epoch.v1' AND position > ?1",
            )?;
            st.query_map([to_i64(last_pos)?], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        let mut removal = false;
        for p in epochs {
            removal = removal || removes_a_device(&self.db, to_u64(p)?)?;
        }
        Ok(to_u64(n)? >= SNAPSHOT_CHANGES || to_u64(bytes)? >= SNAPSHOT_BYTES || removal)
    }

    /// Write a snapshot of the app state at the applied position
    /// (`PROTOCOL.md` 14.7, [CMP-3]). The app calls it only with an empty
    /// app outbox. The snapshot goes to the relay at the next sync.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] if the applied position is not on the
    /// verified log, or is 0. [`EngineError::Storage`]. A state larger than
    /// `max_snapshot_bytes` writes nothing, sets `degraded` and returns
    /// false. True if the snapshot waits for the next sync.
    pub fn write_snapshot(&mut self, applied: &Applied, state: &[u8]) -> Result<bool, EngineError> {
        let head = self.base()?;
        if applied.position == 0
            || applied.position > head.position
            || crate::state::verified_digest(&self.db, &self.log_id, applied.position)?
                != Some(applied.digest)
        {
            return Err(EngineError::Invalid(
                "the applied position is not on the verified log".into(),
            ));
        }
        let epoch = self.current_epoch()?;
        let key = self
            .epoch_key(epoch)?
            .ok_or_else(|| EngineError::Invalid("no key of the current epoch".into()))?;
        let aad = keys::snapshot_aad(
            &self.log_id,
            epoch,
            &self.device_id,
            applied.position,
            &applied.digest,
        );
        let ct = keys::encrypt(&key, &aad, state).map_err(|_| EngineError::Random)?;
        let at = Position {
            position: applied.position,
            digest: applied.digest,
        };
        let payload = write::snapshot(&self.log_id, &self.device_id, &head, epoch, &at, &ct);
        // [CMP-3]: the payload limit, and the request limit of the append
        // body that sends the snapshot alone (`PROTOCOL.md` 10.4).
        let limits = relay_limits(&self.db)?;
        let body = (payload.len() as u64)
            .saturating_mul(4)
            .div_ceil(3)
            .saturating_add(1024);
        if payload.len() as u64 > limits.max_snapshot_bytes || body > limits.max_request_bytes {
            self.status = Status::Degraded {
                cause: format!(
                    "the snapshot is larger than the relay limit of {} bytes",
                    limits.max_snapshot_bytes
                ),
            };
            return Ok(false);
        }
        self.add_record("snapshot", "snailfish.snapshot.v1", &payload)?;
        Ok(true)
    }

    /// Queue a snapshot payload as it is, for a test of a snapshot that
    /// does not decrypt.
    #[cfg(test)]
    pub(crate) fn add_record_for_test(&self, payload: &[u8]) {
        self.add_record("snapshot", "snailfish.snapshot.v1", payload)
            .unwrap();
    }

    fn add_record(&self, kind: &str, ptype: &str, payload: &[u8]) -> Result<(), EngineError> {
        let sig = self.sign.sign_record(ptype, payload);
        let json = envelope::write_json(ptype, payload, &sig, &self.device_id());
        let rh = Envelope::parse(json.as_bytes())
            .map_err(storage)?
            .record_hash();
        self.db.execute(
            "INSERT OR IGNORE INTO records (record_hash, kind, envelope) VALUES (?1, ?2, ?3)",
            params![&rh[..], kind, json],
        )?;
        Ok(())
    }

    /// The snapshots for the app to check (`PROTOCOL.md` 14.7, [CMP-5]): each
    /// valid snapshot in full that is not accepted, at or after the
    /// frontier, that the app applied past and the engine has not checked.
    /// A snapshot that does not decrypt is checked at once and sets
    /// `degraded`.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn unchecked_snapshots(&mut self) -> Result<Vec<Snapshot>, EngineError> {
        let c = compaction_state(&self.db)?;
        let applied = applied_position(&self.db)?;
        let f = c.frontier();
        let mut out = Vec::new();
        for (p, s) in &c.snapshots {
            let checked: bool = self
                .db
                .query_row(
                    "SELECT 1 FROM checked WHERE position = ?1",
                    [to_i64(*p)?],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if checked || s.accepted || s.state < f || s.state > applied {
                continue;
            }
            let Some(env) = stored_envelope(&self.db, *p)? else {
                continue;
            };
            if let Some((state, bytes)) = decrypt_snapshot(self, &env) {
                out.push(Snapshot {
                    position: *p,
                    state_position: state.position,
                    state_digest: state.digest,
                    state_bytes: bytes,
                });
            } else {
                self.db.execute(
                    "INSERT OR IGNORE INTO checked (position) VALUES (?1)",
                    [to_i64(*p)?],
                )?;
                self.status = Status::Degraded {
                    cause: format!("the snapshot at position {p} does not decrypt"),
                };
            }
        }
        Ok(out)
    }

    /// The answer of the app for a snapshot of [`Engine::unchecked_snapshots`]
    /// ([CMP-5]). If `ok`, the engine signs an accept record with the applied
    /// position of the last `changes_after` call. If not, it sets
    /// `degraded`.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a position that is not a snapshot, and
    /// [`EngineError::Storage`].
    pub fn accept_snapshot(&mut self, position: u64, ok: bool) -> Result<(), EngineError> {
        let env = stored_envelope(&self.db, position)?
            .filter(|e| e.payload_type == "snailfish.snapshot.v1")
            .ok_or_else(|| EngineError::Invalid("no snapshot at the position".into()))?;
        self.db.execute(
            "INSERT OR IGNORE INTO checked (position) VALUES (?1)",
            [to_i64(position)?],
        )?;
        if !ok {
            self.status = Status::Degraded {
                cause: format!("the app cannot import the snapshot at position {position}"),
            };
            return Ok(());
        }
        let head = self.base()?;
        let applied = applied_position(&self.db)?;
        let digest = crate::state::verified_digest(&self.db, &self.log_id, applied)?
            .ok_or_else(|| storage("no digest at the applied position"))?;
        let payload = write::accept(
            &self.log_id,
            &self.device_id,
            &head,
            position,
            &env.record_hash(),
            &Position {
                position: applied,
                digest,
            },
        );
        self.add_record("accept", "snailfish.accept.v1", &payload)
    }

    /// The usable snapshot, decrypted ([CMP-8]). `None` if the verified log
    /// holds none.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`], also if the usable snapshot does not
    /// decrypt.
    pub fn usable_snapshot(&self) -> Result<Option<Snapshot>, EngineError> {
        let Some(u) = compaction_state(&self.db)?.usable else {
            return Ok(None);
        };
        let env = stored_envelope(&self.db, u)?
            .ok_or_else(|| storage("the usable snapshot is a stub"))?;
        let (state, bytes) = decrypt_snapshot(self, &env)
            .ok_or_else(|| storage("the usable snapshot does not decrypt"))?;
        Ok(Some(Snapshot {
            position: u,
            state_position: state.position,
            state_digest: state.digest,
            state_bytes: bytes,
        }))
    }

    /// True if the verified log holds `change_id`, in full or as a stub, at
    /// or before the frontier ([CMP-14]): the usable snapshot holds the edit.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a change ID that is not 16 bytes, and
    /// [`EngineError::Storage`].
    pub fn is_covered(&self, change_id: &[u8]) -> Result<bool, EngineError> {
        if change_id.len() != 16 {
            return Err(EngineError::Invalid("a change_id must be 16 bytes".into()));
        }
        let f = compaction_state(&self.db)?.frontier();
        let p: Option<i64> = self
            .db
            .query_row(
                "SELECT position FROM log WHERE change_id = ?1",
                [change_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(p.map(to_u64).transpose()?.is_some_and(|p| p <= f))
    }
}

/// The limits of the last `GET /v1/info` answer, or the defaults before
/// the first one (`PROTOCOL.md` 10.4).
fn relay_limits(db: &Connection) -> Result<snailfish_protocol::wire::Limits, EngineError> {
    let body: Option<Vec<u8>> = db
        .query_row("SELECT body FROM relay_info WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    Ok(body
        .and_then(|b| snailfish_protocol::wire::parse_info(&b).ok())
        .map(|i| i.limits)
        .unwrap_or_default())
}

/// True if the epoch record at `position` removes a device.
fn removes_a_device(db: &Connection, position: u64) -> Result<bool, EngineError> {
    let Some(env) = stored_envelope(db, position)? else {
        return Ok(false);
    };
    let r = parse_payload(&env.payload_type, &env.payload).map_err(storage)?;
    Ok(matches!(r.body, Body::Epoch { removed, .. } if !removed.is_empty()))
}

/// [CMP-13] [CMP-15] [CMP-16] for `changes_after`: false while a stub waits
/// for the stub check. `ResetRequired` if the applied position is before
/// the frontier. At or after the frontier, if the verified log holds an own
/// accept that counts for the usable snapshot, replace the covered records
/// with stubs.
pub(crate) fn before_changes(e: &Engine, applied: u64) -> Result<bool, EngineError> {
    // [CMP-15]: a stub that the stub check has not passed can hide a lost
    // change, so the app gets no change until a fetch to the relay head
    // checks it. An invalid stub keeps it so (`stopped: missing records`).
    if stubs_from(&e.db)?.is_some() {
        return Ok(false);
    }
    let c = compaction_state(&e.db)?;
    let f = c.frontier();
    if applied < f {
        return Err(EngineError::ResetRequired);
    }
    let own_accept = c
        .usable
        .and_then(|u| c.snapshots.get(&u))
        .is_some_and(|s| s.accepters.contains(&e.device_id));
    // `stubbed` is the frontier of the last local compaction, so a call
    // with no new frontier scans nothing. The frontier never goes back, so
    // a different frontier is a new one.
    let stubbed: i64 =
        e.db.query_row("SELECT stubbed FROM meta", [], |r| r.get(0))?;
    if own_accept && to_u64(stubbed)? != f {
        let tx = Transaction::new_unchecked(&e.db, TransactionBehavior::Immediate)?;
        stub_covered(&tx, &c)?;
        tx.execute("UPDATE meta SET stubbed = ?1", [to_i64(f)?])?;
        tx.commit()?;
    }
    Ok(true)
}
