//! Removal, recovery key replacement and full recovery (`PROTOCOL.md`
//! section 13, DESIGN.md S4, S5, T8 and T9).
//!
//! The engine keeps at most one pending epoch record (`removal`) and one
//! pending recovery record (`recovery_record`) in its state file, and sends
//! them with the grants in the security phase of a sync. Each one leaves the
//! state file when the verified log holds it.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension as _, params};
use snailfish_protocol::encoding::{Hash32, decode_id, encode_id};
use snailfish_protocol::envelope::{self, Envelope};
use snailfish_protocol::keys;
use snailfish_protocol::records::{Author, Body, Device, KeySet, Keys, Record, parse_payload};
use snailfish_protocol::recovery;
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::wire::AppendResult;
use snailfish_protocol::write;

use crate::state;
use crate::sync::Item;
use crate::{Engine, EngineError, Status};

/// The pending epoch record waits to be signed or sent.
const SEND: &str = "send";
/// The relay refused it with `stale_base`: sign again or ask the user.
const STALE: &str = "stale";
/// The active devices changed: the user confirms again ([LOG-7]).
const CONFIRM: &str = "confirm";
/// The recovery record needs the current recovery key again.
const AGAIN: &str = "again";

/// An active device of the space, for the list that the user confirms
/// (`PROTOCOL.md` 13.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDevice {
    /// The device ID text.
    pub id: String,
    /// The device name of its grant or genesis record.
    pub name: String,
    /// True for the device of this engine. It cannot remove itself.
    pub this_device: bool,
}

/// The recovery key that the user typed for a full recovery (13.4). The
/// engine keeps it in memory only, until the verified log holds the grant
/// of its device.
pub(crate) struct RecoverySigner {
    pub id: Hash32,
    pub sign: SecretKey,
    pub seal_seed: [u8; 32],
    pub name: String,
}

impl RecoverySigner {
    pub(crate) fn new(text: &str, name: &str) -> Result<Self, EngineError> {
        let secret = recovery::parse(text).map_err(|e| EngineError::Invalid(e.to_string()))?;
        let (sign_seed, seal_seed) = recovery::derive(&secret);
        let sign = SecretKey::from_seed(&sign_seed);
        let id = keys::recovery_id(&sign.public(), &keys::seal_public(&seal_seed));
        Ok(Self {
            id,
            sign,
            seal_seed,
            name: name.to_owned(),
        })
    }
}

fn parse(json: &str) -> Result<Record, EngineError> {
    let env = Envelope::parse(json.as_bytes())
        .map_err(|e| EngineError::Storage(format!("stored record: {e}")))?;
    parse_payload(&env.payload_type, &env.payload)
        .map_err(|e| EngineError::Storage(format!("stored record: {e}")))
}

fn id_list(ids: &[Hash32]) -> String {
    ids.iter()
        .map(|i| encode_id("d_", i))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_ids(text: &str) -> Result<Vec<Hash32>, EngineError> {
    text.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            decode_id::<32>(s, "d_").map_err(|e| EngineError::Storage(format!("device ID: {e}")))
        })
        .collect()
}

/// The device object of each device of the genesis record and the grants,
/// in one pass over the log.
fn device_objects(db: &Connection) -> Result<BTreeMap<Hash32, Device>, EngineError> {
    let rows: Vec<String> = {
        let mut st = db.prepare(
            "SELECT envelope FROM log
             WHERE payload_type IN ('snailfish.genesis.v1', 'snailfish.grant.v1') ORDER BY position",
        )?;
        st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    let mut out = BTreeMap::new();
    for json in rows {
        if let Some(d) = crate::enroll::grant_device(&json) {
            out.insert(d.id, d);
        }
    }
    Ok(out)
}

fn no_grant() -> EngineError {
    EngineError::Storage("an active device has no grant".into())
}

/// The keys of the current recovery ID: of the last recovery record, else
/// of the genesis record (`PROTOCOL.md` 10.2).
fn current_recovery_keys(db: &Connection) -> Result<Keys, EngineError> {
    let json: String = db.query_row(
        "SELECT envelope FROM log
         WHERE payload_type IN ('snailfish.genesis.v1', 'snailfish.recovery.v1')
         ORDER BY position DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    match parse(&json)?.body {
        Body::Genesis { recovery, .. } | Body::Recovery { recovery, .. } => Ok(recovery),
        _ => Err(EngineError::Storage("no recovery keys".into())),
    }
}

/// The key of each epoch from 1 to the current epoch, for a grant or a
/// recovery record that seals every epoch (`PROTOCOL.md` 10.6 step 13).
pub(crate) fn all_keys(e: &Engine) -> Result<(Vec<u64>, Vec<[u8; 32]>), EngineError> {
    let epochs: Vec<u64> = (1..=e.current_epoch()?).collect();
    let mut out = Vec::with_capacity(epochs.len());
    for ep in &epochs {
        out.push(
            e.epoch_key(*ep)?.ok_or_else(|| {
                EngineError::Invalid(format!("the engine has no key of epoch {ep}"))
            })?,
        );
    }
    Ok((epochs, out))
}

fn seal(
    e: &Engine,
    to: Author,
    keys_of_to: &Keys,
    epochs: &[u64],
    k: &[[u8; 32]],
) -> Result<KeySet, EngineError> {
    let sealed = keys::seal_key_set(&keys_of_to.seal[..], &e.log_id, to.id(), epochs, k)
        .map_err(|err| EngineError::Invalid(format!("seal: {err}")))?;
    Ok(KeySet {
        to,
        epochs: epochs.to_vec(),
        sealed,
    })
}

/// Sign an epoch record on the verified head that removes `removed`, with a
/// new random key sealed to each device that stays and to the current
/// recovery ID (`PROTOCOL.md` 13.2 step 3).
fn sign_epoch(e: &Engine, removed: &[Hash32]) -> Result<String, EngineError> {
    let view = state::security_state(&e.db)?;
    let epoch = view.epoch.saturating_add(1);
    let key: [u8; 32] = keys::random_bytes().map_err(|_| EngineError::Random)?;
    let stay: Vec<Hash32> = view
        .devices
        .keys()
        .filter(|d| !removed.contains(d))
        .copied()
        .collect();
    let objects = device_objects(&e.db)?;
    let mut sets = Vec::with_capacity(stay.len().saturating_add(1));
    for d in &stay {
        let dev = objects.get(d).ok_or_else(no_grant)?;
        sets.push(seal(e, Author::Device(*d), &dev.keys, &[epoch], &[key])?);
    }
    let (rid, _) = view
        .recovery
        .ok_or_else(|| EngineError::Storage("the space has no recovery ID".into()))?;
    let rkeys = current_recovery_keys(&e.db)?;
    sets.push(seal(e, Author::Recovery(rid), &rkeys, &[epoch], &[key])?);
    sets.sort_by(|a, b| a.to.id().cmp(b.to.id()));
    let mut removed = removed.to_vec();
    removed.sort_unstable();
    let payload = write::epoch(
        &e.log_id,
        &Author::Device(e.device_id),
        &e.base()?,
        &write::Epoch {
            epoch,
            removed: &removed,
            stay: &stay,
            commitment: &keys::key_commitment(&e.log_id, epoch, &key),
            keys: &sets,
        },
    );
    let t = "snailfish.epoch.v1";
    let sig = e.sign.sign_record(t, &payload);
    Ok(envelope::write_json(t, &payload, &sig, &e.device_id()))
}

struct RemovalRow {
    removed: String,
    confirmed: String,
    after_recovery: Option<Vec<u8>>,
    state: String,
}

impl RemovalRow {
    /// True if the user must confirm the list again ([LOG-7]): after the
    /// engine found other active devices, or after `stale_base` with other
    /// active devices in the verified log. A rotation removes no device, so
    /// the user has no list to confirm.
    fn waits_for_user(&self, list: &str) -> bool {
        self.after_recovery.is_none()
            && (self.state == CONFIRM || (self.state == STALE && self.confirmed != list))
    }
}

fn removal_row(db: &Connection) -> Result<Option<RemovalRow>, EngineError> {
    Ok(db
        .query_row(
            "SELECT removed, confirmed, after_recovery, state FROM removal WHERE id = 1",
            [],
            |r| {
                Ok(RemovalRow {
                    removed: r.get(0)?,
                    confirmed: r.get(1)?,
                    after_recovery: r.get(2)?,
                    state: r.get(3)?,
                })
            },
        )
        .optional()?)
}

/// The new recovery ID, the envelope and the state of a pending recovery
/// record.
type RecoveryRow = (Vec<u8>, Option<String>, String);

fn recovery_row(db: &Connection) -> Result<Option<RecoveryRow>, EngineError> {
    Ok(db
        .query_row(
            "SELECT new_id, envelope, state FROM recovery_record WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?)
}

/// The epoch record and the recovery record to send in this sync
/// (`PROTOCOL.md` 13.2 and 13.3). A rotation after a recovery key
/// replacement waits until the verified log holds the recovery record.
pub(crate) fn security_to_send(e: &mut Engine) -> Result<Vec<(Item, String)>, EngineError> {
    let mut out = Vec::new();
    if let Some((_, Some(env), st)) = recovery_row(&e.db)?
        && st == SEND
    {
        out.push((Item::Recovery, env));
    }
    let Some(row) = removal_row(&e.db)? else {
        return Ok(out);
    };
    if let Some(rid) = &row.after_recovery {
        let view = state::security_state(&e.db)?;
        let current = view.recovery.map(|(r, _)| r.to_vec());
        // Another recovery record replaced the key of this device after it
        // landed. That replacement queues its own rotation (T9), so this one
        // goes.
        if view.retired.iter().any(|r| r[..] == rid[..]) {
            e.db.execute("DELETE FROM removal", [])?;
            return Ok(out);
        }
        if current.as_ref() != Some(rid) {
            return Ok(out);
        }
    }
    let list = state::device_list(&e.db)?;
    let mut removed = parse_ids(&row.removed)?;
    // Another epoch record removed some of the devices first. Drop them, and
    // drop the removal if none is left ([LOG-7], as for a grant of a device
    // that became active). A rotation has no removed device and stays.
    let before = removed.len();
    let active = state::security_state(&e.db)?.devices;
    removed.retain(|d| active.contains_key(d));
    if removed.len() < before {
        if removed.is_empty() {
            e.db.execute("DELETE FROM removal", [])?;
            return Ok(out);
        }
        e.db.execute(
            "UPDATE removal SET removed = ?1, state = ?2",
            params![id_list(&removed), CONFIRM],
        )?;
        return Ok(out);
    }
    if row.state == CONFIRM {
        return Ok(out);
    }
    // [LOG-7]: sign only on the list that the user confirmed. A rotation
    // keeps every active device, so it signs on the current list.
    if row.after_recovery.is_none() && list != row.confirmed {
        e.db.execute("UPDATE removal SET state = ?1", [CONFIRM])?;
        return Ok(out);
    }
    // 13.2 steps 3 and 5: each sync until the verified log holds the record
    // signs it on the verified head with a new key. A refused record sealed
    // its key to its recipients, and a stored record whose answer was lost is
    // in the verified log before this point, so the row is gone.
    let env = sign_epoch(e, &removed)?;
    e.db.execute("UPDATE removal SET state = ?1", [SEND])?;
    out.push((Item::Epoch, env));
    Ok(out)
}

/// The append result of a pending epoch record or recovery record.
pub(crate) fn answer(e: &mut Engine, item: &Item, r: &AppendResult) -> Result<(), EngineError> {
    let table = if matches!(item, Item::Recovery) {
        "recovery_record"
    } else {
        "removal"
    };
    match r {
        // It leaves the state file when the verified log holds it.
        AppendResult::Stored(_) | AppendResult::Known(_) | AppendResult::Conflict(_) => {}
        // 13.3 step 6: another recovery record came first. Its key is now
        // current, and the record of this device either names a stale base
        // or a retired author (`not_active`, 10.6 step 7 runs first).
        AppendResult::Refused(code)
            if code == "stale_base" || (code == "not_active" && matches!(item, Item::Recovery)) =>
        {
            let next = if matches!(item, Item::Recovery) {
                AGAIN
            } else {
                STALE
            };
            if matches!(item, Item::Recovery) {
                e.db.execute(
                    "UPDATE recovery_record SET state = ?1, envelope = NULL",
                    [next],
                )?;
            } else {
                e.db.execute("UPDATE removal SET state = ?1", [next])?;
            }
        }
        AppendResult::Refused(code) if code == "bad_base" => {}
        AppendResult::Refused(code) if code == "reserve" || code == "security_limit" => {
            e.status = Status::RelayUnavailable;
        }
        AppendResult::Refused(code) => {
            e.db.execute(&format!("DELETE FROM {table}"), [])?;
            if matches!(item, Item::Recovery) {
                e.db.execute("DELETE FROM removal WHERE after_recovery IS NOT NULL", [])?;
            }
            e.status = Status::Degraded {
                cause: format!("security record refused: {code}"),
            };
        }
    }
    Ok(())
}

/// Drop the pending record that the verified log now holds. The caller
/// runs it in the fetch transaction, after it stores the record.
pub(crate) fn verified(tx: &Connection, record: &Record) -> Result<(), EngineError> {
    match &record.body {
        // An epoch record of another device that removes the same devices
        // ends this removal too. A rotation of another device before the
        // recovery record of this device lands makes that record stale
        // (13.3 step 6), which drops its rotation in any case.
        Body::Epoch { removed, .. } => {
            if let Some(row) = removal_row(tx)?
                && parse_ids(&row.removed)? == *removed
            {
                tx.execute("DELETE FROM removal", [])?;
            }
        }
        Body::Recovery { recovery: k, .. } => {
            let id = keys::recovery_id(&k.sign, &k.seal);
            tx.execute("DELETE FROM recovery_record WHERE new_id = ?1", [&id[..]])?;
        }
        _ => {}
    }
    Ok(())
}

/// The keys of each epoch that the verified log seals to the recovery ID of
/// `r`: in the genesis record, in epoch records and in recovery records
/// (`PROTOCOL.md` 13.4 step 5). Each key passes its commitment check.
pub(crate) fn recovery_keys(
    db: &Connection,
    log_id: &[u8; 16],
    r: &RecoverySigner,
) -> Result<BTreeMap<u64, [u8; 32]>, EngineError> {
    let bad = |m: String| EngineError::Storage(format!("recovery key sets: {m}"));
    let rows: Vec<String> = {
        let mut st = db.prepare(
            "SELECT envelope FROM log WHERE payload_type IN
             ('snailfish.genesis.v1', 'snailfish.epoch.v1', 'snailfish.recovery.v1') ORDER BY position",
        )?;
        st.query_map([], |q| q.get(0))?.collect::<Result<_, _>>()?
    };
    let mut commitments = BTreeMap::new();
    let mut keys_out = BTreeMap::new();
    for json in rows {
        let rec = parse(&json)?;
        let sets = match rec.body {
            Body::Genesis {
                commitment, keys, ..
            } => {
                commitments.insert(1, commitment);
                keys
            }
            Body::Epoch {
                epoch,
                commitment,
                keys,
                ..
            } => {
                commitments.insert(epoch, commitment);
                keys
            }
            Body::Recovery { keys, .. } => keys,
            _ => continue,
        };
        for set in sets.iter().filter(|k| k.to == Author::Recovery(r.id)) {
            let opened = keys::open_key_set(&r.seal_seed, log_id, &r.id, &set.epochs, &set.sealed)
                .map_err(|err| bad(err.to_string()))?;
            for (ep, k) in set.epochs.iter().zip(opened) {
                keys_out.insert(*ep, k);
            }
        }
    }
    for (ep, k) in &keys_out {
        if commitments.get(ep) != Some(&keys::key_commitment(log_id, *ep, k)) {
            return Err(bad(format!(
                "the key of epoch {ep} does not match its commitment"
            )));
        }
    }
    Ok(keys_out)
}

impl Engine {
    /// The active devices of the verified log, with their names: the list
    /// that the user confirms for a removal (`PROTOCOL.md` 13.2 step 1).
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn active_devices(&self) -> Result<Vec<ActiveDevice>, EngineError> {
        let view = state::security_state(&self.db)?;
        let objects = device_objects(&self.db)?;
        let mut out = Vec::new();
        for id in view.devices.keys() {
            out.push(ActiveDevice {
                id: encode_id("d_", id),
                name: objects.get(id).ok_or_else(no_grant)?.name.clone(),
                this_device: *id == self.device_id,
            });
        }
        Ok(out)
    }

    /// Remove the devices `removed` (device ID texts). The other active
    /// devices stay. The user confirmed this list on this device
    /// (`PROTOCOL.md` 13.2 step 2). The next sync signs the epoch record.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for an empty list, this device, a device
    /// that is not active, or while another removal or a recovery key
    /// replacement waits.
    pub fn remove_devices(&mut self, removed: &[String]) -> Result<(), EngineError> {
        let view = state::security_state(&self.db)?;
        let mut ids = Vec::with_capacity(removed.len());
        for text in removed {
            let id = decode_id::<32>(text, "d_")
                .map_err(|e| EngineError::Invalid(format!("device ID: {e}")))?;
            if id == self.device_id {
                return Err(EngineError::Invalid("a device cannot remove itself".into()));
            }
            if !view.devices.contains_key(&id) {
                return Err(EngineError::Invalid(format!(
                    "{text} is not an active device"
                )));
            }
            ids.push(id);
        }
        if ids.is_empty() {
            return Err(EngineError::Invalid("no device to remove".into()));
        }
        ids.sort_unstable();
        ids.dedup();
        let list = state::device_list(&self.db)?;
        if removal_row(&self.db)?.is_some_and(|r| !r.waits_for_user(&list)) {
            return Err(EngineError::Invalid("another removal waits".into()));
        }
        self.db.execute(
            "INSERT INTO removal (id, removed, confirmed, after_recovery, state)
             VALUES (1, ?1, ?2, NULL, ?3)
             ON CONFLICT (id) DO UPDATE SET removed = excluded.removed,
               confirmed = excluded.confirmed, after_recovery = NULL, state = excluded.state",
            params![id_list(&ids), list, SEND],
        )?;
        Ok(())
    }

    /// The devices of a removal that waits for the user to confirm it
    /// again, because the active devices changed ([LOG-7]). The app shows
    /// the list again and calls [`Engine::remove_devices`].
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn removal_to_confirm(&self) -> Result<Option<Vec<String>>, EngineError> {
        let list = state::device_list(&self.db)?;
        // A removal that got `stale_base` asks again as soon as the fetch
        // shows other active devices, so the app can ask right after the sync.
        Ok(removal_row(&self.db)?
            .filter(|r| r.waits_for_user(&list))
            .map(|r| {
                r.removed
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            }))
    }

    /// True if a removal or a rotation waits for the verified log.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn removal_pending(&self) -> Result<bool, EngineError> {
        Ok(removal_row(&self.db)?.is_some())
    }

    /// Make a new recovery key and return its display form
    /// (`PROTOCOL.md` 13.3 step 1). The engine keeps no copy.
    ///
    /// # Errors
    ///
    /// [`EngineError::Random`].
    pub fn new_recovery_key() -> Result<String, EngineError> {
        let secret: [u8; 16] = keys::random_bytes().map_err(|_| EngineError::Random)?;
        Ok(recovery::display(&secret))
    }

    /// Replace the recovery key (`PROTOCOL.md` 13.3 steps 3 to 5): sign a
    /// recovery record with `current`, and queue a rotation that waits for
    /// it. The app calls this only after the user typed `new` back.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] if a key does not parse, `current` is not
    /// the current recovery key of the space, `new` equals it, or a removal
    /// waits.
    pub fn replace_recovery_key(&mut self, current: &str, new: &str) -> Result<(), EngineError> {
        self.clear_recovery_retry()?;
        let cur = RecoverySigner::new(current, "")?;
        let next = RecoverySigner::new(new, "")?;
        let view = state::security_state(&self.db)?;
        if view.recovery.map(|(r, _)| r) != Some(cur.id) {
            return Err(EngineError::Invalid(
                "the recovery key is not the current recovery key of the space".into(),
            ));
        }
        if next.id == cur.id || view.retired.contains(&next.id) {
            return Err(EngineError::Invalid(
                "the new recovery key is not new".into(),
            ));
        }
        if removal_row(&self.db)?.is_some() {
            return Err(EngineError::Invalid("a removal waits".into()));
        }
        let new_keys = Keys {
            sign: next.sign.public(),
            seal: Box::new(keys::seal_public(&next.seal_seed)),
        };
        let (epochs, k) = all_keys(self)?;
        let set = seal(self, Author::Recovery(next.id), &new_keys, &epochs, &k)?;
        let proof = next.sign.sign_raw(&recovery::proof_message(
            &self.log_id,
            &new_keys.sign,
            &new_keys.seal[..],
        ));
        let payload = write::recovery(
            &self.log_id,
            &Author::Recovery(cur.id),
            &self.base()?,
            &new_keys,
            &proof,
            &set,
        );
        let t = "snailfish.recovery.v1";
        let sig = cur.sign.sign_record(t, &payload);
        let env = envelope::write_json(t, &payload, &sig, &encode_id("r_", &cur.id));
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute(
            "INSERT INTO recovery_record (id, new_id, envelope, state) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET new_id = excluded.new_id,
               envelope = excluded.envelope, state = excluded.state",
            params![&next.id[..], env, SEND],
        )?;
        // T9: the rotation that follows, so the holder of the old key cannot
        // read later changes.
        tx.execute(
            "INSERT INTO removal (id, removed, confirmed, after_recovery, state)
             VALUES (1, '', ?1, ?2, ?3)",
            params![state::device_list(&tx)?, &next.id[..], SEND],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// True if the recovery record got `stale_base`: the app asks for the
    /// current recovery key again and calls
    /// [`Engine::replace_recovery_key`] again (13.3 step 6).
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn recovery_key_needed(&self) -> Result<bool, EngineError> {
        Ok(recovery_row(&self.db)?.is_some_and(|(_, _, st)| st == AGAIN))
    }

    /// Before a new [`Engine::replace_recovery_key`] after `stale_base`,
    /// drop the old records.
    fn clear_recovery_retry(&self) -> Result<(), EngineError> {
        if self.recovery_key_needed()? {
            self.db.execute("DELETE FROM recovery_record", [])?;
            self.db
                .execute("DELETE FROM removal WHERE after_recovery IS NOT NULL", [])?;
        }
        Ok(())
    }

    /// True while a full recovery waits for the grant of this device: the
    /// engine holds the recovery key, and the verified log does not make
    /// this device active (`PROTOCOL.md` 13.4).
    pub(crate) fn recovering(&self) -> Result<bool, EngineError> {
        Ok(self.recovery.is_some() && !state::is_active(&self.db, &self.device_id)?)
    }

    /// Open the engine of a new device for a full recovery (`PROTOCOL.md`
    /// 13.4). `recovery_key` is the paper recovery key of the space. The
    /// engine keeps it in memory until the verified log holds the grant of
    /// this device, and the app must open the engine with it again after a
    /// restart before that.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a recovery key that does not parse, and
    /// the errors of [`Engine::open`].
    pub fn open_recovery(
        data_dir: &std::path::Path,
        space: crate::SpaceRef,
        keys: &crate::DeviceKeys,
        recovery_key: &str,
        name: &str,
    ) -> Result<Self, EngineError> {
        let signer = RecoverySigner::new(recovery_key, name)?;
        let mut e = Self::open(data_dir, space, keys)?;
        if !state::is_active(&e.db, &e.device_id)? {
            e.recovery = Some(signer);
        }
        Ok(e)
    }

    /// Queue the grant of a full recovery (13.4 step 6): the recovery key
    /// signs a grant for this device on the verified head, with each epoch
    /// key that the log seals to the recovery ID. Each sync signs it again
    /// after its fetch, so a grant that got `stale_base` names the new head.
    pub(crate) fn queue_recovery_grant(&mut self) -> Result<(), EngineError> {
        let Some(r) = self.recovery.as_ref() else {
            return Ok(());
        };
        let view = state::security_state(&self.db)?;
        if view.devices.contains_key(&self.device_id) {
            return Ok(());
        }
        if view.recovery.map(|(id, _)| id) != Some(r.id) {
            return Err(EngineError::Invalid(
                "the recovery key is not the current recovery key of the space".into(),
            ));
        }
        let keys_by_epoch = recovery_keys(&self.db, &self.log_id, r)?;
        let epochs: Vec<u64> = (1..=view.epoch).collect();
        let mut k = Vec::with_capacity(epochs.len());
        for ep in &epochs {
            k.push(*keys_by_epoch.get(ep).ok_or_else(|| {
                EngineError::Invalid(format!(
                    "the log seals no key of epoch {ep} to the recovery key"
                ))
            })?);
        }
        let device = Device {
            id: self.device_id,
            keys: Keys {
                sign: self.sign.public(),
                seal: Box::new(keys::seal_public(&self.seal_seed)),
            },
            name: r.name.clone(),
            level: crate::MAX_LEVEL,
        };
        let set = seal(
            self,
            Author::Device(self.device_id),
            &device.keys,
            &epochs,
            &k,
        )?;
        let payload = write::grant(
            &self.log_id,
            &Author::Recovery(r.id),
            &self.base()?,
            &device,
            &set,
        );
        let t = "snailfish.grant.v1";
        let sig = r.sign.sign_record(t, &payload);
        let env = envelope::write_json(t, &payload, &sig, &encode_id("r_", &r.id));
        state::put_grant(
            &self.db,
            &state::GrantRow {
                device_id: self.device_id,
                device: write::device(&device),
                confirmed: state::device_list(&self.db)?,
                by_recovery: true,
                envelope: Some(env),
                state: state::GRANT_SEND.into(),
            },
        )
    }
}
