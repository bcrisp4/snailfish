//! The space-state check (`PROTOCOL.md` 10.2, 10.5, 10.6 and 10.9).
//!
//! The relay and the engine use the same functions ([LOG-9]). They check the
//! signature, the strict parse, dense positions, the digest chain, the base
//! rule ([LOG-6]), the base rule for security records ([LOG-7]) and the
//! space state of 10.2 ([LOG-8]): active and removed devices, the current
//! epoch, the current recovery ID, device levels and the write level. The
//! relay also refuses changes during a restore hold ([LOG-14]).
//!
//! The functions do no I/O. The caller gives the log state through
//! [`SpaceView`], for example from SQLite.

use crate::compaction::{self, Compaction};
use crate::encoding::Hash32;
use crate::envelope::Envelope;
use crate::hash::{digest_next, digest0, entry_hash};
use crate::records::{self, Author, Body, Record};
use crate::sig::PublicKey;

/// The protocol levels that a verifier knows (`PROTOCOL.md` 6.2, [VER-6]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Levels {
    /// The highest level.
    pub max: u64,
    /// Each record type that a level after 1 drops, with the first level
    /// without it. Level 1 holds every `v1` type.
    pub retired: &'static [(&'static str, u64)],
}

impl Levels {
    /// The levels of this crate: level 1 only.
    pub const CURRENT: Self = Self {
        max: 1,
        retired: &[],
    };

    /// True if the set of `level` holds `payload_type` ([VER-9]). A level
    /// above [`Levels::max`] holds nothing, because its set is unknown.
    #[must_use]
    pub fn holds(&self, level: u64, payload_type: &str) -> bool {
        (1..=self.max).contains(&level)
            && records::RECORD_TYPES.contains(&payload_type)
            && !self
                .retired
                .iter()
                .any(|(t, at)| *t == payload_type && level >= *at)
    }
}

/// The log state that the check reads.
pub trait SpaceView {
    /// The log ID of the space.
    fn log_id(&self) -> [u8; 16];
    /// The last position. 0 for an empty log.
    fn head(&self) -> u64;
    /// The log digest at a position from 0 to [`SpaceView::head`].
    fn digest_at(&self, position: u64) -> Option<Hash32>;
    /// The Ed25519 public key of an active device ([LOG-8]).
    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]>;
    /// The active devices, in ID order.
    fn active_devices(&self) -> Vec<Hash32>;
    /// True if an epoch record removed the device.
    fn is_removed(&self, id: &Hash32) -> bool;
    /// The device level of an active or removed device (`PROTOCOL.md` 10.2).
    fn device_level(&self, id: &Hash32) -> Option<u64>;
    /// The Ed25519 public key of the recovery ID `id`, if `id` is the
    /// current recovery ID of the space (`PROTOCOL.md` 10.2).
    fn recovery_key(&self, id: &Hash32) -> Option<[u8; 32]>;
    /// True if `id` is the current recovery ID or a recovery ID that a
    /// recovery record replaced.
    fn recovery_known(&self, id: &Hash32) -> bool;
    /// The position and record hash of a change with this `change_id`.
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)>;
    /// The space write level ([VER-9]).
    fn write_level(&self) -> u64;
    /// The current epoch.
    fn epoch(&self) -> u64;
    /// The position of the last security record ([LOG-7]). 0 for an empty
    /// log.
    fn last_security(&self) -> u64;
    /// The record hash of the snapshot record at `position`, in full or as a
    /// stub. `None` if the entry is not a snapshot.
    fn snapshot_hash(&self, position: u64) -> Option<Hash32>;
    /// The compaction state of the log (`PROTOCOL.md` section 14).
    fn compaction(&self) -> Compaction;
}

/// Who checks the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The relay checks an append request. `signer` is the request `keyid`.
    Relay {
        /// The device that signed the request.
        signer: Hash32,
        /// `max_change_bytes` of `PROTOCOL.md` 10.4.
        max_change_bytes: usize,
        /// `max_snapshot_bytes` of `PROTOCOL.md` 10.4 ([CMP-3]).
        max_snapshot_bytes: usize,
        /// The space is on restore hold ([LOG-14]).
        hold: bool,
    },
    /// The engine checks a record that it fetched, and the relay checks a
    /// repair entry (`PROTOCOL.md` 10.9). A known `change_id` is a fault of
    /// the relay or of the repair, because the log never holds it twice
    /// ([WIR-6]).
    Verify,
}

/// A refused record, with the code of `PROTOCOL.md` 10.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `invalid_record`, with the cause.
    InvalidRecord(String),
    /// `too_large`.
    TooLarge,
    /// `not_author`.
    NotAuthor,
    /// `not_active`.
    NotActive,
    /// `bad_base`. Transient ([DLV-9]).
    BadBase,
    /// `stale_base`: a security record with a security record after its
    /// base ([LOG-7]). Transient.
    StaleBase,
    /// `on_hold`: a record that is not a security record during a restore
    /// hold ([LOG-14]). Transient.
    OnHold,
    /// `unsupported`.
    Unsupported,
    /// `wrong_epoch`.
    WrongEpoch,
    /// A fetched change with a known `change_id` (engine only).
    DuplicateChange,
}

impl Refusal {
    /// The code of `PROTOCOL.md` 10.6.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRecord(_) => "invalid_record",
            Self::TooLarge => "too_large",
            Self::NotAuthor => "not_author",
            Self::NotActive => "not_active",
            Self::BadBase => "bad_base",
            Self::StaleBase => "stale_base",
            Self::OnHold => "on_hold",
            Self::Unsupported => "unsupported",
            Self::WrongEpoch => "wrong_epoch",
            Self::DuplicateChange => "duplicate_change",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecord(why) => write!(f, "invalid_record: {why}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for Refusal {}

/// A record that the check accepts at the next position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The parsed payload.
    pub record: Record,
    /// The new position: head + 1 ([LOG-1]).
    pub position: u64,
    /// The record hash ([LOG-3]).
    pub record_hash: Hash32,
    /// The log digest at the new position ([LOG-5]).
    pub digest: Hash32,
    /// The device that a genesis or grant record makes active, with its
    /// Ed25519 key.
    pub new_device: Option<(Hash32, [u8; 32])>,
}

/// The result of one append check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Append the record.
    Store(Box<Accepted>),
    /// An exact retry: the original position ([WIR-6]).
    Known(u64),
    /// The same `change_id` with another record hash: the original
    /// position ([WIR-6]).
    Conflict(u64),
    /// Refused, with the cause.
    Refused(Refusal),
}

fn invalid(e: impl std::fmt::Display) -> Refusal {
    Refusal::InvalidRecord(e.to_string())
}

/// The answer for a known `change_id` ([WIR-6]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dedupe {
    /// The same record hash: the original position.
    Known(u64),
    /// Another record hash: the original position.
    Conflict(u64),
}

/// The answer for a known `change_id` ([WIR-6]): `Known` for the same
/// record hash, `Conflict` for another one, `None` for a new `change_id`.
#[must_use]
pub fn dedupe(stored: Option<(u64, Hash32)>, record_hash: &Hash32) -> Option<Dedupe> {
    stored.map(|(pos, h)| {
        if &h == record_hash {
            Dedupe::Known(pos)
        } else {
            Dedupe::Conflict(pos)
        }
    })
}

/// True if a base at `base` is valid for a record at `head + 1`: an entry
/// at position 1 or later, before the record ([LOG-6]).
#[must_use]
pub fn base_in_range(base: u64, head: u64) -> bool {
    base >= 1 && base <= head
}

/// True if the base of a record is valid against the last security record
/// ([LOG-7]): a security record needs its base at or after the last
/// security record. Changes after the base do not matter.
#[must_use]
pub fn security_base_ok(security: bool, base: u64, last_security: u64) -> bool {
    !security || base >= last_security
}

/// [`check_append_at`] with [`Levels::CURRENT`].
#[must_use]
pub fn check_append(view: &impl SpaceView, env: &Envelope, mode: Mode) -> Verdict {
    check_append_at(view, env, mode, &Levels::CURRENT)
}

/// True if a level record to `level` is valid: above the write level, and
/// no active device below it ([VER-8]). `lowest` is the lowest device
/// level of the active devices.
#[must_use]
pub fn raise_ok(level: u64, write_level: u64, lowest: u64) -> bool {
    level > write_level && lowest >= level
}

/// Check one record for the next position (`PROTOCOL.md` 10.6, in that
/// order). The genesis record has its own check, [`check_genesis`].
///
/// [WIR-2]: the parse before the signature check only finds the author.
/// The function changes no state. The caller applies an [`Accepted`] only
/// after it returns, so no state changes before the signature verifies.
#[must_use]
pub fn check_append_at(
    view: &impl SpaceView,
    env: &Envelope,
    mode: Mode,
    levels: &Levels,
) -> Verdict {
    let record = match records::parse_payload(&env.payload_type, &env.payload) {
        Ok(r) => r,
        Err(e) => return Verdict::Refused(invalid(e)),
    };
    let record_hash = env.record_hash();
    if let Some(cid) = record.change_id() {
        let stored = view.change(cid);
        match mode {
            Mode::Relay { .. } => match dedupe(stored, &record_hash) {
                Some(Dedupe::Known(p)) => return Verdict::Known(p),
                Some(Dedupe::Conflict(p)) => return Verdict::Conflict(p),
                None => {}
            },
            Mode::Verify => {
                if stored.is_some() {
                    return Verdict::Refused(Refusal::DuplicateChange);
                }
            }
        }
    }
    if let Mode::Relay { hold: true, .. } = mode
        && !record.is_security()
    {
        return Verdict::Refused(Refusal::OnHold);
    }
    match judge(view, env, record, record_hash, mode, levels) {
        Ok(a) => Verdict::Store(Box::new(a)),
        Err(r) => Verdict::Refused(r),
    }
}

fn judge(
    view: &impl SpaceView,
    env: &Envelope,
    record: Record,
    record_hash: Hash32,
    mode: Mode,
    levels: &Levels,
) -> Result<Accepted, Refusal> {
    if let Mode::Relay {
        max_change_bytes,
        max_snapshot_bytes,
        ..
    } = mode
    {
        let limit = match record.body {
            Body::Change { .. } => max_change_bytes,
            Body::Snapshot { .. } => max_snapshot_bytes,
            _ => usize::MAX,
        };
        if env.payload.len() > limit {
            return Err(Refusal::TooLarge);
        }
    }
    if record.log != view.log_id() {
        return Err(invalid("log: the record names another log"));
    }
    // PROTOCOL.md 10.6 steps 6 and 7. A record by the recovery key has no
    // request signer to match: any active device can send it.
    let key = match record.author {
        Author::Device(id) => {
            if let Mode::Relay { signer, .. } = mode
                && signer != id
            {
                return Err(Refusal::NotAuthor);
            }
            view.device_key(&id).ok_or(Refusal::NotActive)?
        }
        Author::Recovery(rid) => view.recovery_key(&rid).ok_or(Refusal::NotActive)?,
    };
    PublicKey::from_bytes(&key)
        .and_then(|k| k.verify_record(&env.payload_type, &env.payload, &env.sig))
        .map_err(invalid)?;
    let head = view.head();
    if !base_in_range(record.base.position, head)
        || view.digest_at(record.base.position) != Some(record.base.digest)
    {
        return Err(Refusal::BadBase);
    }
    // Only a security record reads the last security record: a store scans
    // for it, and a change is the common append.
    if record.is_security() && !security_base_ok(true, record.base.position, view.last_security()) {
        return Err(Refusal::StaleBase);
    }
    let ptype = env.payload_type.as_str();
    let level_above =
        matches!(record.body, Body::Device { level } | Body::Level { level } if level > levels.max);
    if !levels.holds(view.write_level(), ptype) || level_above {
        return Err(Refusal::Unsupported);
    }
    if let Body::Change { epoch, .. } | Body::Snapshot { epoch, .. } = &record.body
        && *epoch != view.epoch()
    {
        return Err(Refusal::WrongEpoch);
    }
    state_rule(view, &record)?;
    let new_device = match &record.body {
        Body::Grant { device, .. } => Some((device.id, device.keys.sign)),
        _ => None,
    };
    let position = head.checked_add(1).ok_or(Refusal::BadBase)?;
    let prev = view.digest_at(head).ok_or(Refusal::BadBase)?;
    let digest = digest_next(
        &prev,
        position,
        &entry_hash(&env.payload_type, record.change_id(), &record_hash),
    );
    Ok(Accepted {
        record,
        position,
        record_hash,
        digest,
        new_device,
    })
}

/// The state rule of each record type (`PROTOCOL.md` 10.6 step 13).
fn state_rule(view: &impl SpaceView, record: &Record) -> Result<(), Refusal> {
    let epoch = view.epoch();
    match &record.body {
        Body::Grant { device, keys } => {
            if view.device_key(&device.id).is_some() {
                return Err(invalid("grant: the device is already active"));
            }
            if view.is_removed(&device.id) {
                return Err(invalid("grant: an epoch record removed the device"));
            }
            if device.level < view.write_level() {
                return Err(invalid("grant: the device level is below the write level"));
            }
            if !keys_ok(view, keys) {
                return Err(invalid("grant: the key set must hold each needed epoch"));
            }
        }
        Body::Epoch {
            epoch: e,
            removed,
            stay,
            keys,
            ..
        } => {
            if Some(*e) != epoch.checked_add(1) {
                return Err(invalid("epoch: the epoch is not the current epoch plus 1"));
            }
            if removed.contains(record.author.id()) && matches!(record.author, Author::Device(_)) {
                return Err(invalid("epoch: the record removes its author"));
            }
            if removed.iter().any(|d| view.device_key(d).is_none()) {
                return Err(invalid("epoch: a removed device is not active"));
            }
            let want: Vec<Hash32> = view
                .active_devices()
                .into_iter()
                .filter(|d| !removed.contains(d))
                .collect();
            if *stay != want {
                return Err(invalid(
                    "epoch: stay differs from the active devices that stay",
                ));
            }
            let to_current = keys.iter().any(|k| match k.to {
                Author::Recovery(r) => view.recovery_key(&r).is_some(),
                Author::Device(_) => false,
            });
            if !to_current {
                return Err(invalid("epoch: no key set to the current recovery ID"));
            }
        }
        Body::Recovery { recovery, keys, .. } => {
            let rid = crate::keys::recovery_id(&recovery.sign, &recovery.seal);
            if view.recovery_known(&rid) {
                return Err(invalid("recovery: the new recovery ID is not new"));
            }
            if !keys_ok(view, keys) {
                return Err(invalid("recovery: the key set must hold each needed epoch"));
            }
        }
        Body::Device { level } => {
            let current = view.device_level(record.author.id()).unwrap_or(0);
            if *level <= current {
                return Err(invalid("device: the level is not above the device level"));
            }
        }
        Body::Level { level } => {
            let lowest = view
                .active_devices()
                .iter()
                .filter_map(|d| view.device_level(d))
                .min()
                .unwrap_or(0);
            if !raise_ok(*level, view.write_level(), lowest) {
                return Err(invalid(
                    "level: not above the write level, or an active device is below it",
                ));
            }
        }
        Body::Snapshot { .. } | Body::Accept { .. } => compaction_rule(view, record)?,
        _ => {}
    }
    Ok(())
}

/// The state rule of a snapshot and of an accept record (`PROTOCOL.md` 10.6
/// step 13).
fn compaction_rule(view: &impl SpaceView, record: &Record) -> Result<(), Refusal> {
    match &record.body {
        Body::Snapshot { state, .. } => {
            // [CMP-3]: the state position is before the record, and the state
            // digest is the log digest there.
            if !base_in_range(state.position, view.head())
                || view.digest_at(state.position) != Some(state.digest)
            {
                return Err(invalid(
                    "snapshot: the state is not an entry before the record",
                ));
            }
        }
        Body::Accept {
            snapshot_position,
            snapshot_hash,
            applied,
        } => {
            if view.snapshot_hash(*snapshot_position) != Some(*snapshot_hash) {
                return Err(invalid(
                    "accept: no snapshot with this hash at the position",
                ));
            }
            if applied.position > record.base.position
                || view.digest_at(applied.position) != Some(applied.digest)
            {
                return Err(invalid(
                    "accept: the applied position is not an entry at or before the base",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// The key set rule of a grant or a recovery record ([CMP-20], `PROTOCOL.md`
/// 14.5): one key set with each needed epoch and no epoch above the current.
fn keys_ok(view: &impl SpaceView, keys: &[records::KeySet]) -> bool {
    let epoch = view.epoch();
    let needed = view.compaction().needed_epochs(epoch);
    keys.len() == 1
        && keys
            .iter()
            .all(|k| compaction::epochs_ok(&k.epochs, &needed, epoch))
}

/// Check a genesis record for a new space with log ID `log_id`
/// (`PROTOCOL.md` 10.5). The recovery key of the record signs it. If
/// `signer` is set, it must be the device of the record.
///
/// # Errors
///
/// [`Refusal::InvalidRecord`] or [`Refusal::NotAuthor`].
pub fn check_genesis(
    env: &Envelope,
    log_id: &[u8; 16],
    signer: Option<&Hash32>,
) -> Result<Accepted, Refusal> {
    if env.payload_type != "snailfish.genesis.v1" {
        return Err(invalid("the first record must be a genesis record"));
    }
    let record = records::parse_payload(&env.payload_type, &env.payload).map_err(invalid)?;
    let Body::Genesis {
        recovery, device, ..
    } = &record.body
    else {
        return Err(invalid("the first record must be a genesis record"));
    };
    if &record.log != log_id {
        return Err(invalid("log: the record names another log"));
    }
    PublicKey::from_bytes(&recovery.sign)
        .and_then(|k| k.verify_record(&env.payload_type, &env.payload, &env.sig))
        .map_err(invalid)?;
    if signer.is_some_and(|s| s != &device.id) {
        return Err(Refusal::NotAuthor);
    }
    let record_hash = env.record_hash();
    let digest = digest_next(
        &digest0(log_id),
        1,
        &entry_hash(&env.payload_type, None, &record_hash),
    );
    let new_device = Some((device.id, device.keys.sign));
    Ok(Accepted {
        record,
        position: 1,
        record_hash,
        digest,
        new_device,
    })
}

/// The write level of a genesis record.
#[must_use]
pub fn genesis_level(record: &Record) -> Option<u64> {
    match record.body {
        Body::Genesis { level, .. } => Some(level),
        _ => None,
    }
}

/// The recovery ID and the Ed25519 key of a genesis record.
#[must_use]
pub fn genesis_recovery(record: &Record) -> Option<(Hash32, [u8; 32])> {
    match &record.body {
        Body::Genesis { recovery, .. } => Some((
            crate::keys::recovery_id(&recovery.sign, &recovery.seal),
            recovery.sign,
        )),
        _ => None,
    }
}

/// The recovery ID and the Ed25519 key of a stored genesis envelope, for
/// a [`SpaceView`] that keeps the envelope text. `None` if the text is not a
/// genesis record.
#[must_use]
pub fn genesis_recovery_of(envelope_json: &str) -> Option<(Hash32, [u8; 32])> {
    let env = Envelope::parse(envelope_json.as_bytes()).ok()?;
    let record = records::parse_payload(&env.payload_type, &env.payload).ok()?;
    genesis_recovery(&record)
}

/// The change that one accepted record makes to the space state
/// (`PROTOCOL.md` 10.2), apart from the digest, the change IDs and the last
/// security record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// No state change.
    None,
    /// A genesis record or a grant adds a device with its key and level.
    Device {
        /// The device ID.
        id: Hash32,
        /// The Ed25519 public key.
        sign: [u8; 32],
        /// The device level.
        level: u64,
    },
    /// An epoch record removes devices and starts an epoch.
    Epoch {
        /// The new epoch.
        epoch: u64,
        /// The removed devices.
        removed: Vec<Hash32>,
    },
    /// A recovery record makes a new current recovery ID.
    Recovery {
        /// The new recovery ID.
        id: Hash32,
        /// Its Ed25519 public key.
        sign: [u8; 32],
    },
    /// A device record sets the level of its author.
    DeviceLevel {
        /// The device.
        id: Hash32,
        /// The new device level.
        level: u64,
    },
    /// A level record sets the write level.
    WriteLevel(u64),
}

/// The state change of a record that the check accepted.
#[must_use]
pub fn effect(record: &Record) -> Effect {
    match &record.body {
        Body::Genesis { device, .. } | Body::Grant { device, .. } => Effect::Device {
            id: device.id,
            sign: device.keys.sign,
            level: device.level,
        },
        Body::Epoch { epoch, removed, .. } => Effect::Epoch {
            epoch: *epoch,
            removed: removed.clone(),
        },
        Body::Recovery { recovery, .. } => Effect::Recovery {
            id: crate::keys::recovery_id(&recovery.sign, &recovery.seal),
            sign: recovery.sign,
        },
        Body::Device { level } => Effect::DeviceLevel {
            id: *record.author.id(),
            level: *level,
        },
        Body::Level { level } => Effect::WriteLevel(*level),
        _ => Effect::None,
    }
}

/// The space state of `PROTOCOL.md` 10.2, apart from the positions, the
/// digests and the change IDs. Each security record changes it, so a store
/// can rebuild it from its security records alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// The active devices and their Ed25519 keys.
    pub devices: std::collections::BTreeMap<Hash32, [u8; 32]>,
    /// The devices that an epoch record removed.
    pub removed: std::collections::BTreeSet<Hash32>,
    /// The device level of each active or removed device.
    pub device_levels: std::collections::BTreeMap<Hash32, u64>,
    /// The write level.
    pub level: u64,
    /// The current epoch. 0 before the genesis record.
    pub epoch: u64,
    /// The current recovery ID and its Ed25519 key.
    pub recovery: Option<(Hash32, [u8; 32])>,
    /// The recovery IDs that a recovery record replaced.
    pub retired: std::collections::BTreeSet<Hash32>,
}

impl State {
    /// Apply a record that the check accepted, or a stored record.
    pub fn apply(&mut self, record: &Record) {
        if let Some(level) = genesis_level(record) {
            self.level = level;
            self.epoch = 1;
        }
        if let Some(r) = genesis_recovery(record) {
            self.recovery = Some(r);
        }
        match effect(record) {
            Effect::Device { id, sign, level } => {
                self.devices.insert(id, sign);
                self.device_levels.insert(id, level);
            }
            Effect::Epoch { epoch, removed } => {
                for d in removed {
                    self.devices.remove(&d);
                    self.removed.insert(d);
                }
                self.epoch = epoch;
            }
            Effect::Recovery { id, sign } => {
                if let Some((old, _)) = self.recovery.replace((id, sign)) {
                    self.retired.insert(old);
                }
            }
            Effect::DeviceLevel { id, level } => {
                self.device_levels.insert(id, level);
            }
            Effect::WriteLevel(level) => self.level = level,
            Effect::None => {}
        }
    }

    /// Apply a stored envelope. A store calls it for each security record
    /// in position order. A record that does not parse is a corrupt store.
    ///
    /// # Errors
    ///
    /// The parse error of the envelope or the payload.
    pub fn apply_envelope(&mut self, envelope_json: &str) -> Result<(), String> {
        let env = Envelope::parse(envelope_json.as_bytes()).map_err(|e| e.to_string())?;
        let record =
            records::parse_payload(&env.payload_type, &env.payload).map_err(|e| e.to_string())?;
        self.apply(&record);
        Ok(())
    }

    /// See [`SpaceView::device_key`].
    #[must_use]
    pub fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.devices.get(id).copied()
    }

    /// See [`SpaceView::recovery_key`].
    #[must_use]
    pub fn recovery_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.recovery.filter(|(r, _)| r == id).map(|(_, k)| k)
    }

    /// See [`SpaceView::recovery_known`].
    #[must_use]
    pub fn recovery_known(&self, id: &Hash32) -> bool {
        self.recovery_key(id).is_some() || self.retired.contains(id)
    }
}

/// An in-memory [`SpaceView`]: the engine and tests use it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemorySpace {
    /// The log ID.
    pub log_id: [u8; 16],
    /// `digests[n]` is the digest at position n, from 0.
    pub digests: Vec<Hash32>,
    /// Each change: its position and record hash.
    pub changes: std::collections::BTreeMap<[u8; 16], (u64, Hash32)>,
    /// The position of the last security record.
    pub last_security: u64,
    /// The space state of 10.2.
    pub state: State,
    /// The record hash of each snapshot, in full or as a stub, by position.
    pub snapshots: std::collections::BTreeMap<u64, Hash32>,
    /// The compaction state (section 14).
    pub compaction: Compaction,
}

impl MemorySpace {
    /// A space with no entries.
    #[must_use]
    pub fn new(log_id: [u8; 16]) -> Self {
        Self {
            log_id,
            digests: vec![digest0(&log_id)],
            ..Self::default()
        }
    }

    /// Apply a record that the check accepted.
    pub fn apply(&mut self, a: &Accepted) {
        self.digests.push(a.digest);
        if let Some(cid) = a.record.change_id() {
            self.changes.insert(*cid, (a.position, a.record_hash));
        }
        if a.record.is_security() {
            self.last_security = a.position;
        }
        if matches!(a.record.body, Body::Snapshot { .. }) {
            self.snapshots.insert(a.position, a.record_hash);
        }
        self.state.apply(&a.record);
        let active = self.state.devices.keys().copied().collect();
        self.compaction
            .apply(a.position, compaction::kind(&a.record), &active);
    }

    /// Apply a stub at the next position ([CMP-1]).
    pub fn apply_stub(&mut self, s: &StubEntry) {
        self.digests.push(s.digest);
        if let Some(cid) = s.change_id {
            self.changes.insert(cid, (s.position, s.record_hash));
        }
        if s.payload_type == "snailfish.snapshot.v1" {
            self.snapshots.insert(s.position, s.record_hash);
        }
        let active = self.state.devices.keys().copied().collect();
        self.compaction
            .apply(s.position, compaction::stub_kind(&s.payload_type), &active);
    }
}

/// A stub at a position, with its log digest (`PROTOCOL.md` 10.7, [CMP-1]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubEntry {
    /// The position.
    pub position: u64,
    /// The payload type of the record.
    pub payload_type: String,
    /// The change ID of a change.
    pub change_id: Option<[u8; 16]>,
    /// The record hash.
    pub record_hash: Hash32,
    /// The log digest at the position.
    pub digest: Hash32,
}

impl StubEntry {
    /// The stub of the next position after `prev`, the digest at the
    /// position before it.
    #[must_use]
    pub fn new(
        position: u64,
        payload_type: &str,
        change_id: Option<[u8; 16]>,
        record_hash: Hash32,
        prev: &Hash32,
    ) -> Self {
        let digest = digest_next(
            prev,
            position,
            &entry_hash(payload_type, change_id.as_ref(), &record_hash),
        );
        Self {
            position,
            payload_type: payload_type.to_owned(),
            change_id,
            record_hash,
            digest,
        }
    }
}

/// One entry of an [`Overlay`]: a record that the check accepted, or a
/// staged stub of a repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staged {
    /// A record in full.
    Full(Box<Accepted>),
    /// A stub.
    Stub(StubEntry),
}

impl Staged {
    /// The position.
    #[must_use]
    pub fn position(&self) -> u64 {
        match self {
            Self::Full(a) => a.position,
            Self::Stub(s) => s.position,
        }
    }

    /// The log digest at the position.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        match self {
            Self::Full(a) => a.digest,
            Self::Stub(s) => s.digest,
        }
    }
}

impl SpaceView for MemorySpace {
    fn log_id(&self) -> [u8; 16] {
        self.log_id
    }
    fn head(&self) -> u64 {
        (self.digests.len() as u64).saturating_sub(1)
    }
    fn digest_at(&self, position: u64) -> Option<Hash32> {
        usize::try_from(position)
            .ok()
            .and_then(|p| self.digests.get(p))
            .copied()
    }
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)> {
        self.changes.get(change_id).copied()
    }
    fn last_security(&self) -> u64 {
        self.last_security
    }
    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.state.device_key(id)
    }
    fn active_devices(&self) -> Vec<Hash32> {
        self.state.devices.keys().copied().collect()
    }
    fn is_removed(&self, id: &Hash32) -> bool {
        self.state.removed.contains(id)
    }
    fn device_level(&self, id: &Hash32) -> Option<u64> {
        self.state.device_levels.get(id).copied()
    }
    fn recovery_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.state.recovery_key(id)
    }
    fn recovery_known(&self, id: &Hash32) -> bool {
        self.state.recovery_known(id)
    }
    fn write_level(&self) -> u64 {
        self.state.level
    }
    fn epoch(&self) -> u64 {
        self.state.epoch
    }
    fn snapshot_hash(&self, position: u64) -> Option<Hash32> {
        self.snapshots.get(&position).copied()
    }
    fn compaction(&self) -> Compaction {
        self.compaction.clone()
    }
}

/// A [`SpaceView`] with records of the current request on top of a stored
/// view: the relay checks each envelope of one append request against the
/// state after the earlier ones (`PROTOCOL.md` 10.6).
pub struct Overlay<'a, V: SpaceView> {
    inner: &'a V,
    staged: Vec<Staged>,
}

impl<'a, V: SpaceView> Overlay<'a, V> {
    /// An overlay with no records.
    pub fn new(inner: &'a V) -> Self {
        Self {
            inner,
            staged: Vec::new(),
        }
    }

    /// Add a record that the check accepted.
    pub fn apply(&mut self, a: Accepted) {
        self.staged.push(Staged::Full(Box::new(a)));
    }

    /// Add a stub of a repair at the next position.
    pub fn apply_stub(&mut self, s: StubEntry) {
        self.staged.push(Staged::Stub(s));
    }

    /// Add a staged entry of a repair chain at the next position.
    pub fn push(&mut self, s: Staged) {
        self.staged.push(s);
    }

    /// The added records in full, in order.
    #[must_use]
    pub fn into_added(self) -> Vec<Accepted> {
        self.staged
            .into_iter()
            .filter_map(|s| match s {
                Staged::Full(a) => Some(*a),
                Staged::Stub(_) => None,
            })
            .collect()
    }

    /// The added records and stubs, in order.
    #[must_use]
    pub fn into_staged(self) -> Vec<Staged> {
        self.staged
    }

    fn added(&self) -> impl DoubleEndedIterator<Item = &Accepted> + '_ {
        self.staged.iter().filter_map(|s| match s {
            Staged::Full(a) => Some(a.as_ref()),
            Staged::Stub(_) => None,
        })
    }

    fn effects(&self) -> impl DoubleEndedIterator<Item = Effect> + '_ {
        self.added().map(|a| effect(&a.record))
    }

    fn removed_here(&self, id: &Hash32) -> bool {
        self.effects()
            .any(|e| matches!(e, Effect::Epoch { removed, .. } if removed.contains(id)))
    }
}

impl<V: SpaceView> SpaceView for Overlay<'_, V> {
    fn log_id(&self) -> [u8; 16] {
        self.inner.log_id()
    }
    fn head(&self) -> u64 {
        self.staged
            .last()
            .map_or_else(|| self.inner.head(), Staged::position)
    }
    fn digest_at(&self, position: u64) -> Option<Hash32> {
        self.staged
            .iter()
            .find(|s| s.position() == position)
            .map(Staged::digest)
            .or_else(|| self.inner.digest_at(position))
    }
    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        if self.removed_here(id) {
            return None;
        }
        self.added()
            .find_map(|a| a.new_device.filter(|(d, _)| d == id).map(|(_, k)| k))
            .or_else(|| self.inner.device_key(id))
    }
    fn active_devices(&self) -> Vec<Hash32> {
        let mut all: std::collections::BTreeSet<Hash32> =
            self.inner.active_devices().into_iter().collect();
        for e in self.effects() {
            match e {
                Effect::Device { id, .. } => {
                    all.insert(id);
                }
                Effect::Epoch { removed, .. } => {
                    for d in &removed {
                        all.remove(d);
                    }
                }
                _ => {}
            }
        }
        all.into_iter().collect()
    }
    fn is_removed(&self, id: &Hash32) -> bool {
        self.removed_here(id) || self.inner.is_removed(id)
    }
    fn device_level(&self, id: &Hash32) -> Option<u64> {
        self.effects()
            .rev()
            .find_map(|e| match e {
                Effect::Device { id: d, level, .. } | Effect::DeviceLevel { id: d, level }
                    if &d == id =>
                {
                    Some(level)
                }
                _ => None,
            })
            .or_else(|| self.inner.device_level(id))
    }
    fn recovery_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        match self.effects().rev().find_map(|e| match e {
            Effect::Recovery { id, sign } => Some((id, sign)),
            _ => None,
        }) {
            Some((r, k)) => (&r == id).then_some(k),
            None => self.inner.recovery_key(id),
        }
    }
    fn recovery_known(&self, id: &Hash32) -> bool {
        self.inner.recovery_known(id)
            || self
                .effects()
                .any(|e| matches!(e, Effect::Recovery { id: r, .. } if &r == id))
    }
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)> {
        self.staged
            .iter()
            .find_map(|s| match s {
                Staged::Full(a) => {
                    (a.record.change_id() == Some(change_id)).then_some((a.position, a.record_hash))
                }
                Staged::Stub(st) => (st.change_id.as_ref() == Some(change_id))
                    .then_some((st.position, st.record_hash)),
            })
            .or_else(|| self.inner.change(change_id))
    }
    fn write_level(&self) -> u64 {
        self.effects()
            .rev()
            .find_map(|e| match e {
                Effect::WriteLevel(l) => Some(l),
                _ => None,
            })
            .unwrap_or_else(|| self.inner.write_level())
    }
    fn epoch(&self) -> u64 {
        self.effects()
            .rev()
            .find_map(|e| match e {
                Effect::Epoch { epoch, .. } => Some(epoch),
                _ => None,
            })
            .unwrap_or_else(|| self.inner.epoch())
    }
    fn last_security(&self) -> u64 {
        self.added()
            .rev()
            .find(|a| a.record.is_security())
            .map_or_else(|| self.inner.last_security(), |a| a.position)
    }
    fn snapshot_hash(&self, position: u64) -> Option<Hash32> {
        self.staged
            .iter()
            .find_map(|s| match s {
                Staged::Full(a) if a.position == position => {
                    matches!(a.record.body, Body::Snapshot { .. }).then_some(a.record_hash)
                }
                Staged::Stub(st) if st.position == position => {
                    (st.payload_type == "snailfish.snapshot.v1").then_some(st.record_hash)
                }
                _ => None,
            })
            .or_else(|| self.inner.snapshot_hash(position))
    }
    fn compaction(&self) -> Compaction {
        let mut c = self.inner.compaction();
        let mut active: std::collections::BTreeSet<Hash32> =
            self.inner.active_devices().into_iter().collect();
        for s in &self.staged {
            match s {
                Staged::Full(a) => {
                    match effect(&a.record) {
                        Effect::Device { id, .. } => {
                            active.insert(id);
                        }
                        Effect::Epoch { removed, .. } => {
                            for d in &removed {
                                active.remove(d);
                            }
                        }
                        _ => {}
                    }
                    c.apply(a.position, compaction::kind(&a.record), &active);
                }
                Staged::Stub(st) => {
                    c.apply(
                        st.position,
                        compaction::stub_kind(&st.payload_type),
                        &active,
                    );
                }
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dedupe_answers_known_and_conflict() {
        let h = [1; 32];
        assert_eq!(dedupe(None, &h), None);
        assert_eq!(dedupe(Some((4, h)), &h), Some(Dedupe::Known(4)));
        assert_eq!(dedupe(Some((4, [2; 32])), &h), Some(Dedupe::Conflict(4)));
    }

    #[test]
    fn refusal_codes() {
        let all = [
            Refusal::InvalidRecord("x".into()),
            Refusal::TooLarge,
            Refusal::NotAuthor,
            Refusal::NotActive,
            Refusal::BadBase,
            Refusal::StaleBase,
            Refusal::OnHold,
            Refusal::Unsupported,
            Refusal::WrongEpoch,
            Refusal::DuplicateChange,
        ];
        let codes: Vec<&str> = all.iter().map(Refusal::code).collect();
        assert_eq!(
            codes,
            [
                "invalid_record",
                "too_large",
                "not_author",
                "not_active",
                "bad_base",
                "stale_base",
                "on_hold",
                "unsupported",
                "wrong_epoch",
                "duplicate_change"
            ]
        );
        assert_eq!(all[0].to_string(), "invalid_record: x");
        assert_eq!(all[4].to_string(), "bad_base");
    }

    #[test]
    fn memory_space_positions() {
        let s = MemorySpace::new([3; 16]);
        assert_eq!(s.head(), 0);
        assert_eq!(s.digest_at(0), Some(digest0(&[3; 16])));
        assert_eq!(s.digest_at(1), None);
        assert_eq!(s.digest_at(u64::MAX), None);
        assert_eq!(s.epoch(), 0);
    }

    proptest! {
        /// [LOG-6]: the base of a record at head + 1 is an entry from 1 to head.
        #[test]
        fn base_range(base in 0u64..1000, head in 0u64..1000) {
            prop_assert_eq!(base_in_range(base, head), (1..=head).contains(&base));
        }

        /// [VER-8]: a raise goes above the write level, and no active device
        /// is below the new level.
        #[test]
        fn raise_needs_every_device(level in 0u64..10, write in 0u64..10, lowest in 0u64..10) {
            prop_assert_eq!(raise_ok(level, write, lowest), level > write && lowest >= level);
        }

        /// [VER-6] [VER-9]: a level holds a known type only from level 1 to
        /// the highest level, and not from the level that drops it.
        #[test]
        fn levels_hold(level in 0u64..5, max in 0u64..5, i in 0usize..9) {
            let t = records::RECORD_TYPES[i];
            let l = Levels { max, retired: &[("snailfish.device.v1", 3)] };
            let dropped = t == "snailfish.device.v1" && level >= 3;
            prop_assert_eq!(l.holds(level, t), (1..=max).contains(&level) && !dropped);
            prop_assert!(!l.holds(level, "snailfish.unknown.v1"));
        }

        /// [LOG-7]: a change passes with any base. A security record passes
        /// only if no security record lies after its base.
        #[test]
        fn security_base(security: bool, base in 0u64..1000, last in 0u64..1000) {
            let after_base = last > base;
            prop_assert_eq!(security_base_ok(security, base, last), !(security && after_base));
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// [LOG-6]: for every 64-bit base and head, a valid base names an entry
    /// at position 1 or later and before the new position head + 1.
    #[kani::proof]
    fn base_rule() {
        let base: u64 = kani::any();
        let head: u64 = kani::any();
        if base_in_range(base, head) {
            assert!(base >= 1 && base <= head);
        } else {
            assert!(base == 0 || base > head);
        }
    }

    /// [LOG-7]: for every 64-bit base and last security position, a
    /// security record passes only with its base at or after the last
    /// security record, and a change always passes.
    #[kani::proof]
    fn security_base_rule() {
        let base: u64 = kani::any();
        let last: u64 = kani::any();
        assert!(security_base_ok(false, base, last));
        assert!(security_base_ok(true, base, last) == (base >= last));
    }

    /// [VER-8]: for every 64-bit input, a valid raise is above the write
    /// level and at or below the lowest active device level.
    #[kani::proof]
    fn raise_rule() {
        let level: u64 = kani::any();
        let write: u64 = kani::any();
        let lowest: u64 = kani::any();
        assert!(raise_ok(level, write, lowest) == (level > write && lowest >= level));
    }

    /// [WIR-6]: a stored `change_id` never gives a new append, and the
    /// answer names the original position. Bound: 2 distinct hash values in
    /// the first byte, the rest fixed, so CBMC compares 32-byte arrays only.
    #[kani::proof]
    fn dedupe_names_original_position() {
        let pos: u64 = kani::any();
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let mut stored = [0u8; 32];
        stored[0] = a;
        let mut sent = [0u8; 32];
        sent[0] = b;
        match dedupe(Some((pos, stored)), &sent) {
            Some(Dedupe::Known(p)) => assert!(p == pos && a == b),
            Some(Dedupe::Conflict(p)) => assert!(p == pos && a != b),
            None => panic!("a stored change_id must be known or a conflict"),
        }
        assert!(dedupe(None, &sent).is_none());
    }
}
