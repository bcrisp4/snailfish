//! The space-state check of M3 (`PROTOCOL.md` 10.5, 10.6 and 10.9).
//!
//! The relay and the engine use the same functions ([LOG-9]). They check the
//! signature, the strict parse, dense positions, the digest chain, the base
//! rule ([LOG-6]), the base rule for security records ([LOG-7]) and the
//! active devices from the genesis record and the grants ([LOG-8]). The
//! relay also refuses changes during a restore hold ([LOG-14]). Removal
//! comes in M7.
//!
//! The functions do no I/O. The caller gives the log state through
//! [`SpaceView`], for example from SQLite.

use crate::encoding::Hash32;
use crate::envelope::Envelope;
use crate::hash::{digest_next, digest0, entry_hash};
use crate::records::{self, Author, Body, Record};
use crate::sig::PublicKey;

/// The record types that M2 accepts after the genesis record.
pub const M2_TYPES: [&str; 2] = ["snailfish.change.v1", "snailfish.grant.v1"];

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
    /// The position and record hash of a change with this `change_id`.
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)>;
    /// The space write level ([VER-9]).
    fn write_level(&self) -> u64;
    /// The current epoch. M3 has no epoch record, so it is 1.
    fn epoch(&self) -> u64;
    /// The position of the last security record ([LOG-7]). 0 for an empty
    /// log.
    fn last_security(&self) -> u64;
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

/// Check one record for the next position (`PROTOCOL.md` 10.6, in that
/// order). The genesis record has its own check, [`check_genesis`].
///
/// [WIR-2]: the parse before the signature check only finds the author.
/// The function changes no state. The caller applies an [`Accepted`] only
/// after it returns, so no state changes before the signature verifies.
#[must_use]
pub fn check_append(view: &impl SpaceView, env: &Envelope, mode: Mode) -> Verdict {
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
    match judge(view, env, record, record_hash, mode) {
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
) -> Result<Accepted, Refusal> {
    if let Mode::Relay {
        max_change_bytes, ..
    } = mode
        && matches!(record.body, Body::Change { .. })
        && env.payload.len() > max_change_bytes
    {
        return Err(Refusal::TooLarge);
    }
    if record.log != view.log_id() {
        return Err(invalid("log: the record names another log"));
    }
    let author = match record.author {
        Author::Device(id) => id,
        Author::Recovery(_) => {
            if let Mode::Relay { .. } = mode {
                return Err(Refusal::NotAuthor);
            }
            return Err(Refusal::NotActive);
        }
    };
    if let Mode::Relay { signer, .. } = mode
        && signer != author
    {
        return Err(Refusal::NotAuthor);
    }
    let key = view.device_key(&author).ok_or(Refusal::NotActive)?;
    PublicKey::from_bytes(&key)
        .and_then(|k| k.verify_record(&env.payload_type, &env.payload, &env.sig))
        .map_err(invalid)?;
    let head = view.head();
    if !base_in_range(record.base.position, head)
        || view.digest_at(record.base.position) != Some(record.base.digest)
    {
        return Err(Refusal::BadBase);
    }
    if !security_base_ok(
        record.is_security(),
        record.base.position,
        view.last_security(),
    ) {
        return Err(Refusal::StaleBase);
    }
    if !M2_TYPES.contains(&env.payload_type.as_str()) {
        return Err(Refusal::Unsupported);
    }
    let new_device = match &record.body {
        Body::Change { epoch, .. } => {
            if *epoch != view.epoch() {
                return Err(Refusal::WrongEpoch);
            }
            None
        }
        Body::Grant { device, keys } => {
            if view.device_key(&device.id).is_some() {
                return Err(invalid("grant: the device is already active"));
            }
            if device.level < view.write_level() {
                return Err(invalid("grant: the device level is below the write level"));
            }
            let want: Vec<u64> = (1..=view.epoch()).collect();
            if keys.iter().any(|k| k.epochs != want) {
                return Err(invalid("grant: the key set must hold each epoch"));
            }
            Some((device.id, device.keys.sign))
        }
        _ => return Err(Refusal::Unsupported),
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

/// An in-memory [`SpaceView`]: the engine and tests use it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemorySpace {
    /// The log ID.
    pub log_id: [u8; 16],
    /// `digests[n]` is the digest at position n, from 0.
    pub digests: Vec<Hash32>,
    /// The active devices and their Ed25519 keys.
    pub devices: std::collections::BTreeMap<Hash32, [u8; 32]>,
    /// Each change: its position and record hash.
    pub changes: std::collections::BTreeMap<[u8; 16], (u64, Hash32)>,
    /// The write level.
    pub level: u64,
    /// The position of the last security record.
    pub last_security: u64,
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

    /// Add an accepted record at the next position.
    ///
    /// # Panics
    ///
    /// Never: the check computed the position from this view.
    pub fn apply(&mut self, a: &Accepted) {
        self.digests.push(a.digest);
        if let Some((id, key)) = a.new_device {
            self.devices.insert(id, key);
        }
        if let Some(cid) = a.record.change_id() {
            self.changes.insert(*cid, (a.position, a.record_hash));
        }
        if let Some(level) = genesis_level(&a.record) {
            self.level = level;
        }
        if a.record.is_security() {
            self.last_security = a.position;
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
    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.devices.get(id).copied()
    }
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)> {
        self.changes.get(change_id).copied()
    }
    fn write_level(&self) -> u64 {
        self.level
    }
    fn epoch(&self) -> u64 {
        1
    }
    fn last_security(&self) -> u64 {
        self.last_security
    }
}

/// A [`SpaceView`] of a log and the accepted records after its head. The
/// relay checks repair entries against the log and the entries before them
/// (`PROTOCOL.md` 10.9), with no write to the log.
pub struct Overlay<'a, V: SpaceView> {
    inner: &'a V,
    added: Vec<Accepted>,
}

impl<'a, V: SpaceView> Overlay<'a, V> {
    /// An overlay with no added records.
    pub fn new(inner: &'a V) -> Self {
        Self {
            inner,
            added: Vec::new(),
        }
    }

    /// Add an accepted record at the next position.
    pub fn apply(&mut self, a: Accepted) {
        self.added.push(a);
    }

    /// The added records, in position order.
    #[must_use]
    pub fn into_added(self) -> Vec<Accepted> {
        self.added
    }
}

impl<V: SpaceView> SpaceView for Overlay<'_, V> {
    fn log_id(&self) -> [u8; 16] {
        self.inner.log_id()
    }
    fn head(&self) -> u64 {
        self.added
            .last()
            .map_or_else(|| self.inner.head(), |a| a.position)
    }
    fn digest_at(&self, position: u64) -> Option<Hash32> {
        self.added
            .iter()
            .find(|a| a.position == position)
            .map(|a| a.digest)
            .or_else(|| self.inner.digest_at(position))
    }
    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.added
            .iter()
            .find_map(|a| a.new_device.filter(|(d, _)| d == id).map(|(_, k)| k))
            .or_else(|| self.inner.device_key(id))
    }
    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)> {
        self.added
            .iter()
            .find(|a| a.record.change_id() == Some(change_id))
            .map(|a| (a.position, a.record_hash))
            .or_else(|| self.inner.change(change_id))
    }
    fn write_level(&self) -> u64 {
        self.inner.write_level()
    }
    fn epoch(&self) -> u64 {
        self.inner.epoch()
    }
    fn last_security(&self) -> u64 {
        self.added
            .iter()
            .rev()
            .find(|a| a.record.is_security())
            .map_or_else(|| self.inner.last_security(), |a| a.position)
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
        assert_eq!(s.epoch(), 1);
    }

    proptest! {
        /// [LOG-6]: the base of a record at head + 1 is an entry from 1 to head.
        #[test]
        fn base_range(base in 0u64..1000, head in 0u64..1000) {
            prop_assert_eq!(base_in_range(base, head), (1..=head).contains(&base));
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
