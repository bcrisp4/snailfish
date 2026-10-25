//! Record payloads (`PROTOCOL.md` section 6).
//!
//! [`parse_payload`] applies the strict JSON rules and the field rules of each
//! payload type. It does not check signatures, the space state or the log
//! position. A verifier must check the signature before it acts on the result
//! ([WIR-2]).

use crate::encoding::{Hash32, decode_b64_strict, decode_id};
use crate::keys::{NONCE_LEN, SEAL_PK_LEN, TAG_LEN, device_id, recovery_id, sealed_len};
use crate::strict::{self, Fields, MAX_INT, StrictError, Value};

/// A log position and the log digest at that position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// The position, from 0.
    pub position: u64,
    /// The log digest at the position.
    pub digest: Hash32,
}

/// The two public keys of a device or a recovery key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    /// The Ed25519 public key.
    pub sign: [u8; 32],
    /// The X-Wing public key.
    pub seal: Vec<u8>,
}

/// A device in a genesis or grant record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device ID. It equals [`device_id`] of the keys.
    pub id: Hash32,
    /// The public keys.
    pub keys: Keys,
    /// The device name.
    pub name: String,
    /// The highest protocol level of the device ([VER-7]).
    pub level: u64,
}

/// The author of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Author {
    /// A device ID.
    Device(Hash32),
    /// A recovery ID.
    Recovery(Hash32),
}

impl Author {
    /// The 32 bytes of the ID.
    #[must_use]
    pub fn id(&self) -> &Hash32 {
        match self {
            Self::Device(id) | Self::Recovery(id) => id,
        }
    }
}

/// The app keys of one or more epochs, sealed to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    /// The recipient.
    pub to: Author,
    /// The epochs, strictly increasing.
    pub epochs: Vec<u64>,
    /// `enc || ciphertext` (`PROTOCOL.md` 7.3).
    pub sealed: Vec<u8>,
}

/// The fields of one record type after the common fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // The fields are the payload fields of PROTOCOL.md 6.2.
pub enum Body {
    Genesis {
        app: String,
        recovery: Keys,
        level: u64,
        device: Device,
        epoch: u64,
        commitment: Hash32,
        keys: Vec<KeySet>,
    },
    Grant {
        device: Device,
        keys: Vec<KeySet>,
    },
    Epoch {
        epoch: u64,
        removed: Vec<Hash32>,
        stay: Vec<Hash32>,
        commitment: Hash32,
        keys: Vec<KeySet>,
    },
    Recovery {
        recovery: Keys,
        proof: [u8; 64],
        keys: Vec<KeySet>,
    },
    Device {
        level: u64,
    },
    Level {
        level: u64,
    },
    Change {
        epoch: u64,
        change_id: [u8; 16],
        ciphertext: Vec<u8>,
    },
    Snapshot {
        epoch: u64,
        state: Position,
        ciphertext: Vec<u8>,
    },
    Accept {
        snapshot_position: u64,
        snapshot_hash: Hash32,
        applied: Position,
    },
}

/// One parsed log record payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The log ID.
    pub log: [u8; 16],
    /// The signing key ([LOG-2]).
    pub author: Author,
    /// The base ([LOG-6]).
    pub base: Position,
    /// The fields of the record type.
    pub body: Body,
}

impl Record {
    /// The change ID of a change record. `None` for each other type
    /// ([LOG-4]).
    #[must_use]
    pub fn change_id(&self) -> Option<&[u8; 16]> {
        match &self.body {
            Body::Change { change_id, .. } => Some(change_id),
            _ => None,
        }
    }

    /// True for a security record ([VER-5]): each type outside the change,
    /// snapshot and accept families.
    #[must_use]
    pub fn is_security(&self) -> bool {
        !matches!(
            self.body,
            Body::Change { .. } | Body::Snapshot { .. } | Body::Accept { .. }
        )
    }
}

/// A signed statement that is not a log record (`PROTOCOL.md` 6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // The fields are the payload fields of PROTOCOL.md 6.3.
pub enum Statement {
    /// A checkpoint (DESIGN.md "Enrollment", [ENR-8]).
    Checkpoint {
        log: [u8; 16],
        author: Hash32,
        at: Position,
    },
    /// A space deletion ([LOG-13]).
    Delete {
        log: [u8; 16],
        author: Author,
        head: Position,
        expires: u64,
    },
}

/// The class of a payload type (`PROTOCOL.md` 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeClass {
    /// A log record type that this crate parses.
    Record,
    /// A statement type that this crate parses.
    Statement,
    /// An unknown change or snapshot version. The engine skips the record and
    /// reports `degraded` ([VER-5], [DLV-13]).
    UnknownContent,
    /// An unknown accept version or security record type. The engine stops
    /// with `stopped: update required` ([VER-4], [VER-5]).
    UpdateRequired,
}

/// The record types of protocol level 1.
pub const RECORD_TYPES: [&str; 9] = [
    "snailfish.genesis.v1",
    "snailfish.grant.v1",
    "snailfish.epoch.v1",
    "snailfish.recovery.v1",
    "snailfish.device.v1",
    "snailfish.level.v1",
    "snailfish.change.v1",
    "snailfish.snapshot.v1",
    "snailfish.accept.v1",
];

/// Classify a payload type (`PROTOCOL.md` 6.4).
#[must_use]
pub fn classify(payload_type: &str) -> TypeClass {
    if RECORD_TYPES.contains(&payload_type) {
        TypeClass::Record
    } else if matches!(
        payload_type,
        "snailfish.checkpoint.v1" | "snailfish.delete.v1"
    ) {
        TypeClass::Statement
    } else if is_family(payload_type, "snailfish.change")
        || is_family(payload_type, "snailfish.snapshot")
    {
        TypeClass::UnknownContent
    } else {
        TypeClass::UpdateRequired
    }
}

/// True if `t` is `family` followed by `.` and a version, for example
/// `snailfish.change.v2`.
fn is_family(t: &str, family: &str) -> bool {
    t.strip_prefix(family)
        .is_some_and(|rest| rest.starts_with('.'))
}

/// A payload that breaks `PROTOCOL.md` section 3 or 6.
pub type ParseError = StrictError;

fn bad(msg: impl Into<String>) -> ParseError {
    StrictError(msg.into())
}

/// Parse a log record payload of a known type.
///
/// # Errors
///
/// Refuses an unknown type, and each payload that breaks `PROTOCOL.md`
/// section 3 or 6.
pub fn parse_payload(payload_type: &str, payload: &[u8]) -> Result<Record, ParseError> {
    let map = strict::parse_object(payload)?;
    let extra: &[&str] = match payload_type {
        "snailfish.genesis.v1" => &[
            "app",
            "recovery",
            "level",
            "device",
            "epoch",
            "commitment",
            "keys",
        ],
        "snailfish.grant.v1" => &["device", "keys"],
        "snailfish.epoch.v1" => &["epoch", "removed", "stay", "commitment", "keys"],
        "snailfish.recovery.v1" => &["recovery", "proof", "keys"],
        "snailfish.device.v1" | "snailfish.level.v1" => &["level"],
        "snailfish.change.v1" => &["epoch", "change_id", "ciphertext"],
        "snailfish.snapshot.v1" => &["epoch", "state", "ciphertext"],
        "snailfish.accept.v1" => &["snapshot", "applied"],
        _ => return Err(bad(format!("unknown record type `{payload_type}`"))),
    };
    let mut names = vec!["log", "author", "base"];
    names.extend_from_slice(extra);
    let f = Fields::exact(&map, "payload", &names)?;
    let log = log_id(&f, "log")?;
    let author = author(f.str("author")?)?;
    let base = position(f.get("base")?, "base")?;
    let body = match payload_type {
        "snailfish.genesis.v1" => genesis(&f, &author, &log, &base)?,
        "snailfish.grant.v1" => grant(&f)?,

        "snailfish.epoch.v1" => epoch_record(&f)?,

        "snailfish.recovery.v1" => recovery_record(&f, &author)?,

        "snailfish.device.v1" => {
            require_device(&author)?;
            Body::Device {
                level: f.int("level", 1, 65535)?,
            }
        }
        "snailfish.level.v1" => {
            require_device(&author)?;
            Body::Level {
                level: f.int("level", 1, 65535)?,
            }
        }
        "snailfish.change.v1" => {
            require_device(&author)?;
            Body::Change {
                epoch: f.int("epoch", 1, MAX_INT)?,
                change_id: decode_id::<16>(f.str("change_id")?, "c_")
                    .map_err(|e| bad(format!("change_id: rule 7: {e}")))?,
                ciphertext: ciphertext(&f)?,
            }
        }
        "snailfish.snapshot.v1" => {
            require_device(&author)?;
            Body::Snapshot {
                epoch: f.int("epoch", 1, MAX_INT)?,
                state: position(f.get("state")?, "state")?,
                ciphertext: ciphertext(&f)?,
            }
        }
        // The match above leaves only the accept type.
        _ => {
            require_device(&author)?;
            let s = Fields::object(f.get("snapshot")?, "snapshot", &["position", "hash"])?;
            Body::Accept {
                snapshot_position: s.int("position", 1, MAX_INT)?,
                snapshot_hash: bin32(&s, "hash")?,
                applied: position(f.get("applied")?, "applied")?,
            }
        }
    };
    let is_genesis = matches!(body, Body::Genesis { .. });
    if !is_genesis && base.position == 0 {
        return Err(bad(
            "base: rule 6.1: the base of a record that is not a genesis record has a position from 1",
        ));
    }
    Ok(Record {
        log,
        author,
        base,
        body,
    })
}

/// Parse a signed statement (`PROTOCOL.md` 6.3).
///
/// # Errors
///
/// Refuses an unknown type, and each payload that breaks the rules.
pub fn parse_statement(payload_type: &str, payload: &[u8]) -> Result<Statement, ParseError> {
    let map = strict::parse_object(payload)?;
    match payload_type {
        "snailfish.checkpoint.v1" => {
            let f = Fields::exact(&map, "checkpoint", &["log", "author", "position", "digest"])?;
            let Author::Device(author) = author(f.str("author")?)? else {
                return Err(bad("checkpoint: rule 6.3: the author must be a device ID"));
            };
            Ok(Statement::Checkpoint {
                log: log_id(&f, "log")?,
                author,
                at: Position {
                    position: f.int("position", 1, MAX_INT)?,
                    digest: bin32(&f, "digest")?,
                },
            })
        }
        "snailfish.delete.v1" => {
            let f = Fields::exact(&map, "delete", &["log", "author", "head", "expires"])?;
            Ok(Statement::Delete {
                log: log_id(&f, "log")?,
                author: author(f.str("author")?)?,
                head: position(f.get("head")?, "head")?,
                expires: f.int("expires", 0, MAX_INT)?,
            })
        }
        _ => Err(bad(format!("unknown statement type `{payload_type}`"))),
    }
}

fn grant(f: &Fields<'_>) -> Result<Body, ParseError> {
    let device = device(f.get("device")?)?;
    let keys = key_sets(f, "keys")?;
    if !matches!(keys.as_slice(), [k] if k.to == Author::Device(device.id)) {
        return Err(bad(
            "grant: rule 6.2: keys must be one key set to the new device",
        ));
    }
    Ok(Body::Grant { device, keys })
}

fn epoch_record(f: &Fields<'_>) -> Result<Body, ParseError> {
    let epoch = f.int("epoch", 2, MAX_INT)?;
    let removed = device_ids(f, "removed")?;
    let stay = device_ids(f, "stay")?;
    if stay.is_empty() {
        return Err(bad("epoch: rule 6.2: stay is empty"));
    }
    let commitment = bin32(f, "commitment")?;
    let keys = key_sets(f, "keys")?;
    let devices_ok = stay
        .iter()
        .all(|d| keys.iter().any(|k| k.to == Author::Device(*d)));
    let recovery_count = keys
        .iter()
        .filter(|k| matches!(k.to, Author::Recovery(_)))
        .count();
    if keys.len() != stay.len().saturating_add(1) || !devices_ok || recovery_count != 1 {
        return Err(bad(
            "epoch: rule 6.2: keys must be one key set to each device in stay and one to the recovery ID",
        ));
    }
    if keys.iter().any(|k| k.epochs != [epoch]) {
        return Err(bad("epoch: rule 6.2: each key set must hold [epoch]"));
    }
    Ok(Body::Epoch {
        epoch,
        removed,
        stay,
        commitment,
        keys,
    })
}

fn recovery_record(f: &Fields<'_>, author: &Author) -> Result<Body, ParseError> {
    require_recovery(author)?;
    let recovery = keys_obj(f.get("recovery")?, "recovery")?;
    let proof: [u8; 64] = bin_exact(f, "proof", 64)?
        .try_into()
        .map_err(|_| bad("recovery.proof: rule 7: not 64 bytes"))?;
    let keys = key_sets(f, "keys")?;
    let new_id = recovery_id(&recovery.sign, &recovery.seal);
    if !matches!(keys.as_slice(), [k] if k.to == Author::Recovery(new_id)) {
        return Err(bad(
            "recovery: rule 6.2: keys must be one key set to the new recovery ID",
        ));
    }
    Ok(Body::Recovery {
        recovery,
        proof,
        keys,
    })
}

fn genesis(
    f: &Fields<'_>,
    author: &Author,
    log: &[u8; 16],
    base: &Position,
) -> Result<Body, ParseError> {
    require_recovery(author)?;
    let app = f.str("app")?.to_owned();
    if !(1..=255).contains(&app.len()) {
        return Err(bad("genesis.app: rule 6.2: length must be 1 to 255 bytes"));
    }
    let recovery = keys_obj(f.get("recovery")?, "recovery")?;
    let rid = recovery_id(&recovery.sign, &recovery.seal);
    if author.id() != &rid {
        return Err(bad(
            "genesis.author: rule 6.2: must equal the recovery ID of `recovery`",
        ));
    }
    let level = f.int("level", 1, 65535)?;
    let device = device(f.get("device")?)?;
    let epoch = f.int("epoch", 1, MAX_INT)?;
    if epoch != 1 {
        return Err(bad("genesis.epoch: rule 6.2: must be 1"));
    }
    let commitment = bin32(f, "commitment")?;
    let keys = key_sets(f, "keys")?;
    let to_device = keys.iter().any(|k| k.to == Author::Device(device.id));
    let to_recovery = keys.iter().any(|k| k.to == Author::Recovery(rid));
    if keys.len() != 2 || !to_device || !to_recovery || keys.iter().any(|k| k.epochs != [1]) {
        return Err(bad(
            "genesis.keys: rule 6.2: must be key sets to the device and the recovery ID, with epochs [1]",
        ));
    }
    if base.position != 0 || base.digest != crate::hash::digest0(log) {
        return Err(bad(
            "genesis.base: rule 6.1: must be position 0 with digest(0)",
        ));
    }
    Ok(Body::Genesis {
        app,
        recovery,
        level,
        device,
        epoch,
        commitment,
        keys,
    })
}

fn require_device(author: &Author) -> Result<(), ParseError> {
    match author {
        Author::Device(_) => Ok(()),
        Author::Recovery(_) => Err(bad("author: rule 6.2: must be a device ID")),
    }
}

fn require_recovery(author: &Author) -> Result<(), ParseError> {
    match author {
        Author::Recovery(_) => Ok(()),
        Author::Device(_) => Err(bad("author: rule 6.2: must be a recovery ID")),
    }
}

fn log_id(f: &Fields<'_>, name: &str) -> Result<[u8; 16], ParseError> {
    decode_id::<16>(f.str(name)?, "l_").map_err(|e| bad(format!("{name}: rule 7: {e}")))
}

fn author(text: &str) -> Result<Author, ParseError> {
    if let Ok(id) = decode_id::<32>(text, "d_") {
        return Ok(Author::Device(id));
    }
    decode_id::<32>(text, "r_")
        .map(Author::Recovery)
        .map_err(|e| bad(format!("author: rule 7: {e}")))
}

fn bin(f: &Fields<'_>, name: &str) -> Result<Vec<u8>, ParseError> {
    decode_b64_strict(f.str(name)?).map_err(|e| bad(format!("{name}: rule 7: {e}")))
}

fn bin_exact(f: &Fields<'_>, name: &str, n: usize) -> Result<Vec<u8>, ParseError> {
    let b = bin(f, name)?;
    if b.len() != n {
        return Err(bad(format!("{name}: rule 7: must be {n} bytes")));
    }
    Ok(b)
}

fn bin32(f: &Fields<'_>, name: &str) -> Result<[u8; 32], ParseError> {
    bin_exact(f, name, 32)?
        .try_into()
        .map_err(|_| bad(format!("{name}: rule 7: must be 32 bytes")))
}

fn ciphertext(f: &Fields<'_>) -> Result<Vec<u8>, ParseError> {
    let b = bin(f, "ciphertext")?;
    if b.len() < NONCE_LEN.saturating_add(TAG_LEN) {
        return Err(bad("ciphertext: rule 6.2: must be at least 40 bytes"));
    }
    Ok(b)
}

fn position(value: &Value, what: &'static str) -> Result<Position, ParseError> {
    let f = Fields::object(value, what, &["position", "digest"])?;
    Ok(Position {
        position: f.int("position", 0, MAX_INT)?,
        digest: bin32(&f, "digest")?,
    })
}

fn keys_obj(value: &Value, what: &'static str) -> Result<Keys, ParseError> {
    let f = Fields::object(value, what, &["sign", "seal"])?;
    keys_from(&f)
}

fn keys_from(f: &Fields<'_>) -> Result<Keys, ParseError> {
    let sign = bin32(f, "sign")?;
    let seal = bin_exact(f, "seal", SEAL_PK_LEN)?;
    Ok(Keys { sign, seal })
}

fn device(value: &Value) -> Result<Device, ParseError> {
    let f = Fields::object(value, "device", &["id", "sign", "seal", "name", "level"])?;
    let id =
        decode_id::<32>(f.str("id")?, "d_").map_err(|e| bad(format!("device.id: rule 7: {e}")))?;
    let keys = keys_from(&f)?;
    let name = f.str("name")?.to_owned();
    if !(1..=128).contains(&name.len()) {
        return Err(bad("device.name: rule 6.1: length must be 1 to 128 bytes"));
    }
    let level = f.int("level", 1, 65535)?;
    if id != device_id(&keys.sign, &keys.seal) {
        return Err(bad("device.id: rule 6.1: does not match the keys"));
    }
    Ok(Device {
        id,
        keys,
        name,
        level,
    })
}

fn device_ids(f: &Fields<'_>, name: &str) -> Result<Vec<Hash32>, ParseError> {
    let mut out: Vec<Hash32> = Vec::new();
    for v in f.arr(name)? {
        let Value::Str(s) = v else {
            return Err(bad(format!("{name}: rule 7: not a string")));
        };
        let id = decode_id::<32>(s, "d_").map_err(|e| bad(format!("{name}: rule 7: {e}")))?;
        if out.last().is_some_and(|last| last >= &id) {
            return Err(bad(format!("{name}: rule 6.1: not sorted, or a duplicate")));
        }
        out.push(id);
    }
    Ok(out)
}

fn key_sets(f: &Fields<'_>, name: &str) -> Result<Vec<KeySet>, ParseError> {
    let mut out: Vec<KeySet> = Vec::new();
    for v in f.arr(name)? {
        let k = Fields::object(v, "key set", &["to", "epochs", "sealed"])?;
        let to = author(k.str("to")?)?;
        let mut epochs: Vec<u64> = Vec::new();
        for e in k.arr("epochs")? {
            let Value::Int(n) = e else {
                return Err(bad("key set.epochs: rule 7: not an integer"));
            };
            let n = u64::try_from(*n)
                .ok()
                .filter(|n| *n >= 1)
                .ok_or_else(|| bad("key set.epochs: rule 7: below 1"))?;
            if epochs.last().is_some_and(|last| *last >= n) {
                return Err(bad("key set.epochs: rule 6.1: not strictly increasing"));
            }
            epochs.push(n);
        }
        if epochs.is_empty() {
            return Err(bad("key set.epochs: rule 6.1: empty"));
        }
        let sealed = bin_exact(&k, "sealed", sealed_len(epochs.len()))?;
        if out.last().is_some_and(|last| last.to.id() >= to.id()) {
            return Err(bad(format!(
                "{name}: rule 6.1: not sorted by `to`, or a duplicate"
            )));
        }
        out.push(KeySet { to, epochs, sealed });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_follows_protocol_6_4() {
        assert_eq!(classify("snailfish.change.v1"), TypeClass::Record);
        assert_eq!(classify("snailfish.checkpoint.v1"), TypeClass::Statement);
        assert_eq!(classify("snailfish.change.v2"), TypeClass::UnknownContent);
        assert_eq!(classify("snailfish.snapshot.v9"), TypeClass::UnknownContent);
        assert_eq!(classify("snailfish.accept.v2"), TypeClass::UpdateRequired);
        assert_eq!(classify("snailfish.grant.v2"), TypeClass::UpdateRequired);
        assert_eq!(classify("snailfish.changes.v1"), TypeClass::UpdateRequired);
        assert_eq!(classify("snailfish.change"), TypeClass::UpdateRequired);
        assert_eq!(classify(""), TypeClass::UpdateRequired);
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::is_family;

    /// [VER-5]: a type is in a family only if it is the family name, a dot
    /// and more bytes. Without this, `snailfish.changes.v1` could pass as a
    /// change and an unknown security record could be skipped ([VER-4]).
    #[kani::proof]
    #[kani::unwind(8)]
    fn is_family_needs_a_dot_after_the_family() {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 4);
        if let Ok(t) = core::str::from_utf8(&bytes[..len]) {
            if is_family(t, "ab") {
                assert!(len >= 3 && bytes[0] == b'a' && bytes[1] == b'b' && bytes[2] == b'.');
            }
        }
    }
}
