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
    /// The X-Wing public key. Boxed, so that [`Body`] stays small.
    pub seal: Box<[u8; SEAL_PK_LEN]>,
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
    /// The signed confirmation of a new device ([ENR-7], `PROTOCOL.md`
    /// 11.2). `device.keys.sign` is the signing key.
    Confirm {
        session: [u8; 16],
        trusted: Hash32,
        device: Device,
        trusted_nonce: [u8; 32],
        new_nonce: [u8; 32],
    },
}

/// The statement types of `PROTOCOL.md` 6.3.
pub const STATEMENT_TYPES: [&str; 3] = [
    "snailfish.checkpoint.v1",
    "snailfish.delete.v1",
    "snailfish.confirm.v1",
];

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
    } else if STATEMENT_TYPES.contains(&payload_type) {
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
    let author = parse_author(f.str("author")?)?;
    let base = position(f.get("base")?, "base")?;
    let body = match payload_type {
        "snailfish.genesis.v1" => genesis(&f, &author, &log, &base)?,
        "snailfish.grant.v1" => grant(&f)?,
        "snailfish.epoch.v1" => epoch_record(&f)?,
        "snailfish.recovery.v1" => recovery_record(&f, &author, &log)?,

        "snailfish.device.v1" | "snailfish.level.v1" => {
            require_device(&author)?;
            let level = f.int("level", 1, 65535)?;
            if payload_type == "snailfish.device.v1" {
                Body::Device { level }
            } else {
                Body::Level { level }
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
        "snailfish.accept.v1" => {
            require_device(&author)?;
            let s = Fields::object(f.get("snapshot")?, "snapshot", &["position", "hash"])?;
            Body::Accept {
                snapshot_position: s.int("position", 1, MAX_INT)?,
                snapshot_hash: bin32(&s, "hash")?,
                applied: position(f.get("applied")?, "applied")?,
            }
        }
        _ => return Err(bad(format!("unknown record type `{payload_type}`"))),
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
            let Author::Device(author) = parse_author(f.str("author")?)? else {
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
                author: parse_author(f.str("author")?)?,
                head: position(f.get("head")?, "head")?,
                expires: f.int("expires", 0, MAX_INT)?,
            })
        }
        "snailfish.confirm.v1" => {
            let f = Fields::exact(
                &map,
                "confirm",
                &["session", "trusted", "device", "trusted_nonce", "new_nonce"],
            )?;
            Ok(Statement::Confirm {
                session: decode_id::<16>(f.str("session")?, "e_")
                    .map_err(|e| bad(format!("session: rule 7: {e}")))?,
                trusted: decode_id::<32>(f.str("trusted")?, "d_")
                    .map_err(|e| bad(format!("trusted: rule 7: {e}")))?,
                device: device(f.get("device")?)?,
                trusted_nonce: bin32(&f, "trusted_nonce")?,
                new_nonce: bin32(&f, "new_nonce")?,
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
    // A device in both lists would get the key of the epoch that removes it.
    // `stay` is sorted, so a binary search is valid.
    if removed.iter().any(|d| stay.binary_search(d).is_ok()) {
        return Err(bad("epoch: rule 6.2: a device is in both removed and stay"));
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

fn recovery_record(f: &Fields<'_>, author: &Author, log: &[u8; 16]) -> Result<Body, ParseError> {
    require_recovery(author)?;
    let recovery = keys_obj(f.get("recovery")?, "recovery")?;
    let proof: [u8; 64] = bin_exact(f, "proof", 64)?
        .try_into()
        .map_err(|_| bad("recovery.proof: rule 7: not 64 bytes"))?;
    let keys = key_sets(f, "keys")?;
    // PROTOCOL.md 6.2: the record holds every input of the proof, so the
    // parser checks it. keys_from already refused a weak or non-canonical key.
    let msg = crate::encoding::frame(&[
        b"snailfish.recovery-proof.v1",
        log,
        &recovery.sign,
        &recovery.seal[..],
    ]);
    crate::sig::PublicKey::from_bytes(&recovery.sign)
        .and_then(|pk| pk.verify_raw(&msg, &proof))
        .map_err(|e| bad(format!("recovery.proof: rule 6.2: {e}")))?;
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

/// Parse a device object (`PROTOCOL.md` 6.1) with the strict rules of
/// section 3, for the enrollment messages of 10.10.
///
/// # Errors
///
/// Refuses each object that breaks section 3 or 6.1.
pub fn parse_device_json(bytes: &[u8]) -> Result<Device, ParseError> {
    device(&strict::parse(bytes)?)
}

/// Parse a keys object (`PROTOCOL.md` 6.1), as [`parse_device_json`].
///
/// # Errors
///
/// Refuses each object that breaks section 3 or 6.1.
pub fn parse_keys_json(bytes: &[u8]) -> Result<Keys, ParseError> {
    keys_obj(&strict::parse(bytes)?, "keys")
}

/// Parse an author or recipient ID text: a device ID or a recovery ID.
///
/// # Errors
///
/// Refuses each text that is not `d_` or `r_` with 64 lowercase hex digits.
pub fn parse_author(text: &str) -> Result<Author, ParseError> {
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
    // PROTOCOL.md 6.1: a record must not introduce a key that no signature
    // can verify, or a second encoding of one key.
    crate::sig::PublicKey::from_bytes(&sign).map_err(|e| bad(format!("sign: rule 6.1: {e}")))?;
    let seal: Box<[u8; SEAL_PK_LEN]> = bin_exact(f, "seal", SEAL_PK_LEN)?
        .into_boxed_slice()
        .try_into()
        .map_err(|_| bad("seal: rule 7: must be 1216 bytes"))?;
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
        let to = parse_author(k.str("to")?)?;
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
    use proptest::prelude::*;

    /// Each payload of the shared vectors, as `(payload_type, payload)`.
    fn vector_payloads() -> Vec<(String, Vec<u8>)> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/protocol.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut out = Vec::new();
        for e in v["log"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .chain(v["statements"].as_array().unwrap())
        {
            out.push((
                e["payload_type"].as_str().unwrap().to_owned(),
                e["payload"].as_str().unwrap().as_bytes().to_vec(),
            ));
        }
        out
    }

    /// The vector payload of log entry `n` (from 1), as a JSON value.
    fn entry(n: usize) -> (String, serde_json::Value) {
        let (t, p) = vector_payloads().swap_remove(n.wrapping_sub(1));
        (t, serde_json::from_slice(&p).unwrap())
    }

    fn reparse(t: &str, v: &serde_json::Value) -> Result<Record, ParseError> {
        parse_payload(t, serde_json::to_string(v).unwrap().as_bytes())
    }

    /// The parsed body of each vector type, and the security class of
    /// [VER-5]. Without this, a device record could parse as a level record,
    /// and a change could count as a security record for [LOG-7].
    #[test]
    fn vector_bodies_and_security_class() {
        let want = [
            ("snailfish.genesis.v1", true),
            ("snailfish.grant.v1", true),
            ("snailfish.change.v1", false),
            ("snailfish.snapshot.v1", false),
            ("snailfish.accept.v1", false),
            ("snailfish.device.v1", true),
            ("snailfish.level.v1", true),
        ];
        for (i, (t, sec)) in want.iter().enumerate() {
            let (ty, v) = entry(i.wrapping_add(1));
            assert_eq!(ty, *t);
            let r = reparse(&ty, &v).unwrap();
            assert_eq!(r.is_security(), *sec, "{t}");
            match (&r.body, *t) {
                (Body::Device { level: 2 }, "snailfish.device.v1")
                | (Body::Level { level: 2 }, "snailfish.level.v1")
                | (Body::Genesis { .. }, "snailfish.genesis.v1")
                | (Body::Grant { .. }, "snailfish.grant.v1")
                | (Body::Change { .. }, "snailfish.change.v1")
                | (Body::Snapshot { .. }, "snailfish.snapshot.v1")
                | (Body::Accept { .. }, "snailfish.accept.v1") => {}
                (b, t) => panic!("{t}: {b:?}"),
            }
        }
    }

    /// [LOG-2] and `PROTOCOL.md` 6.2: each type has a fixed author kind. A
    /// change by a recovery ID, or a genesis or recovery record by a device,
    /// is refused.
    #[test]
    fn author_kind_is_enforced() {
        for n in [3, 4, 5, 6, 7] {
            let (t, mut v) = entry(n);
            let id = v["author"].as_str().unwrap().replacen("d_", "r_", 1);
            v["author"] = id.into();
            assert!(reparse(&t, &v).is_err(), "{t} by a recovery ID");
        }
        for n in [1, 11] {
            let (t, mut v) = entry(n);
            let id = v["author"].as_str().unwrap().replacen("r_", "d_", 1);
            v["author"] = id.into();
            assert!(reparse(&t, &v).is_err(), "{t} by a device ID");
        }
    }

    /// `PROTOCOL.md` 6.2: genesis key sets go to the first device and the
    /// recovery ID, each with epochs [1].
    #[test]
    fn genesis_key_sets_need_both_recipients() {
        let (t, v) = entry(1);
        assert!(reparse(&t, &v).is_ok());
        // Only one key set.
        let mut one = v.clone();
        one["keys"].as_array_mut().unwrap().truncate(1);
        assert!(reparse(&t, &one).is_err());
        // The device key set goes to another device ID.
        let mut other = v.clone();
        other["keys"][0]["to"] = format!("d_{}", "00".repeat(32)).into();
        assert!(reparse(&t, &other).is_err());
        // The recovery key set goes to another recovery ID.
        let mut rother = v.clone();
        rother["keys"][1]["to"] = format!("r_{}", "ff".repeat(32)).into();
        assert!(reparse(&t, &rother).is_err());
        // Two recovery key sets: one to the right ID, one to another.
        let mut two = v.clone();
        two["keys"][0]["to"] = format!("r_{}", "00".repeat(32)).into();
        assert!(reparse(&t, &two).is_err());
        // Epochs [2] in one key set: same sealed length as [1].
        let mut e2 = v.clone();
        e2["keys"][1]["epochs"] = serde_json::json!([2]);
        assert!(reparse(&t, &e2).is_err());
        // A genesis base at position 0 with another digest.
        let mut b = v;
        b["base"]["digest"] = crate::encoding::encode_b64(&[0; 32]).into();
        assert!(reparse(&t, &b).is_err());
    }

    /// `PROTOCOL.md` 6.2: an epoch record has one key set for each device in
    /// `stay` and one for a recovery ID, and nothing else.
    #[test]
    fn epoch_key_sets_match_stay() {
        let (t, v) = entry(9);
        assert!(reparse(&t, &v).is_ok());
        let keys = v["keys"].as_array().unwrap().clone();
        // A device in stay without a key set: drop the first device set and
        // add a second recovery-ID set at the end.
        let mut missing = v.clone();
        let mut ks = keys[1..].to_vec();
        let mut extra = keys[2].clone();
        extra["to"] = format!("r_{}", "ff".repeat(32)).into();
        ks.push(extra);
        missing["keys"] = ks.into();
        assert!(reparse(&t, &missing).is_err());
        // No recovery key set: replace it with a device that is not in stay.
        let mut norec = v.clone();
        let mut ks = keys.clone();
        ks[2]["to"] = format!("d_{}", "ff".repeat(32)).into();
        norec["keys"] = ks.into();
        assert!(reparse(&t, &norec).is_err());
        // One key set too few.
        let mut few = v.clone();
        few["keys"] = keys[..2].to_vec().into();
        assert!(reparse(&t, &few).is_err());
        // Each count is right, but a device in stay has no key set: the
        // second device set goes to a device that is not in stay. The ID
        // 99.. keeps the list sorted between 28.. and ab...
        let mut other = v.clone();
        let mut ks = keys.clone();
        ks[1]["to"] = format!("d_99{}", "00".repeat(31)).into();
        other["keys"] = ks.into();
        assert!(reparse(&t, &other).is_err());
        // Each device in stay and one recovery ID have a set, plus one more
        // device set. The ID ab50.. sorts between ab3d.. and ab76...
        let mut more = v;
        let mut ks = keys.clone();
        let mut extra = keys[1].clone();
        extra["to"] = format!("d_ab50{}", "00".repeat(30)).into();
        ks.insert(2, extra);
        more["keys"] = ks.into();
        assert!(reparse(&t, &more).is_err());
    }

    #[test]
    fn vector_payloads_are_found_and_parse() {
        let all = vector_payloads();
        assert!(all.len() >= 5);
        for (t, p) in &all {
            let ok = parse_payload(t, p).is_ok() || parse_statement(t, p).is_ok();
            assert!(ok, "{t}");
        }
    }

    proptest! {
        /// [WIR-4]: the parsers never panic on random bytes, for each
        /// payload type.
        #[test]
        fn parsers_never_panic_on_random_bytes(
            idx in 0usize..12,
            bytes in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let types: Vec<&str> = RECORD_TYPES
                .iter()
                .copied()
                .chain(STATEMENT_TYPES)
                .collect();
            let _ = parse_payload(types[idx], &bytes);
            let _ = parse_statement(types[idx], &bytes);
        }

        /// [WIR-4]: a change, an insertion or a deletion of one byte of a
        /// valid payload never panics. If the result is accepted, it is
        /// valid UTF-8 (rule 1).
        #[test]
        fn parsers_survive_mutated_vector_payloads(
            which in any::<usize>(),
            pos in any::<usize>(),
            byte in any::<u8>(),
            mode in 0u8..3,
        ) {
            let all = vector_payloads();
            let (t, p) = &all[which.checked_rem(all.len()).unwrap()];
            let mut m = p.clone();
            let i = pos.checked_rem(m.len()).unwrap();
            match mode {
                0 => m[i] = byte,
                1 => m.insert(i, byte),
                _ => { m.remove(i); }
            }
            if parse_payload(t, &m).is_ok() || parse_statement(t, &m).is_ok() {
                prop_assert!(std::str::from_utf8(&m).is_ok());
            }
        }

        /// [VER-5]: `classify` returns `Record` only for the 9 record types
        /// and `Statement` only for the 3 statement types.
        #[test]
        fn classify_matches_the_type_tables(t in "snailfish\\.[a-z]{0,10}(\\.v[0-9]{0,2})?") {
            let record = RECORD_TYPES.contains(&t.as_str());
            let statement = STATEMENT_TYPES.contains(&t.as_str());
            prop_assert_eq!(classify(&t) == TypeClass::Record, record);
            prop_assert_eq!(classify(&t) == TypeClass::Statement, statement);
        }
    }

    /// [VER-4] [VER-5]: after `snailfish.change.v`, the byte `1` is a known
    /// record and each other ASCII byte is unknown content, never an update.
    #[test]
    fn classify_change_version_byte() {
        for c in 0u8..128 {
            let t = format!("snailfish.change.v{}", char::from(c));
            let want = if c == b'1' {
                TypeClass::Record
            } else {
                TypeClass::UnknownContent
            };
            assert_eq!(classify(&t), want, "{t:?}");
        }
    }

    /// [VER-4]: one more name byte after a family name, not a dot, is an
    /// unknown security record, so a client stops on it.
    #[test]
    fn classify_longer_family_name_needs_an_update() {
        for c in (0u8..128).filter(|c| *c != b'.') {
            let t = format!("snailfish.snapshot{}.v1", char::from(c));
            assert_eq!(classify(&t), TypeClass::UpdateRequired, "{t:?}");
        }
    }

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
    use super::{TypeClass, classify, is_family};

    // `classify` over full type names is checked exhaustively for one
    // varying ASCII byte by the unit tests `classify_change_version_byte`
    // and `classify_longer_family_name_needs_an_update`. As Kani harnesses,
    // both ran for more than 5 minutes (the `str::from_utf8` call and the
    // nine string compares), and the byte domain has only 128 values.

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
