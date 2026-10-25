//! Protocol operations with owned, binding-friendly types.
//!
//! The bindings forward each function here without logic. The shared vectors
//! run through this module in Rust, in Python and in Swift, so a marshalling
//! fault in a binding fails its vector tests (DESIGN.md M1).

use snailfish_protocol::encoding::{self, Hash32, decode_id, encode_id};
use snailfish_protocol::envelope;
use snailfish_protocol::hash;
use snailfish_protocol::keys;
use snailfish_protocol::records::{self, Author, Body, Record, TypeClass};
use snailfish_protocol::recovery;
use snailfish_protocol::sig;

/// A refused input. The message names the rule and holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CodecError {}

fn err(e: impl std::fmt::Display) -> CodecError {
    CodecError(e.to_string())
}

fn arr<const N: usize>(b: &[u8], what: &str) -> Result<[u8; N], CodecError> {
    b.try_into()
        .map_err(|_| CodecError(format!("{what} must be {N} bytes")))
}

fn author_text(a: &Author) -> String {
    match a {
        Author::Device(id) => encode_id("d_", id),
        Author::Recovery(id) => encode_id("r_", id),
    }
}

fn author_id(text: &str) -> Result<Hash32, CodecError> {
    decode_id::<32>(text, "d_")
        .or_else(|_| decode_id::<32>(text, "r_"))
        .map_err(err)
}

fn log_id(text: &str) -> Result<[u8; 16], CodecError> {
    decode_id::<16>(text, "l_").map_err(err)
}

/// One envelope after the reader of `PROTOCOL.md` section 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The payload type.
    pub payload_type: String,
    /// The exact payload bytes.
    pub payload: Vec<u8>,
    /// The 64-byte signature.
    pub sig: Vec<u8>,
}

/// The routing fields of a parsed log record payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadInfo {
    /// The log ID text.
    pub log: String,
    /// The author ID text.
    pub author: String,
    /// The base position.
    pub base_position: u64,
    /// The base digest.
    pub base_digest: Vec<u8>,
    /// The change ID bytes of a change record.
    pub change_id: Option<Vec<u8>>,
    /// True for a security record ([VER-5]).
    pub is_security: bool,
}

/// One key set of a security record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySetInfo {
    /// The recipient ID text.
    pub to: String,
    /// The epochs.
    pub epochs: Vec<u64>,
    /// `enc || ciphertext`.
    pub sealed: Vec<u8>,
}

/// The class of a payload type (`PROTOCOL.md` 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    /// A known log record type.
    Record,
    /// A known statement type.
    Statement,
    /// Skip the record and report `degraded`.
    UnknownContent,
    /// Stop with `stopped: update required`.
    UpdateRequired,
}

/// The frame of `PROTOCOL.md` 2.1.
#[must_use]
pub fn frame(parts: &[Vec<u8>]) -> Vec<u8> {
    encoding::frame(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

/// The Ed25519 public key of a 32-byte seed.
///
/// # Errors
///
/// Refuses a seed that is not 32 bytes.
pub fn sign_public_key(seed: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(sig::SecretKey::from_seed(&arr(seed, "seed")?)
        .public()
        .to_vec())
}

/// The X-Wing public key of a 32-byte seed.
///
/// # Errors
///
/// Refuses a seed that is not 32 bytes.
pub fn seal_public_key(seed: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(keys::seal_public(&arr(seed, "seed")?))
}

/// The device ID text of two public keys.
///
/// # Errors
///
/// Refuses a signing key that is not 32 bytes.
pub fn device_id(sign_pk: &[u8], seal_pk: &[u8]) -> Result<String, CodecError> {
    Ok(encode_id(
        "d_",
        &keys::device_id(&arr(sign_pk, "sign_pk")?, seal_pk),
    ))
}

/// The recovery ID text of two public keys.
///
/// # Errors
///
/// Refuses a signing key that is not 32 bytes.
pub fn recovery_id(sign_pk: &[u8], seal_pk: &[u8]) -> Result<String, CodecError> {
    Ok(encode_id(
        "r_",
        &keys::recovery_id(&arr(sign_pk, "sign_pk")?, seal_pk),
    ))
}

/// Parse an envelope.
///
/// # Errors
///
/// Refuses an envelope that breaks `PROTOCOL.md` section 4.
pub fn parse_envelope(text: &[u8]) -> Result<Envelope, CodecError> {
    let e = envelope::Envelope::parse(text).map_err(err)?;
    Ok(Envelope {
        payload_type: e.payload_type,
        payload: e.payload,
        sig: e.sig.to_vec(),
    })
}

/// The writer form of an envelope.
///
/// # Errors
///
/// Refuses a signature that is not 64 bytes.
pub fn envelope_to_json(env: &Envelope, keyid: &str) -> Result<String, CodecError> {
    let e = envelope::Envelope {
        payload_type: env.payload_type.clone(),
        payload: env.payload.clone(),
        sig: arr(&env.sig, "sig")?,
    };
    Ok(e.to_json(keyid))
}

/// The record hash ([LOG-3]).
///
/// # Errors
///
/// Refuses a signature that is not 64 bytes.
pub fn record_hash(payload_type: &str, payload: &[u8], sig: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(hash::record_hash(payload_type, payload, &arr(sig, "sig")?).to_vec())
}

/// The entry hash ([LOG-4]).
///
/// # Errors
///
/// Refuses a change ID that is not 16 bytes or a record hash that is not 32.
pub fn entry_hash(
    payload_type: &str,
    change_id: Option<&[u8]>,
    record_hash: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let cid = change_id.map(|c| arr::<16>(c, "change_id")).transpose()?;
    Ok(hash::entry_hash(
        payload_type,
        cid.as_ref(),
        &arr(record_hash, "record_hash")?,
    )
    .to_vec())
}

/// The log digest at position 0 ([LOG-5]).
///
/// # Errors
///
/// Refuses a malformed log ID.
pub fn digest0(log_id_text: &str) -> Result<Vec<u8>, CodecError> {
    Ok(hash::digest0(&log_id(log_id_text)?).to_vec())
}

/// The log digest at position `n` ([LOG-5]).
///
/// # Errors
///
/// Refuses inputs that are not 32 bytes.
pub fn digest_next(prev: &[u8], n: u64, entry_hash: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(hash::digest_next(&arr(prev, "prev")?, n, &arr(entry_hash, "entry_hash")?).to_vec())
}

/// Verify an Ed25519 signature over raw bytes (`PROTOCOL.md` 7.1).
#[must_use]
pub fn ed25519_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let (Ok(pk), Ok(s)) = (arr::<32>(public_key, "pk"), arr::<64>(signature, "sig")) else {
        return false;
    };
    sig::PublicKey::from_bytes(&pk).is_ok_and(|k| k.verify_raw(msg, &s).is_ok())
}

/// Verify a record signature over `PAE(payload_type, payload)` ([WIR-1]).
#[must_use]
pub fn verify_record(
    public_key: &[u8],
    payload_type: &str,
    payload: &[u8],
    signature: &[u8],
) -> bool {
    ed25519_verify(
        public_key,
        &snailfish_protocol::pae::encode(payload_type, payload),
        signature,
    )
}

/// Sign `PAE(payload_type, payload)` with a 32-byte seed.
///
/// # Errors
///
/// Refuses a seed that is not 32 bytes.
pub fn sign_record(seed: &[u8], payload_type: &str, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(sig::SecretKey::from_seed(&arr(seed, "seed")?)
        .sign_record(payload_type, payload)
        .to_vec())
}

/// Classify a payload type.
#[must_use]
pub fn classify(payload_type: &str) -> PayloadClass {
    match records::classify(payload_type) {
        TypeClass::Record => PayloadClass::Record,
        TypeClass::Statement => PayloadClass::Statement,
        TypeClass::UnknownContent => PayloadClass::UnknownContent,
        TypeClass::UpdateRequired => PayloadClass::UpdateRequired,
    }
}

fn parse(payload_type: &str, payload: &[u8]) -> Result<Record, CodecError> {
    records::parse_payload(payload_type, payload).map_err(err)
}

/// Parse a log record payload and return its routing fields.
///
/// # Errors
///
/// Refuses a payload that breaks `PROTOCOL.md` section 3 or 6.
pub fn check_payload(payload_type: &str, payload: &[u8]) -> Result<PayloadInfo, CodecError> {
    let r = parse(payload_type, payload)?;
    Ok(PayloadInfo {
        log: encode_id("l_", &r.log),
        author: author_text(&r.author),
        base_position: r.base.position,
        base_digest: r.base.digest.to_vec(),
        change_id: r.change_id().map(|c| c.to_vec()),
        is_security: r.is_security(),
    })
}

/// Parse a statement payload (`PROTOCOL.md` 6.3).
///
/// # Errors
///
/// Refuses a payload that breaks the rules.
pub fn check_statement(payload_type: &str, payload: &[u8]) -> Result<(), CodecError> {
    records::parse_statement(payload_type, payload)
        .map(|_| ())
        .map_err(err)
}

/// The key sets of a security record payload, in payload order.
///
/// # Errors
///
/// Refuses an invalid payload.
pub fn key_sets(payload_type: &str, payload: &[u8]) -> Result<Vec<KeySetInfo>, CodecError> {
    let r = parse(payload_type, payload)?;
    let sets = match r.body {
        Body::Genesis { keys, .. }
        | Body::Grant { keys, .. }
        | Body::Epoch { keys, .. }
        | Body::Recovery { keys, .. } => keys,
        _ => Vec::new(),
    };
    Ok(sets
        .into_iter()
        .map(|k| KeySetInfo {
            to: author_text(&k.to),
            epochs: k.epochs,
            sealed: k.sealed,
        })
        .collect())
}

/// The key commitment of the app key of one epoch.
///
/// # Errors
///
/// Refuses a malformed log ID or a key that is not 32 bytes.
pub fn key_commitment(log_id_text: &str, epoch: u64, key: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(keys::key_commitment(&log_id(log_id_text)?, epoch, &arr(key, "key")?).to_vec())
}

/// Open a key set. The caller checks each key against its commitment.
///
/// # Errors
///
/// Refuses malformed inputs, and fails if the key set does not open.
pub fn open_key_set(
    seal_seed: &[u8],
    log_id_text: &str,
    to: &str,
    epochs: &[u64],
    sealed: &[u8],
) -> Result<Vec<Vec<u8>>, CodecError> {
    let keys = keys::open_key_set(
        &arr(seal_seed, "seal_seed")?,
        &log_id(log_id_text)?,
        &author_id(to)?,
        epochs,
        sealed,
    )
    .map_err(err)?;
    Ok(keys.into_iter().map(|k| k.to_vec()).collect())
}

/// Decrypt the ciphertext of a change or snapshot payload with the app key
/// of its epoch. The associated data comes from the payload fields
/// (`PROTOCOL.md` 7.2).
///
/// # Errors
///
/// Refuses an invalid payload, a type without ciphertext, and a ciphertext
/// that does not decrypt ([DLV-13]).
pub fn decrypt_payload(
    app_key: &[u8],
    payload_type: &str,
    payload: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let key = arr::<32>(app_key, "app_key")?;
    let r = parse(payload_type, payload)?;
    let (aad, ct) = match &r.body {
        Body::Change {
            epoch,
            change_id,
            ciphertext,
        } => (
            keys::change_aad(&r.log, *epoch, change_id, r.author.id()),
            ciphertext,
        ),
        Body::Snapshot {
            epoch,
            state,
            ciphertext,
        } => (
            keys::snapshot_aad(&r.log, *epoch, r.author.id(), state.position, &state.digest),
            ciphertext,
        ),
        _ => return Err(CodecError(format!("`{payload_type}` holds no ciphertext"))),
    };
    keys::decrypt(&key, &aad, ct).map_err(err)
}

/// Read a recovery key that the user typed.
///
/// # Errors
///
/// Refuses a text that breaks `PROTOCOL.md` section 9.
pub fn recovery_parse(text: &str) -> Result<Vec<u8>, CodecError> {
    recovery::parse(text).map(|s| s.to_vec()).map_err(err)
}

/// The display form of a 16-byte recovery secret.
///
/// # Errors
///
/// Refuses a secret that is not 16 bytes.
pub fn recovery_display(secret: &[u8]) -> Result<String, CodecError> {
    Ok(recovery::display(&arr(secret, "secret")?))
}

/// The Ed25519 seed and the X-Wing seed of a recovery secret, in that order.
///
/// # Errors
///
/// Refuses a secret that is not 16 bytes.
pub fn recovery_derive(secret: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
    let (sign, seal) = recovery::derive(&arr(secret, "secret")?);
    Ok(vec![sign.to_vec(), seal.to_vec()])
}
