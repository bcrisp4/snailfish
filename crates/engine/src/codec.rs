//! Protocol operations with owned, binding-friendly types.
//!
//! The bindings forward each function here without logic. The shared vectors
//! run through this module in Rust, in Python and in Swift, so a marshalling
//! fault in a binding fails its vector tests (DESIGN.md M1).

use snailfish_protocol::encoding::{self, Hash32, decode_id, encode_id};
use snailfish_protocol::envelope;
use snailfish_protocol::hash;
use snailfish_protocol::keys;
use snailfish_protocol::records::{self, Author, Body, Record};
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
    records::parse_author(text).map(|a| *a.id()).map_err(err)
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
    /// The key sets of a genesis, grant, epoch or recovery record, in
    /// payload order. Empty for each other type.
    pub key_sets: Vec<KeySetInfo>,
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
pub use snailfish_protocol::records::TypeClass as PayloadClass;

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
    Ok(keys::seal_public(&arr(seed, "seed")?).to_vec())
}

/// The device ID text of two public keys.
///
/// # Errors
///
/// Refuses a signing key that is not 32 bytes and a sealing key that is not
/// 1,216 bytes. An ID of a key with the wrong size names no device.
pub fn device_id(sign_pk: &[u8], seal_pk: &[u8]) -> Result<String, CodecError> {
    Ok(encode_id(
        "d_",
        &keys::device_id(&arr(sign_pk, "sign_pk")?, &arr(seal_pk, "seal_pk")?),
    ))
}

/// The recovery ID text of two public keys.
///
/// # Errors
///
/// Refuses a signing key that is not 32 bytes and a sealing key that is not
/// 1,216 bytes.
pub fn recovery_id(sign_pk: &[u8], seal_pk: &[u8]) -> Result<String, CodecError> {
    Ok(encode_id(
        "r_",
        &keys::recovery_id(&arr(sign_pk, "sign_pk")?, &arr(seal_pk, "seal_pk")?),
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
    Ok(envelope::write_json(
        &env.payload_type,
        &env.payload,
        &arr(&env.sig, "sig")?,
        keyid,
    ))
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

/// Classify a payload type.
#[must_use]
pub fn classify(payload_type: &str) -> PayloadClass {
    records::classify(payload_type)
}

fn parse(payload_type: &str, payload: &[u8]) -> Result<Record, CodecError> {
    records::parse_payload(payload_type, payload).map_err(err)
}

/// Parse a log record payload and return its routing fields and key sets,
/// in one parse.
///
/// The result does not show that the record is valid in the log: the caller
/// must also verify the signature ([WIR-2]) and the space state ([LOG-8]).
///
/// # Errors
///
/// Refuses a payload that breaks `PROTOCOL.md` section 3 or 6.
pub fn check_payload(payload_type: &str, payload: &[u8]) -> Result<PayloadInfo, CodecError> {
    let r = parse(payload_type, payload)?;
    let change_id = r.change_id().map(|c| c.to_vec());
    let is_security = r.is_security();
    let sets = match r.body {
        Body::Genesis { keys, .. }
        | Body::Grant { keys, .. }
        | Body::Epoch { keys, .. }
        | Body::Recovery { keys, .. } => keys,
        _ => Vec::new(),
    };
    Ok(PayloadInfo {
        log: encode_id("l_", &r.log),
        author: author_text(&r.author),
        base_position: r.base.position,
        base_digest: r.base.digest.to_vec(),
        change_id,
        is_security,
        key_sets: sets
            .into_iter()
            .map(|k| KeySetInfo {
                to: author_text(&k.to),
                epochs: k.epochs,
                sealed: k.sealed,
            })
            .collect(),
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

/// A QR payload of `PROTOCOL.md` 11.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollPayload {
    /// `t` or `n`: the role of the device that shows the payload.
    pub role: String,
    /// The relay URL.
    pub relay_url: String,
    /// The 16-byte session ID.
    pub session: Vec<u8>,
}

/// The typed code of a 16-byte session ID (`PROTOCOL.md` 11.1).
///
/// # Errors
///
/// Refuses a session ID that is not 16 bytes.
pub fn enroll_display(session: &[u8]) -> Result<String, CodecError> {
    Ok(snailfish_protocol::enroll::display(&arr(
        session, "session",
    )?))
}

/// Read a typed code (`PROTOCOL.md` 11.1).
///
/// # Errors
///
/// Refuses a text that breaks the reader steps or the check.
pub fn enroll_parse_code(text: &str) -> Result<Vec<u8>, CodecError> {
    snailfish_protocol::enroll::parse_code(text)
        .map(|s| s.to_vec())
        .map_err(err)
}

/// Read a QR payload (`PROTOCOL.md` 11.1).
///
/// # Errors
///
/// Refuses a payload that breaks 11.1.
pub fn enroll_parse_payload(text: &str) -> Result<EnrollPayload, CodecError> {
    let p = snailfish_protocol::enroll::parse_payload(text).map_err(err)?;
    Ok(EnrollPayload {
        role: p.role.letter().to_owned(),
        relay_url: p.relay_url,
        session: p.session.to_vec(),
    })
}

/// The commitment of the trusted device (`PROTOCOL.md` 11.2). A test relay
/// that substitutes keys needs it to reach the code comparison.
///
/// # Errors
///
/// Refuses a session or a nonce of the wrong size, or a bad device ID.
pub fn enroll_commitment(
    session: &[u8],
    t_id: &str,
    n_id: &str,
    t_nonce: &[u8],
) -> Result<Vec<u8>, CodecError> {
    Ok(snailfish_protocol::enroll::commitment(
        &arr(session, "session")?,
        &decode_id::<32>(t_id, "d_").map_err(err)?,
        &decode_id::<32>(n_id, "d_").map_err(err)?,
        &arr(t_nonce, "t_nonce")?,
    )
    .to_vec())
}

/// The 6-digit code of a transcript (`PROTOCOL.md` 11.2).
///
/// # Errors
///
/// As [`enroll_commitment`].
pub fn enroll_code(
    session: &[u8],
    t_id: &str,
    n_id: &str,
    t_nonce: &[u8],
    n_nonce: &[u8],
) -> Result<String, CodecError> {
    Ok(snailfish_protocol::enroll::code(
        &arr(session, "session")?,
        &decode_id::<32>(t_id, "d_").map_err(err)?,
        &decode_id::<32>(n_id, "d_").map_err(err)?,
        &arr(t_nonce, "t_nonce")?,
        &arr(n_nonce, "n_nonce")?,
    ))
}

/// Check a confirmation envelope for a transcript, as the trusted device
/// does (`PROTOCOL.md` 11.2). `new_device` is the device object JSON of
/// `new.hello`.
///
/// # Errors
///
/// Refuses each confirmation that the trusted device refuses.
pub fn enroll_check_confirm(
    envelope_json: &[u8],
    session: &[u8],
    t_id: &str,
    new_device: &[u8],
    t_nonce: &[u8],
    n_nonce: &[u8],
) -> Result<(), CodecError> {
    let env = envelope::Envelope::parse(envelope_json).map_err(err)?;
    let t = snailfish_protocol::enroll::Transcript {
        session: arr(session, "session")?,
        t_id: decode_id::<32>(t_id, "d_").map_err(err)?,
        new_device: records::parse_device_json(new_device).map_err(err)?,
        t_nonce: arr(t_nonce, "t_nonce")?,
        n_nonce: arr(n_nonce, "n_nonce")?,
    };
    snailfish_protocol::enroll::check_confirm(&env, &t).map_err(err)
}
