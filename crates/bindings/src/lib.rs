//! UniFFI bindings for the Snailfish sync engine (Swift and Python).
//!
//! This crate holds no protocol logic: each function converts types and
//! forwards to `snailfish-engine`. The Python package is `snailfish` and the
//! Swift module is `Snailfish` (DESIGN.md "Code layout").

use std::path::PathBuf;
use std::sync::Mutex;

use snailfish_engine::codec;
pub use snailfish_engine::codec::{Envelope, KeySetInfo, PayloadClass, PayloadInfo};
pub use snailfish_engine::{Header, Request, Status};

uniffi::setup_scaffolding!("snailfish");

/// An error from the engine. The message names the rule or the cause and
/// holds no secret.
#[derive(Debug, uniffi::Error)]
pub enum SnailfishError {
    /// A refused input or a failed check.
    Invalid {
        /// The cause.
        message: String,
    },
    /// Another engine holds the data directory.
    Locked,
    /// A storage or system failure.
    Engine {
        /// The cause.
        message: String,
    },
}

impl std::fmt::Display for SnailfishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid { message } | Self::Engine { message } => f.write_str(message),
            Self::Locked => f.write_str("another engine uses this data directory"),
        }
    }
}

impl std::error::Error for SnailfishError {}

impl From<codec::CodecError> for SnailfishError {
    fn from(e: codec::CodecError) -> Self {
        Self::Invalid { message: e.0 }
    }
}

impl From<snailfish_engine::EngineError> for SnailfishError {
    fn from(e: snailfish_engine::EngineError) -> Self {
        match e {
            snailfish_engine::EngineError::Locked => Self::Locked,
            other => Self::Engine {
                message: other.to_string(),
            },
        }
    }
}

type Result<T> = std::result::Result<T, SnailfishError>;

// The engine owns these types. `uniffi::remote` mirrors each definition for
// the FFI only, and the compiler refuses a mirror that differs from the
// engine type, so a new field or variant cannot be dropped here.

/// One envelope after the reader of `PROTOCOL.md` section 4.
#[uniffi::remote(Record)]
pub struct Envelope {
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub sig: Vec<u8>,
}

/// The routing fields and key sets of a parsed log record payload.
#[uniffi::remote(Record)]
pub struct PayloadInfo {
    pub log: String,
    pub author: String,
    pub base_position: u64,
    pub base_digest: Vec<u8>,
    pub change_id: Option<Vec<u8>>,
    pub is_security: bool,
    pub key_sets: Vec<KeySetInfo>,
}

/// One key set of a security record.
#[uniffi::remote(Record)]
pub struct KeySetInfo {
    pub to: String,
    pub epochs: Vec<u64>,
    pub sealed: Vec<u8>,
}

/// The class of a payload type (`PROTOCOL.md` 6.4).
#[uniffi::remote(Enum)]
pub enum PayloadClass {
    Record,
    Statement,
    UnknownContent,
    UpdateRequired,
}

/// The sync status (DESIGN.md "Sync status").
#[uniffi::remote(Enum)]
pub enum Status {
    Ok,
    RelayUnavailable,
    RelayTooOld,
}

/// One HTTP request for the host app to send. The app must not follow
/// redirects.
#[uniffi::remote(Record)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// One HTTP header.
#[uniffi::remote(Record)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// The frame of `PROTOCOL.md` 2.1.
#[uniffi::export]
#[must_use]
pub fn frame(parts: &[Vec<u8>]) -> Vec<u8> {
    codec::frame(parts)
}

/// The Ed25519 public key of a 32-byte seed.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn sign_public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(codec::sign_public_key(seed)?)
}

/// The X-Wing public key of a 32-byte seed.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn seal_public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(codec::seal_public_key(seed)?)
}

/// The device ID text of two public keys.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn device_id(sign_pk: &[u8], seal_pk: &[u8]) -> Result<String> {
    Ok(codec::device_id(sign_pk, seal_pk)?)
}

/// The recovery ID text of two public keys.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn recovery_id(sign_pk: &[u8], seal_pk: &[u8]) -> Result<String> {
    Ok(codec::recovery_id(sign_pk, seal_pk)?)
}

/// Parse an envelope.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn parse_envelope(text: &[u8]) -> Result<Envelope> {
    Ok(codec::parse_envelope(text)?)
}

/// The writer form of an envelope.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn envelope_to_json(envelope: &Envelope, keyid: &str) -> Result<String> {
    Ok(codec::envelope_to_json(envelope, keyid)?)
}

/// The record hash.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn record_hash(payload_type: &str, payload: &[u8], sig: &[u8]) -> Result<Vec<u8>> {
    Ok(codec::record_hash(payload_type, payload, sig)?)
}

/// The entry hash.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn entry_hash(
    payload_type: &str,
    change_id: &Option<Vec<u8>>,
    record_hash: &[u8],
) -> Result<Vec<u8>> {
    Ok(codec::entry_hash(
        payload_type,
        change_id.as_deref(),
        record_hash,
    )?)
}

/// The log digest at position 0.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn digest0(log_id: &str) -> Result<Vec<u8>> {
    Ok(codec::digest0(log_id)?)
}

/// The log digest at position `n`.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn digest_next(prev: &[u8], n: u64, entry_hash: &[u8]) -> Result<Vec<u8>> {
    Ok(codec::digest_next(prev, n, entry_hash)?)
}

/// Verify an Ed25519 signature over raw bytes with `verify_strict`.
#[uniffi::export]
#[must_use]
pub fn ed25519_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    codec::ed25519_verify(public_key, msg, signature)
}

/// Verify a record signature over the DSSE PAE.
#[uniffi::export]
#[must_use]
pub fn verify_record(
    public_key: &[u8],
    payload_type: &str,
    payload: &[u8],
    signature: &[u8],
) -> bool {
    codec::verify_record(public_key, payload_type, payload, signature)
}

/// Classify a payload type.
#[uniffi::export]
#[must_use]
pub fn classify(payload_type: &str) -> PayloadClass {
    codec::classify(payload_type)
}

/// Parse a log record payload and return its routing fields and key sets.
/// The result does not show that the record is valid in the log.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn check_payload(payload_type: &str, payload: &[u8]) -> Result<PayloadInfo> {
    Ok(codec::check_payload(payload_type, payload)?)
}

/// Parse a statement payload.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn check_statement(payload_type: &str, payload: &[u8]) -> Result<()> {
    Ok(codec::check_statement(payload_type, payload)?)
}

/// The key commitment of the app key of one epoch.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn key_commitment(log_id: &str, epoch: u64, key: &[u8]) -> Result<Vec<u8>> {
    Ok(codec::key_commitment(log_id, epoch, key)?)
}

/// Open a key set.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn open_key_set(
    seal_seed: &[u8],
    log_id: &str,
    to: &str,
    epochs: &[u64],
    sealed: &[u8],
) -> Result<Vec<Vec<u8>>> {
    Ok(codec::open_key_set(seal_seed, log_id, to, epochs, sealed)?)
}

/// Decrypt a change or snapshot payload with the app key of its epoch.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn decrypt_payload(app_key: &[u8], payload_type: &str, payload: &[u8]) -> Result<Vec<u8>> {
    Ok(codec::decrypt_payload(app_key, payload_type, payload)?)
}

/// Read a recovery key that the user typed.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn recovery_parse(text: &str) -> Result<Vec<u8>> {
    Ok(codec::recovery_parse(text)?)
}

/// The display form of a recovery secret.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn recovery_display(secret: &[u8]) -> Result<String> {
    Ok(codec::recovery_display(secret)?)
}

/// The Ed25519 seed and the X-Wing seed of a recovery secret.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn recovery_derive(secret: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(codec::recovery_derive(secret)?)
}

/// The sync engine for one space on one device.
#[derive(uniffi::Object)]
pub struct Engine {
    inner: Mutex<snailfish_engine::Engine>,
}

/// One exchange with the relay.
#[derive(uniffi::Object)]
pub struct Sync {
    engine: std::sync::Arc<Engine>,
    inner: Mutex<snailfish_engine::Sync>,
}

fn poisoned() -> SnailfishError {
    SnailfishError::Engine {
        message: "an earlier call panicked".into(),
    }
}

#[uniffi::export]
impl Engine {
    /// Open the engine state in `data_dir`. One engine per directory.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Locked`] or [`SnailfishError::Engine`].
    #[uniffi::constructor]
    pub fn open(data_dir: &str, relay_url: &str, app_id: &str) -> Result<Self> {
        let inner = snailfish_engine::Engine::open(&PathBuf::from(data_dir), relay_url, app_id)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// A new change ID: 128 random bits.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn new_change_id(&self) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .new_change_id()?
            .to_vec())
    }

    /// The current sync status.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn status(&self) -> Result<Status> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.status())
    }

    /// Start one exchange with the relay.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn start_sync(self: std::sync::Arc<Self>) -> Result<std::sync::Arc<Sync>> {
        let s = self.inner.lock().map_err(|_| poisoned())?.start_sync();
        Ok(std::sync::Arc::new(Sync {
            engine: self,
            inner: Mutex::new(s),
        }))
    }
}

#[uniffi::export]
impl Sync {
    /// The next request, or `None` at the end of the exchange.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn next_request(&self) -> Result<Option<Request>> {
        let engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .next_request(&engine))
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn handle_response(&self, status: u16, headers: &[Header], body: &[u8]) -> Result<()> {
        // Lock order: the engine, then the exchange. `next_request` uses the
        // same order, so two threads cannot deadlock.
        let mut engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        let mut sync = self.inner.lock().map_err(|_| poisoned())?;
        Ok(sync.handle_response(&mut engine, status, headers, body)?)
    }
}
