//! UniFFI bindings for the Snailfish sync engine (Swift and Python).
//!
//! This crate holds no protocol logic: each function converts types and
//! forwards to `snailfish-engine`. The Python package is `snailfish` and the
//! Swift module is `Snailfish` (DESIGN.md "Code layout").

use std::path::PathBuf;
use std::sync::Mutex;

use snailfish_engine::codec;

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

/// See [`codec::Envelope`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct Envelope {
    /// The payload type.
    pub payload_type: String,
    /// The exact payload bytes.
    pub payload: Vec<u8>,
    /// The 64-byte signature.
    pub sig: Vec<u8>,
}

/// See [`codec::PayloadInfo`].
#[derive(Debug, Clone, uniffi::Record)]
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
    /// True for a security record.
    pub is_security: bool,
}

/// See [`codec::KeySetInfo`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeySetInfo {
    /// The recipient ID text.
    pub to: String,
    /// The epochs.
    pub epochs: Vec<u64>,
    /// `enc || ciphertext`.
    pub sealed: Vec<u8>,
}

/// See [`codec::PayloadClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
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

/// The sync status (DESIGN.md "Sync status").
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncStatus {
    /// Sync works.
    Ok,
    /// `stopped: relay too old`.
    RelayTooOld,
}

/// One HTTP request for the host app to send.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HttpRequest {
    /// The HTTP method.
    pub method: String,
    /// The full URL.
    pub url: String,
    /// The headers, in order, as name and value pairs.
    pub headers: Vec<Header>,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// One HTTP header.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Header {
    /// The header name.
    pub name: String,
    /// The header value.
    pub value: String,
}

fn envelope_in(e: &Envelope) -> codec::Envelope {
    codec::Envelope {
        payload_type: e.payload_type.clone(),
        payload: e.payload.clone(),
        sig: e.sig.clone(),
    }
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
    let e = codec::parse_envelope(text)?;
    Ok(Envelope {
        payload_type: e.payload_type,
        payload: e.payload,
        sig: e.sig,
    })
}

/// The writer form of an envelope.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn envelope_to_json(envelope: &Envelope, keyid: &str) -> Result<String> {
    Ok(codec::envelope_to_json(&envelope_in(envelope), keyid)?)
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
    match codec::classify(payload_type) {
        codec::PayloadClass::Record => PayloadClass::Record,
        codec::PayloadClass::Statement => PayloadClass::Statement,
        codec::PayloadClass::UnknownContent => PayloadClass::UnknownContent,
        codec::PayloadClass::UpdateRequired => PayloadClass::UpdateRequired,
    }
}

/// Parse a log record payload and return its routing fields.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn check_payload(payload_type: &str, payload: &[u8]) -> Result<PayloadInfo> {
    let i = codec::check_payload(payload_type, payload)?;
    Ok(PayloadInfo {
        log: i.log,
        author: i.author,
        base_position: i.base_position,
        base_digest: i.base_digest,
        change_id: i.change_id,
        is_security: i.is_security,
    })
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

/// The key sets of a security record payload.
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn key_sets(payload_type: &str, payload: &[u8]) -> Result<Vec<KeySetInfo>> {
    Ok(codec::key_sets(payload_type, payload)?
        .into_iter()
        .map(|k| KeySetInfo {
            to: k.to,
            epochs: k.epochs,
            sealed: k.sealed,
        })
        .collect())
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
    pub fn status(&self) -> Result<SyncStatus> {
        Ok(match self.inner.lock().map_err(|_| poisoned())?.status() {
            snailfish_engine::Status::Ok => SyncStatus::Ok,
            snailfish_engine::Status::RelayTooOld => SyncStatus::RelayTooOld,
        })
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
    pub fn next_request(&self) -> Result<Option<HttpRequest>> {
        let engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        let req = self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .next_request(&engine);
        Ok(req.map(|r| HttpRequest {
            method: r.method,
            url: r.url,
            headers: r
                .headers
                .into_iter()
                .map(|(name, value)| Header { name, value })
                .collect(),
            body: r.body,
        }))
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn handle_response(&self, status: u16, headers: Vec<Header>, body: &[u8]) -> Result<()> {
        let mut engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        let headers: Vec<(String, String)> =
            headers.into_iter().map(|h| (h.name, h.value)).collect();
        self.inner.lock().map_err(|_| poisoned())?.handle_response(
            &mut engine,
            status,
            &headers,
            body,
        )?;
        Ok(())
    }
}
