//! UniFFI bindings for the Snailfish sync engine (Swift and Python).
//!
//! This crate holds no protocol logic: each function converts types and
//! forwards to `snailfish-engine`. The Python package is `snailfish` and the
//! Swift module is `Snailfish` (DESIGN.md "Code layout").

use std::path::PathBuf;
use std::sync::Mutex;

use snailfish_engine::codec;
pub use snailfish_engine::codec::{EnrollPayload, Envelope, KeySetInfo, PayloadClass, PayloadInfo};
pub use snailfish_engine::enroll::EnrollState;
pub use snailfish_engine::{EnqueueResult, Header, OutboxRow, Repair, Request, SpaceRef, Status};

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
    /// The applied position is not on the verified log ([DLV-12]). The app
    /// deletes its synced data and applies its outbox rows again.
    ResetRequired,
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
            Self::ResetRequired => f.write_str("reset required"),
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
            snailfish_engine::EngineError::ResetRequired => Self::ResetRequired,
            snailfish_engine::EngineError::Invalid(message) => Self::Invalid { message },
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
    Degraded { cause: String },
    RelayUnavailable,
    RelayAuthority,
    RestoreHold,
    RepairNeedsAnotherDevice,
    RelayTooOld,
    ClockSkew,
    Fork { cause: String },
}

/// A QR payload of an enrollment (`PROTOCOL.md` 11.1).
#[uniffi::remote(Record)]
pub struct EnrollPayload {
    pub role: String,
    pub relay_url: String,
    pub session: Vec<u8>,
}

/// The state of an enrollment (DESIGN.md "Enrollment").
#[uniffi::remote(Enum)]
pub enum EnrollState {
    Waiting,
    Compare { code: String },
    ConfirmAgain,
    Busy,
    Done,
    Failed { cause: String },
}

/// A repair of the relay log that the engine made (S6).
#[uniffi::remote(Record)]
pub struct Repair {
    pub first: u64,
    pub tip: u64,
}

/// Where the space lives on the relay.
#[uniffi::remote(Record)]
pub struct SpaceRef {
    pub relay_url: String,
    pub tenant: String,
    pub log_id: String,
    pub app_id: String,
}

/// One row of the app outbox.
#[uniffi::remote(Record)]
pub struct OutboxRow {
    pub change_id: Vec<u8>,
    pub change_bytes: Vec<u8>,
}

/// The result of `enqueue_many`.
#[uniffi::remote(Record)]
pub struct EnqueueResult {
    pub stored: Vec<Vec<u8>>,
    pub refused: Vec<Vec<u8>>,
}

/// The keys of one device in one space: 32 bytes each.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceKeys {
    /// The Ed25519 signing seed.
    pub sign_seed: Vec<u8>,
    /// The X-Wing seed.
    pub seal_seed: Vec<u8>,
    /// The app key of epoch 1.
    pub app_key: Vec<u8>,
}

fn bytes32(b: &[u8], what: &str) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| SnailfishError::Invalid {
        message: format!("{what} must be 32 bytes"),
    })
}

impl DeviceKeys {
    fn to_engine(&self) -> Result<snailfish_engine::DeviceKeys> {
        Ok(snailfish_engine::DeviceKeys {
            sign_seed: bytes32(&self.sign_seed, "sign_seed")?,
            seal_seed: bytes32(&self.seal_seed, "seal_seed")?,
            app_key: bytes32(&self.app_key, "app_key")?,
        })
    }

    fn from_engine(k: &snailfish_engine::DeviceKeys) -> Self {
        Self {
            sign_seed: k.sign_seed.to_vec(),
            seal_seed: k.seal_seed.to_vec(),
            app_key: k.app_key.to_vec(),
        }
    }
}

/// The applied position of the app.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Applied {
    /// The log position. 0 before the first change.
    pub position: u64,
    /// The 32-byte log digest at the position.
    pub digest: Vec<u8>,
}

impl Applied {
    fn to_engine(&self) -> Result<snailfish_engine::Applied> {
        Ok(snailfish_engine::Applied {
            position: self.position,
            digest: bytes32(&self.digest, "digest")?,
        })
    }

    fn from_engine(a: &snailfish_engine::Applied) -> Self {
        Self {
            position: a.position,
            digest: a.digest.to_vec(),
        }
    }
}

/// One change for the app, in log order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Change {
    /// The log position.
    pub position: u64,
    /// The 32-byte log digest at the position.
    pub digest: Vec<u8>,
    /// The change ID.
    pub change_id: Vec<u8>,
    /// The app change bytes.
    pub change_bytes: Vec<u8>,
}

/// A new space with its first device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SpaceSetup {
    /// The log ID text.
    pub log_id: String,
    /// The recovery key in its display form.
    pub recovery_key: String,
    /// The 32-byte app key of epoch 1.
    pub app_key: Vec<u8>,
    /// The genesis envelope.
    pub envelopes: Vec<String>,
}

/// A device for [`create_space`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct NewDevice {
    /// The keys. The app key is ignored.
    pub keys: DeviceKeys,
    /// The device name.
    pub name: String,
}

/// The engine form of a [`NewDevice`]. Setup makes the app key, so the app
/// key of the input is not read and can have any length.
fn new_device(d: &NewDevice) -> Result<snailfish_engine::setup::NewDevice> {
    let keys = snailfish_engine::DeviceKeys {
        sign_seed: bytes32(&d.keys.sign_seed, "sign_seed")?,
        seal_seed: bytes32(&d.keys.seal_seed, "seal_seed")?,
        app_key: [0; 32],
    };
    Ok(snailfish_engine::setup::NewDevice {
        keys,
        name: d.name.clone(),
    })
}

/// New device keys from the CSPRNG, with an all-zero app key.
///
/// # Errors
///
/// [`SnailfishError::Engine`].
#[uniffi::export]
pub fn new_device_keys() -> Result<DeviceKeys> {
    Ok(DeviceKeys::from_engine(
        &snailfish_engine::setup::new_device_keys()?,
    ))
}

/// Make a new space: the genesis record with the first device. Each other
/// device joins through enrollment.
///
/// # Errors
///
/// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
#[uniffi::export]
pub fn create_space(app_id: &str, first: &NewDevice) -> Result<SpaceSetup> {
    let s = snailfish_engine::setup::create_space(app_id, &new_device(first)?)?;
    Ok(SpaceSetup {
        log_id: s.log_id,
        recovery_key: s.recovery_key,
        app_key: s.app_key.to_vec(),
        envelopes: s.envelopes,
    })
}

/// Give the setup records to the engine of the first device.
///
/// # Errors
///
/// As [`Engine::open`].
#[uniffi::export]
pub fn install_setup(
    data_dir: &str,
    space: SpaceRef,
    keys: &DeviceKeys,
    envelopes: &[String],
) -> Result<()> {
    Ok(snailfish_engine::setup::install_setup(
        &PathBuf::from(data_dir),
        space,
        &keys.to_engine()?,
        envelopes,
    )?)
}

/// The result of an enrollment on the new device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Joined {
    /// The tenant handle.
    pub tenant: String,
    /// The log ID text.
    pub log_id: String,
    /// The checkpoint position.
    pub position: u64,
    /// The 32-byte checkpoint digest.
    pub digest: Vec<u8>,
    /// The device ID of the trusted device.
    pub trusted: String,
    /// The device object of the new device, as JSON.
    pub device: String,
}

impl Joined {
    fn to_engine(&self) -> Result<snailfish_engine::enroll::Joined> {
        Ok(snailfish_engine::enroll::Joined {
            tenant: self.tenant.clone(),
            log_id: self.log_id.clone(),
            position: self.position,
            digest: bytes32(&self.digest, "digest")?,
            trusted: self.trusted.clone(),
            device: self.device.clone(),
        })
    }

    fn from_engine(j: &snailfish_engine::enroll::Joined) -> Self {
        Self {
            tenant: j.tenant.clone(),
            log_id: j.log_id.clone(),
            position: j.position,
            digest: j.digest.to_vec(),
            trusted: j.trusted.clone(),
            device: j.device.clone(),
        }
    }
}

/// Create the engine state of a new device after its enrollment. Its
/// syncs upload nothing until the log passes the checkpoint check
/// ([ENR-9]).
///
/// # Errors
///
/// As [`Engine::open`], and [`SnailfishError::Invalid`] if the space does
/// not match `joined`.
#[uniffi::export]
pub fn install_enrollment(
    data_dir: &str,
    space: SpaceRef,
    keys: &DeviceKeys,
    joined: &Joined,
) -> Result<()> {
    Ok(snailfish_engine::setup::install_enrollment(
        &PathBuf::from(data_dir),
        space,
        &keys.to_engine()?,
        &joined.to_engine()?,
    )?)
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

/// The typed code of a session ID (`PROTOCOL.md` 11.1).
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn enroll_display(session: &[u8]) -> Result<String> {
    Ok(codec::enroll_display(session)?)
}

/// Read a typed code (`PROTOCOL.md` 11.1).
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn enroll_parse_code(text: &str) -> Result<Vec<u8>> {
    Ok(codec::enroll_parse_code(text)?)
}

/// Read a QR payload (`PROTOCOL.md` 11.1).
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn enroll_parse_payload(text: &str) -> Result<EnrollPayload> {
    Ok(codec::enroll_parse_payload(text)?)
}

/// The commitment of the trusted device (`PROTOCOL.md` 11.2).
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn enroll_commitment(
    session: &[u8],
    t_id: &str,
    n_id: &str,
    t_nonce: &[u8],
) -> Result<Vec<u8>> {
    Ok(codec::enroll_commitment(session, t_id, n_id, t_nonce)?)
}

/// The 6-digit code of a transcript (`PROTOCOL.md` 11.2).
///
/// # Errors
///
/// [`SnailfishError::Invalid`].
#[uniffi::export]
pub fn enroll_code(
    session: &[u8],
    t_id: &str,
    n_id: &str,
    t_nonce: &[u8],
    n_nonce: &[u8],
) -> Result<String> {
    Ok(codec::enroll_code(session, t_id, n_id, t_nonce, n_nonce)?)
}

/// Check a confirmation for a transcript, as the trusted device does
/// (`PROTOCOL.md` 11.2).
///
/// # Errors
///
/// [`SnailfishError::Invalid`] for a confirmation that the trusted device
/// refuses.
#[uniffi::export]
pub fn enroll_check_confirm(
    envelope_json: &[u8],
    session: &[u8],
    t_id: &str,
    new_device: &[u8],
    t_nonce: &[u8],
    n_nonce: &[u8],
) -> Result<()> {
    Ok(codec::enroll_check_confirm(
        envelope_json,
        session,
        t_id,
        new_device,
        t_nonce,
        n_nonce,
    )?)
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
    pub fn open(data_dir: &str, space: SpaceRef, keys: &DeviceKeys) -> Result<Self> {
        let inner =
            snailfish_engine::Engine::open(&PathBuf::from(data_dir), space, &keys.to_engine()?)?;
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

    /// The device ID text.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn device_id(&self) -> Result<String> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.device_id())
    }

    /// The applied position before the first change.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn genesis_base(&self) -> Result<Applied> {
        Ok(Applied::from_engine(
            &self.inner.lock().map_err(|_| poisoned())?.genesis_base(),
        ))
    }

    /// Encrypt, sign and store outbox rows in one durable transaction.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
    pub fn enqueue_many(&self, rows: &[OutboxRow]) -> Result<EnqueueResult> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .enqueue_many(rows)?)
    }

    /// The changes after the applied position, in log order.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::ResetRequired`] or [`SnailfishError::Engine`].
    pub fn changes_after(&self, applied: &Applied, max_changes: u32) -> Result<Vec<Change>> {
        let max = usize::try_from(max_changes).unwrap_or(usize::MAX);
        let out = self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .changes_after(&applied.to_engine()?, max)?;
        Ok(out
            .into_iter()
            .map(|c| Change {
                position: c.position,
                digest: c.digest.to_vec(),
                change_id: c.change_id,
                change_bytes: c.change_bytes,
            })
            .collect())
    }

    /// Take the repairs of the relay log that this engine made since the
    /// last call (S6). The app tells the user.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn take_repairs(&self) -> Result<Vec<Repair>> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.take_repairs()?)
    }

    /// The number of envelopes in the engine outbox.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn outbox_len(&self) -> Result<u64> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.outbox_len()?)
    }

    /// The last verified position and its digest.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn verified_head(&self) -> Result<Applied> {
        Ok(Applied::from_engine(
            &self.inner.lock().map_err(|_| poisoned())?.verified_head()?,
        ))
    }

    /// The app key of epoch 1, if the engine has it. A new device has it
    /// after its sync checks the enrollment checkpoint.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn app_key(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .app_key()
            .map(|k| k.to_vec()))
    }

    /// The grants that wait for the user to confirm them again ([LOG-7]).
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn grants_to_confirm(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .grants_to_confirm()?)
    }

    /// Confirm again a grant that waits ([LOG-7]). A grant by the recovery
    /// key needs the recovery key.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
    pub fn confirm_grant(&self, device_id: &str, recovery_key: Option<String>) -> Result<()> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .confirm_grant(device_id, recovery_key)?)
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
        let mut engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .next_request(&mut engine)?)
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

/// The enrollment on a trusted device (DESIGN.md "Enrollment").
#[derive(uniffi::Object)]
pub struct TrustedEnrollment {
    engine: std::sync::Arc<Engine>,
    inner: Mutex<snailfish_engine::enroll::TrustedEnrollment>,
}

#[uniffi::export]
impl TrustedEnrollment {
    /// Start an enrollment. `scanned` is the payload or the typed code of
    /// the new device, or `None` if this device shows the session. A
    /// recovery key, if given, signs the grant.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
    #[uniffi::constructor]
    pub fn new(
        engine: std::sync::Arc<Engine>,
        scanned: Option<String>,
        recovery_key: Option<String>,
    ) -> Result<Self> {
        let inner = {
            let e = engine.inner.lock().map_err(|_| poisoned())?;
            snailfish_engine::enroll::TrustedEnrollment::new(&e, scanned, recovery_key)?
        };
        Ok(Self {
            engine,
            inner: Mutex::new(inner),
        })
    }

    /// The QR payload to show, if this device shows the session, after the
    /// relay opened it.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn payload(&self) -> Result<Option<String>> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.payload())
    }

    /// The typed code of the session, after the relay opened it if this
    /// device shows it.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn code(&self) -> Result<Option<String>> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.code())
    }

    /// The current state.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn state(&self) -> Result<EnrollState> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.state())
    }

    /// The answer of the user to a comparison or a new confirmation.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
    pub fn confirm(&self, yes: bool) -> Result<()> {
        let mut engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        let mut t = self.inner.lock().map_err(|_| poisoned())?;
        Ok(t.confirm(&mut engine, yes)?)
    }

    /// The next request, or `None`.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn next_request(&self) -> Result<Option<Request>> {
        let mut engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        let mut t = self.inner.lock().map_err(|_| poisoned())?;
        Ok(t.next_request(&mut engine)?)
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn handle_response(&self, status: u16, headers: &[Header], body: &[u8]) -> Result<()> {
        // Lock order: the engine, then the enrollment, as in `Sync`.
        let mut engine = self.engine.inner.lock().map_err(|_| poisoned())?;
        let mut t = self.inner.lock().map_err(|_| poisoned())?;
        Ok(t.handle_response(&mut engine, status, headers, body)?)
    }
}

/// The enrollment on a new device (DESIGN.md "Enrollment").
#[derive(uniffi::Object)]
pub struct NewEnrollment {
    inner: Mutex<snailfish_engine::enroll::NewEnrollment>,
}

#[uniffi::export]
impl NewEnrollment {
    /// Start an enrollment with the device keys and name. `scanned` is the
    /// payload or the typed code of the trusted device, or `None` if this
    /// device shows the session.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
    #[uniffi::constructor]
    pub fn new(
        relay_url: &str,
        keys: &DeviceKeys,
        name: &str,
        scanned: Option<String>,
    ) -> Result<Self> {
        let inner = snailfish_engine::enroll::NewEnrollment::new(
            relay_url,
            &keys.to_engine()?,
            name,
            scanned,
        )?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// The QR payload to show, if this device shows the session.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn payload(&self) -> Result<Option<String>> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.payload())
    }

    /// The typed code of the session.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn code(&self) -> Result<String> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.code())
    }

    /// The relay URL of the session.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn relay_url(&self) -> Result<String> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.relay_url())
    }

    /// The current state.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn state(&self) -> Result<EnrollState> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.state())
    }

    /// The result, after `Done`.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn joined(&self) -> Result<Option<Joined>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .joined()
            .as_ref()
            .map(Joined::from_engine))
    }

    /// The answer of the user to the comparison.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Invalid`] or [`SnailfishError::Engine`].
    pub fn confirm(&self, yes: bool) -> Result<()> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.confirm(yes)?)
    }

    /// The next request, or `None`.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn next_request(&self) -> Result<Option<Request>> {
        Ok(self.inner.lock().map_err(|_| poisoned())?.next_request())
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`SnailfishError::Engine`].
    pub fn handle_response(&self, status: u16, body: &[u8]) -> Result<()> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| poisoned())?
            .handle_response(status, body)?)
    }
}
