//! Snailfish sync engine.
//!
//! A synchronous state machine with no network I/O: it builds each request and
//! reads each response, and the host app sends the bytes (DESIGN.md "Sync
//! engine"). `specs/delivery/model.qnt` is the source of truth for the
//! delivery rules that this crate implements ([DLV-1] to [DLV-14]).
//!
//! The engine state file holds the outbox of signed envelopes and the
//! verified log. It holds no private key and no plaintext. The host app gives
//! the keys at [`Engine::open`] from its key store.

pub mod codec;
pub mod enroll;
pub mod keystore;
pub mod setup;
pub mod signin;
mod state;
mod sync;

use std::fs::{File, TryLockError};
use std::path::Path;

use rusqlite::Connection;
pub use snailfish_protocol as protocol;
use snailfish_protocol::encoding::{Hash32, decode_id, encode_id};
use snailfish_protocol::keys;
use snailfish_protocol::records::Position;
use snailfish_protocol::sig::SecretKey;

pub use sync::Sync;

/// The schema version of the engine state file ([VER-14]).
pub const SCHEMA_VERSION: i64 = 5;

/// The protocol levels that this engine can write ([VER-6]).
pub const MAX_LEVEL: u64 = 1;

/// The most rows of one `enqueue_many` call ([DLV-4]).
pub const MAX_ENQUEUE: usize = 500;

/// The most changes of one `changes_after` batch.
pub const MAX_BATCH: usize = 500;

const STATE_FILE: &str = "engine.sqlite3";
const LOCK_FILE: &str = "engine.lock";

/// An engine failure. The message holds no secret and no app data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// Another engine holds the data directory lock.
    Locked,
    /// The state file has a schema version newer than this engine knows
    /// ([VER-15]). The file is not changed.
    SchemaTooNew {
        /// The version in the file.
        found: i64,
    },
    /// A file system or SQLite failure.
    Storage(String),
    /// The operating system CSPRNG failed.
    Random,
    /// The engine got a response that it did not ask for.
    UnexpectedResponse,
    /// The app gave an input that breaks the API contract, for example more
    /// than [`MAX_ENQUEUE`] rows or keys that do not match the state file.
    Invalid(String),
    /// The applied position of the app is not on the verified log
    /// ([DLV-12]). The app must reset.
    ResetRequired,
    /// The host key store failed or holds no keys for the space. The engine
    /// does not continue without the key store (C62).
    KeyStore(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => f.write_str("another engine uses this data directory"),
            Self::SchemaTooNew { found } => write!(
                f,
                "the engine state file has schema version {found}, and this engine knows {SCHEMA_VERSION}"
            ),
            Self::Storage(e) => write!(f, "engine storage: {e}"),
            Self::Random => f.write_str("the operating system CSPRNG failed"),
            Self::UnexpectedResponse => f.write_str("the engine did not expect a response"),
            Self::Invalid(e) => write!(f, "invalid input: {e}"),
            Self::ResetRequired => {
                f.write_str("reset required: the applied position is not on the verified log")
            }
            Self::KeyStore(e) => write!(f, "key store: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<rusqlite::Error> for EngineError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

/// The sync status that the app shows (DESIGN.md "Sync status").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Sync works.
    Ok,
    /// `degraded`: the relay refused a change for ever ([DLV-9]), or a
    /// validly signed change did not decrypt ([DLV-13]). Sync continues.
    Degraded {
        /// The cause, for example `refused: too_large`.
        cause: String,
    },
    /// `paused: relay unavailable`. The relay gave an HTTP error or an
    /// answer that the engine cannot read. The engine tries again at the
    /// next sync.
    RelayUnavailable,
    /// `paused: relay authority`: the signed authority differs from the
    /// relay configuration.
    RelayAuthority,
    /// `paused: restore hold`: the relay operator restored a backup, and
    /// the relay refuses changes until the user or the operator ends the
    /// hold ([LOG-14]). The engine keeps each change in its outbox.
    RestoreHold,
    /// `paused: quota`: the relay refused a change because the space is at
    /// its quota ([QTA-4]). The engine keeps each change in its outbox and
    /// sends it again at each later sync.
    Quota,
    /// `paused: repair needs another device`: the grant of this device is
    /// only in the range that the relay lost, and the relay head is not the
    /// position before the grant ([LOG-12]). A device that is active in the
    /// relay log must repair it.
    RepairNeedsAnotherDevice,
    /// `stopped: relay too old` ([VER-11]).
    RelayTooOld,
    /// `stopped: clock skew`: the relay refused a request as expired after
    /// a clock correction.
    ClockSkew,
    /// `stopped: fork`: the relay log conflicts with the verified log, or a
    /// fetched record fails the space-state check.
    Fork {
        /// The cause.
        cause: String,
    },
    /// `stopped: setup failed`: the relay refused to create the space
    /// (`bad_setup` or `space_limit`, `PROTOCOL.md` 10.5). The app signs in
    /// again and gives the engine a new setup token.
    SetupFailed {
        /// The error code of the relay.
        cause: String,
    },
}

impl Status {
    /// The status text of DESIGN.md "Sync status", without its cause. The
    /// device status report sends it (`PROTOCOL.md` 10.11).
    #[must_use]
    pub fn text(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded { .. } => "degraded",
            Self::RelayUnavailable => "paused: relay unavailable",
            Self::RelayAuthority => "paused: relay authority",
            Self::RestoreHold => "paused: restore hold",
            Self::Quota => "paused: quota",
            Self::RepairNeedsAnotherDevice => "paused: repair needs another device",
            Self::RelayTooOld => "stopped: relay too old",
            Self::ClockSkew => "stopped: clock skew",
            Self::Fork { .. } => "stopped: fork",
            Self::SetupFailed { .. } => "stopped: setup failed",
        }
    }
}

/// One HTTP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The header name.
    pub name: String,
    /// The header value.
    pub value: String,
}

/// One HTTP request for the host app to send. The app must not follow
/// redirects, because the request signature covers the relay authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The HTTP method.
    pub method: String,
    /// The full URL.
    pub url: String,
    /// The headers, in order.
    pub headers: Vec<Header>,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// The keys of one device in one space. The host app keeps them in its key
/// store and gives them to [`Engine::open`].
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKeys {
    /// The Ed25519 signing seed.
    pub sign_seed: [u8; 32],
    /// The X-Wing seed.
    pub seal_seed: [u8; 32],
    /// The app key of epoch 1. All zero if the app does not know it yet,
    /// for example on a new device: the engine then opens it from the key
    /// set of its grant in the verified log.
    pub app_key: [u8; 32],
}

impl std::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKeys(..)")
    }
}

/// Where the space lives on the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRef {
    /// The relay base URL: `https://` or `http://` and the authority, with no
    /// path, for example `https://sync.example.net`.
    pub relay_url: String,
    /// The tenant handle text (`t_` + 32 hex digits).
    pub tenant: String,
    /// The log ID text.
    pub log_id: String,
    /// The app ID that the genesis record must name.
    pub app_id: String,
}

/// One row of the app outbox for [`Engine::enqueue_many`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// The 16-byte change ID.
    pub change_id: Vec<u8>,
    /// The app change bytes. The engine never reads them.
    pub change_bytes: Vec<u8>,
}

/// The result of [`Engine::enqueue_many`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueResult {
    /// The change IDs that the engine stored now.
    pub stored: Vec<Vec<u8>>,
    /// Change IDs that the app must split or revert ([DLV-5], [DLV-9]): a
    /// known `change_id` with other bytes, or a change that the relay
    /// refused for ever.
    pub refused: Vec<Vec<u8>>,
}

/// A repair of the relay log that this engine made (S6, [LOG-10]): the
/// relay log ended before the verified head, and the engine uploaded the
/// lost entries from `first` to `tip`. The app tells the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repair {
    /// The first position that the engine uploaded.
    pub first: u64,
    /// The verified head of the engine: the last uploaded position.
    pub tip: u64,
}

/// The applied position of the app: the last change that it handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// The log position. 0 before the first change.
    pub position: u64,
    /// The log digest at the position.
    pub digest: [u8; 32],
}

/// One change for the app, in log order ([DLV-10]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The log position.
    pub position: u64,
    /// The log digest at the position.
    pub digest: [u8; 32],
    /// The change ID.
    pub change_id: Vec<u8>,
    /// The decrypted app change bytes.
    pub change_bytes: Vec<u8>,
}

/// The engine for one space on one device.
pub struct Engine {
    db: Connection,
    space: SpaceRef,
    log_id: [u8; 16],
    device_id: Hash32,
    sign: SecretKey,
    seal_seed: [u8; 32],
    // `None` until the engine has the app key: a new device opens it from
    // its grant after the checkpoint check ([ENR-9]).
    app_key: Option<[u8; 32]>,
    // The host key store, if `keystore::open` opened the engine, and
    // whether its item holds the app key.
    key_store: Option<std::sync::Arc<dyn keystore::KeyStore>>,
    app_key_stored: bool,
    status: Status,
    // Seconds to add to the device clock: relay time - device time ([WIR-7]).
    clock_offset: i64,
    // The refusal code of each grant that the relay refused for ever in
    // this process, by device ID, for the enrollment that waits for it.
    grant_refusals: std::collections::BTreeMap<snailfish_protocol::encoding::Hash32, String>,
    clock: fn() -> u64,
    // Held for the life of the engine. The OS releases the lock when the
    // file closes, also after a crash.
    _lock: File,
}

/// Check a relay URL and remove one trailing `/`. The relay routes only
/// `/v1/...` and the signature covers the path as sent, so a URL with a path
/// prefix can never reach it (`PROTOCOL.md` 8.3).
pub(crate) fn relay_base(url: &str) -> Result<String, EngineError> {
    let bad = || {
        EngineError::Invalid("relay URL: use http:// or https:// and the host, with no path".into())
    };
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let auth = rest.strip_suffix('/').unwrap_or(rest);
    if !(scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http"))
        || auth.is_empty()
        || auth.contains(['/', '?', '#', '@'])
    {
        return Err(bad());
    }
    Ok(url.strip_suffix('/').unwrap_or(url).to_owned())
}

pub(crate) fn system_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Engine {
    /// Open the engine state in `data_dir` for one space and one device.
    ///
    /// The engine takes an exclusive lock on the directory, so two engines
    /// never write one state file. It opens the state file with the durable
    /// settings of [DLV-1] and migrates it forward ([VER-14]). The state
    /// file is bound to the log ID and the device ID. A second open with
    /// other values fails.
    ///
    /// # Errors
    ///
    /// [`EngineError::Locked`] if another engine holds the directory,
    /// [`EngineError::SchemaTooNew`] for a file from a newer engine,
    /// [`EngineError::Invalid`] for a relay URL with a path, or a log ID or
    /// keys that do not match the file, and [`EngineError::Storage`].
    pub fn open(data_dir: &Path, space: SpaceRef, keys: &DeviceKeys) -> Result<Self, EngineError> {
        Self::open_with(data_dir, space, keys, None)
    }

    /// [`Engine::open`]. A new state file gets `checkpoint` in the same
    /// transaction that binds it, so no state file of an enrolled device
    /// exists without its checkpoint ([ENR-9]).
    pub(crate) fn open_with(
        data_dir: &Path,
        space: SpaceRef,
        keys: &DeviceKeys,
        checkpoint: Option<&state::PendingCheckpoint>,
    ) -> Result<Self, EngineError> {
        std::fs::create_dir_all(data_dir)?;
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(data_dir.join(LOCK_FILE))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(EngineError::Locked),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let log_id = decode_id::<16>(&space.log_id, "l_")
            .map_err(|e| EngineError::Invalid(format!("log ID: {e}")))?;
        decode_id::<16>(&space.tenant, "t_")
            .map_err(|e| EngineError::Invalid(format!("tenant handle: {e}")))?;
        let sign = SecretKey::from_seed(&keys.sign_seed);
        let device_id = keys::device_id(&sign.public(), &keys::seal_public(&keys.seal_seed));
        let db = Connection::open(data_dir.join(STATE_FILE))?;
        state::open(&db, &log_id, &device_id, checkpoint)?;
        let mut space = space;
        space.relay_url = relay_base(&space.relay_url)?;
        let mut e = Self {
            db,
            space,
            log_id,
            device_id,
            sign,
            seal_seed: keys.seal_seed,
            app_key: (keys.app_key != [0; 32]).then_some(keys.app_key),
            key_store: None,
            app_key_stored: false,
            status: Status::Ok,
            clock_offset: 0,
            grant_refusals: std::collections::BTreeMap::new(),
            clock: system_time,
            _lock: lock,
        };
        if e.app_key.is_none() && state::checkpoint(&e.db)?.is_none() {
            e.app_key = e.open_app_key()?;
        }
        Ok(e)
    }

    /// The app key of epoch 1, if the engine has it. A new device has it
    /// after its sync checks the enrollment checkpoint ([ENR-9]). The app
    /// can keep it in its key store.
    #[must_use]
    pub fn app_key(&self) -> Option<[u8; 32]> {
        self.app_key
    }

    /// Open the app key of epoch 1 from the key set to this device in its
    /// genesis record or grant, and check it against the commitment of the
    /// genesis record (`PROTOCOL.md` 7.3). `None` if the verified log does
    /// not name this device yet.
    fn open_app_key(&self) -> Result<Option<[u8; 32]>, EngineError> {
        use snailfish_protocol::records::{Author, Body};
        let Some((_, json)) = state::activation(&self.db, &self.device_id)? else {
            return Ok(None);
        };
        let bad = |m: &str| EngineError::Storage(format!("own key set: {m}"));
        let env = snailfish_protocol::envelope::Envelope::parse(json.as_bytes())
            .map_err(|e| bad(&e.to_string()))?;
        let r = snailfish_protocol::records::parse_payload(&env.payload_type, &env.payload)
            .map_err(|e| bad(&e.to_string()))?;
        let (Body::Genesis { keys, .. } | Body::Grant { keys, .. }) = &r.body else {
            return Err(bad("not a genesis record or a grant"));
        };
        let set = keys
            .iter()
            .find(|k| k.to == Author::Device(self.device_id))
            .ok_or_else(|| bad("no key set to this device"))?;
        let opened = snailfish_protocol::keys::open_key_set(
            &self.seal_seed,
            &self.log_id,
            &self.device_id,
            &set.epochs,
            &set.sealed,
        )
        .map_err(|e| bad(&e.to_string()))?;
        let key = *set
            .epochs
            .iter()
            .zip(&opened)
            .find(|(e, _)| **e == 1)
            .map(|(_, k)| k)
            .ok_or_else(|| bad("no key of epoch 1"))?;
        let Some((_, genesis)) = state::log_range(&self.db, 1, 1)?.into_iter().next() else {
            return Err(bad("no genesis record"));
        };
        let g = snailfish_protocol::envelope::Envelope::parse(genesis.as_bytes())
            .map_err(|e| bad(&e.to_string()))?;
        let gr = snailfish_protocol::records::parse_payload(&g.payload_type, &g.payload)
            .map_err(|e| bad(&e.to_string()))?;
        let Body::Genesis { commitment, .. } = gr.body else {
            return Err(bad("position 1 is not a genesis record"));
        };
        if snailfish_protocol::keys::key_commitment(&self.log_id, 1, &key) != commitment {
            return Err(bad("the key does not match the commitment of epoch 1"));
        }
        Ok(Some(key))
    }

    /// Replace the device clock, for tests of the clock correction.
    #[doc(hidden)]
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// The device ID text of this engine.
    #[must_use]
    pub fn device_id(&self) -> String {
        encode_id("d_", &self.device_id)
    }

    /// A new change ID: 128 random bits from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`EngineError::Random`].
    pub fn new_change_id(&self) -> Result<[u8; 16], EngineError> {
        keys::random_bytes().map_err(|_| EngineError::Random)
    }

    /// The current sync status.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status.clone()
    }

    /// The applied position before the first change: position 0 with
    /// `digest(0)`.
    #[must_use]
    pub fn genesis_base(&self) -> Applied {
        Applied {
            position: 0,
            digest: snailfish_protocol::hash::digest0(&self.log_id),
        }
    }

    /// Encrypt, sign and store each outbox row in one durable transaction
    /// ([DLV-4], [DLV-5]).
    ///
    /// A row has no effect if the outbox or the verified log holds the
    /// `change_id` with the same bytes. A known `change_id` with other bytes
    /// goes into `refused`. The engine does not check the size limit:
    /// only the relay refuses a change for size (F4). A row that the relay
    /// refused for ever is in `refused` again, so the app sees it after a
    /// restart.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for more than [`MAX_ENQUEUE`] rows or a
    /// change ID that is not 16 bytes, [`EngineError::Random`] and
    /// [`EngineError::Storage`]. On an error the engine stores no row.
    pub fn enqueue_many(&mut self, rows: &[OutboxRow]) -> Result<EnqueueResult, EngineError> {
        if rows.len() > MAX_ENQUEUE {
            return Err(EngineError::Invalid(format!(
                "enqueue_many takes at most {MAX_ENQUEUE} rows"
            )));
        }
        // An app calls this at each startup ([DLV-2]), also on a new device
        // that has no app key yet. With no row there is nothing to encrypt.
        if rows.is_empty() {
            return Ok(EnqueueResult {
                stored: Vec::new(),
                refused: Vec::new(),
            });
        }
        state::enqueue(self, rows)
    }

    /// The changes after the applied position, in log order, at most
    /// `max_changes` ([DLV-10]). Own changes are included. An empty list
    /// means that the app is at the end of the verified log.
    ///
    /// # Errors
    ///
    /// [`EngineError::ResetRequired`] if the verified log holds another
    /// digest at the applied position, or if the applied position is after
    /// the end of a verified log that the engine fetched to the relay head
    /// ([DLV-12]). [`EngineError::Storage`].
    pub fn changes_after(
        &self,
        applied: &Applied,
        max_changes: usize,
    ) -> Result<Vec<Change>, EngineError> {
        state::set_applied(&self.db, applied.position)?;
        state::changes_after(self, applied, max_changes.clamp(1, MAX_BATCH))
    }

    /// Replace the setup token of a space that this device creates
    /// (`PROTOCOL.md` 12.3). The app calls it after a new sign-in, for
    /// example after `stopped: setup failed`.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a text that is not a setup token, and
    /// [`EngineError::Storage`].
    pub fn set_setup_token(&mut self, token: &str) -> Result<(), EngineError> {
        state::set_setup_token(&self.db, token)
    }

    /// Take the repairs that this engine made since the last call, oldest
    /// first (S6). The engine forgets them once it returns them.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn take_repairs(&self) -> Result<Vec<Repair>, EngineError> {
        Ok(state::take_repairs(&self.db)?
            .into_iter()
            .map(|(first, tip)| Repair { first, tip })
            .collect())
    }

    /// The number of envelopes in the engine outbox.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn outbox_len(&self) -> Result<u64, EngineError> {
        state::outbox_len(&self.db)
    }

    /// The last position of the verified log and its digest.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn verified_head(&self) -> Result<Applied, EngineError> {
        let (position, digest) = state::head(&self.db, &self.log_id)?;
        Ok(Applied { position, digest })
    }

    /// Start one exchange with the relay: info, then push, then fetch.
    /// Pass this engine to each call of the returned [`Sync`].
    #[must_use]
    pub fn start_sync(&self) -> Sync {
        Sync::new()
    }

    /// The device time with the relay offset ([WIR-7]).
    fn now(&self) -> u64 {
        let t = (self.clock)();
        t.checked_add_signed(self.clock_offset).unwrap_or(t)
    }

    fn base(&self) -> Result<Position, EngineError> {
        let (position, digest) = state::head(&self.db, &self.log_id)?;
        Ok(Position { position, digest })
    }
}

/// Create or migrate the schema. Refuse a file from a newer engine before
/// any write ([VER-15]).
fn refuse_newer(db: &Connection) -> Result<i64, EngineError> {
    let found: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(EngineError::SchemaTooNew { found });
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
