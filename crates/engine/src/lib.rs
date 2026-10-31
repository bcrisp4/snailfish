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
pub mod setup;
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
pub const SCHEMA_VERSION: i64 = 2;

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
    /// The app key of epoch 1.
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
    app_key: [u8; 32],
    status: Status,
    // Seconds to add to the device clock: relay time - device time ([WIR-7]).
    clock_offset: i64,
    clock: fn() -> u64,
    // Held for the life of the engine. The OS releases the lock when the
    // file closes, also after a crash.
    _lock: File,
}

/// Check a relay URL and remove one trailing `/`. The relay routes only
/// `/v1/...` and the signature covers the path as sent, so a URL with a path
/// prefix can never reach it (`PROTOCOL.md` 8.3).
fn relay_base(url: &str) -> Result<String, EngineError> {
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

fn system_time() -> u64 {
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
        state::open(&db, &log_id, &device_id)?;
        let mut space = space;
        space.relay_url = relay_base(&space.relay_url)?;
        Ok(Self {
            db,
            space,
            log_id,
            device_id,
            sign,
            app_key: keys.app_key,
            status: Status::Ok,
            clock_offset: 0,
            clock: system_time,
            _lock: lock,
        })
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
        state::changes_after(self, applied, max_changes.clamp(1, MAX_BATCH))
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
