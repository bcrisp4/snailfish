//! Snailfish sync engine.
//!
//! A synchronous state machine with no network I/O: it builds each request and
//! reads each response, and the host app sends the bytes (DESIGN.md "Sync
//! engine"). `specs/delivery/model.qnt` is the source of truth for the
//! delivery rules that this crate implements.
//!
//! M1 holds a skeleton: the state file, the data directory lock, change IDs
//! and one request (`GET /v1/info`). M2 adds the outbox, push and pull.

pub mod codec;

use std::fs::{File, TryLockError};
use std::path::Path;

use rusqlite::Connection;
pub use snailfish_protocol as protocol;

/// The schema version of the engine state file ([VER-14]).
pub const SCHEMA_VERSION: i64 = 1;

/// The protocol levels that this engine can write ([VER-6]).
pub const MAX_LEVEL: u64 = 1;

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
    /// The relay is older than this engine needs ([VER-11]).
    RelayTooOld,
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
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// The engine for one space on one device.
pub struct Engine {
    db: Connection,
    relay_url: String,
    status: Status,
    // Held for the life of the engine. The OS releases the lock when the
    // file closes, also after a crash.
    _lock: File,
}

impl Engine {
    /// Open the engine state in `data_dir`. M2 binds the state file to
    /// `_app_id`.
    ///
    /// The engine takes an exclusive lock on the directory, so two engines
    /// never write one state file. It opens the state file with the durable
    /// settings of [DLV-1] and migrates it forward ([VER-14]).
    ///
    /// # Errors
    ///
    /// [`EngineError::Locked`] if another engine holds the directory,
    /// [`EngineError::SchemaTooNew`] for a file from a newer engine, and
    /// [`EngineError::Storage`] for a file system or SQLite failure.
    pub fn open(data_dir: &Path, relay_url: &str, _app_id: &str) -> Result<Self, EngineError> {
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
        let db = Connection::open(data_dir.join(STATE_FILE))?;
        // [DLV-1]: WAL with synchronous=FULL, and fullfsync on Apple
        // platforms, so that a commit survives a power loss.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        if cfg!(target_vendor = "apple") {
            db.pragma_update(None, "fullfsync", "ON")?;
            db.pragma_update(None, "checkpoint_fullfsync", "ON")?;
        }
        migrate(&db)?;
        Ok(Self {
            db,
            relay_url: relay_url.trim_end_matches('/').to_owned(),
            status: Status::Ok,
            _lock: lock,
        })
    }

    /// A new change ID: 128 random bits from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`EngineError::Random`].
    pub fn new_change_id(&self) -> Result<[u8; 16], EngineError> {
        protocol::keys::random_bytes().map_err(|_| EngineError::Random)
    }

    /// The current sync status.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status.clone()
    }

    /// Start one exchange with the relay. Pass this engine to each call of
    /// the returned [`Sync`].
    #[must_use]
    pub fn start_sync(&self) -> Sync {
        Sync { step: Step::Info }
    }
}

/// Create or migrate the schema. Refuse a file from a newer engine before
/// any write ([VER-15]).
fn migrate(db: &Connection) -> Result<(), EngineError> {
    let found: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(EngineError::SchemaTooNew { found });
    }
    if found < 1 {
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE relay_info (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL);
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
    }
    Ok(())
}

#[derive(Debug)]
enum Step {
    Info,
    AwaitInfo,
    Done,
}

/// One exchange with the relay. The app calls [`Sync::next_request`], sends
/// the request, and passes the response to [`Sync::handle_response`].
#[derive(Debug)]
pub struct Sync {
    step: Step,
}

impl Sync {
    /// The next request, or `None` at the end of the exchange.
    pub fn next_request(&mut self, engine: &Engine) -> Option<Request> {
        match self.step {
            Step::Info => {
                self.step = Step::AwaitInfo;
                Some(Request {
                    method: "GET".into(),
                    url: format!("{}/v1/info", engine.relay_url),
                    headers: vec![("accept".into(), "application/json".into())],
                    body: Vec::new(),
                })
            }
            Step::AwaitInfo | Step::Done => None,
        }
    }

    /// Read the response to the last request.
    ///
    /// The engine parses unsigned response JSON loosely and ignores unknown
    /// fields ([VER-13]). M2 reads the relay time from `headers` ([WIR-7]).
    ///
    /// # Errors
    ///
    /// [`EngineError::UnexpectedResponse`] if no request waits for a
    /// response, and [`EngineError::Storage`].
    pub fn handle_response(
        &mut self,
        engine: &mut Engine,
        status: u16,
        _headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), EngineError> {
        if !matches!(self.step, Step::AwaitInfo) {
            return Err(EngineError::UnexpectedResponse);
        }
        self.step = Step::Done;
        let levels = (status == 200)
            .then(|| serde_json::from_slice::<serde_json::Value>(body).ok())
            .flatten()
            .and_then(|v| v.get("levels").cloned());
        let supported = levels
            .as_ref()
            .and_then(serde_json::Value::as_array)
            .is_some_and(|l| l.iter().any(|x| x.as_u64() == Some(MAX_LEVEL)));
        if status == 200 && supported {
            engine.db.execute(
                "INSERT INTO relay_info (id, body) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET body = excluded.body",
                [body],
            )?;
            engine.status = Status::Ok;
        } else if status == 200 {
            engine.status = Status::RelayTooOld;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_engine_on_one_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let a = Engine::open(dir.path(), "https://r.example", "com.example.tasks").unwrap();
        assert!(matches!(
            Engine::open(dir.path(), "https://r.example", "com.example.tasks"),
            Err(EngineError::Locked)
        ));
        drop(a);
        assert!(Engine::open(dir.path(), "https://r.example", "com.example.tasks").is_ok());
    }

    /// [VER-15]: a downgrade fails with a clear error and does not change
    /// the file.
    #[test]
    fn newer_schema_is_refused_and_not_changed() {
        let dir = tempfile::tempdir().unwrap();
        drop(Engine::open(dir.path(), "https://r.example", "a").unwrap());
        {
            let db = Connection::open(dir.path().join(STATE_FILE)).unwrap();
            db.pragma_update(None, "user_version", 7).unwrap();
        }
        let before = std::fs::read(dir.path().join(STATE_FILE)).unwrap();
        let err = Engine::open(dir.path(), "https://r.example", "a")
            .err()
            .unwrap();
        assert_eq!(err, EngineError::SchemaTooNew { found: 7 });
        // [VER-15]: the app shows this text, so it must name both versions.
        assert_eq!(
            err.to_string(),
            "the engine state file has schema version 7, and this engine knows 1"
        );
        assert_eq!(std::fs::read(dir.path().join(STATE_FILE)).unwrap(), before);
    }

    #[test]
    fn state_survives_reopen_with_durable_settings() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), "https://r.example/", "a").unwrap();
        let mut s = e.start_sync();
        let req = s.next_request(&e).unwrap();
        assert_eq!(
            (req.method.as_str(), req.url.as_str()),
            ("GET", "https://r.example/v1/info")
        );
        assert_eq!(s.next_request(&e), None);
        s.handle_response(&mut e, 200, &[], br#"{"levels":[1],"future_field":true}"#)
            .unwrap();
        assert!(s.handle_response(&mut e, 200, &[], b"{}").is_err());
        assert_eq!(e.status(), Status::Ok);
        drop(e);
        let e = Engine::open(dir.path(), "https://r.example", "a").unwrap();
        let version: i64 =
            e.db.pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let mode: String =
            e.db.pragma_query_value(None, "journal_mode", |r| r.get(0))
                .unwrap();
        let sync: i64 =
            e.db.pragma_query_value(None, "synchronous", |r| r.get(0))
                .unwrap();
        assert_eq!((mode.as_str(), sync), ("wal", 2));
        let stored: Vec<u8> =
            e.db.query_row("SELECT body FROM relay_info", [], |r| r.get(0))
                .unwrap();
        assert_eq!(stored, br#"{"levels":[1],"future_field":true}"#);
    }

    /// [VER-11]: a relay without the level of this engine stops sync.
    #[test]
    fn relay_without_engine_level_reports_relay_too_old() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), "https://r.example", "a").unwrap();
        let mut s = e.start_sync();
        s.next_request(&e);
        s.handle_response(&mut e, 200, &[], br#"{"levels":[0]}"#)
            .unwrap();
        assert_eq!(e.status(), Status::RelayTooOld);
    }

    #[test]
    fn change_ids_differ() {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::open(dir.path(), "https://r.example", "a").unwrap();
        assert_ne!(e.new_change_id().unwrap(), e.new_change_id().unwrap());
    }
}
