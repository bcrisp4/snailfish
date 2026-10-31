//! SQLite files of the relay (DESIGN.md "Relay storage").
//!
//! Every file uses WAL mode, `synchronous=FULL`, `secure_delete=ON` and
//! `auto_vacuum=INCREMENTAL` ([STO-1]) and keeps its schema version in
//! `PRAGMA user_version` ([VER-14], [VER-15]).

use std::fmt;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};

/// The kind of a database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `data/directory.db`.
    Directory,
    /// `data/tenants/<tenant ID>/tenant.db`.
    Tenant,
    /// `data/tenants/<tenant ID>/spaces/<random name>.db`.
    Space,
}

/// The schema version of every file kind.
pub const SCHEMA_VERSION: i64 = 1;

impl Kind {
    fn ddl(self) -> &'static str {
        match self {
            Self::Directory => {
                "CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    handle TEXT NOT NULL UNIQUE
                 ) WITHOUT ROWID;"
            }
            Self::Tenant => {
                "CREATE TABLE IF NOT EXISTS tenant (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    handle TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS spaces (
                    log_id TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL UNIQUE,
                    app_id TEXT NOT NULL,
                    status TEXT NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS nonces (
                    keyid TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires INTEGER NOT NULL,
                    PRIMARY KEY (keyid, nonce)
                 ) WITHOUT ROWID;
                 CREATE INDEX IF NOT EXISTS nonces_expires ON nonces (expires);
                 CREATE TABLE IF NOT EXISTS deletion_markers (
                    log_id TEXT PRIMARY KEY
                 ) WITHOUT ROWID;"
            }
            Self::Space => {
                "CREATE TABLE IF NOT EXISTS space (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    log_id BLOB NOT NULL,
                    app_id TEXT NOT NULL,
                    write_level INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS entries (
                    position INTEGER PRIMARY KEY,
                    payload_type TEXT NOT NULL,
                    change_id BLOB UNIQUE,
                    record_hash BLOB NOT NULL,
                    digest BLOB NOT NULL,
                    envelope TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS devices (
                    device_id BLOB PRIMARY KEY,
                    sign_key BLOB NOT NULL,
                    position INTEGER NOT NULL
                 ) WITHOUT ROWID;"
            }
        }
    }
}

/// A storage failure. The relay never sends its text to a client.
#[derive(Debug)]
pub enum StoreError {
    /// SQLite refused an operation.
    Sqlite(rusqlite::Error),
    /// A file operation failed.
    Io(std::io::Error),
    /// The file has a newer schema than this software ([VER-15]).
    SchemaTooNew {
        /// The file kind.
        kind: Kind,
        /// The `user_version` of the file.
        found: i64,
    },
    /// Stored data breaks an invariant of the relay.
    Corrupt(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::SchemaTooNew { kind, found } => write!(
                f,
                "a {kind:?} file has schema version {found}, which is newer than this software knows ({SCHEMA_VERSION})"
            ),
            Self::Corrupt(why) => write!(f, "corrupt: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// How long a writer waits for another writer of the same file.
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

/// Open a database file with the settings of [STO-1].
///
/// If `create` is false, a missing file is an error, and a file without a
/// schema is corrupt. If `create` is true, the function creates the file and
/// its schema. A file with a newer schema never opens ([VER-15]).
///
/// # Errors
///
/// [`StoreError`].
pub fn open(path: &Path, kind: Kind, create: bool) -> Result<Connection, StoreError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let mut conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // Both pragmas below take a write lock, also when they change nothing.
    // A reader must open the file while a writer holds it ([STO-11]), so
    // the open sets them only on a file that does not have them yet.
    let mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        // auto_vacuum only takes effect before the first table exists.
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Corrupt("the file does not use WAL mode"));
        }
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            kind,
            found: version,
        });
    }
    if version < SCHEMA_VERSION {
        if !create {
            return Err(StoreError::Corrupt("the file has no schema"));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Every statement of the DDL is `IF NOT EXISTS`, so a second creator
        // that waited for the lock repeats it without harm.
        tx.execute_batch(kind.ddl())?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    }
    Ok(conn)
}
