//! Relay operator commands: backup, restore and the restore hold
//! (DESIGN.md "Relay storage" [STO-7] to [STO-10], "Space log" [LOG-14]
//! and [LOG-15]).
//!
//! These functions work on the data directory. `backup`, `hold-status` and
//! `release-hold` can run while the relay serves. `restore` needs a stopped
//! relay, and checks the lock that `serve` holds.

use std::fmt;
use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, MAIN_DB, OptionalExtension as _, TransactionBehavior, params};
use snailfish_protocol::encoding::{decode_id, encode_id};
use snailfish_protocol::hash::digest0;

use crate::core::{BACKUP_LOCK, SERVE_LOCK};
use crate::store::{self, Kind, StoreError};

/// A failed operator command.
#[derive(Debug)]
pub enum OpsError {
    /// A storage failure.
    Store(StoreError),
    /// The command cannot run as asked. The text says why.
    Refused(String),
}

impl fmt::Display for OpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => e.fmt(f),
            Self::Refused(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for OpsError {}

impl<E: Into<StoreError>> From<E> for OpsError {
    fn from(e: E) -> Self {
        Self::Store(e.into())
    }
}

fn refused(why: impl Into<String>) -> OpsError {
    OpsError::Refused(why.into())
}

fn to_i64(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Corrupt("a number is out of range"))
}

fn from_i64(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt("a number is out of range"))
}

/// True for a name that the relay made: only lowercase letters and digits
/// ([STO-3]). The commands never follow another name in the data directory.
fn safe_name(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn lock_file(path: &Path) -> Result<File, OpsError> {
    Ok(File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(StoreError::Io)?)
}

/// Take the lock that `serve` holds for its life. `restore` takes the same
/// lock, so the two never run on one data directory.
///
/// # Errors
///
/// [`OpsError::Refused`] if another process holds the lock.
pub fn serve_lock(data: &Path) -> Result<File, OpsError> {
    std::fs::create_dir_all(data).map_err(StoreError::Io)?;
    let f = lock_file(&data.join(SERVE_LOCK))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(TryLockError::WouldBlock) => Err(refused(
            "another snailfish-relay process uses this data directory: stop the relay first",
        )),
        Err(TryLockError::Error(e)) => Err(StoreError::Io(e).into()),
    }
}

/// The tenant directories of a data directory, by tenant ID.
fn tenants(data: &Path) -> Result<Vec<(String, PathBuf)>, OpsError> {
    let dir = data.join("tenants");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).map_err(StoreError::Io)? {
        let e = e.map_err(StoreError::Io)?;
        let name = e.file_name().to_string_lossy().into_owned();
        if safe_name(&name, 32) && e.path().is_dir() {
            out.push((name, e.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// The space files of a tenant directory, by file stem.
fn space_files(tenant: &Path) -> Result<Vec<(String, PathBuf)>, OpsError> {
    let dir = tenant.join("spaces");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).map_err(StoreError::Io)? {
        let p = e.map_err(StoreError::Io)?.path();
        let Some(stem) = p
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".db"))
        else {
            continue;
        };
        if safe_name(stem, 26) {
            out.push((stem.to_owned(), p));
        }
    }
    out.sort();
    Ok(out)
}

fn backup_file(src: &Path, kind: Kind, dst: &Path) -> Result<(), OpsError> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
    }
    let c = store::open(src, kind, false)?;
    c.backup(MAIN_DB, dst, rusqlite::backup::NO_PROGRESS)?;
    File::open(dst)
        .and_then(|f| f.sync_all())
        .map_err(StoreError::Io)?;
    Ok(())
}

/// What a backup copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupSummary {
    /// The tenant files.
    pub tenants: usize,
    /// The space files.
    pub spaces: usize,
}

/// Copy the data directory to `out` with the SQLite online backup API
/// ([STO-8]): the space files, then each tenant file, then `directory.db`.
/// The relay refuses space creation while this runs. The `secrets`
/// directory is outside `data` and is not copied ([STO-9]).
///
/// # Errors
///
/// [`OpsError::Refused`] if `out` exists and is not empty, and a storage
/// failure.
pub fn backup(data: &Path, out: &Path) -> Result<BackupSummary, OpsError> {
    if out.exists()
        && std::fs::read_dir(out)
            .map_err(StoreError::Io)?
            .next()
            .is_some()
    {
        return Err(refused("the backup directory must be empty or absent"));
    }
    if !data.join("directory.db").exists() {
        return Err(refused("the data directory holds no relay data"));
    }
    // Wait for each space creation in progress, and block new ones.
    let lock = lock_file(&data.join(BACKUP_LOCK))?;
    lock.lock().map_err(StoreError::Io)?;
    let ts = tenants(data)?;
    let mut spaces: usize = 0;
    for (id, dir) in &ts {
        for (stem, path) in space_files(dir)? {
            let dst = out
                .join("tenants")
                .join(id)
                .join("spaces")
                .join(format!("{stem}.db"));
            backup_file(&path, Kind::Space, &dst)?;
            spaces = spaces.saturating_add(1);
        }
    }
    for (id, dir) in &ts {
        let dst = out.join("tenants").join(id).join("tenant.db");
        backup_file(&dir.join("tenant.db"), Kind::Tenant, &dst)?;
    }
    backup_file(
        &data.join("directory.db"),
        Kind::Directory,
        &out.join("directory.db"),
    )?;
    Ok(BackupSummary {
        tenants: ts.len(),
        spaces,
    })
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), OpsError> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
    }
    std::fs::copy(src, dst).map_err(StoreError::Io)?;
    File::open(dst)
        .and_then(|f| f.sync_all())
        .map_err(StoreError::Io)?;
    Ok(())
}

fn remove_tree(path: &Path) -> Result<(), OpsError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io(e).into()),
    }
}

fn remove_db(path: &Path) -> Result<(), OpsError> {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        match std::fs::remove_file(PathBuf::from(p)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::Io(e).into()),
        }
    }
    Ok(())
}

/// What a restore did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSummary {
    /// The restored tenants.
    pub tenants: usize,
    /// The log IDs of the restored spaces. Each one is on restore hold.
    pub held: Vec<String>,
}

/// Restore a backup from `from` into the data directory, with the relay
/// stopped. The command rebuilds the space index of each tenant from its
/// space files ([STO-7]) and the handle map from the tenant files
/// ([STO-10]), and puts each restored space on hold ([LOG-14]). A deletion
/// marker wins over a space file with the same log ID. A restore ends each
/// repair session in the restored files.
///
/// # Errors
///
/// [`OpsError::Refused`] if the relay runs, if the data directory holds
/// relay data and `replace` is false, or if the backup is not complete.
pub fn restore(
    data: &Path,
    from: &Path,
    replace: bool,
    now: u64,
) -> Result<RestoreSummary, OpsError> {
    let _serve = serve_lock(data)?;
    if !from.join("directory.db").exists() {
        return Err(refused("the backup directory holds no directory.db"));
    }
    let has_data = data.join("directory.db").exists() || !tenants(data)?.is_empty();
    if has_data && !replace {
        return Err(refused(
            "the data directory holds relay data: pass --replace to delete it first",
        ));
    }
    // Copy the backup next to the data first, so a failed copy leaves the
    // old data in place. The swap below only renames within one directory.
    let tmp = data.join("restore.tmp");
    remove_tree(&tmp)?;
    let ts = tenants(from)?;
    for (id, dir) in &ts {
        let to = tmp.join("tenants").join(id);
        copy_file(&dir.join("tenant.db"), &to.join("tenant.db"))?;
        for (stem, path) in space_files(dir)? {
            copy_file(&path, &to.join("spaces").join(format!("{stem}.db")))?;
        }
    }
    copy_file(&from.join("directory.db"), &tmp.join("directory.db"))?;
    std::fs::create_dir_all(tmp.join("tenants")).map_err(StoreError::Io)?;
    if has_data {
        remove_db(&data.join("directory.db"))?;
        remove_tree(&data.join("tenants"))?;
    }
    std::fs::rename(tmp.join("tenants"), data.join("tenants")).map_err(StoreError::Io)?;
    std::fs::rename(tmp.join("directory.db"), data.join("directory.db")).map_err(StoreError::Io)?;
    remove_tree(&tmp)?;

    let mut handles = Vec::new();
    let mut held = Vec::new();
    for (id, _) in &ts {
        let dir = data.join("tenants").join(id);
        let (handle, logs) = rebuild_tenant(&dir, now)?;
        handles.push((id.clone(), handle));
        held.extend(logs);
    }
    let mut d = store::open(&data.join("directory.db"), Kind::Directory, false)?;
    let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("DELETE FROM tenants", [])?;
    for (id, handle) in &handles {
        tx.execute(
            "INSERT INTO tenants (tenant_id, handle) VALUES (?1, ?2)",
            params![id, handle],
        )?;
    }
    tx.commit()?;
    held.sort();
    Ok(RestoreSummary {
        tenants: ts.len(),
        held,
    })
}

/// Rebuild the space index of one tenant from its space files and hold each
/// space. Returns the tenant handle and the held log IDs.
fn rebuild_tenant(dir: &Path, now: u64) -> Result<(String, Vec<String>), OpsError> {
    let mut tc = store::open(&dir.join("tenant.db"), Kind::Tenant, false)?;
    let handle: String =
        tc.query_row("SELECT handle FROM tenant WHERE id = 1", [], |r| r.get(0))?;
    let mut spaces: Vec<(String, String, String)> = Vec::new();
    for (stem, path) in space_files(dir)? {
        let mut sc = store::open(&path, Kind::Space, false)?;
        let (log_id, app): (Vec<u8>, String) =
            sc.query_row("SELECT log_id, app_id FROM space WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        let log_id = <[u8; 16]>::try_from(log_id)
            .map_err(|_| StoreError::Corrupt("a space file holds a malformed log ID"))?;
        let log = encode_id("l_", &log_id);
        let marked: Option<i64> = tc
            .query_row(
                "SELECT 1 FROM deletion_markers WHERE log_id = ?1",
                params![log],
                |r| r.get(0),
            )
            .optional()?;
        if marked.is_some() {
            drop(sc);
            remove_db(&path)?;
            continue;
        }
        if spaces.iter().any(|(l, _, _)| l == &log) {
            return Err(refused(format!("two space files hold the log ID {log}")));
        }
        let tx = sc.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM staging", [])?;
        tx.execute("DELETE FROM repair", [])?;
        tx.commit()?;
        spaces.push((log, stem, app));
    }
    let tx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("DELETE FROM spaces", [])?;
    tx.execute("DELETE FROM hold_reports", [])?;
    tx.execute("DELETE FROM holds", [])?;
    for (log, stem, app) in &spaces {
        tx.execute(
            "INSERT INTO spaces (log_id, file_name, app_id, status) VALUES (?1, ?2, ?3, 'active')",
            params![log, stem, app],
        )?;
        tx.execute(
            "INSERT INTO holds (log_id, since) VALUES (?1, ?2)",
            params![log, to_i64(now)?],
        )?;
    }
    tx.commit()?;
    Ok((handle, spaces.into_iter().map(|(l, _, _)| l).collect()))
}

/// How the relay reads the tip of a device report (`PROTOCOL.md` 10.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipState {
    /// The log holds the tip: the device reported.
    Reported,
    /// The tip is after the log head: the device did not repair yet.
    Ahead,
    /// The log holds another digest at the tip position.
    OtherDigest,
}

/// One device report since the restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReport {
    /// The device ID text.
    pub device: String,
    /// The verified tip position.
    pub position: u64,
    /// How the relay reads the tip now.
    pub state: TipState,
    /// The device reported a new engine state file: "not repaired" (F3).
    pub not_repaired: bool,
    /// The relay time of the last report.
    pub time: u64,
}

/// One repair session of the space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRecord {
    /// The session ID text.
    pub session: String,
    /// The device ID text.
    pub device: String,
    /// The relay time of the start.
    pub started: u64,
    /// The relay head at the start.
    pub base: u64,
    /// The tip and the relay time of the finish, if the session finished.
    pub finished: Option<(u64, u64)>,
}

/// The restore hold of one space ([LOG-15]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldReport {
    /// The log ID text.
    pub log: String,
    /// The relay time at which the hold began, or `None` without a hold.
    pub since: Option<u64>,
    /// The log head position.
    pub head: u64,
    /// Each device that reported since the restore.
    pub devices: Vec<DeviceReport>,
    /// Each repair session of the space.
    pub repairs: Vec<RepairRecord>,
}

impl HoldReport {
    /// The devices that the report marks "not repaired".
    #[must_use]
    pub fn not_repaired(&self) -> Vec<&str> {
        self.devices
            .iter()
            .filter(|d| d.not_repaired)
            .map(|d| d.device.as_str())
            .collect()
    }
}

impl fmt::Display for HoldReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.since {
            Some(t) => writeln!(
                f,
                "space {}: on hold since {t}, head {}",
                self.log, self.head
            )?,
            None => writeln!(f, "space {}: no hold, head {}", self.log, self.head)?,
        }
        writeln!(
            f,
            "devices that reported since the restore: {}",
            self.devices.len()
        )?;
        for d in &self.devices {
            let state = match d.state {
                TipState::Reported => "reported",
                TipState::Ahead => "tip after the head",
                TipState::OtherDigest => "tip with another digest",
            };
            let mark = if d.not_repaired { ", NOT REPAIRED" } else { "" };
            writeln!(
                f,
                "  {} tip {} ({state}{mark}), last report {}",
                d.device, d.position, d.time
            )?;
        }
        writeln!(f, "repair sessions: {}", self.repairs.len())?;
        for r in &self.repairs {
            match r.finished {
                Some((tip, t)) => writeln!(
                    f,
                    "  {} by {}: started {} at head {}, finished {t} at tip {tip}",
                    r.session, r.device, r.started, r.base
                )?,
                None => writeln!(
                    f,
                    "  {} by {}: started {} at head {}, not finished",
                    r.session, r.device, r.started, r.base
                )?,
            }
        }
        Ok(())
    }
}

/// The tenant directory and the space file of a user and a log ID.
fn locate(data: &Path, user: &str, log: &str) -> Result<(PathBuf, PathBuf), OpsError> {
    decode_id::<16>(log, "l_").map_err(|_| refused("the log ID is malformed"))?;
    let d = store::open(&data.join("directory.db"), Kind::Directory, false)?;
    let tenant: Option<String> = d
        .query_row(
            "SELECT tenant_id FROM users WHERE name = ?1",
            params![user],
            |r| r.get(0),
        )
        .optional()?;
    let tenant = tenant.ok_or_else(|| refused(format!("no user has the name {user}")))?;
    if !safe_name(&tenant, 32) {
        return Err(StoreError::Corrupt("a tenant ID is malformed").into());
    }
    let dir = data.join("tenants").join(tenant);
    let tc = store::open(&dir.join("tenant.db"), Kind::Tenant, false)?;
    let file: Option<String> = tc
        .query_row(
            "SELECT file_name FROM spaces WHERE log_id = ?1 AND status = 'active'",
            params![log],
            |r| r.get(0),
        )
        .optional()?;
    let file = file.ok_or_else(|| refused(format!("the user has no space {log}")))?;
    if !safe_name(&file, 26) {
        return Err(StoreError::Corrupt("a space file name is malformed").into());
    }
    let space = dir.join("spaces").join(format!("{file}.db"));
    Ok((dir, space))
}

fn read_report(tc: &Connection, sc: &Connection, log: &str) -> Result<HoldReport, OpsError> {
    let since = crate::core::hold_since(tc, log)?;
    let log_id = decode_id::<16>(log, "l_").map_err(|_| refused("the log ID is malformed"))?;
    let head: i64 = sc.query_row("SELECT COALESCE(MAX(position), 0) FROM entries", [], |r| {
        r.get(0)
    })?;
    let head = from_i64(head)?;
    let mut devices = Vec::new();
    {
        let mut st = tc.prepare(
            "SELECT device_id, position, digest, fresh, time FROM hold_reports
             WHERE log_id = ?1 ORDER BY device_id",
        )?;
        let mut q = st.query(params![log])?;
        while let Some(r) = q.next()? {
            let position = from_i64(r.get(1)?)?;
            let digest: Vec<u8> = r.get(2)?;
            // The relay reads the tip now, so a later repair by another
            // device can make it reported (10.8).
            let stored: Option<Vec<u8>> = if position == 0 {
                Some(digest0(&log_id).to_vec())
            } else {
                sc.query_row(
                    "SELECT digest FROM entries WHERE position = ?1",
                    params![to_i64(position)?],
                    |r| r.get(0),
                )
                .optional()?
            };
            let state = match stored {
                None => TipState::Ahead,
                Some(d) if d == digest => TipState::Reported,
                Some(_) => TipState::OtherDigest,
            };
            devices.push(DeviceReport {
                device: r.get(0)?,
                position,
                state,
                not_repaired: r.get::<_, i64>(3)? != 0,
                time: from_i64(r.get(4)?)?,
            });
        }
    }
    let mut repairs = Vec::new();
    {
        let mut st = sc.prepare(
            "SELECT session, device_id, started, base_position, tip, finished FROM repairs
             ORDER BY started, session",
        )?;
        let mut q = st.query([])?;
        while let Some(r) = q.next()? {
            let started = from_i64(r.get(2)?)?;
            // A session before the restore belongs to an earlier hold.
            if since.is_some_and(|t| started < t) {
                continue;
            }
            let session: Vec<u8> = r.get(0)?;
            let device: Vec<u8> = r.get(1)?;
            let tip: Option<i64> = r.get(4)?;
            let finished: Option<i64> = r.get(5)?;
            repairs.push(RepairRecord {
                session: encode_id("", &session),
                device: encode_id("d_", &device),
                started,
                base: from_i64(r.get(3)?)?,
                finished: match (tip, finished) {
                    (Some(p), Some(t)) => Some((from_i64(p)?, from_i64(t)?)),
                    _ => None,
                },
            });
        }
    }
    Ok(HoldReport {
        log: log.to_owned(),
        since,
        head,
        devices,
        repairs,
    })
}

/// The restore hold report of a space: each device that reported since the
/// restore, with its tip, and each repair session ([LOG-15]). Changes
/// nothing.
///
/// # Errors
///
/// [`OpsError::Refused`] for an unknown user or space, and a storage
/// failure.
pub fn hold_report(data: &Path, user: &str, log: &str) -> Result<HoldReport, OpsError> {
    let (dir, space) = locate(data, user, log)?;
    let tc = store::open(&dir.join("tenant.db"), Kind::Tenant, false)?;
    let sc = store::open(&space, Kind::Space, false)?;
    read_report(&tc, &sc, log)
}

/// End the restore hold of a space ([LOG-15]). The relay never ends a hold
/// by itself. Refuses while a device is "not repaired", unless `force` is
/// set, because the app database of that device can hold changes that only
/// the lost engine state file and the old relay held (F3). Returns the
/// report at the release.
///
/// # Errors
///
/// [`OpsError::Refused`] if the space has no hold, or if a device is "not
/// repaired" and `force` is false.
pub fn release_hold(
    data: &Path,
    user: &str,
    log: &str,
    force: bool,
) -> Result<HoldReport, OpsError> {
    let (dir, space) = locate(data, user, log)?;
    let mut tc = store::open(&dir.join("tenant.db"), Kind::Tenant, false)?;
    let sc = store::open(&space, Kind::Space, false)?;
    // The transaction makes the check and the release one step, so a report
    // that arrives during the release is either in the check or refused by
    // the ended hold.
    let tx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let report = read_report(&tx, &sc, log)?;
    if report.since.is_none() {
        return Err(refused(format!("the space {log} has no restore hold")));
    }
    let marked = report.not_repaired();
    if !marked.is_empty() && !force {
        return Err(refused(format!(
            "not repaired: {}. Their app databases can hold changes that the release loses. \
             Pass --force to release anyway",
            marked.join(", ")
        )));
    }
    tx.execute("DELETE FROM holds WHERE log_id = ?1", params![log])?;
    tx.execute("DELETE FROM hold_reports WHERE log_id = ?1", params![log])?;
    tx.commit()?;
    Ok(report)
}
