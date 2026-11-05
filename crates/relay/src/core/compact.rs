//! Compaction on the relay (`PROTOCOL.md` section 14, DESIGN.md "Log
//! compaction" and "Relay storage").
//!
//! A stub keeps its `entries` row with an empty `envelope`: the position,
//! the payload type, the change ID, the record hash and the digest stay, so
//! the digest chain and the known `change_id` check of 10.6 step 2 work
//! unchanged ([CMP-1]). `secure_delete=ON` overwrites the deleted text
//! ([STO-1]).

use rusqlite::{Connection, params};
use snailfish_protocol::compaction::{self, Compaction};
use snailfish_protocol::encoding::{Hash32, encode_id};
use snailfish_protocol::wire::{OutEntry, Stub};

use super::{from_i64, to_i64};
use crate::store::StoreError;

/// The payload types that count against the space quota and the snapshot
/// reserve (`PROTOCOL.md` 10.6 step 16, [CMP-18]).
pub(super) const COUNTED: &str =
    "payload_type IN ('snailfish.change.v1', 'snailfish.snapshot.v1', 'snailfish.accept.v1')";

/// The snapshot reserve of 14.6 for a snapshot size limit ([CMP-18]).
#[must_use]
pub fn snapshot_reserve(max_snapshot_bytes: u64) -> u64 {
    max_snapshot_bytes.saturating_add(65_536).saturating_mul(2)
}

fn corrupt(_: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt("a stored record does not parse")
}

/// The compaction state of the log, and of the staging table if `staged`
/// (`PROTOCOL.md` 14.1). It replays the security, snapshot and accept
/// records in position order, and reads the last change position of each
/// epoch. Changes do not move the usable snapshot, so the replay skips them.
pub(super) fn compaction_state(c: &Connection, staged: bool) -> Result<Compaction, StoreError> {
    let tables: &[&str] = if staged {
        &["entries", "staging"]
    } else {
        &["entries"]
    };
    let mut rows: Vec<(u64, String, String)> = Vec::new();
    for t in tables {
        let mut st = c.prepare(&format!(
            "SELECT position, payload_type, envelope FROM {t}
             WHERE payload_type != 'snailfish.change.v1' ORDER BY position"
        ))?;
        let mut q = st.query([])?;
        while let Some(r) = q.next()? {
            rows.push((from_i64(r.get(0)?)?, r.get(1)?, r.get(2)?));
        }
    }
    let (mut cmp, starts) =
        compaction::replay(rows.iter().map(|(p, t, e)| (*p, t.as_str(), e.as_str())))
            .map_err(corrupt)?;
    for (i, (epoch, start)) in starts.iter().enumerate() {
        let end = starts
            .get(i.saturating_add(1))
            .map_or(i64::MAX, |(_, p)| i64::try_from(*p).unwrap_or(i64::MAX));
        let mut last = 0;
        for t in tables {
            let v: Option<i64> = c.query_row(
                &format!(
                    "SELECT MAX(position) FROM {t} WHERE payload_type = 'snailfish.change.v1'
                     AND position >= ?1 AND position < ?2"
                ),
                params![to_i64(*start)?, end],
                |r| r.get(0),
            )?;
            last = last.max(v.map(from_i64).transpose()?.unwrap_or(0));
        }
        if last > 0 {
            cmp.last_change.insert(*epoch, last);
        }
    }
    Ok(cmp)
}

/// The frontier of the log (`PROTOCOL.md` 14.1), 0 if none.
///
/// # Errors
///
/// A storage failure or a stored record that does not parse.
pub fn frontier(c: &Connection) -> Result<u64, StoreError> {
    Ok(compaction_state(c, false)?.frontier())
}

/// Replace each record that the usable snapshot covers with a stub, and
/// take its bytes out of the space usage ([CMP-12], [CMP-19]). Returns the
/// number of new stubs. The caller runs it inside the write transaction.
pub(super) fn compact(tx: &Connection) -> Result<u64, StoreError> {
    let c = compaction_state(tx, false)?;
    let f = c.frontier();
    if f == 0 {
        return Ok(0);
    }
    let covered = "envelope != '' AND ((payload_type = 'snailfish.change.v1' AND position <= ?1)
                   OR position IN (SELECT value FROM json_each(?2)))";
    let snaps = serde_json::to_string(&c.covered_snapshots()).map_err(corrupt)?;
    let f = to_i64(f)?;
    let (n, bytes): (i64, i64) = tx.query_row(
        &format!(
            "SELECT count(*), COALESCE(SUM(length(CAST(envelope AS BLOB))), 0) FROM entries WHERE {covered}"
        ),
        params![f, snaps],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if n == 0 {
        return Ok(0);
    }
    tx.execute(
        &format!("UPDATE entries SET envelope = '' WHERE {covered}"),
        params![f, snaps],
    )?;
    tx.execute(
        "UPDATE usage SET bytes = MAX(bytes - ?1, 0) WHERE id = 1",
        params![bytes],
    )?;
    from_i64(n)
}

/// After a commit that made stubs: give the space back ([STO-2], [STO-13]).
/// A stub leaves most of each page of the `entries` table empty, and
/// `incremental_vacuum` frees only whole free pages, so the relay runs
/// `VACUUM`, which rebuilds the file. Only this space waits for it. A reader
/// can make it fail with `SQLITE_BUSY`: the next compaction tries again, so
/// a failure here loses nothing.
pub(super) fn reclaim(c: &Connection) {
    let _ = c.execute_batch("VACUUM");
    let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
}

/// The stub of a stored row with an empty envelope.
pub(super) fn stub_of(
    payload_type: String,
    change_id: Option<Vec<u8>>,
    record_hash: Vec<u8>,
) -> Result<OutEntry, StoreError> {
    let hash =
        Hash32::try_from(record_hash).map_err(|_| StoreError::Corrupt("a hash is malformed"))?;
    let change_id = change_id
        .map(|c| {
            <[u8; 16]>::try_from(c)
                .map(|c| encode_id("c_", &c))
                .map_err(|_| StoreError::Corrupt("a change ID is malformed"))
        })
        .transpose()?;
    Ok(OutEntry::Stub(Stub {
        payload_type,
        change_id,
        hash,
    }))
}

/// The stub count and the stub bytes of a space for the operator
/// ([CMP-19]). The stub bytes are the length of the stub JSON of 10.7.
///
/// # Errors
///
/// A storage failure or a malformed stub row.
pub fn stub_usage(c: &Connection) -> Result<(u64, u64), StoreError> {
    let mut st =
        c.prepare("SELECT payload_type, change_id, record_hash FROM entries WHERE envelope = ''")?;
    let mut q = st.query([])?;
    let (mut n, mut bytes) = (0u64, 0u64);
    while let Some(r) = q.next()? {
        if let OutEntry::Stub(s) = stub_of(r.get(0)?, r.get(1)?, r.get(2)?)? {
            n = n.saturating_add(1);
            bytes = bytes.saturating_add(s.to_json().len() as u64);
        }
    }
    Ok((n, bytes))
}
