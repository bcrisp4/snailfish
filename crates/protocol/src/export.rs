//! The export file (`PROTOCOL.md` section 15, [FRK-3]).
//!
//! [`parse`] checks the form of a file: the header, one entry on each line,
//! dense positions from 1 and the final LF. [`check_log`] then runs the full
//! chain check of an import (10.13 start step 6) on the parsed entries, with
//! the signature of each record, and compares the last digest with the
//! header. A file holds no key, so neither function needs one.

use crate::encoding::{Hash32, decode_b64_strict, decode_id, encode_b64, encode_id};
use crate::records::Body;
use crate::repair::{self, ChainError, Item, follows};
use crate::space::{MemorySpace, Refusal, Staged, check_genesis};
use crate::strict::{self, Fields, MAX_INT};
use crate::wire::{self, Head, OutEntry, RepairItem, WireError};

/// The `type` of the header line.
pub const EXPORT_TYPE: &str = "snailfish.export.v1";

/// The header line of an export file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The log ID.
    pub log_id: [u8; 16],
    /// The app ID of the genesis record.
    pub app: String,
    /// The last position and its log digest.
    pub head: Head,
}

/// A parsed export file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportFile {
    /// The header.
    pub header: Header,
    /// The entries, positions 1 to `header.head.position`.
    pub entries: Vec<(u64, RepairItem)>,
}

fn bad(msg: impl Into<String>) -> WireError {
    WireError(msg.into())
}

/// True if `bytes` is LF-terminated lines with no empty line: it ends with
/// LF, it does not start with LF, and it holds no two LF bytes in a row.
#[must_use]
pub fn well_formed(bytes: &[u8]) -> bool {
    let mut prev = b'\n';
    for &b in bytes {
        if b == b'\n' && prev == b'\n' {
            return false;
        }
        prev = b;
    }
    !bytes.is_empty() && prev == b'\n'
}

/// The lines of `bytes`, without their LF, if [`well_formed`] holds.
#[must_use]
pub fn split_lines(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    if !well_formed(bytes) {
        return None;
    }
    let body = bytes.strip_suffix(b"\n")?;
    Some(body.split(|b| *b == b'\n').collect())
}

/// The header line, without its LF.
#[must_use]
pub fn header_line(h: &Header) -> String {
    format!(
        "{{\"type\":\"{EXPORT_TYPE}\",\"log\":\"{}\",\"app\":{},\"head\":{{\"position\":{},\"digest\":\"{}\"}}}}",
        encode_id("l_", &h.log_id),
        serde_json::Value::String(h.app.clone()),
        h.head.position,
        encode_b64(&h.head.digest)
    )
}

/// Write an export file. `entries` must hold positions 1 to
/// `header.head.position` in order.
///
/// # Errors
///
/// Refuses an envelope text that is not JSON.
pub fn write(header: &Header, entries: &[(u64, OutEntry)]) -> Result<Vec<u8>, WireError> {
    let mut out = header_line(header).into_bytes();
    out.push(b'\n');
    for (pos, e) in entries {
        out.extend_from_slice(wire::entry_json(*pos, e)?.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

fn parse_header(line: &[u8]) -> Result<Header, WireError> {
    let map = strict::parse_object(line).map_err(|e| bad(format!("header: {e}")))?;
    let f = Fields::exact(&map, "header", &["type", "log", "app", "head"])
        .map_err(|e| bad(e.to_string()))?;
    if f.str("type").map_err(|e| bad(e.to_string()))? != EXPORT_TYPE {
        return Err(bad("header: type is not snailfish.export.v1"));
    }
    let log_id = decode_id::<16>(f.str("log").map_err(|e| bad(e.to_string()))?, "l_")
        .map_err(|e| bad(format!("header: log: {e}")))?;
    let app = f.str("app").map_err(|e| bad(e.to_string()))?.to_owned();
    let hf = Fields::object(
        f.get("head").map_err(|e| bad(e.to_string()))?,
        "head",
        &["position", "digest"],
    )
    .map_err(|e| bad(e.to_string()))?;
    let position = hf
        .int("position", 1, MAX_INT)
        .map_err(|e| bad(e.to_string()))?;
    let digest = decode_b64_strict(hf.str("digest").map_err(|e| bad(e.to_string()))?)
        .ok()
        .and_then(|b| Hash32::try_from(b).ok())
        .ok_or_else(|| bad("header: head.digest is not 32 bytes of base64"))?;
    let head = Head { position, digest };
    Ok(Header { log_id, app, head })
}

/// Parse the form of an export file (`PROTOCOL.md` section 15). An envelope
/// that breaks section 4 is a [`RepairItem::Invalid`] entry, which
/// [`check_log`] refuses.
///
/// # Errors
///
/// Refuses a file whose lines, header or entry objects break section 15, an
/// entry with a position that is not the next one, and a file whose last
/// position is not `head.position`.
pub fn parse(bytes: &[u8]) -> Result<ExportFile, WireError> {
    let lines = split_lines(bytes)
        .ok_or_else(|| bad("the file must be LF-terminated lines with no empty line"))?;
    let (first, rest) = lines
        .split_first()
        .ok_or_else(|| bad("the file is empty"))?;
    let header = parse_header(first)?;
    let mut entries = Vec::with_capacity(rest.len());
    let mut prev = 0;
    for line in rest {
        let (pos, item) = wire::parse_entry(line)?;
        if !follows(prev, pos) {
            return Err(bad(format!(
                "entry {pos}: the position must be {}",
                prev.saturating_add(1)
            )));
        }
        prev = pos;
        entries.push((pos, item));
    }
    if prev != header.head.position {
        return Err(bad("the last position differs from head.position"));
    }
    Ok(ExportFile { header, entries })
}

/// Why [`check_log`] refuses a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    /// Position 1 is not a valid genesis record of the header log and app.
    Genesis(String),
    /// An entry fails the chain check, at this position.
    Chain(u64, ChainError),
    /// The last digest differs from `head.digest`.
    Digest,
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Genesis(why) => write!(f, "position 1: {why}"),
            Self::Chain(pos, e) => write!(f, "position {pos}: {e:?}"),
            Self::Digest => f.write_str("the last digest differs from head.digest"),
        }
    }
}

impl std::error::Error for CheckError {}

fn item(e: &RepairItem) -> Item<'_> {
    match e {
        RepairItem::Envelope(r) => Item::Envelope(&r.envelope),
        RepairItem::Stub(s) => Item::Stub(s),
        RepairItem::Invalid(_) => Item::Invalid,
    }
}

/// Run the chain check of an import (`PROTOCOL.md` 10.13 start step 6) on a
/// parsed file: the genesis record of the header log and app at position 1,
/// then each entry against the entries before it, then the last digest. The
/// stub check of the finish (14.3) is the caller's.
///
/// # Errors
///
/// [`CheckError`] for the first failure.
pub fn check_log(file: &ExportFile) -> Result<Vec<Staged>, CheckError> {
    let log_id = file.header.log_id;
    let Some((1, RepairItem::Envelope(genesis))) = file.entries.first() else {
        return Err(CheckError::Genesis(
            "position 1 must be a genesis envelope".into(),
        ));
    };
    let accepted = check_genesis(&genesis.envelope, &log_id, None)
        .map_err(|e: Refusal| CheckError::Genesis(e.to_string()))?;
    match &accepted.record.body {
        Body::Genesis { app, .. } if *app == file.header.app => {}
        _ => {
            return Err(CheckError::Genesis(
                "the app ID differs from the header".into(),
            ));
        }
    }
    let mut base = MemorySpace::new(log_id);
    base.apply(&accepted);
    let first = Staged::Full(Box::new(accepted));
    let rest = file.entries.get(1..).unwrap_or_default();
    let positions: Vec<u64> = rest.iter().map(|(p, _)| *p).collect();
    let items: Vec<Item<'_>> = rest.iter().map(|(_, e)| item(e)).collect();
    let chain = repair::check_chain(&base, &positions, &items);
    if let Some((i, e)) = chain.failure {
        return Err(CheckError::Chain(positions.get(i).copied().unwrap_or(0), e));
    }
    let mut staged = Vec::with_capacity(file.entries.len());
    staged.push(first);
    staged.extend(chain.accepted);
    let last = staged.last().map(Staged::digest);
    if last != Some(file.header.head.digest) {
        return Err(CheckError::Digest);
    }
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Section 15: `split_lines` accepts exactly the LF-terminated
        /// files with no empty line, and the lines join back to the file.
        #[test]
        fn split_lines_round_trip(bytes in proptest::collection::vec(prop_oneof![Just(b'\n'), Just(b'a'), any::<u8>()], 0..40)) {
            match split_lines(&bytes) {
                Some(lines) => {
                    let mut joined = Vec::new();
                    for l in &lines {
                        prop_assert!(!l.is_empty() && !l.contains(&b'\n'));
                        joined.extend_from_slice(l);
                        joined.push(b'\n');
                    }
                    prop_assert_eq!(joined, bytes);
                }
                None => prop_assert!(
                    bytes.last() != Some(&b'\n')
                        || bytes.starts_with(b"\n")
                        || bytes.windows(2).any(|w| w == b"\n\n")
                ),
            }
        }

        /// Section 15: a header line parses back to the same header.
        #[test]
        fn header_round_trip(log in any::<[u8; 16]>(), app in "[a-z]{1,8}\\.[a-z]{1,8}", pos in 1u64..(1 << 53), digest in any::<[u8; 32]>()) {
            let h = Header { log_id: log, app, head: Head { position: pos, digest } };
            prop_assert_eq!(parse_header(header_line(&h).as_bytes()).unwrap(), h);
        }
    }

    #[test]
    fn header_refusals() {
        let h = Header {
            log_id: [1; 16],
            app: "com.example.tasks".into(),
            head: Head {
                position: 1,
                digest: [2; 32],
            },
        };
        let good = header_line(&h);
        let cases = [
            good.replace("snailfish.export.v1", "snailfish.export.v2"),
            good.replace("\"app\"", "\"app\":\"x\",\"more\":1,\"x\""),
            good.replace(",\"app\":", ",\"app\":\"a\",\"app\":"),
            good.replace("\"position\":1", "\"position\":0"),
            good.replace("\"position\":1", "\"position\":1.0"),
        ];
        for c in cases {
            assert!(parse_header(c.as_bytes()).is_err(), "{c}");
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// [`parse`] and [`check_log`] parse JSON and verify signatures, which CBMC
/// cannot finish. `crates/protocol/tests/export.rs`, the shared vectors and
/// the `export` fuzz target cover them.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Section 15: for each byte string of up to 5 bytes, `well_formed`
    /// holds only if the string ends with LF, does not start with LF, and
    /// holds no two LF bytes in a row. `split_lines` builds a `Vec`, which
    /// CBMC cannot finish ("CBMC failed" at 6 bytes), so the property test
    /// `split_lines_round_trip` covers it.
    #[kani::proof]
    #[kani::unwind(7)]
    fn well_formed_is_exact() {
        let bytes: [u8; 5] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 5);
        let b = &bytes[..len];
        let mut double = false;
        let mut i = 1;
        while i < len {
            double |= b[i] == b'\n' && b[i - 1] == b'\n';
            i += 1;
        }
        let want = len > 0 && b[len - 1] == b'\n' && b[0] != b'\n' && !double;
        assert!(well_formed(b) == want);
    }
}
