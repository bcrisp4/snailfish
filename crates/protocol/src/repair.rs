//! The chain check of a repair request (`PROTOCOL.md` 10.9, [LOG-10] to
//! [LOG-12]).
//!
//! The relay checks each entry against the log and the entries before it,
//! with the fetch rules of [`Mode::Verify`]: no size limit and no hold,
//! because each record was in the log before. The check stops at the first
//! failed entry. The relay accepts a request signer that the passed entries
//! make active ([LOG-12]), so it needs the passed prefix also when an entry
//! fails.

use crate::encoding::decode_id;
use crate::envelope::Envelope;
use crate::space::{Mode, Overlay, Refusal, SpaceView, Staged, StubEntry, Verdict, check_append};
use crate::wire::Stub;

/// One entry of a repair request.
#[derive(Debug, Clone, Copy)]
pub enum Item<'a> {
    /// A full envelope.
    Envelope(&'a Envelope),
    /// A stub (`PROTOCOL.md` 10.7).
    Stub(&'a Stub),
    /// An envelope that breaks section 4.
    Invalid,
}

/// Why an entry failed the chain check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The entry does not have the next position: `bad_repair`.
    Position,
    /// The envelope fails a check of 10.6: `invalid_record`.
    Invalid(Refusal),
    /// A stub of a type that compaction never makes: `uncovered_stub`
    /// ([LOG-11]). The finish checks the other stubs (`PROTOCOL.md` 14.3).
    Stub,
}

impl ChainError {
    /// The error code of `PROTOCOL.md` 10.3.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Position => "bad_repair",
            Self::Invalid(_) => "invalid_record",
            Self::Stub => "uncovered_stub",
        }
    }
}

/// The result of a chain check.
#[derive(Debug)]
pub struct Chain {
    /// The entries that passed, in position order.
    pub accepted: Vec<Staged>,
    /// The index and cause of the first failed entry.
    pub failure: Option<(usize, ChainError)>,
}

/// True if `got` is the position after `prev` (`PROTOCOL.md` 10.9: dense
/// positions, [LOG-1]).
#[must_use]
pub fn follows(prev: u64, got: u64) -> bool {
    prev.checked_add(1) == Some(got)
}

/// Check repair entries in list order after the head of `view`
/// (`PROTOCOL.md` 10.9 start step 3). `positions[i]` is the position of
/// `items[i]`.
///
/// # Panics
///
/// If `positions` and `items` differ in length.
#[must_use]
pub fn check_chain(view: &impl SpaceView, positions: &[u64], items: &[Item<'_>]) -> Chain {
    assert_eq!(positions.len(), items.len(), "one position for each item");
    let mut over = Overlay::new(view);
    let mut failure = None;
    for (i, (pos, item)) in positions.iter().zip(items).enumerate() {
        if !follows(over.head(), *pos) {
            failure = Some((i, ChainError::Position));
            break;
        }
        let env = match item {
            Item::Envelope(e) => *e,
            Item::Stub(s) => match stub_entry(&over, *pos, s) {
                Ok(st) => {
                    over.apply_stub(st);
                    continue;
                }
                Err(e) => {
                    failure = Some((i, e));
                    break;
                }
            },
            Item::Invalid => {
                failure = Some((
                    i,
                    ChainError::Invalid(Refusal::InvalidRecord(
                        "the envelope breaks section 4".into(),
                    )),
                ));
                break;
            }
        };
        match check_append(&over, env, Mode::Verify) {
            Verdict::Store(a) => over.apply(*a),
            Verdict::Refused(r) => {
                failure = Some((i, ChainError::Invalid(r)));
                break;
            }
            Verdict::Known(_) | Verdict::Conflict(_) => {
                failure = Some((i, ChainError::Invalid(Refusal::DuplicateChange)));
                break;
            }
        }
    }
    Chain {
        accepted: over.into_staged(),
        failure,
    }
}

/// The stub at `position` after the head of `view` (10.9 start step 3): a
/// change stub with a new change ID, or a snapshot stub with no change ID.
///
/// # Errors
///
/// [`ChainError::Stub`] for another type, [`ChainError::Invalid`] for a bad
/// or known change ID.
pub fn stub_entry(view: &impl SpaceView, position: u64, s: &Stub) -> Result<StubEntry, ChainError> {
    let bad = |why: &str| ChainError::Invalid(Refusal::InvalidRecord(why.into()));
    let change_id = match (s.payload_type.as_str(), &s.change_id) {
        ("snailfish.change.v1", Some(text)) => {
            let cid = decode_id::<16>(text, "c_").map_err(|_| bad("stub: bad change_id"))?;
            if view.change(&cid).is_some() {
                return Err(ChainError::Invalid(Refusal::DuplicateChange));
            }
            Some(cid)
        }
        ("snailfish.snapshot.v1", None) => None,
        ("snailfish.change.v1" | "snailfish.snapshot.v1", _) => {
            return Err(bad("stub: change_id only on a change stub"));
        }
        _ => return Err(ChainError::Stub),
    };
    let prev = view
        .digest_at(view.head())
        .ok_or_else(|| bad("stub: no digest before it"))?;
    Ok(StubEntry::new(
        position,
        &s.payload_type,
        change_id,
        s.hash,
        &prev,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn error_codes() {
        assert_eq!(ChainError::Position.code(), "bad_repair");
        assert_eq!(
            ChainError::Invalid(Refusal::BadBase).code(),
            "invalid_record"
        );
        assert_eq!(ChainError::Stub.code(), "uncovered_stub");
    }

    proptest! {
        /// [LOG-1]: only the next position follows, with no overflow.
        #[test]
        fn follows_is_next(prev: u64, got: u64) {
            prop_assert_eq!(follows(prev, got), prev.checked_add(1) == Some(got));
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// `check_chain` parses JSON and verifies Ed25519 signatures, which CBMC
/// cannot finish (see `envelope.rs`). `crates/protocol/tests/repair.rs` and
/// the fuzz targets cover it.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// [LOG-1] (`PROTOCOL.md` 10.9): for every 64-bit pair, a position
    /// follows only the one before it, and `u64::MAX` has no successor.
    #[kani::proof]
    fn follows_is_dense() {
        let prev: u64 = kani::any();
        let got: u64 = kani::any();
        if follows(prev, got) {
            assert!(prev < u64::MAX && got == prev + 1);
        } else {
            assert!(prev == u64::MAX || got != prev + 1);
        }
    }
}
