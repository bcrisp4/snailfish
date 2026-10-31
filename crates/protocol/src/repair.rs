//! The chain check of a repair request (`PROTOCOL.md` 10.9, [LOG-10] to
//! [LOG-12]).
//!
//! The relay checks each entry against the log and the entries before it,
//! with the fetch rules of [`Mode::Verify`]: no size limit and no hold,
//! because each record was in the log before. The check stops at the first
//! failed entry. The relay accepts a request signer that the passed entries
//! make active ([LOG-12]), so it needs the passed prefix also when an entry
//! fails.

use crate::envelope::Envelope;
use crate::space::{Accepted, Mode, Overlay, Refusal, SpaceView, Verdict, check_append};

/// One entry of a repair request.
#[derive(Debug, Clone, Copy)]
pub enum Item<'a> {
    /// A full envelope.
    Envelope(&'a Envelope),
    /// A stub (`PROTOCOL.md` 10.7).
    Stub,
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
    /// A stub that no usable snapshot covers: `uncovered_stub` ([LOG-11]).
    /// M3 has no snapshot, so every stub fails.
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
    pub accepted: Vec<Accepted>,
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
            Item::Stub => {
                failure = Some((i, ChainError::Stub));
                break;
            }
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
        accepted: over.into_added(),
        failure,
    }
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
