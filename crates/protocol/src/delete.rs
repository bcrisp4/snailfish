//! The checks of a space deletion (`PROTOCOL.md` 10.12, [LOG-13]) that do
//! not need the relay storage: the statement form, its signature and its
//! expiry. The relay checks `head` against its log.

use crate::encoding::Hash32;
use crate::envelope::Envelope;
use crate::records::{Author, Position, Statement, parse_statement};
use crate::sig::PublicKey;

/// The payload type of a deletion statement.
pub const DELETE_TYPE: &str = "snailfish.delete.v1";

/// The most seconds between the relay time and `expires` (10.12 step 7).
pub const MAX_WINDOW: u64 = 600;

/// A checked deletion statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delete {
    /// The author: the request signer.
    pub author: Author,
    /// The log entry that the author verified.
    pub head: Position,
    /// The end of the time in which the statement is valid.
    pub expires: u64,
}

/// True if `expires` is after `now` and at most [`MAX_WINDOW`] seconds
/// after it (10.12 step 7).
#[must_use]
pub fn expiry_ok(expires: u64, now: u64) -> bool {
    expires
        .checked_sub(now)
        .is_some_and(|d| d > 0 && d <= MAX_WINDOW)
}

/// 10.12 step 4: `env` is a `snailfish.delete.v1` statement for `log_id`
/// whose author is `signer` and whose signature verifies with `key`.
///
/// # Errors
///
/// The reason, for `invalid_record`.
pub fn check_statement(
    env: &Envelope,
    log_id: &[u8; 16],
    signer: &Author,
    key: &[u8; 32],
) -> Result<Delete, String> {
    if env.payload_type != DELETE_TYPE {
        return Err("the statement is not a snailfish.delete.v1 statement".into());
    }
    let Statement::Delete {
        log,
        author,
        head,
        expires,
    } = parse_statement(&env.payload_type, &env.payload).map_err(|e| e.to_string())?
    else {
        return Err("the statement is not a snailfish.delete.v1 statement".into());
    };
    if &log != log_id {
        return Err("log: the statement names another log".into());
    }
    if &author != signer {
        return Err("author: the statement author is not the request signer".into());
    }
    PublicKey::from_bytes(key)
        .and_then(|k| k.verify_record(&env.payload_type, &env.payload, &env.sig))
        .map_err(|e| e.to_string())?;
    Ok(Delete {
        author,
        head,
        expires,
    })
}

/// 10.12 step 6: `head` is an entry of a log whose digest at
/// `head.position` is `digest_at`, and whose head is `relay_head`.
#[must_use]
pub fn head_ok(head: &Position, relay_head: u64, digest_at: Option<Hash32>) -> bool {
    head.position <= relay_head && digest_at == Some(head.digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::SecretKey;
    use crate::write;
    use proptest::prelude::*;

    fn signed(seed: [u8; 32], payload: &[u8]) -> Envelope {
        let k = SecretKey::from_seed(&seed);
        let sig = k.sign_record(DELETE_TYPE, payload);
        Envelope::parse(write_env(payload, &sig).as_bytes()).unwrap()
    }

    fn write_env(payload: &[u8], sig: &[u8; 64]) -> String {
        crate::envelope::write_json(DELETE_TYPE, payload, sig, "x")
    }

    proptest! {
        /// 10.12 step 7: the window is (now, now + 600], with no overflow.
        #[test]
        fn expiry_window(expires: u64, now: u64) {
            prop_assert_eq!(
                expiry_ok(expires, now),
                expires > now && u128::from(expires) <= u128::from(now) + 600
            );
        }

        /// [LOG-13]: a statement passes only with its own log, its own
        /// author and the key that signed it.
        #[test]
        fn statement_binds_log_author_and_key(seed: [u8; 32], other: [u8; 32], log: [u8; 16], pos in 0u64..1000) {
            prop_assume!(seed != other);
            let k = SecretKey::from_seed(&seed);
            let id = crate::keys::device_id(&k.public(), &[0; crate::keys::SEAL_PK_LEN]);
            let author = Author::Device(id);
            let head = Position { position: pos, digest: [7; 32] };
            let env = signed(seed, &write::delete(&log, &author, &head, 99));
            let key = k.public();
            prop_assert_eq!(check_statement(&env, &log, &author, &key), Ok(Delete { author, head, expires: 99 }));
            let mut log2 = log;
            log2[0] ^= 1;
            prop_assert!(check_statement(&env, &log2, &author, &key).is_err());
            prop_assert!(check_statement(&env, &log, &Author::Recovery(id), &key).is_err());
            let wrong = SecretKey::from_seed(&other).public();
            prop_assert!(check_statement(&env, &log, &author, &wrong).is_err());
        }
    }

    #[test]
    fn head_must_be_a_relay_entry() {
        let h = Position {
            position: 3,
            digest: [1; 32],
        };
        assert!(head_ok(&h, 3, Some([1; 32])));
        assert!(head_ok(&h, 9, Some([1; 32])));
        assert!(!head_ok(&h, 2, Some([1; 32])));
        assert!(!head_ok(&h, 3, Some([2; 32])));
        assert!(!head_ok(&h, 3, None));
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// 10.12 step 7 ([LOG-13]): for every 64-bit pair, a statement is in
    /// its window only if `now < expires <= now + 600`, with no overflow.
    #[kani::proof]
    fn expiry_window_is_exact() {
        let expires: u64 = kani::any();
        let now: u64 = kani::any();
        if expiry_ok(expires, now) {
            assert!(now < expires && expires - now <= MAX_WINDOW);
        } else {
            assert!(expires <= now || expires - now > MAX_WINDOW);
        }
    }

    /// 10.12 step 6: a head after the relay head never passes.
    #[kani::proof]
    fn head_after_relay_head_fails() {
        let pos: u64 = kani::any();
        let relay: u64 = kani::any();
        let d: [u8; 32] = [kani::any(); 32];
        let h = Position {
            position: pos,
            digest: d,
        };
        if head_ok(&h, relay, Some(d)) {
            assert!(pos <= relay);
        }
        assert!(!head_ok(&h, relay, None));
    }
}
