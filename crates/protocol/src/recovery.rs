//! Recovery key encoding and derivation (`PROTOCOL.md` section 9).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::encoding::hash_frame;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SYMBOLS: usize = 32;

/// A malformed recovery key text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryKeyError {
    /// A symbol outside the Crockford alphabet, for example `U`.
    BadSymbol,
    /// The text does not hold 32 symbols.
    BadLength,
    /// The check symbols do not match. The text has a typing error.
    BadCheck,
}

impl std::fmt::Display for RecoveryKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadSymbol => "the recovery key holds a symbol that is not allowed",
            Self::BadLength => "the recovery key does not hold 32 symbols",
            Self::BadCheck => "the recovery key has a typing error",
        })
    }
}

impl std::error::Error for RecoveryKeyError {}

/// The 4 check bytes of a secret.
fn check(secret: &[u8; 16]) -> [u8; 4] {
    let h = hash_frame(&[b"snailfish.recovery-check.v1", secret]);
    let mut out = [0u8; 4];
    out.copy_from_slice(h.get(..4).unwrap_or(&[0; 4]));
    out
}

/// The display form of a recovery secret: 8 groups of 4 symbols.
#[must_use]
pub fn display(secret: &[u8; 16]) -> String {
    let mut raw = [0u8; 20];
    raw[..16].copy_from_slice(secret);
    raw[16..].copy_from_slice(&check(secret));
    symbols_display(&raw)
}

/// 20 bytes as 32 Crockford symbols in 8 groups of 4, joined with `-`
/// (`PROTOCOL.md` sections 9 and 11.1).
pub(crate) fn symbols_display(raw: &[u8; 20]) -> String {
    // 20 bytes are 160 bits, exactly 32 symbols of 5 bits.
    let mut bits: u64 = 0;
    let mut n: u32 = 0;
    let mut out = String::with_capacity(39);
    let mut count = 0usize;
    for &byte in raw {
        bits = (bits << 8) | u64::from(byte);
        n = n.saturating_add(8);
        while n >= 5 {
            n = n.saturating_sub(5);
            let idx = usize::try_from((bits >> n) & 31).unwrap_or(0);
            if count > 0 && count.is_multiple_of(4) {
                out.push('-');
            }
            out.push(char::from(*ALPHABET.get(idx).unwrap_or(&b'0')));
            count = count.saturating_add(1);
        }
        bits &= (1u64 << n).saturating_sub(1);
    }
    out
}

/// The value of one symbol after the reader mapping of `PROTOCOL.md` 9.
fn symbol_value(c: u8) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|p| u8::try_from(p).ok())
}

/// Read a recovery key that the user typed.
///
/// # Errors
///
/// [`RecoveryKeyError`] for a symbol outside the alphabet, a wrong number of
/// symbols, or a check mismatch.
pub fn parse(text: &str) -> Result<[u8; 16], RecoveryKeyError> {
    let raw = symbols_read(text)?;
    let mut secret = [0u8; 16];
    secret.copy_from_slice(&raw[..16]);
    if raw[16..] != check(&secret) {
        return Err(RecoveryKeyError::BadCheck);
    }
    Ok(secret)
}

/// Read 32 Crockford symbols into 20 bytes with the reader steps 1 to 5 of
/// `PROTOCOL.md` section 9, except the check.
pub(crate) fn symbols_read(text: &str) -> Result<[u8; 20], RecoveryKeyError> {
    let mut values = Vec::with_capacity(SYMBOLS);
    for c in text.bytes() {
        if c == b'-' || c == b' ' {
            continue;
        }
        values.push(symbol_value(c).ok_or(RecoveryKeyError::BadSymbol)?);
    }
    if values.len() != SYMBOLS {
        return Err(RecoveryKeyError::BadLength);
    }
    let mut raw = [0u8; 20];
    let mut bits: u64 = 0;
    let mut n: u32 = 0;
    let mut i = 0usize;
    for v in values {
        bits = (bits << 5) | u64::from(v);
        n = n.saturating_add(5);
        if n >= 8 {
            n = n.saturating_sub(8);
            if let Some(slot) = raw.get_mut(i) {
                *slot = u8::try_from((bits >> n) & 0xff).unwrap_or(0);
            }
            i = i.saturating_add(1);
            bits &= (1u64 << n).saturating_sub(1);
        }
    }
    Ok(raw)
}

/// The Ed25519 seed and the X-Wing seed of a recovery secret.
#[must_use]
pub fn derive(secret: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(b"snailfish.recovery.v1"), secret);
    let mut sign = [0u8; 32];
    let mut seal = [0u8; 32];
    // Expand fails only for an output longer than 255 * 32 bytes.
    let _ = hk.expand(b"snailfish.recovery.sign.v1", &mut sign);
    let _ = hk.expand(b"snailfish.recovery.seal.v1", &mut seal);
    (sign, seal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app shows this text to a user who typed the key.
    #[test]
    fn check_error_tells_the_user_about_a_typing_error() {
        assert_eq!(
            RecoveryKeyError::BadCheck.to_string(),
            "the recovery key has a typing error"
        );
    }
    use proptest::prelude::*;

    proptest! {
        /// Different secrets give different seeds, and the signing seed
        /// differs from the sealing seed, so one leak does not give the other
        /// key (`PROTOCOL.md` section 9).
        #[test]
        fn derive_separates_secrets_and_purposes(a in any::<[u8; 16]>(), b in any::<[u8; 16]>()) {
            let (sa, ea) = derive(&a);
            let (sb, eb) = derive(&b);
            prop_assert_ne!(sa, ea);
            prop_assert_eq!(a == b, sa == sb);
            prop_assert_eq!(a == b, ea == eb);
            prop_assert_ne!(sa, [0u8; 32]);
            prop_assert_ne!(ea, [0u8; 32]);
            prop_assert_eq!(derive(&a), (sa, ea));
        }

        /// `parse` never panics on any text.
        #[test]
        fn parse_never_panics(text in ".{0,60}") {
            let _ = parse(&text);
        }

        #[test]
        fn display_round_trip(secret in any::<[u8; 16]>()) {
            let text = display(&secret);
            prop_assert_eq!(text.len(), 39);
            prop_assert_eq!(parse(&text), Ok(secret));
            prop_assert_eq!(parse(&text.to_lowercase().replace('-', " ")), Ok(secret));
        }

        /// The check must catch each change of one symbol, because a user
        /// who types one wrong symbol must get an error, not a wrong key.
        #[test]
        fn one_symbol_change_fails_the_check(secret in any::<[u8; 16]>(), pos in 0usize..32, delta in 1u8..32) {
            let mut sym: Vec<u8> = display(&secret).bytes().filter(|&c| c != b'-').collect();
            let old = symbol_value(sym[pos]).unwrap();
            sym[pos] = ALPHABET[usize::from(old.wrapping_add(delta) % 32)];
            prop_assert_eq!(parse(std::str::from_utf8(&sym).unwrap()), Err(RecoveryKeyError::BadCheck));
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// No harness covers `display`, `parse`, `check` or `derive`. Each one runs
/// SHA-256 or HKDF, which CBMC cannot finish, and the 5-bit packing in
/// `display` and `parse` is not a separate function. The property tests
/// `display_round_trip` and `one_symbol_change_fails_the_check` cover the
/// packing. The fuzz target `recovery_key` covers `parse` on arbitrary text.
#[cfg(kani)]
mod proofs {
    use super::{ALPHABET, symbol_value};

    /// `PROTOCOL.md` section 9: the reader maps each of the 32 alphabet
    /// symbols to its index, in both cases, maps `O` to 0 and `I` and `L` to
    /// 1, and refuses each other byte. Exhaustive over all 256 bytes.
    #[kani::proof]
    #[kani::unwind(34)]
    fn symbol_value_accepts_exactly_the_reader_alphabet() {
        let c: u8 = kani::any();
        let v = symbol_value(c);
        let upper = c.to_ascii_uppercase();
        let in_alphabet = ALPHABET.contains(&upper);
        let alias = matches!(upper, b'O' | b'I' | b'L');
        assert!(v.is_some() == (in_alphabet || alias));
        if let Some(v) = v {
            assert!(v < 32);
            if in_alphabet {
                assert!(ALPHABET[usize::from(v)] == upper);
            }
            if upper == b'O' {
                assert!(v == 0);
            }
            if upper == b'I' || upper == b'L' {
                assert!(v == 1);
            }
        }
        // U is not in the alphabet (it is easy to read as V).
        assert!(symbol_value(b'U').is_none() && symbol_value(b'u').is_none());
    }
}
