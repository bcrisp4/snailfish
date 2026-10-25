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
    // 20 bytes are 160 bits, exactly 32 symbols of 5 bits.
    let mut bits: u64 = 0;
    let mut n: u32 = 0;
    let mut out = String::with_capacity(39);
    let mut count = 0usize;
    for byte in raw {
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
    let mut secret = [0u8; 16];
    secret.copy_from_slice(&raw[..16]);
    if raw[16..] != check(&secret) {
        return Err(RecoveryKeyError::BadCheck);
    }
    Ok(secret)
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
    use proptest::prelude::*;

    proptest! {
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
