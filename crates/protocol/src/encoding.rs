//! Common encodings: frames, identifiers and binary fields (`PROTOCOL.md`
//! section 2).

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD, STANDARD_NO_PAD_INDIFFERENT, URL_SAFE_NO_PAD_INDIFFERENT,
};
use sha2::{Digest as _, Sha256};

/// A 32-byte SHA-256 output.
pub type Hash32 = [u8; 32];

/// Encode a list of byte strings as a frame: each part is an 8-byte
/// big-endian length, then the part (`PROTOCOL.md` 2.1).
///
/// The encoding is injective, so two different lists never give the same
/// bytes, and one hash input cannot stand for another.
#[must_use]
pub fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let total = parts.iter().fold(0usize, |acc, p| {
        acc.saturating_add(8).saturating_add(p.len())
    });
    let mut out = Vec::with_capacity(total);
    for part in parts {
        out.extend_from_slice(&u64be(part.len() as u64));
        out.extend_from_slice(part);
    }
    out
}

/// An integer as 8 big-endian bytes.
#[must_use]
pub fn u64be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// SHA-256 of a frame.
#[must_use]
pub fn hash_frame(parts: &[&[u8]]) -> Hash32 {
    Sha256::digest(frame(parts)).into()
}

/// A malformed identifier or binary field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingError(pub &'static str);

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for EncodingError {}

/// Decode `prefix` followed by exactly `2 * N` lowercase hex digits.
///
/// # Errors
///
/// Refuses a wrong prefix, a wrong length, uppercase hex and any non-hex
/// symbol (`PROTOCOL.md` 2.2).
pub fn decode_id<const N: usize>(text: &str, prefix: &str) -> Result<[u8; N], EncodingError> {
    let hex = text
        .strip_prefix(prefix)
        .ok_or(EncodingError("identifier has the wrong prefix"))?;
    if hex.len() != N.saturating_mul(2) {
        return Err(EncodingError("identifier has the wrong length"));
    }
    let mut out = [0u8; N];
    for (slot, [hi, lo]) in out.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        *slot = (lower_hex(*hi)? << 4) | lower_hex(*lo)?;
    }
    Ok(out)
}

/// The value of one lowercase hex digit.
fn lower_hex(c: u8) -> Result<u8, EncodingError> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => Err(EncodingError(
            "identifier holds a symbol that is not lowercase hex",
        )),
    }
}

/// Encode `prefix` followed by lowercase hex.
#[must_use]
pub fn encode_id(prefix: &str, bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(prefix.len().saturating_add(bytes.len().saturating_mul(2)));
    out.push_str(prefix);
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&c) = HEX.get(usize::from(nibble)) {
                out.push(char::from(c));
            }
        }
    }
    out
}

/// Decode a payload binary field: standard base64 with padding, in its one
/// canonical form (`PROTOCOL.md` 2.3).
///
/// # Errors
///
/// Refuses the URL-safe alphabet, missing or extra padding, non-zero
/// trailing bits and whitespace.
pub fn decode_b64_strict(text: &str) -> Result<Vec<u8>, EncodingError> {
    // The default STANDARD engine requires canonical padding and refuses
    // non-zero trailing bits.
    STANDARD
        .decode(text)
        .map_err(|_| EncodingError("binary field is not canonical standard base64"))
}

/// Encode a payload binary field.
#[must_use]
pub fn encode_b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode an envelope field: the standard or the URL-safe alphabet, with or
/// without padding (`PROTOCOL.md` section 4). The envelope is unsigned, so
/// a looser form changes no signed byte.
///
/// # Errors
///
/// Refuses mixed alphabets, symbols outside both alphabets and non-zero
/// trailing bits.
pub fn decode_b64_loose(text: &str) -> Result<Vec<u8>, EncodingError> {
    let url = text.bytes().any(|c| c == b'-' || c == b'_');
    let engine = if url {
        &URL_SAFE_NO_PAD_INDIFFERENT
    } else {
        &STANDARD_NO_PAD_INDIFFERENT
    };
    engine
        .decode(text)
        .map_err(|_| EncodingError("envelope field is not base64"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn frame_matches_protocol_vector() {
        // PROTOCOL.md 2.1.
        assert_eq!(
            frame(&[b"ab", b""]),
            [0, 0, 0, 0, 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn decode_id_refuses_uppercase_prefix_and_length() {
        let ok = "c_00112233445566778899aabbccddeeff";
        assert_eq!(
            decode_id::<16>(ok, "c_").map(|b| encode_id("c_", &b)),
            Ok(ok.to_owned())
        );
        assert!(decode_id::<16>("c_00112233445566778899AABBCCDDEEFF", "c_").is_err());
        assert!(decode_id::<16>("l_00112233445566778899aabbccddeeff", "c_").is_err());
        assert!(decode_id::<16>("c_00112233445566778899aabbccddee", "c_").is_err());
        assert!(decode_id::<16>("c_00112233445566778899aabbccddeeffaa", "c_").is_err());
        assert!(decode_id::<16>("c_0011223344556677889gaabbccddeeff", "c_").is_err());
    }

    #[test]
    fn strict_base64_has_one_form() {
        assert_eq!(decode_b64_strict("AAE="), Ok(vec![0, 1]));
        for bad in ["AAE", "AAE==", "AAF=", "AA E=", "AA-_", "AAE=\n"] {
            assert!(decode_b64_strict(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loose_base64_accepts_both_alphabets_and_padding_choices() {
        for ok in ["+/8=", "+/8", "-_8=", "-_8"] {
            assert_eq!(decode_b64_loose(ok), Ok(vec![0xfb, 0xff]), "{ok}");
        }
        assert!(decode_b64_loose("+_8=").is_err());
    }

    proptest! {
        /// Without injectivity two different hash inputs could collide
        /// before SHA-256 sees them.
        #[test]
        fn frame_is_injective(a in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..6), 0..4),
                              b in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..6), 0..4)) {
            let fa = frame(&a.iter().map(Vec::as_slice).collect::<Vec<_>>());
            let fb = frame(&b.iter().map(Vec::as_slice).collect::<Vec<_>>());
            prop_assert_eq!(fa == fb, a == b);
        }

        #[test]
        fn id_round_trip(bytes in any::<[u8; 32]>()) {
            prop_assert_eq!(decode_id::<32>(&encode_id("d_", &bytes), "d_"), Ok(bytes));
        }

        #[test]
        fn strict_base64_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(decode_b64_strict(&encode_b64(&bytes)), Ok(bytes));
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::{decode_id, frame};

    /// [LOG-3] [LOG-4] [LOG-5] rely on the frame: for two parts of up to 2
    /// bytes each, the frame is exactly the length prefixes and the parts.
    #[kani::proof]
    #[kani::unwind(10)]
    fn frame_layout() {
        let a: [u8; 2] = kani::any();
        let b: [u8; 2] = kani::any();
        let la: usize = kani::any_where(|&n| n <= 2);
        let lb: usize = kani::any_where(|&n| n <= 2);
        let out = frame(&[&a[..la], &b[..lb]]);
        assert!(out.len() == 16 + la + lb);
        assert!(out[7] as usize == la);
        assert!(out[..7].iter().all(|&x| x == 0));
        assert!(&out[8..8 + la] == &a[..la]);
        assert!(out[8 + la + 7] as usize == lb);
        assert!(&out[16 + la..] == &b[..lb]);
    }

    /// The identifier reader never panics, and it accepts only lowercase hex
    /// digits after the prefix.
    #[kani::proof]
    #[kani::unwind(8)]
    fn decode_id_is_strict() {
        let bytes: [u8; 6] = kani::any();
        if let Ok(text) = core::str::from_utf8(&bytes) {
            if let Ok(_) = decode_id::<2>(text, "c_") {
                assert!(bytes[0] == b'c' && bytes[1] == b'_');
                assert!(
                    bytes[2..]
                        .iter()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
                );
            }
        }
    }
}
