//! DSSE v1 pre-authentication encoding (PAE).
//!
//! The signature input of every signed record is
//! `PAE(UTF8(payload_type), payload)` (DESIGN.md "Wire format", [WIR-1]).
//! The encoding is from the DSSE protocol, version 1.0.2:
//!
//! ```text
//! PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//! LEN(s) = ASCII decimal byte length of s, no leading zeros
//! ```
//!
//! The lengths make the encoding injective: two different `(type, body)` pairs
//! never give the same bytes. A signature for one record kind is therefore not
//! valid for another kind.

/// The fixed prefix of a DSSE v1 PAE.
const PREFIX: &[u8] = b"DSSEv1";

/// Return the DSSE v1 PAE of a payload type and payload bytes.
///
/// The result is the exact byte string that a signer signs and a verifier
/// verifies. It allocates once, with the exact capacity.
#[must_use]
pub fn encode(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut type_buf = [0u8; MAX_DIGITS];
    let mut body_buf = [0u8; MAX_DIGITS];
    let type_len = write_decimal(payload_type.len(), &mut type_buf);
    let body_len = write_decimal(payload.len(), &mut body_buf);
    // The sum cannot overflow: each part is the length of an existing
    // allocation or a short decimal string, and usize::MAX bytes cannot exist
    // twice in memory.
    let capacity = PREFIX
        .len()
        .saturating_add(type_len.len())
        .saturating_add(payload_type.len())
        .saturating_add(body_len.len())
        .saturating_add(payload.len())
        .saturating_add(4);
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(PREFIX);
    out.push(b' ');
    out.extend_from_slice(type_len);
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body_len);
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// The number of decimal digits of `usize::MAX` on a 64-bit target.
const MAX_DIGITS: usize = 20;

/// Write `n` as ASCII decimal with no leading zeros into `buf`. Return the
/// digits. `usize::to_string` would also work, but the formatting machinery
/// is too large for Kani to check, and this function is small enough to prove.
fn write_decimal(mut n: usize, buf: &mut [u8; MAX_DIGITS]) -> &[u8] {
    let mut start = MAX_DIGITS;
    loop {
        // `start` is at least 1 here: a usize has at most MAX_DIGITS digits,
        // and each iteration writes one digit.
        start = start.saturating_sub(1);
        // n % 10 is at most 9, so the conversion and the addition cannot fail.
        let digit = u8::try_from(n % 10).unwrap_or(0);
        if let Some(slot) = buf.get_mut(start) {
            *slot = b'0'.saturating_add(digit);
        }
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf.get(start..).unwrap_or(&[])
}

/// Split a DSSE v1 PAE back into its payload type and payload.
///
/// Return `None` if the bytes are not a valid PAE: a wrong prefix, a length
/// with a leading zero or a non-digit, a length that does not match, or a
/// payload type that is not UTF-8. The verifier never needs this function.
/// It exists so that tests and fuzz targets can check that [`encode`] is
/// injective.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let rest = bytes.strip_prefix(PREFIX)?.strip_prefix(b" ")?;
    let (type_len, rest) = take_len(rest)?;
    let (payload_type, rest) = split_at_checked(rest, type_len)?;
    let rest = rest.strip_prefix(b" ")?;
    let (body_len, rest) = take_len(rest)?;
    if rest.len() != body_len {
        return None;
    }
    Some((std::str::from_utf8(payload_type).ok()?, rest))
}

/// Parse `LEN SP` at the start of `bytes`. Return the length and the rest.
fn take_len(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let end = bytes.iter().position(|&b| b == b' ')?;
    let (digits, rest) = split_at_checked(bytes, end)?;
    // DSSE: no leading zeros. "0" alone is the length of an empty string.
    if digits.is_empty() || (digits.len() > 1 && digits.first() == Some(&b'0')) {
        return None;
    }
    let mut len: usize = 0;
    for &d in digits {
        let digit = char::from(d).to_digit(10)?;
        len = len
            .checked_mul(10)?
            .checked_add(usize::try_from(digit).ok()?)?;
    }
    Some((len, rest.get(1..)?))
}

/// `slice::split_at` that returns `None` instead of a panic.
fn split_at_checked(bytes: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    (mid <= bytes.len()).then(|| bytes.split_at(mid))
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use proptest::prelude::*;

    /// The test vector of the DSSE protocol, version 1.0.2.
    #[test]
    fn matches_dsse_test_vector() {
        let pae = encode("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            pae,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn empty_type_and_body_encode_zero_lengths() {
        assert_eq!(encode("", b""), b"DSSEv1 0  0 ");
    }

    #[test]
    fn decode_refuses_leading_zero_length() {
        assert_eq!(decode(b"DSSEv1 01 a 0 "), None);
    }

    #[test]
    fn decode_refuses_length_mismatch() {
        assert_eq!(decode(b"DSSEv1 1 a 2 x"), None);
        assert_eq!(decode(b"DSSEv1 1 a 1 xy"), None);
    }

    #[test]
    fn decode_refuses_wrong_prefix() {
        assert_eq!(decode(b"DSSEv2 1 a 1 x"), None);
    }

    #[test]
    fn write_decimal_matches_to_string_at_the_edges() {
        for n in [0, 1, 9, 10, 99, 100, 12_345, usize::MAX] {
            let mut buf = [0u8; super::MAX_DIGITS];
            assert_eq!(super::write_decimal(n, &mut buf), n.to_string().as_bytes());
        }
    }

    #[test]
    fn decode_refuses_overflowing_length() {
        assert_eq!(decode(b"DSSEv1 99999999999999999999999 a 0 "), None);
    }

    proptest! {
        /// Round trip: decode gives back exactly what encode was given.
        #[test]
        fn decode_inverts_encode(t in ".*", body in proptest::collection::vec(any::<u8>(), 0..256)) {
            let pae = encode(&t, &body);
            prop_assert_eq!(decode(&pae), Some((t.as_str(), body.as_slice())));
        }

        /// Strict: if decode accepts bytes, encode gives the same bytes back.
        /// Without this, two byte strings could verify as one signature input.
        #[test]
        fn decode_accepts_only_canonical_encodings(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut input = b"DSSEv1 ".to_vec();
            input.extend_from_slice(&bytes);
            if let Some((t, body)) = decode(&input) {
                prop_assert_eq!(encode(t, body), input);
            }
        }

    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::{decode, encode};

    /// decode inverts encode for any body of up to 3 bytes, with a concrete
    /// payload type. A symbolic payload type makes CBMC run out of memory in
    /// the UTF-8 validation of `decode`, so the type stays concrete here. The
    /// proptest round trip covers symbolic types (sampled).
    fn round_trip<const B: usize>(payload_type: &str) {
        let body: [u8; B] = kani::any();
        let pae = encode(payload_type, &body);
        let decoded = decode(&pae);
        assert!(decoded.is_some());
        if let Some((t, b)) = decoded {
            assert!(t == payload_type);
            assert!(b == &body[..]);
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_inverts_encode_empty_type() {
        round_trip::<3>("");
    }

    // A harness with the 19-byte type "snailfish.change.v1" did not finish in
    // 60 minutes, because of the UTF-8 validation in `decode`. The proptest
    // round trip and the fuzz target cover real record types.

    /// write_decimal gives canonical ASCII decimal digits that parse back to
    /// n, for every n below 100 000 (5 digits). The unit test checks the
    /// edges up to `usize::MAX` against `to_string`.
    #[kani::proof]
    #[kani::unwind(22)]
    fn write_decimal_is_decimal() {
        let n: usize = kani::any_where(|&n| n < 100_000);
        let mut buf = [0u8; super::MAX_DIGITS];
        let digits = super::write_decimal(n, &mut buf);
        // No leading zero, unless n is 0.
        assert!(digits.first() != Some(&b'0') || n == 0);
        // The digits parse back to n.
        let mut back: usize = 0;
        for &d in digits {
            assert!(d.is_ascii_digit());
            back = back * 10 + usize::from(d - b'0');
        }
        assert!(back == n);
    }

    /// `take_len` never panics, and it accepts only canonical lengths: no
    /// empty length, no leading zero, digits only, and a space after it. The
    /// harness calls `take_len` directly, because a harness on `decode` with a
    /// short input never reaches the digit parser (the prefix uses 7 bytes).
    #[kani::proof]
    #[kani::unwind(8)]
    fn take_len_is_strict() {
        let bytes: [u8; 6] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 6);
        let input = &bytes[..len];
        if let Some((n, rest)) = super::take_len(input) {
            let digits = input.len() - rest.len() - 1;
            assert!(digits >= 1);
            assert!(input[digits] == b' ');
            assert!(input[..digits].iter().all(u8::is_ascii_digit));
            assert!(digits == 1 || input[0] != b'0');
            assert!(n < 100_000);
        }
    }

    /// decode never panics on a valid prefix and any 5 bytes after it. The
    /// bytes reach the length parser, the split and the body check.
    #[kani::proof]
    #[kani::unwind(14)]
    fn decode_never_panics() {
        let tail: [u8; 5] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 5);
        let mut bytes = [0u8; 12];
        bytes[..7].copy_from_slice(b"DSSEv1 ");
        bytes[7..7 + len].copy_from_slice(&tail[..len]);
        let _ = decode(&bytes[..7 + len]);
    }
}
