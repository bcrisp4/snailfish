//! The enrollment transcript (`PROTOCOL.md` section 11, [ENR-1] to [ENR-9]):
//! the session code, the QR payload, the commitment and the 6-digit code.
//!
//! `specs/enrollment/` checks the transcript in a symbolic model. The
//! functions here do no I/O and keep no state.

use crate::encoding::{Hash32, hash_frame};
use crate::envelope::Envelope;
use crate::records::{Device, Position, Statement, parse_statement};
use crate::recovery::{RecoveryKeyError, symbols_display, symbols_read};
use crate::sig::PublicKey;

/// The first part of a QR payload (`PROTOCOL.md` 11.1).
pub const PAYLOAD_VERSION: &str = "snailfish-enroll-v1";

/// A session lives this many seconds after the open (`PROTOCOL.md` 10.10).
pub const SESSION_SECONDS: u64 = 600;

/// The two roles of an enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The device that is active in the space and appends the grant.
    Trusted,
    /// The device that joins.
    New,
}

impl Role {
    /// The role letter of a QR payload: `t` or `n`.
    #[must_use]
    pub fn letter(self) -> &'static str {
        match self {
            Self::Trusted => "t",
            Self::New => "n",
        }
    }

    /// The role of a payload letter.
    #[must_use]
    pub fn from_letter(s: &str) -> Option<Self> {
        Self::from_bytes(s.as_bytes())
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            [b't'] => Some(Self::Trusted),
            [b'n'] => Some(Self::New),
            _ => None,
        }
    }
}

/// A session code or payload that breaks `PROTOCOL.md` 11.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    /// A symbol outside the Crockford alphabet.
    BadSymbol,
    /// The code does not hold 32 symbols.
    BadLength,
    /// The check symbols do not match: a typing error.
    BadCheck,
    /// The payload text breaks 11.1, with the cause.
    BadPayload(&'static str),
}

impl std::fmt::Display for CodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSymbol => f.write_str("the code holds a symbol that is not allowed"),
            Self::BadLength => f.write_str("the code does not hold 32 symbols"),
            Self::BadCheck => f.write_str("the code has a typing error"),
            Self::BadPayload(why) => write!(f, "the enrollment payload is not valid: {why}"),
        }
    }
}

impl std::error::Error for CodeError {}

impl From<RecoveryKeyError> for CodeError {
    fn from(e: RecoveryKeyError) -> Self {
        match e {
            RecoveryKeyError::BadSymbol => Self::BadSymbol,
            RecoveryKeyError::BadLength => Self::BadLength,
            RecoveryKeyError::BadCheck => Self::BadCheck,
        }
    }
}

fn check(session: &[u8; 16]) -> [u8; 4] {
    let h = hash_frame(&[b"snailfish.enroll-check.v1", session]);
    let mut out = [0u8; 4];
    out.copy_from_slice(h.get(..4).unwrap_or(&[0; 4]));
    out
}

/// The typed code of a session ID: 8 groups of 4 symbols (`PROTOCOL.md`
/// 11.1).
#[must_use]
pub fn display(session: &[u8; 16]) -> String {
    let mut raw = [0u8; 20];
    raw[..16].copy_from_slice(session);
    raw[16..].copy_from_slice(&check(session));
    symbols_display(&raw)
}

/// Read a typed code with the reader steps of `PROTOCOL.md` section 9 and
/// the check of 11.1.
///
/// # Errors
///
/// [`CodeError`] for a bad symbol, a wrong length or a check mismatch.
pub fn parse_code(text: &str) -> Result<[u8; 16], CodeError> {
    let raw = symbols_read(text)?;
    let mut session = [0u8; 16];
    session.copy_from_slice(&raw[..16]);
    if raw[16..] != check(&session) {
        return Err(CodeError::BadCheck);
    }
    Ok(session)
}

/// A QR payload (`PROTOCOL.md` 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The role of the device that shows the payload.
    pub role: Role,
    /// The relay URL.
    pub relay_url: String,
    /// The session ID.
    pub session: [u8; 16],
}

/// The QR payload text.
#[must_use]
pub fn payload(p: &Payload) -> String {
    format!(
        "{PAYLOAD_VERSION} {} {} {}",
        p.role.letter(),
        p.relay_url,
        display(&p.session).replace('-', "")
    )
}

/// True if `url` is the relay URL form of a payload (`PROTOCOL.md` 11.1):
/// `http://` or `https://` and the authority of 8.3, with the host in
/// lowercase, no default port, and no path, trailing `/`, query, fragment or
/// user part.
#[must_use]
pub fn relay_url_ok(url: &str) -> bool {
    let Some((scheme, auth)) = url.split_once("://") else {
        return false;
    };
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return false,
    };
    !auth.is_empty()
        && !auth.contains(['/', '?', '#', '@', ' '])
        && !auth.bytes().any(|b| b.is_ascii_uppercase())
        && !auth.ends_with(default_port)
}

/// A confirmation that the trusted device refuses (`PROTOCOL.md` 11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmError(pub String);

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the confirmation is not valid: {}", self.0)
    }
}

impl std::error::Error for ConfirmError {}

/// The values of one transcript that a confirmation must name (11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// The session ID.
    pub session: [u8; 16],
    /// The device ID of the trusted device.
    pub t_id: Hash32,
    /// The device object of `new.hello`.
    pub new_device: Device,
    /// The nonce of the trusted device.
    pub t_nonce: [u8; 32],
    /// The nonce of `new.nonce`.
    pub n_nonce: [u8; 32],
}

/// Check a confirmation for a transcript, as the trusted device does
/// before it appends the grant (`PROTOCOL.md` 11.2, [ENR-7]).
///
/// # Errors
///
/// [`ConfirmError`] if the envelope or the payload breaks sections 4 and
/// 6.3, the signature does not verify with the key of `device.sign`, or a
/// field differs from the transcript.
pub fn check_confirm(envelope: &Envelope, t: &Transcript) -> Result<(), ConfirmError> {
    let err = |m: &str| ConfirmError(m.to_owned());
    if envelope.payload_type != "snailfish.confirm.v1" {
        return Err(err("another payload type"));
    }
    let Statement::Confirm {
        session,
        trusted,
        device,
        trusted_nonce,
        new_nonce,
    } = parse_statement(&envelope.payload_type, &envelope.payload)
        .map_err(|e| ConfirmError(e.to_string()))?
    else {
        return Err(err("not a confirmation"));
    };
    // The device object of `new.hello` holds the key, so the transcript
    // check comes first: a signature by another key never verifies.
    if device != t.new_device {
        return Err(err("the device differs from new.hello"));
    }
    PublicKey::from_bytes(&device.keys.sign)
        .and_then(|k| k.verify_record(&envelope.payload_type, &envelope.payload, &envelope.sig))
        .map_err(|e| ConfirmError(e.to_string()))?;
    if session != t.session {
        return Err(err("another session"));
    }
    if trusted != t.t_id {
        return Err(err("another trusted device"));
    }
    if trusted_nonce != t.t_nonce || new_nonce != t.n_nonce {
        return Err(err("another nonce"));
    }
    Ok(())
}

/// Check the checkpoint of `trusted.done`, as the new device does before it
/// fetches the log (`PROTOCOL.md` 11.2, [ENR-8]). `t_sign` is the signing
/// key of `trusted.hello`. Returns the log ID and the position.
///
/// # Errors
///
/// [`ConfirmError`] if the envelope or the payload breaks sections 4 and
/// 6.3, the author is not `t_id`, or the signature does not verify.
pub fn check_checkpoint(
    envelope: &Envelope,
    t_id: &Hash32,
    t_sign: &[u8; 32],
) -> Result<([u8; 16], Position), ConfirmError> {
    if envelope.payload_type != "snailfish.checkpoint.v1" {
        return Err(ConfirmError("another payload type".into()));
    }
    let Statement::Checkpoint { log, author, at } =
        parse_statement(&envelope.payload_type, &envelope.payload)
            .map_err(|e| ConfirmError(e.to_string()))?
    else {
        return Err(ConfirmError("not a checkpoint".into()));
    };
    if &author != t_id {
        return Err(ConfirmError(
            "the checkpoint author is not the trusted device".into(),
        ));
    }
    PublicKey::from_bytes(t_sign)
        .and_then(|k| k.verify_record(&envelope.payload_type, &envelope.payload, &envelope.sig))
        .map_err(|e| ConfirmError(e.to_string()))?;
    Ok((log, at))
}

/// Read a QR payload text.
///
/// # Errors
///
/// [`CodeError::BadPayload`] for another first part, role or part count,
/// or a relay URL that breaks 8.3. The code errors of [`parse_code`].
pub fn parse_payload(text: &str) -> Result<Payload, CodeError> {
    let parts: Vec<&str> = text.split(' ').collect();
    let [version, role, relay_url, symbols] = parts.as_slice() else {
        return Err(CodeError::BadPayload("it must have 4 parts"));
    };
    if *version != PAYLOAD_VERSION {
        return Err(CodeError::BadPayload("unknown first part"));
    }
    let role = Role::from_letter(role).ok_or(CodeError::BadPayload("unknown role"))?;
    if !relay_url_ok(relay_url) {
        return Err(CodeError::BadPayload(
            "the relay URL breaks PROTOCOL.md 8.3",
        ));
    }
    Ok(Payload {
        role,
        relay_url: (*relay_url).to_owned(),
        session: parse_code(symbols)?,
    })
}

/// The commitment of the trusted device (`PROTOCOL.md` 11.2, [ENR-4]).
#[must_use]
pub fn commitment(session: &[u8; 16], t_id: &Hash32, n_id: &Hash32, t_nonce: &[u8; 32]) -> Hash32 {
    hash_frame(&[
        b"snailfish.enroll-commit.v1",
        session,
        b"trusted",
        t_id,
        b"new",
        n_id,
        t_nonce,
    ])
}

/// The 6-digit code that both devices show (`PROTOCOL.md` 11.2, [ENR-7]).
#[must_use]
pub fn code(
    session: &[u8; 16],
    t_id: &Hash32,
    n_id: &Hash32,
    t_nonce: &[u8; 32],
    n_nonce: &[u8; 32],
) -> String {
    let digits = hash_frame(&[
        b"snailfish.enroll-code.v1",
        session,
        b"trusted",
        t_id,
        b"new",
        n_id,
        t_nonce,
        n_nonce,
    ]);
    format_code(code_value(&digits))
}

/// The code value of a code digest: the first 8 bytes as an unsigned
/// big-endian integer, modulo 1,000,000. Always below 1,000,000.
#[must_use]
pub fn code_value(digits: &Hash32) -> u32 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&digits[..8]);
    // The remainder is below 1,000,000, so it fits in a u32.
    u32::try_from(u64::from_be_bytes(first) % 1_000_000).unwrap_or(0)
}

/// A code value as 6 decimal digits with leading zeros.
#[must_use]
pub fn format_code(value: u32) -> String {
    format!("{:06}", value % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The app shows this text to a user who typed the code.
    #[test]
    fn check_error_tells_the_user_about_a_typing_error() {
        assert_eq!(
            CodeError::BadCheck.to_string(),
            "the code has a typing error"
        );
    }

    /// A code digest whose first 8 bytes are a multiple of 1,000,000 gives
    /// `000000`, and 999,999 more gives `999999`: the two ends of 11.2.
    #[test]
    fn code_value_boundaries() {
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&1_000_000u64.to_be_bytes());
        assert_eq!(format_code(code_value(&d)), "000000");
        d[..8].copy_from_slice(&1_999_999u64.to_be_bytes());
        assert_eq!(format_code(code_value(&d)), "999999");
        d[..8].copy_from_slice(&42u64.to_be_bytes());
        d[8..].fill(0xff);
        assert_eq!(format_code(code_value(&d)), "000042");
        d[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(code_value(&d), u32::try_from(u64::MAX % 1_000_000).unwrap());
    }

    /// A payload reader refuses each break of 11.1.
    #[test]
    fn payload_refusals() {
        let ok = payload(&Payload {
            role: Role::Trusted,
            relay_url: "https://sync.example.net".into(),
            session: [7; 16],
        });
        assert!(parse_payload(&ok).is_ok());
        for bad in [
            ok.replacen("snailfish-enroll-v1", "snailfish-enroll-v2", 1),
            ok.replacen(" t ", " x ", 1),
            ok.replacen("https://sync.example.net", "https://sync.example.net/p", 1),
            ok.replacen("https://sync.example.net", "ftp://sync.example.net", 1),
            ok.replacen("https://sync.example.net", "https://Sync.example.net", 1),
            ok.replacen(
                "https://sync.example.net",
                "https://sync.example.net:443",
                1,
            ),
            ok.replacen("https://sync.example.net", "https://sync.example.net/", 1),
            format!("{ok} extra"),
            ok.replacen(' ', "  ", 1),
        ] {
            assert!(
                matches!(parse_payload(&bad), Err(CodeError::BadPayload(_))),
                "{bad}"
            );
        }
        let last = ok.len() - 1;
        let mut typo = ok.clone().into_bytes();
        typo[last] = if typo[last] == b'0' { b'1' } else { b'0' };
        assert_eq!(
            parse_payload(std::str::from_utf8(&typo).unwrap()),
            Err(CodeError::BadCheck)
        );
    }

    /// [ENR-8], `specs/enrollment/cp_unsigned.pv`: the new device accepts
    /// only a checkpoint by the trusted device of the transcript, with a
    /// valid signature and the checkpoint payload type.
    #[test]
    fn checkpoint_check_refuses_other_signers_and_types() {
        use crate::sig::SecretKey;
        let t = SecretKey::from_seed(&[1; 32]);
        let t_id = [2; 32];
        let at = Position {
            position: 4,
            digest: [3; 32],
        };
        let p = crate::write::checkpoint(&[5; 16], &t_id, &at);
        let ty = "snailfish.checkpoint.v1";
        let env = |key: &SecretKey, ty: &str| Envelope {
            payload_type: ty.into(),
            payload: p.clone(),
            sig: key.sign_record(ty, &p),
        };
        assert_eq!(
            check_checkpoint(&env(&t, ty), &t_id, &t.public()),
            Ok(([5; 16], at))
        );
        let other = SecretKey::from_seed(&[9; 32]);
        assert!(check_checkpoint(&env(&other, ty), &t_id, &t.public()).is_err());
        assert!(check_checkpoint(&env(&t, ty), &[7; 32], &t.public()).is_err());
        assert!(check_checkpoint(&env(&t, "snailfish.delete.v1"), &t_id, &t.public()).is_err());
    }

    proptest! {
        #[test]
        fn code_round_trip(session in any::<[u8; 16]>()) {
            let text = display(&session);
            prop_assert_eq!(text.len(), 39);
            prop_assert_eq!(parse_code(&text), Ok(session));
            prop_assert_eq!(parse_code(&text.to_lowercase().replace('-', " ")), Ok(session));
        }

        /// A one-symbol typing error gives an error, not another session.
        #[test]
        fn one_symbol_change_fails_the_check(session in any::<[u8; 16]>(), pos in 0usize..32, to in 0usize..32) {
            let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
            let mut sym: Vec<u8> = display(&session).bytes().filter(|&c| c != b'-').collect();
            prop_assume!(sym[pos] != alphabet[to]);
            sym[pos] = alphabet[to];
            prop_assert_eq!(parse_code(std::str::from_utf8(&sym).unwrap()), Err(CodeError::BadCheck));
        }

        /// The recovery check and the enrollment check are separate, so a
        /// recovery key never reads as a session code.
        #[test]
        fn recovery_key_is_not_a_session_code(secret in any::<[u8; 16]>()) {
            let text = crate::recovery::display(&secret);
            prop_assert_eq!(parse_code(&text), Err(CodeError::BadCheck));
        }

        #[test]
        fn payload_round_trip(session in any::<[u8; 16]>(), trusted in any::<bool>(), port in 1u16..) {
            let p = Payload {
                role: if trusted { Role::Trusted } else { Role::New },
                relay_url: format!("http://relay.example.ts.net:{port}"),
                session,
            };
            prop_assert_eq!(parse_payload(&payload(&p)), Ok(p));
        }

        /// `parse_payload` never panics on any text.
        #[test]
        fn parse_payload_never_panics(text in ".{0,120}") {
            let _ = parse_payload(&text);
        }

        /// [ENR-4] [ENR-7]: the commitment and the code change with each
        /// input. A relay that changes one key or one nonce changes the
        /// commitment, and the role labels keep the two IDs apart.
        #[test]
        fn transcript_binds_each_input(
            s in any::<[u8; 16]>(), t in any::<[u8; 32]>(), n in any::<[u8; 32]>(),
            tn in any::<[u8; 32]>(), nn in any::<[u8; 32]>(), flip in 0usize..32,
        ) {
            prop_assume!(t != n);
            let c = commitment(&s, &t, &n, &tn);
            prop_assert_ne!(c, commitment(&s, &n, &t, &tn));
            let mut tn2 = tn;
            tn2[flip] ^= 1;
            prop_assert_ne!(c, commitment(&s, &t, &n, &tn2));
            let mut s2 = s;
            s2[flip % 16] ^= 1;
            prop_assert_ne!(c, commitment(&s2, &t, &n, &tn));
            let k = code(&s, &t, &n, &tn, &nn);
            prop_assert_eq!(k.len(), 6);
            prop_assert!(k.bytes().all(|b| b.is_ascii_digit()));
            prop_assert_eq!(&k, &code(&s, &t, &n, &tn, &nn));
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// No harness covers `display`, `parse_code`, `commitment` or `code`: each
/// runs SHA-256, which CBMC cannot finish. The property tests above cover
/// them. The harnesses prove the pure parts of 11.1 and 11.2.
#[cfg(kani)]
mod proofs {
    use super::{Role, code_value};

    /// `PROTOCOL.md` 11.2 ([ENR-7]): the code value of every digest is below
    /// 1,000,000, so `format_code` never drops a digit. The last 24 bytes
    /// are fixed: `code_value` reads only the first 8 (the property test
    /// `code_value_boundaries` covers that). A second symbolic reduction
    /// to compare the value did not finish in 13 minutes.
    #[kani::proof]
    fn code_value_is_below_one_million() {
        let mut d = [0u8; 32];
        let first: [u8; 8] = kani::any();
        d[..8].copy_from_slice(&first);
        assert!(code_value(&d) < 1_000_000);
    }

    /// `PROTOCOL.md` 11.1 ([ENR-1]): only the one-byte texts `t` and `n`
    /// name a role, for every text of up to 2 bytes, and each role letter
    /// reads back to its role. The harness uses the byte reader: a symbolic
    /// `&str` did not finish in 10 minutes.
    #[kani::proof]
    fn role_letters_are_exact() {
        for r in [Role::Trusted, Role::New] {
            assert!(Role::from_letter(r.letter()) == Some(r));
        }
        let b: [u8; 2] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 2);
        let text = &b[..len];
        let want = len == 1 && (b[0] == b't' || b[0] == b'n');
        assert!(Role::from_bytes(text).is_some() == want);
    }
}
