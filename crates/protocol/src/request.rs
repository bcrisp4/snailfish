//! RFC 9421 request signatures with Ed25519 (`PROTOCOL.md` section 8).
//!
//! This module accepts exactly one form of RFC 9421: one label, five
//! components in a fixed order, and fixed parameters. It refuses each other
//! form, also a form that RFC 9421 allows. The nonce store is relay state, so
//! [`check`] returns the nonce and the caller stores it (8.6 step 7).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};

use crate::encoding::{Hash32, decode_id, encode_id};
use crate::sig::{PublicKey, SecretKey};

/// The `tag` parameter. It separates request signatures from other uses of
/// a device key.
pub const TAG: &str = "snailfish.request.v1";
/// The longest validity of one signature, in seconds (T5).
pub const MAX_LIFETIME: u64 = 300;
/// The most that `created` can be after the relay time, in seconds.
pub const MAX_FUTURE: u64 = 60;
/// The largest integer of a parameter: 2^53 - 1.
pub const MAX_TIME: u64 = (1 << 53) - 1;

/// The header that carries the signed authority (`PROTOCOL.md` 8.1).
pub const AUTHORITY_HEADER: &str = "snailfish-authority";
/// The header that carries the relay time ([WIR-7]).
pub const TIME_HEADER: &str = "snailfish-time";

const COMPONENTS: &str = r#"("@method" "@authority" "@path" "@query" "content-digest")"#;

/// The parameters of one signature (`PROTOCOL.md` 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Unix time in seconds.
    pub created: u64,
    /// Unix time in seconds, after `created` and at most `created + 300`.
    pub expires: u64,
    /// 16 random bytes.
    pub nonce: [u8; 16],
    /// The device ID of the signer.
    pub keyid: Hash32,
}

/// The parts of the request target that the signature covers.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// The HTTP method in uppercase.
    pub method: &'a str,
    /// The authority (`PROTOCOL.md` 8.3).
    pub authority: &'a str,
    /// The path, without the query.
    pub path: &'a str,
    /// The query without `?`. Empty if the target has no query.
    pub query: &'a str,
}

/// The four headers of a signed request, in the order of `PROTOCOL.md` 8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `content-digest`.
    pub content_digest: String,
    /// `signature-input`.
    pub signature_input: String,
    /// `signature`.
    pub signature: String,
    /// `snailfish-authority`.
    pub authority: String,
}

impl SignedHeaders {
    /// The headers as name and value pairs, in the order of 8.1.
    #[must_use]
    pub fn pairs(&self) -> [(&'static str, &str); 4] {
        [
            ("content-digest", &self.content_digest),
            ("signature-input", &self.signature_input),
            ("signature", &self.signature),
            (AUTHORITY_HEADER, &self.authority),
        ]
    }
}

/// A refused request, with the error code of `PROTOCOL.md` 10.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// `wrong_authority`: the signed authority differs from the relay
    /// configuration.
    WrongAuthority,
    /// `bad_signature`: a header breaks section 8, or the signature does
    /// not verify. The text names the cause.
    BadSignature(&'static str),
    /// `expired`: the request is outside its time window.
    Expired,
    /// `bad_digest`: `content-digest` differs from the body.
    BadDigest,
    /// `unknown_device`: `keyid` names no active device.
    UnknownDevice,
}

impl RequestError {
    /// The error code of `PROTOCOL.md` 10.3.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongAuthority => "wrong_authority",
            Self::BadSignature(_) => "bad_signature",
            Self::Expired => "expired",
            Self::BadDigest => "bad_digest",
            Self::UnknownDevice => "unknown_device",
        }
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature(why) => write!(f, "bad_signature: {why}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for RequestError {}

/// The `content-digest` value of a body (RFC 9530, `PROTOCOL.md` 8.1).
#[must_use]
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

/// The signature parameters line of `PROTOCOL.md` 8.2.
#[must_use]
pub fn params_line(p: &Params) -> String {
    format!(
        r#"{COMPONENTS};created={};expires={};nonce="{}";keyid="{}";alg="ed25519";tag="{TAG}""#,
        p.created,
        p.expires,
        encode_id("", &p.nonce),
        encode_id("d_", &p.keyid),
    )
}

/// The signature base of `PROTOCOL.md` 8.4.
#[must_use]
pub fn signature_base(t: &Target<'_>, content_digest: &str, params_line: &str) -> String {
    format!(
        "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"@query\": ?{}\n\"content-digest\": {}\n\"@signature-params\": {}",
        t.method, t.authority, t.path, t.query, content_digest, params_line
    )
}

/// Sign a request. The caller sets `created` from the corrected clock
/// ([WIR-7]) and takes the nonce from the CSPRNG.
#[must_use]
pub fn sign(key: &SecretKey, t: &Target<'_>, body: &[u8], p: &Params) -> SignedHeaders {
    let digest = content_digest(body);
    let line = params_line(p);
    let sig = key.sign_raw(signature_base(t, &digest, &line).as_bytes());
    SignedHeaders {
        content_digest: digest,
        signature_input: format!("sf={line}"),
        signature: format!("sf=:{}:", STANDARD.encode(sig)),
        authority: t.authority.to_owned(),
    }
}

/// Parse a decimal parameter: an integer from 1 to 2^53 - 1 with no leading
/// zero (`PROTOCOL.md` 8.2).
#[must_use]
pub fn parse_decimal(s: &[u8]) -> Option<u64> {
    let (&first, _) = s.split_first()?;
    if first == b'0' || s.len() > 16 {
        return None;
    }
    let mut n: u64 = 0;
    for &c in s {
        let d = char::from(c).to_digit(10)?;
        n = n.checked_mul(10)?.checked_add(u64::from(d))?;
    }
    (n <= MAX_TIME).then_some(n)
}

/// Take `prefix` from the front of `s`.
fn take<'a>(s: &'a str, prefix: &str) -> Result<&'a str, RequestError> {
    s.strip_prefix(prefix).ok_or(RequestError::BadSignature(
        "signature-input is not in the form of 8.2",
    ))
}

/// Split `s` at the first `sep`.
fn until(s: &str, sep: char) -> Result<(&str, &str), RequestError> {
    s.split_once(sep).ok_or(RequestError::BadSignature(
        "signature-input is not in the form of 8.2",
    ))
}

/// Parse a `signature-input` header value (`PROTOCOL.md` 8.2). It returns
/// the parameters and the parameters line that the signature base holds.
///
/// # Errors
///
/// [`RequestError::BadSignature`] for each value that is not exactly the
/// form of 8.2, also an `expires` that is not after `created` or more than
/// 300 seconds after it.
pub fn parse_signature_input(value: &str) -> Result<(Params, &str), RequestError> {
    let line = take(value, "sf=")?;
    let rest = take(line, COMPONENTS)?;
    let rest = take(rest, ";created=")?;
    let (created, rest) = until(rest, ';')?;
    let rest = take(rest, "expires=")?;
    let (expires, rest) = until(rest, ';')?;
    let rest = take(rest, "nonce=\"")?;
    let (nonce, rest) = until(rest, '"')?;
    let rest = take(rest, ";keyid=\"")?;
    let (keyid, rest) = until(rest, '"')?;
    if rest != format!(r#";alg="ed25519";tag="{TAG}""#) {
        return Err(RequestError::BadSignature(
            "signature-input is not in the form of 8.2",
        ));
    }
    let bad_int = RequestError::BadSignature("created or expires is not a valid integer");
    let created = parse_decimal(created.as_bytes()).ok_or(bad_int.clone())?;
    let expires = parse_decimal(expires.as_bytes()).ok_or(bad_int)?;
    if !lifetime_ok(created, expires) {
        return Err(RequestError::BadSignature(
            "expires must be after created and at most 300 seconds after it",
        ));
    }
    let nonce = decode_id::<16>(nonce, "")
        .map_err(|_| RequestError::BadSignature("nonce is not 32 lowercase hex digits"))?;
    let keyid = decode_id::<32>(keyid, "d_")
        .map_err(|_| RequestError::BadSignature("keyid is not a device ID"))?;
    Ok((
        Params {
            created,
            expires,
            nonce,
            keyid,
        },
        line,
    ))
}

/// True if `expires` is after `created` and at most [`MAX_LIFETIME`] after it.
#[must_use]
pub fn lifetime_ok(created: u64, expires: u64) -> bool {
    expires > created && expires.saturating_sub(created) <= MAX_LIFETIME
}

/// True if the relay time `now` is inside the window of a signature
/// (`PROTOCOL.md` 8.6 step 3).
#[must_use]
pub fn window_ok(created: u64, expires: u64, now: u64) -> bool {
    expires >= now && created <= now.saturating_add(MAX_FUTURE)
}

/// Decode `prefix` `:` base64 `:` with exactly `N` bytes.
fn colon_b64<const N: usize>(value: &str, prefix: &str) -> Option<[u8; N]> {
    let inner = value
        .strip_prefix(prefix)?
        .strip_prefix(':')?
        .strip_suffix(':')?;
    STANDARD.decode(inner).ok()?.try_into().ok()
}

/// Parse a `signature` header value: `sf=:` base64 of 64 bytes `:`.
///
/// # Errors
///
/// [`RequestError::BadSignature`].
pub fn parse_signature(value: &str) -> Result<[u8; 64], RequestError> {
    colon_b64::<64>(value, "sf=").ok_or(RequestError::BadSignature(
        "signature is not sf=: base64 of 64 bytes :",
    ))
}

/// A request that passed the checks of 8.6 steps 1 to 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// The signer.
    pub keyid: Hash32,
    /// The nonce, which the relay must store until `expires` (step 7).
    pub nonce: [u8; 16],
    /// The end of the validity.
    pub expires: u64,
}

/// The one value of a header that must occur once. Names compare
/// case-insensitively.
fn one<'a>(headers: &[(&str, &'a str)], name: &str) -> Result<Option<&'a str>, RequestError> {
    let mut it = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
    let first = it.next().map(|(_, v)| *v);
    if it.next().is_some() {
        return Err(RequestError::BadSignature(
            "a signature header occurs twice",
        ));
    }
    Ok(first)
}

fn required<'a>(headers: &[(&str, &'a str)], name: &str) -> Result<&'a str, RequestError> {
    one(headers, name)?.ok_or(RequestError::BadSignature("a signature header is missing"))
}

/// Check a signed request (`PROTOCOL.md` 8.6 steps 1 to 6), in that order.
///
/// `target.authority` must be the configured authority, not a value from
/// the request. `device_key` returns the signing key of an active device.
///
/// # Errors
///
/// The first failed check, as a [`RequestError`].
pub fn check(
    headers: &[(&str, &str)],
    target: &Target<'_>,
    body: &[u8],
    now: u64,
    device_key: impl Fn(&Hash32) -> Option<[u8; 32]>,
) -> Result<Verified, RequestError> {
    if let Some(a) = one(headers, AUTHORITY_HEADER)?
        && a != target.authority
    {
        return Err(RequestError::WrongAuthority);
    }
    required(headers, AUTHORITY_HEADER)?;
    let digest_value = required(headers, "content-digest")?;
    let input = required(headers, "signature-input")?;
    let sig_value = required(headers, "signature")?;
    if colon_b64::<32>(digest_value, "sha-256=").is_none() {
        return Err(RequestError::BadSignature(
            "content-digest is not sha-256=: base64 of 32 bytes :",
        ));
    }
    let (params, line) = parse_signature_input(input)?;
    let sig = parse_signature(sig_value)?;
    if !window_ok(params.created, params.expires, now) {
        return Err(RequestError::Expired);
    }
    if digest_value != content_digest(body) {
        return Err(RequestError::BadDigest);
    }
    let pk = device_key(&params.keyid).ok_or(RequestError::UnknownDevice)?;
    let base = signature_base(target, digest_value, line);
    PublicKey::from_bytes(&pk)
        .and_then(|k| k.verify_raw(base.as_bytes(), &sig))
        .map_err(|_| RequestError::BadSignature("the signature does not verify"))?;
    Ok(Verified {
        keyid: params.keyid,
        nonce: params.nonce,
        expires: params.expires,
    })
}

/// Read the relay time from a `snailfish-time` header value ([WIR-7]).
#[must_use]
pub fn parse_time(value: &str) -> Option<u64> {
    if value == "0" {
        return Some(0);
    }
    parse_decimal(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const AUTH: &str = "sync.example.net";

    fn key() -> (SecretKey, Hash32) {
        let sk = SecretKey::from_seed(&[7; 32]);
        (sk, [9; 32])
    }

    fn target<'a>(method: &'a str, path: &'a str, query: &'a str) -> Target<'a> {
        Target {
            method,
            authority: AUTH,
            path,
            query,
        }
    }

    fn params(created: u64) -> Params {
        Params {
            created,
            expires: created.checked_add(MAX_LIFETIME).unwrap(),
            nonce: [1; 16],
            keyid: [9; 32],
        }
    }

    fn signed(t: &Target<'_>, body: &[u8], p: &Params) -> Vec<(String, String)> {
        let (sk, _) = key();
        sign(&sk, t, body, p)
            .pairs()
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn run(
        h: &[(String, String)],
        t: &Target<'_>,
        body: &[u8],
        now: u64,
    ) -> Result<Verified, RequestError> {
        let pairs: Vec<(&str, &str)> = h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let pk = key().0.public();
        check(&pairs, t, body, now, |id| (id == &[9; 32]).then_some(pk))
    }

    #[test]
    fn signature_base_matches_protocol_example() {
        let t = target("GET", "/v1/x", "after=0&limit=500");
        let base = signature_base(
            &t,
            &content_digest(b""),
            &params_line(&params(1_767_225_600)),
        );
        let want = concat!(
            "\"@method\": GET\n\"@authority\": sync.example.net\n\"@path\": /v1/x\n",
            "\"@query\": ?after=0&limit=500\n",
            "\"content-digest\": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n",
            "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\")",
            ";created=1767225600;expires=1767225900;nonce=\"01010101010101010101010101010101\"",
            ";keyid=\"d_0909090909090909090909090909090909090909090909090909090909090909\"",
            ";alg=\"ed25519\";tag=\"snailfish.request.v1\"",
        );
        assert_eq!(base, want);
    }

    #[test]
    fn checks_run_in_protocol_order() {
        let t = target("POST", "/v1/a", "");
        let now = 1000;
        let good = signed(&t, b"{}", &params(now));
        assert_eq!(run(&good, &t, b"{}", now).map(|v| v.nonce), Ok([1; 16]));

        // Step 1 wins over every later failure.
        let mut wrong = good.clone();
        wrong[3].1 = "evil.example".into();
        wrong.remove(0);
        assert_eq!(
            run(&wrong, &t, b"x", now),
            Err(RequestError::WrongAuthority)
        );

        // The authority header is required (8.1), and the signature covers
        // @authority: a request for another authority does not verify.
        let mut no_auth = good.clone();
        no_auth.pop();
        assert!(matches!(
            run(&no_auth, &t, b"{}", now),
            Err(RequestError::BadSignature(_))
        ));
        let other = Target {
            authority: "evil.example",
            ..t
        };
        let mut forged = good.clone();
        forged[3].1 = "evil.example".into();
        assert!(matches!(
            run(&forged, &other, b"{}", now),
            Err(RequestError::BadSignature(_))
        ));

        let mut missing = good.clone();
        missing.remove(1);
        assert!(matches!(
            run(&missing, &t, b"{}", now),
            Err(RequestError::BadSignature(_))
        ));
        let mut twice = good.clone();
        twice.push(("Signature".into(), good[2].1.clone()));
        assert!(matches!(
            run(&twice, &t, b"{}", now),
            Err(RequestError::BadSignature(_))
        ));

        assert_eq!(
            run(&good, &t, b"{}", now + MAX_LIFETIME),
            Ok(run(&good, &t, b"{}", now).unwrap())
        );
        assert_eq!(
            run(&good, &t, b"{}", now + MAX_LIFETIME + 1),
            Err(RequestError::Expired)
        );
        assert!(run(&good, &t, b"{}", now - MAX_FUTURE).is_ok());
        assert_eq!(
            run(&good, &t, b"{}", now - MAX_FUTURE - 1),
            Err(RequestError::Expired)
        );

        assert_eq!(run(&good, &t, b"{ }", now), Err(RequestError::BadDigest));

        let pairs: Vec<(&str, &str)> = good.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        assert_eq!(
            check(&pairs, &t, b"{}", now, |_| None),
            Err(RequestError::UnknownDevice)
        );

        for other in [
            target("PUT", "/v1/a", ""),
            target("POST", "/v1/b", ""),
            target("POST", "/v1/a", "x=1"),
        ] {
            assert!(matches!(
                run(&good, &other, b"{}", now),
                Err(RequestError::BadSignature(_))
            ));
        }
    }

    #[test]
    fn signature_input_refuses_other_forms() {
        let line = params_line(&params(1000));
        assert!(parse_signature_input(&format!("sf={line}")).is_ok());
        for bad in [
            format!("sig1={line}"),
            format!(
                "sf={}",
                line.replace(r#""@path" "@query""#, r#""@query" "@path""#)
            ),
            format!("sf={}", line.replace("ed25519", "rsa-pss-sha512")),
            format!("sf={}", line.replace(TAG, "snailfish.request.v2")),
            format!("sf={line};x=1"),
            format!("sf={}", line.replace("created=1000", "created=01000")),
            format!("sf={}", line.replace("expires=1300", "expires=1301")),
            format!("sf={}", line.replace("expires=1300", "expires=1000")),
            format!("sf={}", line.replace("01010101", "0101010G")),
            format!("sf={}", line.replace(";keyid", "; keyid")),
        ] {
            assert!(
                matches!(
                    parse_signature_input(&bad),
                    Err(RequestError::BadSignature(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn decimal_and_time_forms() {
        assert_eq!(parse_decimal(b"1"), Some(1));
        assert_eq!(parse_decimal(b"9007199254740991"), Some(MAX_TIME));
        for bad in [
            &b""[..],
            b"0",
            b"01",
            b"9007199254740992",
            b"+1",
            b"1a",
            b"99999999999999999",
        ] {
            assert_eq!(parse_decimal(bad), None);
        }
        assert_eq!(parse_time("0"), Some(0));
        assert_eq!(parse_time("1767225600"), Some(1_767_225_600));
        assert_eq!(parse_time(" 1"), None);
    }

    #[test]
    fn signature_header_form() {
        let sig = [3u8; 64];
        let v = format!("sf=:{}:", STANDARD.encode(sig));
        assert_eq!(parse_signature(&v), Ok(sig));
        let url = format!(
            "sf=:{}:",
            base64::engine::general_purpose::URL_SAFE.encode([0xfb; 64])
        );
        assert!(parse_signature(&url).is_err());
        assert!(parse_signature(&v.replace("sf=", "s=")).is_err());
        assert!(parse_signature(&format!("sf=:{}:", STANDARD.encode([3u8; 63]))).is_err());
    }

    #[test]
    fn error_codes_are_the_protocol_codes() {
        let codes: Vec<&str> = [
            RequestError::WrongAuthority,
            RequestError::BadSignature("x"),
            RequestError::Expired,
            RequestError::BadDigest,
            RequestError::UnknownDevice,
        ]
        .iter()
        .map(RequestError::code)
        .collect();
        assert_eq!(
            codes,
            [
                "wrong_authority",
                "bad_signature",
                "expired",
                "bad_digest",
                "unknown_device"
            ]
        );
        assert_eq!(
            RequestError::BadSignature("why").to_string(),
            "bad_signature: why"
        );
        assert_eq!(RequestError::Expired.to_string(), "expired");
    }

    proptest! {
        /// A signed request verifies, and a change to any covered value
        /// makes it fail ([WIR-7] window, 8.6).
        #[test]
        fn sign_then_check(
            created in 1u64..1_000_000_000,
            life in 1u64..=MAX_LIFETIME,
            body in proptest::collection::vec(any::<u8>(), 0..64),
            path in "/[a-z0-9/]{0,16}",
            query in "[a-z0-9=&]{0,12}",
            flip in any::<usize>(),
        ) {
            let t = target("POST", &path, &query);
            let p = Params { expires: created.checked_add(life).unwrap(), ..params(created) };
            let h = signed(&t, &body, &p);
            prop_assert!(run(&h, &t, &body, created).is_ok());
            let mut bad = body.clone();
            if bad.is_empty() { bad.push(0) } else { crate::testutil::flip_bit(&mut bad, flip) }
            prop_assert_eq!(run(&h, &t, &bad, created), Err(RequestError::BadDigest));
        }

        /// The parser never panics, and each accepted value has a valid
        /// lifetime and writes back to the same line.
        #[test]
        fn parse_signature_input_never_panics(s in ".{0,300}") {
            if let Ok((p, line)) = parse_signature_input(&s) {
                prop_assert!(lifetime_ok(p.created, p.expires));
                prop_assert_eq!(params_line(&p), line);
            }
        }

        #[test]
        fn decimal_round_trip(n in 1u64..=MAX_TIME) {
            prop_assert_eq!(parse_decimal(n.to_string().as_bytes()), Some(n));
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `parse_decimal` accepts only the form of 8.2, for every input of up
    /// to 4 bytes. Bound: 4 bytes, so the values stay below 10 000.
    #[kani::proof]
    #[kani::unwind(6)]
    fn parse_decimal_is_strict() {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 4);
        let s = &bytes[..len];
        if let Some(n) = parse_decimal(s) {
            assert!(len >= 1 && s[0] != b'0');
            assert!(s.iter().all(u8::is_ascii_digit));
            assert!(n >= 1 && n < 10_000);
        } else {
            assert!(len == 0 || s[0] == b'0' || !s.iter().all(u8::is_ascii_digit));
        }
    }

    /// The time window of 8.6 step 3 and the lifetime of 8.2, for every
    /// 64-bit input. No overflow, and a request is never valid after
    /// `expires` or more than 360 seconds after `created`.
    #[kani::proof]
    fn window_and_lifetime() {
        let created: u64 = kani::any();
        let expires: u64 = kani::any();
        let now: u64 = kani::any();
        if lifetime_ok(created, expires) && window_ok(created, expires, now) {
            assert!(now <= expires);
            assert!(expires - created <= MAX_LIFETIME);
            assert!(created <= now.saturating_add(MAX_FUTURE));
        }
        if window_ok(created, expires, now) {
            assert!(expires >= now);
        }
    }
}
