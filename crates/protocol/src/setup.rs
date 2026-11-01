//! The user and setup surface (`PROTOCOL.md` sections 10.5, 10.11 and 12):
//! tokens, the PKCE code challenge, redirect URIs, the setup token exchange,
//! device status reports and webhook messages.
//!
//! The byte checks are pure functions on bytes, so Kani can check them. The
//! relay and the engine both use this module, so both apply one rule.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};

use crate::encoding::{Hash32, decode_id, encode_id};
use crate::records::{Keys, parse_keys_json};
use crate::strict::{self, Value};
use crate::wire::WireError;

fn bad(msg: impl Into<String>) -> WireError {
    WireError(msg.into())
}

/// The kind of a relay token (`PROTOCOL.md` 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// An invite token (12.1).
    Invite,
    /// An authorization code (12.2).
    Code,
    /// A setup token (12.3).
    Setup,
}

impl TokenKind {
    /// The text prefix.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Invite => "it_",
            Self::Code => "ac_",
            Self::Setup => "st_",
        }
    }
}

/// Parse a token text: the prefix of `kind` and 64 lowercase hex digits.
///
/// # Errors
///
/// Refuses each other text (`PROTOCOL.md` 2.2).
pub fn parse_token(kind: TokenKind, text: &str) -> Result<[u8; 32], WireError> {
    decode_id::<32>(text, kind.prefix()).map_err(|e| bad(format!("token: {e}")))
}

/// The text form of a token.
#[must_use]
pub fn token_text(kind: TokenKind, token: &[u8; 32]) -> String {
    encode_id(kind.prefix(), token)
}

/// The value that the relay stores for a token: SHA-256 of its 32 bytes
/// (12.1 to 12.3, [USR-1]). The relay never stores the token itself.
#[must_use]
pub fn token_hash(token: &[u8; 32]) -> Hash32 {
    Sha256::digest(token).into()
}

/// True if `b` is an unreserved character of RFC 3986: `A-Z a-z 0-9 - . _ ~`.
#[must_use]
pub fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// True if `v` is a PKCE code verifier: 43 to 128 unreserved characters
/// (RFC 7636 section 4.1, `PROTOCOL.md` 12.2, [USR-4]).
#[must_use]
pub fn verifier_ok(v: &[u8]) -> bool {
    (43..=128).contains(&v.len()) && v.iter().all(|&b| unreserved(b))
}

/// True if `s` is an authorization `state`: 1 to 128 unreserved characters.
#[must_use]
pub fn state_ok(s: &[u8]) -> bool {
    (1..=128).contains(&s.len()) && s.iter().all(|&b| unreserved(b))
}

/// The S256 code challenge of a verifier:
/// `BASE64URL(SHA-256(ASCII(code_verifier)))` without padding ([USR-4]).
#[must_use]
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// True if `c` has the form of an S256 challenge: 43 base64url characters
/// whose last character carries no trailing bits.
#[must_use]
pub fn challenge_ok(c: &[u8]) -> bool {
    c.len() == 43
        && c.iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && URL_SAFE_NO_PAD.decode(c).is_ok()
}

/// The most bytes of a redirect URI or a webhook URL.
pub const MAX_URI: usize = 512;

fn path_ok(p: &[u8]) -> bool {
    let hex = |x: Option<&u8>| x.is_some_and(|x| x.is_ascii_digit() || (b'A'..=b'F').contains(x));
    let mut it = p.iter();
    while let Some(&b) = it.next() {
        if b == b'%' {
            if !(hex(it.next()) && hex(it.next())) {
                return false;
            }
        } else if !(unreserved(b) || b == b'/') {
            return false;
        }
    }
    true
}

/// Parse a decimal port from 1 to 65535 with no leading zero.
fn port(p: &[u8]) -> Option<u16> {
    if p.len() > 5 || p.first().is_none_or(|&c| c == b'0') {
        return None;
    }
    let mut n: u32 = 0;
    for &d in p {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n
            .checked_mul(10)?
            .checked_add(u32::from(d.checked_sub(b'0')?))?;
    }
    u16::try_from(n).ok()
}

/// True if `uri` is a redirect URI of `PROTOCOL.md` 12.2 (RFC 8252
/// section 7): a loopback URI with an IP literal and a port, or a
/// private-use scheme with a `.` and no authority part ([USR-4]).
#[must_use]
pub fn redirect_uri_ok(uri: &[u8]) -> bool {
    if uri.len() > MAX_URI {
        return false;
    }
    for prefix in [&b"http://127.0.0.1:"[..], &b"http://[::1]:"[..]] {
        if let Some(rest) = uri.strip_prefix(prefix) {
            let slash = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
            let (p, path) = rest.split_at(slash);
            return port(p).is_some() && path.first() == Some(&b'/') && path_ok(path);
        }
    }
    let Some(colon) = uri.iter().position(|&b| b == b':') else {
        return false;
    };
    let (scheme, rest) = uri.split_at(colon);
    let scheme_ok = scheme.first().is_some_and(u8::is_ascii_lowercase)
        && scheme.iter().all(|&b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
        })
        && scheme.contains(&b'.');
    let Some(path) = rest.strip_prefix(b":/") else {
        return false;
    };
    scheme_ok && path.first() != Some(&b'/') && path_ok(path)
}

/// Decode one value of a query or a form: `+` is a space and `%XX` is a
/// byte. Returns `None` for a bad `%` sequence or a result that is not
/// UTF-8.
#[must_use]
pub fn form_decode(s: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.iter();
    while let Some(&b) = it.next() {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let h = [*it.next()?, *it.next()?];
                if !h.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                out.push(u8::from_str_radix(std::str::from_utf8(&h).ok()?, 16).ok()?);
            }
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// Parse a query or a form body into its fields. Each field must occur once
/// and must be one of `names`. Each name of `names` must occur.
///
/// # Errors
///
/// Refuses a field outside `names`, a second copy of a field, a missing
/// field and a value that does not decode.
pub fn parse_form(body: &[u8], names: &[&str]) -> Result<BTreeMap<String, String>, WireError> {
    let mut out = BTreeMap::new();
    if !body.is_empty() {
        for pair in body.split(|&b| b == b'&') {
            let eq = pair.iter().position(|&b| b == b'=').unwrap_or(pair.len());
            let (k, v) = pair.split_at(eq);
            let k = form_decode(k).ok_or_else(|| bad("a field name does not decode"))?;
            let v = form_decode(v.get(1..).unwrap_or_default())
                .ok_or_else(|| bad(format!("{k}: the value does not decode")))?;
            if !names.contains(&k.as_str()) {
                return Err(bad(format!("unknown field {k}")));
            }
            if out.insert(k.clone(), v).is_some() {
                return Err(bad(format!("{k} occurs twice")));
            }
        }
    }
    if let Some(missing) = names.iter().find(|n| !out.contains_key(**n)) {
        return Err(bad(format!("{missing} is missing")));
    }
    Ok(out)
}

/// An authorization request of `PROTOCOL.md` 12.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorize {
    /// The S256 code challenge.
    pub challenge: String,
    /// The decoded redirect URI.
    pub redirect_uri: String,
    /// The state of the app.
    pub state: String,
}

/// The fields of an authorization request.
pub const AUTHORIZE_FIELDS: [&str; 5] = [
    "response_type",
    "code_challenge",
    "code_challenge_method",
    "redirect_uri",
    "state",
];

/// Check the five fields of an authorization request (12.2).
///
/// # Errors
///
/// Refuses each field that breaks 12.2.
pub fn check_authorize(f: &BTreeMap<String, String>) -> Result<Authorize, WireError> {
    let get = |k: &str| f.get(k).map(String::as_str).unwrap_or_default();
    if get("response_type") != "code" {
        return Err(bad("response_type must be code"));
    }
    if get("code_challenge_method") != "S256" {
        return Err(bad("code_challenge_method must be S256"));
    }
    if !challenge_ok(get("code_challenge").as_bytes()) {
        return Err(bad("code_challenge is not an S256 challenge"));
    }
    if !redirect_uri_ok(get("redirect_uri").as_bytes()) {
        return Err(bad("redirect_uri breaks PROTOCOL.md 12.2"));
    }
    if !state_ok(get("state").as_bytes()) {
        return Err(bad("state breaks PROTOCOL.md 12.2"));
    }
    Ok(Authorize {
        challenge: get("code_challenge").to_owned(),
        redirect_uri: get("redirect_uri").to_owned(),
        state: get("state").to_owned(),
    })
}

/// Parse the query of `GET /u/authorize` (12.2).
///
/// # Errors
///
/// As [`parse_form`] and [`check_authorize`].
pub fn parse_authorize_query(query: &str) -> Result<Authorize, WireError> {
    check_authorize(&parse_form(query.as_bytes(), &AUTHORIZE_FIELDS)?)
}

fn query_value(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if unreserved(b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The query of an authorization request, for the app to open.
#[must_use]
pub fn authorize_query(a: &Authorize) -> String {
    format!(
        "response_type=code&code_challenge={}&code_challenge_method=S256&redirect_uri={}&state={}",
        query_value(&a.challenge),
        query_value(&a.redirect_uri),
        query_value(&a.state)
    )
}

/// The `Location` of the answer to an approved request (12.2 step 2).
#[must_use]
pub fn redirect_location(redirect_uri: &str, code: &[u8; 32], state: &str) -> String {
    format!(
        "{redirect_uri}?code={}&state={state}",
        token_text(TokenKind::Code, code)
    )
}

/// Read `code` and `state` from the query of a redirect (12.2 step 2). Other
/// fields are ignored.
///
/// # Errors
///
/// Refuses a query without a valid code or state.
pub fn parse_redirect_query(query: &str) -> Result<([u8; 32], String), WireError> {
    let (mut code, mut state) = (None, None);
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("code", v)) => code = Some(parse_token(TokenKind::Code, v)?),
            Some(("state", v)) if state_ok(v.as_bytes()) => state = Some(v.to_owned()),
            _ => {}
        }
    }
    match (code, state) {
        (Some(c), Some(s)) => Ok((c, s)),
        _ => Err(bad("the redirect has no code or state")),
    }
}

/// A setup token request (12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// The authorization code.
    pub code: [u8; 32],
    /// The PKCE code verifier.
    pub verifier: String,
    /// The redirect URI of the authorization request.
    pub redirect_uri: String,
    /// The keys of the device that signs the request.
    pub device: Keys,
}

fn object<'a>(
    v: &'a Value,
    what: &str,
    names: &[&str],
) -> Result<&'a BTreeMap<String, Value>, WireError> {
    let Value::Obj(m) = v else {
        return Err(bad(format!("{what} is not an object")));
    };
    if m.len() != names.len() || !names.iter().all(|n| m.contains_key(*n)) {
        return Err(bad(format!(
            "{what} must hold exactly {}",
            names.join(", ")
        )));
    }
    Ok(m)
}

fn text<'a>(m: &'a BTreeMap<String, Value>, k: &str) -> Result<&'a str, WireError> {
    match m.get(k) {
        Some(Value::Str(s)) => Ok(s),
        _ => Err(bad(format!("{k} is not a string"))),
    }
}

fn uint(m: &BTreeMap<String, Value>, k: &str) -> Result<u64, WireError> {
    match m.get(k) {
        Some(Value::Int(n)) => u64::try_from(*n).map_err(|_| bad(format!("{k} is negative"))),
        _ => Err(bad(format!("{k} is not an integer"))),
    }
}

/// Parse a setup token request body (12.3).
///
/// # Errors
///
/// Refuses a body that breaks section 3 (also a duplicate key) or 12.3.
pub fn parse_token_request(body: &[u8]) -> Result<TokenRequest, WireError> {
    let v = strict::parse(body).map_err(|e| bad(format!("token body: {e}")))?;
    let m = object(
        &v,
        "token body",
        &["code", "code_verifier", "redirect_uri", "device"],
    )?;
    let code = parse_token(TokenKind::Code, text(m, "code")?)?;
    let verifier = text(m, "code_verifier")?;
    if !verifier_ok(verifier.as_bytes()) {
        return Err(bad("code_verifier breaks RFC 7636 section 4.1"));
    }
    let redirect_uri = text(m, "redirect_uri")?;
    if !redirect_uri_ok(redirect_uri.as_bytes()) {
        return Err(bad("redirect_uri breaks PROTOCOL.md 12.2"));
    }
    let device = match m.get("device") {
        Some(d @ Value::Obj(_)) => keys_of(d)?,
        _ => return Err(bad("device is not a keys object")),
    };
    Ok(TokenRequest {
        code,
        verifier: verifier.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        device,
    })
}

fn keys_of(v: &Value) -> Result<Keys, WireError> {
    // The keys parser of section 6.1 reads JSON bytes, so write the checked
    // value back. A strict value has one text form.
    let Value::Obj(m) = v else {
        return Err(bad("device is not a keys object"));
    };
    let mut parts = Vec::new();
    for (k, v) in m {
        let Value::Str(s) = v else {
            return Err(bad(format!("device.{k} is not a string")));
        };
        parts.push(format!(
            "{}:{}",
            serde_json::to_string(k).unwrap_or_default(),
            serde_json::to_string(s).unwrap_or_default()
        ));
    }
    parse_keys_json(format!("{{{}}}", parts.join(",")).as_bytes())
        .map_err(|e| bad(format!("device: {e}")))
}

/// The body of a setup token request.
#[must_use]
pub fn token_request_body(r: &TokenRequest) -> Vec<u8> {
    format!(
        r#"{{"code":"{}","code_verifier":{},"redirect_uri":{},"device":{}}}"#,
        token_text(TokenKind::Code, &r.code),
        serde_json::to_string(&r.verifier).unwrap_or_default(),
        serde_json::to_string(&r.redirect_uri).unwrap_or_default(),
        crate::write::keys_object(&r.device)
    )
    .into_bytes()
}

/// A setup token response (12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenResponse {
    /// The setup token.
    pub token: [u8; 32],
    /// The tenant handle of the user.
    pub tenant: String,
    /// The relay time at which the token expires.
    pub expires: u64,
}

/// The body of a setup token response.
#[must_use]
pub fn token_response_body(r: &TokenResponse) -> Vec<u8> {
    serde_json::json!({
        "token": token_text(TokenKind::Setup, &r.token),
        "tenant": r.tenant,
        "expires": r.expires,
    })
    .to_string()
    .into_bytes()
}

/// Parse a setup token response. Unknown fields are ignored ([VER-13]).
///
/// # Errors
///
/// Refuses a body without a valid token, tenant handle and expiry.
pub fn parse_token_response(body: &[u8]) -> Result<TokenResponse, WireError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("token response: {e}")))?;
    let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
    let token = parse_token(TokenKind::Setup, s("token").unwrap_or_default())?;
    let tenant = s("tenant").unwrap_or_default();
    decode_id::<16>(tenant, "t_").map_err(|e| bad(format!("tenant: {e}")))?;
    let expires = v
        .get("expires")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| bad("expires is not an integer"))?;
    Ok(TokenResponse {
        token,
        tenant: tenant.to_owned(),
        expires,
    })
}

/// A device status report (10.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatus {
    /// The sync status text.
    pub state: String,
    /// The number of own changes that the verified log does not hold yet.
    pub outbox: u64,
    /// The relay time of the oldest of these changes. `None` if `outbox` is 0.
    pub oldest: Option<u64>,
    /// The applied position of the app.
    pub applied: u64,
    /// The current epoch.
    pub epoch: u64,
}

/// True if `s` is a status text of 10.11: 1 to 64 bytes from 0x20 to 0x7E.
#[must_use]
pub fn state_text_ok(s: &[u8]) -> bool {
    (1..=64).contains(&s.len()) && s.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

/// Parse a device status body (10.11).
///
/// # Errors
///
/// Refuses a body that breaks section 3 or 10.11.
pub fn parse_device_status(body: &[u8]) -> Result<DeviceStatus, WireError> {
    let v = strict::parse(body).map_err(|e| bad(format!("device status: {e}")))?;
    let m = object(
        &v,
        "device status",
        &["state", "outbox", "oldest", "applied", "epoch"],
    )?;
    let state = text(m, "state")?;
    if !state_text_ok(state.as_bytes()) {
        return Err(bad("state must be 1 to 64 bytes of printable ASCII"));
    }
    let outbox = uint(m, "outbox")?;
    let oldest = match m.get("oldest") {
        Some(Value::Null) => None,
        _ => Some(uint(m, "oldest")?),
    };
    if oldest.is_some() != (outbox > 0) {
        return Err(bad("oldest must be null exactly when outbox is 0"));
    }
    let applied = uint(m, "applied")?;
    let epoch = uint(m, "epoch")?;
    if epoch == 0 {
        return Err(bad("epoch must be 1 or more"));
    }
    Ok(DeviceStatus {
        state: state.to_owned(),
        outbox,
        oldest,
        applied,
        epoch,
    })
}

/// The body of a device status report.
#[must_use]
pub fn device_status_body(s: &DeviceStatus) -> Vec<u8> {
    serde_json::json!({
        "state": s.state,
        "outbox": s.outbox,
        "oldest": s.oldest,
        "applied": s.applied,
        "epoch": s.epoch,
    })
    .to_string()
    .into_bytes()
}

/// The parts of a webhook URL (12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookUrl {
    /// True for `https`.
    pub https: bool,
    /// The host: a lowercase domain name, an IPv4 literal, or an IPv6
    /// literal without its brackets.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The path and the query, from the first `/`.
    pub target: String,
}

fn domain_ok(h: &[u8]) -> bool {
    !h.is_empty()
        && h.iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn target_ok(t: &[u8]) -> bool {
    t.first() == Some(&b'/')
        && t.iter().all(|&b| {
            (0x21..=0x7e).contains(&b)
                && !matches!(
                    b,
                    b'#' | b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
                )
        })
}

/// Parse a webhook URL of 12.5 ([USR-8]). The allowlist and the address
/// checks are separate: see the relay.
///
/// # Errors
///
/// Refuses a URL that breaks 12.5.
pub fn parse_webhook_url(url: &str) -> Result<WebhookUrl, WireError> {
    let b = url.as_bytes();
    if b.len() > MAX_URI {
        return Err(bad("the URL is longer than 512 bytes"));
    }
    let (https, rest) = if let Some(r) = b.strip_prefix(b"https://") {
        (true, r)
    } else if let Some(r) = b.strip_prefix(b"http://") {
        (false, r)
    } else {
        return Err(bad("the URL must start with https:// or http://"));
    };
    let slash = rest
        .iter()
        .position(|&x| x == b'/')
        .ok_or_else(|| bad("the URL has no path"))?;
    let (authority, target) = rest.split_at(slash);
    if !target_ok(target) {
        return Err(bad("the URL path breaks PROTOCOL.md 12.5"));
    }
    let (host, port_text) = if let Some(r) = authority.strip_prefix(b"[") {
        let end = r
            .iter()
            .position(|&x| x == b']')
            .ok_or_else(|| bad("the IPv6 literal has no ]"))?;
        let (h, after) = r.split_at(end);
        let addr = std::str::from_utf8(h)
            .ok()
            .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok())
            .ok_or_else(|| bad("the IPv6 literal is not valid"))?;
        if addr.to_string().as_bytes() != h {
            return Err(bad(
                "the IPv6 literal is not in its shortest lowercase form",
            ));
        }
        (h, after.strip_prefix(b"]").unwrap_or(after))
    } else {
        let colon = authority
            .iter()
            .position(|&x| x == b':')
            .unwrap_or(authority.len());
        let (h, rest) = authority.split_at(colon);
        if !domain_ok(h) {
            return Err(bad(
                "the host must be a lowercase domain name or an IP literal",
            ));
        }
        (h, rest)
    };
    let port = match port_text {
        [] => {
            if https {
                443
            } else {
                80
            }
        }
        [b':', p @ ..] => port(p).ok_or_else(|| bad("the port breaks PROTOCOL.md 12.5"))?,
        _ => return Err(bad("the host part breaks PROTOCOL.md 12.5")),
    };
    Ok(WebhookUrl {
        https,
        host: String::from_utf8_lossy(host).into_owned(),
        port,
        target: String::from_utf8_lossy(target).into_owned(),
    })
}

/// The body of a webhook message: `{"text":...}` (12.5).
#[must_use]
pub fn webhook_body(text: &str) -> Vec<u8> {
    serde_json::json!({ "text": text }).to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rfc7636_example() {
        // RFC 7636 appendix B.
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(verifier_ok(v.as_bytes()));
        assert_eq!(challenge(v), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(challenge_ok(challenge(v).as_bytes()));
    }

    #[test]
    fn verifier_and_state_bounds() {
        // [USR-4] The exact length limits of RFC 7636 section 4.1 and 12.2.
        assert!(!verifier_ok(&[b'a'; 42]));
        assert!(verifier_ok(&[b'a'; 43]));
        assert!(verifier_ok(&[b'a'; 128]));
        assert!(!verifier_ok(&[b'a'; 129]));
        assert!(!verifier_ok(&[b'+'; 43]));
        assert!(!state_ok(b""));
        assert!(state_ok(b"x"));
        assert!(state_ok(&[b'~'; 128]));
        assert!(!state_ok(&[b'~'; 129]));
        assert!(!state_ok(b"a b"));
    }

    #[test]
    fn redirect_uris() {
        // [USR-4] One case for each rule of 12.2.
        for ok in [
            "http://127.0.0.1:1/",
            "http://127.0.0.1:65535/cb",
            "http://[::1]:8080/a/b%2F",
            "com.example.tasks:/callback",
            "com.example.tasks:/",
        ] {
            assert!(redirect_uri_ok(ok.as_bytes()), "{ok}");
        }
        for no in [
            "http://127.0.0.1:0/",
            "http://127.0.0.1:080/",
            "http://127.0.0.1:65536/",
            "http://127.0.0.1:80",
            "http://localhost:80/",
            "https://127.0.0.1:80/",
            "http://127.0.0.1:80/?q",
            "http://127.0.0.1:80/#f",
            "http://u@127.0.0.1:80/",
            "example:/cb",
            "Com.example:/cb",
            "com.example://host/cb",
            "com.example:cb",
            "com.example:/a%2",
            "com.example:/a%2f",
            "com.example:/a b",
            ".example:/cb",
        ] {
            assert!(!redirect_uri_ok(no.as_bytes()), "{no}");
        }
        let long = format!("com.example:/{}", "a".repeat(MAX_URI - 13));
        assert_eq!(long.len(), MAX_URI);
        assert!(redirect_uri_ok(long.as_bytes()));
        assert!(!redirect_uri_ok(format!("{long}a").as_bytes()));
    }

    #[test]
    fn authorize_query_round_trip() {
        let a = Authorize {
            challenge: challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            redirect_uri: "http://127.0.0.1:5000/cb".into(),
            state: "s1".into(),
        };
        assert_eq!(parse_authorize_query(&authorize_query(&a)), Ok(a.clone()));
        let q = authorize_query(&a);
        assert!(parse_authorize_query(&format!("{q}&state=s2")).is_err());
        assert!(parse_authorize_query(&format!("{q}&x=1")).is_err());
        assert!(parse_authorize_query(&q.replace("S256", "plain")).is_err());
        assert!(
            parse_authorize_query(&q.replace("response_type=code", "response_type=token")).is_err()
        );
        let loc = redirect_location(&a.redirect_uri, &[7; 32], &a.state);
        let (_, query) = loc.split_once('?').unwrap();
        assert_eq!(parse_redirect_query(query), Ok(([7; 32], "s1".into())));
        // [USR-4]: a state outside 12.2 is no state, so the app refuses the
        // redirect instead of comparing a malformed value.
        let code = token_text(TokenKind::Code, &[7; 32]);
        for bad in ["", "a%20b", "a b", &"s".repeat(129)] {
            assert!(
                parse_redirect_query(&format!("code={code}&state={bad}")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn tokens() {
        let t = [0xab; 32];
        for k in [TokenKind::Invite, TokenKind::Code, TokenKind::Setup] {
            assert_eq!(parse_token(k, &token_text(k, &t)), Ok(t));
        }
        assert!(parse_token(TokenKind::Setup, &token_text(TokenKind::Code, &t)).is_err());
        assert!(
            parse_token(
                TokenKind::Setup,
                &token_text(TokenKind::Setup, &t).to_uppercase()
            )
            .is_err()
        );
        assert_eq!(token_hash(&t).as_slice(), Sha256::digest(t).as_slice());
    }

    #[test]
    fn token_request_round_trip_and_refusals() {
        let sk = crate::sig::SecretKey::from_seed(&[1; 32]);
        let r = TokenRequest {
            code: [9; 32],
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
            redirect_uri: "com.example.tasks:/cb".into(),
            device: Keys {
                sign: sk.public(),
                seal: Box::new(crate::keys::seal_public(&[2; 32])),
            },
        };
        let body = token_request_body(&r);
        assert_eq!(parse_token_request(&body), Ok(r.clone()));
        let text = String::from_utf8(body).unwrap();
        for no in [
            text.replacen('{', r#"{"x":1,"#, 1),
            text.replacen(r#""code""#, r#""code":"ac_00","code""#, 1),
            text.replace(&r.verifier, "short"),
            text.replace("com.example.tasks:/cb", "http://localhost:1/"),
            text.replace(r#","redirect_uri":"com.example.tasks:/cb""#, ""),
        ] {
            assert!(parse_token_request(no.as_bytes()).is_err(), "{no}");
        }
        let resp = TokenResponse {
            token: [3; 32],
            tenant: format!("t_{}", "0".repeat(32)),
            expires: 600,
        };
        assert_eq!(parse_token_response(&token_response_body(&resp)), Ok(resp));
    }

    #[test]
    fn device_status_rules() {
        let ok = br#"{"state":"paused: quota","outbox":2,"oldest":5,"applied":12,"epoch":1}"#;
        let s = parse_device_status(ok).unwrap();
        assert_eq!(s.oldest, Some(5));
        assert_eq!(parse_device_status(&device_status_body(&s)), Ok(s));
        for no in [
            &br#"{"state":"","outbox":0,"oldest":null,"applied":0,"epoch":1}"#[..],
            br#"{"state":"ok","outbox":1,"oldest":null,"applied":0,"epoch":1}"#,
            br#"{"state":"ok","outbox":0,"oldest":3,"applied":0,"epoch":1}"#,
            br#"{"state":"ok","outbox":0,"oldest":null,"applied":0,"epoch":0}"#,
            br#"{"state":"ok","outbox":0,"oldest":null,"applied":-1,"epoch":1}"#,
            br#"{"state":"ok","outbox":0,"oldest":null,"applied":1.5,"epoch":1}"#,
            br#"{"state":"ok","outbox":0,"oldest":null,"applied":0,"epoch":1,"x":1}"#,
            br#"{"state":"ok","state":"ok","outbox":0,"oldest":null,"applied":0,"epoch":1}"#,
        ] {
            assert!(
                parse_device_status(no).is_err(),
                "{}",
                String::from_utf8_lossy(no)
            );
        }
        assert!(state_text_ok(&[b'a'; 64]));
        assert!(!state_text_ok(&[b'a'; 65]));
        assert!(!state_text_ok(b"a\x7f"));
    }

    #[test]
    fn webhook_urls() {
        let u = parse_webhook_url("https://hooks.slack.com/services/T0/B0/x?y=1").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port),
            (true, "hooks.slack.com", 443)
        );
        let u = parse_webhook_url("http://[::1]:9000/h").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9000));
        assert_eq!(parse_webhook_url("http://10.0.0.1/").unwrap().port, 80);
        for no in [
            "ftp://h/",
            "https://h",
            "https://u@h/",
            "https://h/#f",
            "https://H/",
            "https://h:0/",
            "https://[::01]/",
            "https://h/a b",
        ] {
            assert!(parse_webhook_url(no).is_err(), "{no}");
        }
        assert!(parse_webhook_url(&format!("https://h/{}", "a".repeat(MAX_URI))).is_err());
        assert_eq!(
            webhook_body("a \"b\" \u{e9}"),
            "{\"text\":\"a \\\"b\\\" \u{e9}\"}".as_bytes()
        );
    }

    proptest! {
        /// A redirect URI that the check accepts has no query, fragment or
        /// user part, and fits the limit ([USR-4]).
        #[test]
        fn accepted_redirect_has_no_query(s in "[ -~]{0,40}") {
            if redirect_uri_ok(s.as_bytes()) {
                prop_assert!(!s.contains(['?', '#', '@']));
                prop_assert!(s.starts_with("http://127.0.0.1:") || s.starts_with("http://[::1]:") || s.split(':').next().unwrap().contains('.'));
            }
        }

        /// Each S256 challenge has the accepted form.
        #[test]
        fn challenge_has_its_form(v in "[A-Za-z0-9._~-]{43,128}") {
            prop_assert!(verifier_ok(v.as_bytes()));
            prop_assert!(challenge_ok(challenge(&v).as_bytes()));
        }

        /// The form reader never panics, and an accepted form with a field
        /// holds it once.
        #[test]
        fn form_never_panics(s in "[a-z=&%+0-9A-F]{0,40}") {
            if let Ok(m) = parse_form(s.as_bytes(), &["a", "b"]) {
                prop_assert_eq!(m.len(), 2);
            }
        }

        /// A device status writes back to the same value.
        #[test]
        fn device_status_round_trip(state in "[ -~]{1,64}", outbox in 0u64..1000, oldest in 0u64..(1 << 53), applied in 0u64..(1 << 53), epoch in 1u64..(1 << 53)) {
            let s = DeviceStatus { state, outbox, oldest: (outbox > 0).then_some(oldest), applied, epoch };
            prop_assert_eq!(parse_device_status(&device_status_body(&s)), Ok(s));
        }

        /// The webhook URL reader never panics, and an accepted URL has a
        /// port and a path ([USR-8]).
        #[test]
        fn webhook_parse_never_panics(s in "[ -~]{0,60}") {
            if let Ok(u) = parse_webhook_url(&s) {
                prop_assert!(u.port >= 1);
                prop_assert!(u.target.starts_with('/'));
            }
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// The checks are on bytes, because CBMC cannot finish a symbolic `&str`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// [USR-4] `verifier_ok` and `state_ok` accept exactly the unreserved
    /// characters, for every input of up to 4 bytes. Bound: 4 bytes, so only
    /// the length and character rules below 43 bytes are covered here. The
    /// unit tests cover the 43 and 128 byte limits.
    #[kani::proof]
    #[kani::unwind(6)]
    fn state_and_verifier_characters() {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 4);
        let s = &bytes[..len];
        assert!(!verifier_ok(s));
        if state_ok(s) {
            assert!(len >= 1);
            assert!(
                s.iter()
                    .all(|&b| b != b'%' && b != b'&' && b != b'=' && b != b' ')
            );
        }
    }

    /// [USR-4] An accepted redirect URI has no `?`, `#` or `@`, for every
    /// input of up to 8 bytes. Bound: 8 bytes, so only the private-use form
    /// is reachable. The unit tests cover the loopback form.
    #[kani::proof]
    #[kani::unwind(10)]
    fn redirect_uri_has_no_query() {
        let bytes: [u8; 8] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 8);
        let s = &bytes[..len];
        if redirect_uri_ok(s) {
            assert!(s.iter().all(|&b| b != b'?' && b != b'#' && b != b'@'));
            assert!(s.contains(&b'.'));
        }
    }

    /// The port reader accepts only 1 to 65535 with no leading zero, for
    /// every input of up to 5 bytes, with no overflow.
    #[kani::proof]
    #[kani::unwind(7)]
    fn port_is_strict() {
        let bytes: [u8; 5] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 5);
        let p = &bytes[..len];
        if let Some(n) = port(p) {
            assert!(n >= 1);
            assert!(p[0] != b'0');
        }
    }

    /// `PROTOCOL.md` 10.11: a status text has no control byte, for every input
    /// of up to 4 bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn state_text_has_no_control_byte() {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|&n| n <= 4);
        let s = &bytes[..len];
        if state_text_ok(s) {
            assert!(s.iter().all(|&b| b >= 0x20 && b != 0x7f));
        }
    }
}
