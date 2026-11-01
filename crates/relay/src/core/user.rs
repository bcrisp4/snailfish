//! The user surface (`PROTOCOL.md` 12): invite links, passkey sign-in,
//! browser sessions, the native sign-in approval, and the user page.
//!
//! Security rules ([USR-1] to [USR-7]):
//!
//! - The session selects the user, and the user selects the tenant. No
//!   value of a request selects a tenant ([USR-3]).
//! - Each `POST` needs the exact configured `origin`. Each `POST` with a
//!   session needs the anti-CSRF token of that session ([USR-7]).
//! - The relay stores only SHA-256 of each invite token, code, setup token
//!   and session ID.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

use hmac::{Hmac, KeyInit as _, Mac as _};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use snailfish_protocol::encoding::{decode_id, encode_id, frame};
use snailfish_protocol::setup::{self, TokenKind};
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use super::{
    ApiError, ApiResult, Config, OpenError, Relay, Reply, Request, api, from_i64, header, internal,
    random, safe_name, to_i64,
};
use crate::store::{self, Kind, StoreError};

/// The default quotas of a tenant ([QTA-1], [QTA-5]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// The most spaces of one tenant.
    pub max_spaces: u64,
    /// The most stored change bytes of one space.
    pub space_bytes: u64,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_spaces: 32,
            space_bytes: 256 * 1024 * 1024,
        }
    }
}

/// The quotas of the tenant of `tc`: its own values, or the defaults.
pub(crate) fn limits(tc: &Connection, defaults: &Quotas) -> Result<Quotas, StoreError> {
    let row: Option<(Option<i64>, Option<i64>)> = tc
        .query_row(
            "SELECT max_spaces, space_bytes FROM limits WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (spaces, bytes) = row.unwrap_or((None, None));
    Ok(Quotas {
        max_spaces: spaces
            .map(from_i64)
            .transpose()?
            .unwrap_or(defaults.max_spaces),
        space_bytes: bytes
            .map(from_i64)
            .transpose()?
            .unwrap_or(defaults.space_bytes),
    })
}

/// An invite link expires this many seconds after the command ([USR-1]).
pub const INVITE_SECONDS: u64 = 604_800;
/// An authorization code expires this many seconds after the approval ([USR-4]).
pub const CODE_SECONDS: u64 = 60;
/// A browser session lasts this many seconds.
pub const SESSION_SECONDS: u64 = 43_200;
/// A `WebAuthn` ceremony lasts this many seconds.
pub const CEREMONY_SECONDS: u64 = 300;
/// The most ceremonies that the relay keeps at once (12.4). When full, a
/// new ceremony replaces the oldest, so a flood of starts cannot refuse
/// the sign-in of the user: it must outpace the rate limit of 12.6 for the
/// whole time that the user takes to answer the passkey prompt.
pub const MAX_CEREMONIES: usize = 16_384;
/// The session cookie name.
pub const COOKIE: &str = "sf_session";
/// The HTML content type.
pub const HTML: &str = "text/html; charset=utf-8";

enum Ceremony {
    Register {
        user_id: String,
        state: PasskeyRegistration,
        // The invite that this registration uses. `None` for one more
        // passkey of a signed-in user.
        invite: Option<[u8; 32]>,
    },
    SignIn {
        user_id: String,
        state: PasskeyAuthentication,
    },
}

/// The secrets and the in-memory state of the user surface.
pub(crate) struct Auth {
    session_key: [u8; 32],
    webauthn: Webauthn,
    origin: String,
    secure: bool,
    ceremonies: Mutex<HashMap<[u8; 16], (Ceremony, u64)>>,
}

fn read_or_make_key(dir: &Path) -> Result<[u8; 32], OpenError> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(StoreError::Io)?;
    // [STO-9]: the directory has mode 0700, also if it existed before.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(StoreError::Io)?;
    let path = dir.join("session.key");
    match std::fs::read(&path) {
        Ok(b) => <[u8; 32]>::try_from(b)
            .map_err(|_| OpenError::Store(StoreError::Corrupt("session.key is not 32 bytes"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key: [u8; 32] = random()?;
            let tmp = dir.join("session.key.tmp");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(StoreError::Io)?;
            f.write_all(&key).map_err(StoreError::Io)?;
            f.sync_all().map_err(StoreError::Io)?;
            std::fs::rename(&tmp, &path).map_err(StoreError::Io)?;
            Ok(key)
        }
        Err(e) => Err(StoreError::Io(e).into()),
    }
}

impl Auth {
    pub(crate) fn open(cfg: &Config) -> Result<Self, OpenError> {
        let origin = Url::parse(&cfg.origin).map_err(|_| OpenError::Origin("not a URL"))?;
        if origin.path() != "/" || origin.query().is_some() || cfg.origin.ends_with('/') {
            return Err(OpenError::Origin(
                "the origin has no path, query or trailing /",
            ));
        }
        let host = origin
            .domain()
            .ok_or(OpenError::Origin(
                "the host of the origin must be a domain name",
            ))?
            .to_owned();
        let webauthn = WebauthnBuilder::new(&host, &origin)
            .and_then(|b| b.rp_name("Snailfish").build())
            .map_err(|_| OpenError::Origin("the origin is not a valid WebAuthn relying party"))?;
        Ok(Self {
            session_key: read_or_make_key(&cfg.secrets_dir)?,
            webauthn,
            origin: cfg.origin.clone(),
            secure: origin.scheme() == "https",
            ceremonies: Mutex::new(HashMap::new()),
        })
    }

    fn mac(&self, label: &[u8], id: &[u8; 16]) -> [u8; 32] {
        let mut m = <Hmac<Sha256>>::new_from_slice(&self.session_key)
            .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
        m.update(&frame(&[label, id]));
        m.finalize().into_bytes().into()
    }

    /// The anti-CSRF token of a session (12.4).
    fn csrf(&self, id: &[u8; 16]) -> String {
        hex(&self.mac(b"snailfish.csrf.v1", id))
    }

    fn cookie_value(&self, id: &[u8; 16]) -> String {
        format!(
            "{}.{}",
            hex(id),
            hex(&self.mac(b"snailfish.session.v1", id))
        )
    }

    /// The session ID of a cookie value with a valid MAC.
    fn cookie_id(&self, value: &str) -> Option<[u8; 16]> {
        let (id, mac) = value.split_once('.')?;
        let id: [u8; 16] = decode_id::<16>(id, "").ok()?;
        let mac: [u8; 32] = decode_id::<32>(mac, "").ok()?;
        let mut m = <Hmac<Sha256>>::new_from_slice(&self.session_key).ok()?;
        m.update(&frame(&[b"snailfish.session.v1", &id]));
        m.verify_slice(&mac).ok()?;
        Some(id)
    }

    fn set_cookie(&self, value: &str, max_age: u64) -> (String, String) {
        let secure = if self.secure { "; Secure" } else { "" };
        (
            "set-cookie".into(),
            format!(
                "{COOKIE}={value}; Path=/u; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
            ),
        )
    }

    fn keep(&self, c: Ceremony, now: u64) -> Result<[u8; 16], ApiError> {
        let id: [u8; 16] = random()?;
        let mut m = self.ceremonies.lock().map_err(|_| internal())?;
        m.retain(|_, (_, exp)| now < *exp);
        if m.len() >= MAX_CEREMONIES {
            // Each ceremony lasts the same time, so the oldest expires first.
            let oldest = m.iter().min_by_key(|(_, (_, exp))| *exp).map(|(k, _)| *k);
            if let Some(k) = oldest {
                m.remove(&k);
            }
        }
        m.insert(id, (c, now.saturating_add(CEREMONY_SECONDS)));
        Ok(id)
    }

    fn take(&self, id: &str, now: u64) -> Result<Ceremony, ApiError> {
        let bad = || api(403, "bad_passkey", "the ceremony is unknown or expired");
        let id: [u8; 16] = decode_id::<16>(id, "").map_err(|_| bad())?;
        let mut m = self.ceremonies.lock().map_err(|_| internal())?;
        match m.remove(&id) {
            Some((c, exp)) if now < exp => Ok(c),
            _ => Err(bad()),
        }
    }
}

/// The value of the first `sf_session` cookie of the request (12.4).
pub(super) fn session_cookie(req: &Request) -> Option<&str> {
    req.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .map(|c| c.trim().split_once('=').unwrap_or((c.trim(), "")))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v)
}

fn hex(b: &[u8]) -> String {
    encode_id("", b)
}

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

/// HTML text escape.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn page(title: &str, body: &str) -> Reply {
    Reply {
        status: 200,
        body: format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{t}</title><style>{CSS}</style><script src=\"/u/app.js\" defer></script></head>\
             <body><main><h1>{t}</h1>{body}</main></body></html>",
            t = esc(title)
        )
        .into_bytes(),
        content_type: HTML,
        headers: vec![
            (
                "content-security-policy".into(),
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; \
                 form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
                    .into(),
            ),
            ("cache-control".into(), "no-store".into()),
            ("referrer-policy".into(), "no-referrer".into()),
        ],
    }
}

fn redirect(to: &str) -> Reply {
    Reply {
        status: 303,
        body: Vec::new(),
        content_type: HTML,
        headers: vec![
            ("location".into(), to.to_owned()),
            ("cache-control".into(), "no-store".into()),
        ],
    }
}

fn json_reply(v: &serde_json::Value) -> Reply {
    Reply::json((200, v.to_string().into_bytes()))
}

const CSS: &str = "body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#fafafa;color:#222}\
main{max-width:960px;margin:0 auto;padding:16px}table{border-collapse:collapse;width:100%;margin:8px 0}\
td,th{border-bottom:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}\
code{font-size:12px;word-break:break-all}.warn{color:#a40}form.inline{display:inline}\
section{background:#fff;border:1px solid #ddd;border-radius:6px;padding:8px 16px;margin:16px 0}\
@media (prefers-color-scheme:dark){body{background:#181818;color:#ddd}section{background:#222;border-color:#444}td,th{border-color:#444}}";

/// The script of the `WebAuthn` calls. It converts the base64url fields of
/// the `webauthn-rs` JSON to and from the binary fields of the browser API.
pub const APP_JS: &str = r#""use strict";
const b64u = {
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)),
  enc: (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
};
function csrf() { const m = document.querySelector("meta[name=csrf]"); return m ? m.content : ""; }
async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json", "snailfish-csrf": csrf() }, body: JSON.stringify(body), credentials: "same-origin" });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.message || j.error || r.status);
  return j;
}
async function register(start, finish, extra) {
  const s = await post(start, extra);
  const o = s.options.publicKey;
  o.challenge = b64u.dec(o.challenge);
  o.user.id = b64u.dec(o.user.id);
  (o.excludeCredentials || []).forEach((c) => (c.id = b64u.dec(c.id)));
  const c = await navigator.credentials.create({ publicKey: o });
  await post(finish, { ceremony: s.ceremony, credential: {
    id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
    response: { attestationObject: b64u.enc(c.response.attestationObject), clientDataJSON: b64u.enc(c.response.clientDataJSON) },
    extensions: c.getClientExtensionResults() } });
}
async function signin(name) {
  const s = await post("/u/signin/start", { name });
  const o = s.options.publicKey;
  o.challenge = b64u.dec(o.challenge);
  (o.allowCredentials || []).forEach((c) => (c.id = b64u.dec(c.id)));
  const c = await navigator.credentials.get({ publicKey: o });
  await post("/u/signin/finish", { ceremony: s.ceremony, credential: {
    id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
    response: { authenticatorData: b64u.enc(c.response.authenticatorData), clientDataJSON: b64u.enc(c.response.clientDataJSON),
      signature: b64u.enc(c.response.signature), userHandle: c.response.userHandle ? b64u.enc(c.response.userHandle) : null },
    extensions: c.getClientExtensionResults() } });
}
function report(e) { const p = document.getElementById("msg"); if (p) p.textContent = String(e.message || e); }
document.addEventListener("DOMContentLoaded", () => {
  const f = document.getElementById("signin");
  if (f) f.addEventListener("submit", (ev) => { ev.preventDefault(); signin(f.elements.name.value).then(() => location.reload(), report); });
  const i = document.getElementById("invite");
  if (i) i.addEventListener("click", () => register("/u/invite/start", "/u/invite/finish", { token: location.hash.slice(1) }).then(() => { history.replaceState(null, "", "/u/"); location.assign("/u/"); }, report));
  const a = document.getElementById("addkey");
  if (a) a.addEventListener("click", () => register("/u/passkeys/start", "/u/passkeys/finish", {}).then(() => location.reload(), report));
});
"#;

/// A signed-in user.
struct Session {
    id: [u8; 16],
    user_id: String,
}

/// The user and tenant of a user ID.
struct UserRow {
    name: String,
    tenant_id: String,
}

fn user_row(c: &Connection, user_id: &str) -> Result<Option<UserRow>, StoreError> {
    Ok(c.query_row(
        "SELECT name, tenant_id FROM users WHERE user_id = ?1",
        params![user_id],
        |r| {
            Ok(UserRow {
                name: r.get(0)?,
                tenant_id: r.get(1)?,
            })
        },
    )
    .optional()?)
}

fn webauthn_uuid(user_id: &str) -> Result<Uuid, ApiError> {
    decode_id::<16>(user_id, "u_")
        .map(Uuid::from_bytes)
        .map_err(|_| internal())
}

fn passkeys_of(c: &Connection, user_id: &str) -> Result<Vec<Passkey>, ApiError> {
    let mut st = c.prepare("SELECT passkey FROM passkeys WHERE user_id = ?1 ORDER BY created")?;
    let rows: Vec<String> = st
        .query_map(params![user_id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    rows.iter()
        .map(|j| serde_json::from_str(j).map_err(|_| internal()))
        .collect()
}

/// A JSON body of a user route: strict, as the JSON routes of section 10.
fn json_body(
    body: &[u8],
    names: &[&str],
) -> Result<serde_json::Map<String, serde_json::Value>, ApiError> {
    snailfish_protocol::strict::parse_envelope_json(body)
        .map_err(|e| api(400, "bad_request", e.to_string()))?;
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(m))
            if m.keys().all(|k| names.contains(&k.as_str())) && m.len() == names.len() =>
        {
            Ok(m)
        }
        _ => Err(api(
            400,
            "bad_request",
            format!("the body must hold exactly {}", names.join(", ")),
        )),
    }
}

fn str_field<'a>(
    m: &'a serde_json::Map<String, serde_json::Value>,
    k: &str,
) -> Result<&'a str, ApiError> {
    m.get(k)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| api(400, "bad_request", format!("{k} is not a string")))
}

fn options(ceremony: &[u8; 16], opts: &serde_json::Value) -> Reply {
    json_reply(&serde_json::json!({ "ceremony": hex(ceremony), "options": opts }))
}

impl Relay {
    /// Each route under `/u/` (12.4).
    pub(super) fn user_route(&self, req: &Request, now: u64) -> ApiResult<Reply> {
        // Write rule 1.
        if header(req, "signature").is_some() || header(req, "signature-input").is_some() {
            return Err(api(
                400,
                "bad_request",
                "a user route takes no device signature",
            ));
        }
        let post = req.method == "POST";
        // Write rule 2.
        if post && header(req, "origin") != Some(self.auth.origin.as_str()) {
            return Err(api(
                403,
                "bad_origin",
                "the origin header is not the user page origin",
            ));
        }
        let max = usize::try_from(self.cfg.limits.max_request_bytes).unwrap_or(usize::MAX);
        if req.body.len() > max {
            return Err(api(413, "too_large", "the body is too large"));
        }
        let session = self.session(req, now)?;
        let path = req.path.as_str();
        match (req.method.as_str(), path) {
            ("GET", "/u" | "/u/") => match &session {
                Some(s) => self.home(s, now),
                None => Ok(signin_page("")),
            },
            ("GET", "/u/signin") => Ok(signin_page("")),
            ("GET", "/u/invite") => Ok(invite_page()),
            ("GET", "/u/app.js") => Ok(Reply {
                status: 200,
                body: APP_JS.as_bytes().to_vec(),
                content_type: "text/javascript; charset=utf-8",
                headers: vec![("cache-control".into(), "no-store".into())],
            }),
            ("GET", "/u/authorize") => {
                let a = setup::parse_authorize_query(&req.query)
                    .map_err(|e| api(400, "bad_request", e.0))?;
                match &session {
                    Some(s) => Ok(self.authorize_page(s, &a)),
                    None => Ok(signin_page(
                        "An app asks to set up sync. Sign in, and this page shows its request.",
                    )),
                }
            }
            ("POST", "/u/signin/start") => self.signin_start(req, now),
            ("POST", "/u/signin/finish") => self.signin_finish(req, now),
            ("POST", "/u/invite/start") => self.invite_start(req, now),
            ("POST", "/u/invite/finish") => self.invite_finish(req, now),
            ("POST", _) => {
                // Write rules 3 and 4.
                let s = session.ok_or_else(|| api(401, "signed_out", "sign in first"))?;
                self.session_write(req, now, &s, path)
            }
            _ => Err(api(404, "not_found", "no route has this path")),
        }
    }

    fn session(&self, req: &Request, now: u64) -> ApiResult<Option<Session>> {
        let Some(value) = session_cookie(req) else {
            return Ok(None);
        };
        let Some(id) = self.auth.cookie_id(value) else {
            return Ok(None);
        };
        let d = self.directory()?;
        let user_id: Option<String> = d
            .query_row(
                "SELECT user_id FROM sessions WHERE id_hash = ?1 AND expires > ?2",
                params![sha(&id), to_i64(now)?],
                |r| r.get(0),
            )
            .optional()?;
        Ok(user_id.map(|user_id| Session { id, user_id }))
    }

    fn new_session(&self, c: &Connection, user_id: &str, now: u64) -> ApiResult<(String, String)> {
        let id: [u8; 16] = random()?;
        c.execute(
            "DELETE FROM sessions WHERE expires <= ?1",
            params![to_i64(now)?],
        )?;
        c.execute(
            "INSERT INTO sessions (id_hash, user_id, expires) VALUES (?1, ?2, ?3)",
            params![
                sha(&id),
                user_id,
                to_i64(now.saturating_add(SESSION_SECONDS))?
            ],
        )?;
        Ok(self
            .auth
            .set_cookie(&self.auth.cookie_value(&id), SESSION_SECONDS))
    }

    // ------------------------------------------------------------ sign-in

    fn signin_start(&self, req: &Request, now: u64) -> ApiResult<Reply> {
        let m = json_body(&req.body, &["name"])?;
        let name = str_field(&m, "name")?;
        let d = self.directory()?;
        let user_id: Option<String> = d
            .query_row(
                "SELECT user_id FROM users WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        let no_user = || api(403, "bad_passkey", "no passkey of this user can sign in");
        let user_id = user_id.ok_or_else(no_user)?;
        let keys = passkeys_of(&d, &user_id)?;
        if keys.is_empty() {
            return Err(no_user());
        }
        let (rcr, state): (RequestChallengeResponse, PasskeyAuthentication) = self
            .auth
            .webauthn
            .start_passkey_authentication(&keys)
            .map_err(|_| internal())?;
        let id = self.auth.keep(Ceremony::SignIn { user_id, state }, now)?;
        Ok(options(
            &id,
            &serde_json::to_value(rcr).map_err(|_| internal())?,
        ))
    }

    fn signin_finish(&self, req: &Request, now: u64) -> ApiResult<Reply> {
        let m = json_body(&req.body, &["ceremony", "credential"])?;
        let Ceremony::SignIn { user_id, state } =
            self.auth.take(str_field(&m, "ceremony")?, now)?
        else {
            return Err(api(403, "bad_passkey", "the ceremony is not a sign-in"));
        };
        let cred: PublicKeyCredential = serde_json::from_value(
            m.get("credential").cloned().unwrap_or_default(),
        )
        .map_err(|_| {
            api(
                400,
                "bad_request",
                "credential is not a WebAuthn credential",
            )
        })?;
        let result = self
            .auth
            .webauthn
            .finish_passkey_authentication(&cred, &state)
            .map_err(|_| api(403, "bad_passkey", "the passkey response does not verify"))?;
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The passkey of the result must still belong to the user: a new
        // invite link can remove it during the ceremony ([USR-2]).
        let mut found = false;
        for mut pk in passkeys_of(&tx, &user_id)? {
            if pk.cred_id() == result.cred_id() {
                found = true;
                if pk.update_credential(&result).is_some() {
                    tx.execute(
                        "UPDATE passkeys SET passkey = ?1 WHERE cred_id = ?2",
                        params![
                            serde_json::to_string(&pk).map_err(|_| internal())?,
                            pk.cred_id().as_slice()
                        ],
                    )?;
                }
            }
        }
        if !found {
            return Err(api(
                403,
                "bad_passkey",
                "the passkey is not a passkey of the user",
            ));
        }
        let cookie = self.new_session(&tx, &user_id, now)?;
        tx.commit()?;
        let mut r = json_reply(&serde_json::json!({}));
        r.headers.push(cookie);
        Ok(r)
    }

    // ------------------------------------------------------------ invites

    fn invite_start(&self, req: &Request, now: u64) -> ApiResult<Reply> {
        let m = json_body(&req.body, &["token"])?;
        let bad = || {
            api(
                403,
                "bad_invite",
                "the invite link is unknown, used or expired",
            )
        };
        let token =
            setup::parse_token(TokenKind::Invite, str_field(&m, "token")?).map_err(|_| bad())?;
        let d = self.directory()?;
        let row: Option<(String, i64)> = d
            .query_row(
                "SELECT user_id, expires FROM invites WHERE token_hash = ?1",
                params![setup::token_hash(&token).as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (user_id, expires) = row.ok_or_else(bad)?;
        if now >= from_i64(expires)? {
            return Err(bad());
        }
        self.register_start(&d, &user_id, Some(token), now)
    }

    fn register_start(
        &self,
        d: &Connection,
        user_id: &str,
        invite: Option<[u8; 32]>,
        now: u64,
    ) -> ApiResult<Reply> {
        let name = user_row(d, user_id)?.ok_or_else(internal)?.name;
        let exclude: Vec<_> = passkeys_of(d, user_id)?
            .iter()
            .map(|p| p.cred_id().clone())
            .collect();
        let (ccr, state): (CreationChallengeResponse, PasskeyRegistration) = self
            .auth
            .webauthn
            .start_passkey_registration(
                webauthn_uuid(user_id)?,
                &name,
                &name,
                (!exclude.is_empty() && invite.is_none()).then_some(exclude),
            )
            .map_err(|_| internal())?;
        let id = self.auth.keep(
            Ceremony::Register {
                user_id: user_id.to_owned(),
                state,
                invite,
            },
            now,
        )?;
        Ok(options(
            &id,
            &serde_json::to_value(ccr).map_err(|_| internal())?,
        ))
    }

    fn invite_finish(&self, req: &Request, now: u64) -> ApiResult<Reply> {
        self.register_finish(req, now, None)
    }

    fn register_finish(
        &self,
        req: &Request,
        now: u64,
        session: Option<&Session>,
    ) -> ApiResult<Reply> {
        let m = json_body(&req.body, &["ceremony", "credential"])?;
        let Ceremony::Register {
            user_id,
            state,
            invite,
        } = self.auth.take(str_field(&m, "ceremony")?, now)?
        else {
            return Err(api(
                403,
                "bad_passkey",
                "the ceremony is not a registration",
            ));
        };
        // A ceremony of the invite route needs an invite, and a ceremony of
        // a session needs that session and no invite.
        match (session, invite) {
            (None, Some(_)) => {}
            (Some(s), None) if s.user_id == user_id => {}
            _ => return Err(api(403, "bad_passkey", "the ceremony is for another route")),
        }
        let cred: RegisterPublicKeyCredential = serde_json::from_value(
            m.get("credential").cloned().unwrap_or_default(),
        )
        .map_err(|_| {
            api(
                400,
                "bad_request",
                "credential is not a WebAuthn credential",
            )
        })?;
        let pk = self
            .auth
            .webauthn
            .finish_passkey_registration(&cred, &state)
            .map_err(|_| api(403, "bad_passkey", "the passkey response does not verify"))?;
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(token) = invite {
            // [USR-1]: the link works once, so the registration deletes it
            // in the transaction that stores the passkey.
            let gone = tx.execute(
                "DELETE FROM invites WHERE token_hash = ?1 AND user_id = ?2 AND expires > ?3",
                params![setup::token_hash(&token).as_slice(), user_id, to_i64(now)?],
            )?;
            if gone == 0 {
                return Err(api(
                    403,
                    "bad_invite",
                    "the invite link is unknown, used or expired",
                ));
            }
        }
        tx.execute(
            "INSERT INTO passkeys (cred_id, user_id, passkey, created) VALUES (?1, ?2, ?3, ?4)",
            params![
                pk.cred_id().as_slice(),
                user_id,
                serde_json::to_string(&pk).map_err(|_| internal())?,
                to_i64(now)?
            ],
        )?;
        let mut r = json_reply(&serde_json::json!({}));
        if session.is_none() {
            r.headers.push(self.new_session(&tx, &user_id, now)?);
        }
        tx.commit()?;
        Ok(r)
    }

    // ------------------------------------------------------- session writes

    fn session_write(
        &self,
        req: &Request,
        now: u64,
        session: &Session,
        path: &str,
    ) -> ApiResult<Reply> {
        let want = self.auth.csrf(&session.id);
        let bad_csrf = || api(403, "bad_csrf", "the anti-CSRF token is missing or wrong");
        if matches!(path, "/u/passkeys/start" | "/u/passkeys/finish") {
            if header(req, "snailfish-csrf") != Some(want.as_str()) {
                return Err(bad_csrf());
            }
            if path == "/u/passkeys/finish" {
                return self.register_finish(req, now, Some(session));
            }
            json_body(&req.body, &[])?;
            let dir = self.directory()?;
            return self.register_start(&dir, &session.user_id, None, now);
        }
        let names: &[&str] = match path {
            "/u/authorize" => &[
                "response_type",
                "code_challenge",
                "code_challenge_method",
                "redirect_uri",
                "state",
                "csrf",
            ],
            "/u/groups" => &["name", "csrf"],
            "/u/groups/delete" => &["group", "csrf"],
            "/u/groups/members" => &["group", "device", "op", "csrf"],
            "/u/hold/release" => &["log", "force", "csrf"],
            "/u/webhook" => &["url", "csrf"],
            "/u/signout" | "/u/webhook/test" | "/u/tenant/delete" => &["csrf"],
            _ => return Err(api(404, "not_found", "no route has this path")),
        };
        // The CSRF check runs before any other field check, so a forged
        // form learns nothing from the answer.
        if form_field(&req.body, "csrf").as_deref() != Some(want.as_str()) {
            return Err(bad_csrf());
        }
        let form = setup::parse_form(&req.body, names).map_err(|e| api(400, "bad_request", e.0))?;
        let dir = self.directory()?;
        let user = user_row(&dir, &session.user_id)?
            .ok_or_else(|| api(401, "signed_out", "sign in first"))?;
        let ctx = Form {
            session,
            tdir: self.tenant_by_id(user.tenant_id.clone())?.dir,
            user,
            fields: form,
            now,
        };
        match path {
            "/u/authorize" => approve(&dir, &ctx),
            "/u/signout" => {
                dir.execute(
                    "DELETE FROM sessions WHERE id_hash = ?1",
                    params![sha(&session.id)],
                )?;
                let mut r = redirect("/u/");
                r.headers.push(self.auth.set_cookie("", 0));
                Ok(r)
            }
            "/u/groups" | "/u/groups/delete" | "/u/groups/members" => group_write(&ctx, path),
            "/u/hold/release" => {
                let force = match ctx.field("force") {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(api(400, "bad_request", "force is yes or no")),
                };
                crate::ops::release_hold(
                    &self.cfg.data_dir,
                    &ctx.user.name,
                    ctx.field("log"),
                    force,
                )
                .map_err(|e| api(409, "not_released", e.to_string()))?;
                Ok(redirect("/u/"))
            }
            "/u/webhook" | "/u/webhook/test" => self.webhook_write(&ctx, path),
            "/u/tenant/delete" => self.delete_tenant(&session.user_id, &ctx.user, &ctx.tdir),
            _ => Err(api(404, "not_found", "no route has this path")),
        }
    }

    fn webhook_write(&self, ctx: &Form<'_>, path: &str) -> ApiResult<Reply> {
        let c = store::open(&ctx.tdir.join("tenant.db"), Kind::Tenant, false)?;
        if path == "/u/webhook/test" {
            let set: Option<String> = c
                .query_row("SELECT url FROM webhook WHERE id = 1", [], |r| r.get(0))
                .optional()?;
            if set.is_none() {
                return Err(api(400, "bad_webhook", "set a webhook URL first"));
            }
            c.execute(
                "INSERT INTO webhook_outbox (text, queued) VALUES (?1, ?2)",
                params![
                    "Snailfish: a test message from the user page.",
                    to_i64(ctx.now)?
                ],
            )?;
            return Ok(redirect("/u/"));
        }
        let url = ctx.field("url");
        if url.is_empty() {
            c.execute("DELETE FROM webhook", [])?;
        } else {
            // [USR-8]: the allowlist and the address rule at the set.
            crate::webhook::check_url(url, &self.cfg.webhook_hosts)
                .map_err(|e| api(400, "bad_webhook", e))?;
            c.execute(
                "INSERT INTO webhook (id, url) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE SET url = excluded.url, last_time = NULL, last_result = NULL",
                params![url],
            )?;
        }
        Ok(redirect("/u/"))
    }

    fn delete_tenant(&self, user_id: &str, user: &UserRow, tdir: &Path) -> ApiResult<Reply> {
        // [STO-8]: no tenant directory disappears while a backup copies it.
        let _backup = self.backup_shared()?;
        // Space creation holds this lock from its space count to its commit.
        // So a creation either comes first and this check sees its space, or
        // it waits and then finds no setup token (10.5 step 3).
        let mut tc = store::open(&tdir.join("tenant.db"), Kind::Tenant, false)?;
        let ttx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let spaces: i64 = ttx.query_row(
            "SELECT count(*) FROM spaces WHERE status = 'active'",
            [],
            |r| r.get(0),
        )?;
        if spaces > 0 {
            return Err(api(409, "not_empty", "the tenant has a space"));
        }
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for table in ["passkeys", "invites", "sessions", "codes", "setup_tokens"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE user_id = ?1"),
                params![user_id],
            )?;
        }
        tx.execute("DELETE FROM users WHERE user_id = ?1", params![user_id])?;
        tx.execute(
            "DELETE FROM tenants WHERE tenant_id = ?1",
            params![user.tenant_id],
        )?;
        tx.commit()?;
        // The directory no longer names the tenant, so nothing reaches its
        // files. Best effort: a failed removal leaves an unused directory.
        let _ = std::fs::remove_dir_all(tdir);
        drop(ttx);
        let mut r = page("Deleted", "<p>The account and its tenant are deleted.</p>");
        r.headers.push(self.auth.set_cookie("", 0));
        Ok(r)
    }

    // -------------------------------------------------------------- pages

    fn authorize_page(&self, s: &Session, a: &setup::Authorize) -> Reply {
        let mut b = String::new();
        let _ = write!(
            b,
            "<p>An app asks to set up sync with your account. It will receive the handle of your tenant. \
             It cannot read data of other apps.</p><p>Return address: <code>{}</code></p>\
             <form method=\"post\" action=\"/u/authorize\">\
             <input type=\"hidden\" name=\"response_type\" value=\"code\">\
             <input type=\"hidden\" name=\"code_challenge\" value=\"{}\">\
             <input type=\"hidden\" name=\"code_challenge_method\" value=\"S256\">\
             <input type=\"hidden\" name=\"redirect_uri\" value=\"{}\">\
             <input type=\"hidden\" name=\"state\" value=\"{}\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <button type=\"submit\">Allow</button></form>",
            esc(&a.redirect_uri),
            esc(&a.challenge),
            esc(&a.redirect_uri),
            esc(&a.state),
            self.auth.csrf(&s.id)
        );
        page("Allow the app", &b)
    }

    fn home(&self, session: &Session, now: u64) -> ApiResult<Reply> {
        let dir = self.directory()?;
        let user = user_row(&dir, &session.user_id)?
            .ok_or_else(|| api(401, "signed_out", "sign in first"))?;
        let csrf = self.auth.csrf(&session.id);
        let tenant = self.tenant_by_id(user.tenant_id.clone())?;
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let quota = limits(&tc, &self.cfg.quotas)?;
        let spaces = tenant_spaces(&tc, &tenant.dir)?;
        let devices = tenant_devices(&tc, &tenant.dir, &spaces)?;
        let hidden = format!("<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">");
        let mut html = format!(
            "<meta name=\"csrf\" content=\"{csrf}\"><p>Signed in as <b>{}</b>. \
             <form class=\"inline\" method=\"post\" action=\"/u/signout\">{hidden}<button>Sign out</button></form></p>",
            esc(&user.name)
        );
        html.push_str(&spaces_html(&spaces, &quota, &hidden));
        html.push_str(&devices_html(&devices, now));
        html.push_str(&groups_html(&groups(&tc)?, &devices, &hidden));
        html.push_str(&passkeys_html(&dir, &session.user_id)?);
        if !self.cfg.webhook_hosts.is_empty() {
            html.push_str(&webhook_html(&tc, &self.cfg.webhook_hosts, &hidden)?);
        }
        if spaces.is_empty() {
            let _ = write!(
                html,
                "<section><h2>Delete account</h2><form method=\"post\" action=\"/u/tenant/delete\">{hidden}\
                 <button>Delete the account and its tenant</button></form></section>"
            );
        }
        Ok(page("Snailfish", &html))
    }

    /// The alerts of one tenant for its webhook (12.5): stalled devices and
    /// spaces at 80% of their quota. Each alert goes into the webhook outbox
    /// once until its case ends. Returns the number of new messages.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn queue_alerts(&self, tenant_id: &str, now: u64) -> Result<usize, StoreError> {
        let tenant = self.tenant_by_id(tenant_id.to_owned())?;
        let mut c = store::open(&tenant.db(), Kind::Tenant, false)?;
        let has_hook: Option<i64> = c
            .query_row("SELECT 1 FROM webhook WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        if has_hook.is_none() || self.cfg.webhook_hosts.is_empty() {
            return Ok(0);
        }
        let spaces = tenant_spaces(&c, &tenant.dir)?;
        let devices = tenant_devices(&c, &tenant.dir, &spaces)?;
        let quota = limits(&c, &self.cfg.quotas)?;
        let mut cases: Vec<(String, String)> = Vec::new();
        for sp in &spaces {
            let pct = percent(sp.used, quota.space_bytes);
            if pct >= 80 {
                cases.push((
                    format!("quota:{}", sp.log),
                    format!("Snailfish: {} uses {pct}% of its storage quota.", sp.app),
                ));
            }
        }
        for dv in &devices {
            if let Some(why) = dv.status.as_ref().and_then(|st| stalled(st, now)) {
                cases.push((
                    format!("stalled:{}:{}", dv.log, dv.id),
                    format!(
                        "Snailfish: device \"{}\" in {} is stalled: {why}.",
                        dv.name, dv.app
                    ),
                ));
            }
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // An alert whose case ended is forgotten, so a new case sends again.
        let keys: Vec<String> = cases.iter().map(|(k, _)| k.clone()).collect();
        let old: Vec<String> = {
            let mut st = tx.prepare("SELECT key FROM alerts")?;
            st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
        };
        for k in old.iter().filter(|k| !keys.contains(k)) {
            tx.execute("DELETE FROM alerts WHERE key = ?1", params![k])?;
        }
        let mut n: usize = 0;
        for (key, text) in cases {
            let new = tx.execute(
                "INSERT INTO alerts (key, sent) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![key, to_i64(now)?],
            )?;
            if new == 1 {
                tx.execute(
                    "INSERT INTO webhook_outbox (text, queued) VALUES (?1, ?2)",
                    params![text, to_i64(now)?],
                )?;
                n = n.saturating_add(1);
            }
        }
        tx.commit()?;
        Ok(n)
    }
}

/// The active spaces of a tenant with their usage. `tc` is its `tenant.db`.
fn tenant_spaces(tc: &Connection, tdir: &Path) -> Result<Vec<SpaceRow>, StoreError> {
    let mut st = tc.prepare(
        "SELECT s.log_id, s.file_name, s.app_id, h.since IS NOT NULL FROM spaces s
         LEFT JOIN holds h ON h.log_id = s.log_id WHERE s.status = 'active' ORDER BY s.app_id",
    )?;
    let rows: Vec<(String, String, String, bool)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for (log, file, app, hold) in rows {
        if !safe_name(&file, 26) {
            return Err(StoreError::Corrupt("a space file name is malformed"));
        }
        let sc = store::open(
            &tdir.join("spaces").join(format!("{file}.db")),
            Kind::Space,
            false,
        )?;
        let used: i64 = sc.query_row("SELECT bytes FROM usage WHERE id = 1", [], |r| r.get(0))?;
        let head: i64 =
            sc.query_row("SELECT COALESCE(MAX(position), 0) FROM entries", [], |r| {
                r.get(0)
            })?;
        out.push(SpaceRow {
            log,
            file,
            app,
            hold,
            used: from_i64(used)?,
            head: from_i64(head)?,
        });
    }
    Ok(out)
}

/// The active devices of each space of `spaces`, with their names and
/// their last status reports.
fn tenant_devices(
    tc: &Connection,
    tdir: &Path,
    spaces: &[SpaceRow],
) -> Result<Vec<DeviceRow>, StoreError> {
    let mut out = Vec::new();
    for sp in spaces {
        let sc = store::open(
            &tdir.join("spaces").join(format!("{}.db", sp.file)),
            Kind::Space,
            false,
        )?;
        let mut st = sc.prepare(
            "SELECT d.device_id, e.payload_type, e.envelope FROM devices d
             JOIN entries e ON e.position = d.position ORDER BY d.position",
        )?;
        let rows: Vec<(Vec<u8>, String, String)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (id, ptype, env) in rows {
            let id = encode_id("d_", &id);
            let name = device_name(&ptype, &env, &id).unwrap_or_else(|| "?".to_owned());
            let status = read_status(tc, &sp.log, &id, sp.head)?;
            out.push(DeviceRow {
                id,
                name,
                app: sp.app.clone(),
                log: sp.log.clone(),
                status,
            });
        }
    }
    Ok(out)
}

/// The usage of a space in percent of its quota. A quota of 0 is full.
fn percent(used: u64, quota: u64) -> u64 {
    used.saturating_mul(100).checked_div(quota).unwrap_or(100)
}

/// A form write of a signed-in user.
struct Form<'a> {
    session: &'a Session,
    user: UserRow,
    tdir: std::path::PathBuf,
    fields: std::collections::BTreeMap<String, String>,
    now: u64,
}

impl Form<'_> {
    fn field(&self, k: &str) -> &str {
        self.fields.get(k).map_or("", String::as_str)
    }
}

fn spaces_html(spaces: &[SpaceRow], quota: &Quotas, hidden: &str) -> String {
    let mut html = String::from(
        "<section><h2>Spaces</h2><table><tr><th>App</th><th>Log</th><th>Usage</th><th>Restore hold</th></tr>",
    );
    for sp in spaces {
        let pct = percent(sp.used, quota.space_bytes);
        let warn = if pct >= 80 { " class=\"warn\"" } else { "" };
        let hold = if sp.hold {
            format!(
                "on hold <form class=\"inline\" method=\"post\" action=\"/u/hold/release\">{hidden}\
                 <input type=\"hidden\" name=\"log\" value=\"{l}\">\
                 <select name=\"force\"><option value=\"no\">if repaired</option><option value=\"yes\">even if not repaired</option></select>\
                 <button>Release</button></form>",
                l = esc(&sp.log)
            )
        } else {
            "no".to_owned()
        };
        let _ = write!(
            html,
            "<tr><td>{}</td><td><code>{}</code></td><td{warn}>{} of {} bytes ({pct}%)</td><td>{hold}</td></tr>",
            esc(&sp.app),
            esc(&sp.log),
            sp.used,
            quota.space_bytes
        );
    }
    let _ = write!(
        html,
        "</table><p>{} of {} spaces.</p></section>",
        spaces.len(),
        quota.max_spaces
    );
    html
}

fn devices_html(devices: &[DeviceRow], now: u64) -> String {
    let mut html = String::from(
        "<section><h2>Devices</h2><table><tr><th>Name</th><th>App</th><th>Status</th><th>Last report</th><th>Device ID</th></tr>",
    );
    for dv in devices {
        let status = match &dv.status {
            Some(st) => {
                let stalled = stalled(st, now)
                    .map(|why| format!(" <span class=\"warn\">stalled: {why}</span>"))
                    .unwrap_or_default();
                format!(
                    "{}, outbox {}, applied {}{stalled}",
                    esc(&st.state),
                    st.outbox,
                    st.applied
                )
            }
            None => "no report yet".to_owned(),
        };
        let when = dv
            .status
            .as_ref()
            .map_or_else(String::new, |st| st.time.to_string());
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{status}</td><td>{when}</td><td><code>{}</code></td></tr>",
            esc(&dv.name),
            esc(&dv.app),
            esc(&dv.id)
        );
    }
    html.push_str("</table></section>");
    html
}

fn groups_html(gs: &[(i64, String, Vec<String>)], devices: &[DeviceRow], hidden: &str) -> String {
    let mut html = String::from("<section><h2>Machine groups</h2>");
    for (gid, name, members) in gs {
        let _ = write!(
            html,
            "<h3>{} <form class=\"inline\" method=\"post\" action=\"/u/groups/delete\">{hidden}\
             <input type=\"hidden\" name=\"group\" value=\"{gid}\"><button>Delete</button></form></h3><ul>",
            esc(name)
        );
        for m in members {
            let label = devices
                .iter()
                .find(|d| &d.id == m)
                .map_or(m.as_str(), |d| d.name.as_str());
            let _ = write!(
                html,
                "<li>{} <form class=\"inline\" method=\"post\" action=\"/u/groups/members\">{hidden}\
                 <input type=\"hidden\" name=\"group\" value=\"{gid}\"><input type=\"hidden\" name=\"device\" value=\"{}\">\
                 <input type=\"hidden\" name=\"op\" value=\"remove\"><button>Remove</button></form></li>",
                esc(label),
                esc(m)
            );
        }
        let _ = write!(
            html,
            "</ul><form method=\"post\" action=\"/u/groups/members\">{hidden}<input type=\"hidden\" name=\"group\" value=\"{gid}\">\
             <input type=\"hidden\" name=\"op\" value=\"add\"><select name=\"device\">"
        );
        for dv in devices {
            let _ = write!(
                html,
                "<option value=\"{}\">{} ({})</option>",
                esc(&dv.id),
                esc(&dv.name),
                esc(&dv.app)
            );
        }
        html.push_str("</select><button>Add</button></form>");
    }
    let _ = write!(
        html,
        "<form method=\"post\" action=\"/u/groups\">{hidden}<input name=\"name\" maxlength=\"64\" required>\
         <button>New group</button></form></section>"
    );
    html
}

fn passkeys_html(dir: &Connection, user_id: &str) -> Result<String, StoreError> {
    let mut html = String::from("<section><h2>Passkeys</h2><ul>");
    let mut st =
        dir.prepare("SELECT cred_id, created FROM passkeys WHERE user_id = ?1 ORDER BY created")?;
    let keys: Vec<(Vec<u8>, i64)> = st
        .query_map(params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (id, created) in keys {
        let short = id.get(..8).unwrap_or(&id);
        let _ = write!(
            html,
            "<li><code>{}</code>, added {created}</li>",
            hex(short)
        );
    }
    html.push_str(
        "</ul><button id=\"addkey\" type=\"button\">Add a passkey</button><p id=\"msg\"></p></section>",
    );
    Ok(html)
}

fn webhook_html(tc: &Connection, hosts: &[String], hidden: &str) -> Result<String, StoreError> {
    let row: Option<(String, Option<i64>, Option<String>)> = tc
        .query_row(
            "SELECT url, last_time, last_result FROM webhook WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (url, last) = match &row {
        Some((u, Some(t), Some(r))) => (
            u.as_str(),
            format!("<p>Last message at {t}: {}</p>", esc(r)),
        ),
        Some((u, _, _)) => (u.as_str(), String::new()),
        None => ("", String::new()),
    };
    Ok(format!(
        "<section><h2>Webhook</h2>{last}<form method=\"post\" action=\"/u/webhook\">{hidden}\
         <input name=\"url\" size=\"60\" value=\"{}\"><button>Save</button></form>\
         <form method=\"post\" action=\"/u/webhook/test\">{hidden}<button>Send a test message</button></form>\
         <p>Allowed hosts: {}</p></section>",
        esc(url),
        esc(&hosts.join(", "))
    ))
}

/// `POST /u/authorize` (12.2) ([USR-4]): the code names the user, the
/// challenge and the redirect URI, and works once within 60 seconds.
fn approve(dir: &Connection, ctx: &Form<'_>) -> ApiResult<Reply> {
    let a = setup::check_authorize(&ctx.fields).map_err(|e| api(400, "bad_request", e.0))?;
    let code: [u8; 32] = random()?;
    dir.execute(
        "INSERT INTO codes (code_hash, user_id, challenge, redirect_uri, expires, used)
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![
            setup::token_hash(&code).as_slice(),
            ctx.session.user_id,
            a.challenge,
            a.redirect_uri,
            to_i64(ctx.now.saturating_add(CODE_SECONDS))?
        ],
    )?;
    dir.execute(
        "DELETE FROM codes WHERE expires <= ?1",
        params![to_i64(ctx.now)?],
    )?;
    Ok(redirect(&setup::redirect_location(
        &a.redirect_uri,
        &code,
        &a.state,
    )))
}

fn group_write(ctx: &Form<'_>, path: &str) -> ApiResult<Reply> {
    let mut c = store::open(&ctx.tdir.join("tenant.db"), Kind::Tenant, false)?;
    match path {
        "/u/groups" => {
            let name = ctx.field("name");
            if !(1..=64).contains(&name.len()) {
                return Err(api(400, "bad_request", "a group name is 1 to 64 bytes"));
            }
            c.execute(
                "INSERT OR IGNORE INTO groups (name) VALUES (?1)",
                params![name],
            )?;
        }
        "/u/groups/delete" => {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM group_devices WHERE group_id = ?1",
                params![ctx.field("group")],
            )?;
            tx.execute(
                "DELETE FROM groups WHERE id = ?1",
                params![ctx.field("group")],
            )?;
            tx.commit()?;
        }
        _ => {
            let group: Option<i64> = c
                .query_row(
                    "SELECT id FROM groups WHERE id = ?1",
                    params![ctx.field("group")],
                    |r| r.get(0),
                )
                .optional()?;
            let group = group.ok_or_else(|| api(400, "bad_request", "no such group"))?;
            let device = ctx.field("device");
            // A group member is a device that is active in a space of
            // the tenant (12.4).
            let spaces = tenant_spaces(&c, &ctx.tdir)?;
            if !tenant_devices(&c, &ctx.tdir, &spaces)?
                .iter()
                .any(|d| d.id == device)
            {
                return Err(api(
                    400,
                    "bad_request",
                    "the device is not a device of the tenant",
                ));
            }
            match ctx.field("op") {
                "add" => c.execute(
                    "INSERT OR IGNORE INTO group_devices (group_id, device_id) VALUES (?1, ?2)",
                    params![group, device],
                )?,
                "remove" => c.execute(
                    "DELETE FROM group_devices WHERE group_id = ?1 AND device_id = ?2",
                    params![group, device],
                )?,
                _ => return Err(api(400, "bad_request", "op is add or remove")),
            };
        }
    }
    Ok(redirect("/u/"))
}

/// The value of one field of a form body, if it occurs once.
fn form_field(body: &[u8], name: &str) -> Option<String> {
    let mut found = None;
    for pair in body.split(|&b| b == b'&') {
        let eq = pair.iter().position(|&b| b == b'=').unwrap_or(pair.len());
        let (k, v) = pair.split_at(eq);
        if setup::form_decode(k).as_deref() == Some(name) {
            if found.is_some() {
                return None;
            }
            found = setup::form_decode(v.get(1..).unwrap_or_default());
        }
    }
    found
}

struct SpaceRow {
    log: String,
    file: String,
    app: String,
    hold: bool,
    used: u64,
    head: u64,
}

struct DeviceRow {
    id: String,
    name: String,
    app: String,
    log: String,
    status: Option<StatusRow>,
}

/// The last status report of a device (10.11).
pub(crate) struct StatusRow {
    state: String,
    outbox: u64,
    oldest: Option<u64>,
    applied: u64,
    time: u64,
    behind_since: Option<u64>,
    head: u64,
}

/// A device is stalled after 7 days without a report, after 1 day with an
/// outbox entry older than 1 day, or after 7 days with an applied position
/// behind the log head (DESIGN.md "Monitoring and alerting" item 7).
fn stalled(s: &StatusRow, now: u64) -> Option<&'static str> {
    const DAY: u64 = 86_400;
    if now >= s.time.saturating_add(7 * DAY) {
        Some("no sync for 7 days")
    } else if s.oldest.is_some_and(|o| now >= o.saturating_add(DAY)) {
        Some("an unsent change is older than 1 day")
    } else if s.applied < s.head
        && s.behind_since
            .is_some_and(|b| now >= b.saturating_add(7 * DAY))
    {
        Some("the app is behind the log for 7 days")
    } else {
        None
    }
}

/// The columns of a `device_status` row.
type StatusTuple = (String, i64, Option<i64>, i64, i64, Option<i64>);

fn read_status(
    tc: &Connection,
    log: &str,
    device: &str,
    head: u64,
) -> Result<Option<StatusRow>, StoreError> {
    let row: Option<StatusTuple> = tc
        .query_row(
            "SELECT state, outbox, oldest, applied, time, behind_since FROM device_status
             WHERE log_id = ?1 AND device_id = ?2",
            params![log, device],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    row.map(|(state, outbox, oldest, applied, time, behind)| {
        Ok(StatusRow {
            state,
            outbox: from_i64(outbox)?,
            oldest: oldest.map(from_i64).transpose()?,
            applied: from_i64(applied)?,
            time: from_i64(time)?,
            behind_since: behind.map(from_i64).transpose()?,
            head,
        })
    })
    .transpose()
}

fn groups(tc: &Connection) -> Result<Vec<(i64, String, Vec<String>)>, StoreError> {
    let mut st = tc.prepare("SELECT id, name FROM groups ORDER BY name")?;
    let gs: Vec<(i64, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for (id, name) in gs {
        let mut st = tc.prepare(
            "SELECT device_id FROM group_devices WHERE group_id = ?1 ORDER BY device_id",
        )?;
        let m: Vec<String> = st
            .query_map(params![id], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        out.push((id, name, m));
    }
    Ok(out)
}

/// The name of the device that a genesis record or a grant names.
fn device_name(payload_type: &str, envelope: &str, id: &str) -> Option<String> {
    use snailfish_protocol::envelope::Envelope;
    use snailfish_protocol::records::{Body, parse_payload};
    let env = Envelope::parse(envelope.as_bytes()).ok()?;
    let rec = parse_payload(payload_type, &env.payload).ok()?;
    let (Body::Genesis { device: dev, .. } | Body::Grant { device: dev, .. }) = &rec.body else {
        return None;
    };
    (encode_id("d_", &dev.id) == id).then(|| dev.name.clone())
}

fn signin_page(note: &str) -> Reply {
    let note = if note.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", esc(note))
    };
    page(
        "Sign in",
        &format!(
            "{note}<form id=\"signin\"><label>User name <input name=\"name\" autocomplete=\"username webauthn\" required></label> \
             <button>Sign in with a passkey</button></form><p id=\"msg\"></p>"
        ),
    )
}

fn invite_page() -> Reply {
    page(
        "Register a passkey",
        "<p>This invite link registers a passkey for your account. It works once.</p>\
         <button id=\"invite\" type=\"button\">Register a passkey</button><p id=\"msg\"></p>",
    )
}

impl Relay {
    /// Make a new invite link for a user (12.1): replace the old invite and
    /// remove every passkey, session, authorization code and setup token of
    /// the user, in one transaction ([USR-1], [USR-2]). The operator uses it
    /// to lock out a party with a stolen passkey or session, so no grant of
    /// that party may outlive it. Returns the link.
    ///
    /// # Errors
    ///
    /// [`OpenError::Store`] for a storage failure, and a corrupt-store
    /// error for an unknown user.
    pub fn invite(&self, name: &str) -> Result<String, OpenError> {
        let now = (self.cfg.clock)();
        let token: [u8; 32] = random()?;
        let mut d = self.directory()?;
        let tx = d
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let user_id: Option<String> = tx
            .query_row(
                "SELECT user_id FROM users WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::from)?;
        let user_id = user_id.ok_or(OpenError::UnknownUser)?;
        for table in ["invites", "passkeys", "sessions", "codes", "setup_tokens"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE user_id = ?1"),
                params![user_id],
            )
            .map_err(StoreError::from)?;
        }
        tx.execute(
            "INSERT INTO invites (user_id, token_hash, expires) VALUES (?1, ?2, ?3)",
            params![
                user_id,
                setup::token_hash(&token).as_slice(),
                to_i64(now.saturating_add(INVITE_SECONDS))?
            ],
        )
        .map_err(StoreError::from)?;
        tx.commit().map_err(StoreError::from)?;
        Ok(format!(
            "{}/u/invite#{}",
            self.cfg.origin,
            setup::token_text(TokenKind::Invite, &token)
        ))
    }

    /// Set the quotas of one tenant. `None` keeps the configured default.
    ///
    /// # Errors
    ///
    /// [`OpenError::UnknownUser`] and a storage failure.
    pub fn set_quotas(
        &self,
        name: &str,
        max_spaces: Option<u64>,
        space_bytes: Option<u64>,
    ) -> Result<(), OpenError> {
        let d = self.directory()?;
        let tenant: Option<String> = d
            .query_row(
                "SELECT tenant_id FROM users WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::from)?;
        let tenant = self.tenant_by_id(tenant.ok_or(OpenError::UnknownUser)?)?;
        let c = store::open(&tenant.db(), Kind::Tenant, false)?;
        c.execute(
            "INSERT INTO limits (id, max_spaces, space_bytes) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET max_spaces = excluded.max_spaces, space_bytes = excluded.space_bytes",
            params![max_spaces.map(to_i64).transpose()?, space_bytes.map(to_i64).transpose()?],
        )
        .map_err(StoreError::from)?;
        Ok(())
    }

    /// The tenant IDs of the relay, for the webhook loop.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn tenant_ids(&self) -> Result<Vec<String>, StoreError> {
        let d = self.directory()?;
        let mut st = d.prepare("SELECT tenant_id FROM tenants ORDER BY tenant_id")?;
        let out = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        Ok(out)
    }

    /// Issue an authorization code for a user without a browser, as the
    /// approval of 12.2 does. Only the `test-support` feature has it, for
    /// tests of the setup token exchange against the real core.
    ///
    /// # Errors
    ///
    /// [`OpenError::UnknownUser`] and a storage failure.
    #[cfg(feature = "test-support")]
    pub fn issue_code(
        &self,
        name: &str,
        challenge: &str,
        redirect_uri: &str,
    ) -> Result<String, OpenError> {
        let now = (self.cfg.clock)();
        let d = self.directory()?;
        let user_id: Option<String> = d
            .query_row(
                "SELECT user_id FROM users WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::from)?;
        let user_id = user_id.ok_or(OpenError::UnknownUser)?;
        let code: [u8; 32] = random()?;
        d.execute(
            "INSERT INTO codes (code_hash, user_id, challenge, redirect_uri, expires, used)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![
                setup::token_hash(&code).as_slice(),
                user_id,
                challenge,
                redirect_uri,
                to_i64(now.saturating_add(CODE_SECONDS))?
            ],
        )
        .map_err(StoreError::from)?;
        Ok(setup::token_text(TokenKind::Code, &code))
    }
}

/// One queued webhook message of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    /// The outbox row.
    pub seq: i64,
    /// The webhook URL.
    pub url: String,
    /// The message text.
    pub text: String,
}

impl Relay {
    /// The oldest queued webhook message of a tenant, if the tenant has a
    /// webhook URL.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn next_webhook(&self, tenant_id: &str) -> Result<Option<Queued>, StoreError> {
        let c = store::open(
            &self.tenant_by_id(tenant_id.to_owned())?.db(),
            Kind::Tenant,
            false,
        )?;
        let url: Option<String> = c
            .query_row("SELECT url FROM webhook WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        let Some(url) = url else {
            // Without a URL, a queued message has nowhere to go.
            c.execute("DELETE FROM webhook_outbox", [])?;
            return Ok(None);
        };
        Ok(c.query_row(
            "SELECT seq, text FROM webhook_outbox ORDER BY seq LIMIT 1",
            [],
            |r| {
                Ok(Queued {
                    seq: r.get(0)?,
                    url: url.clone(),
                    text: r.get(1)?,
                })
            },
        )
        .optional()?)
    }

    /// Record the result of one send and remove the message. The relay sends
    /// each message once: a failed send shows on the user page.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn webhook_sent(&self, tenant_id: &str, seq: i64, result: &str) -> Result<(), StoreError> {
        let now = (self.cfg.clock)();
        let mut c = store::open(
            &self.tenant_by_id(tenant_id.to_owned())?.db(),
            Kind::Tenant,
            false,
        )?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM webhook_outbox WHERE seq = ?1", params![seq])?;
        tx.execute(
            "UPDATE webhook SET last_time = ?1, last_result = ?2 WHERE id = 1",
            params![to_i64(now)?, result],
        )?;
        tx.commit()?;
        Ok(())
    }
}
