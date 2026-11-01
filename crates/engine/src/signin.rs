//! The native sign-in of a first device (`PROTOCOL.md` 12.2 and 12.3): an
//! authorization code with PKCE, then a setup token that the device key
//! requests ([USR-4], [USR-5]). The setup token goes to
//! [`crate::setup::install_setup`], and the tenant handle names the space.
//!
//! The engine does no network I/O. The app opens [`SignIn::authorize_url`]
//! in the system browser, gives the redirect URL back, sends the request of
//! [`SignIn::token_request`] and passes the response to
//! [`SignIn::read_token`]. After an `expired` answer, the sign-in keeps the
//! relay time of the answer, and one more [`SignIn::token_request`] signs
//! with the corrected time (`PROTOCOL.md` 8.5).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use snailfish_protocol::encoding::encode_id;
use snailfish_protocol::keys;
use snailfish_protocol::records::Keys;
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::setup::{self, Authorize, TokenKind, TokenRequest};
use snailfish_protocol::sig::SecretKey;

use crate::sync::authority;
use crate::{DeviceKeys, EngineError, Header, Request};

/// The result of a sign-in: the setup token and the tenant handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupToken {
    /// The setup token text (`st_...`).
    pub token: String,
    /// The tenant handle text (`t_...`).
    pub tenant: String,
    /// The relay time at which the token expires.
    pub expires: u64,
}

/// One native sign-in. It holds the PKCE verifier, so the app keeps it until
/// the browser returns.
pub struct SignIn {
    relay_url: String,
    authorize: Authorize,
    verifier: String,
    // Seconds to add to the app clock: relay time - app time ([WIR-7]).
    offset: AtomicI64,
    // The app time of the last token request.
    sent_at: AtomicU64,
}

impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier is a secret until the exchange.
        f.debug_struct("SignIn")
            .field("relay_url", &self.relay_url)
            .finish_non_exhaustive()
    }
}

fn bad(msg: impl Into<String>) -> EngineError {
    EngineError::Invalid(msg.into())
}

impl SignIn {
    /// Start a sign-in at the relay for `redirect_uri`, a loopback or
    /// private-use redirect URI of 12.2.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a redirect URI that breaks 12.2, and
    /// [`EngineError::Random`].
    pub fn new(relay_url: &str, redirect_uri: &str) -> Result<Self, EngineError> {
        if !setup::redirect_uri_ok(redirect_uri.as_bytes()) {
            return Err(bad("the redirect URI breaks PROTOCOL.md 12.2"));
        }
        let v: [u8; 32] = keys::random_bytes().map_err(|_| EngineError::Random)?;
        let s: [u8; 16] = keys::random_bytes().map_err(|_| EngineError::Random)?;
        let verifier = URL_SAFE_NO_PAD.encode(v);
        Ok(Self {
            relay_url: relay_url.trim_end_matches('/').to_owned(),
            authorize: Authorize {
                challenge: setup::challenge(&verifier),
                redirect_uri: redirect_uri.to_owned(),
                state: encode_id("", &s),
            },
            verifier,
            offset: AtomicI64::new(0),
            sent_at: AtomicU64::new(0),
        })
    }

    /// The URL for the system browser.
    #[must_use]
    pub fn authorize_url(&self) -> String {
        format!(
            "{}/u/authorize?{}",
            self.relay_url,
            setup::authorize_query(&self.authorize)
        )
    }

    /// The code challenge of this sign-in.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.authorize.challenge
    }

    /// The setup token request for the URL that the browser redirected to.
    /// The device key signs it, with `now`, the app time, and the offset of
    /// an earlier `expired` answer.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a redirect that is not this redirect
    /// URI, with another `state`, or with no code.
    pub fn token_request(
        &self,
        redirect: &str,
        keys: &DeviceKeys,
        now: u64,
    ) -> Result<Request, EngineError> {
        let query = redirect
            .strip_prefix(self.authorize.redirect_uri.as_str())
            .and_then(|r| r.strip_prefix('?'))
            .ok_or_else(|| bad("the redirect is not for this redirect URI"))?;
        let (code, state) = setup::parse_redirect_query(query).map_err(|e| bad(e.0))?;
        // The state ties the redirect to this sign-in, so another app cannot
        // hand this app a code of another request.
        if state != self.authorize.state {
            return Err(bad("the redirect holds another state"));
        }
        let sk = SecretKey::from_seed(&keys.sign_seed);
        let seal = Box::new(keys::seal_public(&keys.seal_seed));
        let device = Keys {
            sign: sk.public(),
            seal: seal.clone(),
        };
        let body = setup::token_request_body(&TokenRequest {
            code,
            verifier: self.verifier.clone(),
            redirect_uri: self.authorize.redirect_uri.clone(),
            device,
        });
        let auth = authority(&self.relay_url);
        let path = "/v1/setup/token";
        self.sent_at.store(now, Ordering::Relaxed);
        let created = now
            .checked_add_signed(self.offset.load(Ordering::Relaxed))
            .unwrap_or(now);
        let p = Params {
            created,
            expires: created.saturating_add(request::MAX_LIFETIME),
            nonce: keys::random_bytes().map_err(|_| EngineError::Random)?,
            keyid: keys::device_id(&sk.public(), &seal),
        };
        let t = Target {
            method: "POST",
            authority: &auth,
            path,
            query: "",
        };
        let mut headers = vec![
            Header {
                name: "accept".into(),
                value: "application/json".into(),
            },
            Header {
                name: "content-type".into(),
                value: "application/json".into(),
            },
        ];
        for (name, value) in request::sign(&sk, &t, &body, &p).pairs() {
            headers.push(Header {
                name: name.into(),
                value: value.into(),
            });
        }
        Ok(Request {
            method: "POST".into(),
            url: format!("{}{path}", self.relay_url),
            headers,
            body,
        })
    }

    /// Read the answer of the setup token request.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] with the relay error code. After `expired`
    /// the app sends one more [`SignIn::token_request`]. After `bad_setup`
    /// the app starts the sign-in again.
    pub fn read_token(
        &self,
        status: u16,
        headers: &[Header],
        body: &[u8],
    ) -> Result<SetupToken, EngineError> {
        let relay = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(request::TIME_HEADER))
            .and_then(|h| request::parse_time(&h.value));
        if let Some(t) = relay {
            let sent = self.sent_at.load(Ordering::Relaxed);
            let diff = i128::from(t).saturating_sub(i128::from(sent));
            self.offset
                .store(i64::try_from(diff).unwrap_or(0), Ordering::Relaxed);
        }
        if status != 200 {
            let code = snailfish_protocol::wire::parse_error(body)
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(bad(format!("the relay refused the sign-in: {code}")));
        }
        let r = setup::parse_token_response(body).map_err(|e| bad(e.0))?;
        Ok(SetupToken {
            token: setup::token_text(TokenKind::Setup, &r.token),
            tenant: r.tenant,
            expires: r.expires,
        })
    }
}
