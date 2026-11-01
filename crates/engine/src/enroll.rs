//! Enrollment in both directions (DESIGN.md "Enrollment", [ENR-1] to
//! [ENR-9], `PROTOCOL.md` 10.10 and section 11), and the grant outbox with
//! the [LOG-7] retry.
//!
//! Like [`crate::Sync`], each enrollment is a state machine with no network
//! I/O. The app calls `next_request`, sends the request, and passes the
//! response to `handle_response`. While [`EnrollState::Waiting`] holds, the
//! other device has not written its next message: the app waits about one
//! second and asks for the next request again.
//!
//! `specs/enrollment/` checks the transcript in a symbolic model, and
//! `specs/spacelog/` checks the grant and the [LOG-7] retry
//! (`signGrant`, `resignReconfirmTest`, `retryChecksStateTest`).

use snailfish_protocol::encoding::{Hash32, encode_id};
use snailfish_protocol::enroll::{self, Payload, Role, Transcript};
use snailfish_protocol::envelope::{self, Envelope};
use snailfish_protocol::keys;
use snailfish_protocol::mailbox::{self, Session, State};
use snailfish_protocol::records::{
    Author, Body, Device, KeySet, Keys, parse_device_json, parse_payload,
};
use snailfish_protocol::recovery;
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::wire::{self, AppendResult};
use snailfish_protocol::write;

use crate::state::{self, GRANT_CONFIRM, GRANT_SEND, GRANT_STALE, GrantRow};
use crate::sync::{Item, authority};
use crate::{DeviceKeys, Engine, EngineError, Header, MAX_LEVEL, Request, SpaceRef, Status};

/// The most syncs that a trusted device runs to append one grant.
const MAX_GRANT_SYNCS: u32 = 5;

/// The state of an enrollment that the app shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollState {
    /// The other device has not written its next message. Wait about one
    /// second, then ask for the next request.
    Waiting,
    /// Show the 6-digit code. The user compares it with the code on the
    /// other device and calls `confirm` ([ENR-7]).
    Compare {
        /// The 6 decimal digits.
        code: String,
    },
    /// Trusted device only: a grant or a removal arrived after the user
    /// confirmed, so the device list changed. The user confirms the grant
    /// again with `confirm` ([LOG-7]).
    ConfirmAgain,
    /// The enrollment works on its own: send the next request.
    Busy,
    /// The enrollment ended. The trusted device appended the grant and sent
    /// the checkpoint, or the new device holds a checked `trusted.done`.
    Done,
    /// The enrollment failed, with the cause. The user starts a new one.
    Failed {
        /// The cause, for the user.
        cause: String,
    },
}

fn rand<const N: usize>() -> Result<[u8; N], EngineError> {
    keys::random_bytes().map_err(|_| EngineError::Random)
}

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.into(),
        value: value.into(),
    }
}

fn json_headers(body: &[u8]) -> Vec<Header> {
    let mut h = vec![header("accept", "application/json")];
    if !body.is_empty() {
        h.push(header("content-type", "application/json"));
    }
    h
}

/// The relay URL form of a payload (`PROTOCOL.md` 11.1): the scheme and
/// the authority of 8.3, in lowercase, with no default port. The engine
/// accepts a configured URL in other forms (`relay_base`).
fn payload_url(relay_url: &str) -> String {
    let scheme = relay_url
        .split_once("://")
        .map_or("https", |(s, _)| s)
        .to_ascii_lowercase();
    format!("{scheme}://{}", authority(relay_url))
}

fn read_payload_or_code(text: &str, own: Role) -> Result<([u8; 16], Option<String>), EngineError> {
    if text.starts_with(enroll::PAYLOAD_VERSION) {
        let p = enroll::parse_payload(text).map_err(|e| EngineError::Invalid(e.to_string()))?;
        if p.role == own {
            return Err(EngineError::Invalid(
                "the payload comes from a device with the same role".into(),
            ));
        }
        Ok((p.session, Some(p.relay_url)))
    } else {
        let s = enroll::parse_code(text).map_err(|e| EngineError::Invalid(e.to_string()))?;
        Ok((s, None))
    }
}

/// The device object of a genesis record or a grant envelope.
pub(crate) fn grant_device(json: &str) -> Option<Device> {
    let env = Envelope::parse(json.as_bytes()).ok()?;
    match parse_payload(&env.payload_type, &env.payload).ok()?.body {
        Body::Genesis { device, .. } | Body::Grant { device, .. } => Some(device),
        _ => None,
    }
}

/// The signer of a grant: the device key, or the recovery key that the
/// user typed (M4 decision 1).
pub(crate) enum Signer<'a> {
    Device,
    Recovery(&'a [u8; 16]),
}

/// Sign a grant for `device` on the verified head, with the app key sealed
/// to it (`PROTOCOL.md` 6.2 and 7.3).
pub(crate) fn sign_grant(
    e: &Engine,
    device: &Device,
    signer: &Signer<'_>,
) -> Result<String, EngineError> {
    let app_key = e
        .app_key
        .ok_or_else(|| EngineError::Invalid("the engine has no app key".into()))?;
    let sealed = keys::seal_key_set(
        &device.keys.seal[..],
        &e.log_id,
        &device.id,
        &[1],
        &[app_key],
    )
    .map_err(|err| EngineError::Invalid(format!("seal: {err}")))?;
    let set = KeySet {
        to: Author::Device(device.id),
        epochs: vec![1],
        sealed,
    };
    let base = e.base()?;
    let t = "snailfish.grant.v1";
    let (author, key) = match signer {
        Signer::Device => (Author::Device(e.device_id), None),
        Signer::Recovery(secret) => {
            let (sign_seed, seal_seed) = recovery::derive(secret);
            let k = SecretKey::from_seed(&sign_seed);
            let rid = keys::recovery_id(&k.public(), &keys::seal_public(&seal_seed));
            (Author::Recovery(rid), Some(k))
        }
    };
    let payload = write::grant(&e.log_id, &author, &base, device, &set);
    let sig = key.as_ref().unwrap_or(&e.sign).sign_record(t, &payload);
    let keyid = match author {
        Author::Device(id) => encode_id("d_", &id),
        Author::Recovery(id) => encode_id("r_", &id),
    };
    Ok(envelope::write_json(t, &payload, &sig, &keyid))
}

/// The grants to send in this sync, after the [LOG-7] rule for each grant
/// that the relay refused with `stale_base`: drop it if the verified log
/// makes its device active, sign it again on the verified head if the
/// device list equals the confirmed list, and ask the user otherwise. A
/// grant by the recovery key needs the key again, so the user confirms.
pub(crate) fn grants_to_send(e: &mut Engine) -> Result<Vec<(Item, String)>, EngineError> {
    let mut out = Vec::new();
    let list = state::device_list(&e.db)?;
    for mut g in state::grants(&e.db)? {
        if state::is_active(&e.db, &g.device_id)? {
            state::drop_grant(&e.db, &g.device_id)?;
            continue;
        }
        if g.state == GRANT_STALE {
            if !g.by_recovery && g.confirmed == list {
                let d = parse_device_json(g.device.as_bytes())
                    .map_err(|err| EngineError::Storage(err.to_string()))?;
                g.envelope = Some(sign_grant(e, &d, &Signer::Device)?);
                g.state = GRANT_SEND.into();
                state::put_grant(&e.db, &g)?;
            } else {
                state::set_grant_state(&e.db, &g.device_id, GRANT_CONFIRM)?;
                continue;
            }
        }
        if g.state == GRANT_SEND
            && let Some(env) = g.envelope
        {
            out.push((Item::Grant(g.device_id), env));
        }
    }
    Ok(out)
}

/// The append result of a grant ([LOG-7], `PROTOCOL.md` 10.6).
pub(crate) fn grant_answer(
    e: &mut Engine,
    id: &Hash32,
    r: &AppendResult,
) -> Result<(), EngineError> {
    match r {
        // The grant leaves the outbox when the verified log holds it.
        AppendResult::Stored(_) | AppendResult::Known(_) | AppendResult::Conflict(_) => {}
        AppendResult::Refused(code) if code == "stale_base" => {
            state::set_grant_state(&e.db, id, GRANT_STALE)?;
        }
        // [LOG-6]: transient. A repair puts the base back into the log.
        AppendResult::Refused(code) if code == "bad_base" => {}
        AppendResult::Refused(code) => {
            state::drop_grant(&e.db, id)?;
            e.grant_refusals.insert(*id, code.clone());
            e.status = Status::Degraded {
                cause: format!("grant refused: {code}"),
            };
        }
    }
    Ok(())
}

impl Engine {
    /// Confirm again a grant that waits for the user ([LOG-7]): sign it on
    /// the verified head with the current device list as the confirmed list.
    /// A grant by the recovery key needs the recovery key.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] if no grant for the device waits, or the
    /// recovery key is missing or wrong.
    pub fn confirm_grant(
        &mut self,
        device_id: &str,
        recovery_key: Option<String>,
    ) -> Result<(), EngineError> {
        let id = snailfish_protocol::encoding::decode_id::<32>(device_id, "d_")
            .map_err(|err| EngineError::Invalid(format!("device ID: {err}")))?;
        let mut g = state::grants(&self.db)?
            .into_iter()
            .find(|g| g.device_id == id && g.state == GRANT_CONFIRM)
            .ok_or_else(|| EngineError::Invalid("no grant for this device waits".into()))?;
        let secret = match (g.by_recovery, recovery_key) {
            (true, Some(k)) => {
                Some(recovery::parse(&k).map_err(|err| EngineError::Invalid(err.to_string()))?)
            }
            (true, None) => {
                return Err(EngineError::Invalid(
                    "the grant needs the recovery key".into(),
                ));
            }
            (false, _) => None,
        };
        let d = parse_device_json(g.device.as_bytes())
            .map_err(|err| EngineError::Storage(err.to_string()))?;
        let signer = secret.as_ref().map_or(Signer::Device, Signer::Recovery);
        g.envelope = Some(sign_grant(self, &d, &signer)?);
        g.confirmed = state::device_list(&self.db)?;
        g.state = GRANT_SEND.into();
        state::put_grant(&self.db, &g)
    }

    /// The grants that wait for the user to confirm them again ([LOG-7]),
    /// as device IDs.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn grants_to_confirm(&self) -> Result<Vec<String>, EngineError> {
        Ok(state::grants(&self.db)?
            .into_iter()
            .filter(|g| g.state == GRANT_CONFIRM)
            .map(|g| encode_id("d_", &g.device_id))
            .collect())
    }

    /// The current recovery ID of the space, from the genesis record.
    fn recovery_id(&self) -> Result<Option<Hash32>, EngineError> {
        let Some((_, g)) = state::log_range(&self.db, 1, 1)?.into_iter().next() else {
            return Ok(None);
        };
        Ok(snailfish_protocol::space::genesis_recovery_of(&g).map(|(r, _)| r))
    }
}

/// What the trusted device waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TStep {
    Open,
    Hello,
    Nonce,
    Compare,
    Confirm,
    Grant,
    Done,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TSent {
    Open,
    Read,
    Write(mailbox::Slot),
    Cancel,
    Sync,
}

/// The enrollment on the trusted device (`PROTOCOL.md` 11.2 steps 2, 4, 6,
/// 8 and 10). Pass the engine of the space to each call.
pub struct TrustedEnrollment {
    session: [u8; 16],
    payload: Option<String>,
    recovery: Option<[u8; 16]>,
    step: TStep,
    state: EnrollState,
    sent: Option<TSent>,
    new_device: Option<Device>,
    t_nonce: [u8; 32],
    n_nonce: Option<[u8; 32]>,
    sync: Option<crate::Sync>,
    syncs: u32,
    // A message to write before the next read.
    pending: Option<(mailbox::Slot, Vec<u8>)>,
    // The code to show once the relay holds the nonce of this device.
    code: Option<String>,
    cancel_cause: Option<String>,
    // The last signed request, to send again once after `expired` with
    // the corrected clock offset (`PROTOCOL.md` 10.3).
    last: Option<(TSent, &'static str, String, Vec<u8>)>,
    retried: bool,
    resend: bool,
}

impl std::fmt::Debug for TrustedEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedEnrollment")
            .field("step", &self.step)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl TrustedEnrollment {
    /// Start an enrollment on a trusted device. If `scanned` is `None`, the
    /// device shows the session: call [`TrustedEnrollment::payload`] and
    /// [`TrustedEnrollment::code`]. Otherwise `scanned` is the payload or
    /// the typed code that the new device shows ([ENR-1]). If the user
    /// types the recovery key, it signs the grant (M4 decision 1).
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a payload or code that breaks
    /// `PROTOCOL.md` 11.1, a payload of another relay, or a recovery key
    /// that is not the recovery key of the space, and
    /// [`EngineError::Random`].
    pub fn new(
        engine: &Engine,
        scanned: Option<String>,
        recovery_key: Option<String>,
    ) -> Result<Self, EngineError> {
        // A device can grant only with the app key and a checked log
        // ([ENR-9]), so refuse before the users compare codes.
        if engine.app_key.is_none() || state::checkpoint(&engine.db)?.is_some() {
            return Err(EngineError::Invalid(
                "this device has not finished its own enrollment: sync it first".into(),
            ));
        }
        if matches!(engine.status, Status::Fork { .. }) {
            return Err(EngineError::Invalid(
                "sync is stopped on this device".into(),
            ));
        }
        let recovery = recovery_key
            .map(|k| recovery::parse(&k).map_err(|err| EngineError::Invalid(err.to_string())))
            .transpose()?;
        if let Some(secret) = &recovery {
            let (sign, seal) = recovery::derive(secret);
            let rid = keys::recovery_id(
                &SecretKey::from_seed(&sign).public(),
                &keys::seal_public(&seal),
            );
            if engine.recovery_id()? != Some(rid) {
                return Err(EngineError::Invalid(
                    "this is not the recovery key of the space".into(),
                ));
            }
        }
        let own = payload_url(&engine.space.relay_url);
        let (session, payload) = if let Some(text) = scanned {
            let (session, relay) = read_payload_or_code(&text, Role::Trusted)?;
            if relay.is_some_and(|r| r != own) {
                return Err(EngineError::Invalid(
                    "the payload names another relay".into(),
                ));
            }
            (session, None)
        } else {
            let session = rand()?;
            let p = enroll::payload(&Payload {
                role: Role::Trusted,
                relay_url: own,
                session,
            });
            (session, Some(p))
        };
        Ok(Self {
            session,
            payload,
            recovery,
            step: TStep::Open,
            state: EnrollState::Busy,
            sent: None,
            new_device: None,
            t_nonce: rand()?,
            n_nonce: None,
            sync: None,
            syncs: 0,
            pending: None,
            code: None,
            cancel_cause: None,
            last: None,
            retried: false,
            resend: false,
        })
    }

    /// The QR payload to show, if this device shows the session. It is
    /// `None` until the relay opened the session, so a new device that
    /// reads it always finds the session (`PROTOCOL.md` 11.2 step 2).
    #[must_use]
    pub fn payload(&self) -> Option<String> {
        self.payload.clone().filter(|_| self.step != TStep::Open)
    }

    /// The typed code of the session, if this device shows it, after the
    /// relay opened the session. Otherwise the code of the scanned session.
    #[must_use]
    pub fn code(&self) -> Option<String> {
        (self.payload.is_none() || self.step != TStep::Open).then(|| enroll::display(&self.session))
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> EnrollState {
        self.state.clone()
    }

    /// The answer of the user: true if the codes on both devices match
    /// ([ENR-7]), or, in [`EnrollState::ConfirmAgain`], true if the user
    /// confirms the grant again ([LOG-7]). False cancels the enrollment.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] if no question waits, and the errors of
    /// [`Engine::confirm_grant`].
    pub fn confirm(&mut self, engine: &mut Engine, yes: bool) -> Result<(), EngineError> {
        match (&self.state, yes) {
            (EnrollState::Compare { .. }, true) => {
                self.step = TStep::Confirm;
                self.state = EnrollState::Busy;
            }
            (EnrollState::ConfirmAgain, true) => {
                let id = self.device()?.id;
                let key = self.recovery.map(|s| recovery::display(&s));
                engine.confirm_grant(&encode_id("d_", &id), key)?;
                self.state = EnrollState::Busy;
            }
            (EnrollState::Compare { .. } | EnrollState::ConfirmAgain, false) => {
                if let Some(d) = &self.new_device {
                    state::drop_grant(&engine.db, &d.id)?;
                }
                self.cancel("the user reported that the codes differ");
            }
            _ => return Err(EngineError::Invalid("no question waits".into())),
        }
        Ok(())
    }

    fn cancel(&mut self, cause: &str) {
        self.cancel_cause = Some(cause.into());
        self.step = TStep::End;
        self.state = EnrollState::Busy;
    }

    fn fail(&mut self, cause: impl Into<String>) {
        self.step = TStep::End;
        self.state = EnrollState::Failed {
            cause: cause.into(),
        };
    }

    fn device(&self) -> Result<&Device, EngineError> {
        self.new_device
            .as_ref()
            .ok_or(EngineError::UnexpectedResponse)
    }

    fn path(&self, engine: &Engine, session: bool) -> String {
        let sp = &engine.space;
        if session {
            format!(
                "/v1/t/{}/s/{}/enroll/{}",
                sp.tenant,
                sp.log_id,
                encode_id("e_", &self.session)
            )
        } else {
            format!("/v1/t/{}/s/{}/enroll", sp.tenant, sp.log_id)
        }
    }
}

/// A request on a signed route of the trusted device (`PROTOCOL.md` 8).
fn signed(
    engine: &Engine,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<Request, EngineError> {
    let now = engine.now();
    let p = Params {
        created: now,
        expires: now.saturating_add(request::MAX_LIFETIME),
        nonce: rand()?,
        keyid: engine.device_id,
    };
    let auth = authority(&engine.space.relay_url);
    let t = Target {
        method,
        authority: &auth,
        path,
        query: "",
    };
    let mut headers = json_headers(&body);
    for (name, value) in request::sign(&engine.sign, &t, &body, &p).pairs() {
        headers.push(header(name, value));
    }
    Ok(Request {
        method: method.into(),
        url: format!("{}{path}", engine.space.relay_url),
        headers,
        body,
    })
}

impl TrustedEnrollment {
    /// The next request, or `None` if the enrollment waits for the user or
    /// ended.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`], [`EngineError::Random`] and
    /// [`EngineError::Invalid`].
    pub fn next_request(&mut self, engine: &mut Engine) -> Result<Option<Request>, EngineError> {
        if self.sent.is_some() {
            return Ok(None);
        }
        if let Some((sent, method, path, body)) = self.last.take().filter(|_| self.resend) {
            self.resend = false;
            return self.send(engine, sent, method, path, body).map(Some);
        }
        if let Some((slot, body)) = self.pending.take() {
            let path = self.path(engine, true);
            return self
                .send(engine, TSent::Write(slot), "POST", path, body)
                .map(Some);
        }
        if matches!(
            self.state,
            EnrollState::Compare { .. }
                | EnrollState::ConfirmAgain
                | EnrollState::Done
                | EnrollState::Failed { .. }
        ) {
            return Ok(None);
        }
        if let Some(sync) = self.sync.as_mut() {
            if let Some(r) = sync.next_request(engine)? {
                self.sent = Some(TSent::Sync);
                return Ok(Some(r));
            }
            self.sync = None;
            self.after_sync(engine)?;
            return self.next_request(engine);
        }
        let (sent, method, path, body) = match self.step {
            TStep::Open => (
                TSent::Open,
                "POST",
                self.path(engine, false),
                mailbox::open_body(&self.session),
            ),
            TStep::Hello | TStep::Nonce | TStep::Confirm => {
                (TSent::Read, "GET", self.path(engine, true), Vec::new())
            }
            TStep::Compare => return Ok(None),
            TStep::Grant => {
                self.sync = Some(engine.start_sync());
                self.syncs = self.syncs.saturating_add(1);
                return self.next_request(engine);
            }
            TStep::Done => {
                let body = done_body(engine)?;
                self.step = TStep::End;
                (
                    TSent::Write(mailbox::Slot::TrustedDone),
                    "POST",
                    self.path(engine, true),
                    body,
                )
            }
            TStep::End => {
                let Some(cause) = self.cancel_cause.take() else {
                    return Ok(None);
                };
                self.state = EnrollState::Failed { cause };
                (
                    TSent::Cancel,
                    "POST",
                    self.path(engine, true),
                    mailbox::cancel_body(),
                )
            }
        };
        self.send(engine, sent, method, path, body).map(Some)
    }

    fn send(
        &mut self,
        engine: &Engine,
        sent: TSent,
        method: &'static str,
        path: String,
        body: Vec<u8>,
    ) -> Result<Request, EngineError> {
        let req = signed(engine, method, &path, body.clone())?;
        self.last = Some((sent.clone(), method, path, body));
        self.sent = Some(sent);
        Ok(req)
    }
}

/// The checkpoint at the verified head and the tenant handle ([ENR-8]).
fn done_body(engine: &Engine) -> Result<Vec<u8>, EngineError> {
    let at = engine.base()?;
    let t = "snailfish.checkpoint.v1";
    let payload = write::checkpoint(&engine.log_id, &engine.device_id, &at);
    let sig = engine.sign.sign_record(t, &payload);
    let cp = envelope::write_json(t, &payload, &sig, &engine.device_id());
    Ok(mailbox::done_body(&engine.space.tenant, &cp))
}

impl TrustedEnrollment {
    /// After a sync of the grant step: go on if the verified log holds the
    /// grant, ask the user if the grant waits for a confirmation, and sync
    /// again otherwise ([LOG-7]).
    fn after_sync(&mut self, engine: &mut Engine) -> Result<(), EngineError> {
        let id = self.device()?.id;
        if state::is_active(&engine.db, &id)? {
            self.step = TStep::Done;
            return Ok(());
        }
        let row = state::grants(&engine.db)?
            .into_iter()
            .find(|g| g.device_id == id);
        match row {
            None => self.fail(format!(
                "the relay refused the grant: {}",
                engine
                    .grant_refusals
                    .remove(&id)
                    .unwrap_or_else(|| "the grant left the outbox".into())
            )),
            Some(g) if g.state == GRANT_CONFIRM => self.state = EnrollState::ConfirmAgain,
            Some(_) if self.syncs >= MAX_GRANT_SYNCS => {
                state::drop_grant(&engine.db, &id)?;
                self.fail("the grant did not reach the relay");
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnexpectedResponse`] if no request waits for a
    /// response, and [`EngineError::Storage`].
    pub fn handle_response(
        &mut self,
        engine: &mut Engine,
        status: u16,
        headers: &[Header],
        body: &[u8],
    ) -> Result<(), EngineError> {
        let sent = self.sent.take().ok_or(EngineError::UnexpectedResponse)?;
        if sent == TSent::Sync {
            let sync = self.sync.as_mut().ok_or(EngineError::UnexpectedResponse)?;
            return sync.handle_response(engine, status, headers, body);
        }
        crate::sync::read_time(engine, headers);
        if sent == TSent::Cancel {
            return Ok(());
        }
        if !(200..300).contains(&status) {
            let code = wire::parse_error(body).unwrap_or_else(|| format!("HTTP {status}"));
            if code == "expired" && !self.retried {
                // The clock offset is now fresh from this answer.
                self.retried = true;
                self.resend = true;
                return Ok(());
            }
            self.fail(match code.as_str() {
                "unknown_session" => "the session expired".to_owned(),
                other => format!("the relay refused the enrollment: {other}"),
            });
            return Ok(());
        }
        match sent {
            TSent::Open => {
                self.step = TStep::Hello;
                self.state = EnrollState::Waiting;
            }
            TSent::Write(mailbox::Slot::TrustedDone) => self.state = EnrollState::Done,
            TSent::Write(mailbox::Slot::TrustedNonce) => {
                if let Some(code) = self.code.take() {
                    self.state = EnrollState::Compare { code };
                }
            }
            TSent::Read => match mailbox::parse_session(body) {
                Ok(s) => self.on_session(engine, &s)?,
                Err(e) => self.fail(format!("the relay sent a session that is not valid: {e}")),
            },
            TSent::Write(_) | TSent::Cancel | TSent::Sync => {}
        }
        Ok(())
    }

    fn on_session(&mut self, engine: &mut Engine, s: &Session) -> Result<(), EngineError> {
        if s.state == State::Cancelled {
            self.fail("the new device cancelled the enrollment");
            return Ok(());
        }
        self.state = EnrollState::Waiting;
        match self.step {
            TStep::Hello => {
                let Some(d) = &s.new_hello else {
                    return Ok(());
                };
                if d.level < write_level(engine) {
                    self.cancel("update the new device: its protocol level is below the write level of the space");
                    return Ok(());
                }
                if state::is_active(&engine.db, &d.id)? {
                    self.cancel("the new device is already in the space");
                    return Ok(());
                }
                self.new_device = Some(d.clone());
                let c = enroll::commitment(&self.session, &engine.device_id, &d.id, &self.t_nonce);
                let keys = Keys {
                    sign: engine.sign.public(),
                    seal: Box::new(keys::seal_public(&engine.seal_seed)),
                };
                self.write(
                    mailbox::Slot::TrustedHello,
                    mailbox::trusted_hello_body(&keys, &c),
                );
                self.step = TStep::Nonce;
            }
            TStep::Nonce => {
                let Some(n) = s.new_nonce else {
                    return Ok(());
                };
                self.n_nonce = Some(n);
                let code = enroll::code(
                    &self.session,
                    &engine.device_id,
                    &self.device()?.id,
                    &self.t_nonce,
                    &n,
                );
                // Show the code only after the relay holds the nonce: the new
                // device needs it to compute its code while the user compares.
                self.write(
                    mailbox::Slot::TrustedNonce,
                    mailbox::nonce_body(&self.t_nonce),
                );
                self.step = TStep::Compare;
                self.code = Some(code);
                self.state = EnrollState::Busy;
            }
            TStep::Confirm => {
                let Some(cf) = &s.new_confirm else {
                    return Ok(());
                };
                let t = Transcript {
                    session: self.session,
                    t_id: engine.device_id,
                    new_device: self.device()?.clone(),
                    t_nonce: self.t_nonce,
                    n_nonce: self.n_nonce.ok_or(EngineError::UnexpectedResponse)?,
                };
                if let Err(e) = enroll::check_confirm(&cf.envelope, &t) {
                    self.cancel(&e.to_string());
                    return Ok(());
                }
                self.queue_grant(engine)?;
                self.step = TStep::Grant;
                self.state = EnrollState::Busy;
            }
            _ => {}
        }
        Ok(())
    }

    /// Write a message with the next request, before the next read.
    fn write(&mut self, slot: mailbox::Slot, body: Vec<u8>) {
        self.pending = Some((slot, body));
    }

    /// [ENR-8]: put the grant in the grant outbox with the device list that
    /// the user confirmed ([LOG-7]).
    fn queue_grant(&mut self, engine: &mut Engine) -> Result<(), EngineError> {
        let d = self.device()?.clone();
        let signer = self
            .recovery
            .as_ref()
            .map_or(Signer::Device, Signer::Recovery);
        let env = sign_grant(engine, &d, &signer)?;
        state::put_grant(
            &engine.db,
            &GrantRow {
                device_id: d.id,
                device: write::device(&d),
                confirmed: state::device_list(&engine.db)?,
                by_recovery: self.recovery.is_some(),
                envelope: Some(env),
                state: GRANT_SEND.into(),
            },
        )
    }
}

fn write_level(engine: &Engine) -> u64 {
    engine
        .db
        .query_row("SELECT level FROM space", [], |r| r.get::<_, i64>(0))
        .ok()
        .and_then(|l| u64::try_from(l).ok())
        .unwrap_or(MAX_LEVEL)
}

/// What the new device waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NStep {
    Hello,
    TrustedHello,
    TrustedNonce,
    Compare,
    Done,
    End,
}

/// The result of an enrollment on the new device: give it to
/// [`crate::setup::install_enrollment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    /// The tenant handle of `trusted.done`.
    pub tenant: String,
    /// The log ID text of the checkpoint.
    pub log_id: String,
    /// The checkpoint position.
    pub position: u64,
    /// The checkpoint digest.
    pub digest: [u8; 32],
    /// The device ID of the trusted device.
    pub trusted: String,
    /// The device object of `new.hello`, in the writer form.
    pub device: String,
}

/// The enrollment on the new device (`PROTOCOL.md` 11.2 steps 3, 5, 7, 9
/// and 11). It holds the device keys and needs no engine: the engine
/// state starts after the checkpoint check, with [`Joined`].
pub struct NewEnrollment {
    relay_url: String,
    sign: SecretKey,
    device: Device,
    session: [u8; 16],
    payload: Option<String>,
    step: NStep,
    state: EnrollState,
    sent: bool,
    pending: Option<Vec<u8>>,
    n_nonce: [u8; 32],
    trusted: Option<(Keys, Hash32)>,
    t_nonce: Option<[u8; 32]>,
    joined: Option<Joined>,
    cancel_cause: Option<String>,
    // The device read the session from the trusted device, which shows it
    // only after the open. So the session exists.
    scanned: bool,
    clock: fn() -> u64,
    // The device time at which the new device gives up: its own 10
    // minutes from its first request (`PROTOCOL.md` 10.3 `unknown_session`).
    deadline: Option<u64>,
}

impl std::fmt::Debug for NewEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewEnrollment")
            .field("step", &self.step)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl NewEnrollment {
    /// Start an enrollment on a new device with its keys and its name. If
    /// `scanned` is `None`, the device shows the session: call
    /// [`NewEnrollment::payload`]. Otherwise `scanned` is the payload or the
    /// typed code that the trusted device shows ([ENR-1]). A payload names
    /// its relay. A typed code uses `relay_url`.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a payload or a code that breaks
    /// `PROTOCOL.md` 11.1, a bad relay URL or a bad name, and
    /// [`EngineError::Random`].
    pub fn new(
        relay_url: &str,
        keys: &DeviceKeys,
        name: &str,
        scanned: Option<String>,
    ) -> Result<Self, EngineError> {
        if !(1..=128).contains(&name.len()) {
            return Err(EngineError::Invalid(
                "the device name must have 1 to 128 bytes".into(),
            ));
        }
        let mut relay_url = crate::relay_base(relay_url)?;
        let sign = SecretKey::from_seed(&keys.sign_seed);
        let seal = Box::new(keys::seal_public(&keys.seal_seed));
        let device = Device {
            id: keys::device_id(&sign.public(), &seal),
            keys: Keys {
                sign: sign.public(),
                seal,
            },
            name: name.to_owned(),
            level: MAX_LEVEL,
        };
        let scanned_any = scanned.is_some();
        let (session, payload) = if let Some(text) = scanned {
            let (session, relay) = read_payload_or_code(&text, Role::New)?;
            if let Some(r) = relay {
                relay_url = r;
            }
            (session, None)
        } else {
            let session = rand()?;
            let p = enroll::payload(&Payload {
                role: Role::New,
                relay_url: payload_url(&relay_url),
                session,
            });
            (session, Some(p))
        };
        Ok(Self {
            relay_url,
            sign,
            device,
            session,
            payload,
            step: NStep::Hello,
            state: EnrollState::Busy,
            sent: false,
            pending: None,
            n_nonce: rand()?,
            trusted: None,
            t_nonce: None,
            joined: None,
            cancel_cause: None,
            scanned: scanned_any,
            clock: crate::system_time,
            deadline: None,
        })
    }

    /// Replace the device clock, for tests of the deadline.
    #[doc(hidden)]
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// The QR payload to show, if this device shows the session.
    #[must_use]
    pub fn payload(&self) -> Option<String> {
        self.payload.clone()
    }

    /// The typed code of the session.
    #[must_use]
    pub fn code(&self) -> String {
        enroll::display(&self.session)
    }

    /// The relay URL of the session.
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.relay_url.clone()
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> EnrollState {
        self.state.clone()
    }

    /// The result, after [`EnrollState::Done`].
    #[must_use]
    pub fn joined(&self) -> Option<Joined> {
        self.joined.clone()
    }

    /// The answer of the user to [`EnrollState::Compare`]: true if the
    /// codes on both devices match ([ENR-7]). False cancels.
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] if no comparison waits.
    pub fn confirm(&mut self, yes: bool) -> Result<(), EngineError> {
        if !matches!(self.state, EnrollState::Compare { .. }) {
            return Err(EngineError::Invalid("no question waits".into()));
        }
        if yes {
            let (keys, _) = self
                .trusted
                .as_ref()
                .ok_or(EngineError::UnexpectedResponse)?;
            let t_id = keys::device_id(&keys.sign, &keys.seal);
            let t_nonce = self.t_nonce.ok_or(EngineError::UnexpectedResponse)?;
            let tp = "snailfish.confirm.v1";
            let payload =
                write::confirm(&self.session, &t_id, &self.device, &t_nonce, &self.n_nonce);
            let sig = self.sign.sign_record(tp, &payload);
            let env = envelope::write_json(tp, &payload, &sig, &encode_id("d_", &self.device.id));
            self.pending = Some(mailbox::confirm_body(&env));
            self.step = NStep::Done;
            self.state = EnrollState::Waiting;
        } else {
            self.cancel("the user reported that the codes differ");
        }
        Ok(())
    }

    fn cancel(&mut self, cause: &str) {
        self.cancel_cause = Some(cause.into());
        self.pending = Some(mailbox::cancel_body());
        self.step = NStep::End;
        self.state = EnrollState::Busy;
    }

    fn fail(&mut self, cause: impl Into<String>) {
        self.step = NStep::End;
        self.state = EnrollState::Failed {
            cause: cause.into(),
        };
    }

    /// The next request, or `None` if the enrollment waits for the user or
    /// ended. The routes of the new device have no signature: the session
    /// ID is the credential (`PROTOCOL.md` 10.10).
    #[must_use]
    pub fn next_request(&mut self) -> Option<Request> {
        if self.sent {
            return None;
        }
        let now = (self.clock)();
        let deadline = *self
            .deadline
            .get_or_insert(now.saturating_add(enroll::SESSION_SECONDS));
        if now >= deadline && !matches!(self.state, EnrollState::Done | EnrollState::Failed { .. })
        {
            self.fail("the session expired");
            return None;
        }
        let url = format!("{}/v1/e/{}", self.relay_url, encode_id("e_", &self.session));
        let body = match (self.pending.take(), self.step) {
            (Some(b), _) => b,
            (None, NStep::Hello) => mailbox::new_hello_body(&self.device),
            (None, NStep::End | NStep::Compare) => return None,
            (None, _) => {
                self.sent = true;
                return Some(Request {
                    method: "GET".into(),
                    url,
                    headers: json_headers(&[]),
                    body: Vec::new(),
                });
            }
        };
        if matches!(self.state, EnrollState::Done | EnrollState::Failed { .. }) {
            return None;
        }
        self.sent = true;
        Some(Request {
            method: "POST".into(),
            headers: json_headers(&body),
            url,
            body,
        })
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnexpectedResponse`] if no request waits for a
    /// response.
    pub fn handle_response(&mut self, status: u16, body: &[u8]) -> Result<(), EngineError> {
        if !std::mem::take(&mut self.sent) {
            return Err(EngineError::UnexpectedResponse);
        }
        if let Some(cause) = self.cancel_cause.take() {
            self.fail(cause);
            return Ok(());
        }
        if !(200..300).contains(&status) {
            let code = wire::parse_error(body).unwrap_or_else(|| format!("HTTP {status}"));
            if code == "unknown_session" && self.step == NStep::Hello && !self.scanned {
                // This device shows the session, and the trusted device has
                // not read it and opened it yet.
                self.state = EnrollState::Waiting;
            } else {
                self.fail(match code.as_str() {
                    "unknown_session" => "the session expired".to_owned(),
                    other => format!("the relay refused the enrollment: {other}"),
                });
            }
            return Ok(());
        }
        let s = match mailbox::parse_session(body) {
            Ok(s) => s,
            Err(e) => {
                self.fail(format!("the relay sent a session that is not valid: {e}"));
                return Ok(());
            }
        };
        if s.state == State::Cancelled {
            self.fail("the trusted device cancelled the enrollment");
            return Ok(());
        }
        self.state = EnrollState::Waiting;
        match self.step {
            NStep::Hello => self.step = NStep::TrustedHello,
            NStep::TrustedHello => {
                if let Some(t) = s.trusted_hello {
                    self.trusted = Some(t);
                    self.pending = Some(mailbox::nonce_body(&self.n_nonce));
                    self.step = NStep::TrustedNonce;
                }
            }
            NStep::TrustedNonce => {
                let (Some(tn), Some((keys, c))) = (s.trusted_nonce, &self.trusted) else {
                    return Ok(());
                };
                let t_id = keys::device_id(&keys.sign, &keys.seal);
                // [ENR-6]: the revealed nonce must match the commitment.
                if enroll::commitment(&self.session, &t_id, &self.device.id, &tn) != *c {
                    self.cancel("the commitment of the trusted device does not match");
                    return Ok(());
                }
                self.t_nonce = Some(tn);
                let code = enroll::code(&self.session, &t_id, &self.device.id, &tn, &self.n_nonce);
                self.step = NStep::Compare;
                self.state = EnrollState::Compare { code };
            }
            NStep::Done => {
                let Some((tenant, cp)) = s.trusted_done else {
                    return Ok(());
                };
                let (keys, _) = self
                    .trusted
                    .as_ref()
                    .ok_or(EngineError::UnexpectedResponse)?;
                let t_id = keys::device_id(&keys.sign, &keys.seal);
                match enroll::check_checkpoint(&cp.envelope, &t_id, &keys.sign) {
                    Ok((log, at)) => {
                        self.joined = Some(Joined {
                            tenant,
                            log_id: encode_id("l_", &log),
                            position: at.position,
                            digest: at.digest,
                            trusted: encode_id("d_", &t_id),
                            device: write::device(&self.device),
                        });
                        self.step = NStep::End;
                        self.state = EnrollState::Done;
                    }
                    Err(e) => self.fail(e.to_string()),
                }
            }
            NStep::Compare | NStep::End => {}
        }
        Ok(())
    }
}

/// The space of a [`Joined`] result on its relay, for [`Engine::open`].
#[must_use]
pub fn space_of(joined: &Joined, relay_url: &str, app_id: &str) -> SpaceRef {
    SpaceRef {
        relay_url: relay_url.to_owned(),
        tenant: joined.tenant.clone(),
        log_id: joined.log_id.clone(),
        app_id: app_id.to_owned(),
    }
}
