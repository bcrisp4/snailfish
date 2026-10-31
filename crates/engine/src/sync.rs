//! One exchange with the relay: info, create, fetch, push, fetch
//! (`PROTOCOL.md` section 10, `specs/delivery/model.qnt` actions `push`,
//! `fetchExtend` and `fetchConflict`).
//!
//! The order is fixed. The first fetch gives the base of each new change.
//! The last fetch shows the own changes in the verified log, so their
//! envelopes leave the outbox only then ([DLV-8]).

use std::collections::VecDeque;

use rusqlite::{Transaction, TransactionBehavior};
use snailfish_protocol::encoding::encode_id;
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::space::{self, Mode, Verdict};
use snailfish_protocol::wire::{self, AppendResult, FetchEntry, Limits};

use crate::state::{self, DbSpace, Own};
use crate::{Engine, EngineError, Header, MAX_LEVEL, Request, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Info,
    Create,
    FirstFetch,
    Setup,
    Push,
    LastFetch,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    Change([u8; 16]),
    Setup(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    Info,
    Create,
    Fetch,
    Append(Vec<(Item, String)>),
}

/// One exchange with the relay. The app calls [`Sync::next_request`], sends
/// the request, and passes the response to [`Sync::handle_response`].
#[derive(Debug)]
pub struct Sync {
    phase: Phase,
    sent: Option<Sent>,
    // The request to send again after an `expired` answer, signed again.
    retry: Option<Sent>,
    retried: bool,
    limits: Limits,
    batches: Batches,
    queued: bool,
    // Fetch pages in this exchange that added no entry. A relay that sends
    // `has_more` or a later head with no entries must not keep the app in
    // a loop.
    empty_pages: u32,
}

/// The most fetch pages with no new entry in one exchange.
const MAX_EMPTY_PAGES: u32 = 3;

/// A fault of the relay that stops sync (`stopped: fork`).
struct Stop(String);

impl Sync {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Info,
            sent: None,
            retry: None,
            retried: false,
            limits: Limits::default(),
            batches: VecDeque::new(),
            queued: false,
            empty_pages: 0,
        }
    }

    /// The next request, or `None` at the end of the exchange.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] and [`EngineError::Random`].
    pub fn next_request(&mut self, engine: &mut Engine) -> Result<Option<Request>, EngineError> {
        if self.sent.is_some() {
            return Ok(None);
        }
        if let Some(s) = self.retry.take() {
            return self.send(engine, s).map(Some);
        }
        loop {
            let next = match self.phase {
                Phase::Info => Some(Sent::Info),
                Phase::Create => {
                    if engine.verified_head()?.position == 0
                        && state::setup_genesis(&engine.db)?.is_some()
                    {
                        Some(Sent::Create)
                    } else {
                        self.phase = Phase::FirstFetch;
                        continue;
                    }
                }
                Phase::FirstFetch | Phase::LastFetch => Some(Sent::Fetch),
                Phase::Setup | Phase::Push => {
                    if !self.queued {
                        self.queue(engine)?;
                    }
                    if let Some(b) = self.batches.pop_front() {
                        Some(Sent::Append(b))
                    } else {
                        self.queued = false;
                        self.phase = if self.phase == Phase::Setup {
                            Phase::Push
                        } else {
                            Phase::LastFetch
                        };
                        continue;
                    }
                }
                Phase::Done => None,
            };
            return match next {
                Some(s) => self.send(engine, s).map(Some),
                None => Ok(None),
            };
        }
    }

    fn queue(&mut self, engine: &mut Engine) -> Result<(), EngineError> {
        let items: Vec<(Item, String)> = if self.phase == Phase::Setup {
            state::setup_appends(&engine.db)?
                .into_iter()
                .map(|(seq, env)| (Item::Setup(seq), env))
                .collect()
        } else {
            state::pending(engine, usize::MAX)?
                .into_iter()
                .map(|p| (Item::Change(p.change_id), p.envelope))
                .collect()
        };
        let (batches, too_large) = batch(items, &self.limits);
        // A change that no request body can hold is refused for ever
        // ([DLV-9]). A retry would get the same 413 at every sync.
        for cid in too_large {
            state::refuse(&engine.db, &cid, "too_large")?;
            engine.status = Status::Degraded {
                cause: "refused: too_large".into(),
            };
        }
        self.batches = batches;
        self.queued = true;
        Ok(())
    }

    fn send(&mut self, engine: &Engine, s: Sent) -> Result<Request, EngineError> {
        let sp = &engine.space;
        let space_path = format!("/v1/t/{}/s/{}", sp.tenant, sp.log_id);
        let (method, path, query, body, signed) = match &s {
            Sent::Info => (
                "GET",
                "/v1/info".to_owned(),
                String::new(),
                Vec::new(),
                false,
            ),
            Sent::Create => {
                let g = state::setup_genesis(&engine.db)?.ok_or(EngineError::UnexpectedResponse)?;
                (
                    "PUT",
                    space_path,
                    String::new(),
                    wire::genesis_body(&g),
                    true,
                )
            }
            Sent::Fetch => {
                let head = engine.verified_head()?.position;
                let q = format!(
                    "after={head}&limit={}",
                    self.limits.max_fetch_entries.max(1)
                );
                ("GET", format!("{space_path}/entries"), q, Vec::new(), true)
            }
            Sent::Append(items) => {
                let envs: Vec<String> = items.iter().map(|(_, e)| e.clone()).collect();
                (
                    "POST",
                    format!("{space_path}/append"),
                    String::new(),
                    wire::append_body(&envs),
                    true,
                )
            }
        };
        let authority = authority(&sp.relay_url);
        let mut headers = vec![Header {
            name: "accept".into(),
            value: "application/json".into(),
        }];
        if !body.is_empty() {
            headers.push(Header {
                name: "content-type".into(),
                value: "application/json".into(),
            });
        }
        if signed {
            let now = engine.now();
            let p = Params {
                created: now,
                expires: now.saturating_add(request::MAX_LIFETIME),
                nonce: snailfish_protocol::keys::random_bytes().map_err(|_| EngineError::Random)?,
                keyid: engine.device_id,
            };
            let t = Target {
                method,
                authority: &authority,
                path: &path,
                query: &query,
            };
            for (name, value) in request::sign(&engine.sign, &t, &body, &p).pairs() {
                headers.push(Header {
                    name: name.into(),
                    value: value.into(),
                });
            }
        }
        let url = if query.is_empty() {
            format!("{}{path}", sp.relay_url)
        } else {
            format!("{}{path}?{query}", sp.relay_url)
        };
        self.sent = Some(s);
        Ok(Request {
            method: method.into(),
            url,
            headers,
            body,
        })
    }

    /// Read the response to the last request.
    ///
    /// The engine parses unsigned response JSON loosely and ignores unknown
    /// fields ([VER-13]). It reads the relay time from `snailfish-time`
    /// ([WIR-7]).
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
        if let Some(t) = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(request::TIME_HEADER))
            .and_then(|h| request::parse_time(&h.value))
        {
            let local = (engine.clock)();
            engine.clock_offset =
                i64::try_from(i128::from(t).saturating_sub(i128::from(local))).unwrap_or(0);
        }
        if !(200..300).contains(&status) {
            self.error(engine, sent, body);
            return Ok(());
        }
        let result = match sent {
            Sent::Info => self.info(engine, body),
            Sent::Create => {
                // 201 or 200 (an exact retry, PROTOCOL.md 10.5).
                self.phase = Phase::FirstFetch;
                Ok(())
            }
            Sent::Fetch => self.fetch(engine, body),
            Sent::Append(items) => Self::append(engine, &items, body),
        };
        match result {
            Ok(()) => Ok(()),
            Err(Answer::Unreadable) => {
                engine.status = Status::RelayUnavailable;
                self.phase = Phase::Done;
                Ok(())
            }
            Err(Answer::Stop(Stop(cause))) => {
                engine.status = Status::Fork { cause };
                self.phase = Phase::Done;
                Ok(())
            }
            Err(Answer::Engine(e)) => Err(e),
        }
    }

    fn error(&mut self, engine: &mut Engine, sent: Sent, body: &[u8]) {
        let code = wire::parse_error(body);
        engine.status = match code.as_deref() {
            Some("wrong_authority") => Status::RelayAuthority,
            Some("expired") if !self.retried => {
                // The offset is now fresh from this answer. Send once more.
                self.retried = true;
                self.retry = Some(sent);
                return;
            }
            Some("expired") => Status::ClockSkew,
            Some("space_exists") => Status::Fork {
                cause: "the relay holds another genesis record for this log".into(),
            },
            Some("invalid_record") => Status::Fork {
                cause: "the relay refused the genesis record".into(),
            },
            // The batch fits the limits of the last info, so the relay
            // lowered them. The next sync reads them again.
            Some("too_large") => Status::Degraded {
                cause: "refused: too_large".into(),
            },
            _ => Status::RelayUnavailable,
        };
        self.phase = Phase::Done;
    }

    fn info(&mut self, engine: &mut Engine, body: &[u8]) -> Result<(), Answer> {
        // Only a readable answer with a `levels` list can show that the
        // relay is too old. Every other answer is a fault that can pass.
        // [VER-11]: read `levels` before the limits, so a relay of another
        // version with a readable `levels` list but other limits can still
        // give `relay too old`.
        let levels = wire::parse_levels(body).map_err(|_| Answer::Unreadable)?;
        if !levels.contains(&MAX_LEVEL) {
            engine.status = Status::RelayTooOld;
            self.phase = Phase::Done;
            return Ok(());
        }
        let info = wire::parse_info(body).map_err(|_| Answer::Unreadable)?;
        engine
            .db
            .execute(
                "INSERT INTO relay_info (id, body) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET body = excluded.body",
                [body],
            )
            .map_err(|e| Answer::Engine(e.into()))?;
        self.limits = info.limits;
        engine.status = match state::refused_cause(&engine.db).map_err(Answer::Engine)? {
            Some(cause) => Status::Degraded {
                cause: format!("refused: {cause}"),
            },
            None => Status::Ok,
        };
        self.phase = Phase::Create;
        Ok(())
    }

    /// Verify and store one fetch page in one transaction.
    fn fetch(&mut self, engine: &mut Engine, body: &[u8]) -> Result<(), Answer> {
        let f = wire::parse_fetch(body).map_err(|_| Answer::Unreadable)?;
        let log_id = engine.log_id;
        let tx = Transaction::new_unchecked(&engine.db, TransactionBehavior::Immediate)
            .map_err(|e| Answer::Engine(e.into()))?;
        let mut degraded = None;
        for (pos, entry) in &f.entries {
            let view = DbSpace { tx: &tx, log_id };
            let head = snailfish_protocol::space::SpaceView::head(&view);
            if Some(*pos) != head.checked_add(1) {
                return Err(stop(format!("the relay sent position {pos} after {head}")));
            }
            let FetchEntry::Envelope(raw) = entry else {
                // [CMP-15]: M2 has no snapshot, so no stub is valid.
                return Err(stop(format!("a stub at position {pos} with no snapshot")));
            };
            let accepted = if *pos == 1 {
                let a = space::check_genesis(&raw.envelope, &log_id, None)
                    .map_err(|r| stop(format!("genesis record: {r}")))?;
                if let snailfish_protocol::records::Body::Genesis { app, .. } = &a.record.body
                    && app != &engine.space.app_id
                {
                    return Err(stop("the genesis record names another app".into()));
                }
                // The device that made the space holds its genesis record
                // from the setup (`specs/spacelog/model.qnt` `createSpace`).
                // The relay must not replace it.
                if state::setup_genesis_hash(&tx)
                    .map_err(Answer::Engine)?
                    .is_some_and(|h| h != a.record_hash)
                {
                    return Err(stop(
                        "the relay holds another genesis record for this log".into(),
                    ));
                }
                a
            } else {
                match space::check_append(&view, &raw.envelope, Mode::Verify) {
                    Verdict::Store(a) => *a,
                    Verdict::Refused(r) => return Err(stop(format!("position {pos}: {r}"))),
                    Verdict::Known(_) | Verdict::Conflict(_) => {
                        return Err(stop(format!("position {pos}: a duplicate change")));
                    }
                }
            };
            let content = if accepted.record.change_id().is_some() {
                let c =
                    state::decrypt_change(engine, &raw.envelope).map(|b| state::content_hash(&b));
                if c.is_none() {
                    // [DLV-13]: skip it, keep its position, report the author.
                    degraded = Some(format!(
                        "a change at position {pos} by {} does not decrypt",
                        encode_id("d_", accepted.record.author.id())
                    ));
                }
                c
            } else {
                None
            };
            let own = state::store_entry(&tx, &raw.envelope, &raw.json, &accepted, content)
                .map_err(Answer::Engine)?;
            if matches!(own, Own::Conflict) {
                degraded = Some("refused: conflict".into());
            }
            state::drop_setup(&tx, &accepted.record_hash).map_err(Answer::Engine)?;
        }
        let (head, digest) = state::head(&tx, &log_id).map_err(Answer::Engine)?;
        let at_head = !f.has_more && f.head.position == head;
        if !f.has_more {
            if f.head.position < head {
                return Err(stop(format!(
                    "the relay log ends at {} before the verified position {head}",
                    f.head.position
                )));
            }
            if f.head.position == head && f.head.digest != digest {
                return Err(stop(format!("the relay head digest at {head} differs")));
            }
        }
        if at_head {
            state::set_caught_up(&tx, true).map_err(Answer::Engine)?;
        }
        tx.commit().map_err(|e| Answer::Engine(e.into()))?;
        if let Some(cause) = degraded {
            engine.status = Status::Degraded { cause };
        }
        if !at_head {
            // More entries, or the relay head moved past the page: fetch
            // again, unless the relay sends pages with no entries.
            if f.entries.is_empty() {
                self.empty_pages = self.empty_pages.saturating_add(1);
                if self.empty_pages >= MAX_EMPTY_PAGES {
                    engine.status = Status::RelayUnavailable;
                    self.phase = Phase::Done;
                }
            }
            return Ok(());
        }
        self.phase = match self.phase {
            Phase::FirstFetch => Phase::Setup,
            _ => Phase::Done,
        };
        Ok(())
    }

    fn append(engine: &mut Engine, items: &[(Item, String)], body: &[u8]) -> Result<(), Answer> {
        let (results, _) = wire::parse_append_response(body).map_err(|_| Answer::Unreadable)?;
        if results.len() != items.len() {
            return Err(Answer::Unreadable);
        }
        for ((item, _), r) in items.iter().zip(results) {
            let Item::Change(cid) = item else {
                // A setup record leaves its table when the verified log
                // holds it. A refusal is a fault of the setup.
                if let AppendResult::Refused(code) = r
                    && code != "bad_base"
                {
                    return Err(stop(format!("the relay refused a setup record: {code}")));
                }
                continue;
            };
            match r {
                // [DLV-8]: the envelope stays until a fetch shows it.
                // [DLV-6]: a conflict also waits for the fetch, which
                // compares the change bytes at the reported position.
                AppendResult::Stored(_) | AppendResult::Known(_) | AppendResult::Conflict(_) => {}
                // [LOG-6]: transient. A later sync signs nothing again in
                // M2; M3 adds the repair of a relay rollback.
                AppendResult::Refused(code) if code == "bad_base" => {}
                // [DLV-9]: a permanent refusal.
                AppendResult::Refused(code) => {
                    state::refuse(&engine.db, cid, &code).map_err(Answer::Engine)?;
                    engine.status = Status::Degraded {
                        cause: format!("refused: {code}"),
                    };
                }
            }
        }
        Ok(())
    }
}

pub(crate) type Batches = VecDeque<Vec<(Item, String)>>;

/// Split items into append requests of at most `max_append_envelopes`
/// envelopes and `max_request_bytes` body bytes (`PROTOCOL.md` 10.4).
/// Returns the batches and the changes that do not fit in any body alone.
/// A setup record that does not fit goes alone, and the relay answer
/// decides.
pub(crate) fn batch(items: Vec<(Item, String)>, limits: &Limits) -> (Batches, Vec<[u8; 16]>) {
    let max_count = usize::try_from(limits.max_append_envelopes.max(1)).unwrap_or(usize::MAX);
    let max_bytes = usize::try_from(limits.max_request_bytes).unwrap_or(usize::MAX);
    // `{"envelopes":[` and `]}`, then one comma between two envelopes.
    let empty = wire::append_body(&[]).len();
    let mut out = VecDeque::new();
    let mut too_large = Vec::new();
    let mut cur: Vec<(Item, String)> = Vec::new();
    let mut size = empty;
    for (item, env) in items {
        if empty.saturating_add(env.len()) > max_bytes
            && let Item::Change(cid) = item
        {
            too_large.push(cid);
            continue;
        }
        let add = env.len().saturating_add(usize::from(!cur.is_empty()));
        if !cur.is_empty() && (cur.len() >= max_count || size.saturating_add(add) > max_bytes) {
            out.push_back(std::mem::take(&mut cur));
            size = empty;
        }
        size = size.saturating_add(env.len().saturating_add(usize::from(!cur.is_empty())));
        cur.push((item, env));
    }
    if !cur.is_empty() {
        out.push_back(cur);
    }
    (out, too_large)
}

enum Answer {
    Unreadable,
    Stop(Stop),
    Engine(EngineError),
}

fn stop(cause: String) -> Answer {
    Answer::Stop(Stop(cause))
}

/// The authority of a relay URL that `relay_base` accepted
/// (`PROTOCOL.md` 8.3): the host in lowercase, and the port if it is not the
/// default port of the scheme.
pub(crate) fn authority(url: &str) -> String {
    let (scheme, auth) = url.split_once("://").unwrap_or(("https", url));
    let auth = auth.to_ascii_lowercase();
    let default = if scheme.eq_ignore_ascii_case("http") {
        ":80"
    } else {
        ":443"
    };
    auth.strip_suffix(default)
        .map_or(auth.clone(), str::to_owned)
}
