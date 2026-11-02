//! One exchange with the relay: info, create, fetch, repair, status report,
//! push, fetch (`PROTOCOL.md` section 10, `specs/delivery/model.qnt` actions
//! `push`, `fetchExtend`, `fetchConflict`, `startRepair`, `chunkRepair`,
//! `finishRepair` and `reportStatus`).
//!
//! The order is fixed. The first fetch gives the base of each new change,
//! and shows a relay log that ends before the verified head ([LOG-10]) and
//! the restore hold ([LOG-14]). The last fetch shows the own changes in the
//! verified log, so their envelopes leave the outbox only then ([DLV-8]).

use std::collections::VecDeque;

use rusqlite::{Transaction, TransactionBehavior};
use snailfish_protocol::encoding::encode_id;
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::setup;
use snailfish_protocol::space::{self, Mode, Verdict};
use snailfish_protocol::wire::{self, AppendResult, FetchEntry, Head, Limits};

use crate::state::{self, DbSpace, Own};
use crate::{Engine, EngineError, Header, MAX_LEVEL, Request, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Info,
    Create,
    FirstFetch,
    Repair,
    Report,
    Grants,
    Push,
    LastFetch,
    DeviceReport,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    Change([u8; 16]),
    /// A grant of the grant outbox, by the device ID it grants.
    Grant(snailfish_protocol::encoding::Hash32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    Info,
    Create,
    Fetch,
    Append(Vec<(Item, String)>),
    RepairStart(Vec<(u64, String)>),
    RepairChunk(Vec<(u64, String)>),
    RepairFinish,
    Status,
    // The body of the device status report.
    DeviceStatus(Vec<u8>),
}

/// A repair session in this exchange (`PROTOCOL.md` 10.9).
#[derive(Debug)]
struct RepairRun {
    /// The relay head, where the lost range starts.
    base: Head,
    /// The verified head: the tip of the finish.
    tip: Head,
    session: Option<[u8; 16]>,
    chunks: VecDeque<Vec<(u64, String)>>,
    /// A repair from the position before the own grant, after the relay
    /// answered a fetch with `unknown_device` ([LOG-12]).
    late: bool,
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
    // The last fetch showed a restore hold ([LOG-14]).
    hold: bool,
    repair: Option<RepairRun>,
}

/// The most fetch pages with no new entry in one exchange.
const MAX_EMPTY_PAGES: u32 = 3;
/// An unchanged device status report goes at most once in this many
/// seconds of corrected time (`PROTOCOL.md` 10.11).
pub(crate) const REPORT_EVERY: u64 = 3600;

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
            hold: false,
            repair: None,
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
                        // [USR-6]: space creation needs a setup token, so an
                        // engine without one asks for a sign-in.
                        if state::setup_token(&engine.db)?.is_none() {
                            engine.status = Status::SetupFailed {
                                cause: "no setup token".into(),
                            };
                            self.phase = Phase::Done;
                            continue;
                        }
                        Some(Sent::Create)
                    } else {
                        self.phase = Phase::FirstFetch;
                        continue;
                    }
                }
                Phase::FirstFetch | Phase::LastFetch => Some(Sent::Fetch),
                Phase::Repair => {
                    let next = self.repair.as_mut().and_then(|r| {
                        match (r.session, r.chunks.pop_front()) {
                            (None, Some(c)) => Some(Sent::RepairStart(c)),
                            (Some(_), Some(c)) => Some(Sent::RepairChunk(c)),
                            (Some(_), None) => Some(Sent::RepairFinish),
                            (None, None) => None,
                        }
                    });
                    if next.is_none() {
                        self.repair = None;
                        self.phase = self.after_first_fetch(engine)?;
                        continue;
                    }
                    next
                }
                Phase::Report => Some(Sent::Status),
                Phase::DeviceReport => {
                    let now = engine.now();
                    let (applied, outbox, oldest) = state::report_fields(&engine.db, now)?;
                    let body = setup::device_status_body(&setup::DeviceStatus {
                        state: engine.status.text().to_owned(),
                        outbox,
                        oldest,
                        applied,
                        epoch: 1,
                    });
                    // PROTOCOL.md 10.11: a report that equals the last
                    // accepted one goes at most once in REPORT_EVERY.
                    let unchanged = state::last_report(&engine.db)?
                        .is_some_and(|(b, t)| b == body && now < t.saturating_add(REPORT_EVERY));
                    if unchanged {
                        self.phase = Phase::Done;
                        continue;
                    }
                    Some(Sent::DeviceStatus(body))
                }
                Phase::Grants | Phase::Push => {
                    if !self.queued {
                        self.queue(engine)?;
                    }
                    if let Some(b) = self.batches.pop_front() {
                        Some(Sent::Append(b))
                    } else {
                        self.queued = false;
                        self.phase = if self.phase == Phase::Grants {
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
        let items: Vec<(Item, String)> = if self.phase == Phase::Grants {
            crate::enroll::grants_to_send(engine)?
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

    /// The route and body of a repair request (`PROTOCOL.md` 10.9).
    fn repair_body(&self, s: &Sent) -> Result<(&'static str, Vec<u8>), EngineError> {
        let r = self
            .repair
            .as_ref()
            .ok_or(EngineError::UnexpectedResponse)?;
        let wire_err = |e: wire::WireError| EngineError::Storage(e.to_string());
        match (s, r.session) {
            (Sent::RepairStart(chunk), _) => Ok((
                "repair",
                wire::repair_start_body(&r.base, chunk).map_err(wire_err)?,
            )),
            (Sent::RepairChunk(chunk), Some(sid)) => Ok((
                "repair/chunk",
                wire::repair_chunk_body(&sid, chunk).map_err(wire_err)?,
            )),
            (Sent::RepairFinish, Some(session)) => Ok((
                "repair/finish",
                wire::repair_finish_body(&wire::RepairFinish {
                    session,
                    tip: r.tip,
                }),
            )),
            _ => Err(EngineError::UnexpectedResponse),
        }
    }

    /// The method, path, query, body and signature flag of a request.
    fn target(&self, engine: &Engine, s: &Sent) -> Result<Target5, EngineError> {
        let sp = &engine.space;
        let space_path = format!("/v1/t/{}/s/{}", sp.tenant, sp.log_id);
        Ok(match s {
            Sent::Info => (
                "GET",
                "/v1/info".to_owned(),
                String::new(),
                Vec::new(),
                false,
            ),
            Sent::Create => {
                let g = state::setup_genesis(&engine.db)?.ok_or(EngineError::UnexpectedResponse)?;
                let token =
                    state::setup_token(&engine.db)?.ok_or(EngineError::UnexpectedResponse)?;
                (
                    "PUT",
                    space_path,
                    String::new(),
                    wire::genesis_body(&g, &token),
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
            Sent::RepairStart(_) | Sent::RepairChunk(_) | Sent::RepairFinish => {
                let (route, body) = self.repair_body(s)?;
                (
                    "POST",
                    format!("{space_path}/{route}"),
                    String::new(),
                    body,
                    true,
                )
            }
            Sent::Status => {
                let h = engine.verified_head()?;
                let body = wire::status_body(&wire::StatusReport {
                    tip: Head {
                        position: h.position,
                        digest: h.digest,
                    },
                    fresh: state::fresh(&engine.db)?,
                });
                (
                    "POST",
                    format!("{space_path}/status"),
                    String::new(),
                    body,
                    true,
                )
            }
            Sent::DeviceStatus(body) => (
                "POST",
                format!("{space_path}/device-status"),
                String::new(),
                body.clone(),
                true,
            ),
        })
    }

    fn send(&mut self, engine: &Engine, s: Sent) -> Result<Request, EngineError> {
        let sp = &engine.space;
        let (method, path, query, body, signed) = self.target(engine, &s)?;
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
        read_time(engine, headers);
        if !(200..300).contains(&status) {
            return self.error(engine, sent, body);
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
            Sent::RepairStart(chunk) => self.repair_answer(&chunk, body, true),
            Sent::RepairChunk(chunk) => self.repair_answer(&chunk, body, false),
            Sent::RepairFinish => self.repair_finished(engine, body),
            Sent::Status => self.status_answer(engine, body),
            Sent::DeviceStatus(report) => {
                self.phase = Phase::Done;
                state::set_last_report(&engine.db, &report, engine.now()).map_err(Answer::Engine)
            }
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
                // An active device reports the stop to the user page. A new
                // device in its enrollment is not active, so it sends nothing.
                self.phase = if enrolling(engine)? {
                    Phase::Done
                } else {
                    Phase::DeviceReport
                };
                Ok(())
            }
            Err(Answer::Engine(e)) => Err(e),
        }
    }

    fn error(&mut self, engine: &mut Engine, sent: Sent, body: &[u8]) -> Result<(), EngineError> {
        let code = wire::parse_error(body);
        // [LOG-12]: the relay does not know this device, so its grant can be
        // only in the range that the relay lost. Repair from the position
        // before the own grant: the relay head must be that position.
        if code.as_deref() == Some("unknown_device")
            && matches!(sent, Sent::Fetch)
            && self.phase == Phase::FirstFetch
            && let Some(run) = late_repair(engine, &self.limits)?
        {
            self.repair = Some(run);
            self.phase = Phase::Repair;
            return Ok(());
        }
        // A refused status report changes no status: the report is for the
        // user page only.
        if matches!(sent, Sent::DeviceStatus(_)) {
            self.phase = Phase::Done;
            return Ok(());
        }
        let late = self.repair.as_ref().is_some_and(|r| r.late);
        engine.status = match code.as_deref() {
            Some("wrong_authority") => Status::RelayAuthority,
            Some("expired") if !self.retried => {
                // The offset is now fresh from this answer. Send once more.
                self.retried = true;
                self.retry = Some(sent);
                return Ok(());
            }
            // PROTOCOL.md 10.9: with another relay head, no entry passes
            // the chain check, so the relay does not know the signer.
            Some("bad_repair" | "unknown_device") if late => Status::RepairNeedsAnotherDevice,
            Some("expired") => Status::ClockSkew,
            Some(code @ ("bad_setup" | "space_limit" | "bad_request"))
                if matches!(sent, Sent::Create) =>
            {
                Status::SetupFailed {
                    cause: code.to_owned(),
                }
            }
            Some("space_exists") => Status::Fork {
                cause: "the relay holds another genesis record for this log".into(),
            },
            // [LOG-10]: the relay refused a verified entry, so the two logs
            // disagree. `repair_busy` and `bad_repair` pass: the next sync
            // starts a new session.
            Some(code @ ("invalid_record" | "uncovered_stub"))
                if matches!(sent, Sent::RepairStart(_) | Sent::RepairChunk(_)) =>
            {
                Status::Fork {
                    cause: format!("the relay refused a repair entry: {code}"),
                }
            }
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
        // DESIGN.md "Monitoring and alerting" item 6: a refusal that leaves
        // this device active in the space still reaches the user page. The
        // other refusals would refuse the report too.
        self.phase = match (&engine.status, &sent) {
            (_, Sent::Create) => Phase::Done,
            (Status::Fork { .. } | Status::Degraded { .. }, _) if !enrolling(engine)? => {
                Phase::DeviceReport
            }
            _ => Phase::Done,
        };
        Ok(())
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
            if let Some(cause) = verify_entry(engine, &tx, *pos, entry)? {
                degraded = Some(cause);
            }
        }
        let (head, digest) = state::head(&tx, &log_id).map_err(Answer::Engine)?;
        let at_head = !f.has_more && f.head.position == head;
        let mut shorter = false;
        if !f.has_more {
            if f.head.position < head {
                // [LOG-10]: the relay log ends before the verified head.
                // If the relay head is an entry of the verified log, the
                // relay lost the entries after it: repair. Otherwise the
                // relay shows another log ([FRK-1]).
                let mine = state::verified_digest(&tx, &log_id, f.head.position)
                    .map_err(Answer::Engine)?;
                if f.head.position == 0 || mine != Some(f.head.digest) {
                    return Err(stop(format!(
                        "the relay log ends at {} with another digest than the verified log",
                        f.head.position
                    )));
                }
                shorter = true;
            }
            if f.head.position == head && f.head.digest != digest {
                return Err(stop(format!("the relay head digest at {head} differs")));
            }
        }
        let checked = check_checkpoint(engine, &tx)?;
        if at_head {
            state::set_caught_up(&tx, true).map_err(Answer::Engine)?;
            // PROTOCOL.md 10.8: the fresh flag ends at a fetch that reaches
            // the relay head with no hold. A fetch during a hold keeps it.
            if !f.hold {
                state::clear_fresh(&tx).map_err(Answer::Engine)?;
            }
        }
        if checked {
            // [ENR-9]: the log up to the checkpoint verified, so open the
            // key set of the grant, then decrypt the changes stored without
            // the key. Both happen before the commit that clears the
            // checkpoint: a failure or a crash leaves the check to repeat.
            let key = engine
                .open_app_key()
                .map_err(|e| stop(e.to_string()))?
                .ok_or_else(|| stop("the verified log holds no key set to this device".into()))?;
            engine.app_key = Some(key);
            if let Some(p) = state::fill_content(&tx, engine).map_err(Answer::Engine)? {
                degraded = Some(format!("a change at position {p} does not decrypt"));
            }
        }
        tx.commit().map_err(|e| Answer::Engine(e.into()))?;
        let enrolling = enrolling(engine).map_err(Answer::Engine)?;
        self.hold = f.hold;
        if let Some(cause) = degraded {
            engine.status = Status::Degraded { cause };
        }
        if f.hold {
            engine.status = Status::RestoreHold;
        }
        if shorter {
            if self.phase == Phase::FirstFetch && !enrolling {
                let lost = state::log_range(&engine.db, f.head.position.saturating_add(1), head)
                    .map_err(Answer::Engine)?;
                self.repair = Some(RepairRun {
                    base: f.head,
                    tip: Head {
                        position: head,
                        digest,
                    },
                    session: None,
                    chunks: repair_chunks(lost, &f.head, &self.limits),
                    late: false,
                });
                self.phase = Phase::Repair;
            } else {
                // The relay lost entries during this exchange. The next
                // sync repairs them.
                self.phase = Phase::Done;
            }
            return Ok(());
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
            Phase::FirstFetch => self.after_first_fetch(engine).map_err(Answer::Engine)?,
            // PROTOCOL.md 10.11: the status report is the last request.
            Phase::LastFetch => Phase::DeviceReport,
            _ => Phase::Done,
        };
        Ok(())
    }

    /// The answer to a status report (`PROTOCOL.md` 10.8).
    fn status_answer(&mut self, engine: &mut Engine, body: &[u8]) -> Result<(), Answer> {
        if wire::parse_status_response(body).map_err(|_| Answer::Unreadable)? {
            engine.status = Status::RestoreHold;
        }
        self.phase = Phase::Grants;
        Ok(())
    }

    /// The phase after the first fetch and the repair: a status report
    /// during a hold ([LOG-14]), then the append requests. A new device
    /// that has not checked its enrollment checkpoint uploads nothing
    /// ([ENR-9]).
    fn after_first_fetch(&self, engine: &Engine) -> Result<Phase, EngineError> {
        Ok(if enrolling(engine)? {
            Phase::Done
        } else if self.hold {
            Phase::Report
        } else {
            Phase::Grants
        })
    }

    /// The answer to a repair start or chunk: the relay staged the chunk.
    fn repair_answer(
        &mut self,
        chunk: &[(u64, String)],
        body: &[u8],
        start: bool,
    ) -> Result<(), Answer> {
        let r = self.repair.as_mut().ok_or(Answer::Unreadable)?;
        let next = if start {
            let (sid, next) = wire::parse_repair_started(body).map_err(|_| Answer::Unreadable)?;
            r.session = Some(sid);
            next
        } else {
            wire::parse_repair_next(body).map_err(|_| Answer::Unreadable)?
        };
        let want = chunk.last().map(|(p, _)| p.saturating_add(1));
        if Some(next) != want {
            return Err(Answer::Unreadable);
        }
        Ok(())
    }

    /// The answer to a repair finish ([LOG-10]): the relay head must now be
    /// the verified head.
    fn repair_finished(&mut self, engine: &mut Engine, body: &[u8]) -> Result<(), Answer> {
        let head = wire::parse_repair_finished(body).map_err(|_| Answer::Unreadable)?;
        let r = self.repair.take().ok_or(Answer::Unreadable)?;
        if head != r.tip {
            return Err(stop(format!(
                "after the repair the relay head is {}, not the verified head {}",
                head.position, r.tip.position
            )));
        }
        state::add_repair(
            &engine.db,
            r.base.position.saturating_add(1),
            r.tip.position,
        )
        .map_err(Answer::Engine)?;
        self.phase = self.after_first_fetch(engine).map_err(Answer::Engine)?;
        Ok(())
    }

    fn append(engine: &mut Engine, items: &[(Item, String)], body: &[u8]) -> Result<(), Answer> {
        let (results, _) = wire::parse_append_response(body).map_err(|_| Answer::Unreadable)?;
        if results.len() != items.len() {
            return Err(Answer::Unreadable);
        }
        for ((item, _), r) in items.iter().zip(results) {
            let cid = match item {
                Item::Change(cid) => cid,
                Item::Grant(id) => {
                    crate::enroll::grant_answer(engine, id, &r).map_err(Answer::Engine)?;
                    continue;
                }
            };
            match r {
                // [DLV-8]: the envelope stays until a fetch shows it.
                // [DLV-6]: a conflict also waits for the fetch, which
                // compares the change bytes at the reported position.
                AppendResult::Stored(_) | AppendResult::Known(_) | AppendResult::Conflict(_) => {}
                // [LOG-6]: transient. After a relay rollback the next sync
                // repairs the log, and the base is in the log again.
                // [LOG-7]: `stale_base` is for security records only.
                AppendResult::Refused(code) if code == "bad_base" || code == "stale_base" => {}
                // [LOG-14]: a change during a restore hold stays in the
                // outbox and goes again after the hold.
                AppendResult::Refused(code) if code == "on_hold" => {
                    engine.status = Status::RestoreHold;
                }
                // [QTA-4]: transient. The change stays in the outbox and
                // goes again at each later sync.
                AppendResult::Refused(code) if code == "quota" => {
                    engine.status = Status::Quota;
                }
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

/// The method, path, query, body and signature flag of a request.
type Target5 = (&'static str, String, String, Vec<u8>, bool);

/// Split lost entries into repair requests of at most
/// `max_append_envelopes` entries and `max_request_bytes` body bytes
/// (`PROTOCOL.md` 10.9). The first chunk goes in the start body, the others
/// in chunk bodies. An entry that does not fit goes alone: the relay
/// accepts the repair allowance for it.
pub(crate) fn repair_chunks(
    entries: Vec<(u64, String)>,
    base: &Head,
    limits: &Limits,
) -> VecDeque<Vec<(u64, String)>> {
    let max_count = usize::try_from(limits.max_append_envelopes.max(1)).unwrap_or(usize::MAX);
    let max_bytes = usize::try_from(limits.max_request_bytes).unwrap_or(usize::MAX);
    // The bodies with no entry. A session ID has a fixed length.
    let start_empty = wire::repair_start_body(base, &[]).map_or(0, |b| b.len());
    let chunk_empty = wire::repair_chunk_body(&[0; 16], &[]).map_or(0, |b| b.len());
    let mut out = VecDeque::new();
    let mut cur: Vec<(u64, String)> = Vec::new();
    let mut size = start_empty;
    for (pos, env) in entries {
        let len = entry_len(pos, &env);
        let add = len.saturating_add(usize::from(!cur.is_empty()));
        if !cur.is_empty() && (cur.len() >= max_count || size.saturating_add(add) > max_bytes) {
            out.push_back(std::mem::take(&mut cur));
            size = chunk_empty;
        }
        size = size.saturating_add(len.saturating_add(usize::from(!cur.is_empty())));
        cur.push((pos, env));
    }
    if !cur.is_empty() {
        out.push_back(cur);
    }
    out
}

/// The length of one entry in a repair body: `{"position":N,"envelope":E}`.
fn entry_len(pos: u64, env: &str) -> usize {
    format!("{{\"position\":{pos},\"envelope\":}}")
        .len()
        .saturating_add(env.len())
}

/// Split items into append requests of at most `max_append_envelopes`
/// envelopes and `max_request_bytes` body bytes (`PROTOCOL.md` 10.4).
/// Returns the batches and the changes that do not fit in any body alone.
/// A grant that does not fit goes alone, and the relay answer decides.
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

/// Verify and store one fetched entry inside the fetch transaction.
/// Returns a `degraded` cause, if any. [WIR-2]: the check verifies the
/// signature before `store_entry` changes any state.
fn verify_entry(
    engine: &Engine,
    tx: &Transaction<'_>,
    pos: u64,
    entry: &FetchEntry,
) -> Result<Option<String>, Answer> {
    let log_id = engine.log_id;
    let pos = &pos;
    let mut degraded = None;
    let view = DbSpace { tx, log_id };
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
        if state::setup_genesis_hash(tx)
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
        let c = state::decrypt_change(engine, &raw.envelope).map(|b| state::content_hash(&b));
        // A new device has no app key before its checkpoint check. It
        // decrypts these changes after the check (`state::fill_content`).
        if c.is_none() && engine.app_key.is_some() {
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
    let own = state::store_entry(tx, &raw.envelope, &raw.json, &accepted, content)
        .map_err(Answer::Engine)?;
    if matches!(own, Own::Conflict) {
        degraded = Some("refused: conflict".into());
    }
    state::drop_setup(tx, &accepted.record_hash).map_err(Answer::Engine)?;
    if let Some((id, _)) = accepted.new_device {
        // [LOG-7]: the verified log holds a grant for this device, so the
        // grant outbox needs no grant for it.
        state::drop_grant(tx, &id).map_err(Answer::Engine)?;
    }
    Ok(degraded)
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

/// The repair run of [LOG-12]: from the position before the own grant to
/// the verified head. `None` if the verified log holds no own grant after
/// position 1 (`PROTOCOL.md` 10.9).
fn late_repair(engine: &Engine, limits: &Limits) -> Result<Option<RepairRun>, EngineError> {
    // [ENR-9]: a new device uploads nothing before its checkpoint check.
    if enrolling(engine)? {
        return Ok(None);
    }
    let Some((g, _)) = state::activation(&engine.db, &engine.device_id)? else {
        return Ok(None);
    };
    let (head, digest) = state::head(&engine.db, &engine.log_id)?;
    let Some(base_pos) = g.checked_sub(1).filter(|p| *p >= 1) else {
        return Ok(None);
    };
    let Some(base_digest) = state::verified_digest(&engine.db, &engine.log_id, base_pos)? else {
        return Ok(None);
    };
    let base = Head {
        position: base_pos,
        digest: base_digest,
    };
    let lost = state::log_range(&engine.db, g, head)?;
    Ok(Some(RepairRun {
        base,
        tip: Head {
            position: head,
            digest,
        },
        session: None,
        chunks: repair_chunks(lost, &base, limits),
        late: true,
    }))
}

/// [ENR-9]: check the enrollment checkpoint once the verified log reaches
/// it, inside the fetch transaction. True if the check passed now.
fn check_checkpoint(engine: &Engine, tx: &Transaction<'_>) -> Result<bool, Answer> {
    let Some(cp) = state::checkpoint(tx).map_err(Answer::Engine)? else {
        return Ok(false);
    };
    let (head, _) = state::head(tx, &engine.log_id).map_err(Answer::Engine)?;
    if head < cp.position {
        return Ok(false);
    }
    if state::verified_digest(tx, &engine.log_id, cp.position).map_err(Answer::Engine)?
        != Some(cp.digest)
    {
        return Err(stop(format!(
            "the log differs from the enrollment checkpoint at position {}",
            cp.position
        )));
    }
    let want = snailfish_protocol::records::parse_device_json(cp.device.as_bytes())
        .map_err(|e| Answer::Engine(EngineError::Storage(e.to_string())))?;
    let own = state::activation(tx, &engine.device_id).map_err(Answer::Engine)?;
    let own_ok = own.is_some_and(|(p, json)| {
        p <= cp.position && crate::enroll::grant_device(&json).is_some_and(|d| d == want)
    });
    if !own_ok {
        return Err(stop(
            "the log up to the enrollment checkpoint holds no grant for this device".into(),
        ));
    }
    let trusted = state::activation(tx, &cp.trusted).map_err(Answer::Engine)?;
    if trusted.is_none_or(|(p, _)| p > cp.position) {
        return Err(stop(
            "the trusted device is not active at the enrollment checkpoint".into(),
        ));
    }
    state::clear_checkpoint(tx).map_err(Answer::Engine)?;
    Ok(true)
}

/// Keep the clock offset of a response with a valid `snailfish-time`
/// ([WIR-7]).
pub(crate) fn read_time(engine: &mut Engine, headers: &[Header]) {
    if let Some(t) = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(request::TIME_HEADER))
        .and_then(|h| request::parse_time(&h.value))
    {
        let local = (engine.clock)();
        engine.clock_offset =
            i64::try_from(i128::from(t).saturating_sub(i128::from(local))).unwrap_or(0);
    }
}

/// True if the engine holds an enrollment checkpoint that it has not
/// checked yet ([ENR-9]).
fn enrolling(engine: &Engine) -> Result<bool, EngineError> {
    Ok(state::checkpoint(&engine.db)?.is_some())
}
