//! Space export, deletion, import and the fork repair comparison
//! (`PROTOCOL.md` 10.12, 10.13 and section 15, DESIGN.md "Fork repair",
//! `specs/forkrepair/model.qnt` actions `exportLog`, `delete`, `importLog`
//! and `recover`).

use std::collections::VecDeque;

use snailfish_protocol::delete::{DELETE_TYPE, MAX_WINDOW};
use snailfish_protocol::encoding::{Hash32, decode_id, encode_id};
use snailfish_protocol::envelope::{self, Envelope};
use snailfish_protocol::export::{self, Header as ExportHeader};
use snailfish_protocol::keys;
use snailfish_protocol::records::{Author, Body, Keys, parse_payload};
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::setup;
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::wire::{self, Head, Limits, OutEntry, RepairFinish, RepairItem};
use snailfish_protocol::write;

use crate::removal::RecoverySigner;
use crate::state;
use crate::sync::authority;
use crate::{DeviceKeys, Engine, EngineError, Header, OutboxRow, Request, SpaceRef, Status};

fn json_headers(body: &[u8]) -> Vec<Header> {
    let mut h = vec![Header {
        name: "accept".into(),
        value: "application/json".into(),
    }];
    if !body.is_empty() {
        h.push(Header {
            name: "content-type".into(),
            value: "application/json".into(),
        });
    }
    h
}

fn time_of(headers: &[Header]) -> Option<u64> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(request::TIME_HEADER))
        .and_then(|h| request::parse_time(&h.value))
}

/// A request signed by `key` with `keyid` at the time `now`.
#[allow(clippy::too_many_arguments)] // One signed request takes each part.
fn signed(
    relay_url: &str,
    path: &str,
    body: Vec<u8>,
    key: &SecretKey,
    keyid: Hash32,
    recovery: bool,
    now: u64,
) -> Result<Request, EngineError> {
    let p = Params {
        created: now,
        expires: now.saturating_add(request::MAX_LIFETIME),
        nonce: keys::random_bytes().map_err(|_| EngineError::Random)?,
        keyid,
        recovery,
    };
    let auth = authority(relay_url);
    let t = Target {
        method: "POST",
        authority: &auth,
        path,
        query: "",
    };
    let mut headers = json_headers(&body);
    for (name, value) in request::sign(key, &t, &body, &p).pairs() {
        headers.push(Header {
            name: name.into(),
            value: value.into(),
        });
    }
    Ok(Request {
        method: "POST".into(),
        url: format!("{relay_url}{path}"),
        headers,
        body,
    })
}

fn refused(body: &[u8], status: u16) -> EngineError {
    EngineError::Refused {
        code: wire::parse_error(body).unwrap_or_else(|| format!("http {status}")),
    }
}

impl Engine {
    /// The export file of the verified log (`PROTOCOL.md` section 15,
    /// [FRK-3]). It holds only envelopes and stubs, so the app can store it
    /// anywhere.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`].
    pub fn export_log(&self) -> Result<Vec<u8>, EngineError> {
        let (position, digest) = state::head(&self.db, &self.log_id)?;
        let entries = state::log_range(&self.db, 1, position)?;
        let header = ExportHeader {
            log_id: self.log_id,
            app: self.space.app_id.clone(),
            head: Head { position, digest },
        };
        export::write(&header, &entries).map_err(|e| EngineError::Storage(e.0))
    }

    /// The deletion request of the space (`PROTOCOL.md` 10.12, [LOG-13],
    /// [FRK-4]). The statement names the verified head, so the app syncs
    /// first. After a fork, the relay operator can delete the space instead.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] and [`EngineError::Random`].
    pub fn delete_request(&self) -> Result<Request, EngineError> {
        let now = self.now();
        let author = Author::Device(self.device_id);
        let p = write::delete(
            &self.log_id,
            &author,
            &self.base()?,
            now.saturating_add(MAX_WINDOW / 2),
        );
        let sig = self.sign.sign_record(DELETE_TYPE, &p);
        let stmt = envelope::write_json(DELETE_TYPE, &p, &sig, &encode_id("d_", &self.device_id));
        let path = format!("/v1/t/{}/s/{}/delete", self.space.tenant, self.space.log_id);
        signed(
            &self.space.relay_url,
            &path,
            wire::delete_body(&stmt, None),
            &self.sign,
            self.device_id,
            false,
            now,
        )
    }

    /// Read the answer to [`Engine::delete_request`]. After `200` the status
    /// is `stopped: deleted`.
    ///
    /// # Errors
    ///
    /// [`EngineError::Refused`] with the error code of the relay, for
    /// example `bad_head` after another append: sync and send again.
    pub fn handle_delete_response(
        &mut self,
        status: u16,
        headers: &[Header],
        body: &[u8],
    ) -> Result<(), EngineError> {
        crate::sync::read_time(self, headers);
        if status == 200 || wire::parse_error(body).as_deref() == Some("deleted") {
            self.status = Status::Deleted;
            return Ok(());
        }
        Err(refused(body, status))
    }

    /// An import of the verified log into a space on `target`, the same
    /// relay after a deletion or another relay ([FRK-5]). `setup_token` is
    /// a setup token of this device on the target relay (12.3).
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] for a target of another log or a bad token,
    /// and [`EngineError::Storage`].
    pub fn import_space(&self, target: SpaceRef, setup_token: &str) -> Result<Import, EngineError> {
        if target.log_id != self.space.log_id || target.app_id != self.space.app_id {
            return Err(EngineError::Invalid("the target names another log".into()));
        }
        let (position, digest) = state::head(&self.db, &self.log_id)?;
        let entries = state::log_range(&self.db, 1, position)?;
        let device = Keys {
            sign: self.sign.public(),
            seal: Box::new(keys::seal_public(&self.seal_seed)),
        };
        Import::new(
            target,
            setup_token,
            self.sign.clone(),
            device,
            None,
            entries,
            Head { position, digest },
        )
    }

    /// FRK-7: each own change of the old engine `old` that the old verified
    /// log holds in full and the verified log of this engine does not hold,
    /// in full or as a stub, with its `change_id` and decrypted bytes. The
    /// app writes an outbox row for each one, calls
    /// [`Engine::enqueue_many`], and handles `ResetRequired` ([FRK-8]). The
    /// app keeps the old state file until its outbox holds each change.
    ///
    /// The old engine outbox needs no comparison: the app outbox row of
    /// each change stays until `changes_after` returns it ([DLV-11]).
    ///
    /// # Errors
    ///
    /// [`EngineError::Invalid`] if `old` is of another log, and
    /// [`EngineError::Storage`].
    pub fn fork_changes(&self, old: &Engine) -> Result<Vec<OutboxRow>, EngineError> {
        if old.log_id != self.log_id {
            return Err(EngineError::Invalid(
                "the old engine is of another log".into(),
            ));
        }
        // Before the checkpoint check ([ENR-9]) the engine has no app key
        // and its verified log is not the relay log, so the comparison
        // would give changes that the new log holds.
        if self.app_key.is_none() || state::checkpoint(&self.db)?.is_some() {
            return Err(EngineError::Invalid(
                "sync the new engine once before the comparison".into(),
            ));
        }
        let mut st = old.db.prepare(
            "SELECT change_id, envelope FROM log
             WHERE payload_type = 'snailfish.change.v1' AND envelope != '' ORDER BY position",
        )?;
        let mut q = st.query([])?;
        let mut out = Vec::new();
        while let Some(r) = q.next()? {
            let cid: Vec<u8> = r.get(0)?;
            let json: String = r.get(1)?;
            let held: bool = self
                .db
                .query_row("SELECT 1 FROM log WHERE change_id = ?1", [&cid], |_| Ok(()))
                .map(|()| true)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(false),
                    e => Err(e),
                })?;
            if held {
                continue;
            }
            let env = Envelope::parse(json.as_bytes())
                .map_err(|e| EngineError::Storage(format!("stored record: {e}")))?;
            let rec = parse_payload(&env.payload_type, &env.payload)
                .map_err(|e| EngineError::Storage(format!("stored record: {e}")))?;
            if rec.author != Author::Device(old.device_id)
                || !matches!(rec.body, Body::Change { .. })
            {
                continue;
            }
            // [DLV-13]: a change that does not decrypt has no bytes to send.
            if let Some(bytes) = state::decrypt_change(old, &env) {
                out.push(OutboxRow {
                    change_id: cid,
                    change_bytes: bytes,
                });
            }
        }
        Ok(out)
    }
}

/// An import of an export file by a device with no state for the space: a
/// new device after the loss of every device (DESIGN.md "Data retention").
/// The device keys sign the start and the chunks. With `recovery_key`, the
/// recovery key signs the finish, because the device is not active in the
/// log. The app then opens the engine with [`Engine::open_recovery`].
///
/// # Errors
///
/// [`EngineError::Invalid`] for a file that fails section 15 or the chain
/// check, a file of another log or app, a bad token or recovery key.
pub fn import_file(
    file: &[u8],
    space: SpaceRef,
    keys_in: &DeviceKeys,
    setup_token: &str,
    recovery_key: Option<&str>,
) -> Result<Import, EngineError> {
    let f =
        export::parse(file).map_err(|e| EngineError::Invalid(format!("export file: {}", e.0)))?;
    export::check_log(&f).map_err(|e| EngineError::Invalid(format!("export file: {e}")))?;
    let log_id = decode_id::<16>(&space.log_id, "l_")
        .map_err(|e| EngineError::Invalid(format!("log ID: {e}")))?;
    if f.header.log_id != log_id || f.header.app != space.app_id {
        return Err(EngineError::Invalid(
            "the export file names another log or app".into(),
        ));
    }
    let finisher = recovery_key
        .map(|k| RecoverySigner::new(k, ""))
        .transpose()?;
    let entries = f
        .entries
        .into_iter()
        .map(|(p, e)| match e {
            RepairItem::Envelope(r) => Ok((p, OutEntry::Envelope(r.json))),
            RepairItem::Stub(s) => Ok((p, OutEntry::Stub(s))),
            RepairItem::Invalid(e) => Err(EngineError::Invalid(format!("export file: {e}"))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let sign = SecretKey::from_seed(&keys_in.sign_seed);
    let device = Keys {
        sign: sign.public(),
        seal: Box::new(keys::seal_public(&keys_in.seal_seed)),
    };
    Import::new(
        space,
        setup_token,
        sign,
        device,
        finisher,
        entries,
        f.header.head,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Info,
    Start,
    Chunk,
    Finish,
    Done,
}

/// One import session (`PROTOCOL.md` 10.13). The app calls
/// [`Import::next_request`], sends the request, and passes the response to
/// [`Import::handle_response`], until `next_request` gives `None`.
pub struct Import {
    space: SpaceRef,
    setup: [u8; 32],
    sign: SecretKey,
    device_id: Hash32,
    device: Keys,
    finisher: Option<RecoverySigner>,
    entries: Vec<(u64, OutEntry)>,
    tip: Head,
    chunks: VecDeque<Vec<(u64, OutEntry)>>,
    session: Option<[u8; 16]>,
    step: Step,
    sent: bool,
    offset: i64,
    clock: fn() -> u64,
}

impl std::fmt::Debug for Import {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Import")
            .field("step", &self.step)
            .field("tip", &self.tip)
            .finish_non_exhaustive()
    }
}

/// Split `entries` into chunks whose body fits `max_request_bytes` and
/// `max_append_envelopes` (10.13 with the size rule of 10.9). An entry that
/// does not fit alone goes alone: the relay allows 1,024 bytes more.
fn chunks(
    entries: &[(u64, OutEntry)],
    limits: &Limits,
    first_extra: usize,
) -> Result<VecDeque<Vec<(u64, OutEntry)>>, EngineError> {
    let max = usize::try_from(limits.max_request_bytes).unwrap_or(usize::MAX);
    let n_max = usize::try_from(limits.max_append_envelopes)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut out = VecDeque::new();
    let mut cur: Vec<(u64, OutEntry)> = Vec::new();
    // The wrapper of a chunk body: session, brackets and the setup and
    // device fields of the start.
    let wrapper = 96usize;
    let mut size = wrapper.saturating_add(first_extra);
    for (p, e) in entries {
        let len = wire::entry_json(*p, e)
            .map_err(|e| EngineError::Storage(e.0))?
            .len()
            .saturating_add(1);
        if !cur.is_empty() && (size.saturating_add(len) > max || cur.len() >= n_max) {
            out.push_back(std::mem::take(&mut cur));
            size = wrapper;
        }
        size = size.saturating_add(len);
        cur.push((*p, e.clone()));
    }
    if !cur.is_empty() {
        out.push_back(cur);
    }
    Ok(out)
}

impl Import {
    fn new(
        space: SpaceRef,
        setup_token: &str,
        sign: SecretKey,
        device: Keys,
        finisher: Option<RecoverySigner>,
        entries: Vec<(u64, OutEntry)>,
        tip: Head,
    ) -> Result<Self, EngineError> {
        let setup = setup::parse_token(setup::TokenKind::Setup, setup_token)
            .map_err(|e| EngineError::Invalid(format!("setup token: {e}")))?;
        let mut space = space;
        space.relay_url = crate::relay_base(&space.relay_url)?;
        let device_id = keys::device_id(&device.sign, &device.seal);
        Ok(Self {
            space,
            setup,
            sign,
            device_id,
            device,
            finisher,
            entries,
            tip,
            chunks: VecDeque::new(),
            session: None,
            step: Step::Info,
            sent: false,
            offset: 0,
            clock: crate::system_time,
        })
    }

    /// Set the device clock, for tests.
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    fn now(&self) -> u64 {
        let t = (self.clock)();
        t.checked_add_signed(self.offset).unwrap_or(t)
    }

    /// True after the relay made the space.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.step == Step::Done
            && self.session.is_none()
            && self.chunks.is_empty()
            && self.entries.is_empty()
    }

    fn path(&self, tail: &str) -> String {
        format!(
            "/v1/t/{}/s/{}/import{tail}",
            self.space.tenant, self.space.log_id
        )
    }

    /// The next request, or `None` at the end.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnexpectedResponse`] if a request waits for its
    /// response, [`EngineError::Random`] and [`EngineError::Storage`].
    pub fn next_request(&mut self) -> Result<Option<Request>, EngineError> {
        if self.sent {
            return Err(EngineError::UnexpectedResponse);
        }
        let now = self.now();
        let req = match self.step {
            Step::Done => return Ok(None),
            Step::Info => Request {
                method: "GET".into(),
                url: format!("{}/v1/info", self.space.relay_url),
                headers: json_headers(b""),
                body: Vec::new(),
            },
            Step::Start => {
                let first = self.chunks.front().ok_or(EngineError::UnexpectedResponse)?;
                let body = wire::import_start_body(&self.setup, &self.device, first)
                    .map_err(|e| EngineError::Storage(e.0))?;
                signed(
                    &self.space.relay_url,
                    &self.path(""),
                    body,
                    &self.sign,
                    self.device_id,
                    false,
                    now,
                )?
            }
            Step::Chunk => {
                let session = self.session.ok_or(EngineError::UnexpectedResponse)?;
                let c = self.chunks.front().ok_or(EngineError::UnexpectedResponse)?;
                let body =
                    wire::repair_chunk_body(&session, c).map_err(|e| EngineError::Storage(e.0))?;
                signed(
                    &self.space.relay_url,
                    &self.path("/chunk"),
                    body,
                    &self.sign,
                    self.device_id,
                    false,
                    now,
                )?
            }
            Step::Finish => {
                let session = self.session.ok_or(EngineError::UnexpectedResponse)?;
                let body = wire::repair_finish_body(&RepairFinish {
                    session,
                    tip: self.tip,
                });
                let path = self.path("/finish");
                match &self.finisher {
                    Some(r) => {
                        signed(&self.space.relay_url, &path, body, &r.sign, r.id, true, now)?
                    }
                    None => signed(
                        &self.space.relay_url,
                        &path,
                        body,
                        &self.sign,
                        self.device_id,
                        false,
                        now,
                    )?,
                }
            }
        };
        self.sent = true;
        Ok(Some(req))
    }

    /// Read the response to the last request.
    ///
    /// # Errors
    ///
    /// [`EngineError::Refused`] with the error code of the relay, for
    /// example `space_exists`, `bad_setup` or `quota`. The app can start a
    /// new import. [`EngineError::UnexpectedResponse`] if no request waits.
    pub fn handle_response(
        &mut self,
        status: u16,
        headers: &[Header],
        body: &[u8],
    ) -> Result<(), EngineError> {
        if !std::mem::take(&mut self.sent) {
            return Err(EngineError::UnexpectedResponse);
        }
        if let Some(t) = time_of(headers) {
            let local = (self.clock)();
            self.offset =
                i64::try_from(i128::from(t).saturating_sub(i128::from(local))).unwrap_or(0);
        }
        if !(200..300).contains(&status) {
            self.step = Step::Done;
            return Err(refused(body, status));
        }
        let bad = |what: &str| {
            EngineError::Invalid(format!("the relay sent an unreadable {what} answer"))
        };
        match self.step {
            Step::Info => {
                let info = wire::parse_info(body).map_err(|_| bad("info"))?;
                let extra = 128usize.saturating_add(self.device.seal.len().saturating_mul(4) / 3);
                self.chunks = chunks(&std::mem::take(&mut self.entries), &info.limits, extra)?;
                self.step = Step::Start;
            }
            Step::Start | Step::Chunk => {
                let next = if self.step == Step::Start {
                    let (s, n) =
                        wire::parse_repair_started(body).map_err(|_| bad("import start"))?;
                    self.session = Some(s);
                    n
                } else {
                    wire::parse_repair_next(body).map_err(|_| bad("import chunk"))?
                };
                let sent = self.chunks.pop_front().unwrap_or_default();
                let want = sent.last().map_or(0, |(p, _)| p.saturating_add(1));
                if next != want {
                    self.step = Step::Done;
                    return Err(EngineError::Refused {
                        code: "bad_import".into(),
                    });
                }
                self.step = if self.chunks.is_empty() {
                    Step::Finish
                } else {
                    Step::Chunk
                };
            }
            Step::Finish => {
                let head = wire::parse_repair_finished(body).map_err(|_| bad("import finish"))?;
                if head != self.tip {
                    return Err(EngineError::Refused {
                        code: "bad_import".into(),
                    });
                }
                self.session = None;
                self.step = Step::Done;
            }
            Step::Done => return Err(EngineError::UnexpectedResponse),
        }
        Ok(())
    }
}
