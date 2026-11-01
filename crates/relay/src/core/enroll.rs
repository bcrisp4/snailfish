//! The enrollment session routes (`PROTOCOL.md` 10.10, [ENR-1] to
//! [ENR-8]).
//!
//! A session is a mailbox in `directory.db`, because the routes of the new
//! device name only the session ID: the new device has no key that the
//! relay knows. The trusted device opens the session on its signed route,
//! which binds it to its tenant and its space ([ENR-2]). The relay checks
//! the form of each message and its order. The devices check the content.

use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};
use snailfish_protocol::encoding::{decode_id, encode_id};
use snailfish_protocol::enroll::{Role, SESSION_SECONDS};
use snailfish_protocol::mailbox::{self, Slot, State, Write};

use super::{ApiResult, Relay, Request, api, to_i64};
use crate::store::{self, Kind, StoreError};

/// The trusted device and space that opened a session.
struct Owner<'a> {
    tenant: &'a str,
    log: &'a str,
    device: String,
}

struct Row {
    tenant: String,
    log: String,
    device: String,
    expires: u64,
    state: State,
    messages: [Option<String>; 6],
}

fn unknown_session() -> super::ApiError {
    api(
        404,
        "unknown_session",
        "the relay holds no session with this ID",
    )
}

fn session_id(text: &str) -> ApiResult<[u8; 16]> {
    decode_id::<16>(text, "e_").map_err(|_| unknown_session())
}

fn state_of(s: &str) -> Result<State, StoreError> {
    match s {
        "open" => Ok(State::Open),
        "done" => Ok(State::Done),
        "cancelled" => Ok(State::Cancelled),
        _ => Err(StoreError::Corrupt(
            "an enrollment session state is malformed",
        )),
    }
}

/// Delete expired sessions, then read the session. A session at its
/// `expires` time or later does not exist (10.10).
fn load(tx: &Transaction<'_>, session: &str, now: u64) -> ApiResult<Option<Row>> {
    tx.execute(
        "DELETE FROM enroll_sessions WHERE expires <= ?1",
        params![to_i64(now)?],
    )?;
    let row = tx
        .query_row(
            "SELECT tenant, log_id, device_id, expires, state, m0, m1, m2, m3, m4, m5
             FROM enroll_sessions WHERE session = ?1",
            params![session],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    [
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                    ],
                ))
            },
        )
        .optional()?;
    row.map(|(tenant, log, device, expires, state, messages)| {
        Ok(Row {
            tenant,
            log,
            device,
            expires: super::from_i64(expires)?,
            state: state_of(&state)?,
            messages,
        })
    })
    .transpose()
}

/// Read the session for the route of `owner`: the trusted route sees only
/// the sessions that its device opened in its space (10.10 step 4).
fn load_for(
    tx: &Transaction<'_>,
    session: &str,
    now: u64,
    owner: Option<&Owner<'_>>,
) -> ApiResult<Row> {
    let row = load(tx, session, now)?.ok_or_else(unknown_session)?;
    if let Some(o) = owner
        && (row.tenant != o.tenant || row.log != o.log || row.device != o.device)
    {
        return Err(unknown_session());
    }
    Ok(row)
}

fn body_of(session: &[u8; 16], row: &Row) -> Vec<u8> {
    mailbox::session_body(session, row.expires, row.state, &row.messages)
}

impl Relay {
    fn directory(&self) -> Result<rusqlite::Connection, StoreError> {
        store::open(
            &self.cfg.data_dir.join("directory.db"),
            Kind::Directory,
            false,
        )
    }

    /// 8.6 steps 1 to 4 for a signed enrollment route. They run before the
    /// body parse (10.10 write step 1). No key matches yet, so a request
    /// that passes them stops at step 5, which runs after the parse.
    fn enroll_steps_1_to_4(&self, req: &Request, now: u64) -> ApiResult<()> {
        match self.verify(req, now, |_| None) {
            Err(e) if e.code != "unknown_device" => Err(e),
            _ => Ok(()),
        }
    }

    /// 8.6 steps 5 to 7 with the active devices of the space. Returns the
    /// device ID text of the signer.
    fn enroll_signer(&self, req: &Request, now: u64, tenant: &str, log: &str) -> ApiResult<String> {
        let sp = self.open_space(tenant, log)?;
        let keys = super::load_devices(&sp.conn)?;
        let v = self.verify(req, now, |id| keys.get(id).copied())?;
        Self::claim_nonce(&sp.tenant, &v, now)?;
        Ok(encode_id("d_", &v.keyid))
    }

    /// `POST /v1/t/{tenant}/s/{log}/enroll`: open a session (10.10).
    pub(super) fn enroll_open(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        self.guard(req)?;
        self.open_space(tenant, log)?;
        self.enroll_steps_1_to_4(req, now)?;
        let session = mailbox::parse_open(&req.body).map_err(|e| api(400, "bad_request", e.0))?;
        let device = self.enroll_signer(req, now, tenant, log)?;
        let session = encode_id("e_", &session);
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(row) = load(&tx, &session, now)? {
            if row.tenant == tenant && row.log == log && row.device == device {
                tx.commit()?;
                return Ok((200, mailbox::opened_body(row.expires)));
            }
            return Err(api(
                409,
                "session_exists",
                "the relay holds this session for another device or space",
            ));
        }
        let expires = now.saturating_add(SESSION_SECONDS);
        tx.execute(
            "INSERT INTO enroll_sessions (session, tenant, log_id, device_id, expires, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open')",
            params![session, tenant, log, device, to_i64(expires)?],
        )?;
        tx.commit()?;
        Ok((201, mailbox::opened_body(expires)))
    }

    /// `GET` of a session on the trusted route or the route of the new
    /// device (10.10 read).
    pub(super) fn enroll_read(
        &self,
        req: &Request,
        now: u64,
        space: Option<(&str, &str)>,
        session: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        self.guard(req)?;
        let device = match space {
            Some((tenant, log)) => {
                self.open_space(tenant, log)?;
                self.enroll_steps_1_to_4(req, now)?;
                Some(self.enroll_signer(req, now, tenant, log)?)
            }
            None => None,
        };
        let id = session_id(session)?;
        let owner = space.zip(device).map(|((tenant, log), device)| Owner {
            tenant,
            log,
            device,
        });
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = load_for(&tx, session, now, owner.as_ref())?;
        tx.commit()?;
        Ok((200, body_of(&id, &row)))
    }

    /// `POST` of a message on the trusted route or the route of the new
    /// device, in the order of 10.10 write steps 1 to 8.
    pub(super) fn enroll_write(
        &self,
        req: &Request,
        now: u64,
        space: Option<(&str, &str)>,
        session: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        self.guard(req)?;
        let role = if space.is_some() {
            Role::Trusted
        } else {
            Role::New
        };
        if let Some((tenant, log)) = space {
            self.open_space(tenant, log)?;
            self.enroll_steps_1_to_4(req, now)?;
        }
        let write = mailbox::parse_write(&req.body, role, space.map(|(t, _)| t))
            .map_err(|e| api(400, "bad_request", e.0))?;
        let owner = match space {
            Some((tenant, log)) => Some(Owner {
                tenant,
                log,
                device: self.enroll_signer(req, now, tenant, log)?,
            }),
            None => None,
        };
        let id = session_id(session)?;
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut row = load_for(&tx, session, now, owner.as_ref())?;
        let closed = || {
            api(
                409,
                "session_closed",
                "the enrollment session takes no more messages",
            )
        };
        match write {
            Write::Message(slot, text) => {
                let stored = row.messages.get(slot.index()).and_then(Option::as_deref);
                if stored.is_some_and(|s| mailbox::same_message(s, &text)) {
                    tx.commit()?;
                    return Ok((200, body_of(&id, &row)));
                }
                if row.state != State::Open {
                    return Err(closed());
                }
                let filled = row.messages.each_ref().map(Option::is_some);
                if !mailbox::is_next(&filled, slot) {
                    return Err(api(
                        409,
                        "bad_step",
                        "the message is not the next message of the session",
                    ));
                }
                if slot == Slot::TrustedDone {
                    row.state = State::Done;
                }
                if let Some(m) = row.messages.get_mut(slot.index()) {
                    *m = Some(text);
                }
            }
            Write::Cancel => match row.state {
                State::Cancelled => {
                    tx.commit()?;
                    return Ok((200, body_of(&id, &row)));
                }
                State::Done => return Err(closed()),
                State::Open => row.state = State::Cancelled,
            },
        }
        let [m0, m1, m2, m3, m4, m5] = &row.messages;
        tx.execute(
            "UPDATE enroll_sessions SET state = ?2, m0 = ?3, m1 = ?4, m2 = ?5, m3 = ?6, m4 = ?7, m5 = ?8
             WHERE session = ?1",
            params![session, row.state.text(), m0, m1, m2, m3, m4, m5],
        )?;
        tx.commit()?;
        Ok((200, body_of(&id, &row)))
    }
}
