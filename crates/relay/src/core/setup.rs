//! The setup surface (`PROTOCOL.md` 10.5, 10.11 and 12.3): the setup token
//! exchange, the setup token check of space creation, and device status
//! reports.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use snailfish_protocol::encoding::{Hash32, encode_id};
use snailfish_protocol::keys;
use snailfish_protocol::setup::{self, TokenResponse};

use super::{ApiResult, Relay, Request, Tenant, api, from_i64, random, to_i64};
use crate::store::{self, Kind};

/// A setup token expires this many seconds after its exchange ([USR-5]).
pub const SETUP_TOKEN_SECONDS: u64 = 600;

fn bad_setup(why: &str) -> super::ApiError {
    api(403, "bad_setup", why)
}

impl Relay {
    /// `POST /v1/setup/token` (12.3).
    pub(super) fn setup_token(&self, req: &Request, now: u64) -> ApiResult<(u16, Vec<u8>)> {
        self.guard(req)?;
        // Step 1: 8.6 steps 1 to 4. The device key comes from the body.
        match self.verify(req, now, |_| None) {
            Err(e) if e.code != "unknown_device" => return Err(e),
            _ => {}
        }
        // Step 2.
        let r = setup::parse_token_request(&req.body).map_err(|e| api(400, "bad_request", e.0))?;
        // Step 3: 8.6 steps 5 to 7 with the keys of the body only.
        let id = keys::device_id(&r.device.sign, &r.device.seal);
        let sign = r.device.sign;
        let v = self.verify(req, now, |k| (k == &id).then_some(sign))?;
        let mut d = self.directory()?;
        let tx = d.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM setup_nonces WHERE expires < ?1",
            params![to_i64(now)?],
        )?;
        let fresh = tx.execute(
            "INSERT INTO setup_nonces (keyid, nonce, expires) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![
                encode_id("d_", &v.keyid),
                encode_id("", &v.nonce),
                to_i64(v.expires)?
            ],
        )?;
        if fresh == 0 {
            return Err(api(401, "nonce_reused", "the nonce was used before"));
        }
        // A refusal below must still keep the nonce (8.6: a request that
        // fails a check changes no stored state, except the nonce).
        let outcome = (|| {
            let row: Option<(String, String, String, i64, i64)> = tx
                .query_row(
                    "SELECT user_id, challenge, redirect_uri, expires, used FROM codes
                     WHERE code_hash = ?1",
                    params![setup::token_hash(&r.code).as_slice()],
                    |q| Ok((q.get(0)?, q.get(1)?, q.get(2)?, q.get(3)?, q.get(4)?)),
                )
                .optional()?;
            // Step 4.
            let Some((user_id, challenge, redirect_uri, expires, used)) = row else {
                return Err(bad_setup("the relay holds no such code"));
            };
            if used != 0 || now >= from_i64(expires)? {
                return Err(bad_setup("the code is used or expired"));
            }
            // Step 5 ([USR-4]).
            if r.redirect_uri != redirect_uri || setup::challenge(&r.verifier) != challenge {
                return Err(bad_setup(
                    "the redirect URI or the code verifier does not match the code",
                ));
            }
            // Step 6 ([USR-5]).
            let token: [u8; 32] = random()?;
            let expires = now.saturating_add(SETUP_TOKEN_SECONDS);
            tx.execute(
                "UPDATE codes SET used = 1 WHERE code_hash = ?1",
                params![setup::token_hash(&r.code).as_slice()],
            )?;
            tx.execute(
                "INSERT INTO setup_tokens (token_hash, user_id, device_id, expires)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    setup::token_hash(&token).as_slice(),
                    user_id,
                    id.as_slice(),
                    to_i64(expires)?
                ],
            )?;
            // [USR-3]: the user of the code selects the tenant.
            let tenant: String = tx.query_row(
                "SELECT t.handle FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id
                 WHERE u.user_id = ?1",
                params![user_id],
                |q| q.get(0),
            )?;
            Ok(setup::token_response_body(&TokenResponse {
                token,
                tenant,
                expires,
            }))
        })();
        match outcome {
            Ok(body) => {
                tx.commit()?;
                Ok((200, body))
            }
            Err(e) if e.code == "bad_setup" => {
                tx.commit()?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// 10.5 step 3 ([USR-6]): the setup token exists, has not expired, names
    /// the signer and belongs to the user of the tenant.
    pub(super) fn check_setup(
        &self,
        tenant: &Tenant,
        token: &[u8; 32],
        signer: &Hash32,
        now: u64,
    ) -> ApiResult<()> {
        let d = self.directory()?;
        let row: Option<(Vec<u8>, i64, String)> = d
            .query_row(
                "SELECT s.device_id, s.expires, u.tenant_id FROM setup_tokens s
                 JOIN users u ON u.user_id = s.user_id WHERE s.token_hash = ?1",
                params![setup::token_hash(token).as_slice()],
                |q| Ok((q.get(0)?, q.get(1)?, q.get(2)?)),
            )
            .optional()?;
        let Some((device, expires, tenant_id)) = row else {
            return Err(bad_setup("the relay holds no such setup token"));
        };
        if now >= from_i64(expires)? {
            return Err(bad_setup("the setup token expired"));
        }
        if device.as_slice() != signer.as_slice() {
            return Err(bad_setup("the setup token names another device"));
        }
        if tenant_id != tenant.id {
            return Err(bad_setup("the setup token belongs to another tenant"));
        }
        Ok(())
    }

    /// `POST /v1/t/{tenant}/s/{log}/device-status` (10.11).
    pub(super) fn device_status(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        let (sp, v) = self.open_signed(req, now, tenant, log)?;
        let s = setup::parse_device_status(&req.body).map_err(|e| api(400, "bad_request", e.0))?;
        // DESIGN.md "Monitoring and alerting" item 7: the relay keeps the time
        // since which the applied position is behind the log head.
        let head = super::read_head(&sp.conn)?.position;
        let c = store::open(&sp.tenant.db(), Kind::Tenant, false)?;
        let num =
            |n: u64| to_i64(n).map_err(|_| api(400, "bad_request", "a number is out of range"));
        let behind = (s.applied < head).then_some(to_i64(now)?);
        c.execute(
            "INSERT INTO device_status (log_id, device_id, state, outbox, oldest, applied, epoch, time, behind_since)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (log_id, device_id) DO UPDATE SET state = excluded.state,
               outbox = excluded.outbox, oldest = excluded.oldest, applied = excluded.applied,
               epoch = excluded.epoch, time = excluded.time,
               behind_since = CASE WHEN excluded.behind_since IS NULL THEN NULL
                 ELSE COALESCE(device_status.behind_since, excluded.behind_since) END",
            params![
                sp.log,
                encode_id("d_", &v.keyid),
                s.state,
                num(s.outbox)?,
                s.oldest.map(num).transpose()?,
                num(s.applied)?,
                num(s.epoch)?,
                to_i64(now)?,
                behind
            ],
        )?;
        Ok((200, b"{}".to_vec()))
    }
}
