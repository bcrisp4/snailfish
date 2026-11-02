//! Shared fixtures: fixed keys and the space of `vectors/http.json`.
#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]
// Each test crate uses a different part of this module.
#![allow(dead_code)]

pub mod passkey;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use snailfish_protocol::encoding::{decode_id, encode_b64};
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::records::Keys;
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::setup;
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::wire::{self, AppendResult, Head, Limits};
use snailfish_relay::core::{Config, Relay, Request, Response};
use tempfile::TempDir;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn load(file: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root().join("vectors").join(file)).unwrap()).unwrap()
}

pub fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

pub fn limits_of(h: &Value) -> Limits {
    let l = &h["limits"];
    let g = |n: &str| l[n].as_u64().unwrap();
    Limits {
        max_request_bytes: g("max_request_bytes"),
        max_change_bytes: g("max_change_bytes"),
        max_snapshot_bytes: g("max_snapshot_bytes"),
        max_append_envelopes: g("max_append_envelopes"),
        max_fetch_entries: g("max_fetch_entries"),
    }
}

/// The keys object of device `name` of `vectors/protocol.json`.
pub fn keys_of(name: &str) -> Keys {
    let p = load("protocol.json");
    let d = p["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap();
    let b = |k: &str| hex::decode(s(&d[k])).unwrap();
    Keys {
        sign: b("sign_pk").try_into().unwrap(),
        seal: Box::new(b("seal_pk").try_into().unwrap()),
    }
}

pub struct Fx {
    pub dir: TempDir,
    pub relay: Relay,
    pub h: Value,
    pub now: Arc<AtomicU64>,
    pub authority: String,
    nonce: AtomicU64,
}

impl Fx {
    pub fn new() -> Self {
        let h = load("http.json");
        let limits = limits_of(&h);
        let authority = s(&h["authority"]).to_owned();
        Self::build(h, authority, limits, TempDir::new().unwrap())
    }

    pub fn with(authority: &str, limits: Limits) -> Self {
        Self::build(
            load("http.json"),
            authority.to_owned(),
            limits,
            TempDir::new().unwrap(),
        )
    }

    fn build(h: Value, authority: String, limits: Limits, dir: TempDir) -> Self {
        let now = Arc::new(AtomicU64::new(h["now"].as_u64().unwrap()));
        let relay = Self::open(&dir, &authority, limits, &now).unwrap();
        let fx = Self {
            dir,
            relay,
            h,
            now,
            authority,
            nonce: AtomicU64::new(1),
        };
        let t = fx.tenant().to_owned();
        fx.relay.add_user_with_handle("sam", &t).unwrap();
        fx
    }

    pub fn open(
        dir: &TempDir,
        authority: &str,
        limits: Limits,
        now: &Arc<AtomicU64>,
    ) -> Result<Relay, snailfish_relay::core::OpenError> {
        let n = Arc::clone(now);
        let mut cfg = Config::new(dir.path(), authority);
        // Each test has its own secrets, not the shared temporary directory.
        cfg.secrets_dir = dir.path().join("secrets");
        cfg.limits = limits;
        cfg.clock = Arc::new(move || n.load(Ordering::SeqCst));
        Relay::open(cfg)
    }

    /// The same data directory and clock with a relay whose configuration
    /// `f` changes.
    pub fn reopen_with(&mut self, f: impl FnOnce(&mut Config)) {
        let n = Arc::clone(&self.now);
        let mut cfg = Config::new(self.dir.path(), &self.authority);
        cfg.secrets_dir = self.dir.path().join("secrets");
        cfg.limits = limits_of(&self.h);
        cfg.clock = Arc::new(move || n.load(Ordering::SeqCst));
        f(&mut cfg);
        self.relay = Relay::open(cfg).unwrap();
    }

    /// The same data directory with a new relay value, as after a restart.
    pub fn restart(&mut self, limits: Limits) {
        self.relay = Self::open(&self.dir, &self.authority, limits, &self.now).unwrap();
    }

    pub fn tenant(&self) -> &str {
        s(&self.h["tenant"])
    }

    pub fn log(&self) -> &str {
        s(&self.h["log_id"])
    }

    pub fn log_id(&self) -> [u8; 16] {
        decode_id::<16>(self.log(), "l_").unwrap()
    }

    pub fn key(&self, name: &str) -> (SecretKey, [u8; 32], String) {
        let d = self.h["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap();
        let seed: [u8; 32] = hex::decode(s(&d["sign_seed"])).unwrap().try_into().unwrap();
        (
            SecretKey::from_seed(&seed),
            decode_id::<32>(s(&d["id"]), "d_").unwrap(),
            s(&d["id"]).to_owned(),
        )
    }

    #[allow(clippy::unused_self)] // Kept as a method so call sites read like the others.
    pub fn space_path(&self, tenant: &str, log: &str) -> String {
        format!("/v1/t/{tenant}/s/{log}")
    }

    /// A signed request. Each call uses a nonce that no vector uses.
    pub fn signed(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
        signer: &str,
    ) -> Request {
        let n = self.nonce.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0xee; 16];
        nonce[8..].copy_from_slice(&n.to_be_bytes());
        self.signed_with(
            method,
            path,
            query,
            body,
            signer,
            nonce,
            self.now.load(Ordering::SeqCst),
        )
    }

    #[allow(clippy::too_many_arguments)] // A fixture takes each signed value.
    pub fn signed_with(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
        signer: &str,
        nonce: [u8; 16],
        created: u64,
    ) -> Request {
        let (sk, id, _) = self.key(signer);
        let t = Target {
            method,
            authority: &self.authority,
            path,
            query,
        };
        let p = Params {
            created,
            expires: created.saturating_add(300),
            nonce,
            keyid: id,
        };
        let h = request::sign(&sk, &t, body, &p);
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers: h
                .pairs()
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }

    /// A setup token of `user` for device `name`, through the real code
    /// exchange of `PROTOCOL.md` 12.3. Only the browser approval is skipped.
    pub fn setup_token(&self, user: &str, name: &str) -> [u8; 32] {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let redirect = "com.example.tasks:/cb";
        let code = self
            .relay
            .issue_code(user, &setup::challenge(verifier), redirect)
            .unwrap();
        let body = setup::token_request_body(&setup::TokenRequest {
            code: setup::parse_token(setup::TokenKind::Code, &code).unwrap(),
            verifier: verifier.into(),
            redirect_uri: redirect.into(),
            device: keys_of(name),
        });
        let r = self
            .relay
            .handle(&self.signed("POST", "/v1/setup/token", "", &body, name));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        setup::parse_token_response(&r.body).unwrap().token
    }

    /// The user name of a tenant handle, or "sam" for an unknown handle.
    pub fn user_of(&self, tenant: &str) -> String {
        let c = rusqlite::Connection::open(self.dir.path().join("directory.db")).unwrap();
        c.query_row(
            "SELECT u.name FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id WHERE t.handle = ?1",
            [tenant],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "sam".to_owned())
    }

    pub fn put_genesis(&self, tenant: &str) -> Response {
        let g = s(&self.h["space"]["genesis"]);
        let path = self.space_path(tenant, self.log());
        let token = self.setup_token(&self.user_of(tenant), "A");
        self.relay
            .handle(&self.signed("PUT", &path, "", &wire::genesis_body(g, &token), "A"))
    }

    /// Create the space of `space.log` in `tenant`: genesis, then the other
    /// entries, each signed by its author.
    pub fn setup_space(&self, tenant: &str) {
        assert_eq!(self.put_genesis(tenant).status, 201);
        let log = self.h["space"]["log"].as_array().unwrap();
        for e in log.iter().skip(1) {
            let json = s(&e["envelope"]);
            let env = Envelope::parse(json.as_bytes()).unwrap();
            let rec = snailfish_protocol::records::parse_payload(&env.payload_type, &env.payload)
                .unwrap();
            let name = ["A", "B", "C"]
                .into_iter()
                .find(|n| &self.key(n).1 == rec.author.id())
                .unwrap();
            let r = self.append(tenant, name, &[json.to_owned()]);
            assert_eq!(r.0, 200);
            let want = e["position"].as_u64().unwrap();
            assert_eq!(r.1[0], AppendResult::Stored(want));
            assert_eq!(hex::encode(r.2.digest), s(&e["digest"]));
        }
    }

    pub fn append(
        &self,
        tenant: &str,
        signer: &str,
        envs: &[String],
    ) -> (u16, Vec<AppendResult>, Head) {
        let path = format!("{}/append", self.space_path(tenant, self.log()));
        let resp =
            self.relay
                .handle(&self.signed("POST", &path, "", &wire::append_body(envs), signer));
        if resp.status != 200 {
            return (
                resp.status,
                vec![],
                Head {
                    position: 0,
                    digest: [0; 32],
                },
            );
        }
        let (r, h) = wire::parse_append_response(&resp.body).unwrap();
        (resp.status, r, h)
    }

    pub fn fetch(&self, tenant: &str, after: u64, limit: u64) -> Response {
        let path = format!("{}/entries", self.space_path(tenant, self.log()));
        self.relay.handle(&self.signed(
            "GET",
            &path,
            &format!("after={after}&limit={limit}"),
            b"",
            "A",
        ))
    }

    pub fn log_entry(&self, position: usize) -> &Value {
        &self.h["space"]["log"][position - 1]
    }

    /// A change by `signer` with a base at `base` of the vector log.
    pub fn change(
        &self,
        signer: &str,
        base: u64,
        change_id: [u8; 16],
        ct_len: usize,
        fill: u8,
    ) -> String {
        let digest =
            hex::decode(s(&self.log_entry(usize::try_from(base).unwrap())["digest"])).unwrap();
        self.change_on(signer, base, &encode_b64(&digest), change_id, ct_len, fill)
    }

    pub fn change_on(
        &self,
        signer: &str,
        base: u64,
        digest_b64: &str,
        change_id: [u8; 16],
        ct_len: usize,
        fill: u8,
    ) -> String {
        let (sk, _, idtext) = self.key(signer);
        let payload = format!(
            r#"{{"log":"{}","author":"{}","base":{{"position":{},"digest":"{}"}},"epoch":1,"change_id":"c_{}","ciphertext":"{}"}}"#,
            self.log(),
            idtext,
            base,
            digest_b64,
            hex::encode(change_id),
            encode_b64(&vec![fill; ct_len]),
        );
        let t = "snailfish.change.v1";
        let sig = sk.sign_record(t, payload.as_bytes());
        Envelope {
            payload_type: t.to_owned(),
            payload: payload.into_bytes(),
            sig,
        }
        .to_json(&idtext)
    }

    /// The path of the `tenant.db` file of a handle.
    pub fn tenant_db(&self, handle: &str) -> PathBuf {
        let d = rusqlite::Connection::open(self.dir.path().join("directory.db")).unwrap();
        let id: String = d
            .query_row(
                "SELECT tenant_id FROM tenants WHERE handle = ?1",
                [handle],
                |r| r.get(0),
            )
            .unwrap();
        self.dir.path().join("tenants").join(id).join("tenant.db")
    }

    /// The only space file of a tenant.
    pub fn space_file(&self, handle: &str) -> PathBuf {
        let dir = self.tenant_db(handle).parent().unwrap().join("spaces");
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "db"))
            .collect();
        assert_eq!(files.len(), 1);
        files.pop().unwrap()
    }

    pub fn seed_nonce(&self, handle: &str, keyid: &str, nonce: &str, expires: u64) {
        let c = rusqlite::Connection::open(self.tenant_db(handle)).unwrap();
        c.execute(
            "INSERT INTO nonces (keyid, nonce, expires) VALUES (?1, ?2, ?3)",
            rusqlite::params![keyid, nonce, i64::try_from(expires).unwrap()],
        )
        .unwrap();
    }

    /// Make sure a tenant with this handle exists, with a user of its own.
    pub fn ensure_tenant(&self, handle: &str) {
        let c = rusqlite::Connection::open(self.dir.path().join("directory.db")).unwrap();
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM tenants WHERE handle = ?1",
                [handle],
                |r| r.get(0),
            )
            .unwrap();
        if n == 0 {
            self.relay
                .add_user_with_handle(&format!("user-{handle}"), handle)
                .unwrap();
        }
    }

    fn user_id_of(&self, handle: &str) -> String {
        self.ensure_tenant(handle);
        let c = rusqlite::Connection::open(self.dir.path().join("directory.db")).unwrap();
        c.query_row(
            "SELECT u.user_id FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id WHERE t.handle = ?1",
            [handle],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Store an authorization code as the approval of 12.2 stores it.
    pub fn seed_code(
        &self,
        code: &str,
        challenge: &str,
        redirect: &str,
        handle: &str,
        expires: u64,
        used: bool,
    ) {
        let user_id = self.user_id_of(handle);
        let t = setup::parse_token(setup::TokenKind::Code, code).unwrap();
        let c = rusqlite::Connection::open(self.dir.path().join("directory.db")).unwrap();
        c.execute(
            "INSERT INTO codes (code_hash, user_id, challenge, redirect_uri, expires, used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                setup::token_hash(&t).as_slice(),
                user_id,
                challenge,
                redirect,
                i64::try_from(expires).unwrap(),
                i64::from(used)
            ],
        )
        .unwrap();
    }

    /// Store a setup token as the exchange of 12.3 stores it.
    pub fn seed_setup_token(&self, token: &str, device: &str, handle: &str, expires: u64) {
        let user = self.user_id_of(handle);
        let t = setup::parse_token(setup::TokenKind::Setup, token).unwrap();
        let id = self.key(device).1;
        let c = rusqlite::Connection::open(self.dir.path().join("directory.db")).unwrap();
        c.execute(
            "INSERT INTO setup_tokens (token_hash, user_id, device_id, expires) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![setup::token_hash(&t).as_slice(), user, id.as_slice(), i64::try_from(expires).unwrap()],
        )
        .unwrap();
    }

    /// The stored change bytes of the space of `space.log` ([QTA-1]).
    pub fn usage(&self, handle: &str) -> u64 {
        let tc = rusqlite::Connection::open(self.tenant_db(handle)).unwrap();
        let file: String = tc
            .query_row(
                "SELECT file_name FROM spaces WHERE log_id = ?1",
                [self.log()],
                |r| r.get(0),
            )
            .unwrap();
        let dir = self
            .tenant_db(handle)
            .parent()
            .unwrap()
            .join("spaces")
            .join(format!("{file}.db"));
        let sc = rusqlite::Connection::open(dir).unwrap();
        let n: i64 = sc
            .query_row("SELECT bytes FROM usage WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        u64::try_from(n).unwrap()
    }

    pub fn nonce_count(&self, handle: &str) -> i64 {
        let c = rusqlite::Connection::open(self.tenant_db(handle)).unwrap();
        c.query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get(0))
            .unwrap()
    }
}

impl Fx {
    /// Put a space on restore hold, or end the hold, as `restore` and
    /// `release-hold` do in the tenant file.
    pub fn set_hold(&self, handle: &str, on: bool) {
        let c = rusqlite::Connection::open(self.tenant_db(handle)).unwrap();
        if on {
            c.execute(
                "INSERT OR REPLACE INTO holds (log_id, since) VALUES (?1, ?2)",
                rusqlite::params![
                    self.log(),
                    i64::try_from(self.now.load(Ordering::SeqCst)).unwrap()
                ],
            )
            .unwrap();
        } else {
            c.execute("DELETE FROM holds", []).unwrap();
            c.execute("DELETE FROM hold_reports", []).unwrap();
        }
    }

    /// Cut the log to positions 1..=n, as a restore of an older space file
    /// does.
    pub fn cut_log(&self, handle: &str, n: u64) {
        let c = rusqlite::Connection::open(self.space_file(handle)).unwrap();
        let n = i64::try_from(n).unwrap();
        c.execute("DELETE FROM entries WHERE position > ?1", [n])
            .unwrap();
        c.execute("DELETE FROM devices WHERE position > ?1", [n])
            .unwrap();
    }

    /// A signed POST to a route under the space path.
    pub fn post(&self, handle: &str, route: &str, body: &[u8], signer: &str) -> Response {
        let path = format!("{}/{route}", self.space_path(handle, self.log()));
        self.relay
            .handle(&self.signed("POST", &path, "", body, signer))
    }

    /// The record hashes of the relay log, read through a fetch.
    pub fn record_hashes(&self, handle: &str) -> Vec<String> {
        let page = wire::parse_fetch(&self.fetch(handle, 0, 500).body).unwrap();
        page.entries
            .into_iter()
            .map(|(_, e)| match e {
                wire::FetchEntry::Envelope(r) => hex::encode(r.envelope.record_hash()),
                wire::FetchEntry::Stub(s) => hex::encode(s.hash),
            })
            .collect()
    }
}

pub fn error_code(r: &Response) -> String {
    wire::parse_error(&r.body).unwrap_or_default()
}
