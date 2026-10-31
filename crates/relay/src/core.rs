//! The synchronous core: all SQLite and protocol logic of the relay.
//!
//! The core needs no async runtime. It opens each database file for each
//! request (no pool), so a write in one tenant never waits for another
//! tenant ([STO-1], [STO-3], [STO-11]). A reader uses a deferred
//! transaction. A writer uses `BEGIN IMMEDIATE` and the busy timeout.
//!
//! All check logic lives in `snailfish-protocol`. The core stores and reads.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use snailfish_protocol::encoding::{Hash32, decode_id, encode_id};
use snailfish_protocol::records::{self, Body};
use snailfish_protocol::request::{self, AUTHORITY_HEADER, RequestError, Target, Verified};
use snailfish_protocol::space::{
    Accepted, Mode, SpaceView, Verdict, check_append, check_genesis, genesis_level,
};
use snailfish_protocol::wire::{self, AppendResult, Head, Limits};

use crate::store::{self, Kind, StoreError};

/// The protocol levels that the relay accepts ([VER-6]).
pub const LEVELS: [u64; 1] = [1];

/// A source of the relay time in Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The relay configuration.
#[derive(Clone)]
pub struct Config {
    /// The data directory (`directory.db` and `tenants/`).
    pub data_dir: PathBuf,
    /// The authority that request signatures cover (`PROTOCOL.md` 8.3). The
    /// relay never reads it from a request.
    pub authority: String,
    /// The size limits of `GET /v1/info`.
    pub limits: Limits,
    /// The relay time.
    pub clock: Clock,
}

impl Config {
    /// A configuration with the default limits and the system clock.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, authority: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            authority: authority.into(),
            limits: Limits::default(),
            clock: Arc::new(system_time),
        }
    }
}

/// The system time in Unix seconds.
#[must_use]
pub fn system_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A configuration or start-up failure.
#[derive(Debug)]
pub enum OpenError {
    /// The authority is missing or malformed.
    Authority(&'static str),
    /// A storage failure.
    Store(StoreError),
    /// The user name is in use.
    UserExists,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(why) => write!(f, "authority: {why}"),
            Self::Store(e) => e.fmt(f),
            Self::UserExists => f.write_str("a user with this name exists"),
        }
    }
}

impl std::error::Error for OpenError {}

impl<E: Into<StoreError>> From<E> for OpenError {
    fn from(e: E) -> Self {
        Self::Store(e.into())
    }
}

/// One HTTP request, as the edge received it.
#[derive(Debug, Clone)]
pub struct Request {
    /// The method in uppercase.
    pub method: String,
    /// The path exactly as received, without the query.
    pub path: String,
    /// The query exactly as received, without `?`. Empty if none.
    pub query: String,
    /// Every header, one pair for each occurrence.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// One HTTP response. The edge adds `snailfish-time` from `time` ([WIR-7]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body.
    pub body: Vec<u8>,
    /// The relay time for the `snailfish-time` header.
    pub time: u64,
}

impl Response {
    /// A JSON error response for the edge (`PROTOCOL.md` 10.3).
    #[must_use]
    pub fn error(status: u16, code: &str, message: &str, time: u64) -> Self {
        Self {
            status,
            body: wire::error_body(code, message),
            time,
        }
    }
}

/// A refused request with its `PROTOCOL.md` 10.3 code.
#[derive(Debug)]
struct ApiError {
    status: u16,
    code: &'static str,
    message: String,
}

fn api(status: u16, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError {
        status,
        code,
        message: message.into(),
    }
}

fn internal() -> ApiError {
    // The text never names the cause: a cause can hold a path or an ID.
    api(500, "internal", "the relay failed")
}

impl From<StoreError> for ApiError {
    fn from(_: StoreError) -> Self {
        internal()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        internal()
    }
}

impl From<RequestError> for ApiError {
    fn from(e: RequestError) -> Self {
        let status = match e {
            RequestError::WrongAuthority => 421,
            RequestError::BadSignature(_) | RequestError::Expired => 401,
            RequestError::BadDigest => 400,
            RequestError::UnknownDevice => 403,
        };
        api(status, e.code(), e.to_string())
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// The relay core. It is cheap to clone.
#[derive(Clone)]
pub struct Relay {
    cfg: Arc<Config>,
}

struct Tenant {
    dir: PathBuf,
}

impl Tenant {
    fn db(&self) -> PathBuf {
        self.dir.join("tenant.db")
    }
}

fn to_i64(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Corrupt("a number is out of range"))
}

fn from_i64(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt("a number is out of range"))
}

fn random<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| StoreError::Corrupt("no random bytes"))?;
    Ok(b)
}

/// True if `s` is a tenant ID or a space file stem that the relay made:
/// only lowercase letters and digits. A path component never comes from a
/// caller ([STO-3]).
fn safe_name(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn valid_handle(h: &str) -> bool {
    decode_id::<16>(h, "t_").is_ok()
}

fn remove_db_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        // Best effort: the file can be absent.
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}

impl Relay {
    /// Create the data layout and open the relay.
    ///
    /// # Errors
    ///
    /// [`OpenError::Authority`] if the authority is empty or not in the
    /// form of `PROTOCOL.md` 8.3, and [`OpenError::Store`] for a storage
    /// failure, also a database file with a newer schema ([VER-15]).
    pub fn open(cfg: Config) -> Result<Self, OpenError> {
        let a = &cfg.authority;
        if a.is_empty() {
            return Err(OpenError::Authority("the relay needs an authority"));
        }
        if a.bytes()
            .any(|c| c.is_ascii_uppercase() || c.is_ascii_whitespace() || c == b'/' || c == b'@')
        {
            return Err(OpenError::Authority(
                "the authority is a lowercase host with an optional port",
            ));
        }
        std::fs::create_dir_all(cfg.data_dir.join("tenants")).map_err(StoreError::Io)?;
        store::open(&cfg.data_dir.join("directory.db"), Kind::Directory, true)?;
        Ok(Self { cfg: Arc::new(cfg) })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Create a user and its tenant. Returns the tenant handle ([STO-10]).
    ///
    /// # Errors
    ///
    /// [`OpenError::UserExists`] for a known name, or a storage failure.
    pub fn add_user(&self, name: &str) -> Result<String, OpenError> {
        let handle = encode_id("t_", &random::<16>()?);
        self.add_user_with_handle(name, &handle)?;
        Ok(handle)
    }

    /// Create a user and its tenant with a chosen handle. Tests use this to
    /// match the shared vectors. The handle must be `t_` and 32 lowercase hex
    /// digits.
    ///
    /// # Errors
    ///
    /// As [`Relay::add_user`], and [`OpenError::Authority`] is not used here:
    /// a malformed handle gives [`StoreError::Corrupt`].
    pub fn add_user_with_handle(&self, name: &str, handle: &str) -> Result<(), OpenError> {
        if !valid_handle(handle) {
            return Err(StoreError::Corrupt("the tenant handle is malformed").into());
        }
        let tenant_id = encode_id("", &random::<16>()?);
        let user_id = encode_id("u_", &random::<16>()?);
        let dir = self.cfg.data_dir.join("tenants").join(&tenant_id);
        std::fs::create_dir_all(dir.join("spaces")).map_err(StoreError::Io)?;
        let made = self.add_tenant(name, handle, &tenant_id, &user_id, &dir);
        if made.is_err() {
            // The directory does not name the tenant, so nothing reaches its
            // files. Best effort: a failed removal leaves an unused directory.
            let _ = std::fs::remove_dir_all(&dir);
        }
        made
    }

    fn add_tenant(
        &self,
        name: &str,
        handle: &str,
        tenant_id: &str,
        user_id: &str,
        dir: &Path,
    ) -> Result<(), OpenError> {
        let t = store::open(&dir.join("tenant.db"), Kind::Tenant, true)?;
        t.execute(
            "INSERT INTO tenant (id, handle) VALUES (1, ?1)",
            params![handle],
        )
        .map_err(StoreError::from)?;
        let mut d = store::open(
            &self.cfg.data_dir.join("directory.db"),
            Kind::Directory,
            false,
        )?;
        let tx = d
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let taken: Option<i64> = tx
            .query_row("SELECT 1 FROM users WHERE name = ?1", params![name], |r| {
                r.get(0)
            })
            .optional()
            .map_err(StoreError::from)?;
        if taken.is_some() {
            return Err(OpenError::UserExists);
        }
        tx.execute(
            "INSERT INTO tenants (tenant_id, handle) VALUES (?1, ?2)",
            params![tenant_id, handle],
        )
        .map_err(StoreError::from)?;
        tx.execute(
            "INSERT INTO users (user_id, name, tenant_id) VALUES (?1, ?2, ?3)",
            params![user_id, name, tenant_id],
        )
        .map_err(StoreError::from)?;
        tx.commit().map_err(StoreError::from)?;
        Ok(())
    }

    /// Handle one request. This is the only entry point of the HTTP edge.
    #[must_use]
    pub fn handle(&self, req: &Request) -> Response {
        let now = (self.cfg.clock)();
        match self.dispatch(req, now) {
            Ok((status, body)) => Response {
                status,
                body,
                time: now,
            },
            Err(e) => Response::error(e.status, e.code, &e.message, now),
        }
    }

    fn dispatch(&self, req: &Request, now: u64) -> ApiResult<(u16, Vec<u8>)> {
        let segs: Vec<&str> = req.path.split('/').collect();
        match (req.method.as_str(), segs.as_slice()) {
            ("GET", ["", "v1", "health"]) => Ok((200, br#"{"status":"ok"}"#.to_vec())),
            ("GET", ["", "v1", "info"]) => {
                Ok((200, wire::info_body(&LEVELS, &self.cfg.limits, now)))
            }
            ("PUT", ["", "v1", "t", t, "s", l]) => self.put_space(req, now, t, l),
            ("POST", ["", "v1", "t", t, "s", l, "append"]) => self.append(req, now, t, l),
            ("GET", ["", "v1", "t", t, "s", l, "entries"]) => self.entries(req, now, t, l),
            _ => Err(api(404, "not_found", "no route has this path")),
        }
    }

    fn guard(&self, req: &Request) -> ApiResult<()> {
        let max = usize::try_from(self.cfg.limits.max_request_bytes).unwrap_or(usize::MAX);
        if req.body.len() > max {
            return Err(api(413, "too_large", "the body is too large"));
        }
        // 8.6 step 1 runs before every other lookup, so a client with a
        // wrong authority learns it first.
        let mut it = req
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(AUTHORITY_HEADER));
        if let (Some((_, a)), None) = (it.next(), it.next())
            && a != &self.cfg.authority
        {
            return Err(RequestError::WrongAuthority.into());
        }
        Ok(())
    }

    fn tenant(&self, handle: &str) -> ApiResult<Tenant> {
        if !valid_handle(handle) {
            return Err(api(404, "unknown_tenant", "no tenant has this handle"));
        }
        let d = store::open(
            &self.cfg.data_dir.join("directory.db"),
            Kind::Directory,
            false,
        )?;
        let id: Option<String> = d
            .query_row(
                "SELECT tenant_id FROM tenants WHERE handle = ?1",
                params![handle],
                |r| r.get(0),
            )
            .optional()?;
        let id = id.ok_or_else(|| api(404, "unknown_tenant", "no tenant has this handle"))?;
        if !safe_name(&id, 32) {
            return Err(StoreError::Corrupt("a tenant ID is malformed").into());
        }
        Ok(Tenant {
            dir: self.cfg.data_dir.join("tenants").join(id),
        })
    }

    fn space_file(tenant: &Tenant, tc: &Connection, log: &str) -> ApiResult<Option<PathBuf>> {
        let name: Option<String> = tc
            .query_row(
                "SELECT file_name FROM spaces WHERE log_id = ?1 AND status = 'active'",
                params![log],
                |r| r.get(0),
            )
            .optional()?;
        name.map(|n| {
            if safe_name(&n, 26) {
                Ok(tenant.dir.join("spaces").join(format!("{n}.db")))
            } else {
                Err(StoreError::Corrupt("a space file name is malformed").into())
            }
        })
        .transpose()
    }

    fn verify(
        &self,
        req: &Request,
        now: u64,
        keys: impl Fn(&Hash32) -> Option<[u8; 32]>,
    ) -> ApiResult<Verified> {
        let headers: Vec<(&str, &str)> = req
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let target = Target {
            method: &req.method,
            authority: &self.cfg.authority,
            path: &req.path,
            query: &req.query,
        };
        Ok(request::check(&headers, &target, &req.body, now, keys)?)
    }

    /// 8.6 step 7. The relay stores the nonce only after the signature
    /// verifies, and deletes expired nonces.
    fn claim_nonce(tenant: &Tenant, v: &Verified, now: u64) -> ApiResult<()> {
        let mut c = store::open(&tenant.db(), Kind::Tenant, false)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM nonces WHERE expires < ?1",
            params![to_i64(now)?],
        )?;
        let n = tx.execute(
            "INSERT INTO nonces (keyid, nonce, expires) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![
                encode_id("d_", &v.keyid),
                encode_id("", &v.nonce),
                to_i64(v.expires)?
            ],
        )?;
        if n == 0 {
            return Err(api(401, "nonce_reused", "the nonce was used before"));
        }
        tx.commit()?;
        Ok(())
    }

    // ---------------------------------------------------------------- PUT

    fn put_space(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        self.guard(req)?;
        let tenant = self.tenant(tenant)?;
        // 8.6 steps 1 to 4 run before the body parse. The device key comes
        // from the body, so no key matches yet, and a request that passes
        // steps 1 to 4 stops at step 5.
        match self.verify(req, now, |_| None) {
            Err(e) if e.code != "unknown_device" => return Err(e),
            _ => {}
        }
        // The space does not exist yet, so a malformed log ID is a bad
        // request, not `unknown_space`.
        let log_id = decode_id::<16>(log, "l_")
            .map_err(|_| api(400, "bad_request", "the log ID is malformed"))?;
        let raw = wire::parse_genesis(&req.body).map_err(|e| {
            if e.0.starts_with("genesis body:") {
                api(400, "bad_request", e.0)
            } else {
                api(422, "invalid_record", e.0)
            }
        })?;
        // The device key comes from the genesis record: the space does not
        // exist yet. The record signature is checked below ([WIR-2]).
        let record = records::parse_payload(&raw.envelope.payload_type, &raw.envelope.payload)
            .map_err(|e| api(422, "invalid_record", e.to_string()))?;
        let Body::Genesis { device, app, .. } = &record.body else {
            return Err(api(
                422,
                "invalid_record",
                "the first record must be a genesis record",
            ));
        };
        let (dev_id, dev_key) = (device.id, device.keys.sign);
        let v = self.verify(req, now, |id| (id == &dev_id).then_some(dev_key))?;
        Self::claim_nonce(&tenant, &v, now)?;
        let acc = check_genesis(&raw.envelope, &log_id, Some(&v.keyid))
            .map_err(|r| api(422, "invalid_record", r.to_string()))?;

        let mut tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let tx = tc.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(path) = Self::space_file(&tenant, &tx, log)? {
            let sc = store::open(&path, Kind::Space, false)?;
            let stored: Option<Vec<u8>> = sc
                .query_row(
                    "SELECT record_hash FROM entries WHERE position = 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if stored.as_deref() == Some(acc.record_hash.as_slice()) {
                return Ok((
                    200,
                    wire::head_body(&Head {
                        position: 1,
                        digest: acc.digest,
                    }),
                ));
            }
            return Err(api(
                409,
                "space_exists",
                "the space exists with another genesis record",
            ));
        }
        let name = data_encoding::BASE32_NOPAD
            .encode(&random::<16>()?)
            .to_ascii_lowercase();
        let path = tenant.dir.join("spaces").join(format!("{name}.db"));
        let made = Self::create_space_file(&path, &log_id, app, &acc, &raw.json);
        if let Err(e) = made {
            remove_db_files(&path);
            return Err(e.into());
        }
        let ins = tx.execute(
            "INSERT INTO spaces (log_id, file_name, app_id, status) VALUES (?1, ?2, ?3, 'active')",
            params![log, name, app],
        );
        if let Err(e) = ins
            .map_err(ApiError::from)
            .and_then(|_| tx.commit().map_err(ApiError::from))
        {
            remove_db_files(&path);
            return Err(e);
        }
        Ok((
            201,
            wire::head_body(&Head {
                position: 1,
                digest: acc.digest,
            }),
        ))
    }

    fn create_space_file(
        path: &Path,
        log_id: &[u8; 16],
        app: &str,
        acc: &Accepted,
        json: &str,
    ) -> Result<(), StoreError> {
        let mut c = store::open(path, Kind::Space, true)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let level = genesis_level(&acc.record).ok_or(StoreError::Corrupt("no genesis level"))?;
        tx.execute(
            "INSERT INTO space (id, log_id, app_id, write_level) VALUES (1, ?1, ?2, ?3)",
            params![log_id.as_slice(), app, to_i64(level)?],
        )?;
        insert_entry(&tx, acc, "snailfish.genesis.v1", json)?;
        tx.commit()?;
        Ok(())
    }

    // ------------------------------------------------------------- append

    /// Open the space of a signed sync request and verify the request.
    fn open_signed(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(Connection, Verified, [u8; 16])> {
        self.guard(req)?;
        let tenant = self.tenant(tenant)?;
        let log_id = decode_id::<16>(log, "l_").map_err(|_| {
            api(
                404,
                "unknown_space",
                "the tenant has no space with this log ID",
            )
        })?;
        let tc = store::open(&tenant.db(), Kind::Tenant, false)?;
        let path = Self::space_file(&tenant, &tc, log)?.ok_or_else(|| {
            api(
                404,
                "unknown_space",
                "the tenant has no space with this log ID",
            )
        })?;
        drop(tc);
        let sc = store::open(&path, Kind::Space, false)?;
        let stored: Vec<u8> =
            sc.query_row("SELECT log_id FROM space WHERE id = 1", [], |r| r.get(0))?;
        if stored != log_id {
            return Err(StoreError::Corrupt("a space file holds another log ID").into());
        }
        let keys = load_devices(&sc)?;
        let v = self.verify(req, now, |id| keys.get(id).copied())?;
        Self::claim_nonce(&tenant, &v, now)?;
        Ok((sc, v, log_id))
    }

    fn append(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        let (mut sc, v, log_id) = self.open_signed(req, now, tenant, log)?;
        let limits = &self.cfg.limits;
        let items = wire::parse_append(&req.body, limits.max_append_envelopes)
            .map_err(|e| api(400, "bad_request", e.0))?;
        let max_change_bytes = usize::try_from(limits.max_change_bytes).unwrap_or(usize::MAX);
        // [STO-11]: the checks and the appends of all envelopes share one
        // transaction in the space file.
        let tx = sc.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut results = Vec::with_capacity(items.len());
        {
            let view = SqlView::new(&tx, log_id)?;
            for item in items {
                let Ok(raw) = item else {
                    results.push(AppendResult::Refused("invalid_record".into()));
                    continue;
                };
                let mode = Mode::Relay {
                    signer: v.keyid,
                    max_change_bytes,
                    hold: false,
                };
                let verdict = check_append(&view, &raw.envelope, mode);
                view.take_error()?;
                results.push(match verdict {
                    Verdict::Store(acc) => {
                        insert_entry(&tx, &acc, &raw.envelope.payload_type, &raw.json)?;
                        AppendResult::Stored(acc.position)
                    }
                    Verdict::Known(p) => AppendResult::Known(p),
                    Verdict::Conflict(p) => AppendResult::Conflict(p),
                    Verdict::Refused(r) => AppendResult::Refused(r.code().to_owned()),
                });
            }
        }
        let head = read_head(&tx)?;
        tx.commit()?;
        Ok((200, wire::append_response(&results, &head)))
    }

    // ------------------------------------------------------------ entries

    fn entries(
        &self,
        req: &Request,
        now: u64,
        tenant: &str,
        log: &str,
    ) -> ApiResult<(u16, Vec<u8>)> {
        let (mut sc, _v, _log_id) = self.open_signed(req, now, tenant, log)?;
        let (after, limit) = parse_fetch_query(&req.query, self.cfg.limits.max_fetch_entries)
            .ok_or_else(|| api(400, "bad_request", "the query is not after=N&limit=M"))?;
        // A deferred transaction reads one snapshot, also while a writer
        // appends ([STO-11]).
        let tx = sc.transaction()?;
        let head = read_head(&tx)?;
        let mut rows = Vec::new();
        {
            let mut st = tx.prepare(
                "SELECT position, envelope FROM entries WHERE position > ?1 ORDER BY position LIMIT ?2",
            )?;
            let mut q = st.query(params![to_i64(after)?, to_i64(limit)?])?;
            while let Some(r) = q.next()? {
                rows.push((from_i64(r.get(0)?)?, r.get::<_, String>(1)?));
            }
        }
        let last = rows.last().map_or(after, |(p, _)| *p);
        let has_more = last < head.position;
        let body = wire::fetch_response(&rows, &head, has_more, false).map_err(|_| internal())?;
        Ok((200, body))
    }
}

/// Parse `after=N&limit=M` (`PROTOCOL.md` 10.7): both required, in this
/// order, decimal with no leading zero, and `limit` from 1 to `max`.
fn parse_fetch_query(q: &str, max: u64) -> Option<(u64, u64)> {
    let (a, l) = q.split_once('&')?;
    let a = a.strip_prefix("after=")?;
    let l = l.strip_prefix("limit=")?;
    let after = if a == "0" {
        0
    } else {
        request::parse_decimal(a.as_bytes())?
    };
    let limit = request::parse_decimal(l.as_bytes())?;
    (1..=max).contains(&limit).then_some((after, limit))
}

fn load_devices(c: &Connection) -> Result<BTreeMap<Hash32, [u8; 32]>, StoreError> {
    let mut st = c.prepare("SELECT device_id, sign_key FROM devices")?;
    let mut q = st.query([])?;
    let mut out = BTreeMap::new();
    while let Some(r) = q.next()? {
        let id: Vec<u8> = r.get(0)?;
        let key: Vec<u8> = r.get(1)?;
        let (Ok(id), Ok(key)) = (Hash32::try_from(id), <[u8; 32]>::try_from(key)) else {
            return Err(StoreError::Corrupt("a device row is malformed"));
        };
        out.insert(id, key);
    }
    Ok(out)
}

fn read_head(c: &Connection) -> Result<Head, StoreError> {
    let (p, d): (i64, Vec<u8>) = c.query_row(
        "SELECT position, digest FROM entries ORDER BY position DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Head {
        position: from_i64(p)?,
        digest: Hash32::try_from(d).map_err(|_| StoreError::Corrupt("a digest is malformed"))?,
    })
}

fn insert_entry(
    c: &Connection,
    acc: &Accepted,
    payload_type: &str,
    json: &str,
) -> Result<(), StoreError> {
    c.execute(
        "INSERT INTO entries (position, payload_type, change_id, record_hash, digest, envelope)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            to_i64(acc.position)?,
            payload_type,
            acc.record.change_id().map(<[u8; 16]>::as_slice),
            acc.record_hash.as_slice(),
            acc.digest.as_slice(),
            json
        ],
    )?;
    if let Some((id, key)) = acc.new_device {
        c.execute(
            "INSERT INTO devices (device_id, sign_key, position) VALUES (?1, ?2, ?3)",
            params![id.as_slice(), key.as_slice(), to_i64(acc.position)?],
        )?;
    }
    Ok(())
}

/// A [`SpaceView`] over the SQLite connection of the append transaction.
///
/// The trait has no error channel, so the first database error is kept and
/// the view answers `None`. The caller reads it with `take_error` after each
/// check and fails the request.
struct SqlView<'a> {
    conn: &'a Connection,
    log_id: [u8; 16],
    level: u64,
    error: RefCell<Option<StoreError>>,
}

impl<'a> SqlView<'a> {
    fn new(conn: &'a Connection, log_id: [u8; 16]) -> Result<Self, StoreError> {
        let level: i64 = conn.query_row("SELECT write_level FROM space WHERE id = 1", [], |r| {
            r.get(0)
        })?;
        Ok(Self {
            conn,
            log_id,
            level: from_i64(level)?,
            error: RefCell::new(None),
        })
    }

    fn take_error(&self) -> Result<(), StoreError> {
        self.error.borrow_mut().take().map_or(Ok(()), Err)
    }

    fn query<T>(&self, r: Result<Option<T>, StoreError>) -> Option<T> {
        match r {
            Ok(v) => v,
            Err(e) => {
                self.error.borrow_mut().get_or_insert(e);
                None
            }
        }
    }
}

impl SpaceView for SqlView<'_> {
    fn log_id(&self) -> [u8; 16] {
        self.log_id
    }

    fn head(&self) -> u64 {
        self.query(
            self.conn
                .query_row("SELECT COALESCE(MAX(position), 0) FROM entries", [], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(StoreError::from)
                .and_then(from_i64)
                .map(Some),
        )
        .unwrap_or(0)
    }

    fn digest_at(&self, position: u64) -> Option<Hash32> {
        if position == 0 {
            return Some(snailfish_protocol::hash::digest0(&self.log_id));
        }
        self.query(to_i64(position).and_then(|p| {
            let d: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT digest FROM entries WHERE position = ?1",
                    params![p],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(d.and_then(|d| Hash32::try_from(d).ok()))
        }))
    }

    fn device_key(&self, id: &Hash32) -> Option<[u8; 32]> {
        self.query((|| {
            let k: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT sign_key FROM devices WHERE device_id = ?1",
                    params![id.as_slice()],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(k.and_then(|k| <[u8; 32]>::try_from(k).ok()))
        })())
    }

    fn change(&self, change_id: &[u8; 16]) -> Option<(u64, Hash32)> {
        self.query((|| {
            let row: Option<(i64, Vec<u8>)> = self
                .conn
                .query_row(
                    "SELECT position, record_hash FROM entries WHERE change_id = ?1",
                    params![change_id.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            row.map(|(p, h)| {
                Ok((
                    from_i64(p)?,
                    Hash32::try_from(h).map_err(|_| StoreError::Corrupt("a hash is malformed"))?,
                ))
            })
            .transpose()
        })())
    }

    fn write_level(&self) -> u64 {
        self.level
    }

    fn epoch(&self) -> u64 {
        1
    }

    fn last_security(&self) -> u64 {
        // On a read error the request fails through `take_error`.
        self.query(
            self.conn
                .query_row(
                    "SELECT COALESCE(MAX(position), 0) FROM entries
                     WHERE payload_type NOT LIKE 'snailfish.change.%'
                       AND payload_type NOT LIKE 'snailfish.snapshot.%'
                       AND payload_type NOT LIKE 'snailfish.accept.%'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(StoreError::from)
                .and_then(from_i64)
                .map(Some),
        )
        .unwrap_or(u64::MAX)
    }
}
