//! The operator metrics (DESIGN.md "Monitoring and alerting" signals 2 to
//! 4, `ops/prometheus/snailfish.rules.yml`).
//!
//! Counters are process-wide, because one relay process serves one data
//! directory. Gauges come from the data directory at each scrape. No label
//! holds a tenant handle, a log ID, a device ID or an app ID. The one
//! exception is the per-tenant storage figure, which carries the internal
//! tenant ID: the name of `data/tenants/<id>`. It is not a user name and not
//! the tenant handle, which is a routing credential ([STO-10]).
//! `snailfish-relay user list` maps it to the user (DESIGN.md "Monitoring
//! and alerting").

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// The error codes that the relay sends (`PROTOCOL.md` 10.3 and 12.4). A
/// code outside this list counts as `other`, so a label set stays bounded.
const CODES: [&str; 38] = [
    "bad_request",
    "bad_digest",
    "bad_signature",
    "expired",
    "nonce_reused",
    "timeout",
    "bad_setup",
    "blocked",
    "removed",
    "unknown_device",
    "unknown_tenant",
    "unknown_space",
    "deleted",
    "not_found",
    "space_exists",
    "unknown_session",
    "session_exists",
    "bad_step",
    "session_closed",
    "repair_busy",
    "bad_repair",
    "bad_head",
    "bad_import",
    "invalid_record",
    "uncovered_stub",
    "too_large",
    "rate_limited",
    "wrong_authority",
    "internal",
    "backup_running",
    "space_limit",
    "quota",
    "bad_origin",
    "signed_out",
    "bad_csrf",
    "bad_invite",
    "bad_passkey",
    "bad_webhook",
];

/// The append refusals of `PROTOCOL.md` 10.6.
const REASONS: [&str; 12] = [
    "invalid_record",
    "on_hold",
    "too_large",
    "not_author",
    "not_active",
    "bad_base",
    "stale_base",
    "unsupported",
    "wrong_epoch",
    "reserve",
    "security_limit",
    "quota",
];

static CLASSES: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static ERRORS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());
static REFUSALS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());
/// Storage-layer failures: each storage error that became `internal`.
pub static STORAGE_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Schema migrations that failed ([VER-14]).
pub static MIGRATION_FAILURES: AtomicU64 = AtomicU64::new(0);
/// `wal_checkpoint(TRUNCATE)` calls that a reader blocked ([STO-2]).
pub static CHECKPOINT_BUSY: AtomicU64 = AtomicU64::new(0);

fn known(list: &[&'static str], s: &str) -> &'static str {
    list.iter().copied().find(|c| *c == s).unwrap_or("other")
}

/// Count one response by its status class.
pub fn record_status(status: u16) {
    let i = usize::from(status / 100).saturating_sub(1).min(4);
    if let Some(c) = CLASSES.get(i) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Count one error response by its code.
pub fn record_error(code: &str) {
    // A poisoned lock drops the count: metrics never fail a request.
    if let Ok(mut m) = ERRORS.lock() {
        let n = m.entry(known(&CODES, code)).or_insert(0);
        *n = n.saturating_add(1);
    }
}

/// Count one refused envelope of an append by its reason.
pub fn record_refusal(reason: &str) {
    if let Ok(mut m) = REFUSALS.lock() {
        let n = m.entry(known(&REASONS, reason)).or_insert(0);
        *n = n.saturating_add(1);
    }
}

/// The gauges of one scrape, from the data directory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Gauges {
    /// Bytes on disk of each tenant, by internal tenant ID.
    pub tenant_bytes: BTreeMap<String, u64>,
    /// Spaces at or above 80% and 95% of their quota.
    pub above_80: u64,
    /// See `above_80`.
    pub above_95: u64,
    /// Spaces at or above 50% of their security record reserve.
    pub reserve_50: u64,
    /// Stubs of all spaces, their bytes, and the most in one space.
    pub stubs: u64,
    /// See `stubs`.
    pub stub_bytes: u64,
    /// See `stubs`.
    pub stubs_max: u64,
    /// Free and total bytes of the file system of the data directory.
    pub free_bytes: u64,
    /// See `free_bytes`.
    pub size_bytes: u64,
}

/// True if `used` is at or above `num / den` of `limit`.
#[must_use]
pub fn at_least(used: u64, limit: u64, num: u64, den: u64) -> bool {
    u128::from(used).saturating_mul(u128::from(den))
        >= u128::from(limit).saturating_mul(u128::from(num))
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// The metrics page in the Prometheus text format 0.0.4.
#[must_use]
pub fn render(g: &Gauges) -> String {
    let mut out = String::new();
    counters(&mut out);
    gauges(&mut out, g);
    out
}

fn counters(out: &mut String) {
    metric(
        out,
        "snailfish_requests_total",
        "counter",
        "Responses by status class.",
    );
    for (i, c) in CLASSES.iter().enumerate() {
        let _ = writeln!(
            out,
            "snailfish_requests_total{{class=\"{}xx\"}} {}",
            i.saturating_add(1),
            c.load(Ordering::Relaxed)
        );
    }
    metric(
        out,
        "snailfish_request_errors_total",
        "counter",
        "Error responses by error code.",
    );
    if let Ok(m) = ERRORS.lock() {
        for (code, n) in m.iter() {
            let _ = writeln!(out, "snailfish_request_errors_total{{code=\"{code}\"}} {n}");
        }
    }
    metric(
        out,
        "snailfish_append_refusals_total",
        "counter",
        "Refused append envelopes by reason.",
    );
    if let Ok(m) = REFUSALS.lock() {
        for (reason, n) in m.iter() {
            let _ = writeln!(
                out,
                "snailfish_append_refusals_total{{reason=\"{reason}\"}} {n}"
            );
        }
    }
    for (name, help, v) in [
        (
            "snailfish_storage_errors_total",
            "Storage-layer failures.",
            &STORAGE_ERRORS,
        ),
        (
            "snailfish_migration_failures_total",
            "Failed schema migrations.",
            &MIGRATION_FAILURES,
        ),
        (
            "snailfish_wal_checkpoint_busy_total",
            "WAL checkpoints that a reader blocked.",
            &CHECKPOINT_BUSY,
        ),
    ] {
        metric(out, name, "counter", help);
        let _ = writeln!(out, "{name} {}", v.load(Ordering::Relaxed));
    }
}

fn gauges(out: &mut String, g: &Gauges) {
    metric(
        out,
        "snailfish_tenant_stored_bytes",
        "gauge",
        "Bytes on disk of each tenant, by internal tenant ID.",
    );
    for (tenant, n) in &g.tenant_bytes {
        let _ = writeln!(
            out,
            "snailfish_tenant_stored_bytes{{tenant=\"{}\"}} {n}",
            escape(tenant)
        );
    }
    metric(
        out,
        "snailfish_spaces_above_quota",
        "gauge",
        "Spaces at or above a share of their quota.",
    );
    let _ = writeln!(
        out,
        "snailfish_spaces_above_quota{{ratio=\"0.8\"}} {}",
        g.above_80
    );
    let _ = writeln!(
        out,
        "snailfish_spaces_above_quota{{ratio=\"0.95\"}} {}",
        g.above_95
    );
    metric(
        out,
        "snailfish_spaces_above_reserve",
        "gauge",
        "Spaces at or above a share of their security record reserve.",
    );
    let _ = writeln!(
        out,
        "snailfish_spaces_above_reserve{{ratio=\"0.5\"}} {}",
        g.reserve_50
    );
    for (name, help, v) in [
        ("snailfish_stubs", "Stubs of all spaces.", g.stubs),
        (
            "snailfish_stub_bytes",
            "Stub JSON bytes of all spaces.",
            g.stub_bytes,
        ),
        (
            "snailfish_space_stubs_max",
            "The most stubs in one space.",
            g.stubs_max,
        ),
        (
            "snailfish_data_free_bytes",
            "Free bytes of the data file system.",
            g.free_bytes,
        ),
        (
            "snailfish_data_size_bytes",
            "Total bytes of the data file system.",
            g.size_bytes,
        ),
    ] {
        metric(out, name, "gauge", help);
        let _ = writeln!(out, "{name} {v}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_is_exact_at_the_boundary() {
        assert!(at_least(80, 100, 8, 10));
        assert!(!at_least(79, 100, 8, 10));
        assert!(at_least(95, 100, 95, 100));
        assert!(!at_least(94, 100, 95, 100));
        assert!(at_least(u64::MAX, u64::MAX, 1, 2));
    }

    #[test]
    fn unknown_codes_share_one_label() {
        assert_eq!(known(&CODES, "quota"), "quota");
        assert_eq!(known(&CODES, "l_0011"), "other");
    }

    #[test]
    fn tenant_label_is_escaped() {
        let g = Gauges {
            tenant_bytes: BTreeMap::from([("a\"b\\c\nd".to_owned(), 1)]),
            ..Gauges::default()
        };
        assert!(render(&g).contains("tenant=\"a\\\"b\\\\c\\nd\"} 1"));
    }
}
