//! The operator metrics (DESIGN.md "Monitoring and alerting" signals 2 to
//! 4) through the real relay core and its data directory.
#![cfg(test)]

mod common;

use common::{Fx, error_code};
use snailfish_protocol::encoding::encode_b64;
use snailfish_protocol::wire::AppendResult;

fn value(text: &str, series: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(series).and_then(|r| r.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("no series {series} in\n{text}"))
        .parse()
        .unwrap()
}

/// Signals 3 and 5: a space at its quota shows in the 80% and 95% gauges,
/// and a quota refusal counts. The page names the internal tenant ID, not
/// the user name, the tenant handle or the log ID. Without this, the quota alert of the rules file
/// could never fire.
#[test]
fn full_space_shows_in_the_quota_gauges_without_identifiers() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    let before = fx.relay.metrics_text().unwrap();
    assert_eq!(
        value(&before, "snailfish_spaces_above_quota{ratio=\"0.95\"}"),
        0
    );
    let used = fx.usage(fx.tenant());
    // A quota that the next change fills to 100%.
    let mut head = fx.head(fx.tenant());
    let change = fx.change_on(
        "A",
        head.position,
        &encode_b64(&head.digest),
        [7; 16],
        40,
        1,
    );
    let quota = used + change.len() as u64;
    fx.reopen_with(|c| c.quotas.space_bytes = quota);
    let (_, r, h) = fx.append(fx.tenant(), "A", &[change]);
    assert!(matches!(r[0], AppendResult::Stored(_)), "{r:?}");
    head = h;
    let refused = fx.change_on(
        "A",
        head.position,
        &encode_b64(&head.digest),
        [8; 16],
        40,
        1,
    );
    let (_, r, _) = fx.append(fx.tenant(), "A", &[refused]);
    assert_eq!(r, vec![AppendResult::Refused("quota".into())]);
    let text = fx.relay.metrics_text().unwrap();
    assert_eq!(
        value(&text, "snailfish_spaces_above_quota{ratio=\"0.8\"}"),
        1
    );
    assert_eq!(
        value(&text, "snailfish_spaces_above_quota{ratio=\"0.95\"}"),
        1
    );
    assert_eq!(
        value(&text, "snailfish_spaces_above_reserve{ratio=\"0.5\"}"),
        0
    );
    assert!(value(&text, "snailfish_append_refusals_total{reason=\"quota\"}") >= 1);
    let tenant_id = fx
        .tenant_db(fx.tenant())
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        value(
            &text,
            &format!("snailfish_tenant_stored_bytes{{tenant=\"{tenant_id}\"}}")
        ) > 0
    );
    assert!(!text.contains("sam"), "a user name leaks");
    // The value is the bytes on disk of the tenant directory, with the
    // space file in its `spaces` subdirectory.
    let tdir = fx.tenant_db(fx.tenant()).parent().unwrap().to_owned();
    let floor = std::fs::metadata(fx.tenant_db(fx.tenant())).unwrap().len()
        + std::fs::metadata(fx.space_file(fx.tenant())).unwrap().len();
    let got = value(
        &text,
        &format!("snailfish_tenant_stored_bytes{{tenant=\"{tenant_id}\"}}"),
    );
    assert!(got >= floor, "{got} < {floor} in {}", tdir.display());
    assert!(text.contains("# TYPE snailfish_space_stubs_max gauge\n"));
    assert!(text.contains("# TYPE snailfish_requests_total counter\n"));
    assert_eq!(
        fx.relay.users().unwrap(),
        vec![("sam".to_owned(), tenant_id)]
    );
    assert!(value(&text, "snailfish_data_size_bytes") > 0);
    assert!(!text.contains(fx.tenant()), "the tenant handle leaks");
    assert!(!text.contains(fx.log()), "the log ID leaks");
    assert!(!text.contains(&fx.key("A").2), "a device ID leaks");
}

/// Signal 2: error responses count by their code.
#[test]
fn error_responses_count_by_code() {
    let fx = Fx::new();
    let r = fx.fetch(fx.tenant(), 0, 10);
    assert_eq!(error_code(&r), "unknown_space");
    let text = fx.relay.metrics_text().unwrap();
    assert!(
        value(
            &text,
            "snailfish_request_errors_total{code=\"unknown_space\"}"
        ) >= 1
    );
}
