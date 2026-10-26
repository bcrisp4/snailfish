//! Fuzz the request signature header readers (`PROTOCOL.md` section 8).
//! Input: header lines `name: value`, separated by LF, then a NUL byte and
//! the body.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::request::{self, Target};

fuzz_target!(|data: &[u8]| {
    let (head, body) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let Ok(head) = std::str::from_utf8(head) else {
        return;
    };
    let headers: Vec<(&str, &str)> = head
        .split('\n')
        .filter_map(|l| l.split_once(": "))
        .collect();
    for (_, v) in &headers {
        // An accepted parameters line has a valid lifetime and writes back
        // to the same bytes, so the signature base cannot differ from it.
        if let Ok((p, line)) = request::parse_signature_input(v) {
            assert!(request::lifetime_ok(p.created, p.expires));
            assert_eq!(request::params_line(&p), line);
        }
        let _ = request::parse_signature(v);
        let _ = request::parse_time(v);
    }
    let t = Target {
        method: "POST",
        authority: "sync.example.net",
        path: "/v1/x",
        query: "",
    };
    // Any key: the check must never panic, and must refuse each request
    // whose key is unknown.
    let r = request::check(&headers, &t, body, 1_767_225_600, |_| None);
    assert!(r.is_err());
});
