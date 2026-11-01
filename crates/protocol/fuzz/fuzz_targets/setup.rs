//! Fuzz the readers of the user and setup surface (`PROTOCOL.md` 10.11 and
//! 12): the token request, the device status, the authorization query, the
//! redirect query, the webhook URL and the form reader.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::setup;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = setup::parse_token_request(data) {
        assert_eq!(
            setup::parse_token_request(&setup::token_request_body(&r)),
            Ok(r)
        );
    }
    if let Ok(s) = setup::parse_device_status(data) {
        assert_eq!(
            setup::parse_device_status(&setup::device_status_body(&s)),
            Ok(s)
        );
    }
    let _ = setup::parse_token_response(data);
    let _ = setup::parse_form(data, &setup::AUTHORIZE_FIELDS);
    if setup::redirect_uri_ok(data) {
        assert!(!data.contains(&b'?') && !data.contains(&b'#'));
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(a) = setup::parse_authorize_query(text) {
            assert_eq!(
                setup::parse_authorize_query(&setup::authorize_query(&a)),
                Ok(a)
            );
        }
        let _ = setup::parse_redirect_query(text);
        if let Ok(u) = setup::parse_webhook_url(text) {
            assert!(u.target.starts_with('/') && u.port >= 1);
        }
    }
});
