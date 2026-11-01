//! The JSON bodies of the enrollment session routes (`PROTOCOL.md` 10.10).
//!
//! The relay parses each write strictly and stores the JSON text of the
//! message. It checks the form of each message, not its content: only the
//! two devices can check the transcript (section 11). A reader of a session
//! object ignores unknown fields ([VER-13]), but parses each message with
//! the rules of 10.10, because the other device or the relay wrote it.

use std::collections::BTreeMap;

use serde_json::Value;
use serde_json::value::RawValue;

use crate::encoding::{Hash32, decode_b64_strict, decode_id, encode_b64, encode_id};
use crate::enroll::Role;
use crate::envelope::Envelope;
use crate::records::{Device, Keys, parse_device_json, parse_keys_json};
use crate::wire::{RawEnvelope, WireError};
use crate::write;

fn bad(msg: impl Into<String>) -> WireError {
    WireError(msg.into())
}

/// One message slot of a session, in the order of 10.10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    /// 1: the device object of the new device.
    NewHello,
    /// 2: the keys and the commitment of the trusted device.
    TrustedHello,
    /// 3: the nonce of the new device.
    NewNonce,
    /// 4: the nonce of the trusted device.
    TrustedNonce,
    /// 5: the signed confirmation of the new device.
    NewConfirm,
    /// 6: the checkpoint and the tenant handle.
    TrustedDone,
}

/// The six slots in their order.
pub const SLOTS: [Slot; 6] = [
    Slot::NewHello,
    Slot::TrustedHello,
    Slot::NewNonce,
    Slot::TrustedNonce,
    Slot::NewConfirm,
    Slot::TrustedDone,
];

impl Slot {
    /// The index of the slot in [`SLOTS`], from 0.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::NewHello => 0,
            Self::TrustedHello => 1,
            Self::NewNonce => 2,
            Self::TrustedNonce => 3,
            Self::NewConfirm => 4,
            Self::TrustedDone => 5,
        }
    }

    /// The device that writes the slot.
    #[must_use]
    pub fn writer(self) -> Role {
        match self {
            Self::NewHello | Self::NewNonce | Self::NewConfirm => Role::New,
            Self::TrustedHello | Self::TrustedNonce | Self::TrustedDone => Role::Trusted,
        }
    }

    /// The field name of the slot in a body and in the session object.
    #[must_use]
    pub fn field(self) -> &'static str {
        match self {
            Self::NewHello | Self::TrustedHello => "hello",
            Self::NewNonce | Self::TrustedNonce => "nonce",
            Self::NewConfirm => "confirm",
            Self::TrustedDone => "done",
        }
    }

    fn of(role: Role, field: &str) -> Option<Self> {
        SLOTS
            .into_iter()
            .find(|s| s.writer() == role && s.field() == field)
    }
}

/// True if `slot` is the next empty slot (`PROTOCOL.md` 10.10 write step 7):
/// every slot before it holds a message, and it and each later slot are
/// empty. `filled[i]` tells whether slot `i` of [`SLOTS`] holds a message.
#[must_use]
pub fn is_next(filled: &[bool; 6], slot: Slot) -> bool {
    let i = slot.index();
    filled.iter().enumerate().all(|(j, &f)| f == (j < i))
}

/// One write request (10.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// A message for a slot: the JSON text of its value, as the body held
    /// it. The relay stores and serves this text.
    Message(Slot, String),
    /// `{"cancel":true}`.
    Cancel,
}

fn one_field(body: &[u8]) -> Result<(String, &RawValue), WireError> {
    let m: BTreeMap<String, &RawValue> =
        serde_json::from_slice(body).map_err(|e| bad(format!("enrollment body: {e}")))?;
    let mut it = m.into_iter();
    match (it.next(), it.next()) {
        (Some(one), None) => Ok(one),
        _ => Err(bad("enrollment body: it must hold exactly one field")),
    }
}

fn nonce_text(raw: &RawValue) -> Result<[u8; 32], WireError> {
    let s: String = serde_json::from_str(raw.get()).map_err(|_| bad("nonce is not a string"))?;
    b32(&s, "nonce")
}

fn b32(s: &str, what: &str) -> Result<[u8; 32], WireError> {
    decode_b64_strict(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| bad(format!("{what} is not 32 bytes of standard base64")))
}

fn envelope_text(raw: &RawValue, what: &str) -> Result<RawEnvelope, WireError> {
    Envelope::parse(raw.get().as_bytes())
        .map(|envelope| RawEnvelope {
            envelope,
            json: raw.get().to_owned(),
        })
        .map_err(|e| bad(format!("{what}: {e}")))
}

fn object_of<'a>(
    raw: &'a RawValue,
    what: &str,
) -> Result<BTreeMap<String, &'a RawValue>, WireError> {
    serde_json::from_str(raw.get()).map_err(|_| bad(format!("{what} is not an object")))
}

fn exact<'a>(
    m: &BTreeMap<String, &'a RawValue>,
    what: &str,
    names: &[&str],
) -> Result<Vec<&'a RawValue>, WireError> {
    if m.len() != names.len() || !m.keys().all(|k| names.contains(&k.as_str())) {
        return Err(bad(format!(
            "{what} must hold exactly {}",
            names.join(", ")
        )));
    }
    Ok(names.iter().filter_map(|n| m.get(*n).copied()).collect())
}

fn check_new_hello(raw: &RawValue) -> Result<Device, WireError> {
    let m = object_of(raw, "hello")?;
    let [device] = exact(&m, "hello", &["device"])?[..] else {
        return Err(bad("hello must hold device"));
    };
    parse_device_json(device.get().as_bytes()).map_err(|e| bad(format!("hello.device: {e}")))
}

fn check_trusted_hello(raw: &RawValue) -> Result<(Keys, Hash32), WireError> {
    let m = object_of(raw, "hello")?;
    let [keys, commitment] = exact(&m, "hello", &["keys", "commitment"])?[..] else {
        return Err(bad("hello must hold keys and commitment"));
    };
    let keys =
        parse_keys_json(keys.get().as_bytes()).map_err(|e| bad(format!("hello.keys: {e}")))?;
    let c: String =
        serde_json::from_str(commitment.get()).map_err(|_| bad("commitment is not a string"))?;
    Ok((keys, b32(&c, "commitment")?))
}

fn check_done(raw: &RawValue, tenant: Option<&str>) -> Result<(String, RawEnvelope), WireError> {
    let m = object_of(raw, "done")?;
    let [t, cp] = exact(&m, "done", &["tenant", "checkpoint"])?[..] else {
        return Err(bad("done must hold tenant and checkpoint"));
    };
    let t: String = serde_json::from_str(t.get()).map_err(|_| bad("tenant is not a string"))?;
    decode_id::<16>(&t, "t_").map_err(|e| bad(format!("tenant: {e}")))?;
    if tenant.is_some_and(|want| want != t) {
        return Err(bad("done.tenant is not the tenant of the request path"));
    }
    Ok((t, envelope_text(cp, "done.checkpoint")?))
}

fn check_message(slot: Slot, raw: &RawValue, tenant: Option<&str>) -> Result<(), WireError> {
    match slot {
        Slot::NewHello => check_new_hello(raw).map(|_| ()),
        Slot::TrustedHello => check_trusted_hello(raw).map(|_| ()),
        Slot::NewNonce | Slot::TrustedNonce => nonce_text(raw).map(|_| ()),
        Slot::NewConfirm => envelope_text(raw, "confirm").map(|_| ()),
        Slot::TrustedDone => check_done(raw, tenant).map(|_| ()),
    }
}

/// Parse a write request body of the device in `role` (10.10). `tenant` is
/// the tenant handle of the request path of the trusted route.
///
/// # Errors
///
/// Refuses a body that is not one known field of `role`, and a message
/// that breaks 10.10 (write step 2).
pub fn parse_write(body: &[u8], role: Role, tenant: Option<&str>) -> Result<Write, WireError> {
    let (field, raw) = one_field(body)?;
    if field == "cancel" {
        return if raw.get() == "true" {
            Ok(Write::Cancel)
        } else {
            Err(bad("cancel must be true"))
        };
    }
    let slot = Slot::of(role, &field).ok_or_else(|| {
        bad(format!(
            "enrollment body: `{field}` is not a message of this device"
        ))
    })?;
    check_message(slot, raw, tenant)?;
    Ok(Write::Message(slot, raw.get().to_owned()))
}

/// True if two message texts hold the same JSON value (write step 5). Key
/// order and whitespace do not count.
#[must_use]
pub fn same_message(a: &str, b: &str) -> bool {
    match (
        serde_json::from_str::<Value>(a),
        serde_json::from_str::<Value>(b),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// The body of an open request.
#[must_use]
pub fn open_body(session: &[u8; 16]) -> Vec<u8> {
    format!(r#"{{"session":"{}"}}"#, encode_id("e_", session)).into_bytes()
}

/// Parse an open request body.
///
/// # Errors
///
/// Refuses a body that is not exactly `{"session": <session ID text>}`.
pub fn parse_open(body: &[u8]) -> Result<[u8; 16], WireError> {
    let (field, raw) = one_field(body)?;
    if field != "session" {
        return Err(bad("open body: it must hold only session"));
    }
    let s: String = serde_json::from_str(raw.get()).map_err(|_| bad("session is not a string"))?;
    decode_id::<16>(&s, "e_").map_err(|e| bad(format!("session: {e}")))
}

/// The body of an open response.
#[must_use]
pub fn opened_body(expires: u64) -> Vec<u8> {
    format!(r#"{{"expires":{expires}}}"#).into_bytes()
}

/// Parse an open response.
///
/// # Errors
///
/// Refuses a body without an integer `expires`.
pub fn parse_opened(body: &[u8]) -> Result<u64, WireError> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("expires").and_then(Value::as_u64))
        .ok_or_else(|| bad("expires is not an integer"))
}

/// The state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The session takes messages.
    Open,
    /// The trusted device wrote `done`.
    Done,
    /// A device cancelled the session.
    Cancelled,
}

impl State {
    /// The text form of the session object.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The session object of a read or write response. `messages[i]` is the
/// stored text of slot `i` of [`SLOTS`].
#[must_use]
pub fn session_body(
    session: &[u8; 16],
    expires: u64,
    state: State,
    messages: &[Option<String>; 6],
) -> Vec<u8> {
    let side = |role: Role| {
        let items: Vec<String> = SLOTS
            .iter()
            .zip(messages)
            .filter(|(s, _)| s.writer() == role)
            .filter_map(|(s, m)| m.as_ref().map(|m| format!(r#""{}":{m}"#, s.field())))
            .collect();
        format!("{{{}}}", items.join(","))
    };
    format!(
        r#"{{"session":"{}","expires":{expires},"state":"{}","new":{},"trusted":{}}}"#,
        encode_id("e_", session),
        state.text(),
        side(Role::New),
        side(Role::Trusted)
    )
    .into_bytes()
}

/// A session object that a device read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The relay time at which the session ends.
    pub expires: u64,
    /// The state.
    pub state: State,
    /// Slot 1.
    pub new_hello: Option<Device>,
    /// Slot 2: the keys and the commitment.
    pub trusted_hello: Option<(Keys, Hash32)>,
    /// Slot 3.
    pub new_nonce: Option<[u8; 32]>,
    /// Slot 4.
    pub trusted_nonce: Option<[u8; 32]>,
    /// Slot 5.
    pub new_confirm: Option<RawEnvelope>,
    /// Slot 6: the tenant handle and the checkpoint.
    pub trusted_done: Option<(String, RawEnvelope)>,
}

fn side_map<'a>(
    m: &BTreeMap<String, &'a RawValue>,
    name: &str,
) -> Result<BTreeMap<String, &'a RawValue>, WireError> {
    m.get(name)
        .map_or_else(|| Ok(BTreeMap::new()), |raw| object_of(raw, name))
}

/// Parse a session object. Unknown fields are ignored ([VER-13]). Each
/// message must follow 10.10.
///
/// # Errors
///
/// Refuses a body without `expires` and a known `state`, and a message
/// that breaks 10.10.
pub fn parse_session(body: &[u8]) -> Result<Session, WireError> {
    let m: BTreeMap<String, &RawValue> =
        serde_json::from_slice(body).map_err(|e| bad(format!("session object: {e}")))?;
    let expires = m
        .get("expires")
        .and_then(|r| serde_json::from_str::<u64>(r.get()).ok())
        .ok_or_else(|| bad("expires is not an integer"))?;
    let state = match m
        .get("state")
        .and_then(|r| serde_json::from_str::<String>(r.get()).ok())
        .as_deref()
    {
        Some("open") => State::Open,
        Some("done") => State::Done,
        Some("cancelled") => State::Cancelled,
        _ => return Err(bad("state is not open, done or cancelled")),
    };
    let new = side_map(&m, "new")?;
    let trusted = side_map(&m, "trusted")?;
    Ok(Session {
        expires,
        state,
        new_hello: new.get("hello").map(|r| check_new_hello(r)).transpose()?,
        trusted_hello: trusted
            .get("hello")
            .map(|r| check_trusted_hello(r))
            .transpose()?,
        new_nonce: new.get("nonce").map(|r| nonce_text(r)).transpose()?,
        trusted_nonce: trusted.get("nonce").map(|r| nonce_text(r)).transpose()?,
        new_confirm: new
            .get("confirm")
            .map(|r| envelope_text(r, "confirm"))
            .transpose()?,
        trusted_done: trusted
            .get("done")
            .map(|r| check_done(r, None))
            .transpose()?,
    })
}

/// The write body of slot 1.
#[must_use]
pub fn new_hello_body(d: &Device) -> Vec<u8> {
    format!(r#"{{"hello":{{"device":{}}}}}"#, write::device(d)).into_bytes()
}

/// The write body of slot 2.
#[must_use]
pub fn trusted_hello_body(keys: &Keys, commitment: &Hash32) -> Vec<u8> {
    format!(
        r#"{{"hello":{{"keys":{},"commitment":"{}"}}}}"#,
        write::keys_object(keys),
        encode_b64(commitment)
    )
    .into_bytes()
}

/// The write body of slot 3 or 4.
#[must_use]
pub fn nonce_body(nonce: &[u8; 32]) -> Vec<u8> {
    format!(r#"{{"nonce":"{}"}}"#, encode_b64(nonce)).into_bytes()
}

/// The write body of slot 5. `envelope` is the envelope JSON text.
#[must_use]
pub fn confirm_body(envelope: &str) -> Vec<u8> {
    format!(r#"{{"confirm":{envelope}}}"#).into_bytes()
}

/// The write body of slot 6. `checkpoint` is the envelope JSON text.
#[must_use]
pub fn done_body(tenant: &str, checkpoint: &str) -> Vec<u8> {
    format!(
        r#"{{"done":{{"tenant":{},"checkpoint":{checkpoint}}}}}"#,
        Value::String(tenant.to_owned())
    )
    .into_bytes()
}

/// The cancel body.
#[must_use]
pub fn cancel_body() -> Vec<u8> {
    b"{\"cancel\":true}".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{device_id, seal_public};
    use crate::sig::SecretKey;
    use proptest::prelude::*;

    fn device(seed: u8) -> Device {
        let sign = SecretKey::from_seed(&[seed; 32]).public();
        let seal = Box::new(seal_public(&[seed; 32]));
        Device {
            id: device_id(&sign, &seal),
            keys: Keys { sign, seal },
            name: "Phone".into(),
            level: 1,
        }
    }

    const TENANT: &str = "t_00112233445566778899aabbccddeeff";

    fn envelope() -> String {
        let k = SecretKey::from_seed(&[9; 32]);
        let p = br#"{"x":1}"#;
        crate::envelope::write_json(
            "snailfish.checkpoint.v1",
            p,
            &k.sign_record("snailfish.checkpoint.v1", p),
            "d_x",
        )
    }

    /// Each writer body parses back to its slot on the route of its writer,
    /// and the stored text is the message value.
    #[test]
    fn bodies_parse_to_their_slots() {
        let d = device(1);
        let env = envelope();
        let cases: [(Vec<u8>, Role, Slot); 6] = [
            (new_hello_body(&d), Role::New, Slot::NewHello),
            (
                trusted_hello_body(&d.keys, &[3; 32]),
                Role::Trusted,
                Slot::TrustedHello,
            ),
            (nonce_body(&[4; 32]), Role::New, Slot::NewNonce),
            (nonce_body(&[5; 32]), Role::Trusted, Slot::TrustedNonce),
            (confirm_body(&env), Role::New, Slot::NewConfirm),
            (done_body(TENANT, &env), Role::Trusted, Slot::TrustedDone),
        ];
        let mut stored: [Option<String>; 6] = Default::default();
        for (body, role, slot) in cases {
            let Write::Message(s, text) = parse_write(&body, role, Some(TENANT)).unwrap() else {
                panic!("not a message");
            };
            assert_eq!(s, slot);
            stored[slot.index()] = Some(text);
        }
        let read = parse_session(&session_body(&[1; 16], 600, State::Done, &stored)).unwrap();
        assert_eq!(read.state, State::Done);
        assert_eq!(read.new_hello, Some(d.clone()));
        assert_eq!(read.trusted_hello, Some((d.keys.clone(), [3; 32])));
        assert_eq!(
            (read.new_nonce, read.trusted_nonce),
            (Some([4; 32]), Some([5; 32]))
        );
        assert_eq!(read.new_confirm.map(|e| e.json), Some(env.clone()));
        assert_eq!(
            read.trusted_done.map(|(t, e)| (t, e.json)),
            Some((TENANT.into(), env))
        );
    }

    /// 10.10: the new-device route takes no `done` and the trusted route no
    /// `confirm`, so an unsigned caller cannot write the last message of
    /// the trusted device. `done` must name the tenant of the path.
    #[test]
    fn each_route_takes_only_its_own_messages() {
        let env = envelope();
        assert!(parse_write(&done_body(TENANT, &env), Role::New, None).is_err());
        assert!(parse_write(&confirm_body(&env), Role::Trusted, Some(TENANT)).is_err());
        assert!(parse_write(&new_hello_body(&device(1)), Role::Trusted, Some(TENANT)).is_err());
        let other = "t_ffeeddccbbaa99887766554433221100";
        assert!(parse_write(&done_body(other, &env), Role::Trusted, Some(TENANT)).is_err());
        assert_eq!(
            parse_write(&cancel_body(), Role::New, None),
            Ok(Write::Cancel)
        );
        assert!(parse_write(br#"{"cancel":false}"#, Role::New, None).is_err());
        assert!(parse_write(br#"{"nonce":"AAAA","cancel":true}"#, Role::New, None).is_err());
        assert!(parse_write(br#"{"extra":1}"#, Role::New, None).is_err());
        let mut d = device(1);
        d.id = device(2).id;
        assert!(
            parse_write(&new_hello_body(&d), Role::New, None).is_err(),
            "id must match the keys"
        );
    }

    #[test]
    fn open_round_trip_and_refusals() {
        assert_eq!(parse_open(&open_body(&[7; 16])), Ok([7; 16]));
        assert!(parse_open(br#"{"session":"e_00","x":1}"#).is_err());
        assert!(parse_open(br#"{"session":"00112233445566778899aabbccddeeff"}"#).is_err());
        assert_eq!(parse_opened(&opened_body(1_767_226_200)), Ok(1_767_226_200));
    }

    /// Write step 5: an exact retry is the same JSON value, also with
    /// another key order or whitespace. Another value is not.
    #[test]
    fn same_message_ignores_layout_only() {
        assert!(same_message(
            r#"{"a":1,"b":"x"}"#,
            r#"{ "b" : "x", "a" : 1 }"#
        ));
        assert!(!same_message(r#"{"a":1}"#, r#"{"a":2}"#));
        assert!(!same_message("not json", "not json"));
    }

    proptest! {
        /// Write step 7: exactly the first empty slot is next, and only if
        /// every later slot is empty.
        #[test]
        fn is_next_is_the_first_empty_slot(bits in 0u8..64) {
            let filled: [bool; 6] = std::array::from_fn(|i| bits & (1 << i) != 0);
            let prefix = filled.iter().take_while(|f| **f).count();
            let valid = filled.iter().skip(prefix).all(|f| !*f);
            for s in SLOTS {
                prop_assert_eq!(is_next(&filled, s), valid && s.index() == prefix);
            }
        }

        #[test]
        fn parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse_write(&bytes, Role::New, None);
            let _ = parse_write(&bytes, Role::Trusted, Some(TENANT));
            let _ = parse_open(&bytes);
            let _ = parse_session(&bytes);
        }
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// The body parsers use serde_json, which CBMC cannot finish, so the
/// property tests and the fuzz targets cover them. The harness proves the
/// slot order of 10.10 for every fill state.
#[cfg(kani)]
mod proofs {
    use super::{SLOTS, is_next};

    /// `PROTOCOL.md` 10.10 write step 7 ([ENR-1] to [ENR-8]): at most one
    /// slot is next, a slot is next only when each earlier slot holds a
    /// message and it and each later slot are empty, and the slots
    /// alternate between the two writers.
    #[kani::proof]
    #[kani::unwind(8)]
    fn slot_order_is_strict() {
        let filled: [bool; 6] = kani::any();
        let mut count = 0u8;
        for s in SLOTS {
            if is_next(&filled, s) {
                count += 1;
                let i = s.index();
                for (j, f) in filled.iter().enumerate() {
                    assert!(*f == (j < i));
                }
            }
        }
        assert!(count <= 1);
        for w in SLOTS.windows(2) {
            assert!(w[0].writer() != w[1].writer());
            assert!(w[0].index() + 1 == w[1].index());
        }
    }
}
