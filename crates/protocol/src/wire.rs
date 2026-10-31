//! The JSON bodies of the HTTP API (`PROTOCOL.md` section 10).
//!
//! The bodies are unsigned. A reader ignores unknown fields ([VER-13]). Each
//! envelope inside a body goes through the strict envelope reader of
//! section 4, so a body cannot carry an envelope that the log refuses.

use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

use crate::encoding::{Hash32, decode_b64_strict, encode_b64};
use crate::envelope::Envelope;

/// The limits of `GET /v1/info` (`PROTOCOL.md` 10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest request body.
    pub max_request_bytes: u64,
    /// The largest decoded payload of a change record.
    pub max_change_bytes: u64,
    /// The largest decoded payload of a snapshot record.
    pub max_snapshot_bytes: u64,
    /// The most envelopes in one append request.
    pub max_append_envelopes: u64,
    /// The most entries in one fetch response.
    pub max_fetch_entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: 4 * 1024 * 1024,
            max_change_bytes: 64 * 1024,
            max_snapshot_bytes: 16 * 1024 * 1024,
            max_append_envelopes: 100,
            max_fetch_entries: 500,
        }
    }
}

/// A body that breaks section 10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub String);

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

fn bad(msg: impl Into<String>) -> WireError {
    WireError(msg.into())
}

/// One envelope of a request body: the parsed envelope and the exact JSON
/// text, which the relay stores and serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEnvelope {
    /// The parsed envelope.
    pub envelope: Envelope,
    /// The JSON object text as the body held it.
    pub json: String,
}

/// One item of an append request. An envelope that breaks section 4 is
/// still an item, so it gets its own `refused` result (10.6 step 1).
pub type AppendItem = Result<RawEnvelope, String>;

fn raw_envelope(raw: &RawValue) -> AppendItem {
    let text = raw.get();
    Envelope::parse(text.as_bytes())
        .map(|envelope| RawEnvelope {
            envelope,
            json: text.to_owned(),
        })
        .map_err(|e| e.to_string())
}

fn object(body: &[u8]) -> Result<Map<String, Value>, WireError> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(bad("the body is not a JSON object")),
        Err(e) => Err(bad(format!("the body is not JSON: {e}"))),
    }
}

#[derive(serde::Deserialize)]
struct AppendBody<'a> {
    #[serde(borrow)]
    envelopes: Vec<&'a RawValue>,
}

#[derive(serde::Deserialize)]
struct GenesisBody<'a> {
    #[serde(borrow)]
    genesis: &'a RawValue,
}

/// Parse an append request body (`PROTOCOL.md` 10.6).
///
/// # Errors
///
/// Refuses a body that is not an object with an `envelopes` list of 1 to
/// `max` items.
pub fn parse_append(body: &[u8], max: u64) -> Result<Vec<AppendItem>, WireError> {
    let parsed: AppendBody<'_> =
        serde_json::from_slice(body).map_err(|e| bad(format!("append body: {e}")))?;
    let n = parsed.envelopes.len() as u64;
    if n == 0 || n > max {
        return Err(bad(format!(
            "append body: envelopes must hold 1 to {max} items"
        )));
    }
    Ok(parsed.envelopes.into_iter().map(raw_envelope).collect())
}

/// The body of an append request.
#[must_use]
pub fn append_body(envelopes: &[String]) -> Vec<u8> {
    format!("{{\"envelopes\":[{}]}}", envelopes.join(",")).into_bytes()
}

/// Parse the body of `PUT /v1/t/{tenant}/s/{log}` (`PROTOCOL.md` 10.5).
///
/// # Errors
///
/// Refuses a body without a valid `genesis` envelope.
pub fn parse_genesis(body: &[u8]) -> Result<RawEnvelope, WireError> {
    let parsed: GenesisBody<'_> =
        serde_json::from_slice(body).map_err(|e| bad(format!("genesis body: {e}")))?;
    raw_envelope(parsed.genesis).map_err(WireError)
}

/// The body of a create request.
#[must_use]
pub fn genesis_body(envelope: &str) -> Vec<u8> {
    format!("{{\"genesis\":{envelope}}}").into_bytes()
}

/// A position and its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// The position.
    pub position: u64,
    /// The log digest at the position.
    pub digest: Hash32,
}

fn head_json(h: &Head) -> Value {
    json!({"position": h.position, "digest": encode_b64(&h.digest)})
}

/// The result of one envelope of an append request (`PROTOCOL.md` 10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendResult {
    /// Stored at the position.
    Stored(u64),
    /// An exact retry of the change at the position ([WIR-6]).
    Known(u64),
    /// The same `change_id` with another record hash ([WIR-6]).
    Conflict(u64),
    /// Refused with the code.
    Refused(String),
}

/// The body of an append response.
#[must_use]
pub fn append_response(results: &[AppendResult], head: &Head) -> Vec<u8> {
    let rs: Vec<Value> = results
        .iter()
        .map(|r| match r {
            AppendResult::Stored(p) => json!({"status": "stored", "position": p}),
            AppendResult::Known(p) => json!({"status": "known", "position": p}),
            AppendResult::Conflict(p) => json!({"status": "conflict", "position": p}),
            AppendResult::Refused(c) => json!({"status": "refused", "error": c}),
        })
        .collect();
    json!({"results": rs, "head": head_json(head)})
        .to_string()
        .into_bytes()
}

fn read_head(v: Option<&Value>) -> Result<Head, WireError> {
    let v = v.ok_or_else(|| bad("head is missing"))?;
    let position = v
        .get("position")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("head.position is not an integer"))?;
    let digest = v
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|s| decode_b64_strict(s).ok())
        .and_then(|b| <Hash32>::try_from(b).ok())
        .ok_or_else(|| bad("head.digest is not 32 bytes of base64"))?;
    Ok(Head { position, digest })
}

fn position_of(v: &Value) -> Result<u64, WireError> {
    v.get("position")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("result.position is not an integer"))
}

/// Parse an append response. Unknown fields are ignored ([VER-13]).
///
/// # Errors
///
/// Refuses a body that is not in the form of 10.6.
pub fn parse_append_response(body: &[u8]) -> Result<(Vec<AppendResult>, Head), WireError> {
    let m = object(body)?;
    let results = m
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("results is not a list"))?
        .iter()
        .map(|r| match r.get("status").and_then(Value::as_str) {
            Some("stored") => position_of(r).map(AppendResult::Stored),
            Some("known") => position_of(r).map(AppendResult::Known),
            Some("conflict") => position_of(r).map(AppendResult::Conflict),
            Some("refused") => r
                .get("error")
                .and_then(Value::as_str)
                .map(|c| AppendResult::Refused(c.to_owned()))
                .ok_or_else(|| bad("result.error is not a string")),
            _ => Err(bad("result.status is unknown")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((results, read_head(m.get("head"))?))
}

/// The body of `PUT /v1/t/{tenant}/s/{log}` on success.
#[must_use]
pub fn head_body(h: &Head) -> Vec<u8> {
    head_json(h).to_string().into_bytes()
}

/// Parse the body of a create response.
///
/// # Errors
///
/// Refuses a body that is not a position object.
pub fn parse_head_body(body: &[u8]) -> Result<Head, WireError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
    read_head(Some(&v))
}

/// A stub of a fetch entry ([CMP-1]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stub {
    /// The payload type.
    pub payload_type: String,
    /// The change ID text of a change.
    pub change_id: Option<String>,
    /// The record hash.
    pub hash: Hash32,
}

/// One entry of a fetch response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchEntry {
    /// The full envelope.
    Envelope(RawEnvelope),
    /// A stub. The M2 relay sends none.
    Stub(Stub),
}

/// A fetch response (`PROTOCOL.md` 10.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The entries, from position `after + 1`.
    pub entries: Vec<(u64, FetchEntry)>,
    /// The relay head.
    pub head: Head,
    /// More entries follow.
    pub has_more: bool,
}

/// The body of a fetch response. Each envelope is the stored JSON text.
///
/// # Errors
///
/// Refuses a stored text that is not JSON.
pub fn fetch_response(
    entries: &[(u64, String)],
    head: &Head,
    has_more: bool,
) -> Result<Vec<u8>, WireError> {
    let mut parts = Vec::with_capacity(entries.len());
    for (pos, env) in entries {
        // The stored text came from a parsed envelope, so it is JSON. Check
        // it, so that a damaged row cannot break the response syntax.
        serde_json::from_str::<&RawValue>(env).map_err(|e| bad(e.to_string()))?;
        parts.push(format!("{{\"position\":{pos},\"envelope\":{env}}}"));
    }
    let out = format!(
        "{{\"entries\":[{}],\"head\":{},\"has_more\":{has_more}}}",
        parts.join(","),
        head_json(head)
    );
    Ok(out.into_bytes())
}

#[derive(serde::Deserialize)]
struct FetchBody<'a> {
    #[serde(borrow)]
    entries: Vec<FetchItem<'a>>,
    head: Value,
    has_more: bool,
}

#[derive(serde::Deserialize)]
struct FetchItem<'a> {
    position: u64,
    #[serde(borrow, default)]
    envelope: Option<&'a RawValue>,
    #[serde(default)]
    stub: Option<Value>,
}

fn stub(v: &Value) -> Result<Stub, WireError> {
    let payload_type = v
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("stub.type is not a string"))?
        .to_owned();
    let change_id = match v.get("change_id") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(bad("stub.change_id is not a string")),
    };
    let hash = v
        .get("hash")
        .and_then(Value::as_str)
        .and_then(|s| decode_b64_strict(s).ok())
        .and_then(|b| <Hash32>::try_from(b).ok())
        .ok_or_else(|| bad("stub.hash is not 32 bytes of base64"))?;
    Ok(Stub {
        payload_type,
        change_id,
        hash,
    })
}

/// Parse a fetch response. Unknown fields are ignored ([VER-13]). Each
/// envelope goes through the reader of section 4.
///
/// # Errors
///
/// Refuses a body that is not in the form of 10.7, an entry with both or
/// neither of `envelope` and `stub`, and an envelope that breaks section 4.
pub fn parse_fetch(body: &[u8]) -> Result<Fetch, WireError> {
    let parsed: FetchBody<'_> =
        serde_json::from_slice(body).map_err(|e| bad(format!("fetch body: {e}")))?;
    let mut entries = Vec::with_capacity(parsed.entries.len());
    for item in parsed.entries {
        let entry = match (item.envelope, item.stub) {
            (Some(raw), None) => FetchEntry::Envelope(raw_envelope(raw).map_err(WireError)?),
            (None, Some(s)) => FetchEntry::Stub(stub(&s)?),
            _ => return Err(bad("an entry must hold one of envelope and stub")),
        };
        entries.push((item.position, entry));
    }
    Ok(Fetch {
        entries,
        head: read_head(Some(&parsed.head))?,
        has_more: parsed.has_more,
    })
}

/// The body of `GET /v1/info` (`PROTOCOL.md` 10.4).
#[must_use]
pub fn info_body(levels: &[u64], limits: &Limits, time: u64) -> Vec<u8> {
    json!({
        "levels": levels,
        "limits": {
            "max_request_bytes": limits.max_request_bytes,
            "max_change_bytes": limits.max_change_bytes,
            "max_snapshot_bytes": limits.max_snapshot_bytes,
            "max_append_envelopes": limits.max_append_envelopes,
            "max_fetch_entries": limits.max_fetch_entries,
        },
        "time": time,
    })
    .to_string()
    .into_bytes()
}

/// The info of `GET /v1/info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// The protocol levels of the relay.
    pub levels: Vec<u64>,
    /// The limits.
    pub limits: Limits,
}

/// The `levels` list of a `GET /v1/info` body ([VER-11]).
///
/// # Errors
///
/// Refuses a body without a `levels` list of integers.
pub fn parse_levels(body: &[u8]) -> Result<Vec<u64>, WireError> {
    object(body)?
        .get("levels")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("levels is not a list"))?
        .iter()
        .map(|v| v.as_u64().ok_or_else(|| bad("a level is not an integer")))
        .collect()
}

/// Parse a `GET /v1/info` body. Unknown fields are ignored ([VER-13]).
///
/// # Errors
///
/// Refuses a body without a `levels` list of integers or without the
/// limits.
pub fn parse_info(body: &[u8]) -> Result<Info, WireError> {
    let levels = parse_levels(body)?;
    let m = object(body)?;
    let l = m.get("limits").ok_or_else(|| bad("limits is missing"))?;
    let get = |name: &str| {
        l.get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| bad(format!("limits.{name} is not an integer")))
    };
    Ok(Info {
        levels,
        limits: Limits {
            max_request_bytes: get("max_request_bytes")?,
            max_change_bytes: get("max_change_bytes")?,
            max_snapshot_bytes: get("max_snapshot_bytes")?,
            max_append_envelopes: get("max_append_envelopes")?,
            max_fetch_entries: get("max_fetch_entries")?,
        },
    })
}

/// The body of an error response (`PROTOCOL.md` 10.3).
#[must_use]
pub fn error_body(code: &str, message: &str) -> Vec<u8> {
    json!({"error": code, "message": message})
        .to_string()
        .into_bytes()
}

/// The `error` code of an error response, or `None` for a body that is not
/// in the form of 10.3, for example a page from a proxy.
#[must_use]
pub fn parse_error(body: &[u8]) -> Option<String> {
    let m = object(body).ok()?;
    m.get("error").and_then(Value::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The relay puts the text of a `WireError` in an error response. Without
    /// this, the client would get an empty message.
    #[test]
    fn wire_error_displays_its_text() {
        assert_eq!(bad("genesis body: x").to_string(), "genesis body: x");
    }

    fn env_json() -> String {
        Envelope {
            payload_type: "snailfish.change.v1".into(),
            payload: b"{}".to_vec(),
            sig: [5; 64],
        }
        .to_json("d_x")
    }

    #[test]
    fn append_items_keep_the_exact_text_and_refuse_one_bad_envelope() {
        let e = env_json();
        let spaced = e.replace(',', " , ");
        let body = format!(r#"{{"envelopes":[{e},{spaced},{{"payloadType":1}}],"future":true}}"#);
        let items = parse_append(body.as_bytes(), 8).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_ref().unwrap().json, e);
        assert_eq!(items[1].as_ref().unwrap().json, spaced);
        assert_eq!(
            items[0].as_ref().unwrap().envelope,
            items[1].as_ref().unwrap().envelope
        );
        assert!(items[2].is_err());
        assert!(parse_append(br#"{"envelopes":[]}"#, 8).is_err());
        let three = append_body(&[e.clone(), e.clone(), e.clone()]);
        assert!(parse_append(&three, 2).is_err());
        assert_eq!(parse_append(&three, 3).unwrap().len(), 3);
        assert!(parse_append(b"[]", 8).is_err());
    }

    #[test]
    fn append_response_round_trip() {
        let h = Head {
            position: 7,
            digest: [4; 32],
        };
        let rs = vec![
            AppendResult::Stored(7),
            AppendResult::Known(3),
            AppendResult::Conflict(4),
            AppendResult::Refused("bad_base".into()),
        ];
        let body = append_response(&rs, &h);
        assert_eq!(parse_append_response(&body).unwrap(), (rs, h));
        assert!(parse_append_response(br#"{"results":[{"status":"x"}],"head":{}}"#).is_err());
    }

    #[test]
    fn fetch_round_trip_and_entry_forms() {
        let e = env_json();
        let h = Head {
            position: 2,
            digest: [1; 32],
        };
        let body = fetch_response(&[(1, e.clone()), (2, e.clone())], &h, true).unwrap();
        let f = parse_fetch(&body).unwrap();
        assert_eq!(f.head, h);
        assert!(f.has_more);
        assert_eq!(f.entries.len(), 2);
        assert!(matches!(&f.entries[1], (2, FetchEntry::Envelope(r)) if r.json == e));
        assert!(fetch_response(&[(1, "{".into())], &h, false).is_err());

        let stub = format!(
            r#"{{"entries":[{{"position":1,"stub":{{"type":"snailfish.change.v1","change_id":"c_00","hash":"{}"}}}}],"head":{{"position":1,"digest":"{}"}},"has_more":false}}"#,
            encode_b64(&[2; 32]),
            encode_b64(&[1; 32])
        );
        let f = parse_fetch(stub.as_bytes()).unwrap();
        assert!(
            matches!(&f.entries[0].1, FetchEntry::Stub(s) if s.hash == [2; 32] && s.change_id.as_deref() == Some("c_00"))
        );
        let both = stub.replace(r#""stub""#, &format!(r#""envelope":{e},"stub""#));
        assert!(parse_fetch(both.as_bytes()).is_err());
    }

    #[test]
    fn info_and_error_bodies() {
        let l = Limits::default();
        let info = parse_info(&info_body(&[1], &l, 9)).unwrap();
        assert_eq!(
            info,
            Info {
                levels: vec![1],
                limits: l
            }
        );
        assert!(parse_info(br#"{"levels":[1]}"#).is_err());
        assert!(parse_info(br#"{"levels":"1","limits":{}}"#).is_err());
        assert_eq!(parse_levels(br#"{"levels":[0,2]}"#), Ok(vec![0, 2]));
        assert!(parse_levels(br#"{"levels":[-1]}"#).is_err());
        assert_eq!(
            parse_error(&error_body("expired", "x")).as_deref(),
            Some("expired")
        );
        assert_eq!(parse_error(b"<html>"), None);
        assert_eq!(parse_error(br#"{"error":1}"#), None);
        let h = Head {
            position: 1,
            digest: [8; 32],
        };
        assert_eq!(parse_head_body(&head_body(&h)).unwrap(), h);
    }

    proptest! {
        /// The body readers never panic on any bytes.
        #[test]
        fn readers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_append(&bytes, 8);
            let _ = parse_genesis(&bytes);
            let _ = parse_fetch(&bytes);
            let _ = parse_append_response(&bytes);
            let _ = parse_info(&bytes);
            let _ = parse_error(&bytes);
        }
    }
}

// No Kani harness: every function here runs serde_json on a byte slice, and
// CBMC cannot finish a symbolic input through it (see `envelope.rs`). The
// fuzz target `wire` and the property tests cover the readers.
