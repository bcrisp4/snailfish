//! DSSE v1 envelope JSON (`PROTOCOL.md` section 4).

use crate::encoding::{EncodingError, Hash32, decode_b64_loose, encode_b64};
use crate::hash::record_hash;
use crate::strict::{self, StrictError, Value};

/// One signed record or statement, as the envelope carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The payload type, for example `snailfish.change.v1`.
    pub payload_type: String,
    /// The exact payload bytes. Nothing re-encodes them ([WIR-3]).
    pub payload: Vec<u8>,
    /// The one Ed25519 signature ([LOG-2]).
    pub sig: [u8; 64],
}

/// An envelope that breaks `PROTOCOL.md` section 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeError(pub String);

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EnvelopeError {}

impl From<StrictError> for EnvelopeError {
    fn from(e: StrictError) -> Self {
        Self(format!("envelope JSON: {e}"))
    }
}

impl From<EncodingError> for EnvelopeError {
    fn from(e: EncodingError) -> Self {
        Self(e.to_string())
    }
}

impl Envelope {
    /// Parse an envelope.
    ///
    /// The reader applies the JSON rules of `PROTOCOL.md` section 3 to the
    /// envelope text, so it refuses a duplicate key. It ignores `keyid` and
    /// each unknown field ([LOG-2], [VER-13]).
    ///
    /// # Errors
    ///
    /// Refuses a missing field, a field of the wrong type, base64 outside
    /// both alphabets, a signature that is not 64 bytes, and a `signatures`
    /// list without exactly one entry.
    pub fn parse(text: &[u8]) -> Result<Self, EnvelopeError> {
        let map = strict::parse_object(text)?;
        let get_str = |name: &str| match map.get(name) {
            Some(Value::Str(s)) => Ok(s.as_str()),
            _ => Err(EnvelopeError(format!(
                "envelope: `{name}` is missing or not a string"
            ))),
        };
        let payload_type = get_str("payloadType")?.to_owned();
        let payload = decode_b64_loose(get_str("payload")?)?;
        let Some(Value::Arr(sigs)) = map.get("signatures") else {
            return Err(EnvelopeError(
                "envelope: `signatures` is missing or not a list".into(),
            ));
        };
        let [Value::Obj(entry)] = sigs.as_slice() else {
            return Err(EnvelopeError(
                "envelope: `signatures` must hold exactly one object".into(),
            ));
        };
        let Some(Value::Str(sig_text)) = entry.get("sig") else {
            return Err(EnvelopeError(
                "envelope: `sig` is missing or not a string".into(),
            ));
        };
        let sig: [u8; 64] = decode_b64_loose(sig_text)?
            .try_into()
            .map_err(|_| EnvelopeError("envelope: `sig` is not 64 bytes".into()))?;
        Ok(Self {
            payload_type,
            payload,
            sig,
        })
    }

    /// The writer form: fixed field order, standard base64 with padding and
    /// no whitespace. `keyid` is the author ID.
    #[must_use]
    pub fn to_json(&self, keyid: &str) -> String {
        // serde_json escapes the two strings that can hold any text.
        let t = serde_json::to_string(&self.payload_type).unwrap_or_default();
        let k = serde_json::to_string(keyid).unwrap_or_default();
        format!(
            r#"{{"payloadType":{t},"payload":"{}","signatures":[{{"keyid":{k},"sig":"{}"}}]}}"#,
            encode_b64(&self.payload),
            encode_b64(&self.sig)
        )
    }

    /// The record hash of this envelope ([LOG-3]).
    #[must_use]
    pub fn record_hash(&self) -> Hash32 {
        record_hash(&self.payload_type, &self.payload, &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The writer form parses back to the same envelope, so the record
        /// hash survives a round trip through JSON.
        #[test]
        fn round_trip(t in "[a-z.0-9\"\\\\]{0,24}", payload in proptest::collection::vec(any::<u8>(), 0..64), sig in proptest::collection::vec(any::<u8>(), 64..=64), keyid in ".{0,8}") {
            let e = Envelope { payload_type: t, payload, sig: sig.try_into().unwrap() };
            prop_assert_eq!(Envelope::parse(e.to_json(&keyid).as_bytes()), Ok(e));
        }
    }
}
