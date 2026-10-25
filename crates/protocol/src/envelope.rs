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
    /// The reader refuses a duplicate key at any depth. It ignores `keyid`
    /// and each unknown field with any JSON value ([LOG-2], [VER-13]).
    ///
    /// # Errors
    ///
    /// Refuses a missing field, a field of the wrong type, base64 outside
    /// both alphabets, a signature that is not 64 bytes, and a `signatures`
    /// list without exactly one entry.
    pub fn parse(text: &[u8]) -> Result<Self, EnvelopeError> {
        let Value::Obj(map) = strict::parse_envelope_json(text)? else {
            return Err(EnvelopeError(
                "envelope: the top-level value is not an object".into(),
            ));
        };
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
        write_json(&self.payload_type, &self.payload, &self.sig, keyid)
    }

    /// The record hash of this envelope ([LOG-3]).
    #[must_use]
    pub fn record_hash(&self) -> Hash32 {
        record_hash(&self.payload_type, &self.payload, &self.sig)
    }
}

/// The writer form of an envelope from borrowed parts. See
/// [`Envelope::to_json`].
#[must_use]
pub fn write_json(payload_type: &str, payload: &[u8], sig: &[u8; 64], keyid: &str) -> String {
    // serde_json escapes the two strings that can hold any text.
    let t = serde_json::to_string(payload_type).unwrap_or_default();
    let k = serde_json::to_string(keyid).unwrap_or_default();
    format!(
        r#"{{"payloadType":{t},"payload":"{}","signatures":[{{"keyid":{k},"sig":"{}"}}]}}"#,
        encode_b64(payload),
        encode_b64(sig)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error text reaches the app log unchanged.
    #[test]
    fn error_shows_its_cause() {
        assert_eq!(EnvelopeError("x".into()).to_string(), "x");
    }
    use proptest::prelude::*;

    proptest! {
        /// `parse` never panics on any bytes (`PROTOCOL.md` section 4).
        #[test]
        fn parse_never_panics_on_random_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = Envelope::parse(&bytes);
        }

        /// A change of one byte of a valid envelope is refused or gives a
        /// valid envelope. It never panics. A valid result has the same
        /// record hash as its own writer form.
        #[test]
        fn parse_survives_a_changed_byte(
            payload in proptest::collection::vec(any::<u8>(), 0..32),
            sig in any::<[u8; 32]>(),
            pos in any::<usize>(),
            byte in any::<u8>(),
        ) {
            let e = Envelope {
                payload_type: "snailfish.change.v1".into(),
                payload,
                sig: [sig, sig].concat().try_into().unwrap(),
            };
            let mut text = e.to_json("d_00").into_bytes();
            let i = pos.checked_rem(text.len()).unwrap();
            text[i] = byte;
            if let Ok(parsed) = Envelope::parse(&text) {
                let again = Envelope::parse(parsed.to_json("d_00").as_bytes());
                prop_assert_eq!(again.as_ref().map(Envelope::record_hash), Ok(parsed.record_hash()));
            }
        }

        /// The writer form parses back to the same envelope, so the record
        /// hash survives a round trip through JSON.
        #[test]
        fn round_trip(t in "[a-z.0-9\"\\\\]{0,24}", payload in proptest::collection::vec(any::<u8>(), 0..64), sig in proptest::collection::vec(any::<u8>(), 64..=64), keyid in ".{0,8}") {
            let e = Envelope { payload_type: t, payload, sig: sig.try_into().unwrap() };
            prop_assert_eq!(Envelope::parse(e.to_json(&keyid).as_bytes()), Ok(e));
        }
    }
}

// No Kani harness: `parse` is `serde_json` plus base64 on a byte slice, and
// CBMC cannot finish a symbolic input through them (see the note in
// `pae.rs` on UTF-8 validation). The fuzz target `envelope` and the
// property tests above cover the parser.
