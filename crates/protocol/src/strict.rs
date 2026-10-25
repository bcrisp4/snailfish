//! Strict payload JSON (`PROTOCOL.md` section 3, [WIR-4]) and the envelope
//! JSON reader (`PROTOCOL.md` section 4).
//!
//! `serde_json` does the tokenising. It refuses invalid UTF-8, a byte order
//! mark, lone surrogates, numbers outside the binary64 range and trailing
//! data. The visitor in this module adds the rules that `serde_json` does not
//! apply: no duplicate key, and, for payloads only, integers only in the range
//! from -(2^53 - 1) to 2^53 - 1.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// The largest integer that a payload can hold: 2^53 - 1.
pub const MAX_INT: i64 = (1 << 53) - 1;

/// The smallest integer that a payload can hold: -(2^53 - 1).
const MIN_INT: i64 = -MAX_INT;

/// One strict JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`. A payload field is never `null`, but the parser keeps it so
    /// that the field check can name the field.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer from -(2^53 - 1) to 2^53 - 1.
    Int(i64),
    /// Any other number. Only the envelope reader produces it, for an
    /// unknown field ([VER-13]). A payload never holds it.
    OtherNumber,
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<Value>),
    /// An object with unique keys.
    Obj(BTreeMap<String, Value>),
}

/// A payload that breaks a rule of `PROTOCOL.md` section 3 or 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictError(pub String);

impl fmt::Display for StrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StrictError {}

/// Parse a JSON document under the strict rules. The top level can be any
/// value. [`parse_object`] adds the rule that it must be an object.
///
/// # Errors
///
/// Refuses bytes that break rules 1, 3, 4, 5 or 8 of `PROTOCOL.md` section 3.
pub fn parse(bytes: &[u8]) -> Result<Value, StrictError> {
    parse_with(bytes, Numbers::PayloadIntegers)
}

/// Parse the JSON of an envelope. It applies rules 1, 3, 5 and 8, but accepts
/// any number in the binary64 range, because an unknown envelope field can
/// hold any JSON value (`PROTOCOL.md` section 4).
///
/// # Errors
///
/// Refuses bad UTF-8, a duplicate key, a lone surrogate and trailing data.
pub fn parse_envelope_json(bytes: &[u8]) -> Result<Value, StrictError> {
    parse_with(bytes, Numbers::Any)
}

fn parse_with(bytes: &[u8], numbers: Numbers) -> Result<Value, StrictError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = Visit(numbers)
        .deserialize(&mut de)
        .map_err(|e| StrictError(e.to_string()))?;
    de.end().map_err(|e| StrictError(e.to_string()))?;
    Ok(v)
}

/// Parse a payload. The top-level value must be an object (rule 2).
///
/// # Errors
///
/// As [`parse`], and refuses a top-level value that is not an object.
pub fn parse_object(bytes: &[u8]) -> Result<BTreeMap<String, Value>, StrictError> {
    match parse(bytes)? {
        Value::Obj(map) => Ok(map),
        _ => Err(StrictError(
            "rule 2: the top-level value is not an object".into(),
        )),
    }
}

/// Which numbers the reader accepts.
#[derive(Clone, Copy)]
enum Numbers {
    /// Integers in +-(2^53 - 1) only: payloads, rule 4.
    PayloadIntegers,
    /// Each number in the binary64 range: envelopes.
    Any,
}

/// A seed that parses one value with one number rule, also for nested values.
#[derive(Clone, Copy)]
struct Visit(Numbers);

impl<'de> DeserializeSeed<'de> for Visit {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

/// The integer if it is in the payload range ([WIR-4]).
fn in_range(n: i128) -> Option<i64> {
    if (i128::from(MIN_INT)..=i128::from(MAX_INT)).contains(&n) {
        i64::try_from(n).ok()
    } else {
        None
    }
}

/// Check that an integer is in the payload range.
fn int_in_range<E: de::Error>(n: i128) -> Result<Value, E> {
    in_range(n)
        .map(Value::Int)
        .ok_or_else(|| E::custom("rule 4: integer outside +-(2^53 - 1)"))
}

impl<'de> Visitor<'de> for Visit {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a strict JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        self.number(int_in_range(i128::from(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        self.number(int_in_range(i128::from(v)))
    }

    // serde_json gives f64 for each number with a fraction or an exponent,
    // for "-0", and for an integer that does not fit in 64 bits.
    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Value, E> {
        self.number(Err(E::custom(
            "rule 4: a number is not an integer in range",
        )))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Str(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::Str(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(self)? {
            out.push(v);
        }
        Ok(Value::Arr(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = BTreeMap::new();
        // serde_json decodes the escapes of each key before this point, so
        // "a" and "\u0061" are the same key here.
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(self)?;
            if out.insert(key, value).is_some() {
                return Err(de::Error::custom("rule 3: duplicate key"));
            }
        }
        Ok(Value::Obj(out))
    }
}

impl Visit {
    /// Apply the number rule: a payload refuses each number outside the
    /// integer range, and an envelope keeps it as [`Value::OtherNumber`].
    fn number<E: de::Error>(self, payload: Result<Value, E>) -> Result<Value, E> {
        match (self.0, payload) {
            (_, Ok(v)) => Ok(v),
            (Numbers::PayloadIntegers, Err(e)) => Err(e),
            (Numbers::Any, Err(_)) => Ok(Value::OtherNumber),
        }
    }
}

/// Reads the fields of one object and checks that it holds exactly the
/// expected fields (`PROTOCOL.md` section 3, rules 6 and 7).
pub struct Fields<'a> {
    map: &'a BTreeMap<String, Value>,
    what: &'static str,
}

impl<'a> Fields<'a> {
    /// Check that `map` holds each of `names`, no other field, and no `null`.
    ///
    /// # Errors
    ///
    /// Names the first missing, unknown or `null` field.
    pub fn exact(
        map: &'a BTreeMap<String, Value>,
        what: &'static str,
        names: &[&str],
    ) -> Result<Self, StrictError> {
        for name in names {
            match map.get(*name) {
                None => return Err(err(what, name, "rule 6: missing field")),
                Some(Value::Null) => return Err(err(what, name, "rule 6: null field")),
                Some(_) => {}
            }
        }
        if let Some(extra) = map.keys().find(|k| !names.contains(&k.as_str())) {
            return Err(err(what, extra, "rule 6: unknown field"));
        }
        Ok(Self { map, what })
    }

    /// Like [`Fields::exact`] for a value that must be an object.
    ///
    /// # Errors
    ///
    /// Refuses a value that is not an object, and as [`Fields::exact`].
    pub fn object(
        value: &'a Value,
        what: &'static str,
        names: &[&str],
    ) -> Result<Self, StrictError> {
        match value {
            Value::Obj(map) => Self::exact(map, what, names),
            _ => Err(StrictError(format!("{what}: rule 7: not an object"))),
        }
    }

    /// The value of a field that [`Fields::exact`] checked.
    ///
    /// # Errors
    ///
    /// Refuses a field name that the check did not list.
    pub fn get(&self, name: &str) -> Result<&'a Value, StrictError> {
        self.map
            .get(name)
            .ok_or_else(|| err(self.what, name, "rule 6: missing field"))
    }

    /// A string field.
    ///
    /// # Errors
    ///
    /// Refuses a value that is not a string.
    pub fn str(&self, name: &str) -> Result<&'a str, StrictError> {
        match self.get(name)? {
            Value::Str(s) => Ok(s),
            _ => Err(err(self.what, name, "rule 7: not a string")),
        }
    }

    /// An integer field in `lo..=hi`.
    ///
    /// # Errors
    ///
    /// Refuses a value that is not an integer, or that is outside the range.
    pub fn int(&self, name: &str, lo: i64, hi: i64) -> Result<u64, StrictError> {
        match self.get(name)? {
            Value::Int(n) if (lo..=hi).contains(n) => {
                u64::try_from(*n).map_err(|_| err(self.what, name, "rule 7: negative integer"))
            }
            Value::Int(_) => Err(err(self.what, name, "rule 7: integer out of range")),
            _ => Err(err(self.what, name, "rule 7: not an integer")),
        }
    }

    /// An array field.
    ///
    /// # Errors
    ///
    /// Refuses a value that is not an array.
    pub fn arr(&self, name: &str) -> Result<&'a [Value], StrictError> {
        match self.get(name)? {
            Value::Arr(v) => Ok(v),
            _ => Err(err(self.what, name, "rule 7: not an array")),
        }
    }
}

fn err(what: &str, name: &str, rule: &str) -> StrictError {
    StrictError(format!("{what}.{name}: {rule}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error text reaches the app log unchanged.
    #[test]
    fn error_shows_its_cause() {
        assert_eq!(StrictError("x".into()).to_string(), "x");
    }

    fn ok(s: &str) -> bool {
        parse(s.as_bytes()).is_ok()
    }

    #[test]
    fn integer_range_boundaries() {
        assert!(ok("9007199254740991"));
        assert!(ok("-9007199254740991"));
        assert!(!ok("9007199254740992"));
        assert!(!ok("-9007199254740992"));
        assert!(!ok("18446744073709551616"));
        assert!(!ok("-9223372036854775809"));
    }

    #[test]
    fn refuses_non_integers() {
        for s in ["1.0", "1e2", "-0", "0.5", "1E0"] {
            assert!(!ok(s), "{s}");
        }
        assert!(ok("0"));
    }

    #[test]
    fn refuses_duplicate_keys_after_escape_decoding() {
        assert!(!ok(r#"{"a":1,"a":2}"#));
        assert!(!ok(r#"{"a":1,"\u0061":2}"#));
        assert!(!ok(r#"{"x":{"b":1,"b":1}}"#));
        assert!(!ok(r#"[{"b":1,"b":1}]"#));
        assert!(ok(r#"{"a":1,"b":{"a":1}}"#));
    }

    #[test]
    fn refuses_bom_surrogates_and_trailing_data() {
        assert!(parse(b"\xef\xbb\xbf{}").is_err());
        assert!(parse(b"{\"a\":\"\xff\"}").is_err());
        assert!(!ok(r#""\ud800""#));
        assert!(!ok(r#""\udc00""#));
        assert!(ok(r#""\ud83d\ude00""#));
        assert!(!ok("{} x"));
        assert!(!ok("{}{}"));
        assert!(ok("{} \n"));
    }

    proptest::proptest! {
        /// [WIR-4]: every integer in range parses to itself, and every
        /// integer outside the range is refused.
        #[test]
        fn integer_range_is_exact(n in proptest::prelude::any::<i64>()) {
            let r = parse(n.to_string().as_bytes());
            if n.unsigned_abs() <= MAX_INT.unsigned_abs() {
                proptest::prop_assert_eq!(r, Ok(Value::Int(n)));
            } else {
                proptest::prop_assert!(r.is_err());
            }
        }

        /// [WIR-4]: an object with a repeated key is refused at any depth.
        #[test]
        fn repeated_key_is_refused(k in "[a-z]{1,4}", depth in 0usize..4) {
            let mut doc = format!(r#"{{"{k}":1,"{k}":2}}"#);
            for _ in 0..depth {
                doc = format!(r#"{{"x":{doc}}}"#);
            }
            proptest::prop_assert!(parse(doc.as_bytes()).is_err());
        }
    }

    /// PROTOCOL.md section 4: an unknown envelope field can hold any number.
    /// Without this, a relay that adds `"ts":1.5e3` stops every engine.
    #[test]
    fn envelope_json_accepts_any_number_and_refuses_duplicates() {
        for ok in [
            r#"{"x":1.5e3}"#,
            r#"{"x":-0}"#,
            r#"{"x":9007199254740993}"#,
            r#"{"x":[{"y":1.0}]}"#,
        ] {
            assert!(parse_envelope_json(ok.as_bytes()).is_ok(), "{ok}");
            assert!(parse(ok.as_bytes()).is_err(), "{ok}");
        }
        for bad in [
            r#"{"x":1e999}"#,
            r#"{"x":{"a":1.5,"a":2}}"#,
            r#"{"x":"\ud800"}"#,
            "{} x",
        ] {
            assert!(parse_envelope_json(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn fields_exact_refuses_missing_unknown_and_null() {
        let map = parse_object(br#"{"a":1,"b":null}"#).unwrap();
        assert!(Fields::exact(&map, "t", &["a"]).is_err());
        assert!(Fields::exact(&map, "t", &["a", "b"]).is_err());
        let map = parse_object(br#"{"a":1}"#).unwrap();
        assert!(Fields::exact(&map, "t", &["a", "c"]).is_err());
        let f = Fields::exact(&map, "t", &["a"]).unwrap();
        assert_eq!(f.int("a", 1, 1), Ok(1));
        // The error names the rule, so the app log shows why a record failed.
        assert_eq!(
            f.int("a", 2, 3).unwrap_err().0,
            "t.a: rule 7: integer out of range"
        );
        assert_eq!(
            f.str("a").unwrap_err().to_string(),
            "t.a: rule 7: not a string"
        );
        assert!(f.str("a").is_err());
    }
}

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
#[cfg(kani)]
mod proofs {
    use super::{MAX_INT, in_range};

    /// [WIR-4]: the range check accepts exactly -(2^53 - 1) to 2^53 - 1, for
    /// every i64 and every u64 that serde_json can give. The harness checks
    /// `in_range` and not `int_in_range`, because the error path formats a
    /// string, and CBMC did not finish that in 15 minutes.
    #[kani::proof]
    fn in_range_is_exact() {
        let wide: bool = kani::any();
        let n = if wide {
            i128::from(kani::any::<u64>())
        } else {
            i128::from(kani::any::<i64>())
        };
        let r = in_range(n);
        assert!(r.is_some() == (n >= -i128::from(MAX_INT) && n <= i128::from(MAX_INT)));
        if let Some(v) = r {
            assert!(i128::from(v) == n);
        }
    }
}
