//! The shape of every value the signer reads or writes, and the one error type of the core.

use std::collections::BTreeMap;

/// A parsed JSON value.
///
/// Owner of: the shape of a value. Invariant: object keys are unique (a map cannot hold a
/// duplicate) and emission order is decided by the emitters alone, never by this type.
/// `Bool` and `Number` exist because result lines and the checker-form input carry them; the
/// canonical subset recognizer never produces either and the subset emitter refuses both.
#[derive(Debug, Clone, PartialEq)]
pub enum JValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JValue>),
    Object(BTreeMap<String, JValue>),
}

impl JValue {
    pub fn str(&self) -> Option<&str> {
        match self {
            JValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn dict(&self) -> Option<&BTreeMap<String, JValue>> {
        match self {
            JValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn list(&self) -> Option<&[JValue]> {
        match self {
            JValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The member `key` of an object; `None` for anything else or a missing key.
    pub fn get(&self, key: &str) -> Option<&JValue> {
        self.dict().and_then(|o| o.get(key))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, JValue::Null)
    }

    pub fn string(text: &str) -> JValue {
        JValue::String(text.to_string())
    }
}

/// A rule of the profile said no. `code` is the reason code the spec names (section 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
}

impl Refusal {
    pub const fn new(code: &'static str) -> Refusal {
        Refusal { code }
    }
}

pub type Checked<T> = Result<T, Refusal>;
