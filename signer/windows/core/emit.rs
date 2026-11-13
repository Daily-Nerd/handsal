//! Emitters (ACT-05, SG-01).
//!
//! `subset` writes a value of the canonical subset: keys sorted by byte order, no whitespace,
//! strings verbatim (`/` unescaped), arrays in the given order. It refuses everything the subset
//! cannot express instead of coercing it, so bytes that are signed or hashed come from here only.
//! `result_line` writes a command result (RFC 8785 style): result objects are not signed values,
//! so they may carry booleans and numbers.
//! Failure mode: `Refusal("schema_refused")`, loudly, never a repaired value.

use crate::limits::{MAX_DEPTH, MAX_PAYLOAD};
use crate::text;
use crate::value::{Checked, JValue, Refusal};

fn refuse() -> Refusal {
    Refusal::new("schema_refused")
}

pub fn subset(value: &JValue) -> Checked<Vec<u8>> {
    let mut out = Vec::new();
    write(value, 0, &mut out)?;
    if out.len() > MAX_PAYLOAD {
        return Err(refuse());
    }
    Ok(out)
}

fn write_string(text: &str, out: &mut Vec<u8>) -> Checked<()> {
    if !text::is_plain(text) {
        return Err(refuse());
    }
    out.push(b'"');
    out.extend_from_slice(text.as_bytes());
    out.push(b'"');
    Ok(())
}

fn write(value: &JValue, depth: usize, out: &mut Vec<u8>) -> Checked<()> {
    match value {
        JValue::Null => out.extend_from_slice(b"null"),
        JValue::Bool(_) | JValue::Number(_) => return Err(refuse()),
        JValue::String(text) => write_string(text, out)?,
        JValue::Object(members) => {
            if depth + 1 > MAX_DEPTH {
                return Err(refuse());
            }
            out.push(b'{');
            // A BTreeMap of Strings iterates in byte order, which is the order ACT-05 wants.
            for (index, (key, member)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out)?;
                out.push(b':');
                write(member, depth + 1, out)?;
            }
            out.push(b'}');
        }
        JValue::Array(items) => {
            if depth + 1 > MAX_DEPTH {
                return Err(refuse());
            }
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write(item, depth + 1, out)?;
            }
            out.push(b']');
        }
    }
    Ok(())
}

fn result_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for byte in text.bytes() {
        match byte {
            0x22 => out.extend_from_slice(b"\\\""),
            0x5C => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x09 => out.extend_from_slice(b"\\t"),
            0..=0x1f => out.extend_from_slice(format!("\\u{:04x}", byte).as_bytes()),
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

/// The JCS bytes of a result (no trailing LF). Keys sort by UTF-16 code unit, as RFC 8785 says.
pub fn result_line(value: &JValue) -> Vec<u8> {
    let mut out = Vec::new();
    result(value, &mut out);
    out
}

fn result(value: &JValue, out: &mut Vec<u8>) {
    match value {
        JValue::Null => out.extend_from_slice(b"null"),
        JValue::Bool(flag) => out.extend_from_slice(if *flag { b"true" } else { b"false" }),
        JValue::Number(raw) => out.extend_from_slice(raw.as_bytes()),
        JValue::String(text) => result_string(text, out),
        JValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                result(item, out);
            }
            out.push(b']');
        }
        JValue::Object(members) => {
            out.push(b'{');
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                result_string(key, out);
                out.push(b':');
                result(&members[key], out);
            }
            out.push(b'}');
        }
    }
}
