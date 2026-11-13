//! The canonical subset recognizer (ACT-04), grammar only.
//!
//! Invariants: a value is accepted only if every byte is part of the grammar. The recognizer works
//! on bytes, so invalid UTF-8 and a byte order mark fail as bytes outside the string alphabet, with
//! no decoding step to disagree about. Object keys are unique, ASCII and strictly ascending by
//! byte. Nesting is bounded at `MAX_DEPTH` before recursion goes deeper, so hostile input cannot
//! exhaust the stack.
//! Failure modes: `TooLarge` when the input exceeds the caller's bound (checked first), otherwise
//! `NotCanonical`. Both fail closed; there is no partial result.

use crate::limits::max_depth;
use crate::text;
use crate::value::JValue;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsetFailure {
    NotCanonical,
    TooLarge,
}

/// `max_size` is the byte bound of the caller: `MAX_PAYLOAD` for a signed value, `MAX_INPUT` for
/// stdin (SG-01).
pub fn parse(bytes: &[u8], max_size: usize) -> Result<JValue, SubsetFailure> {
    if bytes.len() > max_size {
        return Err(SubsetFailure::TooLarge);
    }
    let mut reader = Reader { bytes, i: 0 };
    let value = reader.value(0).ok_or(SubsetFailure::NotCanonical)?;
    if reader.i == bytes.len() {
        Ok(value)
    } else {
        Err(SubsetFailure::NotCanonical)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.i).copied()
    }

    fn take(&mut self, byte: u8) -> Option<()> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Some(())
        } else {
            None
        }
    }

    fn string(&mut self) -> Option<String> {
        self.take(b'"')?;
        let start = self.i;
        loop {
            let b = self.peek()?;
            if b == b'"' {
                break;
            }
            if !text::is_plain_byte(b) {
                return None;
            }
            self.i += 1;
        }
        let out = String::from_utf8(self.bytes[start..self.i].to_vec()).ok()?;
        self.i += 1;
        Some(out)
    }

    fn value(&mut self, depth: usize) -> Option<JValue> {
        match self.peek()? {
            b'"' => Some(JValue::String(self.string()?)),
            b'n' => {
                if self.bytes[self.i..].starts_with(b"null") {
                    self.i += 4;
                    Some(JValue::Null)
                } else {
                    None
                }
            }
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            _ => None,
        }
    }

    fn object(&mut self, depth: usize) -> Option<JValue> {
        if depth > max_depth() {
            return None;
        }
        self.take(b'{')?;
        let mut out = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Some(JValue::Object(out));
        }
        let mut previous: Option<String> = None;
        loop {
            let key = self.string()?;
            if let Some(prev) = &previous {
                if prev.as_bytes() >= key.as_bytes() {
                    return None;
                }
            }
            previous = Some(key.clone());
            self.take(b':')?;
            let value = self.value(depth)?;
            out.insert(key, value);
            if self.peek() == Some(b',') {
                self.i += 1;
                continue;
            }
            self.take(b'}')?;
            return Some(JValue::Object(out));
        }
    }

    fn array(&mut self, depth: usize) -> Option<JValue> {
        if depth > max_depth() {
            return None;
        }
        self.take(b'[')?;
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Some(JValue::Array(out));
        }
        loop {
            out.push(self.value(depth)?);
            if self.peek() == Some(b',') {
                self.i += 1;
                continue;
            }
            self.take(b']')?;
            return Some(JValue::Array(out));
        }
    }
}
