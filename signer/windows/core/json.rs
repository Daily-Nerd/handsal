//! The I-JSON reader of the checker-form input (CF-03 framing): UTF-8, no duplicate member name at
//! any depth, no lone surrogate. Only the conformance entry point reads input through it; the
//! shipped commands read through the canonical subset recognizer (SG-01).
//!
//! Invariants: every byte is part of the grammar; nesting is bounded at `MAX_NESTING` before
//! recursion goes deeper, so hostile input cannot exhaust the stack. Numbers keep their text.
//! Failure mode: `JsonError`, no partial result.

use crate::value::JValue;
use std::collections::BTreeMap;

/// Deeper than any value the profile defines (MAX_DEPTH is 8 for signed values) with ample room
/// for attachments around them.
const MAX_NESTING: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError;

pub fn parse(bytes: &[u8]) -> Result<JValue, JsonError> {
    let mut reader = Reader { bytes, i: 0 };
    reader.space();
    let value = reader.value(0)?;
    reader.space();
    if reader.i == bytes.len() {
        Ok(value)
    } else {
        Err(JsonError)
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

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn take(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError)
        }
    }

    fn word(&mut self, word: &str, value: JValue) -> Result<JValue, JsonError> {
        if self.bytes[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(JsonError)
        }
    }

    fn value(&mut self, depth: usize) -> Result<JValue, JsonError> {
        match self.peek() {
            Some(b'"') => Ok(JValue::String(self.string()?)),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b't') => self.word("true", JValue::Bool(true)),
            Some(b'f') => self.word("false", JValue::Bool(false)),
            Some(b'n') => self.word("null", JValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError),
        }
    }

    fn digits(&mut self) -> Result<(), JsonError> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == start {
            Err(JsonError)
        } else {
            Ok(())
        }
    }

    fn number(&mut self) -> Result<JValue, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        if self.peek() == Some(b'0') {
            self.i += 1;
        } else {
            self.digits()?;
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            self.digits()?;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.i]).map_err(|_| JsonError)?;
        Ok(JValue::Number(text.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self.bytes.get(self.i..self.i + 4).ok_or(JsonError)?;
        let text = std::str::from_utf8(digits).map_err(|_| JsonError)?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(JsonError);
        }
        self.i += 4;
        u32::from_str_radix(text, 16).map_err(|_| JsonError)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.take(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.peek().ok_or(JsonError)?;
            self.i += 1;
            match b {
                b'"' => break,
                0..=0x1f => return Err(JsonError),
                b'\\' => {
                    let e = self.peek().ok_or(JsonError)?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                self.take(b'\\')?;
                                self.take(b'u')?;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return Err(JsonError);
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                first
                            };
                            let ch = char::from_u32(code).ok_or(JsonError)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(JsonError),
                    }
                }
                _ => out.push(b),
            }
        }
        String::from_utf8(out).map_err(|_| JsonError)
    }

    fn object(&mut self, depth: usize) -> Result<JValue, JsonError> {
        if depth > MAX_NESTING {
            return Err(JsonError);
        }
        self.take(b'{')?;
        let mut out = BTreeMap::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(JValue::Object(out));
        }
        loop {
            self.space();
            let key = self.string()?;
            self.space();
            self.take(b':')?;
            self.space();
            let value = self.value(depth)?;
            if out.insert(key, value).is_some() {
                return Err(JsonError);
            }
            self.space();
            if self.peek() == Some(b',') {
                self.i += 1;
                continue;
            }
            self.take(b'}')?;
            return Ok(JValue::Object(out));
        }
    }

    fn array(&mut self, depth: usize) -> Result<JValue, JsonError> {
        if depth > MAX_NESTING {
            return Err(JsonError);
        }
        self.take(b'[')?;
        let mut out = Vec::new();
        self.space();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(JValue::Array(out));
        }
        loop {
            self.space();
            out.push(self.value(depth)?);
            self.space();
            if self.peek() == Some(b',') {
                self.i += 1;
                continue;
            }
            self.take(b']')?;
            return Ok(JValue::Array(out));
        }
    }
}
