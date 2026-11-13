//! Encodings shared by every command (ACT-03, ACT-07, ACT-11). Pure functions; a function that
//! cannot decode answers `None` and the caller picks the reason code.

use crate::sha256;

const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = Vec::new();
    for group in bytes.chunks(3) {
        let n = group.len();
        let mut chunk = (group[0] as u32) << 16;
        if n > 1 {
            chunk |= (group[1] as u32) << 8;
        }
        if n > 2 {
            chunk |= group[2] as u32;
        }
        for k in 0..=n {
            out.push(alphabet[((chunk >> (18 - 6 * k)) & 63) as usize]);
        }
        if pad {
            out.extend(std::iter::repeat(b'=').take(3 - n));
        }
    }
    String::from_utf8(out).expect("base64 alphabets are ASCII")
}

/// Decodes `symbols` (no padding) and requires that encoding gives the input back (canonical).
fn decode(symbols: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut lookup = [-1i32; 256];
    for (index, byte) in alphabet.iter().enumerate() {
        lookup[*byte as usize] = index as i32;
    }
    if symbols.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    for group in symbols.chunks(4) {
        let mut chunk = 0u32;
        for (k, symbol) in group.iter().enumerate() {
            let v = lookup[*symbol as usize];
            if v < 0 {
                return None;
            }
            chunk |= (v as u32) << (18 - 6 * k);
        }
        out.push((chunk >> 16) as u8);
        if group.len() > 2 {
            out.push((chunk >> 8) as u8);
        }
        if group.len() > 3 {
            out.push(chunk as u8);
        }
    }
    (encode(&out, alphabet, false).as_bytes() == symbols).then_some(out)
}

pub fn base64url(bytes: &[u8]) -> String {
    encode(bytes, URL, false)
}

/// Canonical base64url without padding (ACT-03): no other alphabet, no spare bits set.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    decode(text.as_bytes(), URL)
}

/// Standard base64 with padding, canonical (section 2.2 `_b64` inputs).
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut symbols = text.as_bytes();
    if symbols.len() % 4 != 0 {
        return None;
    }
    let mut pad = 0;
    while symbols.last() == Some(&b'=') && pad < 3 {
        symbols = &symbols[..symbols.len() - 1];
        pad += 1;
    }
    if pad > 2 || symbols.contains(&b'=') {
        return None;
    }
    let out = decode(symbols, STD)?;
    (encode(&out, STD, true) == text).then_some(out)
}

/// `"u" + base64url(0x12 0x20 || sha256(bytes))`, 47 characters (section 2.1).
pub fn hashstr(bytes: &[u8]) -> String {
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(&sha256::digest(bytes));
    format!("u{}", base64url(&multihash))
}

pub fn empty_hash() -> String {
    hashstr(&[])
}

pub fn is_hashstr(text: &str) -> bool {
    if text.len() != 47 || !text.starts_with("uEi") {
        return false;
    }
    match base64url_decode(&text[1..]) {
        Some(raw) => raw.len() == 34 && raw[0] == 0x12 && raw[1] == 0x20,
        None => false,
    }
}

/// RFC 7638 thumbprint of a P-256 key, over the members crv, kty, x, y in that order (ACT-11).
pub fn thumbprint(x: &str, y: &str) -> String {
    let json = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", x, y);
    base64url(&sha256::digest(json.as_bytes()))
}
