//! `agree` (SG-16): the key port and the derivation layout, in the platform-neutral core.
//!
//! The core owns what a caller and a verifier can see: the input and output of the command, the form of `context`
//! (`forms::is_agree_context`) and the layout of the HKDF `info`. A key backend (T6.6, CNG) owns the agreement key,
//! does the key agreement and the HKDF inside its key store and returns only the derived bytes: no function of this
//! port returns the shared secret, and the core holds no private scalar, so nothing here can leak one.
//!
//! ```text
//! info = "handsal-agree/1" || 0x00 || lo || hi || context
//! ```
//!
//! `lo` and `hi` are the two public points of the agreement (the key's own and the peer's), each 65 bytes
//! `0x04 || x || y`, the smaller in byte order first: ordered by value and not by role, so both parties of one
//! agreement build the same `info`. Everything before `context` has a fixed length. The backend uses HKDF-SHA-256
//! with an empty salt (HashLen zero bytes, RFC 5869) and length `KEY_LENGTH`.
//! Failure modes: a backend failure is its own `Refusal` (`key_unavailable`, or `internal` for what no code names);
//! an answer that is not `KEY_LENGTH` bytes cannot be expressed by the port's type.

use crate::devicekey;
use crate::encoding;
use crate::value::{Checked, JValue, Refusal};

/// The label that confines the output to handsal's agreement domain.
pub const LABEL: &[u8] = b"handsal-agree/1";
/// The length of the derived key, in bytes.
pub const KEY_LENGTH: usize = 32;

/// An uncompressed P-256 point: `0x04 || x || y`.
pub type Point65 = [u8; 65];

/// The device's agreement key, behind a platform's key store.
pub trait AgreementKey {
    /// The key's own public point.
    fn public(&self) -> Point65;

    /// ECDH between the key and `peer` (a point already checked to be on P-256), then HKDF-SHA-256 with an empty
    /// salt over `info`: `KEY_LENGTH` bytes. No prompt, no signing key.
    fn agree(&self, peer: &Point65, info: &[u8]) -> Result<[u8; KEY_LENGTH], Refusal>;
}

/// The `info` of an agreement between `own` and `peer` for `context`.
pub fn info(own: &Point65, peer: &Point65, context: &str) -> Vec<u8> {
    let (low, high) = if own <= peer { (own, peer) } else { (peer, own) };
    let mut out = Vec::with_capacity(LABEL.len() + 1 + 130 + context.len());
    out.extend_from_slice(LABEL);
    out.push(0);
    out.extend_from_slice(low);
    out.extend_from_slice(high);
    out.extend_from_slice(context.as_bytes());
    out
}

/// The point of a `{x, y}` value of the input, `None` unless it is exactly that and on P-256.
pub fn point_of(value: &JValue) -> Option<Point65> {
    if !devicekey::point_ok(value) {
        return None;
    }
    let x = encoding::base64url_decode(value.get("x")?.str()?)?;
    let y = encoding::base64url_decode(value.get("y")?.str()?)?;
    let mut out = [4u8; 65];
    out[1..33].copy_from_slice(&x);
    out[33..].copy_from_slice(&y);
    Some(out)
}

/// The command (SG-16): `{key}` from a validated `{context, peer}` and the bound key.
pub fn derive(key: &dyn AgreementKey, peer: &Point65, context: &str) -> Checked<JValue> {
    let derived = key.agree(peer, &info(&key.public(), peer, context))?;
    Ok(JValue::Object([("key".to_string(), JValue::String(encoding::base64url(&derived)))].into()))
}
