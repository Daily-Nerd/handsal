//! Device key validity (ACT-11, KC-05): one definition of a device's keys.
//!
//! A device has a signing key and an agreement key, both P-256 points `{x, y}` of 32 big-endian
//! bytes in canonical base64url, and a `kid` that is the thumbprint of the signing key. The
//! agreement key differs from the signing key.
//! The curve check is the curve equation `y^2 = x^3 - 3x + b (mod p)` with both coordinates below
//! the field prime; the cofactor is 1, so on the curve is a valid point. No crate: the arithmetic
//! is four 64-bit limbs and a double-and-add multiply, slow and obviously correct.

use crate::encoding;
use crate::value::JValue;

type U256 = [u64; 4];

const P: U256 = [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0x0000_0000_0000_0000, 0xffff_ffff_0000_0001];
const B: U256 = [0x3bce_3c3e_27d2_604b, 0x651d_06b0_cc53_b0f6, 0xb3eb_bd55_7698_86bc, 0x5ac6_35d8_aa3a_93e7];

fn from_be(bytes: &[u8]) -> U256 {
    let mut out = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        out[3 - i] = u64::from_be_bytes(word);
    }
    out
}

fn less(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn add(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = [0u64; 4];
    let mut carry = false;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry as u64);
        out[i] = s2;
        carry = c1 || c2;
    }
    (out, carry)
}

fn sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as u64);
        out[i] = d2;
        borrow = b1 || b2;
    }
    (out, borrow)
}

fn add_mod(a: &U256, b: &U256) -> U256 {
    let (sum, carry) = add(a, b);
    if carry || !less(&sum, &P) {
        sub(&sum, &P).0
    } else {
        sum
    }
}

fn sub_mod(a: &U256, b: &U256) -> U256 {
    let (diff, borrow) = sub(a, b);
    if borrow {
        add(&diff, &P).0
    } else {
        diff
    }
}

fn mul_mod(a: &U256, b: &U256) -> U256 {
    let mut acc = [0u64; 4];
    for bit in (0..256).rev() {
        acc = add_mod(&acc, &acc);
        if (b[bit / 64] >> (bit % 64)) & 1 == 1 {
            acc = add_mod(&acc, a);
        }
    }
    acc
}

pub fn is_on_curve(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    let (x, y) = (from_be(x), from_be(y));
    if !less(&x, &P) || !less(&y, &P) {
        return false;
    }
    let x3 = mul_mod(&mul_mod(&x, &x), &x);
    let three_x = add_mod(&add_mod(&x, &x), &x);
    let rhs = add_mod(&sub_mod(&x3, &three_x), &B);
    mul_mod(&y, &y) == rhs
}

fn coordinates(point: &JValue) -> Option<(&str, &str)> {
    Some((point.get("x")?.str()?, point.get("y")?.str()?))
}

/// True iff `point` is exactly `{x, y}`, canonical 32-byte coordinates, on P-256.
pub fn point_ok(point: &JValue) -> bool {
    let Some(members) = point.dict() else { return false };
    if members.len() != 2 {
        return false;
    }
    let Some((xs, ys)) = coordinates(point) else { return false };
    if xs.len() != 43 || ys.len() != 43 {
        return false;
    }
    match (encoding::base64url_decode(xs), encoding::base64url_decode(ys)) {
        (Some(x), Some(y)) => is_on_curve(&x, &y),
        _ => false,
    }
}

/// `None` for a valid key set, else the first defect: `sign_point`, `agree_point`,
/// `kid_not_thumbprint`, `agree_equals_sign`.
pub fn defect(kid: &str, sign: &JValue, agree: &JValue) -> Option<&'static str> {
    let signed = coordinates(sign).filter(|_| point_ok(sign));
    let Some((x, y)) = signed else { return Some("sign_point") };
    if !point_ok(agree) {
        return Some("agree_point");
    }
    if kid != encoding::thumbprint(x, y) {
        return Some("kid_not_thumbprint");
    }
    if sign == agree {
        return Some("agree_equals_sign");
    }
    None
}
