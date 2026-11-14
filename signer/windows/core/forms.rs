//! Field forms of section 2.2: the single owner of what each named form accepts. ASCII only, no
//! regular expression engine, no locale.

use crate::encoding;
use crate::text;

fn ascii(s: &str) -> Option<&[u8]> {
    s.is_ascii().then_some(s.as_bytes())
}

fn lower(b: u8) -> bool {
    b.is_ascii_lowercase()
}

fn digit(b: u8) -> bool {
    b.is_ascii_digit()
}

/// `[a-z0-9][a-z0-9-]{min-1,max-1}` (or letter first for the role and class forms).
fn slug(s: &str, min: usize, max: usize, letter_first: bool) -> bool {
    let Some(b) = ascii(s) else { return false };
    if b.len() < min || b.len() > max {
        return false;
    }
    let first_ok = if letter_first { lower(b[0]) } else { lower(b[0]) || digit(b[0]) };
    first_ok && b[1..].iter().all(|&c| lower(c) || digit(c) || c == b'-')
}

pub fn is_member_id(s: &str) -> bool {
    slug(s, 2, 32, false)
}

pub fn is_role_id(s: &str) -> bool {
    slug(s, 1, 32, true)
}

pub fn is_class_id(s: &str) -> bool {
    is_role_id(s)
}

pub fn is_request_id(s: &str) -> bool {
    slug(s, 8, 36, false)
}

pub fn is_record_id(s: &str) -> bool {
    slug(s, 2, 32, false)
}

/// `[a-z][a-z0-9-]{1,31}`, the consumer a decision is for (VR-18).
pub fn is_consumer_id(s: &str) -> bool {
    slug(s, 2, 32, true)
}

/// `[a-z0-9][a-z0-9-]{1,63}`, what a decision is about (VR-18).
pub fn is_subject_id(s: &str) -> bool {
    slug(s, 2, 64, false)
}

/// The longest `action` the grammar allows: the room line 1 of the render leaves for it (RN-03).
pub const ACTION_MAX: usize = 24;

/// Lowercase ASCII words separated by single spaces, 1 to 24 characters in all (VR-18).
pub fn is_action(s: &str) -> bool {
    let Some(b) = ascii(s) else { return false };
    if b.is_empty() || b.len() > ACTION_MAX {
        return false;
    }
    let mut previous_space = true; // a leading space is as wrong as a doubled one
    for &byte in b {
        if byte == b' ' {
            if previous_space {
                return false;
            }
            previous_space = true;
        } else if lower(byte) {
            previous_space = false;
        } else {
            return false;
        }
    }
    !previous_space // not a trailing space
}

fn plain_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && text::is_plain(s)
}

pub fn is_label(s: &str) -> bool {
    plain_text(s, 64)
}

pub fn is_org_name(s: &str) -> bool {
    plain_text(s, 24)
}

pub fn is_anchor(s: &str) -> bool {
    plain_text(s, 128)
}

/// `0` or `[1-9][0-9]{0,8}`
pub fn is_decimal(s: &str) -> bool {
    let Some(b) = ascii(s) else { return false };
    !b.is_empty() && b.len() <= 9 && b.iter().all(|&c| digit(c)) && (b.len() == 1 || b[0] != b'0')
}

pub fn is_b64u32(s: &str) -> bool {
    s.len() == 43 && encoding::base64url_decode(s).map_or(false, |raw| raw.len() == 32)
}

pub fn is_hashstr(s: &str) -> bool {
    encoding::is_hashstr(s)
}

// time

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn fields(s: &str) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let mut out = 0i64;
        for &c in &b[from..to] {
            if !digit(c) {
                return None;
            }
            out = out * 10 + (c - b'0') as i64;
        }
        Some(out)
    };
    let (y, mo, d, h, mi, sec) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    ((1..=12).contains(&mo) && d >= 1 && d <= days_in(y, mo) && h <= 23 && mi <= 59 && sec <= 59).then_some((y, mo, d, h, mi, sec))
}

pub fn is_time(s: &str) -> bool {
    fields(s).is_some()
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z0: i64) -> (i64, i64, i64) {
    let z = z0 + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Seconds since the epoch of a `time` value, or `None` when `time` is not a `time`.
pub fn epoch_seconds(time: &str) -> Option<i64> {
    let (y, mo, d, h, mi, s) = fields(time)?;
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

pub fn time(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let rest = epoch_seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rest / 3600, rest % 3600 / 60, rest % 60)
}

// hostname

pub fn is_hostname(s: &str) -> bool {
    let Some(b) = ascii(s) else { return false };
    !b.is_empty() && b.len() <= 253 && b.split(|&c| c == b'.').all(is_host_label) && !b.contains(&b' ')
}

fn is_host_label(label: &[u8]) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    let alnum = |b: u8| lower(b) || digit(b);
    if !alnum(label[0]) || !alnum(label[label.len() - 1]) || !label.iter().all(|&c| alnum(c) || c == b'-') {
        return false;
    }
    match label.strip_prefix(b"xn--") {
        Some(rest) => punycode_decodes(rest),
        None => true,
    }
}

/// True when `input` (the part after `xn--`) is non-empty and decodes as Punycode (RFC 3492) to at
/// least one code point.
fn punycode_decodes(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    const BASE: i64 = 36;
    const TMIN: i64 = 1;
    const TMAX: i64 = 26;
    const SKEW: i64 = 38;
    const DAMP: i64 = 700;
    let (mut n, mut i, mut bias) = (128i64, 0i64, 72i64);
    let mut output: Vec<u32> = Vec::new();
    let mut position = 0usize;
    if let Some(delimiter) = input.iter().rposition(|&c| c == b'-') {
        output = input[..delimiter].iter().map(|&c| c as u32).collect();
        position = delimiter + 1;
    }
    let digit_value = |c: u8| -> Option<i64> {
        if lower(c) {
            Some((c - b'a') as i64)
        } else if digit(c) {
            Some((c - b'0') as i64 + 26)
        } else {
            None
        }
    };
    let adapt = |delta0: i64, points: i64, first: bool| -> i64 {
        let mut delta = if first { delta0 / DAMP } else { delta0 / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + SKEW)
    };
    while position < input.len() {
        let old = i;
        let mut w = 1i64;
        let mut k = BASE;
        loop {
            let Some(d) = input.get(position).and_then(|&c| digit_value(c)) else { return false };
            position += 1;
            let Some(sum) = d.checked_mul(w).and_then(|p| i.checked_add(p)) else { return false };
            i = sum;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if d < t {
                break;
            }
            let Some(next) = w.checked_mul(BASE - t) else { return false };
            w = next;
            k += BASE;
        }
        let count = output.len() as i64 + 1;
        bias = adapt(i - old, count, old == 0);
        n += i / count;
        i %= count;
        if n > 0x10FFFF || char::from_u32(n as u32).is_none() {
            return false;
        }
        output.insert(i as usize, n as u32);
        i += 1;
    }
    !output.is_empty()
}
