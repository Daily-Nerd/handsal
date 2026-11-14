//! The render core (RN-01, RN-02, RN-03, RN-06): short forms, the layout frame and the refusals.
//!
//! The render is a pure function of signed bytes plus the attachments bound to them: ASCII, no
//! locale, no clock, no I/O. `frame` is the one place that lays lines out, wraps them and counts
//! them against 72; the signer and the fold's genesis size check both go through it.
//! Failure mode: a `Refusal` carrying a code of section 11, never a partial render.

use crate::limits::{line_max, max_lines, wrap_segment};
use crate::value::{Checked, JValue, Refusal};

#[derive(Debug, Clone)]
pub struct RenderInput {
    pub attachments: JValue,
    pub kid: String,
    pub method: String,
    pub payload: JValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub first_line: String,
    pub text: String,
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

/// The group separator is never a character of what it groups: kids and hashstrs are base64url, which
/// holds `-`, so a `-` separator made `pbubEyWn-20K` read `pbub-EyWn--20K` (section 2.1).
const GROUP_SEPARATOR: u8 = b' ';

fn group(text: &[u8]) -> String {
    let mut out = Vec::new();
    for (index, byte) in text.iter().enumerate() {
        if index > 0 && index % 4 == 0 {
            out.push(GROUP_SEPARATOR);
        }
        out.push(*byte);
    }
    lossy(&out)
}

/// The 12 characters after the constant `uEi` of a hashstr, grouped `xxxx xxxx xxxx` (section 2.1).
pub fn hash12(value: &str) -> String {
    let bytes = value.as_bytes();
    group(bytes.get(3..).map_or(&[][..], |rest| &rest[..rest.len().min(12)]))
}

/// The first 12 characters of a kid, grouped like `hash12`.
pub fn kid12(value: &str) -> String {
    let bytes = value.as_bytes();
    group(&bytes[..bytes.len().min(12)])
}

/// A free field in line 1: as is up to 12 characters, else its first 11 and `~` (RN-03).
pub fn cut12(value: &str) -> String {
    cut_if_longer(value, 11, 12)
}

/// `text` as is up to `size` bytes, else its first `size` bytes and `~` (RN-03).
pub fn cut(text: &str, size: usize) -> String {
    cut_if_longer(text, size, size)
}

fn cut_if_longer(text: &str, size: usize, limit: usize) -> String {
    let bytes = text.as_bytes();
    if bytes.len() <= limit {
        text.to_string()
    } else {
        format!("{}~", lossy(&bytes[..size]))
    }
}

/// A line of at most 100 bytes as is; a longer one in segments of at most 98 bytes, each
/// continuation prefixed `+ `, so no signed byte is hidden (RN-02).
pub fn wrap(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    if bytes.len() <= line_max() {
        return vec![line.to_string()];
    }
    let mut out = vec![lossy(&bytes[..wrap_segment()])];
    let mut index = wrap_segment();
    while index < bytes.len() {
        out.push(format!("+ {}", lossy(&bytes[index..(index + wrap_segment()).min(bytes.len())])));
        index += wrap_segment();
    }
    out
}

pub struct Frame<'a> {
    pub first: String,
    pub method: &'a str,
    pub org: &'a str,
    pub performer: &'a str,
    pub kid: &'a str,
    pub body: Vec<String>,
    pub ts: &'a str,
    pub expires: Option<&'a str>,
    pub parent: Option<&'a str>,
    pub head: Option<&'a str>,
    pub sender: bool,
}

/// The `Rendered` of RN-02: line 1, `Method`, `Org`, `Signer`, the method lines `body`, `Signed at`,
/// `Expires`, `Parent`, `Head`, and `Sender: not proven` for verdicts. A render over 72 lines is
/// `render_refused`. `org`, `parent` and `head` are hashstrs shown as `hash12`.
pub fn frame(f: Frame) -> Checked<Rendered> {
    let mut lines = vec![
        format!("Method: {}", f.method),
        format!("Org: {}", hash12(f.org)),
        format!("Signer: {} key {}", f.performer, kid12(f.kid)),
    ];
    lines.extend(f.body);
    lines.push(format!("Signed at: {}", f.ts));
    if let Some(expires) = f.expires {
        lines.push(format!("Expires: {}", expires));
    }
    if let Some(parent) = f.parent {
        lines.push(format!("Parent: {}", hash12(parent)));
    }
    if let Some(head) = f.head {
        lines.push(format!("Head: {}", hash12(head)));
    }
    if f.sender {
        lines.push("Sender: not proven".to_string());
    }
    let mut out = vec![f.first.clone()];
    out.extend(lines.iter().flat_map(|l| wrap(l)));
    if out.len() > max_lines() {
        return Err(Refusal::new("render_refused"));
    }
    Ok(Rendered { first_line: f.first, text: format!("{}\n", out.join("\n")) })
}
