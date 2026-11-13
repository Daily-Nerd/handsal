//! Line 1 (RN-03), the method lines (RN-04) and the request and record blocks (RN-05, RN-12).
//!
//! `Facts` carries what a bound attachment tells line 1 and the method lines: the raw bytes of a
//! request or a record body, the line 1 of each attached candidate and head act, the endorsed act,
//! the genesis summary. Nothing here reads an attachment; `render_attach` binds them first.
//!
//! `block` renders untrusted bytes. They are never decoded as UTF-8: each source line is `| `
//! plus its escaped bytes, 0x20 to 0x7E as is and every other byte as `\xHH`, so no Unicode table
//! is needed, a line `----- end -----` in the request cannot end the block, and control and
//! bidirectional bytes are visible. A block over 2048 source bytes or 32 lines is `render_refused`:
//! nothing is truncated.

use crate::acts::EXT_KEY;
use crate::encoding;
use crate::limits::{BLOCK_LINE_BYTES, BLOCK_MAX_BYTES, BLOCK_MAX_LINES};
use crate::methods;
use crate::render::{cut, cut12, hash12, kid12};
use crate::value::{Checked, JValue, Refusal};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Facts {
    pub raw: Option<Vec<u8>>,
    pub summary: Option<String>,
    pub candidates: BTreeMap<String, String>,
    pub heads: BTreeMap<String, String>,
    pub endorsed_line1: Option<String>,
    pub endorsed_lines: Vec<String>,
}

type Object = BTreeMap<String, JValue>;

fn schema() -> Refusal {
    Refusal::new("schema")
}

fn missing() -> Refusal {
    Refusal::new("attachment_missing")
}

fn verdict_title(method: &str) -> Option<&'static str> {
    match method {
        methods::APPROVE => Some("APPROVE request"),
        methods::REJECT => Some("REJECT request"),
        methods::NEEDS_INFO => Some("NEEDS-INFO on request"),
        _ => None,
    }
}

fn act(payload: &Object) -> Checked<&Object> {
    payload.get("ext").and_then(|e| e.get(EXT_KEY)).and_then(JValue::dict).ok_or_else(schema)
}

fn field<'a>(object: Option<&'a Object>, key: &str) -> Checked<&'a str> {
    object.and_then(|o| o.get(key)).and_then(JValue::str).ok_or_else(schema)
}

fn body(act: &Object) -> Checked<&Object> {
    act.get("body").and_then(JValue::dict).ok_or_else(schema)
}

pub fn first_line(method: &str, payload: &Object, facts: &Facts) -> Checked<String> {
    let a = act(payload)?;
    let b = body(a)?;
    let some_b = Some(b);
    match method {
        methods::DEVICE_ADD => Ok(format!(
            "Add device {} ({}) to {}",
            kid12(field(some_b, "kid")?),
            cut12(field(some_b, "class")?),
            cut12(field(some_b, "person")?)
        )),
        methods::DEVICE_REMOVE => {
            Ok(format!("Remove device {} of {}", kid12(field(some_b, "kid")?), cut12(field(some_b, "person")?)))
        }
        methods::MEMBER_ADD => {
            let device = b.get("device").and_then(JValue::dict);
            Ok(format!(
                "Add device {} as member {} ({})",
                kid12(field(device, "kid")?),
                cut12(field(some_b, "member")?),
                cut12(field(some_b, "role")?)
            ))
        }
        methods::PROMOTE => {
            let raw = facts.raw.as_ref().ok_or_else(missing)?;
            Ok(format!(
                "Promote record {} ({}, {} bytes)",
                cut12(field(some_b, "record_id")?),
                hash12(field(Some(payload), "inputs_hash")?),
                raw.len()
            ))
        }
        methods::RESOLVE => {
            let line = facts.candidates.get(field(some_b, "choose")?).ok_or_else(missing)?;
            Ok(format!("Resolve fork, keep: {}", cut(line, 59)))
        }
        methods::ENDORSE => {
            let line = facts.endorsed_line1.as_ref().ok_or_else(missing)?;
            Ok(format!("Endorse: {}", cut(line, 70)))
        }
        methods::GENESIS_SIGN => facts.summary.clone().ok_or_else(missing),
        _ => {
            let (Some(title), Some(raw)) = (verdict_title(method), facts.raw.as_ref()) else {
                return Err(Refusal::new("method_unknown"));
            };
            Ok(format!(
                "{} {} ({}, {} bytes)",
                title,
                cut12(field(Some(a), "request_id")?),
                hash12(field(Some(payload), "inputs_hash")?),
                raw.len()
            ))
        }
    }
}

// block

fn escape(raw: &[u8]) -> Vec<String> {
    raw.iter()
        .map(|&byte| if (0x20..=0x7E).contains(&byte) { (byte as char).to_string() } else { format!("\\x{:02x}", byte) })
        .collect()
}

/// The content of one source line in segments of at most 96 characters, never splitting an escape.
fn segments(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for token in tokens {
        if current.len() + token.len() > BLOCK_LINE_BYTES {
            out.push(std::mem::take(&mut current));
        }
        current.push_str(token);
    }
    out.push(current);
    out
}

pub fn block(title: &str, raw: &[u8], inputs_hash: &str) -> Checked<Vec<String>> {
    if raw.len() > BLOCK_MAX_BYTES {
        return Err(Refusal::new("render_refused"));
    }
    let mut sources: Vec<&[u8]> = raw.split(|&b| b == 0x0A).collect();
    if sources.last().map_or(false, |last| last.is_empty()) {
        sources.pop(); // a final LF ends the last line
    }
    let mut content = Vec::new();
    for source in sources {
        let parts = segments(&escape(source));
        content.push(format!("| {}", parts[0]));
        content.extend(parts[1..].iter().map(|part| format!("|+{}", part)));
    }
    if content.len() > BLOCK_MAX_LINES {
        return Err(Refusal::new("render_refused"));
    }
    let header = format!("----- {} ({} bytes, sha256 {}) -----", title, raw.len(), hash12(inputs_hash));
    let mut out = vec![header];
    out.extend(content);
    out.push("----- end -----".to_string());
    Ok(out)
}

// method lines

fn agree(device: Option<&Object>) -> Checked<String> {
    let point = device.and_then(|d| d.get("agree")).and_then(JValue::dict);
    Ok(format!("Agree key: {}", encoding::thumbprint(field(point, "x")?, field(point, "y")?)))
}

fn listed(title: &str, ids: &[&str], line_of: &BTreeMap<String, String>, marker: Option<&str>) -> Checked<Vec<String>> {
    let mut out = vec![title.to_string()];
    for id in ids {
        let line = line_of.get(*id).ok_or_else(missing)?;
        let lead = match marker {
            None => "  - ",
            Some(m) if m == *id => "  > ",
            Some(_) => "    ",
        };
        out.push(format!("{}{} {}", lead, hash12(id), line));
    }
    Ok(out)
}

fn strings(value: Option<&JValue>) -> Checked<Vec<&str>> {
    value.and_then(JValue::list).ok_or_else(schema)?.iter().map(|item| item.str().ok_or_else(schema)).collect()
}

pub fn method_lines(method: &str, payload: &Object, facts: &Facts) -> Checked<Vec<String>> {
    let a = act(payload)?;
    let b = body(a)?;
    let some_b = Some(b);
    let inputs = field(Some(payload), "inputs_hash")?;
    match method {
        methods::DEVICE_ADD => Ok(vec![
            format!("Person: {}", field(some_b, "person")?),
            format!("New device: {}", field(some_b, "kid")?),
            agree(some_b)?,
            format!("Class: {}", field(some_b, "class")?),
            format!("Label: {}", field(some_b, "label")?),
            format!("Link code: {}", hash12(field(some_b, "link_code_hash")?)),
        ]),
        methods::DEVICE_REMOVE => {
            Ok(vec![format!("Person: {}", field(some_b, "person")?), format!("Remove device: {}", field(some_b, "kid")?)])
        }
        methods::MEMBER_ADD => {
            let device = b.get("device").and_then(JValue::dict);
            Ok(vec![
                format!("Member: {}", field(some_b, "member")?),
                format!("Role: {}", field(some_b, "role")?),
                format!("New device: {}", field(device, "kid")?),
                agree(device)?,
                format!("Class: {}", field(device, "class")?),
                format!("Label: {}", field(device, "label")?),
            ])
        }
        methods::PROMOTE => {
            let raw = facts.raw.as_ref().ok_or_else(missing)?;
            let mut out = vec![format!("Record: {}", field(some_b, "record_id")?), "Anchors:".to_string()];
            out.extend(strings(b.get("anchors"))?.into_iter().map(|a| format!("  - {}", a)));
            out.push(format!("Body hash: {}", hash12(inputs)));
            out.extend(block("record body", raw, inputs)?);
            Ok(out)
        }
        methods::RESOLVE => {
            let choose = field(some_b, "choose")?;
            let mut out = vec![
                format!("Fork parent: {}", field(Some(payload), "parent_receipt_hash")?),
                format!("Choose: {}", choose),
            ];
            out.extend(listed("Candidates:", &strings(b.get("candidates"))?, &facts.candidates, Some(choose))?);
            out.extend(listed("Heads:", &strings(b.get("heads"))?, &facts.heads, None)?);
            let overrides = b.get("overrides").and_then(JValue::list).ok_or_else(schema)?;
            if overrides.is_empty() {
                out.push("Overrides: none".to_string());
                return Ok(out);
            }
            out.push("Overrides:".to_string());
            for entry in overrides {
                let e = entry.dict().ok_or_else(schema)?;
                let count = e.get("endorsements").and_then(JValue::list).ok_or_else(schema)?.len();
                out.push(format!("  - {} (endorsements: {})", hash12(field(Some(e), "resolve")?), count));
            }
            Ok(out)
        }
        methods::ENDORSE => {
            let mut out = vec![format!("Endorsed act: {}", field(some_b, "act")?)];
            out.extend(facts.endorsed_lines.iter().cloned());
            Ok(out)
        }
        _ => {
            let (Some(_), Some(raw)) = (verdict_title(method), facts.raw.as_ref()) else {
                return Err(Refusal::new("method_unknown"));
            };
            let mut out = vec![
                format!("Request: {}", field(Some(a), "request_id")?),
                format!("Recipient: {}", field(Some(a), "recipient")?),
                format!("Relay: {}", field(Some(a), "relay")?),
                format!("Request hash: {}", hash12(inputs)),
            ];
            out.extend(block("request", raw, inputs)?);
            Ok(out)
        }
    }
}
