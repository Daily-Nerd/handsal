//! RN-09: attachments are bound to the payload, then the whole render.
//!
//! Every renderer verifies every attachment against the signed payload before it shows a word, so
//! the words a person sees are a function of signed bytes only. An attachment is bound by hash or
//! by id:
//!   verdicts          `request_b64`      hashstr(bytes) = `inputs_hash`
//!   record.promote    `record_body_b64`  hashstr(bytes) = `inputs_hash`
//!   decision          `decision_b64`     hashstr(bytes) = `inputs_hash`
//!   genesis.sign      `document`         hashstr(JCS(document)) = `inputs_hash`
//!                     `previous`         (a change) hashstr(JCS(previous)) = `document.prev`
//!                     `head.id` of the payload = `document.head` (a change)
//!                     both are valid alone (GP-15 steps 1 and 3), else `attachment_mismatch`
//!   act.endorse       `act`              receipt id = `body.act` = `parent_receipt_hash`; `performer_id` =
//!                                        `parent_performer_id`; its `parent_receipt_hash` = `head.id`;
//!                                        a chain primary or a resolve
//!   chain.resolve     `candidates`       one JWS per id of `body.candidates`, each with the resolve's parent
//!                     `heads`            one JWS per id of `body.heads`, each a chain primary
//!   act.endorse of a resolve: `candidates` and `heads` bound against the attached resolve, the same way
//! A list holds exactly one JWS per id and nothing else, in any order. Every attached act passes
//! ACT-01 to ACT-14 (`acts::parse`), whatever its defect: that is `attachment_mismatch`. An absent
//! attachment or list is `attachment_missing`. Attachments the method does not bind (a `sender`,
//! say) are never read. Whether a head lies in a losing subtree is the fold's to decide (FO-25).
//!
//! Order (RN-09, "Order of checks"): envelope and method (`schema`, `method_unknown`), for `genesis.sign`
//! its document (which fixes whether a head is due), the act object and body (`schema`, `body_schema`),
//! then the other attachments in the order above, each read and bound completely before the next; the
//! first defect wins. A `request_b64` or `record_body_b64` that is not canonical base64 is
//! `malformed_input` (CF-03).

use crate::acts::{self, ParsedAct, EXT_KEY};
use crate::encoding;
use crate::genesis;
use crate::methods;
use crate::registry::Registry;
use crate::render::{frame, Frame, RenderInput, Rendered};
use crate::render_genesis::{self, Doc};
use crate::render_lines::{self, Facts};
use crate::value::{Checked, JValue, Refusal};
use std::collections::BTreeMap;

type Object = BTreeMap<String, JValue>;

fn missing() -> Refusal {
    Refusal::new("attachment_missing")
}

fn mismatch() -> Refusal {
    Refusal::new("attachment_mismatch")
}

fn schema() -> Refusal {
    Refusal::new("schema")
}

fn bytes(attachments: &Object, name: &str, inputs: &str) -> Checked<Vec<u8>> {
    let value = attachments.get(name).ok_or_else(missing)?;
    let raw = value.str().and_then(encoding::base64_decode).ok_or(Refusal::new("malformed_input"))?;
    if encoding::hashstr(&raw) != inputs {
        return Err(mismatch());
    }
    Ok(raw)
}

fn document(attachments: &Object, name: &str, hash: &str) -> Checked<Doc> {
    let value = attachments.get(name).ok_or_else(missing)?;
    if genesis::doc_hash(value).ok().as_deref() != Some(hash) {
        return Err(mismatch());
    }
    genesis::check_alone(value).map_err(|_| mismatch())?;
    render_genesis::read(value).map_err(|_| mismatch())
}

fn act(value: Option<&JValue>, registry: &Registry, wanted: &[&str]) -> Checked<ParsedAct> {
    let text = value.and_then(JValue::str).ok_or_else(mismatch)?;
    acts::parse(text, registry, wanted, None).map_err(|_| mismatch())
}

/// `{receipt id: line 1}` of the JWS list `name`: exactly one per id in `ids`, each passing `accept`.
fn act_list(
    attachments: &Object,
    name: &str,
    ids: &[&str],
    registry: &Registry,
    accept: impl Fn(&ParsedAct) -> bool,
) -> Checked<BTreeMap<String, String>> {
    let items = attachments.get(name).ok_or_else(missing)?.list().ok_or_else(mismatch)?;
    let parsed = items.iter().map(|item| act(Some(item), registry, &methods::PRIMARIES)).collect::<Checked<Vec<_>>>()?;
    let mut got: Vec<&str> = parsed.iter().map(|p| p.id.as_str()).collect();
    let mut want: Vec<&str> = ids.to_vec();
    got.sort_unstable();
    want.sort_unstable();
    if got != want || !parsed.iter().all(accept) {
        return Err(mismatch());
    }
    let mut lines = BTreeMap::new();
    for item in &parsed {
        lines.insert(item.id.clone(), render_lines::first_line(&item.method, &item.payload, &Facts::default())?);
    }
    Ok(lines)
}

fn act_object(payload: &Object) -> Option<&JValue> {
    payload.get("ext").and_then(|e| e.get(EXT_KEY))
}

fn id_list<'a>(body: &'a JValue, key: &str) -> Option<Vec<&'a str>> {
    Some(body.get(key)?.list()?.iter().filter_map(JValue::str).collect())
}

fn resolve_facts(payload: &Object, attachments: &Object, registry: &Registry) -> Checked<Facts> {
    let body = act_object(payload).and_then(|a| a.get("body")).ok_or_else(schema)?;
    let parent = payload.get("parent_receipt_hash").and_then(JValue::str).ok_or_else(schema)?;
    let candidates = id_list(body, "candidates").ok_or_else(schema)?;
    let heads = id_list(body, "heads").ok_or_else(schema)?;
    let mut facts = Facts::default();
    facts.candidates = act_list(attachments, "candidates", &candidates, registry, |p| p.parent.as_deref() == Some(parent))?;
    facts.heads = act_list(attachments, "heads", &heads, registry, |_| true)?;
    Ok(facts)
}

fn endorse_facts(payload: &Object, attachments: &Object, registry: &Registry) -> Checked<Facts> {
    let act_obj = act_object(payload).ok_or_else(schema)?;
    let attached = attachments.get("act").ok_or_else(missing)?;
    let endorsed = act(Some(attached), registry, &methods::CHAIN_ACTS)?;
    let same = |value: Option<&str>, other: Option<&str>| value.is_some() && value == other;
    if !same(Some(&endorsed.id), act_obj.get("body").and_then(|b| b.get("act")).and_then(JValue::str))
        || !same(payload.get("parent_receipt_hash").and_then(JValue::str), Some(&endorsed.id))
        || !same(payload.get("parent_performer_id").and_then(JValue::str), Some(&endorsed.performer))
        || !same(endorsed.parent.as_deref(), act_obj.get("head").and_then(|h| h.get("id")).and_then(JValue::str))
    {
        return Err(mismatch());
    }
    let mut inner = Facts::default();
    if endorsed.method == methods::RESOLVE {
        inner = resolve_facts(&endorsed.payload, attachments, registry)?;
    } else if attachments.contains_key("candidates") || attachments.contains_key("heads") {
        return Err(mismatch());
    }
    Ok(Facts {
        endorsed_line1: Some(render_lines::first_line(&endorsed.method, &endorsed.payload, &inner)?),
        endorsed_lines: render_lines::method_lines(&endorsed.method, &endorsed.payload, &inner)?,
        ..Facts::default()
    })
}

fn check_act(payload: &Object, kid: &str, registry: &Registry, head_present: Option<bool>) -> Checked<()> {
    acts::check_act_object(payload, kid, registry, head_present)?;
    if payload.get("method").and_then(JValue::str) == Some(methods::RESOLVE) {
        let body = act_object(payload).and_then(|a| a.get("body"));
        let choose = body.and_then(|b| b.get("choose")).and_then(JValue::str);
        let listed = body.and_then(|b| b.get("candidates")).and_then(JValue::list);
        match (choose, listed) {
            (Some(choose), Some(list)) if list.iter().any(|c| c.str() == Some(choose)) => {}
            _ => return Err(Refusal::new("body_schema")),
        }
    }
    Ok(())
}

fn lay_out(payload: &Object, first: String, body: Vec<String>) -> Checked<Rendered> {
    let act = act_object(payload).and_then(JValue::dict).ok_or_else(schema)?;
    let text = |o: &Object, key: &str| o.get(key).and_then(JValue::str).map(str::to_string);
    let (Some(method), Some(org), Some(performer), Some(kid), Some(ts)) =
        (text(payload, "method"), text(act, "org"), text(payload, "performer_id"), text(act, "kid"), text(payload, "ts"))
    else {
        return Err(schema());
    };
    let expires = text(act, "expires");
    let parent = text(payload, "parent_receipt_hash");
    let head = act.get("head").and_then(|h| h.get("id")).and_then(JValue::str).map(str::to_string);
    frame(Frame {
        first,
        method: &method,
        org: &org,
        performer: &performer,
        kid: &kid,
        body,
        ts: &ts,
        expires: expires.as_deref(),
        parent: parent.as_deref(),
        head: head.as_deref(),
        sender: methods::is_verdict(&method),
    })
}

/// The `Rendered` of an input (RN-01), or a `Refusal` with the code of section 11.
pub fn render(input: &RenderInput) -> Checked<Rendered> {
    let registry = Registry::standard();
    let method = input.method.as_str();
    acts::check_envelope(&input.payload)?;
    let payload = input.payload.dict().filter(|p| p.get("method").and_then(JValue::str) == Some(method)).ok_or_else(schema)?;
    if !registry.methods.contains_key(method) {
        return Err(Refusal::new("method_unknown"));
    }
    let attachments = input.attachments.dict().ok_or_else(schema)?;
    let inputs = payload.get("inputs_hash").and_then(JValue::str).ok_or_else(schema)?;

    if method == methods::GENESIS_SIGN {
        let doc = document(attachments, "document", inputs)?;
        // RN-09 Order of checks: the document fixes whether a head is due, and the act object's form
        // (head presence included) is decided before `previous` is read.
        check_act(payload, &input.kid, registry, Some(doc.prev.is_some()))?;
        let previous = match doc.prev.as_deref() {
            Some(prev) => Some(document(attachments, "previous", prev)?),
            None => None,
        };
        let head = act_object(payload).and_then(|a| a.get("head")).and_then(|h| h.get("id")).and_then(JValue::str);
        if let Some(head) = head {
            if Some(head) != doc.head.as_deref() {
                return Err(mismatch());
            }
        }
        let first = render_genesis::summary(&doc, previous.as_ref())?;
        let body = render_genesis::lines(&doc, previous.as_ref())?;
        return lay_out(payload, first, body);
    }
    check_act(payload, &input.kid, registry, None)?;
    let mut facts = Facts::default();
    if methods::is_verdict(method) {
        facts.raw = Some(bytes(attachments, "request_b64", inputs)?);
    } else if method == methods::PROMOTE {
        facts.raw = Some(bytes(attachments, "record_body_b64", inputs)?);
    } else if method == methods::DECISION {
        facts.raw = Some(bytes(attachments, "decision_b64", inputs)?);
    } else if method == methods::RESOLVE {
        facts = resolve_facts(payload, attachments, registry)?;
    } else if method == methods::ENDORSE {
        facts = endorse_facts(payload, attachments, registry)?;
    }
    let first = render_lines::first_line(method, payload, &facts)?;
    let body = render_lines::method_lines(method, payload, &facts)?;
    lay_out(payload, first, body)
}
