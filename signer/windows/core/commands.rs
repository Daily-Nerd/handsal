//! The signer commands that need no key backend: `emit` (SG-01) and the draft form of `render`
//! (RN-01, SG-04). Each is a function from one parsed input object to one result object.

use crate::agree;
use crate::cli::Environment;
use crate::draft::{self, Draft, Fixed};
use crate::forms;
use crate::render::RenderInput;
use crate::render_attach;
use crate::value::{Checked, JValue, Refusal};
use std::collections::BTreeSet;

fn refused() -> Refusal {
    Refusal::new("schema_refused")
}

fn closed<'a>(input: &'a JValue, keys: &[&str]) -> Checked<&'a std::collections::BTreeMap<String, JValue>> {
    let top = input.dict().ok_or_else(refused)?;
    let have: BTreeSet<&str> = top.keys().map(String::as_str).collect();
    if have != keys.iter().copied().collect::<BTreeSet<_>>() {
        return Err(refused());
    }
    Ok(top)
}

/// `emit` (SG-01): `{attachments, draft, fixed}` in, `{payload_hex}` out. It never signs, so the
/// caller may choose `fixed = {kid, nonce, performer, ts}` here and nowhere else.
pub fn emit(input: &JValue) -> Checked<JValue> {
    let top = closed(input, &["attachments", "draft", "fixed"])?;
    let f = closed(&top["fixed"], &["kid", "nonce", "performer", "ts"])?;
    let text = |key: &str| f[key].str().map(str::to_string).ok_or_else(refused);
    let fixed = Fixed { kid: text("kid")?, nonce: text("nonce")?, performer: text("performer")?, ts: text("ts")? };
    let payload = draft::build(&Draft::read(&top["draft"])?, &top["attachments"], &fixed)?;
    let hex: String = crate::emit::subset(&payload)?.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(JValue::Object([("payload_hex".to_string(), JValue::String(hex))].into()))
}

/// `render` (SG-01, SG-04): `{attachments, draft}` in, `{first_line, text}` out: the text of the
/// payload the signer would sign. The signer fills performer, kid, ts and nonce itself, so a key
/// must be bound first.
pub fn render(input: &JValue, environment: &Environment) -> Checked<JValue> {
    let top = closed(input, &["attachments", "draft"])?;
    let draft = Draft::read(&top["draft"])?;
    let identity = environment.identity.as_ref().ok_or(Refusal::new("key_unavailable"))?;
    let fixed = Fixed {
        kid: identity.kid.clone(),
        nonce: environment.nonce()?,
        performer: identity.performer.clone(),
        ts: forms::time(environment.now()),
    };
    let payload = draft::build(&draft, &top["attachments"], &fixed)?;
    let rendered = render_attach::render(&RenderInput {
        attachments: top["attachments"].clone(),
        kid: identity.kid.clone(),
        method: draft.method.clone(),
        payload,
    })?;
    Ok(JValue::Object(
        [("first_line".to_string(), JValue::String(rendered.first_line)), ("text".to_string(), JValue::String(rendered.text))].into(),
    ))
}

/// `agree` (SG-16, SG-08 order): the form of `{context, peer}` first, then the bound key, then the derivation. It
/// needs no prompt, no display and no sensor, and it reads nothing of a signing key.
pub fn agree(input: &JValue, environment: &Environment) -> Checked<JValue> {
    let top = closed(input, &["context", "peer"])?;
    let context = top["context"].str().filter(|c| forms::is_agree_context(c)).ok_or_else(refused)?;
    let peer = agree::point_of(&top["peer"]).ok_or_else(refused)?;
    let key = environment.agreement_key().ok_or(Refusal::new("key_unavailable"))?;
    agree::derive(key, &peer, context)
}
