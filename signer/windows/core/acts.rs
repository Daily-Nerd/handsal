//! The act envelope (ACT-01, ACT-06, ACT-08, ACT-13, ACT-14): `check-act` steps 3 and 5.
//!
//! Step 3 checks the envelope alone: the 17 keys, the constants, the forms of the envelope fields
//! and the shape of `ext`. Step 5 checks the act object once the method is known: its closed key
//! set, `head`, the extra keys of the method, the per-method parent fields (ACT-13), the signer
//! kid (ACT-14), then the body. Every defect is `schema` except a body structure defect, which is
//! `body_schema`; `schema` is reported first.

use crate::encoding;
use crate::forms;
use crate::limits::MAX_PAYLOAD;
use crate::methods::{self, ParentRule};
use crate::registry::schema;
use crate::registry::{Form, HeadRule, Registry, SchemaNode};
use crate::subset::{self, SubsetFailure};
use crate::value::{Checked, JValue, Refusal};
use std::collections::BTreeMap;

pub const EXT_KEY: &str = "dev.handsal/act";

const KEYS: [&str; 17] = [
    "action_ref",
    "binding",
    "cost",
    "ext",
    "inputs_hash",
    "log_policy",
    "method",
    "nonce",
    "outputs_hash",
    "parent_performer_id",
    "parent_receipt_hash",
    "performer_id",
    "reason",
    "requester_id",
    "status",
    "ts",
    "v",
];

const CONSTANTS: [(&str, &str); 4] = [("v", "vitni/0.2"), ("binding", "local"), ("status", "OK"), ("log_policy", "best_effort")];

fn refuse() -> Refusal {
    Refusal::new("schema")
}

fn cost() -> JValue {
    JValue::Object(BTreeMap::from([
        ("rail_ref".to_string(), JValue::Null),
        ("tokens".to_string(), JValue::string("0")),
        ("usd_micros".to_string(), JValue::string("0")),
        ("wall_ms".to_string(), JValue::string("0")),
    ]))
}

fn head_node() -> SchemaNode {
    SchemaNode::keys(vec![("id", SchemaNode::Leaf(Form::Hashstr)), ("kind", SchemaNode::Const("chain".to_string()))])
}

/// The ACT-08 head object `{id, kind: "chain"}`, as a schema node (the draft shares it).
pub fn chain_head_node() -> SchemaNode {
    head_node()
}

fn nullable(value: Option<&JValue>, accepts: fn(&str) -> bool) -> bool {
    match value {
        Some(JValue::Null) => true,
        Some(JValue::String(s)) => accepts(s),
        _ => false,
    }
}

/// Step 3: ACT-01 constants and key set, ACT-07 forms of envelope fields, shape of `ext`.
pub fn check_envelope(value: &JValue) -> Checked<()> {
    let p = value.dict().ok_or_else(refuse)?;
    if p.len() != KEYS.len() || !KEYS.iter().all(|k| p.contains_key(*k)) {
        return Err(refuse());
    }
    for (key, want) in CONSTANTS {
        if p[key].str() != Some(want) {
            return Err(refuse());
        }
    }
    for key in ["reason", "action_ref", "requester_id"] {
        if !p[key].is_null() {
            return Err(refuse());
        }
    }
    if p["cost"] != cost() || p["method"].str().is_none() {
        return Err(refuse());
    }
    for key in ["inputs_hash", "outputs_hash", "nonce"] {
        if !p[key].str().map_or(false, forms::is_hashstr) {
            return Err(refuse());
        }
    }
    if !nullable(p.get("parent_receipt_hash"), forms::is_hashstr) || !nullable(p.get("parent_performer_id"), forms::is_member_id) {
        return Err(refuse());
    }
    if !p["performer_id"].str().map_or(false, forms::is_member_id) || !p["ts"].str().map_or(false, forms::is_time) {
        return Err(refuse());
    }
    let ext = p["ext"].dict().ok_or_else(refuse)?;
    if ext.len() != 1 || ext.get(EXT_KEY).and_then(JValue::dict).is_none() {
        return Err(refuse());
    }
    Ok(())
}

fn parents_ok(method: &str, p: &BTreeMap<String, JValue>) -> bool {
    let parent = p.get("parent_receipt_hash").map_or(true, JValue::is_null);
    let performer = p.get("parent_performer_id").map_or(true, JValue::is_null);
    match methods::parent_rule(method) {
        ParentRule::None => parent && performer,
        ParentRule::Primary => !parent,
        ParentRule::Endorse => !parent && !performer,
    }
}

/// Step 5 for a payload whose envelope passed step 3 and whose method is in the registry.
/// `head_present` says whether a conditional `head` (genesis.sign) is due, and must be given for it.
pub fn check_act_object(
    payload: &BTreeMap<String, JValue>,
    header_kid: &str,
    registry: &Registry,
    head_present: Option<bool>,
) -> Checked<()> {
    let name = payload.get("method").and_then(JValue::str).ok_or_else(refuse)?;
    let spec = registry.methods.get(name).ok_or_else(refuse)?;
    let act = payload.get("ext").and_then(|e| e.get(EXT_KEY)).filter(|a| a.dict().is_some()).ok_or_else(refuse)?;
    let mut members: BTreeMap<String, SchemaNode> = BTreeMap::from([
        ("body".to_string(), SchemaNode::Scoped("body_schema", Box::new(spec.body.clone()))),
        ("kid".to_string(), SchemaNode::Leaf(Form::Kid)),
        ("org".to_string(), SchemaNode::Leaf(Form::Hashstr)),
    ]);
    match spec.head {
        HeadRule::Always => {
            members.insert("head".to_string(), head_node());
        }
        HeadRule::Never => {}
        HeadRule::Conditional => {
            // A caller that does not know whether the head is due has a bug: fail loudly as `internal`.
            let due = head_present.ok_or(Refusal::new("internal"))?;
            if due {
                members.insert("head".to_string(), head_node());
            }
        }
    }
    for key in &spec.act_extra_keys {
        let form = registry.act_extra_key_types.get(key).ok_or(Refusal::new("internal"))?;
        members.insert(key.clone(), SchemaNode::Leaf(*form));
    }
    let mut found = schema::defects(&SchemaNode::Keys(members), act, registry, "schema");
    if !parents_ok(name, payload) {
        found.push("schema");
    }
    if act.get("kid").and_then(JValue::str) != Some(header_kid) {
        found.push("schema");
    }
    schema::refuse(&found)
}

/// An act read once: the JWS shape and header (ACT-02, ACT-03), the canonical payload, the
/// envelope, the method, the act object with its closed body, and the hashes a method fixes to the
/// empty hash. Nothing here reads a key, a state or a clock. The receipt id is the identity
/// (ACT-12): two texts of one payload differ only by their signature.
#[derive(Debug, Clone)]
pub struct ParsedAct {
    pub payload: BTreeMap<String, JValue>,
    pub method: String,
    pub id: String,
    pub performer: String,
    pub parent: Option<String>,
}

fn shape() -> Refusal {
    Refusal::new("jws_shape")
}

fn jws_parts(text: &str) -> Checked<(String, Vec<u8>)> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 3 {
        return Err(shape());
    }
    let mut decoded = Vec::new();
    for part in &parts {
        decoded.push(encoding::base64url_decode(part).ok_or_else(shape)?);
    }
    let prefix = br#"{"alg":"ES256","kid":""#;
    let header = &decoded[0];
    if header.len() != prefix.len() + 43 + 2 || !header.starts_with(prefix) || !header.ends_with(br#""}"#) {
        return Err(shape());
    }
    let kid = String::from_utf8_lossy(&header[prefix.len()..prefix.len() + 43]).to_string();
    if !forms::is_b64u32(&kid) || decoded[2].len() != 64 {
        return Err(shape());
    }
    Ok((kid, decoded.swap_remove(1)))
}

/// The `ParsedAct` of `text`, whose method must be in `wanted`, else a `Refusal`.
pub fn parse(text: &str, registry: &Registry, wanted: &[&str], head_present: Option<bool>) -> Checked<ParsedAct> {
    let (kid, payload_bytes) = jws_parts(text)?;
    let value = match subset::parse(&payload_bytes, MAX_PAYLOAD) {
        Ok(v) => v,
        Err(SubsetFailure::TooLarge) => return Err(Refusal::new("payload_too_large")),
        Err(SubsetFailure::NotCanonical) => return Err(Refusal::new("payload_not_canonical_subset")),
    };
    let payload = value.dict().ok_or(Refusal::new("payload_not_canonical_subset"))?;
    check_envelope(&value)?;
    let method = payload["method"].str().ok_or_else(refuse)?;
    let spec = match registry.methods.get(method) {
        Some(spec) if wanted.contains(&method) => spec,
        _ => return Err(Refusal::new("method_unknown")),
    };
    check_act_object(payload, &kid, registry, head_present)?;
    let empty = JValue::String(encoding::empty_hash());
    if spec.inputs_hash == "empty" && payload["inputs_hash"] != empty {
        return Err(refuse());
    }
    if spec.outputs_hash == "empty" && payload["outputs_hash"] != empty {
        return Err(refuse());
    }
    let field = |key: &str| payload.get(key).and_then(JValue::str).map(str::to_string);
    Ok(ParsedAct {
        payload: payload.clone(),
        method: method.to_string(),
        id: encoding::hashstr(&payload_bytes),
        performer: field("performer_id").ok_or_else(refuse)?,
        parent: field("parent_receipt_hash"),
    })
}
