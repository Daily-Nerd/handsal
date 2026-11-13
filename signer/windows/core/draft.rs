//! The draft a caller hands the signer (SG-04): facts only, never derived values or words.
//!
//! Invariants: the draft is a closed object `{body, expires_in_s?, head?, method, org, parent?}`
//! plus, for a verdict, the act-object keys the registry gives that method (`recipient`, `relay`,
//! `request_id`). Each optional key is present exactly where its method has it, and the registry
//! says where: `expires_in_s` iff the method carries `expires`, a verdict key iff it is in the
//! method's `act_extra_keys`, `head` per its head rule, `parent` where ACT-13 gives the method a
//! parent. The body satisfies the method's closed schema.
//! The signer owns `performer_id`, `kid`, `ts`, `nonce`, `expires`, every pinned constant and both
//! hashes; a draft key outside the closed set (`ts`, `nonce`, `inputs_hash`, display text, an
//! authentication handle, anything else) is `schema_refused`.
//! Failure modes: `schema_refused`, `unsupported_method`, `attachment_missing`,
//! `attachment_mismatch`, `identity_mismatch`; all exit 2.

use crate::acts::chain_head_node;
use crate::emit;
use crate::encoding;
use crate::forms;
use crate::genesis;
use crate::methods::{self, ParentRule};
use crate::registry::schema;
use crate::registry::{HeadRule, Registry};
use crate::value::{Checked, JValue, Refusal};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftParent {
    pub id: String,
    pub performer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Draft {
    pub method: String,
    pub org: String,
    pub body: JValue,
    pub head: Option<JValue>,
    pub parent: Option<DraftParent>,
    pub expires_in_s: Option<i64>,
    pub recipient: Option<String>,
    pub relay: Option<String>,
    pub request_id: Option<String>,
}

fn refused() -> Refusal {
    Refusal::new("schema_refused")
}

/// The act-object keys of a method that a draft supplies: everything but `expires`, which the
/// signer computes from `expires_in_s`.
fn draft_act_keys<'a>(spec_keys: &'a [String]) -> impl Iterator<Item = &'a str> {
    spec_keys.iter().map(String::as_str).filter(|k| *k != "expires")
}

impl Draft {
    pub fn read(value: &JValue) -> Checked<Draft> {
        let registry = Registry::standard();
        let members = value.dict().ok_or_else(refused)?;
        // The closed key set is the base set plus every verdict key the registry names anywhere.
        let mut allowed: BTreeSet<&str> = BTreeSet::from(["body", "expires_in_s", "head", "method", "org", "parent"]);
        for spec in registry.methods.values() {
            allowed.extend(draft_act_keys(&spec.act_extra_keys));
        }
        if !members.keys().all(|k| allowed.contains(k.as_str())) {
            return Err(refused());
        }
        let (Some(method), Some(body), Some(org)) =
            (members.get("method").and_then(JValue::str), members.get("body"), members.get("org").and_then(JValue::str))
        else {
            return Err(refused());
        };
        let spec = registry.methods.get(method).ok_or(Refusal::new("unsupported_method"))?;
        if !forms::is_hashstr(org) {
            return Err(refused());
        }

        let mut expires_in_s = None;
        if spec.act_extra_keys.iter().any(|k| k == "expires") {
            let text = members.get("expires_in_s").and_then(JValue::str).filter(|t| forms::is_decimal(t)).ok_or_else(refused)?;
            let n: i64 = text.parse().map_err(|_| refused())?;
            if n < 1 || n > registry.number("MAX_EXPIRES_IN_S") {
                return Err(refused());
            }
            expires_in_s = Some(n);
        } else if members.contains_key("expires_in_s") {
            return Err(refused());
        }

        let mut verdict: BTreeMap<&str, String> = BTreeMap::new();
        let mine: Vec<&str> = draft_act_keys(&spec.act_extra_keys).collect();
        for key in &allowed {
            if matches!(*key, "body" | "expires_in_s" | "head" | "method" | "org" | "parent") {
                continue;
            }
            match (mine.contains(key), members.get(*key)) {
                (true, Some(JValue::String(text))) => {
                    let form = registry.act_extra_key_types.get(*key).ok_or(Refusal::new("internal"))?;
                    if !form.accepts(text) {
                        return Err(refused());
                    }
                    verdict.insert(key, text.clone());
                }
                (false, None) => {}
                _ => return Err(refused()),
            }
        }

        match (spec.head, members.get("head")) {
            (HeadRule::Always, None) | (HeadRule::Never, Some(_)) => return Err(refused()),
            _ => {}
        }
        let head = members.get("head").cloned();
        if let Some(given) = &head {
            if !schema::defects(&chain_head_node(), given, registry, "schema").is_empty() {
                return Err(refused());
            }
        }

        let rule = methods::parent_rule(method);
        let parent = if rule == ParentRule::None {
            if members.contains_key("parent") {
                return Err(refused());
            }
            None
        } else {
            let p = members.get("parent").and_then(JValue::dict).filter(|p| p.len() == 2 && p.contains_key("id") && p.contains_key("performer"));
            let p = p.ok_or_else(refused)?;
            let id = p["id"].str().filter(|id| forms::is_hashstr(id)).ok_or_else(refused)?;
            let performer = match &p["performer"] {
                JValue::String(who) if forms::is_member_id(who) => Some(who.clone()),
                JValue::Null if rule == ParentRule::Primary => None,
                _ => return Err(refused()),
            };
            Some(DraftParent { id: id.to_string(), performer })
        };

        if !schema::defects(&spec.body, body, registry, "body_schema").is_empty() {
            return Err(refused());
        }
        Ok(Draft {
            method: method.to_string(),
            org: org.to_string(),
            body: body.clone(),
            head,
            parent,
            expires_in_s,
            recipient: verdict.remove("recipient"),
            relay: verdict.remove("relay"),
            request_id: verdict.remove("request_id"),
        })
    }
}

/// The values `emit` takes from the caller, and the values `sign` takes from the signer itself.
#[derive(Debug, Clone)]
pub struct Fixed {
    pub kid: String,
    pub nonce: String,
    pub performer: String,
    pub ts: String,
}

fn raw_bytes(files: &BTreeMap<String, JValue>, name: &str) -> Checked<Vec<u8>> {
    let value = files.get(name).ok_or(Refusal::new("attachment_missing"))?;
    value.str().and_then(encoding::base64_decode).ok_or_else(refused)
}

/// The payload the signer would sign for `draft`. `attachments` supply the bytes both hashes derive
/// from; nothing here trusts a hash the caller wrote. `fixed.performer` is the person bound to the
/// key: a verdict addressed to anyone else is `identity_mismatch` (SG-04).
pub fn build(draft: &Draft, attachments: &JValue, fixed: &Fixed) -> Checked<JValue> {
    let registry = Registry::standard();
    let files = attachments.dict().ok_or_else(refused)?;
    let start = match forms::epoch_seconds(&fixed.ts) {
        Some(start) if forms::is_b64u32(&fixed.kid) && encoding::is_hashstr(&fixed.nonce) && forms::is_member_id(&fixed.performer) => start,
        _ => return Err(refused()),
    };
    let spec = registry.methods.get(&draft.method).ok_or(Refusal::new("unsupported_method"))?;
    if draft.recipient.as_deref().map_or(false, |recipient| recipient != fixed.performer) {
        return Err(Refusal::new("identity_mismatch"));
    }

    let mut head_due = spec.head == HeadRule::Always;
    let mut derived_org: Option<String> = None;
    let inputs = match spec.inputs_hash.as_str() {
        "empty" => encoding::empty_hash(),
        "raw_request_bytes" => encoding::hashstr(&raw_bytes(files, "request_b64")?),
        "raw_record_body_bytes" => encoding::hashstr(&raw_bytes(files, "record_body_b64")?),
        "jcs_genesis_document" => {
            let document = files.get("document").ok_or(Refusal::new("attachment_missing"))?;
            let mismatch = || Refusal::new("attachment_mismatch");
            let prev = document.get("prev").ok_or_else(mismatch)?;
            let hash = encoding::hashstr(&emit::subset(document).map_err(|_| mismatch())?);
            head_due = !prev.is_null();
            // SG-13: the org is derived from the document, never taken from the draft.
            derived_org = Some(if prev.is_null() { hash.clone() } else { document.get("org").and_then(JValue::str).ok_or_else(mismatch)?.to_string() });
            hash
        }
        _ => return Err(Refusal::new("internal")),
    };
    if draft.head.is_some() != head_due {
        return Err(refused());
    }
    if derived_org.as_deref().map_or(false, |org| org != draft.org) {
        return Err(Refusal::new("attachment_mismatch"));
    }

    let mut act: BTreeMap<String, JValue> = BTreeMap::from([
        ("body".to_string(), draft.body.clone()),
        ("kid".to_string(), JValue::string(&fixed.kid)),
        ("org".to_string(), JValue::string(&draft.org)),
    ]);
    if let Some(head) = &draft.head {
        act.insert("head".to_string(), head.clone());
    }
    if let Some(seconds) = draft.expires_in_s {
        act.insert("expires".to_string(), JValue::String(forms::time(start + seconds)));
    }
    for (key, value) in [("recipient", &draft.recipient), ("relay", &draft.relay), ("request_id", &draft.request_id)] {
        if let Some(text) = value {
            act.insert(key.to_string(), JValue::string(text));
        }
    }

    let text_or_null = |value: Option<&String>| value.map_or(JValue::Null, |s| JValue::string(s));
    let parent_performer = draft.parent.as_ref().and_then(|p| p.performer.as_ref());
    let parent_id = draft.parent.as_ref().map(|p| &p.id);
    Ok(JValue::Object(BTreeMap::from([
        ("action_ref".to_string(), JValue::Null),
        ("binding".to_string(), JValue::string("local")),
        (
            "cost".to_string(),
            JValue::Object(BTreeMap::from([
                ("rail_ref".to_string(), JValue::Null),
                ("tokens".to_string(), JValue::string("0")),
                ("usd_micros".to_string(), JValue::string("0")),
                ("wall_ms".to_string(), JValue::string("0")),
            ])),
        ),
        ("ext".to_string(), JValue::Object(BTreeMap::from([("dev.handsal/act".to_string(), JValue::Object(act))]))),
        ("inputs_hash".to_string(), JValue::String(inputs)),
        ("log_policy".to_string(), JValue::string("best_effort")),
        ("method".to_string(), JValue::string(&draft.method)),
        ("nonce".to_string(), JValue::string(&fixed.nonce)),
        ("outputs_hash".to_string(), JValue::String(outputs_hash(&spec.outputs_hash, draft.request_id.as_deref())?)),
        ("parent_performer_id".to_string(), text_or_null(parent_performer)),
        ("parent_receipt_hash".to_string(), text_or_null(parent_id)),
        ("performer_id".to_string(), JValue::string(&fixed.performer)),
        ("reason".to_string(), JValue::Null),
        ("requester_id".to_string(), JValue::Null),
        ("status".to_string(), JValue::string("OK")),
        ("ts".to_string(), JValue::string(&fixed.ts)),
        ("v".to_string(), JValue::string("vitni/0.2")),
    ])))
}

/// The hashstr of a genesis document, shared with the renderer; exposed for callers that derive
/// `org` the same way (SG-13).
pub fn document_hash(document: &JValue) -> Checked<String> {
    genesis::doc_hash(document)
}

/// `outputs_hash` as the registry derives it (ACT-09, VR-07): EMPTY_HASH, or for `verdict:V`
/// hashstr(JCS({"request_id":R,"verdict":V})). One owner; an unknown rule is `internal`.
fn outputs_hash(rule: &str, request_id: Option<&str>) -> Checked<String> {
    if rule == "empty" {
        return Ok(encoding::empty_hash());
    }
    let (Some(verdict), Some(request_id)) = (rule.strip_prefix("verdict:"), request_id) else {
        return Err(Refusal::new("internal"));
    };
    let object = JValue::Object(BTreeMap::from([
        ("request_id".to_string(), JValue::string(request_id)),
        ("verdict".to_string(), JValue::string(verdict)),
    ]));
    Ok(encoding::hashstr(&emit::subset(&object)?))
}
