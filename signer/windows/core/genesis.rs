//! Genesis document validation (GP-01, GP-15 steps 1 and 3, GP-18, KC-05, KC-08), for a renderer
//! that holds a document and no lineage (RN-09).
//!
//! `check_alone` checks one document by itself in the order GP-15 fixes and refuses with the reason
//! code of the first failing check:
//!   step 1, structure   `genesis_schema`, `doc_not_sorted`, `genesis_key_invalid`, `duplicate_key`;
//!                       each pass covers the whole document before the next begins
//!   step 3, policy      `policy::validate` (its codes), then a listed device of a class the policy
//!                       does not accept (`genesis_schema`), `role_key_class`, `fixture_key`
//! Step 2 (profile) and the lineage steps belong to the fold, so an unimplemented profile is no
//! defect here. Step 3 runs under the profile the document names: strict (fixture keys refused)
//! unless it names the fixture profile or none this build implements.

use crate::devicekey;
use crate::emit;
use crate::encoding;
use crate::forms;
use crate::policy;
use crate::profiles::{Edition, Profiles};
use crate::registry::Registry;
use crate::value::{Checked, JValue, Refusal};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: &str = "handsal-genesis/1";
const BASE_KEYS: [&str; 7] = ["devices", "members", "name", "org", "prev", "profile", "v"];
const DEVICE_KEYS: [&str; 6] = ["agree", "class", "kid", "label", "person", "sign"];

fn schema() -> Refusal {
    Refusal::new("genesis_schema")
}

/// hashstr(JCS(doc)): the document hash, the org id of an original, and a change's `prev`.
pub fn doc_hash(doc: &JValue) -> Checked<String> {
    Ok(encoding::hashstr(&emit::subset(doc)?))
}

fn string<'a>(value: Option<&'a JValue>) -> Option<&'a str> {
    value.and_then(JValue::str)
}

fn is_hashstr(value: Option<&JValue>) -> bool {
    string(value).map_or(false, forms::is_hashstr)
}

fn keys_are(members: &BTreeMap<String, JValue>, expected: &[&str]) -> bool {
    members.len() == expected.len() && expected.iter().all(|k| members.contains_key(*k))
}

fn is_point_shape(value: Option<&JValue>) -> bool {
    value.and_then(JValue::dict).map_or(false, |m| keys_are(m, &["x", "y"]) && string(m.get("x")).is_some() && string(m.get("y")).is_some())
}

fn check_shape(value: &JValue) -> Checked<&BTreeMap<String, JValue>> {
    let doc = value.dict().filter(|_| emit::subset(value).is_ok()).ok_or_else(schema)?;
    let without_optional = doc.keys().filter(|k| *k != "policy" && *k != "head").count();
    if without_optional != BASE_KEYS.len() || !BASE_KEYS.iter().all(|k| doc.contains_key(*k)) {
        return Err(schema());
    }
    if string(doc.get("v")) != Some(VERSION)
        || !string(doc.get("name")).map_or(false, forms::is_org_name)
        || !string(doc.get("profile")).map_or(false, forms::is_hashstr)
    {
        return Err(schema());
    }
    if doc["prev"].is_null() {
        if !doc["org"].is_null() || doc.contains_key("head") {
            return Err(schema());
        }
    } else if !is_hashstr(doc.get("prev")) || !is_hashstr(doc.get("org")) || !is_hashstr(doc.get("head")) {
        return Err(schema());
    }
    let members = doc["members"].list().filter(|m| !m.is_empty()).ok_or_else(schema)?;
    let devices = doc["devices"].list().filter(|d| !d.is_empty()).ok_or_else(schema)?;
    let mut ids: Vec<&str> = Vec::new();
    for member in members {
        let m = member.dict().filter(|m| keys_are(m, &["id", "role"])).ok_or_else(schema)?;
        match (string(m.get("id")), string(m.get("role"))) {
            (Some(id), Some(role)) if forms::is_member_id(id) && forms::is_role_id(role) => ids.push(id),
            _ => return Err(schema()),
        }
    }
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(schema());
    }
    let mut persons = BTreeSet::new();
    for device in devices {
        let d = device.dict().filter(|d| keys_are(d, &DEVICE_KEYS)).ok_or_else(schema)?;
        let person = string(d.get("person")).filter(|p| ids.contains(p));
        if string(d.get("class")).is_none()
            || string(d.get("kid")).is_none()
            || !string(d.get("label")).map_or(false, forms::is_label)
            || person.is_none()
            || !is_point_shape(d.get("sign"))
            || !is_point_shape(d.get("agree"))
        {
            return Err(schema());
        }
        persons.insert(person.unwrap_or_default());
    }
    if persons != ids.iter().copied().collect::<BTreeSet<_>>() {
        return Err(schema());
    }
    Ok(doc)
}

fn ascending(values: &[&str]) -> bool {
    values.windows(2).all(|pair| pair[1].as_bytes() >= pair[0].as_bytes())
}

fn strings(value: Option<&JValue>) -> Option<Vec<&str>> {
    value?.list()?.iter().map(JValue::str).collect()
}

/// Every list of the policy that one byte form depends on, when it is well formed enough to be
/// ordered. A malformed policy is `policy_invalid` later, never `doc_not_sorted`.
fn policy_lists(policy: Option<&JValue>) -> Vec<Vec<&str>> {
    let Some(p) = policy.and_then(JValue::dict) else { return vec![] };
    let mut out = Vec::new();
    if let Some(classes) = p.get("classes").and_then(JValue::list) {
        let names: Vec<&str> = classes.iter().filter_map(|c| string(c.get("class"))).collect();
        if names.len() == classes.len() {
            out.push(names);
        }
    }
    if let Some(roles) = strings(p.get("roles")) {
        out.push(roles);
    }
    if let Some(relays) = strings(p.get("relays")) {
        out.push(relays);
    }
    if let Some(rules) = p.get("rules").and_then(JValue::dict) {
        for rule in rules.values() {
            if let Some(roles) = strings(rule.get("roles")) {
                out.push(roles);
            }
        }
    }
    out
}

fn check_sorted(doc: &BTreeMap<String, JValue>) -> Checked<()> {
    let members = doc.get("members").and_then(JValue::list).ok_or_else(schema)?;
    let devices = doc.get("devices").and_then(JValue::list).ok_or_else(schema)?;
    let mut lists: Vec<Vec<&str>> = vec![
        members.iter().filter_map(|m| string(m.get("id"))).collect(),
        devices.iter().filter_map(|d| string(d.get("kid"))).collect(),
    ];
    lists.extend(policy_lists(doc.get("policy")));
    if lists.iter().all(|l| ascending(l)) {
        Ok(())
    } else {
        Err(Refusal::new("doc_not_sorted"))
    }
}

fn check_keys(doc: &BTreeMap<String, JValue>) -> Checked<()> {
    let devices = doc.get("devices").and_then(JValue::list).ok_or_else(schema)?;
    let mut kids: Vec<&str> = Vec::new();
    let mut agrees: Vec<&JValue> = Vec::new();
    for device in devices {
        let (Some(kid), Some(sign), Some(agree)) = (string(device.get("kid")), device.get("sign"), device.get("agree")) else {
            return Err(schema());
        };
        if devicekey::defect(kid, sign, agree).is_some() {
            return Err(Refusal::new("genesis_key_invalid"));
        }
        kids.push(kid);
        agrees.push(agree);
    }
    let mut unique: Vec<&JValue> = Vec::new();
    for agree in &agrees {
        if !unique.contains(agree) {
            unique.push(agree);
        }
    }
    if kids.iter().collect::<BTreeSet<_>>().len() != kids.len() || unique.len() != agrees.len() {
        return Err(Refusal::new("duplicate_key"));
    }
    Ok(())
}

fn check_devices_against_policy(doc: &BTreeMap<String, JValue>, registry: &Registry, fixture: bool) -> Checked<()> {
    let policy = doc.get("policy").and_then(JValue::dict).ok_or_else(schema)?;
    let classes = policy.get("classes").and_then(JValue::list).ok_or_else(schema)?;
    let rules = policy.get("rules").and_then(JValue::dict).ok_or_else(schema)?;
    let members = doc.get("members").and_then(JValue::list).ok_or_else(schema)?;
    let devices = doc.get("devices").and_then(JValue::list).ok_or_else(schema)?;
    let accepted: BTreeSet<&str> = classes.iter().filter_map(|c| string(c.get("class"))).collect();
    let mut holder_roles: BTreeSet<&str> = BTreeSet::new();
    for rule in rules.values() {
        if let Some(roles) = strings(rule.get("roles")) {
            holder_roles.extend(roles);
        }
    }
    let holders: BTreeSet<&str> = members
        .iter()
        .filter_map(|m| match (string(m.get("id")), string(m.get("role"))) {
            (Some(id), Some(role)) if holder_roles.contains(role) => Some(id),
            _ => None,
        })
        .collect();
    for device in devices {
        let (Some(class), Some(person)) = (string(device.get("class")), string(device.get("person"))) else {
            return Err(schema());
        };
        if !accepted.contains(class) {
            return Err(schema());
        }
        let strong = registry.lookup_class(class, fixture).and_then(|c| c.user_verification.as_deref()) == Some("biometric_only");
        if holders.contains(person) && !strong {
            return Err(Refusal::new("role_key_class"));
        }
    }
    Ok(())
}

fn check_fixture_keys(doc: &BTreeMap<String, JValue>, edition: &Edition) -> Checked<()> {
    let devices = doc.get("devices").and_then(JValue::list).ok_or_else(schema)?;
    let witness = doc.get("policy").and_then(|p| p.get("witness")).and_then(JValue::dict).ok_or_else(schema)?;
    let mut kids: Vec<&str> = devices.iter().filter_map(|d| string(d.get("kid"))).collect();
    if string(witness.get("mode")) == Some("relay") {
        if let Some(relay) = string(witness.get("relay_kid")) {
            kids.push(relay);
        }
    }
    if kids.iter().any(|kid| edition.is_fixture_kid(kid)) {
        return Err(Refusal::new("fixture_key"));
    }
    Ok(())
}

pub fn check_alone(value: &JValue) -> Checked<()> {
    check_alone_in(value, Profiles::standard())
}

/// `check_alone` over a given edition table. The document is checked under the tables of the edition its
/// `profile` names (RN-09, GP-23); a hash no edition lists is checked under the current edition, leniently like a
/// fixture hash (the profile codes are the fold's, GP-15 step 2).
pub fn check_alone_in(value: &JValue, profiles: &Profiles) -> Checked<()> {
    let doc = check_shape(value)?;
    check_sorted(doc)?;
    check_keys(doc)?;
    let (edition, fixture) = match string(doc.get("profile")).and_then(|p| profiles.resolve(p)) {
        Some(profile) => (profile.edition, profile.fixture),
        None => (profiles.current(), true),
    };
    let registry = &edition.registry;
    let members = doc.get("members").and_then(JValue::list).ok_or_else(schema)?;
    let devices = doc.get("devices").and_then(JValue::list).ok_or_else(schema)?;
    policy::validate(doc.get("policy"), members, devices, registry, fixture)?;
    check_devices_against_policy(doc, registry, fixture)?;
    if !fixture {
        check_fixture_keys(doc, edition)?;
    }
    Ok(())
}
