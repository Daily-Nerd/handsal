//! Genesis rendering (RN-04, RN-08, RN-10) and the size bound of GP-15 step 5.
//!
//! An original renders in full: every member, every device (full kid, class on its own line,
//! label, agree thumbprint) and the whole policy, the witness included. A change renders as a
//! difference from the document it replaces: `Org name` and `Profile`, `Previous`, the full `Head`,
//! the members and devices added or removed, the roles changed, the full policy, and what stayed.
//! Carried devices are byte-identical (GP-20), so there is no "devices changed" section; a section
//! with no entry is not written.
//! It reads a document that passed `genesis::check_alone`; a shape that is not there is
//! `genesis_schema`, never a default.

use crate::emit;
use crate::encoding;
use crate::genesis::doc_hash;
use crate::render::{cut12, hash12};
use crate::value::{Checked, JValue, Refusal};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Device {
    kid: String,
    person: String,
    class: String,
    label: String,
    agree: String,
}

#[derive(Debug, Clone)]
pub struct Doc {
    value: JValue,
    name: String,
    profile: String,
    pub prev: Option<String>,
    pub head: Option<String>,
    members: Vec<(String, String)>,
    devices: Vec<Device>,
    policy: BTreeMap<String, JValue>,
}

fn bad() -> Refusal {
    Refusal::new("genesis_schema")
}

fn text<'a>(value: Option<&'a JValue>) -> Checked<&'a str> {
    value.and_then(JValue::str).ok_or_else(bad)
}

pub fn read(value: &JValue) -> Checked<Doc> {
    let d = value.dict().ok_or_else(bad)?;
    let members = d
        .get("members")
        .and_then(JValue::list)
        .ok_or_else(bad)?
        .iter()
        .map(|m| Ok((text(m.get("id"))?.to_string(), text(m.get("role"))?.to_string())))
        .collect::<Checked<Vec<_>>>()?;
    let devices = d
        .get("devices")
        .and_then(JValue::list)
        .ok_or_else(bad)?
        .iter()
        .map(|v| {
            let agree = v.get("agree");
            Ok(Device {
                kid: text(v.get("kid"))?.to_string(),
                person: text(v.get("person"))?.to_string(),
                class: text(v.get("class"))?.to_string(),
                label: text(v.get("label"))?.to_string(),
                agree: encoding::thumbprint(text(agree.and_then(|a| a.get("x")))?, text(agree.and_then(|a| a.get("y")))?),
            })
        })
        .collect::<Checked<Vec<_>>>()?;
    Ok(Doc {
        value: value.clone(),
        name: text(d.get("name"))?.to_string(),
        profile: text(d.get("profile"))?.to_string(),
        prev: d.get("prev").and_then(JValue::str).map(str::to_string),
        head: d.get("head").and_then(JValue::str).map(str::to_string),
        members,
        devices,
        policy: d.get("policy").and_then(JValue::dict).ok_or_else(bad)?.clone(),
    })
}

fn device_lines(d: &Device) -> Vec<String> {
    vec![
        format!("  - {} of {}", d.kid, d.person),
        format!("    Class: {}", d.class),
        format!("    Label: {}", d.label),
        format!("    Agree: {}", d.agree),
    ]
}

fn policy_lines(policy: &BTreeMap<String, JValue>) -> Checked<Vec<String>> {
    let join = |value: Option<&JValue>| -> Option<String> {
        let items: Option<Vec<&str>> = value?.list()?.iter().map(JValue::str).collect();
        Some(items?.join(","))
    };
    let roles = join(policy.get("roles")).ok_or_else(bad)?;
    let rules = policy.get("rules").and_then(JValue::dict).ok_or_else(bad)?;
    let classes = policy.get("classes").and_then(JValue::list).ok_or_else(bad)?;
    let fresh = policy.get("freshness").and_then(JValue::dict).ok_or_else(bad)?;
    let witness = policy.get("witness").and_then(JValue::dict).ok_or_else(bad)?;
    let mut out = vec!["Policy:".to_string(), format!("  Roles: {}", roles)];
    for (name, rule) in rules {
        let persons = text(rule.get("persons"))?;
        let rule_roles = join(rule.get("roles")).ok_or_else(bad)?;
        out.push(format!("  Rule {}: {} of {}", name, persons, rule_roles));
    }
    for entry in classes {
        out.push(format!("  Class {}: {}", text(entry.get("class"))?, text(entry.get("user_verification"))?));
    }
    out.push(format!("  Clock skew: {} s", text(fresh.get("clock_skew_s"))?));
    out.push(format!("  Max validity: {} s", text(fresh.get("max_validity_s"))?));
    out.push(format!("  Max view age: {} s", text(fresh.get("max_view_age_s"))?));
    if witness.get("mode").and_then(JValue::str) == Some("none") {
        out.push("  Witness: none".to_string());
    } else {
        out.push("  Witness: relay".to_string());
        out.push(format!("  Relay key: {}", text(witness.get("relay_kid"))?));
        out.push(format!("  Max tip age: {} s", text(witness.get("max_tip_age_s"))?));
    }
    Ok(out)
}

#[derive(Default)]
struct Difference<'a> {
    added: Vec<&'a (String, String)>,
    removed: Vec<&'a (String, String)>,
    changed: Vec<(String, String, String)>,
    devices_added: Vec<&'a Device>,
    devices_removed: Vec<&'a Device>,
    carried: usize,
}

fn difference<'a>(doc: &'a Doc, previous: &'a Doc) -> Difference<'a> {
    let before: BTreeMap<&str, &str> = previous.members.iter().map(|(i, r)| (i.as_str(), r.as_str())).collect();
    let after: BTreeMap<&str, &str> = doc.members.iter().map(|(i, r)| (i.as_str(), r.as_str())).collect();
    let old: BTreeSet<&str> = previous.devices.iter().map(|d| d.kid.as_str()).collect();
    let new: BTreeSet<&str> = doc.devices.iter().map(|d| d.kid.as_str()).collect();
    Difference {
        added: doc.members.iter().filter(|m| !before.contains_key(m.0.as_str())).collect(),
        removed: previous.members.iter().filter(|m| !after.contains_key(m.0.as_str())).collect(),
        changed: doc
            .members
            .iter()
            .filter_map(|(id, role)| before.get(id.as_str()).filter(|old| **old != role).map(|old| (id.clone(), old.to_string(), role.clone())))
            .collect(),
        devices_added: doc.devices.iter().filter(|d| !old.contains(d.kid.as_str())).collect(),
        devices_removed: previous.devices.iter().filter(|d| !new.contains(d.kid.as_str())).collect(),
        carried: doc.devices.iter().filter(|d| old.contains(d.kid.as_str())).count(),
    }
}

/// Line 1 of the `genesis.sign` over `doc` (RN-03): an original, or a change against `previous`.
pub fn summary(doc: &Doc, previous: Option<&Doc>) -> Checked<String> {
    let name = cut12(&doc.name);
    let digest = hash12(&doc_hash(&doc.value)?);
    let Some(previous) = previous else {
        return Ok(format!("Sign genesis of {} ({}): {} members, {} devices", name, digest, doc.members.len(), doc.devices.len()));
    };
    let diff = difference(doc, previous);
    let policy_of = |d: &Doc| emit::subset(&JValue::Object(d.policy.clone())).ok();
    let policy_new = policy_of(doc) != policy_of(previous);
    Ok(format!(
        "Change {} ({}): +{}/-{} dev, {} mem, policy {}",
        name,
        digest,
        diff.devices_added.len(),
        diff.devices_removed.len(),
        diff.added.len() + diff.removed.len() + diff.changed.len(),
        if policy_new { "NEW" } else { "same" }
    ))
}

fn section(title: &str, entries: Vec<String>) -> Vec<String> {
    if entries.is_empty() {
        vec![]
    } else {
        let mut out = vec![title.to_string()];
        out.extend(entries);
        out
    }
}

/// The method lines of the `genesis.sign` over `doc` (RN-04, RN-10).
pub fn lines(doc: &Doc, previous: Option<&Doc>) -> Checked<Vec<String>> {
    let (Some(previous), Some(prev), Some(head)) = (previous, doc.prev.as_deref(), doc.head.as_deref()) else {
        let mut out = vec![format!("Org name: {}", doc.name), format!("Profile: {}", doc.profile), "Members:".to_string()];
        out.extend(doc.members.iter().map(|(id, role)| format!("  - {} {}", id, role)));
        out.push("Devices:".to_string());
        out.extend(doc.devices.iter().flat_map(device_lines));
        out.extend(policy_lines(&doc.policy)?);
        out.push(format!("Document hash: {}", hash12(&doc_hash(&doc.value)?)));
        return Ok(out);
    };
    let diff = difference(doc, previous);
    let mut out = vec![
        format!("Org name: {}", doc.name),
        format!("Profile: {}", doc.profile),
        format!("Previous: {}", hash12(prev)),
        format!("Head: {}", head),
    ];
    out.extend(section("Members added:", diff.added.iter().map(|(id, role)| format!("  - {} {}", id, role)).collect()));
    out.extend(section("Members removed:", diff.removed.iter().map(|(id, role)| format!("  - {} {}", id, role)).collect()));
    out.extend(section("Role changed:", diff.changed.iter().map(|(id, old, new)| format!("  - {} {} -> {}", id, old, new)).collect()));
    out.extend(section("Devices added:", diff.devices_added.iter().flat_map(|d| device_lines(d)).collect()));
    out.extend(section("Devices removed:", diff.devices_removed.iter().map(|d| format!("  - {} of {}", d.kid, d.person)).collect()));
    out.extend(policy_lines(&doc.policy)?);
    let unchanged = doc.members.len() - diff.added.len() - diff.changed.len();
    out.push(format!("Unchanged: {} devices, {} members", diff.carried, unchanged));
    Ok(out)
}
