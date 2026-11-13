//! Policy validation (GP-02, KC-02, KC-03, KC-07, WT-01): GP-15 step 3 up to the class codes.
//!
//! One entry point, `validate`, running the checks in the order GP-15 fixes, each pass over the
//! whole policy before the next begins:
//!   1. shape                        `policy_invalid` (witness shape included)
//!   2. bounds                       `policy_out_of_bounds`
//!   3. a spare person per rule      `policy_unreachable`
//!   4. classes, one code per pass   `class_unknown`, `class_pending`, `class_test_only`,
//!                                   `class_policy_mismatch`
//! Bounds are the registry's constants; this file names none. The policy is data: nothing here
//! names a class, a role or a threshold.

use crate::devicekey;
use crate::encoding;
use crate::forms;
use crate::registry::Registry;
use crate::value::{Checked, JValue, Refusal};
use std::collections::{BTreeMap, BTreeSet};

const TOP_KEYS: [&str; 6] = ["classes", "freshness", "roles", "rules", "v", "witness"];
const FRESHNESS_KEYS: [&str; 3] = ["clock_skew_s", "max_validity_s", "max_view_age_s"];
const RULE_NAMES: [&str; 4] = ["chain.resolve", "device.remove", "genesis.change", "member.add"];
const VERSION: &str = "handsal-policy/1";
const JWK_KEYS: [&str; 4] = ["crv", "kty", "x", "y"];
const RELAY_KEYS: [&str; 4] = ["max_tip_age_s", "mode", "relay_kid", "relay_pub_jwk"];

fn invalid() -> Refusal {
    Refusal::new("policy_invalid")
}

fn keys_are(members: &BTreeMap<String, JValue>, expected: &[&str]) -> bool {
    members.len() == expected.len() && expected.iter().all(|k| members.contains_key(*k))
}

fn role_list(value: Option<&JValue>, listed: Option<&[String]>) -> Checked<Vec<String>> {
    let items = value.and_then(JValue::list).filter(|items| !items.is_empty()).ok_or_else(invalid)?;
    let mut out = Vec::new();
    for item in items {
        match item.str() {
            Some(s) if forms::is_role_id(s) => out.push(s.to_string()),
            _ => return Err(invalid()),
        }
    }
    if out.iter().collect::<BTreeSet<_>>().len() != out.len() {
        return Err(invalid());
    }
    if let Some(listed) = listed {
        if !out.iter().all(|r| listed.contains(r)) {
            return Err(invalid());
        }
    }
    Ok(out)
}

fn decimal(value: Option<&JValue>) -> Option<i64> {
    let s = value?.str()?;
    if forms::is_decimal(s) {
        s.parse().ok()
    } else {
        None
    }
}

struct Parsed<'a> {
    classes: Vec<(&'a str, &'a str)>,
    witness: &'a BTreeMap<String, JValue>,
    freshness: BTreeMap<&'static str, i64>,
    persons: Vec<i64>,
    rule_roles: Vec<Vec<String>>,
}

fn shape<'a>(policy: Option<&'a JValue>, members: &[JValue]) -> Checked<Parsed<'a>> {
    let p = policy.and_then(JValue::dict).filter(|p| keys_are(p, &TOP_KEYS) && p["v"].str() == Some(VERSION)).ok_or_else(invalid)?;
    let roles = role_list(p.get("roles"), None)?;
    let classes = p["classes"].list().filter(|c| !c.is_empty()).ok_or_else(invalid)?;
    let mut parsed_classes = Vec::new();
    for entry in classes {
        let c = entry.dict().filter(|c| keys_are(c, &["class", "user_verification"])).ok_or_else(invalid)?;
        match (c["class"].str(), c["user_verification"].str()) {
            (Some(name), Some(uv)) => parsed_classes.push((name, uv)),
            _ => return Err(invalid()),
        }
    }
    if parsed_classes.iter().map(|c| c.0).collect::<BTreeSet<_>>().len() != parsed_classes.len() {
        return Err(invalid());
    }
    let fresh = p["freshness"].dict().filter(|f| keys_are(f, &FRESHNESS_KEYS)).ok_or_else(invalid)?;
    let mut freshness = BTreeMap::new();
    for key in FRESHNESS_KEYS {
        freshness.insert(key, decimal(fresh.get(key)).ok_or_else(invalid)?);
    }
    let rules = p["rules"].dict().filter(|r| keys_are(r, &RULE_NAMES)).ok_or_else(invalid)?;
    let mut persons = Vec::new();
    let mut rule_roles = Vec::new();
    for rule in rules.values() {
        let r = rule.dict().filter(|r| keys_are(r, &["persons", "roles"])).ok_or_else(invalid)?;
        persons.push(decimal(r.get("persons")).ok_or_else(invalid)?);
        rule_roles.push(role_list(r.get("roles"), Some(&roles))?);
    }
    for member in members {
        match (member.dict(), member.get("role").and_then(JValue::str)) {
            (Some(_), Some(role)) if roles.iter().any(|r| r == role) => {}
            _ => return Err(invalid()),
        }
    }
    let witness = p["witness"].dict().ok_or_else(invalid)?;
    Ok(Parsed { classes: parsed_classes, witness, freshness, persons, rule_roles })
}

fn witness_shape(witness: &BTreeMap<String, JValue>, devices: &[JValue]) -> Checked<()> {
    let mode = witness.get("mode").and_then(JValue::str).ok_or_else(invalid)?;
    if mode == "none" {
        return if witness.len() == 1 { Ok(()) } else { Err(invalid()) };
    }
    if mode != "relay" || !keys_are(witness, &RELAY_KEYS) || decimal(witness.get("max_tip_age_s")).is_none() {
        return Err(invalid());
    }
    let jwk = witness["relay_pub_jwk"].dict().filter(|j| keys_are(j, &JWK_KEYS)).ok_or_else(invalid)?;
    let (Some("P-256"), Some("EC"), Some(x), Some(y)) = (jwk["crv"].str(), jwk["kty"].str(), jwk["x"].str(), jwk["y"].str()) else {
        return Err(invalid());
    };
    let point = JValue::Object(BTreeMap::from([("x".to_string(), JValue::string(x)), ("y".to_string(), JValue::string(y))]));
    let kid = witness["relay_kid"].str().ok_or_else(invalid)?;
    if !devicekey::point_ok(&point) || kid != encoding::thumbprint(x, y) {
        return Err(invalid());
    }
    for device in devices {
        let Some(d) = device.dict() else { continue };
        if d.get("kid").and_then(JValue::str) == Some(kid) {
            return Err(invalid());
        }
        for key in ["sign", "agree"] {
            if let Some(p) = d.get(key) {
                if p.get("x").and_then(JValue::str) == Some(x) && p.get("y").and_then(JValue::str) == Some(y) {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(())
}

fn out_of_bounds() -> Refusal {
    Refusal::new("policy_out_of_bounds")
}

pub fn validate(policy: Option<&JValue>, members: &[JValue], devices: &[JValue], registry: &Registry, fixture: bool) -> Checked<()> {
    let parsed = shape(policy, members)?;
    witness_shape(parsed.witness, devices)?;
    for key in FRESHNESS_KEYS {
        let n = parsed.freshness[key];
        if n < registry.number(&format!("{}.min", key)) || n > registry.number(&format!("{}.max", key)) {
            return Err(out_of_bounds());
        }
    }
    for n in &parsed.persons {
        if *n < registry.number("persons.min") || *n > registry.number("persons.max") {
            return Err(out_of_bounds());
        }
    }
    if parsed.witness.get("mode").and_then(JValue::str) == Some("relay") {
        if let Some(age) = decimal(parsed.witness.get("max_tip_age_s")) {
            if age < registry.number("max_tip_age_s.min") || age > registry.number("max_tip_age_s.max") {
                return Err(out_of_bounds());
            }
        }
    }
    for (index, roles) in parsed.rule_roles.iter().enumerate() {
        let holders = members
            .iter()
            .filter(|m| m.get("role").and_then(JValue::str).map_or(false, |role| roles.iter().any(|r| r == role)))
            .count() as i64;
        if parsed.persons[index] >= holders {
            return Err(Refusal::new("policy_unreachable"));
        }
    }
    let known: Vec<_> = parsed.classes.iter().map(|(name, uv)| (*uv, registry.lookup_class(name, fixture))).collect();
    if known.iter().any(|(_, class)| class.is_none()) {
        return Err(Refusal::new("class_unknown"));
    }
    if known.iter().any(|(_, class)| class.map_or(false, |c| c.status == "pending-spike")) {
        return Err(Refusal::new("class_pending"));
    }
    if known.iter().any(|(_, class)| class.map_or(false, |c| c.status == "test-only")) {
        return Err(Refusal::new("class_test_only"));
    }
    if known.iter().any(|(uv, class)| class.and_then(|c| c.user_verification.as_deref()) != Some(*uv)) {
        return Err(Refusal::new("class_policy_mismatch"));
    }
    Ok(())
}
