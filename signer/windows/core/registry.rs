//! The registry (KC-01, ACT-09): key classes, the method table and the section 2 constants.
//!
//! `spec/registry.json` is the file the profile hash covers, and it is the only copy: it is embedded
//! at build time and read here, so no table can drift from the file. A change to the file changes
//! the profile hash and the signer binary together.

use crate::forms;
use crate::json;
use crate::value::{Checked, JValue, Refusal};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const REGISTRY_JSON: &[u8] = include_bytes!("../../../spec/registry.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Hashstr,
    B64u32,
    Kid,
    MemberId,
    RoleId,
    ClassId,
    RequestId,
    RecordId,
    Label,
    OrgName,
    Anchor,
    Hostname,
    Time,
    Decimal,
    ConsumerId,
    SubjectId,
    Action,
}

impl Form {
    fn from_name(name: &str) -> Option<Form> {
        Some(match name {
            "hashstr" => Form::Hashstr,
            "b64u32" => Form::B64u32,
            "kid" => Form::Kid,
            "member_id" => Form::MemberId,
            "role_id" => Form::RoleId,
            "class_id" => Form::ClassId,
            "request_id" => Form::RequestId,
            "record_id" => Form::RecordId,
            "label" => Form::Label,
            "org_name" => Form::OrgName,
            "anchor" => Form::Anchor,
            "hostname" => Form::Hostname,
            "time" => Form::Time,
            "decimal" => Form::Decimal,
            "consumer_id" => Form::ConsumerId,
            "subject_id" => Form::SubjectId,
            "action" => Form::Action,
            _ => return None,
        })
    }

    pub fn accepts(self, value: &str) -> bool {
        match self {
            Form::Hashstr => forms::is_hashstr(value),
            Form::B64u32 | Form::Kid => forms::is_b64u32(value),
            Form::MemberId => forms::is_member_id(value),
            Form::RoleId => forms::is_role_id(value),
            Form::ClassId => forms::is_class_id(value),
            Form::RequestId => forms::is_request_id(value),
            Form::RecordId => forms::is_record_id(value),
            Form::Label => forms::is_label(value),
            Form::OrgName => forms::is_org_name(value),
            Form::Anchor => forms::is_anchor(value),
            Form::Hostname => forms::is_hostname(value),
            Form::Time => forms::is_time(value),
            Form::Decimal => forms::is_decimal(value),
            Form::ConsumerId => forms::is_consumer_id(value),
            Form::SubjectId => forms::is_subject_id(value),
            Form::Action => forms::is_action(value),
        }
    }

    /// The forms ACT-07 names: their defect is `schema` wherever they sit.
    fn is_act07(self) -> bool {
        matches!(self, Form::Hashstr | Form::Time | Form::MemberId | Form::Decimal)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SchemaNode {
    Leaf(Form),
    Const(String),
    Keys(BTreeMap<String, SchemaNode>),
    /// The subtree reports its defects under another container code (a body inside the act object).
    Scoped(&'static str, Box<SchemaNode>),
    List {
        of: Box<SchemaNode>,
        cap: String,
        sorted: bool,
        distinct: bool,
        sorted_by: Option<String>,
        distinct_by: Option<String>,
    },
}

impl SchemaNode {
    pub fn keys(members: Vec<(&str, SchemaNode)>) -> SchemaNode {
        SchemaNode::Keys(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadRule {
    Always,
    Conditional,
    Never,
}

#[derive(Debug, Clone)]
pub struct MethodSpec {
    pub name: String,
    pub act_extra_keys: Vec<String>,
    pub head: HeadRule,
    pub body: SchemaNode,
    pub inputs_hash: String,
    pub outputs_hash: String,
}

#[derive(Debug, Clone)]
pub struct ClassSpec {
    pub id: String,
    pub status: String,
    pub user_verification: Option<String>,
}

#[derive(Debug)]
pub struct Registry {
    pub methods: BTreeMap<String, MethodSpec>,
    pub classes: BTreeMap<String, ClassSpec>,
    pub fixture_only: BTreeMap<String, ClassSpec>,
    pub act_extra_key_types: BTreeMap<String, Form>,
    constants: BTreeMap<String, i64>,
}

impl Registry {
    /// The value of a registry constant by path, for example `persons.min`. A name that is not in
    /// the table is a bug in the caller and stops the process, never a default.
    pub fn number(&self, path: &str) -> i64 {
        match self.constants.get(path) {
            Some(value) => *value,
            None => panic!("registry has no constant {}", path),
        }
    }

    /// The class `id` under the profile kind, or `None` (`class_unknown`).
    pub fn lookup_class(&self, id: &str, fixture: bool) -> Option<&ClassSpec> {
        self.classes.get(id).or(if fixture { self.fixture_only.get(id) } else { None })
    }

    /// A registry from the bytes of a registry file. The shipped one is `standard`; this is for tests of a
    /// rule the shipped registry has no case for (a `pending-spike` class, KC-02: the first tag has none).
    pub fn from_bytes(bytes: &[u8]) -> Result<Registry, String> {
        parse(bytes)
    }

    pub fn standard() -> &'static Registry {
        static REGISTRY: OnceLock<Registry> = OnceLock::new();
        REGISTRY.get_or_init(|| {
            parse(REGISTRY_JSON).unwrap_or_else(|why| panic!("embedded spec/registry.json is not a registry: {}", why))
        })
    }
}

fn text<'a>(value: &'a JValue, what: &str) -> Result<&'a str, String> {
    value.str().ok_or_else(|| format!("{} is not a string", what))
}

fn member<'a>(value: &'a JValue, key: &str) -> Result<&'a JValue, String> {
    value.get(key).ok_or_else(|| format!("missing {}", key))
}

fn form_named(name: &str) -> Result<Form, String> {
    Form::from_name(name).ok_or_else(|| format!("unknown form {}", name))
}

fn node(value: &JValue) -> Result<SchemaNode, String> {
    if let Some(keys) = value.get("keys") {
        let members = keys.dict().ok_or("keys is not an object")?;
        let mut out = BTreeMap::new();
        for (name, child) in members {
            out.insert(name.clone(), node(child)?);
        }
        return Ok(SchemaNode::Keys(out));
    }
    if let Some(constant) = value.get("const") {
        return Ok(SchemaNode::Const(text(constant, "const")?.to_string()));
    }
    let kind = text(member(value, "type")?, "type")?;
    if kind != "list" {
        return Ok(SchemaNode::Leaf(form_named(kind)?));
    }
    let of = member(value, "of")?;
    let of = match of.str() {
        Some(name) => SchemaNode::Leaf(form_named(name)?),
        None => node(of)?,
    };
    let flag = |key: &str| value.get(key) == Some(&JValue::Bool(true));
    let name = |key: &str| value.get(key).and_then(JValue::str).map(str::to_string);
    Ok(SchemaNode::List {
        of: Box::new(of),
        cap: text(member(value, "cap")?, "cap")?.to_string(),
        sorted: flag("sorted"),
        distinct: flag("distinct"),
        sorted_by: name("sorted_by"),
        distinct_by: name("distinct_by"),
    })
}

fn class(value: &JValue) -> Result<ClassSpec, String> {
    Ok(ClassSpec {
        id: text(member(value, "id")?, "id")?.to_string(),
        status: text(member(value, "status")?, "status")?.to_string(),
        user_verification: value.get("user_verification").and_then(JValue::str).map(str::to_string),
    })
}

fn classes(value: &JValue) -> Result<BTreeMap<String, ClassSpec>, String> {
    let list = value.list().ok_or("classes are not a list")?;
    let mut out = BTreeMap::new();
    for entry in list {
        let spec = class(entry)?;
        out.insert(spec.id.clone(), spec);
    }
    Ok(out)
}

/// `{"min":"2","max":"15"}` and `{"value":"16384","unit":"bytes"}` become `persons.min`,
/// `persons.max`, `MAX_PAYLOAD`; a `unit` is no number.
fn flatten(prefix: &str, value: &JValue, out: &mut BTreeMap<String, i64>) -> Result<(), String> {
    let members = value.dict().ok_or_else(|| format!("{} is not an object", prefix))?;
    for (key, child) in members {
        if key == "unit" {
            continue;
        }
        let path = if prefix.is_empty() { key.clone() } else { format!("{}.{}", prefix, key) };
        match child {
            JValue::Object(_) => {
                if let Some(single) = child.get("value") {
                    let n = text(single, &path)?.parse::<i64>().map_err(|_| format!("{} is not a number", path))?;
                    out.insert(path, n);
                } else {
                    flatten(&path, child, out)?;
                }
            }
            JValue::String(raw) => {
                let n = raw.parse::<i64>().map_err(|_| format!("{} is not a number", path))?;
                out.insert(path, n);
            }
            _ => return Err(format!("{} is neither a number nor a group", path)),
        }
    }
    Ok(())
}

fn parse(bytes: &[u8]) -> Result<Registry, String> {
    let doc = json::parse_embedded(bytes).map_err(|_| "not JSON".to_string())?;
    let mut methods = BTreeMap::new();
    for entry in member(&doc, "methods")?.list().ok_or("methods are not a list")? {
        let name = text(member(entry, "method")?, "method")?.to_string();
        let head = match text(member(entry, "head")?, "head")? {
            "always" => HeadRule::Always,
            "conditional" => HeadRule::Conditional,
            "never" => HeadRule::Never,
            other => return Err(format!("unknown head rule {}", other)),
        };
        let extra = member(entry, "act_extra_keys")?.list().ok_or("act_extra_keys is not a list")?;
        let spec = MethodSpec {
            name: name.clone(),
            act_extra_keys: extra.iter().map(|k| text(k, "act extra key").map(str::to_string)).collect::<Result<_, _>>()?,
            head,
            body: node(member(entry, "body")?)?,
            inputs_hash: text(member(entry, "inputs_hash")?, "inputs_hash")?.to_string(),
            outputs_hash: text(member(entry, "outputs_hash")?, "outputs_hash")?.to_string(),
        };
        methods.insert(name, spec);
    }
    let mut act_extra_key_types = BTreeMap::new();
    for (key, form) in member(&doc, "act_extra_key_types")?.dict().ok_or("act_extra_key_types is not an object")? {
        act_extra_key_types.insert(key.clone(), form_named(text(form, key)?)?);
    }
    let mut constants = BTreeMap::new();
    flatten("", member(&doc, "constants")?, &mut constants)?;
    Ok(Registry {
        methods,
        classes: classes(member(&doc, "key_classes")?)?,
        fixture_only: classes(member(&doc, "fixture_only")?)?,
        act_extra_key_types,
        constants,
    })
}

/// The closed-object engine (ACT-07, ACT-09, ACT-10). Which reason code a defect gets: the ACT-07
/// forms are `schema` wherever they sit; any other defect takes the code of the container being
/// checked (`schema` for the act object, `body_schema` for a body).
pub mod schema {
    use super::*;

    pub fn defects(node: &SchemaNode, value: &JValue, registry: &Registry, code: &'static str) -> Vec<&'static str> {
        let mut found = Vec::new();
        walk(node, value, registry, code, &mut found);
        found
    }

    /// The code ordered first in `found`: `schema` before the rest.
    pub fn refuse(found: &[&'static str]) -> Checked<()> {
        if found.contains(&"schema") {
            return Err(Refusal::new("schema"));
        }
        match found.first() {
            Some(first) => Err(Refusal::new(first)),
            None => Ok(()),
        }
    }

    pub fn check(node: &SchemaNode, value: &JValue, registry: &Registry, code: &'static str) -> Checked<()> {
        refuse(&defects(node, value, registry, code))
    }

    fn order_defect(sorted: bool, distinct: bool, by: Option<&str>, items: &[JValue]) -> bool {
        let mut keys: Vec<&[u8]> = Vec::new();
        for item in items {
            let key = match by {
                Some(name) => item.get(name).and_then(JValue::str),
                None => item.str(),
            };
            match key {
                Some(s) => keys.push(s.as_bytes()),
                None => return false,
            }
        }
        if sorted && keys.windows(2).any(|pair| pair[1] < pair[0]) {
            return true;
        }
        distinct && keys.iter().collect::<BTreeSet<_>>().len() != keys.len()
    }

    fn walk(node: &SchemaNode, value: &JValue, registry: &Registry, code: &'static str, found: &mut Vec<&'static str>) {
        match node {
            SchemaNode::Const(text) => {
                if value.str() != Some(text.as_str()) {
                    found.push(code);
                }
            }
            SchemaNode::Scoped(scope, inner) => walk(inner, value, registry, scope, found),
            SchemaNode::Keys(expected) => {
                let Some(members) = value.dict() else {
                    found.push(code);
                    return;
                };
                if members.keys().ne(expected.keys()) {
                    found.push(code);
                }
                for (name, child_node) in expected {
                    if let Some(child) = members.get(name) {
                        walk(child_node, child, registry, code, found);
                    }
                }
            }
            SchemaNode::List { of, cap, sorted, distinct, sorted_by, distinct_by } => {
                let Some(items) = value.list() else {
                    found.push(code);
                    return;
                };
                let count = items.len() as i64;
                if count < registry.number(&format!("{}.min", cap)) || count > registry.number(&format!("{}.max", cap)) {
                    found.push(code);
                }
                for item in items {
                    walk(of, item, registry, code, found);
                }
                let by = sorted_by.as_deref().or(distinct_by.as_deref());
                if order_defect(*sorted || sorted_by.is_some(), *distinct || distinct_by.is_some(), by, items) {
                    found.push(code);
                }
            }
            SchemaNode::Leaf(form) => {
                if value.str().map_or(false, |s| form.accepts(s)) {
                    return;
                }
                found.push(if form.is_act07() { "schema" } else { code });
            }
        }
    }
}
