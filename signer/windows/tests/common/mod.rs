//! Shared test data for the edition tests: genesis documents and synthetic editions.
//!
//! An edition here is three byte strings (a registry, a fixture kid list and the manifest that lists
//! them), the same shape a frozen directory of `profiles/<label>/` has, so a synthetic table is built
//! by the code that builds the real one.
#![allow(dead_code)]

use handsal_core::encoding;
use handsal_core::json;
use handsal_core::profiles::{self, CoreData, FrozenRow};
use handsal_core::value::JValue;
use std::collections::BTreeMap;

pub const REGISTRY_PATH: &str = "spec/registry.json";
pub const KIDS_PATH: &str = "conformance/fixtures/fixture-kids.json";

/// Six real P-256 points no edition lists (made for these tests): `(kid, x, y)`. The first three sign, the last
/// three agree. A listed fixture kid would make a production edition refuse the document for its keys.
pub const POINTS: [(&str, &str, &str); 6] = [
    ("BiC-pu__JFixcU4EgSuWluIApRpD1zesmDr5mRpJl2Q", "VaQ6Bm8b0UFw-LnpKO-GucxexSDD0yPMaZv1R7q_bE0", "U-tHyd0P0Jmw_osmY422Ggxt_Ba89TE4ZroeaXPJOXA"),
    ("6f221vSlOh_ZDTZjXwtJVmOZwOYw7NzR1x6Omlc98U0", "lCB7N4y3tYPQ2RkWyf4tsMkUhd5q4N8y9l-9sPu5Ymw", "dYlF08XV7eullRweyNSEGDg_WqItjdzFDeZIRZnskqE"),
    ("_3EWACwo8ozwVKDazsFltI8boTxJ9YARC_L9U3O1ekk", "TifPlDDtmCOjQBV2LnvFMHgg9KTd76_Z-uQc7vKl5WE", "sd-ECIBnI2eHaMsnFvbp6aDu13tA1kg64jF4LgwkK_E"),
    ("8u5iq3cvU5gBm6Wi6zayQsJXiA78ivhyn4qIWt5ovi4", "alprybF2j9B3tNV4MC1CiMf0qElUMhaBphXvoPeIaDc", "24VE5nzbo4wd307DwkqZEOscsfDwl_jYiuY8XLmf8AU"),
    ("P6apsv6wHMr4C5D6dWvnZrdrfvmPSTwkKKWy6siHD0U", "il6vDvXB2SAbFdrTA4PWE4eXomqrIGWlj3yyq1qUV2c", "wj_4Yb7bn6oXkDnEL3YcJXgdsyq66t7sn5zxqjZV0hY"),
    ("fvb23VwrT5vVJT9rqK6nTNKTalzbjxoKi1ebE7x-S1g", "9dIviLUaqbO-q_7-kTTsGL5e2yZ2XwOi1uAAL0DBm1U", "F2-aYUsVp4UjhisBt8jteiNberUOC4UmadLc2iN24SU"),
];

pub fn hs(seed: &str) -> String {
    encoding::hashstr(seed.as_bytes())
}

/// A lone original of three maintainers, one device each of `class`, naming `profile`; the signing key of alice is
/// `first`.
pub fn document_of(profile: &str, class: &str, first: (&str, &str, &str)) -> JValue {
    let mut devices: Vec<(&str, String)> = ["alice", "bob", "carol"]
        .iter()
        .enumerate()
        .map(|(i, person)| {
            let (kid, x, y) = if i == 0 { first } else { POINTS[i] };
            let (_, ax, ay) = POINTS[i + 3];
            let text = format!(
                r#"{{"agree":{{"x":"{}","y":"{}"}},"class":"{}","kid":"{}","label":"phone","person":"{}","sign":{{"x":"{}","y":"{}"}}}}"#,
                ax, ay, class, kid, person, x, y
            );
            (kid, text)
        })
        .collect();
    devices.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let devices: Vec<String> = devices.into_iter().map(|d| d.1).collect();
    let rule = r#"{"persons":"2","roles":["maintainer"]}"#;
    let policy = format!(
        r#"{{"classes":[{{"class":"{c}","user_verification":"biometric_only"}}],"freshness":{{"clock_skew_s":"300","max_validity_s":"604800","max_view_age_s":"86400"}},"relays":[],"roles":["maintainer","member"],"rules":{{"chain.resolve":{r},"device.remove":{r},"genesis.change":{r},"member.add":{r}}},"v":"handsal-policy/1","witness":{{"mode":"none"}}}}"#,
        c = class,
        r = rule
    );
    let text = format!(
        r#"{{"devices":[{}],"members":[{{"id":"alice","role":"maintainer"}},{{"id":"bob","role":"maintainer"}},{{"id":"carol","role":"maintainer"}}],"name":"acme","org":null,"policy":{},"prev":null,"profile":"{}","v":"handsal-genesis/1"}}"#,
        devices.join(","),
        policy,
        profile
    );
    json::parse(text.as_bytes()).unwrap()
}

pub fn document(profile: &str) -> JValue {
    document_of(profile, "apple-se-bio", POINTS[0])
}

pub fn shipped_registry() -> String {
    std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/registry.json")).unwrap()
}

pub fn shipped_kids() -> String {
    std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures/fixture-kids.json")).unwrap()
}

/// The shipped registry with one more active key class that has the strength of `apple-se-bio`.
pub fn registry_with_class(id: &str) -> String {
    let shipped = shipped_registry();
    let extra = format!(
        r#""key_classes": [{{"alg":"ES256","hardware_bound":true,"id":"{}","per_signature_user_verification":true,"status":"active","user_verification":"biometric_only"}},"#,
        id
    );
    let edited = shipped.replacen(r#""key_classes": ["#, &extra, 1);
    assert_ne!(edited, shipped, "the registry file has no key_classes list to extend");
    edited
}

/// The shipped kid list with `kid` listed as well.
pub fn kids_with(kid: &str) -> String {
    let shipped = shipped_kids();
    let edited = shipped.replacen("[\n", &format!("[\n  \"{}\",\n", kid), 1);
    assert_ne!(edited, shipped, "the kid list is not a list that starts on its own line");
    edited
}

/// One synthetic edition: the bytes of its three files and what they hash to.
pub struct Files {
    pub label: String,
    pub registry: Vec<u8>,
    pub kids: Vec<u8>,
}

impl Files {
    pub fn new(label: &str, registry: &str, kids: &str) -> Files {
        Files { label: label.to_string(), registry: registry.as_bytes().to_vec(), kids: kids.as_bytes().to_vec() }
    }

    pub fn manifest(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (KIDS_PATH.to_string(), encoding::hashstr(&self.kids)),
            (REGISTRY_PATH.to_string(), encoding::hashstr(&self.registry)),
        ])
    }

    pub fn manifest_bytes(&self) -> Vec<u8> {
        let members: BTreeMap<String, JValue> = self.manifest().into_iter().map(|(k, v)| (k, JValue::String(v))).collect();
        handsal_core::emit::subset(&JValue::Object(members)).unwrap()
    }

    pub fn production(&self) -> String {
        profiles::profile_hash("production", &self.manifest())
    }

    pub fn fixture(&self) -> String {
        profiles::profile_hash("fixture", &self.manifest())
    }

    /// This edition as the live (newest, unreleased) core.
    pub fn live(&self) -> CoreData<'_> {
        CoreData { label: &self.label, manifest: self.manifest(), registry: &self.registry, kids: &self.kids }
    }
}

/// A frozen row for `files`, with the manifest bytes held by `manifest` (a row borrows them).
pub fn row<'a>(files: &'a Files, manifest: &'a [u8], production: &'a str, fixture: &'a str) -> FrozenRow<'a> {
    FrozenRow { label: &files.label, production, fixture, manifest, registry: &files.registry, kids: &files.kids }
}
