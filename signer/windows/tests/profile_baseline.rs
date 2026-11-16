//! T16.1 characterization of what the Rust core says about profiles today. Green on the first run by
//! design; each test pins behavior that a later row restructures, so that row changes the lock knowingly.
//!
//! Rust has no ceremony (the ceremony refusal of `fixture_profile` and `profile_mismatch` lives only in
//! Swift), so the equivalent lock here is what `genesis::check_alone` does with the profile: nothing.
//! Step 2 of GP-15 belongs to the fold, which this core does not run.

use handsal_core::cli::{self, Environment};
use handsal_core::encoding;
use handsal_core::genesis;
use handsal_core::json;
use handsal_core::profiles::Profiles;
use handsal_core::value::{JValue, Refusal};

/// Six real P-256 points no profile lists (made for this test): `(kid, x, y)`. The first three sign, the last
/// three agree. A listed fixture kid would make the production profile refuse the document for its keys.
const POINTS: [(&str, &str, &str); 6] = [
    ("BiC-pu__JFixcU4EgSuWluIApRpD1zesmDr5mRpJl2Q", "VaQ6Bm8b0UFw-LnpKO-GucxexSDD0yPMaZv1R7q_bE0", "U-tHyd0P0Jmw_osmY422Ggxt_Ba89TE4ZroeaXPJOXA"),
    ("6f221vSlOh_ZDTZjXwtJVmOZwOYw7NzR1x6Omlc98U0", "lCB7N4y3tYPQ2RkWyf4tsMkUhd5q4N8y9l-9sPu5Ymw", "dYlF08XV7eullRweyNSEGDg_WqItjdzFDeZIRZnskqE"),
    ("_3EWACwo8ozwVKDazsFltI8boTxJ9YARC_L9U3O1ekk", "TifPlDDtmCOjQBV2LnvFMHgg9KTd76_Z-uQc7vKl5WE", "sd-ECIBnI2eHaMsnFvbp6aDu13tA1kg64jF4LgwkK_E"),
    ("8u5iq3cvU5gBm6Wi6zayQsJXiA78ivhyn4qIWt5ovi4", "alprybF2j9B3tNV4MC1CiMf0qElUMhaBphXvoPeIaDc", "24VE5nzbo4wd307DwkqZEOscsfDwl_jYiuY8XLmf8AU"),
    ("P6apsv6wHMr4C5D6dWvnZrdrfvmPSTwkKKWy6siHD0U", "il6vDvXB2SAbFdrTA4PWE4eXomqrIGWlj3yyq1qUV2c", "wj_4Yb7bn6oXkDnEL3YcJXgdsyq66t7sn5zxqjZV0hY"),
    ("fvb23VwrT5vVJT9rqK6nTNKTalzbjxoKi1ebE7x-S1g", "9dIviLUaqbO-q_7-kTTsGL5e2yZ2XwOi1uAAL0DBm1U", "F2-aYUsVp4UjhisBt8jteiNberUOC4UmadLc2iN24SU"),
];

fn hs(seed: &str) -> String {
    encoding::hashstr(seed.as_bytes())
}

/// A lone original of three maintainers, one device each, naming `profile`.
fn document(profile: &str) -> JValue {
    document_with(profile, POINTS[0])
}

/// The same document with the signing key of alice replaced by `first`.
fn document_with(profile: &str, first: (&str, &str, &str)) -> JValue {
    let mut devices: Vec<(&str, String)> = ["alice", "bob", "carol"]
        .iter()
        .enumerate()
        .map(|(i, person)| {
            let (kid, x, y) = if i == 0 { first } else { POINTS[i] };
            let (_, ax, ay) = POINTS[i + 3];
            let text = format!(
                r#"{{"agree":{{"x":"{}","y":"{}"}},"class":"apple-se-bio","kid":"{}","label":"phone","person":"{}","sign":{{"x":"{}","y":"{}"}}}}"#,
                ax, ay, kid, person, x, y
            );
            (kid, text)
        })
        .collect();
    devices.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let devices: Vec<String> = devices.into_iter().map(|d| d.1).collect();
    let rule = r#"{"persons":"2","roles":["maintainer"]}"#;
    let policy = format!(
        r#"{{"classes":[{{"class":"apple-se-bio","user_verification":"biometric_only"}}],"freshness":{{"clock_skew_s":"300","max_validity_s":"604800","max_view_age_s":"86400"}},"relays":[],"roles":["maintainer","member"],"rules":{{"chain.resolve":{r},"device.remove":{r},"genesis.change":{r},"member.add":{r}}},"v":"handsal-policy/1","witness":{{"mode":"none"}}}}"#,
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

fn code(result: Result<(), Refusal>) -> Option<&'static str> {
    result.err().map(|r| r.code)
}

#[test]
fn kind_answers_production_fixture_and_none() {
    let profiles = Profiles::standard();
    assert_eq!(profiles.kind(&profiles.production), Some("production"));
    assert_eq!(profiles.kind(&profiles.fixture), Some("fixture"));
    assert_eq!(profiles.kind(&hs("an edition this build does not implement")), None);
}

/// T16.11 rewrites this lock to the key set `class, impl, profiles, spec`.
#[test]
fn version_returns_exactly_the_keys_class_impl_and_spec() {
    let environment = Environment::fixed(None, 0, hs("nonce")).with_key_class("apple-se-bio");
    let mut stdin = || -> Result<Vec<u8>, Refusal> { panic!("version reads no stdin") };
    let out = cli::run(&["version".to_string()], &mut stdin, &environment);
    assert_eq!(out.exit, 0);
    let parsed = json::parse(out.line.strip_suffix(b"\n").unwrap_or(&out.line)).unwrap();
    let JValue::Object(members) = parsed else { panic!("version is one object") };
    assert_eq!(members.keys().map(String::as_str).collect::<Vec<_>>(), ["class", "impl", "spec"]);
    assert_eq!(members["spec"].str(), Some(Profiles::standard().production.as_str()));
}

/// The key of the vector rig that `fixture-kids.json` lists.
const FIXTURE_KEY: (&str, &str, &str) =
    ("E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI", "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM", "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw");

/// The D6 equivalent of the Swift ceremony refusals: this core never answers `profile_mismatch` or
/// `fixture_profile` for a document, whatever hash it names (GP-15 step 2 is the fold's); a well-formed
/// document is valid under all three names. A Rust ceremony written later must add those refusals itself
/// (T16.11 names the obligation and lets `sign` stay the `internal` stub until then).
#[test]
fn check_alone_never_answers_a_profile_code_whatever_hash_the_document_names() {
    let profiles = Profiles::standard();
    let unknown = hs("an edition this build does not implement");
    for name in [&profiles.production, &profiles.fixture, &unknown] {
        assert_eq!(code(genesis::check_alone(&document(name))), None, "{}", name);
    }
}

/// Only the production hash is strict about fixture keys; the fixture hash and an unknown hash are judged
/// alike, leniently (the RN-09 status quo that T16.11 keeps for an unknown hash).
#[test]
fn only_the_production_hash_refuses_a_fixture_key_and_an_unknown_hash_is_judged_like_the_fixture_one() {
    let profiles = Profiles::standard();
    assert!(profiles.is_fixture_kid(FIXTURE_KEY.0));
    let unknown = hs("an edition this build does not implement");
    let judged = |name: &str| code(genesis::check_alone(&document_with(name, FIXTURE_KEY)));
    assert_eq!(judged(&profiles.production), Some("fixture_key"));
    assert_eq!(judged(&profiles.fixture), None);
    assert_eq!(judged(&unknown), None);
}
