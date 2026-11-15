//! Field forms (section 2.2), the registry, device keys (ACT-11, KC-05) and the profile hashes
//! (CF-01), the pieces every later command stands on.

use handsal_core::devicekey;
use handsal_core::encoding;
use handsal_core::forms;
use handsal_core::json;
use handsal_core::profiles::Profiles;
use handsal_core::registry::{Form, Registry};
use handsal_core::value::JValue;

fn j(text: &str) -> JValue {
    json::parse(text.as_bytes()).unwrap()
}

const X: &str = "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM";
const Y: &str = "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw";
const KID: &str = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI";
const AX: &str = "GnEkTo7EpA3CgI-cW-9HF9-PGHDbwkcJ5KebUl3SfGQ";
const AY: &str = "2uUIevgMQObsWEYt2uruvbqcgugPMXmnncoodHcJ9zQ";

fn point(x: &str, y: &str) -> JValue {
    j(&format!(r#"{{"x":"{}","y":"{}"}}"#, x, y))
}

#[test]
fn slug_forms_have_their_bounds() {
    assert!(forms::is_member_id("al") && forms::is_member_id("0a") && forms::is_member_id(&"a".repeat(32)));
    assert!(!forms::is_member_id("a") && !forms::is_member_id(&"a".repeat(33)));
    assert!(!forms::is_member_id("-a") && !forms::is_member_id("aB") && !forms::is_member_id("a_"));
    assert!(!forms::is_member_id("\u{e9}a"));
    assert!(forms::is_role_id("a") && forms::is_class_id("apple-se-bio"));
    assert!(!forms::is_role_id("0a") && !forms::is_class_id(""));
    assert!(forms::is_request_id("req-0001") && !forms::is_request_id("req-001"));
    assert!(forms::is_request_id(&"a".repeat(36)) && !forms::is_request_id(&"a".repeat(37)));
}

#[test]
fn text_forms_are_plain_ascii_within_their_length() {
    assert!(forms::is_label("alice se-bio") && !forms::is_label("") && !forms::is_label(&"a".repeat(65)));
    assert!(!forms::is_label("a\"b") && !forms::is_label("a\\b") && !forms::is_label("a\u{7f}") && !forms::is_label("caf\u{e9}"));
    assert!(forms::is_org_name(&"a".repeat(24)) && !forms::is_org_name(&"a".repeat(25)));
}

#[test]
fn decimal_is_zero_or_no_leading_zero_up_to_nine_digits() {
    for ok in ["0", "7", "10", "123456789"] {
        assert!(forms::is_decimal(ok), "{}", ok);
    }
    for bad in ["", "01", "-1", "1.5", "1234567890", "+1", " 1", "\u{661}"] {
        assert!(!forms::is_decimal(bad), "{}", bad);
    }
}

#[test]
fn time_is_a_real_utc_instant() {
    assert!(forms::is_time("2024-02-29T23:59:59Z"));
    for bad in [
        "2026-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-01-32T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00z",
        "2026-1-01T00:00:00Z",
    ] {
        assert!(!forms::is_time(bad), "{}", bad);
    }
    assert_eq!(forms::epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(forms::epoch_seconds("2000-01-01T00:00:00Z"), Some(946_684_800));
    assert_eq!(forms::epoch_seconds("2038-01-19T03:14:07Z"), Some(2_147_483_647));
    assert_eq!(forms::epoch_seconds("1969-12-31T23:59:59Z"), Some(-1));
    assert_eq!(forms::epoch_seconds("2026-13-01T00:00:00Z"), None);
    for t in [0i64, -1, 946_684_800, 2_147_483_647, 1_794_139_140, 4_102_444_800] {
        assert_eq!(forms::epoch_seconds(&forms::time(t)), Some(t));
    }
    assert_eq!(forms::time(946_684_800), "2000-01-01T00:00:00Z");
}

#[test]
fn hostname_is_lowercase_ldh_labels_with_checked_punycode() {
    for ok in ["r.example", "a", "relay-1.example.com", "xn--bcher-kva.example", &format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61))] {
        assert!(forms::is_hostname(ok), "{}", ok);
    }
    let long_label = "a".repeat(64);
    for bad in [
        "",
        ".",
        "a..b",
        "-a.example",
        "a-.example",
        "A.example",
        "a_b.example",
        "a b",
        "caf\u{e9}.example",
        "xn--",
        "xn--999999999999.example",
        long_label.as_str(),
    ] {
        assert!(!forms::is_hostname(bad), "{}", bad);
    }
    assert!(!forms::is_hostname(&"a.".repeat(127)), "254 bytes");
}

#[test]
fn key_forms_are_canonical_base64url_of_32_bytes() {
    assert!(forms::is_b64u32(X));
    assert!(!forms::is_b64u32("short") && !forms::is_b64u32(&"A".repeat(44)));
    assert!(!forms::is_b64u32(&format!("{}x", &X[..42])), "spare bits");
    assert!(forms::is_hashstr(&encoding::empty_hash()));
}

#[test]
fn points_must_lie_on_p256() {
    assert!(devicekey::point_ok(&point(X, Y)));
    assert!(devicekey::point_ok(&point(AX, AY)));
    assert!(!devicekey::point_ok(&point(X, X)), "off the curve");
    assert!(!devicekey::point_ok(&point(Y, X)));
    assert!(!devicekey::point_ok(&point(&"A".repeat(43), &"A".repeat(43))), "zero is not on the curve");
    let above_p = format!("{}w", "_".repeat(42));
    assert!(!devicekey::point_ok(&point(&above_p, Y)), "coordinate above p");
    assert!(!devicekey::point_ok(&point(X, "short")));
    assert!(!devicekey::point_ok(&j(&format!(r#"{{"x":"{}"}}"#, X))));
    assert!(!devicekey::point_ok(&j(&format!(r#"{{"x":"{}","y":"{}","z":null}}"#, X, Y))));
    assert!(!devicekey::point_ok(&j(r#""p""#)));
}

#[test]
fn key_defect_names_the_first_problem_in_order() {
    let sign = point(X, Y);
    let agree = point(AX, AY);
    assert_eq!(devicekey::defect(KID, &sign, &agree), None);
    assert_eq!(devicekey::defect(KID, &point(X, X), &agree), Some("sign_point"));
    assert_eq!(devicekey::defect(KID, &sign, &point(X, X)), Some("agree_point"));
    let wrong = format!("{}J", &KID[..42]);
    assert_eq!(devicekey::defect(&wrong, &sign, &agree), Some("kid_not_thumbprint"));
    assert_eq!(devicekey::defect(KID, &sign, &sign), Some("agree_equals_sign"));
}

#[test]
fn registry_is_the_embedded_spec_file() {
    let registry = Registry::standard();
    assert_eq!(registry.methods.len(), 10);
    let approve = &registry.methods["local:handsal.request.approve"];
    assert_eq!(approve.act_extra_keys, ["expires", "recipient", "relay", "request_id"]);
    assert_eq!(approve.inputs_hash, "raw_request_bytes");
    assert_eq!(registry.number("persons.min"), 2);
    assert_eq!(registry.number("chain_resolve_caps.endorsements_per_override.max"), 15);
    assert_eq!(registry.number("MAX_EXPIRES_IN_S"), 2_592_000);
    assert_eq!(registry.number("content_block.max_block_lines"), 32);
    assert_eq!(registry.lookup_class("apple-se-bio", false).unwrap().user_verification.as_deref(), Some("biometric_only"));
    assert!(registry.lookup_class("fixture-pin", false).is_none());
    assert!(registry.lookup_class("fixture-pin", true).is_some());
    // the first tag is macOS only: no Windows class and no pending class in the registry (T7.7, KC-02)
    assert!(registry.lookup_class("win-hello-hw", false).is_none());
    assert!(registry.lookup_class("win-hello-hw", true).is_none());
    assert!(registry.classes.values().all(|class| class.status != "pending-spike"));
    assert_eq!(registry.act_extra_key_types["relay"], Form::Hostname);
}

#[test]
fn profile_hashes_are_the_pins_computed_outside_the_code() {
    let profiles = Profiles::standard();
    // computed with openssl from the files by tools/repin.py, the one place the pins live
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/pins.json");
    let pins = handsal_core::json::parse(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(profiles.production, pins.get("production_profile").and_then(|v| v.str()).unwrap());
    assert_eq!(profiles.fixture, pins.get("fixture_profile").and_then(|v| v.str()).unwrap());
    assert_eq!(profiles.kind(&profiles.production), Some("production"));
    assert_eq!(profiles.kind(&profiles.fixture), Some("fixture"));
    assert_eq!(profiles.kind(&encoding::empty_hash()), None);
    assert_eq!(profiles.fixture_kids.len(), 18);
    assert!(profiles.is_fixture_kid("E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"));
    assert!(!profiles.is_fixture_kid("not-a-fixture-kid"));
}

/// KC-02: a tagged registry holds no `pending-spike` class, so the rule is proven on a registry that
/// has one, built from the shipped file with one more class.
#[test]
fn a_pending_class_is_refused_on_a_registry_that_has_one() {
    use handsal_core::policy;
    let shipped = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/registry.json")).unwrap();
    let pending = r#""key_classes": [{"alg":"ES256","hardware_bound":true,"id":"later-hw","per_signature_user_verification":true,"status":"pending-spike","user_verification":null},"#;
    let edited = shipped.replacen(r#""key_classes": ["#, pending, 1);
    assert_ne!(edited, shipped, "the registry file has no key_classes list to extend");
    let registry = Registry::from_bytes(edited.as_bytes()).unwrap();
    let rule = r#"{"persons":"2","roles":["maintainer"]}"#;
    let policy_with = |class: &str, uv: &str| j(&format!(
        r#"{{"classes":[{{"class":"{}","user_verification":"{}"}}],"freshness":{{"clock_skew_s":"300","max_validity_s":"604800","max_view_age_s":"86400"}},"relays":["r.example"],"roles":["maintainer","member"],"rules":{{"chain.resolve":{},"device.remove":{},"genesis.change":{},"member.add":{}}},"v":"handsal-policy/1","witness":{{"mode":"none"}}}}"#,
        class, uv, rule, rule, rule, rule));
    let members: Vec<JValue> = ["alice", "bob", "carol"].iter().map(|id| j(&format!(r#"{{"id":"{}","role":"maintainer"}}"#, id))).collect();
    let code = |class: &str, reg: &Registry| {
        policy::validate(Some(&policy_with(class, "biometric_only")), &members, &[], reg, true).unwrap_err().code
    };
    assert_eq!(code("later-hw", &registry), "class_pending");
    assert_eq!(code("later-hw", Registry::standard()), "class_unknown");
    assert_eq!(code("win-hello-hw", Registry::standard()), "class_unknown");
}

/// GP-02 `relays`: a sorted, unique list of 0 to 2 hostnames, required. Absence is never an empty list.
fn relays_policy(relays: Option<&str>) -> JValue {
    j(&relays_policy_text(relays))
}

fn relays_policy_text(relays: Option<&str>) -> String {
    let rule = r#"{"persons":"2","roles":["maintainer"]}"#;
    let relays = relays.map(|r| format!(r#""relays":{},"#, r)).unwrap_or_default();
    format!(
        r#"{{"classes":[{{"class":"apple-se-bio","user_verification":"biometric_only"}}],"freshness":{{"clock_skew_s":"300","max_validity_s":"604800","max_view_age_s":"86400"}},{}"roles":["maintainer","member"],"rules":{{"chain.resolve":{r},"device.remove":{r},"genesis.change":{r},"member.add":{r}}},"v":"handsal-policy/1","witness":{{"mode":"none"}}}}"#,
        relays, r = rule)
}

fn relays_verdict(relays: Option<&str>) -> Result<(), &'static str> {
    use handsal_core::policy;
    let members: Vec<JValue> = ["alice", "bob", "carol"].iter().map(|id| j(&format!(r#"{{"id":"{}","role":"maintainer"}}"#, id))).collect();
    policy::validate(Some(&relays_policy(relays)), &members, &[], Registry::standard(), false).map_err(|r| r.code)
}

#[test]
fn a_policy_carries_relays_and_without_it_is_policy_invalid() {
    assert_eq!(relays_verdict(Some(r#"["r.example"]"#)), Ok(()));
    assert_eq!(relays_verdict(Some(r#"["a.example","b.example"]"#)), Ok(()));
    assert_eq!(relays_verdict(Some("[]")), Ok(()), "an empty list is valid at founding");
    assert_eq!(relays_verdict(None), Err("policy_invalid"), "absence is never an empty list");
}

#[test]
fn relays_shape_and_bounds_have_their_codes() {
    assert_eq!(relays_verdict(Some(r#"["r.example","r.example"]"#)), Err("policy_invalid"));
    assert_eq!(relays_verdict(Some(r#"["Not A Host"]"#)), Err("policy_invalid"));
    assert_eq!(relays_verdict(Some(r#"[null]"#)), Err("policy_invalid"), "an entry that is no string; a number is not reachable here");
    assert_eq!(relays_verdict(Some(r#""r.example""#)), Err("policy_invalid"));
    assert_eq!(relays_verdict(Some(r#"["a.example","b.example","c.example"]"#)), Err("policy_out_of_bounds"));
}

/// A lone fixture original whose policy has `relays` as given (raw JSON text, so a value outside the canonical
/// subset can be written): the document `genesis::check_alone` judges end to end.
fn relays_document(relays: &str) -> JValue {
    let device = |kid: &str, person: &str| {
        format!(r#"{{"agree":{{"x":"{}","y":"{}"}},"class":"apple-se-bio","kid":"{}","label":"phone","person":"{}","sign":{{"x":"{}","y":"{}"}}}}"#, AX, AY, kid, person, X, Y)
    };
    let mut text = String::from(r#"{"devices":["#);
    text.push_str(&[device("k1", "alice"), device("k2", "bob"), device("k3", "carol")].join(","));
    text.push_str(r#"],"members":[{"id":"alice","role":"maintainer"},{"id":"bob","role":"maintainer"},{"id":"carol","role":"maintainer"}],"name":"acme","org":null,"prev":null,"profile":"uEiBaoxeB9R9OJoeq_7x99cxph-JSGlwaAGybMpG7cuPEeA","v":"handsal-genesis/1","policy":"#);
    text.push_str(&relays_policy_text(Some(relays)));
    text.push('}');
    j(&text)
}

/// GP-01: `relays` joins the sorted policy lists, so an unsorted one is `doc_not_sorted` (step 1),
/// before the policy is judged.
#[test]
fn unsorted_relays_are_doc_not_sorted() {
    use handsal_core::genesis;
    assert_eq!(genesis::check_alone(&relays_document(r#"["b.example","a.example"]"#)).unwrap_err().code, "doc_not_sorted");
    assert_ne!(genesis::check_alone(&relays_document(r#"["a.example","b.example"]"#)).unwrap_err().code, "doc_not_sorted");
}

/// GP-02, ACT-04: a JSON number inside `relays` is outside the canonical subset, so the document is no genesis
/// document (`genesis_schema`, step 1) before the policy is read. That is the only way a number reaches a
/// signer, and it is the answer of `pol/relays-number` (`vectors.rs` runs it).
#[test]
fn a_number_in_relays_is_genesis_schema() {
    use handsal_core::genesis;
    for relays in ["[5]", r#"["r.example",5]"#] {
        assert_eq!(genesis::check_alone(&relays_document(relays)).unwrap_err().code, "genesis_schema", "{}", relays);
    }
}
