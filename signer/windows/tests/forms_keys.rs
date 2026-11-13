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
    assert!(forms::is_record_id("ab") && !forms::is_record_id("a") && !forms::is_record_id(&"a".repeat(33)));
}

#[test]
fn text_forms_are_plain_ascii_within_their_length() {
    assert!(forms::is_label("alice se-bio") && !forms::is_label("") && !forms::is_label(&"a".repeat(65)));
    assert!(!forms::is_label("a\"b") && !forms::is_label("a\\b") && !forms::is_label("a\u{7f}") && !forms::is_label("caf\u{e9}"));
    assert!(forms::is_org_name(&"a".repeat(24)) && !forms::is_org_name(&"a".repeat(25)));
    assert!(forms::is_anchor(&"a".repeat(128)) && !forms::is_anchor(&"a".repeat(129)) && !forms::is_anchor(""));
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
    assert_eq!(registry.number("request_and_record_block.max_block_lines"), 32);
    assert_eq!(registry.lookup_class("apple-se-bio", false).unwrap().user_verification.as_deref(), Some("biometric_only"));
    assert!(registry.lookup_class("fixture-pin", false).is_none());
    assert!(registry.lookup_class("fixture-pin", true).is_some());
    assert_eq!(registry.lookup_class("win-hello-hw", false).unwrap().status, "pending-spike");
    assert_eq!(registry.act_extra_key_types["relay"], Form::Hostname);
}

#[test]
fn profile_hashes_are_the_pins_computed_outside_the_code() {
    let profiles = Profiles::standard();
    assert_eq!(profiles.production, "uEiB4GDZV_65eyT5v50lk60TIqnxq8LoPvGyRB9OvtWTygA");
    assert_eq!(profiles.fixture, "uEiDUOaenui4yV-QoVmwFFNb5OwbtU1qEJbyKsWjcdUBaUw");
    assert_eq!(profiles.kind(&profiles.production), Some("production"));
    assert_eq!(profiles.kind(&profiles.fixture), Some("fixture"));
    assert_eq!(profiles.kind(&encoding::empty_hash()), None);
    assert_eq!(profiles.fixture_kids.len(), 18);
    assert!(profiles.is_fixture_kid("E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"));
    assert!(!profiles.is_fixture_kid("not-a-fixture-kid"));
}
