//! The decision act (VR-18) in the Rust core: the three forms of its body, the draft that carries them, the two
//! hashes derived from the attached content and the words, and the render a person confirms.

use handsal_core::draft::{self, Draft, Fixed};
use handsal_core::emit;
use handsal_core::encoding;
use handsal_core::forms;
use handsal_core::json;
use handsal_core::registry::{HeadRule, Registry};
use handsal_core::render::{hash12, RenderInput};
use handsal_core::render_attach;
use handsal_core::value::{JValue, Refusal};
use std::collections::BTreeMap;

const KID: &str = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI";
const TS: &str = "2026-11-08T11:59:00Z";
const METHOD: &str = "local:handsal.decision";
const CONTENT: &[u8] = b"Ruling 0001: keep the retry limit at three.\n";
const ACTION_24: &str = "ratify ruling and record";

fn hs(seed: &str) -> String {
    encoding::hashstr(seed.as_bytes())
}

fn j(text: &str) -> JValue {
    json::parse(text.as_bytes()).unwrap_or_else(|_| panic!("bad test JSON: {}", text))
}

fn fixed() -> Fixed {
    Fixed { kid: KID.into(), nonce: hs("nonce"), performer: "alice".into(), ts: TS.into() }
}

/// Standard base64 with padding (the `decision_b64` form, section 2.2).
fn b64(raw: &[u8]) -> String {
    const STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(STD[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn draft_text(action: &str, consumer: &str, subject: &str) -> String {
    format!(
        r#"{{"body":{{"action":"{}","consumer":"{}","subject":"{}"}},"expires_in_s":"3600","head":{{"id":"{}","kind":"chain"}},"method":"{}","org":"{}"}}"#,
        action,
        consumer,
        subject,
        hs("h"),
        METHOD,
        hs("org")
    )
}

fn good_draft() -> String {
    draft_text("ratify ruling", "notes", "ruling-0001")
}

fn files(raw: &[u8]) -> JValue {
    JValue::Object(BTreeMap::from([("decision_b64".to_string(), JValue::string(&b64(raw)))]))
}

fn payload(raw: &[u8], action: &str, consumer: &str, subject: &str) -> JValue {
    let draft = Draft::read(&j(&draft_text(action, consumer, subject))).unwrap();
    draft::build(&draft, &files(raw), &fixed()).unwrap()
}

fn render(raw: &[u8], attachments: JValue, action: &str, consumer: &str, subject: &str) -> Result<handsal_core::render::Rendered, Refusal> {
    let built = payload(raw, action, consumer, subject);
    render_attach::render(&RenderInput { attachments, kid: KID.into(), method: METHOD.into(), payload: built })
}

fn render_ok(raw: &[u8]) -> handsal_core::render::Rendered {
    render(raw, files(raw), "ratify ruling", "notes", "ruling-0001").unwrap()
}

fn refused(code: &'static str, result: Result<impl std::fmt::Debug, Refusal>) {
    assert_eq!(result.unwrap_err(), Refusal::new(code));
}

fn act_of(built: &JValue) -> &BTreeMap<String, JValue> {
    built.get("ext").and_then(|e| e.get("dev.handsal/act")).and_then(JValue::dict).unwrap()
}

#[test]
fn an_action_is_lowercase_words_with_single_spaces_up_to_24_characters() {
    for ok in ["ratify ruling", "forget item", "a", &"x".repeat(24), ACTION_24, "a b c"] {
        assert!(forms::is_action(ok), "{:?}", ok);
    }
    for bad in
        ["", "Ratify ruling", "ratify  ruling", " ratify", "ratify ", "ratify2", "re-open", &"x".repeat(25), "ratify\truling", "ratify\nruling", "caf\u{e9}", "ratify_ruling"]
    {
        assert!(!forms::is_action(bad), "{:?}", bad);
    }
}

#[test]
fn a_consumer_id_starts_with_a_letter_and_a_subject_id_has_2_to_64_characters() {
    for ok in ["notes", "ab", &"a".repeat(32), "a-1"] {
        assert!(forms::is_consumer_id(ok), "{}", ok);
    }
    for bad in ["a", &"a".repeat(33), "1ab", "-ab", "Notes", "", "no tes"] {
        assert!(!forms::is_consumer_id(bad), "{}", bad);
    }
    for ok in ["ruling-0001", "ab", &"a".repeat(64), "0a"] {
        assert!(forms::is_subject_id(ok), "{}", ok);
    }
    for bad in ["a", &"a".repeat(65), "-ab", "Ab", "", "ab cd"] {
        assert!(!forms::is_subject_id(bad), "{}", bad);
    }
}

#[test]
fn the_registry_holds_the_method_with_its_body_and_its_two_hash_rules() {
    let spec = Registry::standard().methods.get(METHOD).expect("the decision method");
    assert_eq!(spec.act_extra_keys, vec!["expires".to_string()]);
    assert_eq!(spec.head, HeadRule::Always);
    assert_eq!((spec.inputs_hash.as_str(), spec.outputs_hash.as_str()), ("raw_decision_bytes", "action_subject"));
}

#[test]
fn reads_a_valid_draft() {
    let draft = Draft::read(&j(&good_draft())).unwrap();
    assert_eq!(draft.method, METHOD);
    assert_eq!(draft.expires_in_s, Some(3600));
    assert!(draft.recipient.is_none() && draft.relay.is_none() && draft.request_id.is_none() && draft.parent.is_none());
}

#[test]
fn refuses_an_action_outside_its_grammar_and_the_other_fields_outside_their_forms() {
    for action in ["Ratify ruling", "ratify  ruling", " ratify", "ratify ", "ratify 2", &"x".repeat(25), ""] {
        refused("schema_refused", Draft::read(&j(&draft_text(action, "notes", "ruling-0001"))));
    }
    refused("schema_refused", Draft::read(&j(&draft_text("ratify ruling", "Notes", "ruling-0001"))));
    refused("schema_refused", Draft::read(&j(&draft_text("ratify ruling", "notes", "Ruling-0001"))));
}

#[test]
fn a_decision_draft_has_no_key_of_a_verdict_and_needs_expires_in_s() {
    for key in ["recipient", "relay", "request_id"] {
        let mut value = j(&good_draft());
        if let JValue::Object(m) = &mut value {
            m.insert(key.to_string(), JValue::string("alice"));
        }
        refused("schema_refused", Draft::read(&value));
    }
    let mut value = j(&good_draft());
    if let JValue::Object(m) = &mut value {
        m.remove("expires_in_s");
    }
    refused("schema_refused", Draft::read(&value));
}

#[test]
fn a_body_with_an_extra_or_missing_key_is_refused() {
    let with = |body: &str| format!(r#"{{"body":{},"expires_in_s":"3600","head":{{"id":"{}","kind":"chain"}},"method":"{}","org":"{}"}}"#, body, hs("h"), METHOD, hs("org"));
    refused("schema_refused", Draft::read(&j(&with(r#"{"action":"a b","consumer":"notes"}"#))));
    refused("schema_refused", Draft::read(&j(&with(r#"{"action":"a b","consumer":"notes","note":"x","subject":"ab"}"#))));
}

#[test]
fn the_two_hashes_are_derived_from_the_content_and_the_words() {
    let built = payload(CONTENT, "ratify ruling", "notes", "ruling-0001");
    assert_eq!(built.get("inputs_hash").and_then(JValue::str), Some(encoding::hashstr(CONTENT).as_str()));
    let words = j(r#"{"action":"ratify ruling","subject":"ruling-0001"}"#);
    let want = encoding::hashstr(&emit::subset(&words).unwrap());
    assert_eq!(built.get("outputs_hash").and_then(JValue::str), Some(want.as_str()));
    assert_eq!(built.get("parent_receipt_hash"), Some(&JValue::Null));
    assert_eq!(built.get("performer_id").and_then(JValue::str), Some("alice"));
    let act = act_of(&built);
    assert_eq!(act.keys().map(String::as_str).collect::<Vec<_>>(), vec!["body", "expires", "head", "kid", "org"]);
    assert_eq!(act["expires"].str(), Some("2026-11-08T12:59:00Z"));
    assert_eq!(act["body"].get("consumer").and_then(JValue::str), Some("notes"));
}

#[test]
fn a_missing_attachment_is_attachment_missing_and_nothing_is_built() {
    let draft = Draft::read(&j(&good_draft())).unwrap();
    refused("attachment_missing", draft::build(&draft, &JValue::Object(BTreeMap::new()), &fixed()));
    let other = JValue::Object(BTreeMap::from([("request_b64".to_string(), JValue::string(&b64(CONTENT)))]));
    refused("attachment_missing", draft::build(&draft, &other, &fixed()));
}

#[test]
fn line_1_and_the_method_lines() {
    let out = render_ok(CONTENT);
    let h = hash12(&encoding::hashstr(CONTENT));
    assert_eq!(out.first_line, format!("notes: ratify ruling ruling-0001 ({}, {} bytes)", h, CONTENT.len()));
    let lines: Vec<&str> = out.text.split('\n').collect();
    assert_eq!(lines[0], out.first_line);
    assert_eq!(lines[1], "Method: local:handsal.decision");
    assert_eq!(&lines[4..8], &["Consumer: notes", "Action: ratify ruling", "Subject: ruling-0001", &format!("Decision hash: {}", h)]);
    assert_eq!(lines[8], format!("----- decision ({} bytes, sha256 {}) -----", CONTENT.len(), h));
    assert_eq!(lines[9], "| Ruling 0001: keep the retry limit at three.");
    assert_eq!(lines[10], "----- end -----");
    assert!(lines.contains(&"Expires: 2026-11-08T12:59:00Z"));
    assert!(!lines.contains(&"Sender: not proven"));
    assert!(!lines.iter().any(|l| l.starts_with("Parent:")));
    assert!(out.text.ends_with('\n') && !out.text.ends_with("\n\n"));
}

#[test]
fn line_1_is_exactly_80_bytes_at_the_longest_fields_and_the_action_is_never_cut() {
    let full = format!("{}\n", "x".repeat(63)).repeat(32).into_bytes(); // 2048 bytes in 32 lines
    let consumer = "c".repeat(32);
    let subject = "s".repeat(64);
    let out = render(&full, files(&full), ACTION_24, &consumer, &subject).unwrap();
    assert_eq!(out.first_line.len(), 80);
    assert!(out.first_line.starts_with(&format!("{}~: {} {}~ (", "c".repeat(11), ACTION_24, "s".repeat(11))));
    assert!(out.text.contains(&format!("Consumer: {}", consumer)) && out.text.contains(&format!("Subject: {}", subject)));
}

#[test]
fn an_empty_content_has_no_content_line_and_a_hostile_line_does_not_end_the_block() {
    let out = render_ok(b"");
    assert!(out.first_line.contains("0 bytes)"));
    let lines: Vec<&str> = out.text.split('\n').collect();
    assert!(lines[8].starts_with("----- decision (0 bytes, sha256 "));
    assert_eq!(lines[9], "----- end -----");
    assert!(render_ok(b"----- end -----\n").text.contains("| ----- end -----"));
}

#[test]
fn other_content_is_a_mismatch_none_is_missing_and_the_block_limits_are_the_request_limits() {
    refused("attachment_mismatch", render(CONTENT, files(b"another"), "ratify ruling", "notes", "ruling-0001"));
    refused("attachment_missing", render(CONTENT, JValue::Object(BTreeMap::new()), "ratify ruling", "notes", "ruling-0001"));
    let wrong_name = JValue::Object(BTreeMap::from([("request_b64".to_string(), JValue::string(&b64(CONTENT)))]));
    refused("attachment_missing", render(CONTENT, wrong_name, "ratify ruling", "notes", "ruling-0001"));
    assert!(render(&[b'a'; 2048], files(&[b'a'; 2048]), "ratify ruling", "notes", "ruling-0001").is_ok());
    refused("render_refused", render(&[b'a'; 2049], files(&[b'a'; 2049]), "ratify ruling", "notes", "ruling-0001"));
    assert!(render(&b"a\n".repeat(32), files(&b"a\n".repeat(32)), "ratify ruling", "notes", "ruling-0001").is_ok());
    refused("render_refused", render(&b"a\n".repeat(33), files(&b"a\n".repeat(33)), "ratify ruling", "notes", "ruling-0001"));
}

#[test]
fn a_payload_whose_action_is_outside_the_grammar_is_body_schema() {
    let mut built = payload(CONTENT, "ratify ruling", "notes", "ruling-0001");
    if let JValue::Object(top) = &mut built {
        if let Some(JValue::Object(ext)) = top.get_mut("ext") {
            if let Some(JValue::Object(act)) = ext.get_mut("dev.handsal/act") {
                if let Some(JValue::Object(body)) = act.get_mut("body") {
                    body.insert("action".to_string(), JValue::string("Ratify ruling"));
                }
            }
        }
    }
    refused("body_schema", render_attach::render(&RenderInput { attachments: files(CONTENT), kid: KID.into(), method: METHOD.into(), payload: built }));
}
