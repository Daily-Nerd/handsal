//! The draft a caller hands the signer (SG-04), the payload built from it, the `emit` command
//! (SG-01) and the draft form of `render` (RN-01). T6.3.

use handsal_core::cli::{Environment, Identity};
use handsal_core::commands;
use handsal_core::draft::{self, Draft, DraftParent, Fixed};
use handsal_core::encoding;
use handsal_core::json;
use handsal_core::value::{JValue, Refusal};

const KID: &str = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI";
const OTHER_KID: &str = "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY";
const TS: &str = "2026-11-08T11:59:00Z";

fn hs(seed: &str) -> String {
    encoding::hashstr(seed.as_bytes())
}

fn j(text: &str) -> JValue {
    json::parse(text.as_bytes()).unwrap_or_else(|_| panic!("bad test JSON: {}", text))
}

fn fixed() -> Fixed {
    Fixed { kid: KID.into(), nonce: hs("nonce"), performer: "alice".into(), ts: TS.into() }
}

fn head() -> String {
    format!(r#"{{"id":"{}","kind":"chain"}}"#, hs("h"))
}

fn remove_draft() -> String {
    format!(
        r#"{{"body":{{"kid":"{}","person":"carol"}},"method":"local:handsal.device.remove","org":"{}","parent":{{"id":"{}","performer":"bob"}}}}"#,
        OTHER_KID,
        hs("org"),
        hs("p")
    )
}

fn promote_draft() -> String {
    format!(
        r#"{{"body":{{"anchors":["a-1"],"record_id":"rec-0001"}},"expires_in_s":"3600","head":{},"method":"local:handsal.record.promote","org":"{}"}}"#,
        head(),
        hs("org")
    )
}

fn approve_draft() -> String {
    format!(
        r#"{{"body":{{}},"expires_in_s":"3600","head":{},"method":"local:handsal.request.approve","org":"{}","recipient":"alice","relay":"r.example","request_id":"req-00000001"}}"#,
        head(),
        hs("org")
    )
}

fn with(draft: &str, edit: impl FnOnce(&mut std::collections::BTreeMap<String, JValue>)) -> JValue {
    let mut value = j(draft);
    if let JValue::Object(members) = &mut value {
        edit(members);
    }
    value
}

fn set(draft: &str, key: &str, value: JValue) -> JValue {
    with(draft, |m| {
        m.insert(key.to_string(), value);
    })
}

fn without(draft: &str, key: &str) -> JValue {
    with(draft, |m| {
        m.remove(key);
    })
}

fn refused(code: &'static str, result: Result<impl std::fmt::Debug, Refusal>) {
    assert_eq!(result.unwrap_err(), Refusal::new(code));
}

#[test]
fn reads_a_valid_draft() {
    let draft = Draft::read(&j(&remove_draft())).unwrap();
    assert_eq!(draft.method, "local:handsal.device.remove");
    assert_eq!(draft.parent, Some(DraftParent { id: hs("p"), performer: Some("bob".into()) }));
    assert!(draft.expires_in_s.is_none() && draft.head.is_none());
    assert_eq!(Draft::read(&j(&promote_draft())).unwrap().expires_in_s, Some(3600));
    let verdict = Draft::read(&j(&approve_draft())).unwrap();
    assert_eq!((verdict.recipient.as_deref(), verdict.relay.as_deref()), (Some("alice"), Some("r.example")));
    assert_eq!(verdict.request_id.as_deref(), Some("req-00000001"));
}

#[test]
fn refuses_any_key_the_caller_may_not_supply() {
    for key in
        ["ts", "nonce", "inputs_hash", "outputs_hash", "display", "prompt", "text", "auth", "auth_context", "performer_id", "kid", "extra"]
    {
        refused("schema_refused", Draft::read(&set(&remove_draft(), key, JValue::string("x"))));
    }
}

#[test]
fn requires_the_closed_key_set() {
    for key in ["body", "method", "org"] {
        refused("schema_refused", Draft::read(&without(&remove_draft(), key)));
    }
    refused("schema_refused", Draft::read(&j(r#""x""#)));
    refused("schema_refused", Draft::read(&j("[]")));
    refused("schema_refused", Draft::read(&set(&remove_draft(), "org", JValue::string("uEi"))));
}

#[test]
fn unknown_method_is_unsupported() {
    refused("unsupported_method", Draft::read(&set(&remove_draft(), "method", JValue::string("local:handsal.request.send"))));
    refused("unsupported_method", Draft::read(&set(&remove_draft(), "method", JValue::string("LOCAL:handsal.device.remove"))));
}

#[test]
fn expires_in_s_is_present_iff_the_method_carries_expires() {
    refused("schema_refused", Draft::read(&set(&remove_draft(), "expires_in_s", JValue::string("60"))));
    refused("schema_refused", Draft::read(&without(&promote_draft(), "expires_in_s")));
    for bad in ["0", "2592001", "01", "-1", "", "1.5"] {
        refused("schema_refused", Draft::read(&set(&promote_draft(), "expires_in_s", JValue::string(bad))));
    }
    for bad in [JValue::Number("60".into()), JValue::Null] {
        refused("schema_refused", Draft::read(&set(&promote_draft(), "expires_in_s", bad)));
    }
    assert_eq!(Draft::read(&set(&promote_draft(), "expires_in_s", JValue::string("1"))).unwrap().expires_in_s, Some(1));
    assert_eq!(Draft::read(&set(&promote_draft(), "expires_in_s", JValue::string("2592000"))).unwrap().expires_in_s, Some(2_592_000));
}

#[test]
fn head_rules() {
    let endorse = |head: Option<&str>| {
        let mut text = format!(
            r#"{{"body":{{"act":"{}"}},"method":"local:handsal.act.endorse","org":"{}","parent":{{"id":"{}","performer":"bob"}}"#,
            hs("a"),
            hs("org"),
            hs("a")
        );
        if let Some(h) = head {
            text.push_str(&format!(r#","head":{}"#, h));
        }
        text.push('}');
        text
    };
    refused("schema_refused", Draft::read(&j(&endorse(None))));
    assert!(Draft::read(&j(&endorse(Some(&head())))).is_ok());
    refused("schema_refused", Draft::read(&set(&remove_draft(), "head", j(&head()))));
    for bad in [
        format!(r#"{{"id":"{}","kind":"merkle"}}"#, hs("h")),
        format!(r#"{{"id":"{}","kind":"chain","n":"1"}}"#, hs("h")),
        r#"{"id":"x","kind":"chain"}"#.to_string(),
        "null".to_string(),
    ] {
        refused("schema_refused", Draft::read(&set(&promote_draft(), "head", j(&bad))));
    }
    // genesis.sign: the head is due only for a change, which needs the document, so the builder decides.
    let genesis = format!(r#"{{"body":{{}},"method":"local:handsal.genesis.sign","org":"{}"}}"#, hs("org"));
    assert!(Draft::read(&j(&genesis)).unwrap().head.is_none());
    assert!(Draft::read(&set(&genesis, "head", j(&head()))).unwrap().head.is_some());
}

#[test]
fn parent_rules() {
    refused("schema_refused", Draft::read(&without(&remove_draft(), "parent")));
    refused("schema_refused", Draft::read(&set(&promote_draft(), "parent", j(&format!(r#"{{"id":"{}","performer":null}}"#, hs("p"))))));
    let root = set(&remove_draft(), "parent", j(&format!(r#"{{"id":"{}","performer":null}}"#, hs("p"))));
    assert_eq!(Draft::read(&root).unwrap().parent, Some(DraftParent { id: hs("p"), performer: None }));
    for bad in [
        format!(r#"{{"id":"{}"}}"#, hs("p")),
        r#"{"id":"x","performer":null}"#.to_string(),
        format!(r#"{{"id":"{}","performer":"A"}}"#, hs("p")),
        format!(r#"{{"id":"{}","performer":null,"extra":null}}"#, hs("p")),
        r#""p""#.to_string(),
    ] {
        refused("schema_refused", Draft::read(&set(&remove_draft(), "parent", j(&bad))));
    }
}

#[test]
fn body_is_validated_against_the_method_schema() {
    let extra = set(&remove_draft(), "body", j(&format!(r#"{{"kid":"{}","person":"carol","x":null}}"#, OTHER_KID)));
    refused("schema_refused", Draft::read(&extra));
    refused("schema_refused", Draft::read(&set(&remove_draft(), "body", j(r#"{"kid":"short","person":"carol"}"#))));
}

#[test]
fn verdict_drafts_carry_recipient_relay_and_request_id_and_no_other_method_does() {
    for key in ["recipient", "relay", "request_id"] {
        refused("schema_refused", Draft::read(&without(&approve_draft(), key)));
        refused("schema_refused", Draft::read(&set(&remove_draft(), key, JValue::string("alice"))));
        refused("schema_refused", Draft::read(&set(&promote_draft(), key, JValue::string("alice"))));
    }
    refused("schema_refused", Draft::read(&set(&approve_draft(), "recipient", JValue::string("Alice"))));
    refused("schema_refused", Draft::read(&set(&approve_draft(), "relay", JValue::string("R.example"))));
    refused("schema_refused", Draft::read(&set(&approve_draft(), "request_id", JValue::string("short"))));
    refused("schema_refused", Draft::read(&set(&approve_draft(), "parent", j(&format!(r#"{{"id":"{}","performer":null}}"#, hs("p"))))));
    for method in ["request.reject", "request.needs-info"] {
        let draft = set(&approve_draft(), "method", JValue::string(&format!("local:handsal.{}", method)));
        assert!(Draft::read(&draft).is_ok(), "{}", method);
    }
}

fn payload_text(draft: &str, attachments: &str) -> Result<String, Refusal> {
    let draft = Draft::read(&j(draft))?;
    let payload = draft::build(&draft, &j(attachments), &fixed())?;
    Ok(String::from_utf8(handsal_core::emit::subset(&payload)?).unwrap())
}

#[test]
fn builds_the_payload_the_signer_would_sign() {
    let e = encoding::empty_hash();
    let want = format!(
        concat!(
            r#"{{"action_ref":null,"binding":"local","cost":{{"rail_ref":null,"tokens":"0","usd_micros":"0","wall_ms":"0"}},"#,
            r#""ext":{{"dev.handsal/act":{{"body":{{"kid":"{o}","person":"carol"}},"kid":"{k}","org":"{org}"}}}},"#,
            r#""inputs_hash":"{e}","log_policy":"best_effort","method":"local:handsal.device.remove","nonce":"{n}","#,
            r#""outputs_hash":"{e}","parent_performer_id":"bob","parent_receipt_hash":"{p}","performer_id":"alice","#,
            r#""reason":null,"requester_id":null,"status":"OK","ts":"{ts}","v":"vitni/0.2"}}"#
        ),
        o = OTHER_KID,
        k = KID,
        org = hs("org"),
        e = e,
        n = hs("nonce"),
        p = hs("p"),
        ts = TS
    );
    assert_eq!(payload_text(&remove_draft(), "{}").unwrap(), want);
}

#[test]
fn expires_is_ts_plus_expires_in_s_and_the_act_object_carries_the_header_kid() {
    let body = format!("{{\"request_b64\":\"{}\"}}", "aGVsbG8=");
    let text = payload_text(&approve_draft(), &body).unwrap();
    assert!(text.contains(r#""expires":"2026-11-08T12:59:00Z""#), "{}", text);
    assert!(text.contains(&format!(r#""kid":"{}","org""#, KID)), "{}", text);
    assert!(text.contains(r#""recipient":"alice","relay":"r.example","request_id":"req-00000001""#), "{}", text);
    assert!(text.contains(&format!(r#""inputs_hash":"{}""#, hs("hello"))), "inputs_hash is the hash of the request bytes");
}

#[test]
fn the_body_attachments_fix_inputs_hash() {
    let text = payload_text(&promote_draft(), r#"{"record_body_b64":"aGVsbG8="}"#).unwrap();
    assert!(text.contains(&format!(r#""inputs_hash":"{}""#, hs("hello"))));
    refused("attachment_missing", payload_text(&promote_draft(), "{}"));
    refused("schema_refused", payload_text(&promote_draft(), r#"{"record_body_b64":"aGVsbG8"}"#));
    refused("attachment_missing", payload_text(&approve_draft(), "{}"));
}

#[test]
fn a_verdict_for_another_person_is_identity_mismatch() {
    let draft = set(&approve_draft(), "recipient", JValue::string("bob"));
    let draft = Draft::read(&draft).unwrap();
    refused("identity_mismatch", draft::build(&draft, &j(r#"{"request_b64":"aGVsbG8="}"#), &fixed()));
}

fn genesis_draft(org: &str, head: Option<&str>) -> String {
    let mut text = format!(r#"{{"body":{{}},"method":"local:handsal.genesis.sign","org":"{}""#, org);
    if let Some(h) = head {
        text.push_str(&format!(r#","head":{}"#, h));
    }
    text.push('}');
    text
}

#[test]
fn genesis_org_is_derived_from_the_attached_document() {
    let original = r#"{"devices":[],"members":[],"name":"x","org":null,"prev":null,"profile":"p","v":"handsal-genesis/1"}"#;
    let document_hash = encoding::hashstr(handsal_core::emit::subset(&j(original)).unwrap().as_slice());
    let attachments = format!(r#"{{"document":{}}}"#, original);
    let text = payload_text(&genesis_draft(&document_hash, None), &attachments).unwrap();
    assert!(text.contains(&format!(r#""inputs_hash":"{}""#, document_hash)));
    refused("attachment_mismatch", payload_text(&genesis_draft(&hs("other"), None), &attachments));
    refused("attachment_missing", payload_text(&genesis_draft(&document_hash, None), "{}"));
    // A head is due only for a change.
    refused("schema_refused", payload_text(&genesis_draft(&document_hash, Some(&head())), &attachments));
    let change = format!(
        r#"{{"devices":[],"head":"{}","members":[],"name":"x","org":"{}","prev":"{}","profile":"p","v":"handsal-genesis/1"}}"#,
        hs("h"),
        document_hash,
        document_hash
    );
    let change_attachments = format!(r#"{{"document":{}}}"#, change);
    assert!(payload_text(&genesis_draft(&document_hash, Some(&head())), &change_attachments).is_ok());
    refused("schema_refused", payload_text(&genesis_draft(&document_hash, None), &change_attachments));
    refused("attachment_mismatch", payload_text(&genesis_draft(&hs("other"), Some(&head())), &change_attachments));
}

fn emit_input(draft: &str, attachments: &str) -> JValue {
    j(&format!(
        r#"{{"attachments":{},"draft":{},"fixed":{{"kid":"{}","nonce":"{}","performer":"alice","ts":"{}"}}}}"#,
        attachments,
        draft,
        KID,
        hs("nonce"),
        TS
    ))
}

#[test]
fn emit_returns_the_payload_hex() {
    let out = commands::emit(&emit_input(&remove_draft(), "{}")).unwrap();
    let want = payload_text(&remove_draft(), "{}").unwrap();
    let hex: String = want.bytes().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(out, j(&format!(r#"{{"payload_hex":"{}"}}"#, hex)));
}

#[test]
fn emit_takes_exactly_attachments_draft_and_fixed() {
    let input = emit_input(&remove_draft(), "{}");
    for key in ["attachments", "draft", "fixed"] {
        let mut broken = input.clone();
        if let JValue::Object(m) = &mut broken {
            m.remove(key);
        }
        refused("schema_refused", commands::emit(&broken));
    }
    let mut extra = input.clone();
    if let JValue::Object(m) = &mut extra {
        m.insert("sender".into(), JValue::Null);
    }
    refused("schema_refused", commands::emit(&extra));
    refused("schema_refused", commands::emit(&j("[]")));
}

#[test]
fn emit_applies_the_draft_rules() {
    refused("schema_refused", commands::emit(&emit_input(&set(&remove_draft(), "ts", JValue::string(TS)).to_string_for_test(), "{}")));
    refused("unsupported_method", commands::emit(&emit_input(&set(&remove_draft(), "method", JValue::string("local:handsal.x")).to_string_for_test(), "{}")));
    let wrong = set(&approve_draft(), "recipient", JValue::string("bob")).to_string_for_test();
    refused("identity_mismatch", commands::emit(&emit_input(&wrong, r#"{"request_b64":"aGVsbG8="}"#)));
}

fn environment(identity: Option<Identity>) -> Environment {
    Environment::fixed(identity, 1_794_139_140, hs("nonce"))
}

#[test]
fn render_needs_a_key_and_fills_performer_kid_and_time() {
    let input = j(&format!(r#"{{"attachments":{{}},"draft":{}}}"#, remove_draft()));
    refused("key_unavailable", commands::render(&input, &environment(None)));
    let id = Identity { performer: "alice".into(), kid: KID.into() };
    let out = commands::render(&input, &environment(Some(id.clone()))).unwrap();
    let first = out.get("first_line").and_then(JValue::str).unwrap();
    assert_eq!(first, "Remove device NAjt fK8u Px9m of carol");
    let text = out.get("text").and_then(JValue::str).unwrap();
    assert!(text.contains("Signer: alice key E5ua 1p9O mQf5\n"), "{}", text);
    assert!(text.contains("Signed at: 2026-11-08T11:59:00Z"), "{}", text);
    // A draft the schema refuses is refused before the missing key matters.
    let bad = j(&format!(r#"{{"attachments":{{}},"draft":{}}}"#, set(&remove_draft(), "ts", JValue::string(TS)).to_string_for_test()));
    refused("schema_refused", commands::render(&bad, &environment(None)));
    refused("schema_refused", commands::render(&j(r#"{"draft":{}}"#), &environment(Some(id))));
}

trait ToStringForTest {
    fn to_string_for_test(&self) -> String;
}

impl ToStringForTest for JValue {
    fn to_string_for_test(&self) -> String {
        String::from_utf8(handsal_core::emit::result_line(self)).unwrap()
    }
}

/// ACT-09, VR-07: a verdict's `outputs_hash` is hashstr(JCS({"request_id":R,"verdict":V})) from the
/// act's `request_id` and the verdict of its method; every other method keeps EMPTY_HASH.
#[test]
fn a_verdict_outputs_hash_binds_request_id_and_verdict() {
    for (method, verdict) in [("approve", "approve"), ("reject", "reject"), ("needs-info", "needs-info")] {
        let draft = set(&approve_draft(), "method", JValue::string(&format!("local:handsal.request.{}", method))).to_string_for_test();
        let text = payload_text(&draft, r#"{"request_b64":"aGVsbG8="}"#).unwrap();
        let want = hs_bytes(&format!(r#"{{"request_id":"req-00000001","verdict":"{}"}}"#, verdict));
        assert!(text.contains(&format!(r#""outputs_hash":"{}""#, want)), "{}: {}", method, text);
    }
    let other = payload_text(&promote_draft(), r#"{"record_body_b64":"aGVsbG8="}"#).unwrap();
    assert!(other.contains(&format!(r#""outputs_hash":"{}""#, encoding::empty_hash())));
    assert_ne!(hs_bytes(r#"{"request_id":"req-00000001","verdict":"approve"}"#), hs_bytes(r#"{"request_id":"req-00000001","verdict":"reject"}"#));
}

fn hs_bytes(text: &str) -> String {
    encoding::hashstr(text.as_bytes())
}

/// SG-08 step 2 before step 3: the key's person is weighed before any attachment is read, so a
/// verdict for another person whose request is missing is `identity_mismatch`.
#[test]
fn identity_is_decided_before_an_attachment_is_read() {
    let wrong = set(&approve_draft(), "recipient", JValue::string("bob")).to_string_for_test();
    refused("identity_mismatch", commands::emit(&emit_input(&wrong, "{}")));
    refused("attachment_missing", commands::emit(&emit_input(&approve_draft(), "{}")));
}

/// SG-08 step 3: head presence is draft shape, so it comes before the `org` derived from the document.
#[test]
fn genesis_head_presence_comes_before_the_org_derivation() {
    let original = r#"{"devices":[],"members":[],"name":"x","org":null,"prev":null,"profile":"p","v":"handsal-genesis/1"}"#;
    let attachments = format!(r#"{{"document":{}}}"#, original);
    // an original with a head and a wrong org: the head decides
    refused("schema_refused", commands::emit(&emit_input(&genesis_draft(&hs("other"), Some(&head())), &attachments)));
    // the same draft without the head reaches the org check
    refused("attachment_mismatch", commands::emit(&emit_input(&genesis_draft(&hs("other"), None), &attachments)));
    // a change without a head and a wrong org
    let change = format!(
        r#"{{"devices":[],"head":"{}","members":[],"name":"x","org":"{}","prev":"{}","profile":"p","v":"handsal-genesis/1"}}"#,
        hs("h"),
        hs("o"),
        hs("o")
    );
    let change_attachments = format!(r#"{{"document":{}}}"#, change);
    refused("schema_refused", commands::emit(&emit_input(&genesis_draft(&hs("other"), None), &change_attachments)));
}

/// SG-04: `emit` checks the forms of the four `fixed` values, a missing or extra key included.
#[test]
fn emit_checks_the_forms_of_the_fixed_values() {
    let with_fixed = |kid: &str, nonce: &str, performer: &str, ts: &str| {
        j(&format!(
            r#"{{"attachments":{{}},"draft":{},"fixed":{{"kid":{},"nonce":{},"performer":{},"ts":{}}}}}"#,
            remove_draft(),
            kid,
            nonce,
            performer,
            ts
        ))
    };
    let q = |s: &str| format!("\"{}\"", s);
    let (kid, nonce, who, ts) = (q(KID), q(&hs("nonce")), q("alice"), q(TS));
    assert!(commands::emit(&with_fixed(&kid, &nonce, &who, &ts)).is_ok());
    let short = q("short");
    let long = q(&"A".repeat(44));
    let bad_nonce = q("not-a-hashstr");
    let cut_nonce = q(&hs("x")[..hs("x").len() - 1]);
    let upper = q("Alice");
    let empty = q("");
    let spaced = q("2026-11-08 11:59:00");
    let month = q("2026-13-08T11:59:00Z");
    for broken in [
        with_fixed(&short, &nonce, &who, &ts),
        with_fixed(&long, &nonce, &who, &ts),
        with_fixed(&kid, &bad_nonce, &who, &ts),
        with_fixed(&kid, &cut_nonce, &who, &ts),
        with_fixed(&kid, &nonce, &upper, &ts),
        with_fixed(&kid, &nonce, &empty, &ts),
        with_fixed(&kid, &nonce, &who, &spaced),
        with_fixed(&kid, &nonce, &who, &month),
        with_fixed(&kid, &nonce, &who, "null"),
        with_fixed("null", &nonce, &who, &ts),
    ] {
        refused("schema_refused", commands::emit(&broken));
    }
    let base = emit_input(&remove_draft(), "{}");
    for key in ["kid", "nonce", "performer", "ts", "extra"] {
        let mut changed = base.clone();
        if let JValue::Object(top) = &mut changed {
            if let Some(JValue::Object(f)) = top.get_mut("fixed") {
                if key == "extra" {
                    f.insert(key.into(), JValue::string("x"));
                } else {
                    f.remove(key);
                }
            }
        }
        refused("schema_refused", commands::emit(&changed));
    }
}

/// SG-08 step 3: an absent `document` is `attachment_missing` whatever the draft's `head` says,
/// because whether a head is due is known only from the document. One the signer cannot read is
/// `attachment_mismatch`.
#[test]
fn an_absent_genesis_document_is_missing_before_the_head_is_weighed() {
    refused("attachment_missing", commands::emit(&emit_input(&genesis_draft(&hs("org"), None), "{}")));
    refused("attachment_missing", commands::emit(&emit_input(&genesis_draft(&hs("org"), Some(&head())), "{}")));
    refused("attachment_mismatch", commands::emit(&emit_input(&genesis_draft(&hs("org"), Some(&head())), r#"{"document":"x"}"#)));
}

/// SG-08 step 1: the method is decided before the forms of `fixed`, and the shape of `fixed` before the method.
#[test]
fn an_unsupported_method_comes_before_a_malformed_fixed_value() {
    let draft = set(&approve_draft(), "method", JValue::string("local:handsal.request.send")).to_string_for_test();
    let input = |fixed: &str| {
        j(&format!(r#"{{"attachments":{{"request_b64":"aGVsbG8="}},"draft":{},"fixed":{}}}"#, draft, fixed))
    };
    let bad_nonce = format!(r#"{{"kid":"{}","nonce":"not-a-hashstr","performer":"alice","ts":"{}"}}"#, KID, TS);
    refused("unsupported_method", commands::emit(&input(&bad_nonce)));
    let no_ts = format!(r#"{{"kid":"{}","nonce":"{}","performer":"alice"}}"#, KID, hs("nonce"));
    refused("schema_refused", commands::emit(&input(&no_ts)));
}

/// SG-08, between steps 1 and 2: a refusal that needs no key is decided before `key_unavailable`;
/// what needs the key's person (here the attachment checks that follow it) comes after it.
#[test]
fn the_key_comes_after_the_form_of_the_draft_and_before_the_attachments() {
    let id = Identity { performer: "alice".into(), kid: KID.into() };
    let with_draft = |draft: &str| j(&format!(r#"{{"attachments":{{}},"draft":{}}}"#, draft));
    let malformed = without(&approve_draft(), "relay").to_string_for_test();
    refused("schema_refused", commands::render(&with_draft(&malformed), &environment(None)));
    refused("key_unavailable", commands::render(&with_draft(&approve_draft()), &environment(None)));
    refused("attachment_missing", commands::render(&with_draft(&approve_draft()), &environment(Some(id))));
}

/// base64url holds `-`, so the group separator must not be `-`: a kid of a real ceremony starts `pbubEyWn-20K`
/// and must read `pbub EyWn -20K`, never `pbub-EyWn--20K`.
#[test]
fn a_dash_of_the_alphabet_is_never_taken_for_the_group_separator() {
    use handsal_core::render::{hash12, kid12};
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    assert!(!alphabet.contains(' '));
    for at in 0..12 {
        let mut twelve: Vec<char> = "abcdefghijkl".chars().collect();
        twelve[at] = '-';
        let source: String = twelve.iter().collect();
        let want: Vec<String> = (0..3).map(|g| twelve[g * 4..g * 4 + 4].iter().collect()).collect();
        let kid = format!("{}{}", source, "q".repeat(31));
        let hash = format!("uEi{}{}", source, "q".repeat(28));
        assert_eq!(kid12(&kid).split(' ').collect::<Vec<_>>(), want, "kid, dash at {}", at);
        assert_eq!(hash12(&hash).split(' ').collect::<Vec<_>>(), want, "hash, dash at {}", at);
    }
    assert_eq!(kid12(&format!("pbubEyWn-20K{}", "q".repeat(31))), "pbub EyWn -20K");
    assert_eq!(kid12(&format!("FpA-qzTN5X8O{}", "q".repeat(31))), "FpA- qzTN 5X8O");
}
