//! SHA-256, encodings, the JSON reader, the canonical subset recognizer and the emitters
//! (T6.2, SG-01, ACT-03, ACT-04, ACT-05, ACT-11).

use handsal_core::emit;
use handsal_core::encoding;
use handsal_core::json::{self, JsonError};
use handsal_core::sha256;
use handsal_core::subset::{self, SubsetFailure};
use handsal_core::value::{JValue, Refusal};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

fn s(value: &str) -> JValue {
    JValue::String(value.to_string())
}

fn object(members: Vec<(&str, JValue)>) -> JValue {
    JValue::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

#[test]
fn sha256_matches_the_published_test_vectors() {
    assert_eq!(hex(&sha256::digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&sha256::digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(&sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // Lengths around the padding boundary: 55, 56, 63, 64 and 65 bytes.
    assert_eq!(hex(&sha256::digest(&[b'a'; 55])), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    assert_eq!(hex(&sha256::digest(&[b'a'; 56])), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    assert_eq!(hex(&sha256::digest(&[b'a'; 64])), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    assert_eq!(hex(&sha256::digest(&vec![b'a'; 1_000_000])), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

#[test]
fn base64url_round_trips_and_refuses_non_canonical_text() {
    assert_eq!(encoding::base64url(b"Man"), "TWFu");
    assert_eq!(encoding::base64url(&[0xfb, 0xff]), "-_8");
    assert_eq!(encoding::base64url_decode("TWFu"), Some(b"Man".to_vec()));
    assert_eq!(encoding::base64url_decode("TQ"), Some(vec![0x4d]));
    assert_eq!(encoding::base64url_decode("TR"), None, "spare bits set");
    assert_eq!(encoding::base64url_decode("T"), None, "one symbol is no group");
    assert_eq!(encoding::base64url_decode("TQ=="), None, "padding");
    assert_eq!(encoding::base64url_decode("+/8"), None, "standard alphabet");
    assert_eq!(encoding::base64url_decode(""), Some(vec![]));
}

#[test]
fn standard_base64_needs_padding_and_canonical_bits() {
    assert_eq!(encoding::base64_decode("TQ=="), Some(vec![0x4d]));
    assert_eq!(encoding::base64_decode("TWE="), Some(b"Ma".to_vec()));
    assert_eq!(encoding::base64_decode("TWFu"), Some(b"Man".to_vec()));
    assert_eq!(encoding::base64_decode("TQ="), None);
    assert_eq!(encoding::base64_decode("TQ"), None);
    assert_eq!(encoding::base64_decode("TR=="), None);
    assert_eq!(encoding::base64_decode("T==="), None);
    assert_eq!(encoding::base64_decode("-_8="), None, "url alphabet");
    assert_eq!(encoding::base64_decode(""), Some(vec![]));
}

#[test]
fn hashstr_and_thumbprint_match_the_vectors() {
    assert_eq!(encoding::empty_hash(), "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ");
    assert_eq!(encoding::hashstr(b""), encoding::empty_hash());
    assert!(encoding::is_hashstr(&encoding::empty_hash()));
    assert!(!encoding::is_hashstr("uEi"));
    assert!(!encoding::is_hashstr(&encoding::empty_hash().replace("uEi", "uEj")));
    // The last symbol carries two spare bits, so one that sets them is not canonical.
    let mut loose = encoding::empty_hash();
    loose.replace_range(46.., "W");
    assert!(!encoding::is_hashstr(&loose));
    assert_eq!(
        encoding::thumbprint("FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM", "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw"),
        "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
    );
}

#[test]
fn json_reader_reads_values_and_refuses_what_ijson_forbids() {
    let value = json::parse(br#" {"a":[1,-2.5e3,true,false,null],"b":"x\u00e9\n\ud83d\ude00"} "#).unwrap();
    let top = value.dict().unwrap();
    assert_eq!(
        top["a"],
        JValue::Array(vec![
            JValue::Number("1".into()),
            JValue::Number("-2.5e3".into()),
            JValue::Bool(true),
            JValue::Bool(false),
            JValue::Null
        ])
    );
    assert_eq!(top["b"], s("x\u{e9}\n\u{1f600}"));
    assert_eq!(json::parse(br#"{"a":1,"a":2}"#), Err(JsonError));
    assert_eq!(json::parse(br#"{"x":{"a":1,"a":2}}"#), Err(JsonError), "duplicate at depth");
    assert_eq!(json::parse(br#""\ud800""#), Err(JsonError), "lone surrogate");
    assert_eq!(json::parse(br#""\udc00""#), Err(JsonError));
    assert_eq!(json::parse(&[b'"', 0xff, b'"']), Err(JsonError), "invalid UTF-8");
    assert_eq!(json::parse(b"{} x"), Err(JsonError), "trailing bytes");
    assert_eq!(json::parse(b""), Err(JsonError));
    assert_eq!(json::parse(b"[1,]"), Err(JsonError));
    assert_eq!(json::parse(b"01"), Err(JsonError), "leading zero");
    assert_eq!(json::parse(b"\"a\nb\""), Err(JsonError), "raw control byte in a string");
    assert_eq!(json::parse(br#""\x""#), Err(JsonError));
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    assert_eq!(json::parse(deep.as_bytes()), Err(JsonError), "bounded nesting");
}

#[test]
fn subset_recognizer_accepts_the_grammar_and_nothing_else() {
    let ok = |bytes: &[u8]| subset::parse(bytes, 16_384);
    assert!(ok(br#"{"a":null,"b":["x",{}]}"#).is_ok());
    assert_eq!(ok(br#"{"b":null,"a":null}"#), Err(SubsetFailure::NotCanonical), "unsorted");
    assert_eq!(ok(br#"{"a":null,"a":null}"#), Err(SubsetFailure::NotCanonical), "duplicate");
    assert_eq!(ok(br#"{"a": null}"#), Err(SubsetFailure::NotCanonical), "whitespace");
    assert_eq!(ok(br#"{"a":1}"#), Err(SubsetFailure::NotCanonical), "number");
    assert_eq!(ok(br#"{"a":true}"#), Err(SubsetFailure::NotCanonical), "boolean");
    assert_eq!(ok(br#"{"a":"\n"}"#), Err(SubsetFailure::NotCanonical), "escape");
    assert_eq!(ok(&[b'"', 0xc3, 0xa9, b'"']), Err(SubsetFailure::NotCanonical), "non-ASCII");
    assert_eq!(ok(&[0xef, 0xbb, 0xbf, b'n', b'u', b'l', b'l']), Err(SubsetFailure::NotCanonical), "BOM");
    assert_eq!(ok(b"nullx"), Err(SubsetFailure::NotCanonical), "trailing byte");
    assert_eq!(subset::parse(&[b'a'; 17], 16), Err(SubsetFailure::TooLarge), "size is checked first");
    let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(ok(nested(8).as_bytes()).is_ok());
    assert_eq!(ok(nested(9).as_bytes()), Err(SubsetFailure::NotCanonical));
    let deep = nested(100_000);
    assert_eq!(subset::parse(deep.as_bytes(), 1 << 20), Err(SubsetFailure::NotCanonical), "no stack exhaustion");
}

#[test]
fn emitter_writes_sorted_compact_subset_bytes_and_refuses_the_rest() {
    let value = object(vec![("b", s("2")), ("a", JValue::Null), ("B", JValue::Array(vec![s("x"), JValue::Null]))]);
    assert_eq!(text(emit::subset(&value).unwrap()), r#"{"B":["x",null],"a":null,"b":"2"}"#);
    assert_eq!(text(emit::subset(&JValue::Array(vec![s("z"), s("a/b")])).unwrap()), r#"["z","a/b"]"#);
    assert_eq!(text(emit::subset(&object(vec![])).unwrap()), "{}");
    for bad in [
        JValue::Number("1".into()),
        JValue::Bool(true),
        s("caf\u{e9}"),
        s("a\"b"),
        s("a\\b"),
        s("a\nb"),
        s("\u{7f}"),
        object(vec![("k\u{e9}", JValue::Null)]),
        object(vec![("a", JValue::Number("1".into()))]),
    ] {
        assert_eq!(emit::subset(&bad), Err(Refusal::new("schema_refused")), "{:?}", bad);
    }
    let mut deep = JValue::Array(vec![]);
    for _ in 0..8 {
        deep = JValue::Array(vec![deep]);
    }
    assert!(emit::subset(&deep).is_err(), "nesting past 8");
    assert!(emit::subset(&s(&"a".repeat(16_384))).is_err(), "past MAX_PAYLOAD");
    // emit then recognize is the identity.
    let value = object(vec![("z", JValue::Array(vec![object(vec![("y", s("v")), ("x", JValue::Null)])])), ("a", s("a/b c"))]);
    let bytes = emit::subset(&value).unwrap();
    assert_eq!(subset::parse(&bytes, 16_384), Ok(value));
}

#[test]
fn result_line_writer_is_jcs_style() {
    let value = object(vec![("text", s("a\nb\"c\\d\u{1}")), ("first_line", s("x"))]);
    assert_eq!(text(emit::result_line(&value)), r#"{"first_line":"x","text":"a\nb\"c\\d\u0001"}"#);
    let value = object(vec![("canonical", JValue::Bool(false)), ("reason", JValue::Null), ("n", JValue::Number("5".into()))]);
    assert_eq!(text(emit::result_line(&value)), r#"{"canonical":false,"n":5,"reason":null}"#);
    assert_eq!(text(emit::result_line(&s("\u{e9}\u{1f600}"))), "\"\u{e9}\u{1f600}\"", "UTF-8 as is");
}

/// CF-03: arrays and objects count together, the root counts as 1, exactly MAX_NESTING levels pass
/// the reader and one more fails. The bound is the registry's constant, not a literal of the reader.
#[test]
fn json_nesting_is_bounded_at_max_nesting_with_the_root_counting_as_one() {
    let max = handsal_core::registry::Registry::standard().number("MAX_NESTING") as usize;
    assert_eq!(max, 64);
    let arrays = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let objects = |n: usize| format!("{}{{}}{}", r#"{"a":"#.repeat(n - 1), "}".repeat(n - 1));
    for build in [&arrays as &dyn Fn(usize) -> String, &objects] {
        assert!(json::parse(build(1).as_bytes()).is_ok());
        assert!(json::parse(build(max - 1).as_bytes()).is_ok(), "63 levels");
        assert!(json::parse(build(max).as_bytes()).is_ok(), "exactly the bound");
        assert_eq!(json::parse(build(max + 1).as_bytes()), Err(JsonError), "one more");
    }
    let mixed = format!("{}0{}", r#"[{"a":"#.repeat(32), "}]".repeat(32));
    assert!(json::parse(mixed.as_bytes()).is_ok());
    let over = format!("[{}0{}]", r#"[{"a":"#.repeat(32), "}]".repeat(32));
    assert_eq!(json::parse(over.as_bytes()), Err(JsonError));
}
