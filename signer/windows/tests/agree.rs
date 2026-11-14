//! The `agree` command (SG-16) and the agreement key (KC-09) in the Rust core, on a software key.
//!
//! The core owns the command's input and output, the form of `context` and the layout of the HKDF `info`. A key
//! backend (T6.6, CNG) will own the key and do the key agreement and the HKDF itself, so the raw shared secret
//! never crosses the port. The software key here is test code: its P-256 multiply is built on the core's field
//! arithmetic, its HMAC and HKDF on the core's SHA-256, and every answer is checked against
//! `conformance/fixtures/agree-kat.json`, which a pure Python derivation wrote and the `cryptography` package
//! recomputed (`_gen/tests/test_agree_kat.py`).

use handsal_core::agree::{self, AgreementKey, Point65};
use handsal_core::cli::{self, Environment};
use handsal_core::devicekey::{add_mod, from_be, mul_mod, sub_mod, to_be, U256, P};
use handsal_core::encoding;
use handsal_core::forms;
use handsal_core::json;
use handsal_core::sha256;
use handsal_core::value::{JValue, Refusal};
use std::path::PathBuf;

// MARK: a software P-256 key (test code)

const GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn double_mod(a: &U256) -> U256 {
    add_mod(a, a)
}

fn pow_mod(base: &U256, exponent: &U256) -> U256 {
    let mut result: U256 = [1, 0, 0, 0];
    for bit in (0..256).rev() {
        result = mul_mod(&result, &result);
        if (exponent[bit / 64] >> (bit % 64)) & 1 == 1 {
            result = mul_mod(&result, base);
        }
    }
    result
}

/// Jacobian coordinates; `None` is the point at infinity.
type Jacobian = Option<(U256, U256, U256)>;

fn double(p: &Jacobian) -> Jacobian {
    let (x, y, z) = (*p)?;
    if y == [0; 4] {
        return None;
    }
    let delta = mul_mod(&z, &z);
    let gamma = mul_mod(&y, &y);
    let beta = mul_mod(&x, &gamma);
    let alpha = {
        let t = mul_mod(&sub_mod(&x, &delta), &add_mod(&x, &delta));
        add_mod(&double_mod(&t), &t)
    };
    let eight_beta = double_mod(&double_mod(&double_mod(&beta)));
    let x3 = sub_mod(&mul_mod(&alpha, &alpha), &eight_beta);
    let yz = add_mod(&y, &z);
    let z3 = sub_mod(&sub_mod(&mul_mod(&yz, &yz), &gamma), &delta);
    let four_beta = double_mod(&double_mod(&beta));
    let eight_gamma_sq = double_mod(&double_mod(&double_mod(&mul_mod(&gamma, &gamma))));
    let y3 = sub_mod(&mul_mod(&alpha, &sub_mod(&four_beta, &x3)), &eight_gamma_sq);
    Some((x3, y3, z3))
}

fn add(a: &Jacobian, b: &Jacobian) -> Jacobian {
    let (Some((x1, y1, z1)), Some((x2, y2, z2))) = (a, b) else { return a.or(*b) };
    let z1z1 = mul_mod(z1, z1);
    let z2z2 = mul_mod(z2, z2);
    let u1 = mul_mod(x1, &z2z2);
    let u2 = mul_mod(x2, &z1z1);
    let s1 = mul_mod(&mul_mod(y1, z2), &z2z2);
    let s2 = mul_mod(&mul_mod(y2, z1), &z1z1);
    if u1 == u2 {
        return if s1 == s2 { double(a) } else { None };
    }
    let h = sub_mod(&u2, &u1);
    let i = mul_mod(&double_mod(&h), &double_mod(&h));
    let j = mul_mod(&h, &i);
    let r = double_mod(&sub_mod(&s2, &s1));
    let v = mul_mod(&u1, &i);
    let x3 = sub_mod(&sub_mod(&mul_mod(&r, &r), &j), &double_mod(&v));
    let y3 = sub_mod(&mul_mod(&r, &sub_mod(&v, &x3)), &double_mod(&mul_mod(&s1, &j)));
    let zz = add_mod(z1, z2);
    let z3 = mul_mod(&sub_mod(&sub_mod(&mul_mod(&zz, &zz), &z1z1), &z2z2), &h);
    Some((x3, y3, z3))
}

/// `scalar * (x, y)` as affine big-endian coordinates, `None` for infinity.
fn multiply(scalar: &[u8; 32], x: &[u8], y: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let point: Jacobian = Some((from_be(x), from_be(y), [1, 0, 0, 0]));
    let mut acc: Jacobian = None;
    for byte in scalar {
        for bit in (0..8).rev() {
            acc = double(&acc);
            if (byte >> bit) & 1 == 1 {
                acc = add(&acc, &point);
            }
        }
    }
    let (x, y, z) = acc?;
    let zinv = pow_mod(&z, &sub_mod(&P, &[2, 0, 0, 0]));
    let zinv2 = mul_mod(&zinv, &zinv);
    Some((to_be(&mul_mod(&x, &zinv2)), to_be(&mul_mod(&y, &mul_mod(&zinv2, &zinv)))))
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let inner: Vec<u8> = block.iter().map(|b| b ^ 0x36).chain(message.iter().copied()).collect();
    let outer: Vec<u8> = block.iter().map(|b| b ^ 0x5c).chain(sha256::digest(&inner)).collect();
    sha256::digest(&outer)
}

/// RFC 5869 HKDF with SHA-256; an empty salt is HashLen zero bytes.
fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let salt: Vec<u8> = if salt.is_empty() { vec![0; 32] } else { salt.to_vec() };
    let prk = hmac(&salt, ikm);
    let mut out = Vec::new();
    let mut block: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let input: Vec<u8> = block.iter().chain(info).copied().chain([counter]).collect();
        block = hmac(&prk, &input).to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(length);
    out
}

struct SoftKey {
    scalar: [u8; 32],
}

impl SoftKey {
    fn new(scalar_hex: &str) -> SoftKey {
        SoftKey { scalar: hex(scalar_hex).try_into().unwrap() }
    }

    fn secret(&self, peer: &Point65) -> [u8; 32] {
        multiply(&self.scalar, &peer[1..33], &peer[33..65]).expect("not infinity").0
    }
}

impl AgreementKey for SoftKey {
    fn public(&self) -> Point65 {
        let (x, y) = multiply(&self.scalar, &hex(GX), &hex(GY)).unwrap();
        let mut out = [4u8; 65];
        out[1..33].copy_from_slice(&x);
        out[33..].copy_from_slice(&y);
        out
    }

    fn agree(&self, peer: &Point65, info: &[u8]) -> Result<[u8; agree::KEY_LENGTH], Refusal> {
        Ok(hkdf(&self.secret(peer), &[], info, agree::KEY_LENGTH).try_into().unwrap())
    }
}

// MARK: the known answers

struct Known {
    id: String,
    context: String,
    key: String,
    scalar: String,
    own: Point65,
    peer: Point65,
    info_hex: String,
}

fn point65(value: &JValue) -> Point65 {
    let part = |k: &str| encoding::base64url_decode(value.get(k).unwrap().str().unwrap()).unwrap();
    let mut out = [4u8; 65];
    out[1..33].copy_from_slice(&part("x"));
    out[33..].copy_from_slice(&part("y"));
    out
}

fn knowns() -> Vec<Known> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures/agree-kat.json");
    let doc = json::parse(&std::fs::read(path).unwrap()).unwrap();
    let text = |row: &JValue, k: &str| row.get(k).unwrap().str().unwrap().to_string();
    doc.get("vectors")
        .unwrap()
        .list()
        .unwrap()
        .iter()
        .map(|row| Known {
            id: text(row, "id"),
            context: text(row, "context"),
            key: text(row, "key"),
            scalar: text(row.get("own").unwrap(), "d"),
            own: point65(row.get("own").unwrap()),
            peer: point65(row.get("peer").unwrap()),
            info_hex: text(row, "info_hex"),
        })
        .collect()
}

fn named(id: &str) -> Known {
    knowns().into_iter().find(|k| k.id == id).unwrap()
}

// MARK: running the command

fn point_value(p: &Point65) -> String {
    format!(r#"{{"x":"{}","y":"{}"}}"#, encoding::base64url(&p[1..33]), encoding::base64url(&p[33..]))
}

fn input(context: &str, peer: &Point65) -> String {
    format!(r#"{{"context":"{}","peer":{}}}"#, context, point_value(peer))
}

fn environment(key: Option<SoftKey>) -> Environment {
    let environment = Environment::fixed(None, 0, encoding::hashstr(b"nonce"));
    match key {
        Some(key) => environment.with_agreement_key(Box::new(key)),
        None => environment,
    }
}

fn run(environment: &Environment, stdin: &str) -> (i32, String) {
    let mut bytes = || -> Result<Vec<u8>, Refusal> { Ok(stdin.as_bytes().to_vec()) };
    let out = cli::run(&["agree".to_string()], &mut bytes, environment);
    (out.exit, String::from_utf8(out.line).unwrap())
}

fn error(code: &str) -> String {
    format!(r#"{{"error":"{}"}}"#, code)
}

/// A second point on the curve, for the peer: the fixture public key of another label.
fn other_point() -> Point65 {
    named("other-pair").peer
}

#[test]
fn the_test_hkdf_is_rfc_5869() {
    // RFC 5869 appendix A, test cases 1 and 3 (SHA-256): the support code is pinned before anything relies on it.
    let okm1 = hkdf(&[0x0b; 22], &hex("000102030405060708090a0b0c"), &hex("f0f1f2f3f4f5f6f7f8f9"), 42);
    assert_eq!(
        to_hex(&okm1),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    let okm3 = hkdf(&[0x0b; 22], &[], &[], 42);
    assert_eq!(
        to_hex(&okm3),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn the_test_multiply_gives_the_fixture_public_points() {
    for known in knowns() {
        assert_eq!(SoftKey::new(&known.scalar).public(), known.own, "{}", known.id);
    }
}

#[test]
fn the_known_answers_are_derived_from_fixture_keys() {
    let all = knowns();
    assert!(all.len() >= 5);
    for known in all {
        let env = environment(Some(SoftKey::new(&known.scalar)));
        let (exit, line) = run(&env, &input(&known.context, &known.peer));
        assert_eq!((exit, line), (0, format!(r#"{{"key":"{}"}}"#, known.key)), "{}", known.id);
    }
}

#[test]
fn the_info_layout_is_the_one_the_spec_states() {
    for known in knowns() {
        let info = agree::info(&known.own, &known.peer, &known.context);
        assert_eq!(to_hex(&info), known.info_hex, "{}", known.id);
        assert_eq!(&info[..16], b"handsal-agree/1\0");
        assert_eq!(info.len(), 16 + 65 + 65 + known.context.len());
    }
}

#[test]
fn both_parties_of_one_pair_derive_the_same_key() {
    let (a, b) = (named("basic"), named("other-side"));
    let first = run(&environment(Some(SoftKey::new(&a.scalar))), &input(&a.context, &a.peer));
    let second = run(&environment(Some(SoftKey::new(&b.scalar))), &input(&b.context, &b.peer));
    assert_eq!(first.0, 0);
    assert_eq!(first, second);
    assert_eq!(agree::info(&a.own, &a.peer, &a.context), agree::info(&b.own, &b.peer, &b.context));
}

#[test]
fn a_different_context_or_peer_gives_another_key() {
    let known = named("basic");
    let env = environment(Some(SoftKey::new(&known.scalar)));
    let one = run(&env, &input("one", &known.peer));
    let two = run(&env, &input("two", &known.peer));
    let elsewhere = run(&env, &input("one", &other_point()));
    assert!(one.0 == 0 && two.0 == 0 && elsewhere.0 == 0);
    assert!(one.1 != two.1 && one.1 != elsewhere.1 && two.1 != elsewhere.1);
    assert_eq!(one, run(&env, &input("one", &known.peer)));
}

#[test]
fn the_answer_is_the_key_and_nothing_else_and_never_the_shared_secret() {
    let known = named("basic");
    let soft = SoftKey::new(&known.scalar);
    let secret = soft.secret(&known.peer);
    let (exit, line) = run(&environment(Some(soft)), &input(&known.context, &known.peer));
    assert_eq!(exit, 0);
    let answer = json::parse(line.as_bytes()).unwrap();
    assert_eq!(answer.dict().unwrap().keys().collect::<Vec<_>>(), vec!["key"]);
    let key = answer.get("key").unwrap().str().unwrap();
    assert_eq!(key.len(), 43);
    assert_eq!(encoding::base64url_decode(key).unwrap().len(), 32);
    // the key scan of SG-03 for this command: neither the scalar nor the secret, in any form a person could paste
    for needle in [hex(&known.scalar), secret.to_vec()] {
        for form in [to_hex(&needle), to_hex(&needle).to_uppercase(), encoding::base64url(&needle)] {
            assert!(!line.contains(&form), "output carries {}", form);
        }
    }
    // HKDF without the handsal label is another key: the label is part of the output's domain
    let unlabelled = hkdf(&secret, &[], known.context.as_bytes(), 32);
    assert_ne!(encoding::base64url_decode(key).unwrap(), unlabelled);
}

#[test]
fn the_input_is_a_closed_context_and_peer_and_anything_else_is_schema_refused() {
    let known = named("basic");
    let peer = point_value(&known.peer);
    let off = format!(r#"{{"x":"{}","y":"{}"}}"#, encoding::base64url(&[1u8; 32]), encoding::base64url(&[2u8; 32]));
    let long = "a".repeat(129);
    let bad = [
        "{}".to_string(),
        format!(r#"{{"context":"a"}}"#),
        format!(r#"{{"peer":{}}}"#, peer),
        format!(r#"{{"context":"a","peer":{},"extra":null}}"#, peer),
        format!(r#"{{"context":"","peer":{}}}"#, peer),
        format!(r#"{{"context":"{}","peer":{}}}"#, long, peer),
        format!(r#"{{"context":"has space","peer":{}}}"#, peer),
        format!(r#"{{"context":"café","peer":{}}}"#, peer),
        format!(r#"{{"context":"a\u007f","peer":{}}}"#, peer),
        format!(r#"{{"context":"quo\"te","peer":{}}}"#, peer),
        format!(r#"{{"context":"back\\slash","peer":{}}}"#, peer),
        format!(r#"{{"context":null,"peer":{}}}"#, peer),
        r#"{"context":"a","peer":null}"#.to_string(),
        r#"{"context":"a","peer":"x"}"#.to_string(),
        format!(r#"{{"context":"a","peer":{{"x":"{}"}}}}"#, encoding::base64url(&known.peer[1..33])),
        format!(r#"{{"context":"a","peer":{{"x":"{}","y":"{}","z":"q"}}}}"#, encoding::base64url(&known.peer[1..33]), encoding::base64url(&known.peer[33..])),
        format!(r#"{{"context":"a","peer":{}}}"#, off),
        "[]".to_string(),
        r#""x""#.to_string(),
    ];
    for text in bad {
        let env = environment(Some(SoftKey::new(&known.scalar)));
        assert_eq!(run(&env, &text), (2, error("schema_refused")), "{}", text);
    }
    for context in ["a".to_string(), "~".repeat(128), "!#$%&'()*+,-./0129:;<=>?@AZ[]^_`az{|}~".to_string()] {
        let env = environment(Some(SoftKey::new(&known.scalar)));
        assert_eq!(run(&env, &input(&context, &known.peer)).0, 0, "{}", context);
    }
}

#[test]
fn the_context_form_is_the_signed_alphabet_without_space_1_to_128() {
    assert!(forms::is_agree_context("a") && forms::is_agree_context(&"~".repeat(128)) && forms::is_agree_context("mail/v1"));
    for bad in ["", &"x".repeat(129), "has space", "tab\t", "caf\u{e9}", "\u{7f}", "new\nline", "quo\"te", "back\\slash"] {
        assert!(!forms::is_agree_context(bad), "{:?}", bad);
    }
}

#[test]
fn the_form_is_decided_before_the_key_and_no_key_is_key_unavailable() {
    let known = named("basic");
    let none = environment(None);
    assert_eq!(run(&none, r#"{"context":"a"}"#), (2, error("schema_refused")));
    assert_eq!(run(&none, &input("a", &known.peer)), (3, error("key_unavailable")));
}

#[test]
fn agree_reads_one_object_and_a_second_argument_is_unsupported_command() {
    let env = environment(None);
    let mut calls = 0;
    let mut bytes = || -> Result<Vec<u8>, Refusal> {
        calls += 1;
        Ok(b"{}".to_vec())
    };
    let out = cli::run(&["agree".to_string()], &mut bytes, &env);
    assert_eq!((calls, out.exit), (1, 2));
    let mut none = || -> Result<Vec<u8>, Refusal> { panic!("not read") };
    let extra = cli::run(&["agree".to_string(), "now".to_string()], &mut none, &env);
    assert_eq!((extra.exit, String::from_utf8(extra.line).unwrap()), (2, error("unsupported_command")));
}

#[test]
fn no_api_returns_the_shared_secret_only_derived_bytes_cross_the_port() {
    let source = include_str!("../core/agree.rs");
    let code: String = source.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    assert!(code.contains("fn agree(&self, peer: &Point65, info: &[u8]) -> Result<[u8; KEY_LENGTH], Refusal>"));
    assert!(!code.to_lowercase().contains("shared_secret") && !code.contains("fn secret"));
    // the core itself never multiplies a point: that is the key backend's work, so no scalar ever reaches the core
    assert!(!code.contains("scalar"));
}
