//! T16.1 characterization of what the Rust core says about profiles, rewritten by T16.11 into the state after
//! the edition table. Each test still pins one behavior the table must keep, now through `resolve` and the
//! edition a document names.
//!
//! Rust has no ceremony (the ceremony refusal of `fixture_profile` and `profile_mismatch` lives only in
//! Swift), so the equivalent lock here is what `genesis::check_alone` does with the profile: it picks the
//! tables, it never refuses the hash. Step 2 of GP-15 belongs to the fold, which this core does not run.

mod common;

use common::*;
use handsal_core::cli::{self, Environment};
use handsal_core::genesis;
use handsal_core::json;
use handsal_core::profiles::Profiles;
use handsal_core::value::{JValue, Refusal};

fn code(result: Result<(), Refusal>) -> Option<&'static str> {
    result.err().map(|r| r.code)
}

#[test]
fn resolve_answers_production_fixture_and_none() {
    let current = Profiles::standard().current();
    let profiles = Profiles::standard();
    let hit = profiles.resolve(&current.production).unwrap();
    assert_eq!((hit.fixture, hit.edition.production.as_str()), (false, current.production.as_str()));
    let hit = profiles.resolve(&current.fixture).unwrap();
    assert_eq!((hit.fixture, hit.edition.fixture.as_str()), (true, current.fixture.as_str()));
    assert!(profiles.resolve(&hs("an edition this build does not implement")).is_none());
}

/// SG-02: the key set is `class, impl, profiles, spec`, in that order (T16.1 pinned `class, impl, spec`).
#[test]
fn version_returns_exactly_the_keys_class_impl_profiles_and_spec() {
    let environment = Environment::fixed(None, 0, hs("nonce")).with_key_class("apple-se-bio");
    let mut stdin = || -> Result<Vec<u8>, Refusal> { panic!("version reads no stdin") };
    let out = cli::run(&["version".to_string()], &mut stdin, &environment);
    assert_eq!(out.exit, 0);
    let parsed = json::parse(out.line.strip_suffix(b"\n").unwrap_or(&out.line)).unwrap();
    let JValue::Object(members) = parsed else { panic!("version is one object") };
    assert_eq!(members.keys().map(String::as_str).collect::<Vec<_>>(), ["class", "impl", "profiles", "spec"]);
    let production = Profiles::standard().current().production.as_str();
    assert_eq!(members["spec"].str(), Some(production));
    assert_eq!(members["profiles"].list().unwrap().iter().map(|p| p.str().unwrap()).collect::<Vec<_>>(), [production]);
}

/// The key of the vector rig that `fixture-kids.json` lists.
const FIXTURE_KEY: (&str, &str, &str) =
    ("E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI", "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM", "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw");

/// The D6 equivalent of the Swift ceremony refusals: this core never answers `profile_mismatch` or
/// `fixture_profile` for a document, whatever hash it names (GP-15 step 2 is the fold's); a well-formed
/// document is valid under all three names. A Rust ceremony written later must add those refusals itself
/// (`sign_is_still_the_internal_stub_until_a_rust_signer_resolves_profiles` in `cli.rs` names the obligation).
#[test]
fn check_alone_never_answers_a_profile_code_whatever_hash_the_document_names() {
    let current = Profiles::standard().current();
    let unknown = hs("an edition this build does not implement");
    for name in [&current.production, &current.fixture, &unknown] {
        assert_eq!(code(genesis::check_alone(&document(name))), None, "{}", name);
    }
}

/// Only a production hash is strict about fixture keys; the fixture hash and an unknown hash are evaluated
/// alike, leniently (the RN-09 status quo that the table keeps for an unknown hash).
#[test]
fn only_the_production_hash_refuses_a_fixture_key_and_an_unknown_hash_is_evaluated_like_the_fixture_one() {
    let profiles = Profiles::standard();
    let current = profiles.current();
    assert!(current.is_fixture_kid(FIXTURE_KEY.0));
    let unknown = hs("an edition this build does not implement");
    let evaluated = |name: &str| code(genesis::check_alone(&document_of(name, "apple-se-bio", FIXTURE_KEY)));
    assert_eq!(evaluated(&current.production), Some("fixture_key"));
    assert_eq!(evaluated(&current.fixture), None);
    assert_eq!(evaluated(&unknown), None);
}
