//! T16.11: the Rust edition table (GP-22, GP-23, GP-18, RN-09). A synthetic second edition is injected
//! through `Profiles::assemble`, the one builder the real table uses, so what these tests prove about
//! two editions is what the shipped build does with the editions it embeds.

mod common;

use common::*;
use handsal_core::genesis;
use handsal_core::json;
use handsal_core::profiles::{self, Profiles};
use handsal_core::value::JValue;

/// A kid that only the newer synthetic edition lists (a real point, not listed by the shipped kid file).
const KID_OF_NEWER: (&str, &str, &str) = POINTS[4];

fn older() -> Files {
    Files::new("older", &registry_with_class("old-hw"), &shipped_kids())
}

fn newer() -> Files {
    Files::new("newer", &registry_with_class("new-hw"), &kids_with(KID_OF_NEWER.0))
}

/// The table of `older` frozen and `newer` live.
fn two() -> (Profiles, Files, Files) {
    let (a, b) = (older(), newer());
    let manifest = a.manifest_bytes();
    let (production, fixture) = (a.production(), a.fixture());
    let table = Profiles::assemble(&[row(&a, &manifest, &production, &fixture)], b.live()).unwrap();
    (table, a, b)
}

fn code(table: &Profiles, doc: &JValue) -> Option<&'static str> {
    genesis::check_alone_in(doc, table).err().map(|r| r.code)
}

#[test]
fn check_alone_reads_the_registry_of_the_edition_the_document_names() {
    let (table, a, b) = two();
    let with = |profile: &str, class: &str| code(&table, &document_of(profile, class, POINTS[0]));
    // a class only the older registry holds
    assert_eq!(with(&a.production(), "old-hw"), None);
    assert_eq!(with(&b.production(), "old-hw"), Some("class_unknown"));
    // a class only the newer registry holds
    assert_eq!(with(&b.production(), "new-hw"), None);
    assert_eq!(with(&a.production(), "new-hw"), Some("class_unknown"));
    // a class both hold is valid under both
    assert_eq!(with(&a.production(), "apple-se-bio"), None);
    assert_eq!(with(&b.production(), "apple-se-bio"), None);
    // the fixture hash of an edition reads the same edition's registry
    assert_eq!(with(&a.fixture(), "old-hw"), None);
    assert_eq!(with(&b.fixture(), "old-hw"), Some("class_unknown"));
}

#[test]
fn check_alone_reads_the_current_edition_for_an_unknown_hash() {
    let (table, _, _) = two();
    let unknown = hs("an edition this build does not implement");
    let with = |class: &str, first| code(&table, &document_of(&unknown, class, first));
    assert_eq!(with("new-hw", POINTS[0]), None);
    assert_eq!(with("old-hw", POINTS[0]), Some("class_unknown"));
    // an unknown hash is checked like a fixture hash (RN-09): no `fixture_key`, even for a listed kid
    assert_eq!(with("apple-se-bio", KID_OF_NEWER), None);
}

#[test]
fn a_fixture_kid_is_decided_by_the_kid_list_of_the_document_s_own_edition() {
    let (table, a, b) = two();
    let with = |profile: &str| code(&table, &document_of(profile, "apple-se-bio", KID_OF_NEWER));
    assert_eq!(with(&a.production()), None);
    assert_eq!(with(&b.production()), Some("fixture_key"));
    assert_eq!(with(&b.fixture()), None);
}

#[test]
fn resolve_names_the_edition_and_the_kind_of_a_hash_and_nothing_for_any_other() {
    let (table, a, b) = two();
    let hit = table.resolve(&a.production()).unwrap();
    assert_eq!((hit.fixture, hit.edition.label.as_str()), (false, "older"));
    let hit = table.resolve(&a.fixture()).unwrap();
    assert_eq!((hit.fixture, hit.edition.label.as_str()), (true, "older"));
    let hit = table.resolve(&b.production()).unwrap();
    assert_eq!((hit.fixture, hit.edition.label.as_str()), (false, "newer"));
    assert!(table.resolve(&hs("no edition")).is_none());
    assert_eq!(table.production_hashes(), [a.production(), b.production()]);
    assert_eq!(table.current().production, b.production());
}

#[test]
fn a_frozen_row_must_hash_to_its_own_files() {
    let (a, b) = (older(), newer());
    let manifest = a.manifest_bytes();
    let (production, fixture) = (a.production(), a.fixture());
    // the catalog's hash is not what the frozen manifest gives
    let wrong = b.production();
    assert!(Profiles::assemble(&[row(&a, &manifest, &wrong, &fixture)], b.live()).is_err());
    assert!(Profiles::assemble(&[row(&a, &manifest, &production, &wrong)], b.live()).is_err());
    // the registry bytes are not the bytes the frozen manifest lists
    let mut edited = Files::new("older", &registry_with_class("old-hw"), &shipped_kids());
    edited.registry.push(b' ');
    assert!(Profiles::assemble(&[row(&edited, &manifest, &production, &fixture)], b.live()).is_err());
    // the kid list is not the bytes the frozen manifest lists
    let mut kids = Files::new("older", &registry_with_class("old-hw"), &shipped_kids());
    kids.kids.push(b' ');
    assert!(Profiles::assemble(&[row(&kids, &manifest, &production, &fixture)], b.live()).is_err());
    // and the untouched row is accepted
    assert!(Profiles::assemble(&[row(&a, &manifest, &production, &fixture)], b.live()).is_ok());
}

#[test]
fn the_current_core_is_the_newest_frozen_edition_or_a_new_one_never_an_older_one() {
    let (a, b) = (older(), newer());
    let (ma, mb) = (a.manifest_bytes(), b.manifest_bytes());
    let (pa, fa, pb, fb) = (a.production(), a.fixture(), b.production(), b.fixture());
    let frozen = [row(&a, &ma, &pa, &fa), row(&b, &mb, &pb, &fb)];
    // equal to the newest frozen edition: it is that edition, not a third one
    let same = Profiles::assemble(&frozen, b.live()).unwrap();
    assert_eq!(same.production_hashes(), [pa.clone(), pb.clone()]);
    // a new, unreleased edition after the frozen ones is appended
    let c = Files::new("third", &registry_with_class("third-hw"), &kids_with(KID_OF_NEWER.0));
    let three = Profiles::assemble(&frozen, c.live()).unwrap();
    assert_eq!(three.production_hashes(), [pa.clone(), pb.clone(), c.production()]);
    // equal to an older frozen edition: refused
    assert!(Profiles::assemble(&frozen, a.live()).is_err());
}

#[test]
fn a_fixture_kid_listed_by_an_edition_stays_listed_by_every_newer_one() {
    let (a, b) = (older(), newer());
    // the newer edition drops a kid that the older one lists
    let dropped = Files::new("older", &registry_with_class("old-hw"), &kids_with(KID_OF_NEWER.0));
    let manifest = dropped.manifest_bytes();
    let (production, fixture) = (dropped.production(), dropped.fixture());
    let shrunk = Files::new("newer", &registry_with_class("new-hw"), &shipped_kids());
    assert!(Profiles::assemble(&[row(&dropped, &manifest, &production, &fixture)], shrunk.live()).is_err());
    // the same two lists in the other order are append-only
    let manifest = a.manifest_bytes();
    let (production, fixture) = (a.production(), a.fixture());
    assert!(Profiles::assemble(&[row(&a, &manifest, &production, &fixture)], b.live()).is_ok());
}

#[test]
fn an_edition_listed_twice_is_refused() {
    let a = older();
    let manifest = a.manifest_bytes();
    let (production, fixture) = (a.production(), a.fixture());
    let twice = [row(&a, &manifest, &production, &fixture), row(&a, &manifest, &production, &fixture)];
    assert!(Profiles::assemble(&twice, newer().live()).is_err());
}

/// C3 for Rust: one table row per catalog entry, in catalog order, with the catalog's hashes. Before the founding
/// release there is no catalog file, which is an empty catalog and one current edition.
#[test]
fn the_table_has_one_row_per_catalog_entry() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../profiles/catalog.json");
    let rows: Vec<(String, String, String)> = match std::fs::read(&path) {
        Ok(bytes) => json::parse(&bytes)
            .unwrap()
            .list()
            .unwrap()
            .iter()
            .map(|r| {
                let get = |k: &str| r.get(k).and_then(JValue::str).unwrap().to_string();
                (get("label"), get("production"), get("fixture"))
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    let table: Vec<(String, String, String)> =
        profiles::VERSIONS.iter().map(|r| (r.label.to_string(), r.production.to_string(), r.fixture.to_string())).collect();
    assert_eq!(table, rows);
    // the shipped set is those rows, then the live core unless it is the newest of them
    let live = profiles::live_core();
    let current = profiles::profile_hash("production", &live.manifest);
    let mut want: Vec<String> = rows.iter().map(|r| r.1.clone()).collect();
    if want.last() != Some(&current) {
        want.push(current);
    }
    assert_eq!(Profiles::standard().production_hashes(), want);
}
