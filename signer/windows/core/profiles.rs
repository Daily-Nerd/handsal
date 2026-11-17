//! The supported set of editions (CF-01, GP-07, GP-18, GP-22, RN-09).
//!
//! A profile hash is the hashstr of the canonical bytes of `{"core": <core manifest>, "kind": ...}`, where the
//! core manifest maps each core file path to the hashstr of its bytes. An **edition** is one core: it has two
//! hashes, the registry of its rules and its list of fixture kids. The set is the frozen editions of the catalog
//! (`profiles/catalog.json`, one row of `VERSIONS` each, oldest first), then the live core unless it is the newest
//! frozen edition. The live core is never an older one (C4). Before the founding release there is no catalog, so
//! the set is the live core alone.
//!
//! The live core files (`tools/manifest.py` lists them; `tools/tests/test_core_files.py` compares this table) are
//! embedded at build time and hashed here, so there is no second copy of any hash to go stale: the current
//! edition a binary implements is the spec it was built from. A frozen edition embeds the files of
//! `profiles/<label>/` the same way and is checked once, at assembly, against the hashes its catalog row gives.
//!
//! This module is the one owner of the edition set. A document's `profile` is resolved here (`Profiles::resolve`)
//! and everything after reads the `Profile` that comes back; no other file compares a profile hash. The order of
//! the table is the only order there is (a label is a display name, never parsed or compared). A Rust `sign` or
//! ceremony, when one exists, MUST resolve profiles through `Profiles::resolve` (SG-12, SG-17).

use crate::emit;
use crate::encoding;
use crate::json;
use crate::registry::Registry;
use crate::value::JValue;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const REGISTRY_PATH: &str = "spec/registry.json";
const KIDS_PATH: &str = "conformance/fixtures/fixture-kids.json";

const CORE_FILES: [(&str, &[u8]); 8] = [
    ("conformance/CONTRACT.md", include_bytes!("../../../conformance/CONTRACT.md")),
    ("conformance/fixtures/fixture-kids.json", include_bytes!("../../../conformance/fixtures/fixture-kids.json")),
    ("conformance/fixtures/keys.json", include_bytes!("../../../conformance/fixtures/keys.json")),
    ("spec/profile-checks.md", include_bytes!("../../../spec/profile-checks.md")),
    ("spec/profile-interfaces.md", include_bytes!("../../../spec/profile-interfaces.md")),
    ("spec/profile-part3.md", include_bytes!("../../../spec/profile-part3.md")),
    ("spec/profile.md", include_bytes!("../../../spec/profile.md")),
    ("spec/registry.json", include_bytes!("../../../spec/registry.json")),
];

/// One frozen edition: a catalog row and the three files of `profiles/<label>/` (`core-manifest.json`,
/// `spec/registry.json`, `conformance/fixtures/fixture-kids.json`).
pub struct FrozenRow<'a> {
    pub label: &'a str,
    pub production: &'a str,
    pub fixture: &'a str,
    pub manifest: &'a [u8],
    pub registry: &'a [u8],
    pub kids: &'a [u8],
}

/// The frozen editions, one row per catalog entry, in catalog order, oldest first. A new row is added by hand
/// when an edition is frozen, and `tools/tests/test_core_files.py` fails until it matches the catalog. A row is
/// written as `FrozenRow { label, production, fixture, manifest: include_bytes!(..core-manifest.json), registry: .., kids: .. }`.
pub const VERSIONS: &[FrozenRow<'static>] = &[FrozenRow {
    label: "edition-1",
    production: "uEiAz8uavexP4kqfurWMbcWjTWFbU70U-yFmnMQ26nFGUyg",
    fixture: "uEiBRo_o8HamPzPI5_lhAo6TTqU72k3qSFcxevj-aIbU8cw",
    manifest: include_bytes!("../../../profiles/edition-1/core-manifest.json"),
    registry: include_bytes!("../../../profiles/edition-1/spec/registry.json"),
    kids: include_bytes!("../../../profiles/edition-1/conformance/fixtures/fixture-kids.json"),
}, FrozenRow {
    label: "edition-2",
    production: "uEiAkXLE-J521O1S9VNWWKAzs5rgOzZKTTMsoDsIM2PR5yg",
    fixture: "uEiDfzHDOu6-PRefrAs9Ixf-d-ZBEc3EtdBMSr7AfoimTBQ",
    manifest: include_bytes!("../../../profiles/edition-2/core-manifest.json"),
    registry: include_bytes!("../../../profiles/edition-2/spec/registry.json"),
    kids: include_bytes!("../../../profiles/edition-2/conformance/fixtures/fixture-kids.json"),
}];

/// The files of a core that is not frozen: its manifest and the two files an edition reads.
pub struct CoreData<'a> {
    pub label: &'a str,
    pub manifest: BTreeMap<String, String>,
    pub registry: &'a [u8],
    pub kids: &'a [u8],
}

/// The live core this binary was built from.
pub fn live_core() -> CoreData<'static> {
    let file = |path: &str| CORE_FILES.iter().find(|(p, _)| *p == path).expect("the core lists this file").1;
    CoreData {
        label: "current",
        manifest: CORE_FILES.iter().map(|(path, bytes)| (path.to_string(), encoding::hashstr(bytes))).collect(),
        registry: file(REGISTRY_PATH),
        kids: file(KIDS_PATH),
    }
}

/// The profile hash of `kind` (`"production"` or `"fixture"`) over a core manifest.
pub fn profile_hash(kind: &str, manifest: &BTreeMap<String, String>) -> String {
    let files: BTreeMap<String, JValue> = manifest.iter().map(|(path, hash)| (path.clone(), JValue::string(hash))).collect();
    let doc = JValue::Object(BTreeMap::from([
        ("core".to_string(), JValue::Object(files)),
        ("kind".to_string(), JValue::string(kind)),
    ]));
    let bytes = emit::subset(&doc).expect("the core manifest is in the canonical subset");
    encoding::hashstr(&bytes)
}

/// One edition's rules and its two hashes.
#[derive(Debug)]
pub struct Edition {
    pub label: String,
    pub production: String,
    pub fixture: String,
    pub registry: Registry,
    pub fixture_kids: BTreeSet<String>,
}

impl Edition {
    pub fn is_fixture_kid(&self, kid: &str) -> bool {
        self.fixture_kids.contains(kid)
    }

    /// An edition from the files of a core. Every file the edition reads must be the file its manifest lists.
    fn from_core(label: &str, manifest: &BTreeMap<String, String>, registry: &[u8], kids: &[u8]) -> Result<Edition, String> {
        for (path, bytes) in [(REGISTRY_PATH, registry), (KIDS_PATH, kids)] {
            if manifest.get(path).map(String::as_str) != Some(encoding::hashstr(bytes).as_str()) {
                return Err(format!("{}: {} is not the file the manifest lists", label, path));
            }
        }
        let list = json::parse(kids).map_err(|_| format!("{}: the fixture kid list is not JSON", label))?;
        let fixture_kids = list
            .list()
            .and_then(|kids| kids.iter().map(|k| k.str().map(str::to_string)).collect::<Option<BTreeSet<String>>>())
            .ok_or_else(|| format!("{}: the fixture kid list is not a list of strings", label))?;
        Ok(Edition {
            label: label.to_string(),
            production: profile_hash("production", manifest),
            fixture: profile_hash("fixture", manifest),
            registry: Registry::from_bytes(registry).map_err(|why| format!("{}: the registry is not a registry: {}", label, why))?,
            fixture_kids,
        })
    }

    /// The edition of a catalog row: its manifest must hash to the row's two hashes (GP-22).
    fn frozen(row: &FrozenRow) -> Result<Edition, String> {
        let parsed = json::parse(row.manifest).map_err(|_| format!("{}: the frozen manifest is not JSON", row.label))?;
        let manifest = parsed
            .dict()
            .and_then(|files| files.iter().map(|(path, hash)| hash.str().map(|h| (path.clone(), h.to_string()))).collect::<Option<BTreeMap<_, _>>>())
            .ok_or_else(|| format!("{}: the frozen manifest is not a map of hashes", row.label))?;
        let edition = Edition::from_core(row.label, &manifest, row.registry, row.kids)?;
        if edition.production != row.production || edition.fixture != row.fixture {
            return Err(format!("{}: the frozen manifest does not hash to the catalog's profiles", row.label));
        }
        Ok(edition)
    }
}

/// What a document names: an edition and whether the hash is its fixture one.
#[derive(Debug, Clone, Copy)]
pub struct Profile<'a> {
    pub fixture: bool,
    pub edition: &'a Edition,
}

/// The supported editions, oldest first. Immutable.
#[derive(Debug)]
pub struct Profiles {
    editions: Vec<Edition>,
}

impl Profiles {
    /// The set this build implements: `VERSIONS`, then the live core unless it is the newest of them.
    pub fn standard() -> &'static Profiles {
        static PROFILES: OnceLock<Profiles> = OnceLock::new();
        PROFILES.get_or_init(|| {
            Profiles::assemble(VERSIONS, live_core()).unwrap_or_else(|why| panic!("the embedded editions are not a profile set: {}", why))
        })
    }

    /// A set from frozen rows and a live core. The one builder: the shipped set and the synthetic ones of the tests
    /// go through it. Refused: a row that does not hash to its files, a hash listed twice, a fixture kid that a
    /// newer edition stops listing (GP-22), and a live core that equals an older edition than the newest.
    pub fn assemble(frozen: &[FrozenRow], live: CoreData) -> Result<Profiles, String> {
        let mut editions = frozen.iter().map(Edition::frozen).collect::<Result<Vec<_>, _>>()?;
        let current = Edition::from_core(live.label, &live.manifest, live.registry, live.kids)?;
        match editions.iter().position(|e| e.production == current.production) {
            Some(place) if place + 1 == editions.len() => {}
            Some(_) => return Err("the live core is an older edition than the newest (GP-22)".to_string()),
            None => editions.push(current),
        }
        let mut seen = BTreeSet::new();
        for edition in &editions {
            if !seen.insert(&edition.production) || !seen.insert(&edition.fixture) {
                return Err(format!("{}: a profile hash is listed twice", edition.label));
            }
        }
        for pair in editions.windows(2) {
            if !pair[0].fixture_kids.is_subset(&pair[1].fixture_kids) {
                return Err(format!("a fixture kid of {} is not listed by {} (GP-22)", pair[0].label, pair[1].label));
            }
        }
        Ok(Profiles { editions })
    }

    /// The newest edition: the one a signer creates under.
    pub fn current(&self) -> &Edition {
        self.editions.last().expect("a profile set lists at least one edition")
    }

    /// The production hash of every edition, in catalog order (SG-02); the last is the current one.
    pub fn production_hashes(&self) -> Vec<&str> {
        self.editions.iter().map(|e| e.production.as_str()).collect()
    }

    /// The edition and kind a hash names, or `None` for a value that no edition lists.
    pub fn resolve(&self, hash: &str) -> Option<Profile<'_>> {
        self.editions.iter().find_map(|edition| {
            if edition.production == hash {
                Some(Profile { fixture: false, edition })
            } else if edition.fixture == hash {
                Some(Profile { fixture: true, edition })
            } else {
                None
            }
        })
    }
}
