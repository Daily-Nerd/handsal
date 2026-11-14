//! The two profiles (CF-01, GP-07, GP-18): their hashes and the fixture kid list.
//!
//! A profile hash is the hashstr of the canonical bytes of `{"core": <core manifest>, "kind": ...}`,
//! where the core manifest maps each core file path to the hashstr of its bytes. The core files
//! (`tools/manifest.py` lists them; `tools/tests/test_core_files.py` compares this table) are embedded at build time and hashed here, so there is no second copy of any hash to go stale:
//! the profile a binary implements is the spec it was built from.

use crate::emit;
use crate::encoding;
use crate::json;
use crate::value::JValue;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const CORE_FILES: [(&str, &[u8]); 6] = [
    ("conformance/CONTRACT.md", include_bytes!("../../../conformance/CONTRACT.md")),
    ("conformance/fixtures/fixture-kids.json", include_bytes!("../../../conformance/fixtures/fixture-kids.json")),
    ("conformance/fixtures/keys.json", include_bytes!("../../../conformance/fixtures/keys.json")),
    ("spec/profile-interfaces.md", include_bytes!("../../../spec/profile-interfaces.md")),
    ("spec/profile.md", include_bytes!("../../../spec/profile.md")),
    ("spec/registry.json", include_bytes!("../../../spec/registry.json")),
];

const FIXTURE_KIDS: &[u8] = include_bytes!("../../../conformance/fixtures/fixture-kids.json");

#[derive(Debug)]
pub struct Profiles {
    pub production: String,
    pub fixture: String,
    pub fixture_kids: BTreeSet<String>,
}

fn profile_hash(kind: &str) -> String {
    let manifest: BTreeMap<String, JValue> =
        CORE_FILES.iter().map(|(path, bytes)| (path.to_string(), JValue::String(encoding::hashstr(bytes)))).collect();
    let doc = JValue::Object(BTreeMap::from([
        ("core".to_string(), JValue::Object(manifest)),
        ("kind".to_string(), JValue::string(kind)),
    ]));
    let bytes = emit::subset(&doc).expect("the core manifest is in the canonical subset");
    encoding::hashstr(&bytes)
}

impl Profiles {
    pub fn standard() -> &'static Profiles {
        static PROFILES: OnceLock<Profiles> = OnceLock::new();
        PROFILES.get_or_init(|| {
            let list = json::parse(FIXTURE_KIDS).expect("embedded fixture-kids.json is JSON");
            let kids = list.list().expect("fixture-kids.json is a list");
            Profiles {
                production: profile_hash("production"),
                fixture: profile_hash("fixture"),
                fixture_kids: kids.iter().map(|k| k.str().expect("a fixture kid is a string").to_string()).collect(),
            }
        })
    }

    /// `"production"`, `"fixture"` or `None` for a value that is no implemented profile.
    pub fn kind(&self, profile: &str) -> Option<&'static str> {
        if profile == self.production {
            Some("production")
        } else if profile == self.fixture {
            Some("fixture")
        } else {
            None
        }
    }

    pub fn is_fixture_kid(&self, kid: &str) -> bool {
        self.fixture_kids.contains(kid)
    }
}
