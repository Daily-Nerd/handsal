---
id: 0
type: landmine
title: "Editing a profile part under spec/ changes the profile hash and turns pins, manifests and vectors red on purpose"
severity: medium
confidence: 0.9
created: 2026-11-12
authors: ["maintainer"]
anchors:
  - path: spec/profile.md
  - path: spec/profile-interfaces.md
  - path: tools/repin.py
evidence:
  - note: "auto-harvested from session cd28e419-988e-4d01-ac67-2668b310d233, then checked against the repo on 2026-11-12"
  - note: "re-checked 2026-11-13: the profile hash was a literal in five test files and tables; conformance/pins.json (written by tools/repin.py) now holds the pins and the generator, bundle manifest, Rust and Swift tests read it; the Swift Profiles.coreManifest table, the checker data/core-manifest.json and spec/MANIFEST.json are copies with their own writers"
expires:
  condition: "the profile hash stops covering the text of the profile parts"
  review_after: 2027-11-12
status: candidate
---

The profile hash covers the text of `spec/profile.md` and `spec/profile-interfaces.md` (and `spec/registry.json`,
`conformance/CONTRACT.md` and the two fixture files). Any edit, even a typo
fix, changes that hash, and every value derived from it goes red at once.
That is intended (CF-01): a different spec text is a different profile.

Where the hash and its derivatives live, and who writes each:

| Place | What it holds | Written by |
|---|---|---|
| `conformance/pins.json` | the two profile hashes and the two org ids, computed with openssl | `tools/repin.py --write` |
| `signer/apple/Sources/HandsalCore/Profiles.swift` (`coreManifest`) | every core file hash (the list is `CORE_FILES` in `tools/manifest.py`); Swift cannot embed a file outside its package | `tools/repin.py --write` |
| `checker/python/src/handsal_check/data/core-manifest.json` | the checker's copy of the core | `checker/python/sync_core.py` |
| `conformance/vectors/*.json` | every genesis `profile` and org id | `conformance/vectors/_gen/generate.py` |
| `spec/MANIFEST.json` | the bundle manifest | `tools/manifest.py --write` |

The generator tests (`test_base.py`), `tools/tests/test_bundle_manifest.py`, the
Rust `forms_keys.rs` and the Swift `KeyAndProfileTests` read `pins.json`; none
of them carries a literal. `tools/repin.py --check` lists every place that has
drifted and what to run.

Do not loosen any of those checks and do not edit a pin by hand. After the
edit, in this order:
1. `checker/python/sync_core.py`;
2. regenerate the vectors (`generate.py`, with both vitni verifiers);
3. `tools/repin.py --write`, which refuses vectors that still name the old profile;
4. `tools/manifest.py --write`.

Batch spec edits into one solo step before parallel work, so lanes do not
build on a hash that is about to change.
