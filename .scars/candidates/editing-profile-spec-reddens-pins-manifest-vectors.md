---
id: 0
type: landmine
title: "Editing spec/profile.md changes the profile hash and turns pins, manifests and vectors red on purpose"
severity: medium
confidence: 0.9
created: 2026-11-12
authors: ["maintainer"]
anchors:
  - path: spec/profile.md
evidence:
  - note: "auto-harvested from session cd28e419-988e-4d01-ac67-2668b310d233, then checked against the repo on 2026-11-12"
  - note: "pins in conformance/vectors/_gen/tests/test_base.py (PINNED_FIXTURE_PROFILE, PINNED_ORG_ID, PINNED_WIT_ORG_ID); spec/profile.md hash in signer/apple/Sources/HandsalCore/Profiles.swift coreManifest; spec/profile.md listed in tools/manifest.py"
expires:
  condition: "the profile hash stops covering the text of spec/profile.md"
  review_after: 2027-11-12
status: candidate
---

The profile hash covers the text of `spec/profile.md`. Any edit, even a typo
fix, changes that hash, and every value derived from it goes red at once.
That is intended (CF-01): a different spec text is a different profile.

What breaks: the pinned ids in `conformance/vectors/_gen/tests/test_base.py`,
the core manifest copied into the checker, every generated vector, the bundle
manifest `spec/MANIFEST.json`, and the Swift `Profiles.coreManifest` table
that the Swift guard tests enforce.

Do not loosen any of those checks. After the edit, in this order:
1. run `checker/python/sync_core.py`;
2. regenerate the vectors;
3. re-pin the three ids in `test_base.py`, recomputed independently with openssl;
4. run `tools/manifest.py --write`;
5. update the Swift `Profiles.coreManifest` and registry tables.

Batch spec edits into one solo step before parallel work, so lanes do not
build on a hash that is about to change.
