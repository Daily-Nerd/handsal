"""The settled rules of spec/profile.md, each pinned in the one requirement that owns it.

A rule lives in one place. These tests fail when that place loses the sentence, and
the NOT_IN cases fail when an older sentence that contradicts the rule comes back.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "spec" / "profile.md"


def section(heading):
    """The text from the heading that starts with `heading` to the next heading of any level."""
    text = PROFILE.read_text(encoding="utf-8")
    m = re.search(r"^#{2,4} %s\b.*$" % re.escape(heading), text, re.M)
    if m is None:
        raise AssertionError("no heading %r" % heading)
    rest = text[m.end():]
    nxt = re.search(r"^#{2,4} ", rest, re.M)
    return text[m.start():m.end() + (nxt.start() if nxt else len(rest))]


# (requirement, phrase the requirement must carry)
MUST_CARRY = (
    # 1. check-act class and receipt_id on failure (VR-01)
    ("VR-01", "`receipt_id` is null for steps 1 and 2 and the hashstr of the payload bytes from step 3 on"),
    ("VR-01", "`class` is null for steps 1 to 6 and from step 7 on is the class of the device"),
    # 2. a missing policy is policy_invalid (GP-01 leaves it to GP-02)
    ("GP-01", "a document without `policy` is `policy_invalid`"),
    ("GP-02", "`policy_invalid`, not `genesis_schema`. V: pol/missing-policy"),
    # 3. ACT-10: observable restatement
    ("ACT-10", "`payload_not_canonical_subset`"),
    ("ACT-10", "jcs/raw-non-ascii-e9"),
    ("ACT-10", "no reason code of that case is a vector"),
    # 4. GP-15 code ties
    ("GP-01", "Sorted means ascending in byte order, equal neighbours allowed"),
    ("GP-01", "a repeated member `id` too, are `genesis_schema`"),
    ("GP-02", "a repeated entry in a list that must be unique"),
    ("GP-02", "are `policy_invalid`"),
    ("GP-07", "its first document has a non-null `prev`"),
    ("GP-15", "each over the whole document before the next"),
    # 5. expect_method
    ("VR-01", "`expect_method` is a string"),
    ("VR-01", "`chain_method` at step 4 whatever `expect_method` says"),
    # 6. non-subset document and non-hashstr profile
    ("GP-01", "a `profile` that is not a canonical hashstr"),
    # 7. class_id alphabet
    ("2.2", "`class_id`: `[a-z][a-z0-9-]{0,31}`"),
    # 8. base64 flavor of the _b64 inputs
    ("2.2", "`bytes_b64`, `request_b64` and `record_body_b64`"),
    ("2.2", "standard base64 (RFC 4648 section 4) with padding"),
    # 9. performer violation
    ("ACT-13", "`identity_mismatch` at step 11 (VR-05)"),
    # 10. empty lineage, last document without a hash
    ("GP-07", "An empty lineage is `lineage_broken`"),
    ("GP-07", "`genesis_pin_mismatch`"),
    ("VR-02", "(g) `lineage_broken` for an empty lineage"),
    # 11. ok for subset, kid shape, repeated pin member
    ("11. Reason codes", "`genesis-check`, `subset` and the pin helper"),
    ("CF-03", "`kid` takes exactly `{x, y}`"),
    ("GP-05", "a member name that repeats, whatever its values"),
    # 12. untestable order under registry version 1
    ("CF-07", "`role_key_class` before `fixture_key`"),
    # 13. the pin's org against the first lineage document (owner decision A)
    ("GP-07", "The pin's `org` MUST equal the hash of the first lineage document, which is the org id (GP-04), else `lineage_broken`"),
    ("GP-07", "as the first document it is `lineage_broken`, as the last it is `genesis_pin_mismatch`"),
    ("GP-07", "`genesis-check` and the pin helper read no pin"),
    ("GP-07", "V: pin/lineage-original-not-org"),
    ("VR-02", "(g) `lineage_broken` for an empty lineage, then `lineage_broken` for a first document whose hash differs from the pin's `org`, then `genesis_pin_mismatch`"),
    ("GP-05", "the hash of the first lineage document MUST equal the pin's `org`, else `lineage_broken` (GP-07)"),
    ("GP-13", "the pin checks of VR-02 step 6, (a) to (h), in that order and with those codes"),
    ("GP-14", "compares probe, pin, input and lineage"),
    ("11. Reason codes", "`pin_spec_mismatch`, `lineage_broken` |"),
    # 14. the eight gaps of the first fold build
    ("FO-01", "`tip.n` is a decimal string"),
    ("FO-02", "has no entry in `keys`, not even an empty object"),
    ("SG-09", "an applied primary on the path from the epoch's root to the act's parent"),
    ("FO-07", "one pool of kids and one pool of points"),
    ("GP-07", "an item of any other type is `malformed_input`"),
    ("ACT-09", "No reason code is output for the hash itself"),
    ("GP-11", "The reference checker has no Windows path for this check"),
    # 15. rules proven by implementation tests, not vectors
    ("CF-07", "`verifier_unavailable` and `verifier_unexpected`"),
    ("CF-07", "implementation tests"),
    ("VR-03", "an implementation test, CF-07"),
    ("CF-05", "an implementation test, CF-07"),
    # 16. one case per vector id
    ("FO-16", "V: fld/at-0-state, fld/at-1-state, fld/at-prefix-states, fld/at-3-state, fld/at-4-state, fld/at-beyond-tip"),
    ("FO-27", "V: quo/one-left-unreachable, quo/last-device-removed-no-vote"),
    ("FO-27", "V: quo/two-lost-persons-unreachable"),
    ("GP-05", "V: pin/duplicate-key, pin/duplicate-key-differing-values"),
    # 17. render input shape, layout and block rules (batch 8, owner decision 1)
    ("CF-03", "`render` takes exactly the keys `attachments`, `kid`, `method` and `payload`, else `malformed_input`"),
    ("CF-03", "`payload` is the signed payload as a JSON object"),
    ("CF-03", "any other attachment of the wrong JSON type is `attachment_mismatch`"),
    ("CF-03", "the JCS line and its closing LF"),
    ("RN-02", "is written as its first 98 bytes, with no prefix, and then continuation lines"),
    ("RN-02", "each `+ ` followed by the next at most 98 bytes"),
    ("RN-04", "A field line is the field name, a colon, one space and the value"),
    ("RN-04", "`Anchors:` and one line `  - <anchor>` per anchor"),
    ("RN-04", "`Org name: <name>`, `Profile: <full profile hash>`, `Members:`"),
    ("RN-04", "`  Rule <name>: <persons> of <roles joined by \",\">`"),
    ("RN-04", "`Policy:`"),
    ("RN-04", "`  Witness: none`"),
    ("RN-04", "`Document hash: <hash12 of the document hash>`"),
    ("RN-05", "`|+` (no space) followed by the next at most 96 bytes"),
    ("RN-05", "An empty source line is `| ` (a pipe and a space)"),
    ("RN-05", "A final LF ends the last line and does not start another"),
    ("RN-05", "content lines, continuations included, without the two delimiter lines"),
    ("RN-10", "`Org name: <name>`, `Profile: <full profile hash>` (the two lines an original opens with"),
    ("RN-10", "`Previous: <hash12(prev)>`, `Head: <full H>`"),
    ("RN-10", "`Role changed:` (`  - <id> <old role> -> <new role>`)"),
    ("RN-10", "`Unchanged: <D> devices, <M> members`"),
    ("RN-10", "A change has no `Document hash` line"),
    ("RN-10", "The count does not depend on the signer"),
    # 18. RN-09: absent is missing, anything else wrong is a mismatch (owner decision 3)
    ("RN-09", "| `genesis.sign` over a change | `document` | `head.id` of the payload = `document.head` |"),
    ("RN-09", "A name that is absent from `attachments` is `attachment_missing`"),
    ("RN-09", "is `attachment_mismatch`, the same code as an act attachment that fails ACT-01 to ACT-14"),
    ("RN-09", "GP-15 steps 1 and 3 over the document alone"),
    ("RN-09", "V: rnd/genesis-head-mismatch"),
    # 19. VR-07 owns outputs_hash for every method check-act decides (owner decision 2)
    ("VR-07", "is the single owner of `outputs_hash` for every method that `check-act` decides"),
    ("VR-07", "for `record.promote`, EMPTY_HASH"),
    ("VR-07", "V: vrd/record-outputs-not-empty"),
    ("ACT-09", "For a verdict and for `record.promote`, `inputs_hash` is checked by VR-06 and `outputs_hash` by VR-07"),
    # 20. a form outside ACT-07 takes the code of its container (relay)
    ("ACT-10", "is `schema` when the field is an ACT-07 form or a key of the act object (`kid`, `recipient`, `relay`, `request_id`, `expires`, `head`), and `body_schema` when it is a field of `body`"),
    # 21. the pin helper, the ceremony and the consumer store are proven by tests, not vectors
    ("GP-21", "Helper tests are implementation tests (CF-07), not vectors"),
    ("CF-07", "GP-21 pin helper"),
    ("CF-07", "SG-12 ceremony"),
    ("CF-07", "VR-14 consumer store"),
    ("CF-07", "`cli/genesis-check-missing-head-acts-invalid`"),
    ("CF-07", "the acceptance half of clean(k, H)"),
    ("VR-14", "(a consumer implementation test, CF-07)"),
    ("WT-10", "`next` `\"no\"` WHEN checked THEN valid, whatever the consumer's bag holds"),
    # 22. batch 8, resolve step: hostname labels, resolve forms, production-only rules, gaps
    ("2.2", "each label 1 to 63 characters"),
    ("2.2", "at most 253 characters in all"),
    ("ACT-07", "WHEN folded THEN the resolve is ignored"),
    ("ACT-07", "`check-act` never reads a resolve (VR-02 step 4)"),
    ("ACT-07", "V: rsv/override-entry-non-canonical-hashstr, rsv/override-resolve-non-canonical-hashstr, rsv/candidate-non-canonical-hashstr, rsv/head-non-canonical-hashstr, rsv/choose-non-canonical-hashstr"),
    ("CF-08", "Production-only behaviour is proven by implementation tests (CF-07)"),
    ("CF-08", "No vector runs against the production build"),
    ("CF-07", "Production-only behaviour, `test_builds.py` of the checker"),
    ("CF-07", "`test_probe_posix.py`"),
    ("GP-10", "the ancestor symlink case is a probe test (CF-07)"),
    ("VR-01", "the production build refuses `pin` in a test of the build (CF-07, CF-08)"),
    ("RN-03", "The free fields are `<class>`, `<person>`, `<member>`, `<role>`, `<request_id>`, `<record_id>` and the genesis `<name>`"),
    ("RN-04", "Entries inside a change section keep document order"),
    ("RN-09", "`fixture_key` follows the profile the document itself names"),
    ("CF-05", "from `check-act`, `fold`, `enrolled` and `genesis-check`"),
    ("GP-14", "two test-only constructor arguments, a root path and the uid it treats as administrator"),
    ("GP-17", "A WSL2 host is a Linux host whose kernel release contains `microsoft`"),
    ("GP-17", "Any other host has no pin location the checker can read"),
    ("GP-11", "a WSL2 host gets `pin_probe_unprotected` (GP-17)"),
    ("CF-07", "`enrolled:true` can be shown by a vector only under production keys (PRODK, CF-08)"),
    ("FO-25", "V: rsv/revoked-on-branch-not-counted, rsv/stale-head-not-current, rsv/stale-head-covers-removal-ignored"),
)

NOT_IN = (
    ("ACT-13", "A violation is `schema` at `check-act` step 5 (VR-02)."),
    ("ACT-10", "A violation is `schema` or `body_schema`."),
    ("VR-01", "`receipt_id` is null until the payload parses"),
    ("VR-02", "ACT-13 envelope fields"),
    ("GP-07", "An empty or inconsistent lineage is `lineage_broken`."),
    ("GP-07", "never equals the pin and is `genesis_pin_mismatch`"),
    ("VR-02", "(g) `lineage_broken` for an empty lineage, else `genesis_pin_mismatch`"),
    ("GP-13", "`genesis` equals the hash of the last lineage document (`genesis_pin_mismatch`)"),
    ("SG-09", "already used by an applied primary in the epoch"),
    ("VR-03", "V: vtn/unexpected-vitni-reason"),
    ("CF-05", "V: cli/verifier-unavailable"),
    ("FO-16", "V: fld/at-prefix-states, fld/at-beyond-tip"),
    ("CF-07", "every reason code in section 11 has an only-defect vector"),
    ("RN-02", "A longer line wraps into segments of at most 98 bytes, each continuation line prefixed `+ `"),
    ("RN-04", "`Members` (one line each: id, role)"),
    ("RN-05", "continues on lines prefixed `|+`, never splitting an escape"),
    ("RN-09", "A missing attachment or list is `attachment_missing`; one that does not bind is `attachment_mismatch`."),
    ("RN-10", "after the summary, `Head: <full H>`; then `Members added`"),
    ("VR-07", "For verdicts, `outputs_hash` MUST equal the value derived from the method and `request_id` (ACT-09)."),
    ("ACT-09", "For a verdict, `inputs_hash` is checked by VR-06 and `outputs_hash` by VR-07"),
    ("ACT-10", "is `schema` (the ACT-07 forms) or `body_schema`. The label"),
    ("GP-21", "Helper vectors (`sgn/pin-helper-*`)"),
    ("GP-21", "V: sgn/pin-helper-refuses-rollback"),
    ("VR-14", "V: ing/revoked-after-ingestion-recheck-fails, ing/record-contains-tip"),
    ("VR-14", "V: ing/invalid-not-recorded-by-receipt-id"),
    ("WT-10", "a bag holding a valid change to epoch 1"),
    ("ACT-07", "WHEN checked THEN `schema`; WHEN folded THEN ignored"),
    ("CF-08", "V: cli/prod-pin-input-refused"),
    ("VR-01", "V: cli/prod-pin-input-refused"),
    ("GP-10", "V: enr/pin-owner, pin/probe-symlink-ancestor"),
    ("GP-11", "A WSL2-side caller that cannot run it gets `pin_probe_unavailable`"),
)


# ids the batch 8 amendment adds (one id per case); each must be named by a scenario
SPLIT_IDS = (
    "frk/losing-branch-extension-lifted", "frk/resolve-new-child-lifted",
    "frk/stale-proposal-first-resolve-lifts", "frk/stale-proposal-second-stale-refreezes",
    "frk/stale-resolve-completed-forks", "frk/stale-resolve-late-endorsement-still-forks",
    "frk/two-stale-artifacts-winner-applied", "frk/two-stale-artifacts-stale-primary-forks",
    "frk/two-stale-artifacts-override-lifts", "frk/pending-name-override-first-resolve-applies",
    "frk/pending-name-override-lifted", "frk/ancestor-override-before-completion-applies",
    "frk/ancestor-override-lifted", "frk/finality-base-bag-applies", "frk/r11-honest-resolve-applies",
    "frk/r11-override-lifts", "frk/r11-minted-person-change-recovers", "frk/two-self-removals-no-fork",
    "rsv/override-resolve-non-canonical-hashstr", "rsv/candidate-non-canonical-hashstr",
    "rsv/head-non-canonical-hashstr", "rsv/choose-non-canonical-hashstr",
    "rsv/override-entry-non-canonical-hashstr", "rsv/override-entry-bare-hashstr-schema",
    "rsv/stale-head-covers-removal-ignored",
    "rsv/override-entry-sixteen-endorsements-schema", "rsv/override-completion-evidence-first-resolve-applies",
    "rnd/prompt-line-max-device-remove", "rnd/prompt-line-max-member-add", "rnd/prompt-line-max-resolve",
    "rnd/prompt-line-max-approve", "rnd/prompt-line-max-reject", "rnd/prompt-line-max-needs-info",
    "rnd/prompt-line-max-promote", "rnd/prompt-line-max-genesis-original",
    "rnd/prompt-line-max-genesis-change", "wit/pol-tip-age-upper-bound-ok", "wit/next-hashstr-malformed",
    "rep/same-payload-low-s-same-receipt-id", "quo/raised-floor-3-three-applied",
    "vrd/record-outputs-not-empty", "rnd/genesis-head-mismatch", "rnd/genesis-document-invalid-bound",
    "rnd/genesis-previous-invalid-bound", "rnd/genesis-change-org-name-profile-lines",
    "rnd/attachment-wrong-type-mismatch", "cli/genesis-check-missing-head-acts-invalid",
    "cli/genesis-check-extra-acts-same-result",
)


class SettledRules(unittest.TestCase):
    def test_each_owner_carries_its_rule(self):
        for heading, phrase in MUST_CARRY:
            with self.subTest(requirement=heading, phrase=phrase):
                self.assertIn(phrase, section(heading))

    def test_no_older_contradicting_sentence_is_left(self):
        for heading, phrase in NOT_IN:
            with self.subTest(requirement=heading, phrase=phrase):
                self.assertNotIn(phrase, section(heading))

    def test_every_vector_a_scenario_names_is_an_active_id(self):
        """A `V:` id that was retired or never issued is a scenario with no vector."""
        ids = json.loads((ROOT / "conformance" / "vector-ids.json").read_text(encoding="utf-8"))
        active = set(ids["ids"])
        for line in PROFILE.read_text(encoding="utf-8").splitlines():
            m = re.search(r"\bV: (.*)$", line)
            if m is None:
                continue
            for name in re.findall(r"[a-z0-9]+/[A-Za-z0-9._-]+", m.group(1)):
                with self.subTest(vector=name):
                    self.assertIn(name, active)

    def test_every_split_id_is_named_by_a_scenario_or_a_test_list(self):
        text = PROFILE.read_text(encoding="utf-8")
        for name in SPLIT_IDS:
            with self.subTest(vector=name):
                self.assertIn(name, text)

    def test_a_missing_policy_is_not_listed_as_a_schema_scenario(self):
        self.assertNotIn("pol/missing-policy", section("GP-01"))


if __name__ == "__main__":
    unittest.main()
