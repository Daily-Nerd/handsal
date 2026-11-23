"""The settled rules of the profile (spec/profile.md and its parts), each pinned in the one requirement that owns it.

A rule lives in one place. These tests fail when that place loses the sentence, and
the NOT_IN cases fail when an older sentence that contradicts the rule comes back.
"""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import check_catalog  # noqa: E402
import manifest  # noqa: E402

PROFILE_TEXT = manifest.read_profile(ROOT)


def section(heading):
    """The text from the heading that starts with `heading` to the next heading of any level."""
    text = PROFILE_TEXT
    m = re.search(r"^#{2,4} %s\b.*$" % re.escape(heading), text, re.M)
    if m is None:
        raise AssertionError("no heading %r" % heading)
    rest = text[m.end():]
    nxt = re.search(r"^#{2,4} ", rest, re.M)
    return text[m.start():m.end() + (nxt.start() if nxt else len(rest))]


ID = re.compile(r"[a-z0-9]+/[A-Za-z0-9._-]*[A-Za-z0-9]")
TEST_REF = re.compile(r"[A-Za-z0-9_./-]+::[A-Za-z0-9_]+")
TAIL = re.compile(r"(?<=[ .])([VPCTO]): ")
SPEC_TEXT = PROFILE_TEXT
IDS = json.loads((ROOT / "conformance" / "vector-ids.json").read_text(encoding="utf-8"))
PENDING = set(IDS.get("pending", []))
CODES = set(check_catalog.spec_codes(SPEC_TEXT)[0]) - {"ok"}


def scenarios():
    """[(line, text before the tails, {"V": ids, "C": ids, "P": ids, "T": test refs, "O": text})] per scenario line.

    A scenario ends in at least one tail that names its proof, each with one meaning:
      V: vectors that ship (a file in conformance/vectors) and show the outcome the scenario names
      C: vectors that ship and show no reason code: the positive control of a scenario that names a code
      P: vectors that ship at the tag and wait for an owner step (PRODK, Windows Hello)
      T: implementation tests, as `path::name` (CF-07 lists them)
      O: a proof that lives outside this repository's suites (a consumer's own tests, a platform check
         the owner runs by hand); the text says whose
    """
    found = []
    for number, line in enumerate(SPEC_TEXT.splitlines(), 1):
        if not re.match(r"- S\d+: ", line):
            continue
        marks = list(TAIL.finditer(line))
        head = line[:marks[0].start()] if marks else line
        tails = {"V": [], "C": [], "P": [], "T": [], "O": ""}
        for i, mark in enumerate(marks):
            end = marks[i + 1].start() if i + 1 < len(marks) else len(line)
            body = line[mark.end():end]
            kind = mark.group(1)
            if kind == "O":
                tails["O"] += body.strip(" .")
            else:
                tails[kind] += (TEST_REF if kind == "T" else ID).findall(body)
        found.append((number, head, tails))
    return found


SCENARIOS = scenarios()


def vector_codes(name):
    """The reason codes the anchor of the vector file shows (empty for a success or a state)."""
    path = ROOT / "conformance" / "vectors" / (name.replace("/", ".") + ".json")
    if not path.is_file():
        return set()  # a missing file is reported by the test of the V tail
    doc = json.loads(path.read_text(encoding="utf-8"))
    return check_catalog._anchor_codes(doc.get("anchor")) & CODES


def then_codes(head):
    """The reason codes a scenario's THEN part names inside backticks."""
    then = head.split(" THEN ", 1)[1] if " THEN " in head else ""
    named = set()
    for span in re.findall(r"`([^`]*)`", then):
        named |= set(re.findall(r"[a-z_]+", span)) & CODES
    return named


DEFINITIONS = {
    ".py": r"\bdef %s\(",
    ".swift": r"\bfunc %s\(",
    ".rs": r"\bfn %s\(",
    # the installer test builds one world per case: `make_world <name>`
    ".sh": r"\bmake_world %s\b",
}


def definition(path, name):
    """The pattern that makes `name` a test defined in `path`, not a word that happens to occur in it."""
    return DEFINITIONS[Path(path).suffix] % re.escape(name)


def named_tests():
    """The `path::name` entries CF-07 lists as the named implementation tests."""
    return set(TEST_REF.findall(section("CF-07")))


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
    ("2.2", "`bytes_b64`, `request_b64` and `decision_b64`"),
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
    ("VR-03", "T: checker/python/tests/test_verifier.py::test_four_reasons_pass_through_and_the_rest_is_unexpected"),
    ("CF-05", "T: checker/python/tests/test_rules.py::test_a_verifier_that_cannot_answer_is_verifier_unavailable_with_the_class"),
    # 16. one case per vector id
    ("FO-16", "V: fld/at-beyond-tip. C: fld/at-0-state, fld/at-1-state, fld/at-prefix-states, fld/at-3-state, fld/at-4-state"),
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
    ("ACT-09", "For a non-chain act, `inputs_hash` is checked by VR-06 and `outputs_hash` by VR-07"),
    # 20. a form outside ACT-07 takes the code of its container (relay)
    ("ACT-10", "is `schema` when the field is an ACT-07 form or a key of the act object (`kid`, `recipient`, `relay`, `request_id`, `expires`, `head`), and `body_schema` when it is a field of `body`"),
    # 21. the pin helper, the ceremony and the consumer store are proven by tests, not vectors
    ("GP-21", "Helper tests are implementation tests (CF-07), not vectors"),
    ("CF-07", "GP-21 pin helper"),
    ("CF-07", "SG-12 ceremony"),
    ("VR-14", "belong to each consumer's own suite"),
    ("CF-07", "`cli/genesis-check-missing-head-acts-invalid`"),
    ("CF-07", "the acceptance half of clean(k, H)"),
    ("VR-14", "O: the consumer's own test suite; this repository ships no store"),
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
    ("RN-03", "The free fields are `<class>`, `<person>`, `<member>`, `<role>`, `<request_id>`, the decision `<consumer>` and `<subject>`, and the genesis `<name>`"),
    ("RN-04", "Entries inside a change section keep document order"),
    ("RN-09", "`fixture_key` follows the profile the document itself names"),
    ("CF-05", "from `check-act`, `fold`, `enrolled` and `genesis-check`"),
    ("GP-14", "two test-only constructor arguments, a root path and the uid it treats as administrator"),
    ("GP-17", "A WSL2 host is a Linux host whose kernel release contains `microsoft`"),
    ("GP-17", "Any other host has no pin location the checker can read"),
    ("GP-11", "a WSL2 host gets `pin_probe_unprotected` (GP-17)"),
    ("CF-07", "`enrolled:true` can be shown by a vector only under production keys (PRODK, CF-08)"),
    ("FO-25", "V: rsv/revoked-on-branch-not-counted, rsv/stale-head-not-current, rsv/stale-head-covers-removal-ignored"),
    # 23. batch 10: the signer contract (conformance executable, verdict drafts, smaller gaps)
    ("CF-04", "A signer implementation runs the `render` and `emit` vectors, and only those, through its own conformance executable, `handsal-sign-conformance`"),
    ("CF-04", "is never installed at an administrator path"),
    ("CF-04", "A signer has no `fold` and no `genesis-check`, so the `pol/*` rows are run by each signer's own suite"),
    ("CF-04", "T: signer/windows/tests/vectors.rs::pol_rows_through_check_alone, signer/apple/Tests/HandsalCoreTests/VectorRunnerTests.swift::polRowsThroughCheckAlone"),
    ("CF-04", "`render` takes the CF-03 `render` input, read as CF-03 reads it, MAX_NESTING included, and writes the CF-03 output, with exit 0 for every result"),
    ("CF-04", "`emit` is the shipped `emit`"),
    ("CF-04", "holds no key, shows no prompt and reads neither the clock nor a random source"),
    ("CF-04", "V: jcs/emit-value-with-number-refused. C: cli/build-approve"),
    ("CF-07", "(checker), and `pin_invalid`, `pin_rollback`, `internal`, `user_cancel`, `key_unavailable`, `key_exists`, `no_display`, `prompt_refused`, `biometric_unavailable` and `profile_not_current` (pin helper and signer)"),
    ("CF-07", "a second `sign` while a prompt is open is `prompt_refused`"),
    ("CF-07", "SG signer, tests of the signer"),
    ("CF-07", "SG-12 ceremony, tests of the ceremony"),
    ("CF-07", "SG-15 installer, tests of the installation procedure"),
    # 24. the stored-act re-check (VR-17): the time-free half of check-act, one implementation, honest bounds
    ("VR-17", "re-verifies the time-free part of one non-chain act that a consumer stored"),
    ("VR-17", "There is no `valid` key"),
    ("VR-17", "V: rly/relay-dropped-at-tip-mismatch. C: rck/relay-from-head-epoch"),
    ("VR-17", "the state at the act's own head"),
    ("VR-17", "does not run step 13, step 14 or step 15"),
    ("VR-17", "`not_proven`"),
    ("VR-17", "The production build reads the pin in process, as `check-act` does"),
    ("VR-17", "`check-act` is the steps of `recheck-act` and then the steps that read the verifier's moment"),
    ("VR-17", "head is a position in its own epoch, and the lineage proves which epoch that is"),
    ("VR-17", "`stale_view` here means only that the head is no position of a chain the lineage proves"),
    ("VR-17", "on the path to the head H of the change that follows"),
    ("VR-17", "does not prove that the act was ever ingested"),
    ("VR-14", "A consumer MUST keep the full JWS of every act it accepts"),
    ("VR-14", "`recheck-act` (VR-17) on the stored JWS at read time"),
    ("VR-14", "Freshness and expiry are ingestion-only"),
    ("VR-14", "MUST NOT re-run `check-act` on stored acts to decide historic validity"),
    ("VR-02", "Steps 7 to 12 and 16 read no moment"),
    ("CF-03", "| `recheck-act` | VR-17 |"),
    ("CF-04", "The checker role runs every command but `emit`, `recheck-act` included"),
    ("CF-08", "An owner-signed vector names the production profiles of its lineage"),
    ("CF-08", "`owner-stale`"),
    ("KC-04", "`rechecked:true` from `recheck-act`"),
    ("14. Known limitations", "**L9. Verdicts are one touch, and consumer storage is editable.**"),
    ("14. Known limitations", "a holder of a removed key can sign a verdict that names a head before the removal"),
    ("14. Known limitations", "stored data cannot show when an act arrived"),
    ("14. Known limitations", "root-owned append-only storage"),
    ("14. Known limitations", "key removed by a later epoch does not change the answer for an act of an earlier epoch"),
    ("CF-07", "`render` and `sign` without a key are `key_unavailable`"),
    ("CF-07", "an unknown command, none or two arguments are `unsupported_command`"),
    ("RN-01", "The signer's `render` command is that function composed with the signer's own fill"),
    ("RN-01", "`key_unavailable`, exit 3"),
    ("SG-01", "the JCS bytes then one LF"),
    ("SG-01", "One trailing LF of stdin is framing"),
    ("SG-01", "`{\"error\":\"unsupported_command\"}`, exit 2"),
    ("SG-01", "`emit` writes `{payload_hex}`"),
    ("SG-02", "`impl` is `handsal-sign-swift` on macOS and `handsal-sign-rust` on Windows"),
    ("SG-02", "`spec` is the current production profile hash"),
    ("SG-04", "a verdict draft also carries `recipient`, `relay` and `request_id`"),
    ("SG-04", "`identity_mismatch`, exit 2"),
    ("SG-04", "a decimal string from \"1\" to MAX_EXPIRES_IN_S"),
    ("SG-04", "`head` is exactly the ACT-08 object"),
    ("SG-04", "V: sgn/verdict-recipient-not-performer-refused, sgn/verdict-draft-missing-relay-refused, sgn/chain-draft-recipient-refused"),
    ("SG-04", "sgn/expires-in-s-zero-refused"),
    ("SG-08", "`unsupported_command`, `identity_mismatch`"),
    ("SG-08", "no key is bound (`render` or `sign` before `keygen`)"),
    ("SG-13", "For `genesis.sign` the signer derives `org` from the attached `document`"),
    ("SG-13", "V: sgn/genesis-org-not-document-hash-refused"),
    # 24. batch 11: emit checks `fixed`, one nesting bound, a code for a refused prompt, the order of refusals
    ("SG-04", "`emit` checks the forms of the four `fixed` values"),
    ("SG-04", "a malformed value, a missing key or an extra key is `schema_refused`"),
    ("SG-04", "V: cli/build-bad-nonce"),
    ("2.3", "| MAX_NESTING | 64 |"),
    ("CF-03", "Nesting deeper than MAX_NESTING"),
    ("CF-03", "V: cli/stdin-nesting-over-max-unparseable, cli/stdin-nesting-at-max-malformed"),
    ("CF-04", "read as CF-03 reads it, MAX_NESTING included"),
    ("SG-10", "is exit 4, `prompt_refused`"),
    ("SG-10", "not `internal`"),
    ("SG-08", "4 `no_display`, `prompt_refused`, `biometric_unavailable`"),
    ("11. Reason codes", "`no_display`, `prompt_refused`, `biometric_unavailable` (4)"),
    # 25. T5.13 owner run: a system condition is not a person's decision, and a refused prompt shows nothing
    ("SG-08", "the sensor (`biometric_unavailable`)"),
    ("SG-08", "is never `user_cancel`"),
    ("SG-08", "S5: GIVEN a sensor that cannot verify now"),
    ("SG-10", "nothing is shown"),
    ("SG-10", "no second prompt and nothing shown"),
    ("SG-07", "Once it holds the prompt guard"),
    ("SG-08", "When a command has more than one defect, the first of these decides"),
    ("SG-08", "`identity_mismatch`, decided before any attachment is read"),
    ("SG-08", "V: sgn/identity-before-attachment-refused, sgn/genesis-head-before-org-refused"),
    ("SG-13", "(SG-08 gives the order of the refusals)"),
    ("ACT-07", "The one exception is the fixture profile"),
    ("ACT-05", "V: jcs/emit-roundtrip-approve"),
    ("FO-08", "The `ts` of an endorsement is the time its signer signed it"),
    ("FO-08", "The fold reads no `ts`"),
    ("FO-23", "Shape of a signed chain act."),
    ("FO-23", "three receipts: the primary by one person, one endorsement by a second person, and the proof of possession by the new key"),
    ("FO-07", "are listed in FO-23"),
    ("FO-22", "The receipts that carry the signatures are listed in FO-23"),
    ("SG-09", "The new key endorses (FO-07, FO-23)"),
    ("SG-14", "`/Library/Application Support/handsal/lib/handsal-check.pyz`"),
    ("SG-14", "`/Library/Application Support/handsal/python/bin/python3`"),
    ("SG-14", "`python/licenses/`"),
    ("SG-15", "`lib/handsal-check.pyz`"),
    ("SG-15", "`python/licenses/`"),
    ("SG-15", "neither conformance executable"),
    ("SG-15", "its licence texts as a gzip tar packed from the pinned notices"),
    ("SG-15", "It needs only stock tools at its fixed PATH (checked before any privileged step) and unpacks in staging before creating anything at an administrator path"),
    ("CF-07", "a failed unpack leaves the install path as it was"),
    ("11. Reason codes", "`unsupported_method`, `unsupported_command`, `identity_mismatch`, `profile_not_current`, `key_exists` (2)"),
    # 25. batch 12: who creates what, one order of attachment checks, the key and the display, the ceremony bag, the QR
    ("GP-21", "The installer (SG-15) creates `handsal` and the directories of its own artifacts (`bin`, `lib`, `python`)"),
    ("GP-21", "The helper is the only creator of `orgs` and of `pin.lock` on both platforms, and it creates `handsal` itself only when it finds it absent"),
    ("SG-15", "never `orgs` or `pin.lock`"),
    ("RN-09", "Order of checks."),
    ("RN-09", "the first defect wins"),
    ("RN-09", "`attachment_mismatch` whether or not `heads` is there"),
    ("RN-09", "V: rnd/endorse-resolve-act-mismatch-before-heads-missing, rnd/resolve-candidates-mismatch-before-heads-missing, rnd/genesis-head-missing-before-previous-missing"),
    ("SG-08", "the attachments, in the order RN-09 gives (Order of checks)"),
    ("SG-08", "An absent `document` is `attachment_missing` whatever the draft's `head` says"),
    ("SG-08", "so a draft with an unsupported method and a malformed `fixed` value is `unsupported_method`"),
    ("SG-08", "The key sits between steps 1 and 2"),
    ("SG-08", "V: sgn/genesis-document-missing-before-head-refused"),
    ("SG-08", "V: sgn/unsupported-method-before-bad-fixed-refused"),
    ("CF-07", "a refusal that needs no key is decided before `key_unavailable`"),
    ("SG-09", "The QR carries the code itself as the 43-character base64url text of the 32 bytes"),
    ("SG-12", "one object with exactly the keys `acts` (the bag of every epoch), `device_kid`, `lineage`"),
    ("SG-12", "`H is below candidate <full c>` also when H is c itself"),
    ("SG-12", "a fork inside a branch shows its lines too instead of stopping the ceremony"),
    ("SG-12", "Steps 2 to 8 depend on the ceremony's input alone"),
    ("SG-12", "which read no pin, no clock and no store (CF-08)"),
    ("SG-12", "a policy whose witness `mode` is `relay`, with `witness_missing`"),
    ("CF-08", "`genesis-check` and `genesis-aids` read no pin, no clock and no store at all"),
    ("CF-03", "`genesis-aids` takes the `genesis-check` input"),
    # 26. the local decision act (VR-18): one generic method, the content decided is attached and shown,
    # the consumer is signed and checked, the action is text under a grammar the profile owns
    ("VR-18", "`local:handsal.decision` records one decision of a person about content, on the machine where the person signs"),
    ("VR-18", "A verdict that travels between machines through a relay stays `request.*`"),
    ("VR-18", "carries no `recipient`, no `relay` and no `request_id`"),
    ("VR-18", "The profile owns the grammar and the rendering; a consumer owns its vocabulary"),
    ("VR-18", "`action` is not data in the genesis policy"),
    ("VR-18", "a consumer MUST accept only its own exact labels, and decide which `action` and `subject` to ask for"),
    ("VR-18", "no consumer compares them again"),
    ("VR-18", "no code is added"),
    ("VR-18", "`inputs_hash` is hashstr(raw bytes of the content decided)"),
    ("VR-18", "`outputs_hash` is hashstr(JCS({\"action\":A,\"subject\":S}))"),
    ("VR-18", "a decision signed for one consumer cannot be accepted by another"),
    ("VR-18", "`consumer_mismatch`"),
    ("VR-18", "a `consumer` input that is not a `consumer_id` is `malformed_input`"),
    ("VR-18", "`recheck-act` (VR-17) runs the same steps, through the one implementation"),
    ("ACT-09", "| `local:handsal.decision` | `expires` | always | `{action, consumer, subject}` |"),
    ("ACT-09", "`consumer` is a `consumer_id`; `subject` is a `subject_id`; `action` is an `action`"),
    ("ACT-13", "| `decision` | null | null |"),
    ("2.2", "- `action`: lowercase ASCII words"),
    ("2.2", "- `consumer_id`: `[a-z][a-z0-9-]{1,31}`"),
    ("2.2", "- `subject_id`: `[a-z0-9][a-z0-9-]{1,63}`"),
    ("2.2", "`decision_b64`"),
    ("VR-01", "`action`, `consumer`, `decision_b64` and `subject` are required"),
    ("VR-02", "`consumer_mismatch` (decisions"),
    ("VR-06", "`decision_b64`"),
    ("VR-07", "hashstr(JCS({\"action\":A,\"subject\":S}))"),
    ("VR-11", "Non-chain acts carry `expires`"),
    ("VR-17", "`action`, `consumer`, `decision_b64` and `subject` are read as `check-act` reads them"),
    ("VR-07", "A new code would split one refusal in two"),
    ("FO-15", "Non-chain acts are never on the chain"),
    ("RN-03", "`decision`: `<consumer>: <action> <subject> (<hash12(inputs_hash)>, <N> bytes)`"),
    ("RN-03", "`<action>` is shown whole"),
    ("RN-04", "`decision`: `Consumer: <consumer>`, `Action: <action>`, `Subject: <subject>`, `Decision hash: <hash12(inputs_hash)>`"),
    ("RN-09", "| `decision` | `decision_b64` | hashstr(bytes) = `inputs_hash` |"),
    ("RN-12", "`decision` renders its attached content exactly like"),
    ("RN-12", "`----- decision (<N> bytes, sha256 <hash12>) -----`"),
    ("CF-03", "`decision_b64`"),
    ("SG-04", "(verdicts and `decision`)"),
    ("11. Reason codes", "`request_mismatch`, `consumer_mismatch`, `inputs_mismatch`, `outputs_mismatch`"),
    ("12. Vector groups", "`dec`"),
    # the agreement key and the `agree` command (KC-09, SG-16; owner decision 2026-11-14, option (a))
    ("KC-09", "it is created without per-use presence"),
    ("KC-09", "never biometry"),
    ("KC-09", "An agreement key never signs."),
    ("KC-09", "so a device's agreement key cannot later be changed to require presence without replacing the device"),
    ("KC-09", "V: fld/agree-not-in-keys"),
    ("KC-01", "Both properties describe the signing key of a device."),
    ("SG-01", "`sign`, `agree`, and `pin-read` (Windows only, GP-11)"),
    ("SG-03", "created without per-use presence (KC-09)"),
    ("SG-16", "handsal-agree/1"),
    ("SG-16", "`info = \"handsal-agree/1\" || 0x00 || lo || hi || context`"),
    # retirement of local:handsal.record.promote (section 19 of the design; FO-02 and L18; VR-14 without a tip)
    ("2.1 Terms", "**non-chain act**: a verdict"),
    ("ACT-09", "`local:handsal.record.promote` is retired and never reused"),
    ("FO-02", "and only when the production build (CF-08) returns them"),
    ("FO-02", "a consumer MUST NOT use its output to decide whether an act is a human decision, tests excepted"),
    ("14. Known limitations", "**L18. An automation host proves no human act.**"),
    ("14. Known limitations", "MUST report a human act as not proven, never as passed"),
    ("14. Known limitations", "defines no trust anchor for an automation host"),
    ("VR-14", "record `{receipt_id, valid, reason}` for a valid act"),
    ("SG-16", "HKDF (RFC 5869) with SHA-256"),
    ("SG-16", "an empty salt"),
    ("SG-16", "length 32"),
    ("SG-16", "The command never returns the raw shared secret"),
    ("SG-16", "The command needs no prompt, no display, no sensor check and no prompt guard"),
    ("SG-16", "The command never uses the signing key"),
    ("SG-16", "the smaller in byte order first"),
    ("SG-16", "`schema_refused`, exit 2"),
    ("SG-16", "`key_unavailable`, exit 3"),
    ("SG-16", "conformance/fixtures/agree-kat.json"),
    ("SG-08", "`agree` (SG-16) takes only"),
    ("SG-05", "The agreement key is not a signing key and has no such rule (KC-09)."),
    ("CF-04", "`agree` is not a conformance command"),
    ("CF-07", "`agree` (SG-16)"),
    ("2.2 Alphabets", "`agree_context`: 1 to 128 bytes"),
    ("14. Known limitations", "**L17. The agreement key needs no touch.**"),
    ("14. Known limitations", "Any process running as the user on that device can use the agreement key"),
    ("14. Known limitations", "read that device's mail and send as the device"),
    ("14. Known limitations", "can never act as the person"),
    # the per-machine store and `sync` (CF-09; owner decision 2026-11-14): one view of the chain per machine
    ("CF-09", "The conformance build has no store and no `sync`"),
    ("CF-09", "`<home>/Library/Application Support/handsal-check/<hex64>.store`"),
    ("CF-09", "never `$HOME` or any other environment variable"),
    ("CF-09", "`<LocalAppData>\\handsal-check\\<hex64>.store`"),
    ("CF-09", "the WSL2-side checker never writes a store"),
    ("CF-09", "`handsal-store/1`"),
    ("CF-09", "`acts` is strictly increasing in byte order"),
    ("CF-09", "There is no `org` member"),
    ("CF-09", "`witness` is the slot of the relay tip statement and is `null` in this version"),
    ("CF-09", "`store_missing`"),
    ("CF-09", "`store_owner`"),
    ("CF-09", "`store_malformed`"),
    ("CF-09", "`store_unavailable`"),
    ("CF-09", "`store_full`"),
    ("CF-09", "the closed object `{acts, docs, org}`"),
    ("CF-09", "runs before the lock and before any directory is created"),
    ("CF-09", "one blocking exclusive lock"),
    ("CF-09", "read the old store inside it"),
    ("CF-09", "A forked union is written with `fork`"),
    ("CF-09", "A `sync` that adds no act still writes"),
    ("CF-09", "Readers take no lock"),
    ("CF-09", "an agent running as the user can withhold acts from `sync`"),
    ("CF-09", "`sync` answers `unsupported_command` in the conformance build"),
    ("CF-03", "| `sync` | `{acts, docs, org}` (CF-09), production build only | `{reason, synced_at}` |"),
    ("CF-03", "it reads `acts` and `lineage` from the store (CF-09), and `check-act`, `enrolled` and `head` also its `synced_at` and `next` (`recheck-act` checks no view age and no `next`, VR-17), and they take no `tip_statement`"),
    ("CF-08", "also read the store (CF-09) in process, once per call"),
    ("CF-08", "`fold` and `genesis-check` take their bag explicitly and read no store"),
    ("CF-07", "`store_missing`, `store_owner`, `store_malformed`, `store_unavailable` and `store_full` (the store, CF-09, and admission, CF-11)"),
    ("CF-07", "the table of each build is the sentence of CF-08 or CF-10 that states it"),
    ("CF-07", "CF-09 store and `sync`, tests of the store"),
    ("VR-01", "reads the pin, the clock and the store in process (CF-08, CF-09)"),
    ("VR-02", "(f) production build only: `fixture_profile`, then the store reason (CF-09)"),
    ("VR-12", "the time `sync` last wrote the store after a fold that reached a verdict"),
    ("VR-12", "only `sync` sets it"),
    ("VR-17", "takes no `pin`, `acts` or `lineage`"),
    ("GP-07", "read `acts` and `lineage` from the store (CF-09)"),
    ("GP-13", "Input (production build) `{device_kid, org}`"),
    ("WT-03", "The production build takes no `tip_statement`"),
    ("WT-03", "reads the `witness` slot of the store"),
    ("WT-03", "answers `witness_missing` for every non-chain act until the relay path is specified"),
    ("13. Freshness witness", "A statement arrives through the store slot that `sync` writes"),
    ("SG-12", "run `sync` with `{acts, docs, org}` (CF-09), `docs` being the lineage of step 1, then run `enrolled` with `{device_kid, org}` (GP-13)"),
    ("SG-12", "a failed `sync` after the write fails the ceremony and leaves the pin"),
    ("SG-12", "Only a `sync` answer of `ok` lets the ceremony continue to `enrolled`; any other answer, `fork` and `epoch_superseded` included, fails the ceremony with that reason"),
    ("SG-12", "aForkedSyncAfterTheWriteFailsWithForkAndLeavesThePin"),
    ("SG-15", "never creates a store"),
    ("1.1 What this profile covers", "their storage on the verifying machine is CF-09"),
    ("11. Reason codes", "`store_missing`, `store_owner`, `store_malformed`, `store_unavailable`"),
    ("11. Reason codes", "| `store_full` | `sync` (CF-09), `admit` (CF-11) |"),
    ("14. Known limitations", "withhold acts from `sync`, delete the store, hold its lock or edit `synced_at`"),
    ("14. Known limitations", "`sync` itself cannot roll the store back"),
    ("14. Known limitations", "do not switch an organization to relay mode"),
    ("14. Known limitations", "Editing `synced_at` in the store"),
    ("14. Known limitations", "a retained store over that bound is `store_full`"),
    # the relay source (design section 20): the server build, `admit`, `pool`, the snapshot, the pinned `relays`
    ("2.3", "| ADMIT_RESERVE | 1048576 bytes (2^20) |"),
    ("2.3", "| `relays` | 0 to 2 | GP-02 |"),
    ("GP-01", "`classes`, `relays`, `roles` and the `roles` of each rule"),
    ("GP-02", "`relays`: a sorted, unique list of 0 to 2 `hostname` values"),
    ("GP-02", "a policy without it is `policy_invalid`, never read as an empty list"),
    ("GP-02", "an unsorted list `doc_not_sorted` (GP-01)"),
    ("GP-02", "three or more entries `policy_out_of_bounds`"),
    ("GP-02", "An empty list is valid: every verdict is `relay_mismatch` until a genesis change names a host"),
    ("GP-02", "V: pol/relays-missing, pol/relays-unsorted, pol/relays-duplicate, pol/relays-three, pol/relays-not-hostname"),
    ("GP-02", "a number is outside the canonical subset, so the document is no genesis document before its policy is read"),
    ("GP-02", "V: pol/relays-number"),
    ("VR-01", "an input carrying `relay` is `malformed_input` in both builds (VR-08)"),
    ("VR-08", "MUST be listed in `relays` of the policy of the state the step reads (GP-02)"),
    ("VR-08", "the tip's epoch for `check-act`, the head epoch of the act for `recheck-act` (VR-17)"),
    ("VR-08", "an input that carries it is `malformed_input` in both builds"),
    ("VR-08", "A rename from A to B is two genesis changes: `relays [A, B]` and a re-pin on every machine, then `relays [B]`"),
    ("VR-08", "The policy holds no time"),
    ("VR-08", "V: rly/relay-input-refused"),
    ("VR-08", "C: rly/two-names-old-ok, rly/two-names-new-ok"),
    ("VR-08", "V: rly/empty-relays-mismatch"),
    ("VR-17", "`relay` is `malformed_input` in both builds too (VR-08)"),
    ("VR-17", "`relay_mismatch` (against `relays` of that head's epoch, VR-08)"),
    ("VR-17", "C: rck/relay-from-head-epoch"),
    ("RN-04", "`  Relays: none` or `  Relays: <hosts joined by \",\">`"),
    ("RN-04", "V: rnd/genesis-relays-line"),
    ("RN-10", "V: rnd/genesis-change-relays-diff"),
    ("CF-03", "| `admit` | CF-11, conformance and server builds | `{reason, store}` |"),
    ("CF-03", "| `pool` | CF-12, conformance and server builds | `{in_pool, reason}` |"),
    ("CF-05", "on Linux, in the server build only (CF-10), `/opt/handsal/bin/vitni-verify`"),
    ("CF-07", "no test counts commands"),
    ("CF-07", "Server build and admission, tests of the checker"),
    ("CF-07", "checker/python/tests/test_server.py::test_every_other_command_is_unsupported_and_no_output_proves_anything"),
    ("CF-07", "checker/python/tests/test_admit.py::test_a_store_past_the_reserve_is_store_full"),
    ("CF-07", "checker/python/tests/test_pool.py::test_a_key_true_for_a_store_is_true_for_every_larger_store"),
    ("CF-08", "The checker ships as three builds of one pure core"),
    ("CF-08", "**server** `handsal-check-server`"),
    ("CF-08", "and there is no `sync` and no `version`"),
    ("CF-09", "the path from the original to the document whose hash is the pin's `genesis`"),
    ("CF-09", "that document absent from `docs` is `genesis_pin_mismatch`"),
    ("CF-09", "documents off the path are ignored and not stored"),
    ("CF-09", "with `sigs` sorted and unique"),
    ("CF-10", "Its table is exactly `admit` (CF-11), `pool` (CF-12), `compact` (CF-14), `agree-points` (CF-16) and `version` (CF-03)"),
    ("CF-10", "`{\"error\":\"unsupported_command\"}`"),
    ("CF-10", "reads no pin, no clock and no store"),
    ("CF-10", "takes no `--vitni` option"),
    ("CF-10", "refuses the fixture profile"),
    ("CF-10", "its outputs carry no `valid`, `rechecked` or `enrolled` key"),
    ("CF-10", "never installed at a macOS or Windows administrator path"),
    ("CF-10", "Linux amd64 only"),
    ("CF-10", "`/opt/handsal`"),
    ("CF-10", "proves nothing about any person"),
    ("CF-11", "the closed object `{acts, docs, item, org}`"),
    ("CF-11", "`item`, exactly `{act, sigs}` or exactly `{doc, sigs}`"),
    ("CF-11", "valid now, never \"could matter later\""),
    ("CF-11", "a pending primary, a lone endorsement and a lone `genesis.sign` receipt are never admitted"),
    ("CF-11", "`not_chain_act`"),
    ("CF-11", "`already_stored`"),
    ("CF-11", "`parent_unknown`"),
    ("CF-11", "`act_not_valid`"),
    ("CF-11", "`kid_repeated`"),
    ("CF-11", "once per key of the state at the parent (and once for the new key)"),
    ("CF-11", "V: adm/kid-repeated-endorsement, adm/kid-repeated-pop, adm/kid-repeated-receipt"),
    ("CF-11", "at most MAX_INPUT minus 2 times ADMIT_RESERVE"),
    ("CF-11", "at most MAX_INPUT minus ADMIT_RESERVE"),
    ("CF-11", "`{\"reason\":R,\"store\":S}`"),
    ("CF-11", "pending acts travel to their co-signers outside the chain store"),
    ("CF-11", "V: adm/pending-device-add-not-valid"),
    ("CF-12", "the closed object `{acts, agree, docs, org}`"),
    ("CF-12", "A removed device stays in"),
    ("CF-12", "A `sign` point is not in the pool"),
    ("CF-12", "MUST NOT cache `false`"),
    ("CF-12", "does not say active, current or accepted"),
    ("CF-12", "`{\"in_pool\":B,\"reason\":R}`"),
    ("CF-13", "serves snapshots `{acts, docs, org}`"),
    ("CF-13", "one parser"),
    ("CF-13", "runs one `sync` per source it reaches"),
    ("CF-13", "handsal fetches nothing"),
    ("CF-13", "stays reserved"),
    ("CF-13", "`synced_at` says some source was consulted, not which"),
    ("SG-12", "`docs` being the lineage of step 1"),
    ("SG-14", "`/opt/handsal/bin/vitni-verify`"),
    ("SG-14", "`/opt/handsal/lib/handsal-check-server.pyz`"),
    ("SG-14", "root-owned, mode 0755, never writable by the service user"),
    ("SG-15", "The Linux server artifact set"),
    ("SG-15", "a closed list per platform"),
    ("11. Reason codes", "| `parent_unknown`, `already_stored`, `act_not_valid`, `not_chain_act` | `admit` (CF-11) |"),
    ("11. Reason codes", "| `kid_repeated` | `admit` (CF-11) |"),
    ("11. Reason codes", "| `not_in_pool` | `pool` (CF-12) |"),
    ("12. Vector groups", "`adm`, `kpl`"),
    ("14. Known limitations", "a withholding source still advances `synced_at`"),
    ("14. Known limitations", "bounded below MAX_INPUT by ADMIT_RESERVE (CF-11)"),
    ("14. Known limitations", "Room comes back by dropping (CF-14)"),
    ("14. Known limitations", "The server build (CF-10) runs on automation hosts"),
    ("14. Known limitations", "proves nothing about any person"),
    ("Appendix B", "\"relays\": [\"r.example\"]"),
    # Phase 14 (design 21): what a store may drop, `compact`, `next`, `epoch_superseded`
    ("GP-13", "`{acts, device_kid, lineage, next, now, org, pin, synced_at, tip_statement}`"),
    ("GP-13", "an input carrying `acts`, `lineage`, `next`, `now`, `pin`, `synced_at` or `tip_statement` is `malformed_input`"),
    ("GP-13", "VR-12 (`epoch_superseded` included)"),
    ("GP-13", "V: enr/epoch-superseded"),
    ("GP-19", "The acts this paragraph says are never read are the acts a store may drop once the change is stored (CF-14)."),
    ("VR-01", "`next` is `\"yes\"` or `\"no\"`: whether the store holds a valid successor of the pinned document (VR-12)"),
    ("VR-01", "a `next` that is neither `\"yes\"` nor `\"no\"`"),
    ("VR-01", "an input carrying `pin`, `now`, `acts`, `lineage`, `next`, `synced_at` or `tip_statement` is `malformed_input`"),
    ("VR-01", "V: chk/next-input-missing"),
    ("VR-12", "- `next` is `\"yes\"`: `epoch_superseded`;"),
    ("VR-12", "a machine whose store holds a valid successor of its pin cannot see what the new epoch removed, whatever the age of its view"),
    ("VR-12", "V: frs/epoch-superseded, ord/superseded-before-stale-view"),
    ("VR-12", "checker/python/tests/test_builds.py::test_next_is_read_from_the_store_and_refused_as_input"),
    ("VR-17", "`now`, `synced_at`, `seen`, `tip_statement` and `next` are `malformed_input` in both builds"),
    ("VR-17", "V: rck/next-input-malformed"),
    ("CF-03", "| `compact` | CF-14, conformance and server builds | `{drop, reason}` |"),
    ("CF-03", "`admit`, `pool`, `compact` and `agree-points` read no pin, no clock and no store"),
    ("CF-03", "an input carrying `pin`, `now`, `acts`, `lineage`, `next`, `synced_at` or `tip_statement` is `malformed_input` for those commands"),
    ("CF-07", "the server table and modes are the sentences of CF-10"),
    ("CF-08", "**server** `handsal-check-server` (CF-10): its table and its modes are stated there"),
    ("CF-08", "the store's content (`acts`, `lineage`, `next`, `synced_at`, `tip_statement`)"),
    ("CF-09", "`{\"acts\":[...],\"lineage\":[{\"doc\",\"sigs\"}...],\"next\":N,\"synced_at\":T,\"v\":\"handsal-store/1\",\"witness\":null}`"),
    ("CF-09", "The valid descendants of the pinned document are open epochs"),
    ("CF-09", "the retained store over MAX_INPUT is `store_full`"),
    ("CF-09", "The store never loses an item that any command on the machine reads, now or after any re-pin the pin can make"),
    ("CF-09", "`sync` itself never rolls the store back past what its readers need"),
    ("CF-09", "checker/python/tests/test_sync.py::test_a_closed_epoch_keeps_the_path_to_its_successor_and_drops_the_rest"),
    ("CF-09", "checker/python/tests/test_sync.py::test_a_valid_successor_of_the_pin_sets_next_and_an_invalid_one_does_not"),
    ("CF-09", "checker/python/tests/test_sync.py::test_a_superseded_pin_is_written_with_epoch_superseded"),
    ("CF-11", "`epoch_closed`"),
    ("CF-11", "a garbage twin"),
    ("CF-11", "V: adm/epoch-closed-act"),
    ("CF-11", "C: adm/garbage-twin-not-stored"),
    ("CF-11", "V: adm/change-head-dropped"),
    ("CF-11", "C: adm/ok-change-at-retained-head"),
    ("CF-12", "Monotone under admission"),
    ("CF-12", "clears that cache when it applies a drop"),
    ("CF-12", "V: kpl/dropped-branch-key-not-in-pool"),
    ("CF-13", "`docs` every document the source holds"),
    ("CF-13", "whole groups"),
    ("CF-13", "withholds `epoch_superseded` too (L10)"),
    ("CF-14", "`handsal-check-server compact < input.json`"),
    ("CF-14", "the **retained set**"),
    ("CF-14", "every answer of `fold`, `check-act`, `enrolled`, `recheck-act`, `head` and `genesis-check` is the same over the retained set as over the whole store"),
    ("CF-14", "`{\"drop\":{\"acts\":A,\"sigs\":G},\"reason\":\"ok\"}`"),
    ("CF-14", "a store MUST serialize document admission with computing and applying a drop list"),
    ("CF-14", "Acts need no such lock: an act in a closed epoch is refused `epoch_closed`, and an act in an open epoch is never listed."),
    ("CF-14", "A pin the store supersedes, a closed epoch, is outside the theorem"),
    ("CF-14", "Only the second direction fails closed, and neither is an authorization"),
    ("CF-14", "`check-act`, `enrolled` and `head` then never answer `ok`, over the retained set or over the whole store"),
    ("CF-14", "`unknown_key` by `check-act` (step 9) and `local_key_unknown` by `enrolled` (step 5)"),
    ("CF-14", "or a state with another tip"),
    ("VR-12", "A `fork` of the pinned epoch is a verdict about an open tip."),
    ("VR-12", "V: ord/superseded-before-fork, enr/epoch-superseded-before-fork"),
    ("GP-13", "but a `fork` where `next` is `\"yes\"` is `epoch_superseded`"),
    ("VR-02", "but a `fork` where `next` is `\"yes\"` is `epoch_superseded`"),
    ("CF-14", "SHOULD compact an epoch only after it has been closed for at least the `max_view_age_s` of its policy"),
    ("CF-14", "which one counts is a person's re-pin"),
    ("CF-14", "acts of another organization, whether or not their parent is a node of the store"),
    ("FO-06", "A chain act whose signed `org` is not the organization's is ignored the same way, whatever its parent"),
    ("SG-12", "`fork` and `epoch_superseded` included"),
    ("SG-12", "aids of steps 6 and 7 read the ceremony's bag"),
    ("SG-12", "signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aSupersededSyncAfterTheWriteFailsWithThatReasonAndLeavesThePin"),
    ("11. Reason codes", "| `epoch_superseded` | step 14 (VR-12), `enrolled` step 6, `head` (VR-19), `sync` (CF-09) |"),
    ("11. Reason codes", "| `epoch_closed` | `admit` (CF-11) |"),
    ("12. Vector groups", "`adm`, `kpl`, `cmp`"),
    ("12. Vector groups", "`chk`, `ord`, `vtn`, `sig`, `idn`, `inp`, `rly`, `rep`, `tim`, `frs`, `ing`, `rck`, `dec`, `hed` | VR |"),
    ("14. Known limitations", "only the heads on the retained paths are publishable there"),
    ("14. Known limitations", "The store keeps the path of every earlier epoch (CF-14)"),
    ("14. Known limitations", "refuses the same way (`epoch_superseded`, VR-12)"),
    ("14. Known limitations", "The path floor"),
    ("14. Known limitations", "A hostile sibling lineage"),
    # Phase 15 (design 22.4): the head a signer names (VR-19), and the macOS signer path
    ("VR-19", "### VR-19 Head for a signer"),
    ("VR-19", "`handsal-check head < input.json`"),
    ("VR-19", "Input (conformance build) `{acts, lineage, next, now, org, pin, synced_at, tip_statement}`"),
    ("VR-19", "Input (production build) `{org}`: it reads the pin, `now` and the store in process (CF-08, CF-09)"),
    ("VR-19", "an input carrying `acts`, `lineage`, `next`, `now`, `pin`, `synced_at` or `tip_statement` is `malformed_input`"),
    ("VR-19", "`{\"head\":{\"id\":T,\"kind\":\"chain\"},\"reason\":\"ok\"}` or `{\"head\":null,\"reason\":R}`"),
    ("VR-19", "the pin checks of VR-02 step 6, (a) to (h), in that order and with those codes, the store reason at (f) included in the production build"),
    ("VR-19", "the act-free rules of VR-12 (`epoch_superseded`, `view_in_future`, `stale_view` by age), then the witness rules of the policy's mode (WT-04, WT-05, WT-10)"),
    ("VR-19", "There is no fixture step and no new reason code"),
    ("VR-19", "the current genesis document hash where the chain is empty"),
    ("VR-19", "`head` answers `ok` with T exactly when `check-act` of an otherwise perfect non-chain act that names T as its head passes steps 6 and 14, and answers a code R exactly when `check-act` of such an act answers R at one of those steps"),
    ("VR-19", "It is not human proof, not an enrolment check (the key may be removed or its class not accepted, which `enrolled` answers) and not a promise about later"),
    ("VR-19", "A caller asks again for every signature"),
    ("VR-19", "`head` returns no `parent.performer`"),
    ("VR-19", "VR-14 is unchanged"),
    ("VR-19", "checker/python/tests/test_head.py::test_head_and_check_act_agree_over_every_check_act_world"),
    ("VR-19", "conformance/vectors/_gen/tests/test_group_hed.py::test_every_hed_vector_agrees_with_the_check_act_model"),
    ("VR-19", "checker/python/tests/test_builds.py::test_head_refuses_every_state_key_and_reads_nothing_first"),
    ("VR-19", "checker/python/tests/test_builds.py::test_head_reads_the_store_once_per_call"),
    ("VR-19", "checker/python/tests/test_builds.py::test_head_answers_store_missing_after_the_pin_reasons"),
    ("ACT-08", "A caller on a machine with a store gets it from `head` (VR-19)."),
    ("SG-04", "on a machine with a store the caller gets it from `handsal-check head` (VR-19) and copies it into the draft unchanged"),
    ("CF-03", "| `head` | VR-19 | `{head, reason}` |"),
    ("CF-03", "`check-act`, `recheck-act`, `enrolled` and `head`"),
    ("CF-07", "checker/python/tests/test_head.py::test_head_and_check_act_agree_over_every_check_act_world"),
    ("CF-07", "checker/python/tests/test_builds.py::test_head_refuses_every_state_key_and_reads_nothing_first"),
    ("CF-07", "checker/python/tests/test_builds.py::test_head_reads_the_store_once_per_call"),
    ("CF-07", "checker/python/tests/test_builds.py::test_head_answers_store_missing_after_the_pin_reasons"),
    ("CF-07", "checker/python/tests/test_builds.py::test_the_store_has_one_reader"),
    ("CF-07", "conformance/vectors/_gen/tests/test_group_hed.py::test_every_hed_vector_agrees_with_the_check_act_model"),
    ("CF-07", "every production command asks vitni in one `verify-batch` round"),
    ("CF-07", "checker/python/tests/test_builds.py::test_the_conformance_build_has_no_sync_and_the_production_table_is_the_spec_sentence"),
    ("CF-08", "`check-act`, `recheck-act`, `enrolled` and `head` also read the store (CF-09) in process, once per call"),
    ("CF-08", "Every production command that reads chain state gets it from the one read of the store and the one pinned fold over it"),
    ("CF-08", "a new per-machine query is a new command over them, never a second reader"),
    ("CF-08", "checker/python/tests/test_builds.py::test_the_store_has_one_reader"),
    ("CF-09", "`check-act`, `recheck-act`, `enrolled` and `head` read it in process (CF-08)"),
    ("CF-09", "the table of the production build is its sentence in CF-08"),
    ("SG-14", "`/Library/Application Support/handsal/bin/handsal-sign`"),
    ("SG-14", "`/Library/Application Support/handsal/bin/handsal-ceremony`"),
    ("SG-14", "`/Library/Application Support/handsal/bin/handsal-link`"),
    ("SG-14", "A program that runs the signer runs it only by its fixed path"),
    ("SG-14", "`/mnt/c/Program Files/handsal/handsal-sign.exe`"),
    ("SG-15", "`handsal-sign.exe`, and on macOS `handsal-sign`, `handsal-ceremony` and `handsal-link`"),
    # 26. SH11: the hardware run showed macOS kills a quarantined installed binary
    ("SG-15", "On macOS it removes `com.apple.quarantine` from every file and directory of the staged tree after the second hash check and before the move"),
    ("SG-15", "never from the person's downloaded files"),
    ("SG-15", "an absent attribute is not an error"),
    ("11. Reason codes", "| `view_in_future`, `stale_view` | step 14 (VR-12), `enrolled` step 6, `head` (VR-19);"),
    ("11. Reason codes", "| fold error codes (below) | step 6 (i), `enrolled` step 4, `head` (VR-19), `fold`, `genesis-check` |"),
    ("11. Reason codes", "`enrolled` steps 1 to 3 and 7, `head` (VR-19), fold (GP-05, GP-10, GP-11, GP-13, GP-17, GP-18)"),
    ("11. Reason codes", "| `store_missing`, `store_owner`, `store_malformed`, `store_unavailable` | step 6 (f), `enrolled` steps 1 to 3, `head` (VR-19), `sync` (CF-09) |"),
    ("11. Reason codes", "`enrolled` step 6, `head` (VR-19) |"),
    ("11. Reason codes", "success of `check-act`, `recheck-act` (`rechecked:true`), `enrolled`, `head`, `genesis-check`"),
    # every live production profile stays implemented (GP-22 to GP-24)
    ("GP-22", "Every release MUST implement every production profile that any document of any live lineage names"),
    ("GP-22", "A release MUST NOT remove an edition from the catalog"),
    ("GP-22", "The catalog is append-only and is not a core file"),
    ("GP-22", "Fixture kids are append-only across editions"),
    ("GP-22", "Deferred, and not decided here"),
    ("GP-23", "I5. The rules of an epoch come only from the profile of that epoch's document."),
    ("GP-23", "The rules of a change's authority come only from the profile of the previous document."),
    ("GP-23", "I3. The wire is the same in every edition."),
    ("GP-23", "the shape of a device entry of `S_H` and of the pool of earlier keys"),
    ("GP-23", "is wire by default: an unclassified registry key is frozen across editions"),
    ("GP-24", "I2. Migrability."),
    ("GP-24", "MUST pass GP-15 steps 1 to 5 under Pn+1"),
    ("GP-24", "I4. No downgrade."),
    ("GP-24", "is `profile_downgrade`"),
    ("GP-24", "The fold alone enforces I4: the signer does not (SG-17)."),
    ("GP-15", "2. profile: `profile_mismatch`, `fixture_profile`, then, for a change only, `profile_downgrade` (GP-24);"),
    ("GP-15", "Steps 1 to 5 read the profile of the document under test."),
    ("GP-19", "the previous epoch, its path to H, its state `S_H`, its policy and every rule applied to them are those of the previous document's profile"),
    ("GP-20", "The whole carry (acceptance, byte-identity, `genesis_device_revoked`, `genesis_device_changed`) is evaluated under the new document's profile"),
    ("GP-07", "A change MUST NOT name an older edition than the previous document's (`profile_downgrade`, GP-24)."),
    ("GP-18", "Each edition defines two profile hashes from one core manifest (CF-01)"),
    ("VR-12", "or that an authorized foreign successor is (CF-09)"),
    ("VR-17", "under the profile of that epoch's document (GP-23)"),
    ("VR-18", "Why `consumer` should be a stable product identifier"),
    ("RN-09", "A document that names a profile outside the catalog has no registry of its own"),
    ("CF-01", "A verifier implements the supported set of editions (GP-22)"),
    ("CF-01", "`spec/errata.md`, the file that records editorial fixes between rule editions, is not a core file"),
    ("CF-07", "`prf/downgrade-refused`"),
    ("CF-07", "`profile_not_current` (signer, SG-17) is excepted"),
    ("CF-08", "the tree holds one set: the set of the current edition"),
    ("CF-09", "**Foreign successor.**"),
    ("CF-09", "A foreign successor sets `next` to `\"yes\"` exactly as a valid successor does, is not stored, and nothing below it is read."),
    ("CF-09", "A forged successor with no quorum authority is ignored, so no one below the quorum can cause the outage."),
    ("CF-15", "Consequence, stated: the command interface of the conformance build"),
    ("CF-15", "is **append-only** across the catalog"),
    ("CF-15", "records the name of the tag that shipped its edition and the CF-01 bundle hash of that tag"),
    ("SG-02", "`profiles` is the list of every production profile hash the signer implements"),
    ("SG-08", "3a. for `sign` of a `genesis.sign` only"),
    ("SG-12", "and refuse, with `profile_mismatch`, a lineage in which any document, last or earlier, names a hash that is not a production profile of the supported set"),
    ("SG-17", "MUST refuse to sign a `genesis.sign` whose attached `document` is an original"),
    ("SG-17", "A change is not refused for its edition."),
    ("SG-17", "a future Rust `sign` MUST resolve profiles through the Rust edition table"),
    ("11. Reason codes", "`profile_mismatch`, `fixture_profile`, `profile_downgrade`, `policy_invalid`"),
    ("11. Reason codes", "`identity_mismatch`, `profile_not_current`, `key_exists` (2)"),
    # review fixes to the edition rules
    ("CF-07", "An ordering vector never qualifies as an only-defect vector"),
    ("CF-01", "An erratum never changes what any verifier, signer or consumer answers"),
    ("CF-15", "an added input key is optional"),
    ("CF-09", "Steps 3, 5, 6 and 9 of GP-15 are not run"),
    ("CF-09", "(1) its structure passes (GP-15 step 1); (2) its link passes (GP-15 step 4: `org` and `prev`); (3) its `head` is a node of the pinned epoch's act tree (GP-15 step 7); (4) its authority passes (GP-15 step 8, GP-19)"),
    ("CF-09", "test_a_foreign_successor_is_decided_by_its_four_checks_and_no_other_step"),
    ("GP-24", "test_policy_bounds_never_narrow_between_adjacent_editions"),
    ("GP-24", "test_kc03_kc08_and_the_carry_rules_accept_in_the_next_edition_what_the_previous_accepted"),
    ("GP-24", "test_a_valid_document_reprofiled_to_the_next_edition_passes_steps_1_to_5"),
)

NOT_IN = (
    ("CF-14", "over the retained set and over the whole store alike (a `fork` included, VR-12)"),
    ("CF-14", "so `fold` answers a state where the whole store answered `fork`, and `recheck-act`"),
    ("SG-12", "`synced_at` and `tip_statement` (the `enrolled` inputs, GP-13)"),
    ("13. Freshness witness", "A statement arrives through the consumer"),
    ("VR-12", "the time the consumer last obtained the act bag from its configured source"),
    ("VR-02", "for every method other than verdicts and `record.promote`"),
    ("SG-04", "present iff the method carries `expires` (verdicts, `record.promote`). \"0\""),
    ("VR-11", "Verdicts and record promotions carry `expires`"),
    ("14. Known limitations", "so `recheck-act` answers `stale_view`. This version has no command that re-checks an act against an earlier epoch's evidence"),
    ("CF-07", "VR-14 consumer store"),
    ("CF-07", "`chg/unaccepted-signer-not-counted` therefore uses a member who holds no role"),
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
    ("CF-04", "Signer implementations run the `render` and `emit` vectors only."),
    ("CF-07", "other than the two excepted"),
    ("CF-07", "- SG-12 ceremony: a production policy"),
    ("GP-17", "sgn/wsl-probe-reports-unprotected"),
    ("GP-21", "sgn/ceremony-pin-pipe-busy-fails"),
    ("SG-04", "`expires_in_s` is present iff the method carries `expires` (verdicts, `record.promote`), else `schema_refused`; a value above"),
    ("SG-04", "and never signs, so caller-chosen values there are harmless"),
    ("SG-10", "An unexpected prompt is a signal, never routine.\n\n### SG-11"),
    ("GP-21", "neither the ceremony nor the installer creates them"),
    ("GP-21", "The helper is the only creator of `handsal` and `orgs`"),
    ("SG-08", "then the `head` of a `genesis.sign` draft against `prev` of the attached document (`schema_refused`), then the values the signer derives from the attachments"),
    ("SG-08", "a missing one is `attachment_missing`; one the method cannot read (for `genesis.sign`, a document without `prev`) is `attachment_mismatch`; then"),
    ("VR-14", "tip_id_at_ingestion"),
    ("14. Known limitations", "receipt id, tip id and the relay's statement"),
    # the relay is no input any more; one `sync` input shape; three builds
    ("VR-01", "recipient, relay, request_b64"),
    ("VR-01", "and a non-null `relay` are required"),
    ("VR-01", "`relay` null when it is a verdict"),
    ("VR-08", "The verifier MUST supply its configured relay hostname"),
    ("VR-08", "V: rly/not-configured-flag"),
    ("VR-17", "recipient, relay, request_b64"),
    ("CF-08", "The checker ships as two builds"),
    ("CF-09", "Input: the closed object `{acts, lineage, org}`"),
    ("SG-12", "run `sync` with `{acts, lineage, org}`"),
    # Phase 14: the sentences the compaction text replaces
    ("CF-09", "The set of acts in a store never shrinks through any handsal command"),
    ("CF-09", "a string that is no valid act is kept"),
    ("CF-09", "test_a_stored_act_the_new_epoch_does_not_need_is_kept_too"),
    ("CF-09", "every store written is a superset of the one before it"),
    ("CF-08", "as input data, plus `admit` and `pool`"),
    ("CF-10", "Its table is exactly `admit` (CF-11) and `pool` (CF-12)"),
    ("CF-12", "so a `true` for a store is `true` for every larger store"),
    ("VR-17", "which `sync` only grows"),
    ("14. Known limitations", "A consumer that already holds a successor in its bag accepts statements issued before the successor"),
    ("14. Known limitations", "which this version does not do"),
    ("14. Known limitations", "the set of acts only grows"),
    ("14. Known limitations", "The production store never drops an act"),
    # edition 3: a table is its own sentence in CF-08 or CF-10, never a count
    ("CF-09", "the production table has eleven commands"),
    ("CF-07", "the conformance table has thirteen commands"),
    ("CF-07", "the server table three"),
    ("CF-10", "Its table is exactly `admit` (CF-11), `pool` (CF-12) and `compact` (CF-14)"),
    # Phase 15: `head` is a reader of the store like the three before it, and the production table has one more command
    ("CF-07", "the production table has nine commands"),
    ("CF-09", "the production table has nine commands"),
    ("CF-09", "`check-act`, `recheck-act` and `enrolled` read it in process"),
    ("CF-08", "`check-act`, `recheck-act` and `enrolled` also read the store"),
    ("CF-07", "the conformance table has eleven commands"),
    ("SG-12", "folds each branch alone, its own acts and the acts above the fork"),
    ("SG-12", "because the checker's `fold` of a forked epoch answers the fork and no state"),
    # the aids of the ceremony are a tenth shared command, so the tables have eleven, thirteen and three
    ("CF-07", "the production table has ten commands"),
    ("CF-07", "the conformance table has twelve commands"),
    # the one-profile wording is gone
    ("GP-07", "Version 1 implements one production profile"),
    ("CF-01", "fixed set of profile hashes"),
    ("GP-18", "Each profile version defines"),
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
    "rnd/prompt-line-max-genesis-original",
    "rnd/prompt-line-max-genesis-change", "wit/pol-tip-age-upper-bound-ok", "wit/next-hashstr-malformed",
    "rep/same-payload-low-s-same-receipt-id", "quo/raised-floor-3-three-applied",
    "rnd/genesis-head-mismatch", "rnd/genesis-document-invalid-bound",
    "rnd/genesis-previous-invalid-bound", "rnd/genesis-change-org-name-profile-lines",
    "rnd/attachment-wrong-type-mismatch", "cli/genesis-check-missing-head-acts-invalid",
    "cli/genesis-check-extra-acts-same-result",
    # batch 11: nine emit ids (ACT-05 S1), two nesting ids (CF-03), two ordering ids (SG-08)
    "jcs/emit-device-remove", "jcs/emit-member-add", "jcs/emit-chain-resolve", "jcs/emit-endorse",
    "jcs/emit-reject", "jcs/emit-needs-info", "jcs/emit-genesis-sign-original",
    "jcs/emit-genesis-sign-change", "cli/stdin-nesting-over-max-unparseable", "cli/stdin-nesting-at-max-malformed",
    "sgn/identity-before-attachment-refused", "sgn/genesis-head-before-org-refused",
    # batch 12: the order inside attachments, an absent document, an unsupported method before a bad `fixed`
    "rnd/endorse-resolve-act-mismatch-before-heads-missing", "rnd/resolve-candidates-mismatch-before-heads-missing",
    "rnd/genesis-head-missing-before-previous-missing", "sgn/genesis-document-missing-before-head-refused",
    "sgn/unsupported-method-before-bad-fixed-refused",
)


# the vector ids of the store drop amendment (design 21.9); each must be named by a scenario
STORE_DROP_IDS = (
    "cmp/open-epoch-kept-whole", "cmp/closed-off-path-dropped", "cmp/closed-resolve-dropped",
    "cmp/sibling-successor-paths-kept", "cmp/change-at-root-keeps-nothing-of-epoch",
    "cmp/junk-and-non-chain-dropped", "cmp/other-org-act-dropped", "cmp/invalid-twin-dropped",
    "cmp/second-valid-copy-dropped", "cmp/stranger-endorsement-dropped", "cmp/pending-primary-dropped",
    "cmp/unanchored-act-dropped", "cmp/override-evidence-kept", "cmp/non-counting-receipt-dropped",
    "cmp/store-doc-invalid",
    "adm/epoch-closed-act", "adm/ok-change-at-retained-head", "adm/change-head-dropped",
    "adm/garbage-twin-not-stored", "kpl/dropped-branch-key-not-in-pool",
    "frs/epoch-superseded", "enr/epoch-superseded", "ord/superseded-before-stale-view",
    "chk/next-input-missing", "rck/next-input-malformed",
)


# the vector ids of the relay source amendment (design 20.7); each must be named by a scenario
RELAY_IDS = (
    "adm/ok-original", "adm/ok-change-doc", "adm/ok-device-add-group", "adm/drops-junk-sig",
    "adm/ok-resolve", "adm/ok-valid-child-at-old-parent",
    "adm/already-stored-act", "adm/already-stored-low-s-twin", "adm/already-stored-doc", "adm/high-s",
    "adm/parent-unknown-act", "adm/parent-unknown-doc", "adm/pending-device-add-not-valid",
    "adm/lone-endorsement-not-chain", "adm/verdict-not-chain", "adm/statement-method-unknown",
    "adm/other-org-act", "adm/original-wrong-org", "adm/change-unauthorized", "adm/store-doc-invalid",
    "kpl/genesis-device", "kpl/added-on-losing-branch", "kpl/removed-device", "kpl/sign-point-not-in-pool",
    "kpl/pending-add-not-in-pool", "kpl/unknown", "kpl/store-original-wrong-org",
    "rly/other-relay", "rly/two-names-old-ok", "rly/two-names-new-ok", "rly/empty-relays-mismatch",
    "rly/relay-input-refused", "rck/relay-from-head-epoch", "rly/relay-dropped-at-tip-mismatch",
    "adm/kid-repeated-endorsement", "adm/kid-repeated-pop", "adm/kid-repeated-receipt", "pol/relays-number",
    "pol/relays-missing", "pol/relays-unsorted", "pol/relays-duplicate", "pol/relays-three",
    "pol/relays-not-hostname", "rnd/genesis-relays-line", "rnd/genesis-change-relays-diff",
)


# the vector ids of the signer head amendment (design 22.5); each must be named by a scenario
HEAD_IDS = (
    "hed/ok-tip", "hed/ok-root", "hed/ok-after-resolve", "hed/ok-two-epochs",
    "hed/fork", "hed/epoch-superseded", "hed/superseded-before-fork", "hed/superseded-before-stale-view",
    "hed/stale-view", "hed/view-in-future", "hed/age-exactly-max-ok",
    "hed/relay-witness-missing", "hed/relay-ok", "hed/mode-none-statement-supplied",
    "hed/pin-missing", "hed/pin-org-mismatch", "hed/lineage-broken",
    "hed/next-input-missing", "hed/org-input-missing",
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
        active = set(IDS["ids"])
        for number, _text, tails in SCENARIOS:
            for name in tails["V"] + tails["C"]:
                with self.subTest(line=number, vector=name):
                    self.assertIn(name, active)

    def test_a_vector_tail_names_shipped_vectors_only(self):
        """`V:` is a file in conformance/vectors. What waits for an owner step is `P:`, what is not a vector is `T:`."""
        for number, _text, tails in SCENARIOS:
            for name in tails["V"] + tails["C"]:
                with self.subTest(line=number, vector=name):
                    self.assertNotIn(name, PENDING)
                    self.assertTrue((ROOT / "conformance" / "vectors" / (name.replace("/", ".") + ".json")).is_file())

    def test_a_pending_tail_names_only_ids_the_catalog_lists_as_pending(self):
        for number, _text, tails in SCENARIOS:
            for name in tails["P"]:
                with self.subTest(line=number, vector=name):
                    self.assertIn(name, PENDING)

    def test_every_pending_id_is_named_by_a_scenario(self):
        named = {n for _, _, tails in SCENARIOS for n in tails["P"]}
        for name in sorted(IDS["pending"]):
            with self.subTest(vector=name):
                self.assertIn(name, named)

    def test_a_test_tail_names_a_test_that_cf07_lists_and_that_exists(self):
        listed = named_tests()
        for number, _text, tails in SCENARIOS:
            for ref in tails["T"]:
                with self.subTest(line=number, test=ref):
                    self.assertIn(ref, listed)
        for ref in sorted(listed):
            path, name = ref.split("::")
            with self.subTest(test=ref):
                self.assertTrue((ROOT / path).is_file(), path)
                self.assertRegex((ROOT / path).read_text(encoding="utf-8"), definition(path, name))

    def test_a_cited_vector_shows_a_code_its_scenario_names(self):
        """When the THEN part names reason codes, a `V:` vector ends in one of them.

        A vector that ends in no code (a success, a state) is a control, and the scenario says so with `C:`.
        """
        for number, head, tails in SCENARIOS:
            named = then_codes(head)
            if not named:
                continue
            for name in tails["V"]:
                shown = vector_codes(name)
                with self.subTest(line=number, vector=name):
                    self.assertTrue(shown & named, "%s shows %s, the scenario names %s (a control goes in C:)" % (name, sorted(shown), sorted(named)))

    def test_a_control_vector_shows_no_code(self):
        for number, _head, tails in SCENARIOS:
            for name in tails["C"]:
                with self.subTest(line=number, vector=name):
                    self.assertEqual(vector_codes(name), set(), "%s shows a code, so it is a V: vector" % name)

    def test_a_scenario_that_names_a_code_has_a_proof_that_is_not_only_a_control(self):
        for number, head, tails in SCENARIOS:
            if then_codes(head):
                with self.subTest(line=number):
                    self.assertTrue(tails["V"] or tails["P"] or tails["T"] or tails["O"], "only controls: %s" % head[:80])

    def test_every_scenario_ends_in_a_proof_tail(self):
        """A scenario with no `V:`, `C:`, `P:`, `T:` or `O:` has a proof written in prose that no tool checks."""
        for number, head, tails in SCENARIOS:
            with self.subTest(line=number):
                self.assertTrue(any(tails[k] for k in "VCPTO"), head[:80])

    def test_every_requirement_has_a_scenario(self):
        text = SPEC_TEXT
        for part in re.split(r"^(?=### )", text, flags=re.M):
            m = re.match(r"### ([A-Z]+-\d+)", part)
            if m:
                with self.subTest(requirement=m.group(1)):
                    self.assertRegex(part, r"(?m)^- S\d+: ")

    def test_every_split_id_is_named_by_a_scenario_or_a_test_list(self):
        text = PROFILE_TEXT
        for name in SPLIT_IDS:
            with self.subTest(vector=name):
                self.assertIn(name, text)

    def test_the_retired_method_is_named_only_where_it_is_retired(self):
        """Every line that holds the retired method or its fields is in ACT-09 and says it is retired.

        A NOT_IN row per edited sentence misses the sentence nobody listed. This reads the whole text.
        `record_body_b64` and `<record_id>` belong to no line at all: no input or template survives.
        """
        names = ("record.promote", "`record_id`", "`anchors`", "record_body_b64", "<record_id>")
        act09 = section("ACT-09")
        for number, line in enumerate(PROFILE_TEXT.splitlines(), 1):
            if not any(n in line for n in names):
                continue
            with self.subTest(line=number):
                self.assertNotIn("record_body_b64", line)
                self.assertNotIn("<record_id>", line)
                self.assertIn(line, act09, line[:80])
                self.assertIn("retired", line)

    def test_a_missing_policy_is_not_listed_as_a_schema_scenario(self):
        self.assertNotIn("pol/missing-policy", section("GP-01"))

    def test_every_store_drop_id_is_named_by_a_scenario(self):
        named = {n for _, _, tails in SCENARIOS for n in tails["V"] + tails["C"]}
        for name in STORE_DROP_IDS:
            with self.subTest(vector=name):
                self.assertIn(name, named)

    def test_the_superseded_rule_is_the_first_rule_of_the_view(self):
        """VR-12: `epoch_superseded` before `view_in_future` and `stale_view`, so a stale view of a superseded pin says so."""
        text = section("VR-12")
        self.assertLess(text.index("`epoch_superseded`"), text.index("`view_in_future`"))
        self.assertLess(text.index("`epoch_superseded`"), text.index("`stale_view`"))

    def test_every_relay_source_id_is_named_by_a_scenario(self):
        for name in RELAY_IDS:
            with self.subTest(vector=name):
                self.assertIn(name, PROFILE_TEXT)

    def test_the_retired_flag_vector_is_named_nowhere(self):
        self.assertNotIn("rly/not-configured-flag", PROFILE_TEXT)

    def test_no_input_list_names_relay(self):
        """The hostname is the policy's. A list of command inputs that still holds `relay` is the old copy."""
        self.assertNotRegex(PROFILE_TEXT, r"recipient, relay,|, relay, request")

    def test_a_missing_relays_is_not_listed_as_a_schema_scenario(self):
        self.assertNotIn("pol/relays-missing", section("GP-01"))

    def test_every_head_id_is_named_by_a_scenario_of_vr19(self):
        named = {n for _, _, tails in SCENARIOS for n in tails["V"] + tails["C"]}
        scenario_text = section("VR-19")
        self.assertEqual(len(HEAD_IDS), 19)
        for name in HEAD_IDS:
            with self.subTest(vector=name):
                self.assertIn(name, named)
                self.assertIn(name, scenario_text)

    def test_the_catalog_registry_holds_exactly_the_head_ids(self):
        """Design 22.5: the 19 ids of group `hed`, all active, none pending."""
        hed = {i for i in IDS["ids"] if i.startswith("hed/")}
        self.assertEqual(hed, set(HEAD_IDS))
        self.assertEqual(hed & PENDING, set())

    def test_the_command_table_of_cf03_names_each_command_once(self):
        """A row copied twice is one fact written twice; CF-03 is the one owner of the command list."""
        rows = [l.split("|")[1].strip() for l in section("CF-03").splitlines()
                if l.startswith("| `")]
        self.assertTrue(rows)
        self.assertEqual(sorted(r for r in rows if rows.count(r) > 1), [])

    def test_the_macos_signer_path_is_fixed_by_sg14_alone(self):
        """One owner for the path: SG-14 names it, no other requirement repeats it."""
        path = "/Library/Application Support/handsal/bin/handsal-sign`"
        for heading in ("SG-04", "SG-12", "SG-13", "SG-15", "CF-08", "CF-09", "VR-19"):
            with self.subTest(requirement=heading):
                self.assertNotIn(path, section(heading))
        self.assertIn(path, section("SG-14"))


if __name__ == "__main__":
    unittest.main()
