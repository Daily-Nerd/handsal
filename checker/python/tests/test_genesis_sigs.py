"""T3.18 possession: which `genesis.sign` receipts count for a document (GP-03, GP-15, ACT-13, KC-08).

A signature counts iff it passes ACT-01 to ACT-14 for `genesis.sign`, its kid is listed in the
document and its `performer_id` is that device's person, its `inputs_hash` is the document hash, its
`org` is the original org id, its head matches the document (present iff `prev` is non-null, equal
to `head`), vitni says ok with the one-entry keys map of that device, and S is low. Everything else
is ignored, never an error. Only a listed device without a counting signature fails, as
`genesis_unsigned` (GP-15 step 6).
"""
import json
import unittest

from handsal_check import errors, genesis, genesis_sigs, profiles, registry, verifier

from .act_builder import BAD, HIGH, FakeVitni, Unavailable, build, genesis_sign, head_of, kid_of
from .genesis_fixtures import change, device, org as make_org

REG = registry.load()
FIXTURE = profiles.load().fixture
ORG = make_org(FIXTURE)
ORG_ID = genesis.doc_hash(ORG)
OLD_HEAD = genesis.doc_hash(make_org(FIXTURE, name="OLD"))
CHANGE = change(FIXTURE, ORG_ID, genesis.doc_hash(ORG), OLD_HEAD)
CHANGE_ID = genesis.doc_hash(CHANGE)


def sign(name, doc=ORG, **kw):
    return genesis_sign(name, doc, ORG_ID, **kw).jws


def check(doc, sigs, vitni=None):
    genesis_sigs.check_possession(doc, sigs, ORG_ID, REG, vitni or FakeVitni())


def unsigned(doc, sigs, vitni=None):
    try:
        check(doc, sigs, vitni)
    except errors.Refused as err:
        return err.code
    return None


ALL = [sign(n) for n in ("alice", "bob", "carol")]


class Counting(unittest.TestCase):
    def test_every_listed_device_signed(self):
        self.assertIsNone(unsigned(ORG, ALL))

    def test_a_device_without_a_signature_is_unsigned(self):
        self.assertEqual(unsigned(ORG, ALL[:2]), "genesis_unsigned")
        self.assertEqual(unsigned(ORG, []), "genesis_unsigned")

    def test_junk_and_duplicates_never_fail_the_fold(self):
        junk = ["not a jws", "a.b.c", sign("alice", sig=BAD), "", sign("alice"), sign("alice")]
        self.assertIsNone(unsigned(ORG, junk + ALL))

    def test_a_non_verifying_signature_does_not_count(self):
        self.assertEqual(unsigned(ORG, [sign("alice", sig=BAD)] + ALL[1:]), "genesis_unsigned")

    def test_a_signature_by_an_unlisted_key_is_ignored_next_to_the_listed_ones(self):
        self.assertIsNone(unsigned(ORG, ALL + [sign("dave")]))

    def test_an_unlisted_key_does_not_stand_in_for_a_listed_one(self):
        self.assertEqual(unsigned(ORG, ALL[:2] + [sign("dave")]), "genesis_unsigned")

    def test_a_signature_over_another_document_does_not_count(self):
        other = make_org(FIXTURE, name="OTHER")
        self.assertEqual(unsigned(ORG, ALL[:2] + [genesis_sign("carol", other, ORG_ID).jws]), "genesis_unsigned")

    def test_a_high_s_signature_does_not_count(self):
        self.assertEqual(unsigned(ORG, [sign("alice", sig=HIGH)] + ALL[1:]), "genesis_unsigned")
        self.assertIsNone(unsigned(ORG, [sign("alice", sig=HIGH)] + ALL))

    def test_the_performer_must_be_the_person_of_the_listed_device(self):
        self.assertEqual(unsigned(ORG, [sign("alice", performer="bob")] + ALL[1:]), "genesis_unsigned")

    def test_the_act_object_kid_must_be_the_header_kid(self):
        self.assertEqual(unsigned(ORG, [sign("alice", act_kid=kid_of("bob"))] + ALL[1:]), "genesis_unsigned")

    def test_the_body_must_be_empty(self):
        self.assertEqual(unsigned(ORG, [sign("alice", body={"x": "y"})] + ALL[1:]), "genesis_unsigned")

    def test_parent_fields_must_be_null(self):
        for over in ({"parent": OLD_HEAD}, {"parent_performer": "bob"}):
            self.assertEqual(unsigned(ORG, [sign("alice", **over)] + ALL[1:]), "genesis_unsigned", over)

    def test_the_org_must_be_the_original_org_id(self):
        self.assertEqual(unsigned(ORG, [sign("alice", org=OLD_HEAD)] + ALL[1:]), "genesis_unsigned")

    def test_hashes_are_the_ones_of_the_method(self):
        self.assertEqual(unsigned(ORG, [sign("alice", outputs_hash=OLD_HEAD)] + ALL[1:]), "genesis_unsigned")

    def test_another_method_is_not_a_signature(self):
        approve = build("alice", "request.approve", org=ORG_ID, body={}, inputs_hash=genesis.doc_hash(ORG)).jws
        self.assertEqual(unsigned(ORG, [approve] + ALL[1:]), "genesis_unsigned")

    def test_an_original_with_a_head_does_not_count(self):
        self.assertEqual(unsigned(ORG, [sign("alice", head=head_of(OLD_HEAD))] + ALL[1:]), "genesis_unsigned")


class Changes(unittest.TestCase):
    ALL = [genesis_sign(n, CHANGE, ORG_ID).jws for n in ("alice", "bob", "carol")]

    def test_a_change_needs_its_head(self):
        self.assertIsNone(unsigned(CHANGE, self.ALL))
        self.assertEqual(unsigned(CHANGE, self.ALL[1:] + [sign("alice", doc=CHANGE, head=None)]), "genesis_unsigned")

    def test_the_head_must_name_the_documents_head(self):
        other = genesis_sign("alice", CHANGE, ORG_ID, head=head_of(CHANGE_ID)).jws
        self.assertEqual(unsigned(CHANGE, self.ALL[1:] + [other]), "genesis_unsigned")

    def test_the_org_is_the_original_org_id_not_the_changes_hash(self):
        wrong = genesis_sign("alice", CHANGE, CHANGE_ID).jws
        self.assertEqual(unsigned(CHANGE, self.ALL[1:] + [wrong]), "genesis_unsigned")


class WhatVitniIsAsked(unittest.TestCase):
    def test_a_one_entry_map_of_the_listed_device_and_the_method_pinned(self):
        vitni = FakeVitni()
        genesis_sigs.counting(ORG, [sign("alice")], ORG_ID, REG, vitni)
        (_, keys, method), = vitni.calls
        entry = ORG["devices"][[d["person"] for d in ORG["devices"]].index("alice")]
        self.assertEqual(method, "local:handsal.genesis.sign")
        expected = {"alice": {entry["kid"]: {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active",
                                              "x": entry["sign"]["x"], "y": entry["sign"]["y"]}}}
        self.assertEqual(keys, json.dumps(expected, sort_keys=True))

    def test_nothing_is_asked_about_what_cannot_count(self):
        vitni = FakeVitni()
        genesis_sigs.counting(ORG, ["junk", sign("dave"), sign("alice", sig=BAD)[:-3]], ORG_ID, REG, vitni)
        self.assertEqual(vitni.calls, [])

    def test_a_verifier_that_cannot_answer_is_not_a_missing_signature(self):
        with self.assertRaises(verifier.VerifierUnavailable):
            check(ORG, [sign("alice")], Unavailable())


if __name__ == "__main__":
    unittest.main()
