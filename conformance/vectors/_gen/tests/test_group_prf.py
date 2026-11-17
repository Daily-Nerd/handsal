"""Vectors prf/*: the cross-edition cases the tree can build with two editions (GP-22 to GP-24, CF-08).

Each row is stated from the spec. P1 is the previous edition and P2 the current core; the rows use fixture keys, so
they name the fixture profile of each edition unless the row is about a production profile (GP-18).
"""
import base64
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

P1, P2 = 1, 2
FIXTURE, PRODUCTION = "fixture", "production"
LINEAGE = {   # the profile of each lineage document: (edition, kind)
    "prf/p1-org-folds-on-p2-release": ((P1, FIXTURE),),
    "prf/change-p1-to-p2-ok": ((P1, FIXTURE), (P2, FIXTURE)),
    "prf/change-p1-to-p2-quorum-unmet-under-p1": ((P1, FIXTURE), (P2, FIXTURE)),
    "prf/change-p1-to-p2-fork-path-under-p1": ((P1, FIXTURE), (P2, FIXTURE)),
    "prf/second-change-same-edition-ok": ((P1, FIXTURE), (P2, FIXTURE), (P2, FIXTURE)),
    "prf/downgrade-refused": ((P2, FIXTURE), (P1, FIXTURE)),
    "prf/downgrade-after-migration": ((P1, FIXTURE), (P2, FIXTURE), (P1, FIXTURE)),
    "prf/order-downgrade-before-class": ((P2, FIXTURE), (P1, FIXTURE)),
    "prf/order-fixture-before-downgrade": ((P2, FIXTURE), (P1, PRODUCTION)),
    "prf/mixed-kind-across-editions": ((P1, FIXTURE), (P2, PRODUCTION)),
    "prf/migration-reprofiled-document-valid": ((P1, FIXTURE), (P2, FIXTURE)),
    "prf/pin-spec-older-edition-not-last-doc": ((P1, FIXTURE), (P2, FIXTURE)),
    "prf/p2-successor-supersedes-p1-pin": ((P1, FIXTURE),),
    "prf/recheck-p1-epoch-act-after-repin-to-p2": ((P1, FIXTURE), (P2, FIXTURE)),
}
COMMAND = {"prf/migration-reprofiled-document-valid": "genesis-check",
           "prf/pin-spec-older-edition-not-last-doc": "check-act",
           "prf/p2-successor-supersedes-p1-pin": "check-act",
           "prf/recheck-p1-epoch-act-after-repin-to-p2": "recheck-act",
           "prf/render-change-across-editions": "render"}
FOLD_ERROR = {"prf/change-p1-to-p2-quorum-unmet-under-p1": "genesis_change_unauthorized",
              "prf/downgrade-refused": "profile_downgrade", "prf/downgrade-after-migration": "profile_downgrade",
              "prf/order-downgrade-before-class": "profile_downgrade",
              "prf/order-fixture-before-downgrade": "fixture_profile",
              "prf/mixed-kind-across-editions": "fixture_profile"}
FOLD_STATE = ("prf/p1-org-folds-on-p2-release", "prf/change-p1-to-p2-ok", "prf/change-p1-to-p2-fork-path-under-p1",
              "prf/second-change-same-edition-ok")


def profile_of(edition, kind):
    previous = edition == P1
    return (base.previous_profile(kind) if previous
            else base.fixture_profile() if kind == FIXTURE else base.production_profile())


def payload(jws):
    return json.loads(forge.parts(jws)[1])


class CrossEdition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(("prf",), ("prf",))

    def test_rows_are_the_fifteen_ids_the_generator_builds(self):
        self.assertEqual(len(self.v), 15)
        self.assertFalse([n for n in self.v if n.split("/", 1)[1].startswith("prodk-")])
        for name in self.v:
            self.assertIn(name, catalog.ROWS)

    def test_each_lineage_names_the_profiles_the_row_is_about(self):
        for name, profiles in LINEAGE.items():
            got = [e["doc"]["profile"] for e in self.v[name]["input"]["lineage"]]
            self.assertEqual(got, [profile_of(*p) for p in profiles], name)

    def test_the_two_editions_have_different_profile_hashes(self):
        for kind in (FIXTURE, PRODUCTION):
            self.assertNotEqual(profile_of(P1, kind), profile_of(P2, kind))

    def test_the_commands_are_the_ones_the_scenarios_name(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], COMMAND.get(name, "fold"), name)

    def test_a_refused_fold_is_the_code_of_its_scenario(self):
        for name, code in FOLD_ERROR.items():
            self.assertEqual(json.loads(self.v[name]["anchor"]), {"error": code}, name)

    def test_a_fold_that_gives_a_state_gives_the_state_of_its_last_document(self):
        for name in FOLD_STATE:
            doc = self.v[name]["input"]["lineage"][-1]["doc"]
            got = json.loads(self.v[name]["anchor"])
            self.assertEqual(got["spec"], doc["profile"], name)
            self.assertEqual(got["tip"]["genesis"], inputs.doc_id(doc), name)

    def test_every_change_is_signed_by_every_device_it_lists(self):   # no unwanted second defect (GP-15 step 6)
        for name in LINEAGE:
            if COMMAND.get(name) in ("check-act", "recheck-act") and name != "prf/recheck-p1-epoch-act-after-repin-to-p2":
                continue
            for entry in self.v[name]["input"]["lineage"][1:]:
                kids = {json.loads(base64.urlsafe_b64decode(s.split(".")[0] + "==")) ["kid"] for s in entry["sigs"]}
                if name == "prf/change-p1-to-p2-quorum-unmet-under-p1":
                    self.assertTrue(kids >= {d["kid"] for d in entry["doc"]["devices"]}, name)
                else:
                    self.assertEqual(kids, {d["kid"] for d in entry["doc"]["devices"]}, name)

    def test_the_quorum_unmet_row_carries_one_person_of_the_previous_document(self):
        lineage = self.v["prf/change-p1-to-p2-quorum-unmet-under-p1"]["input"]["lineage"]
        old = {m["id"] for m in lineage[0]["doc"]["members"]}
        carried = {m["id"] for m in lineage[1]["doc"]["members"]} & old
        self.assertEqual(len(carried), 1)

    def test_the_fork_row_has_two_children_of_one_position(self):
        v = self.v["prf/change-p1-to-p2-fork-path-under-p1"]
        parents = [payload(j)["parent_receipt_hash"] for j in v["input"]["acts"]
                   if payload(j)["method"] != "local:handsal.act.endorse"]
        self.assertTrue(any(parents.count(p) > 1 for p in parents if p))

    def test_the_class_row_lists_a_class_no_edition_knows(self):
        change = self.v["prf/order-downgrade-before-class"]["input"]["lineage"][1]["doc"]
        listed = {c["class"] for c in change["policy"]["classes"]}
        self.assertEqual(listed - {base.CLASS}, {"yubikey-piv"})

    def test_the_fixture_mixed_rows_are_ordered_by_kind_before_edition(self):
        self.assertEqual(json.loads(self.v["prf/order-fixture-before-downgrade"]["anchor"]), {"error": "fixture_profile"})
        self.assertNotEqual(json.loads(self.v["prf/order-fixture-before-downgrade"]["anchor"]), {"error": "profile_downgrade"})

    def test_the_migrated_document_equals_the_old_one_but_for_the_four_members(self):   # GP-24 S6, I2
        v = self.v["prf/migration-reprofiled-document-valid"]
        old, new = (e["doc"] for e in v["input"]["lineage"])
        differing = {k for k in set(old) | set(new) if old.get(k) != new.get(k)}
        self.assertEqual(differing, {"profile", "prev", "org", "head"})
        got = json.loads(v["anchor"])
        self.assertEqual((got["valid"], got["reason"]), (True, "ok"))
        pin = inputs.pin_line(inputs.doc_id(old), inputs.doc_id(new), new["profile"]).decode("ascii")
        self.assertEqual(got["pin"], pin)

    def test_the_pin_row_names_the_older_edition_and_the_last_document_the_newer_one(self):
        v = self.v["prf/pin-spec-older-edition-not-last-doc"]
        line = json.loads(base64.b64decode(v["input"]["pin"]["bytes_b64"]))
        self.assertEqual(line["spec"], profile_of(P1, FIXTURE))
        self.assertEqual(v["input"]["lineage"][-1]["doc"]["profile"], profile_of(P2, FIXTURE))
        self.assertEqual(json.loads(v["anchor"])["reason"], "pin_spec_mismatch")

    def test_the_successor_row_pins_the_older_edition_and_knows_a_successor(self):
        v = self.v["prf/p2-successor-supersedes-p1-pin"]
        line = json.loads(base64.b64decode(v["input"]["pin"]["bytes_b64"]))
        self.assertEqual(line["spec"], profile_of(P1, FIXTURE))
        self.assertEqual(v["input"]["next"], "yes")
        self.assertEqual(json.loads(v["anchor"])["reason"], "epoch_superseded")

    def test_the_recheck_row_is_an_act_of_the_first_epoch_under_a_pin_at_the_second(self):   # VR-17 S19
        v = self.v["prf/recheck-p1-epoch-act-after-repin-to-p2"]
        lineage = v["input"]["lineage"]
        head = payload(v["input"]["jws"])["ext"]["dev.handsal/act"]["head"]["id"]
        self.assertEqual(head, inputs.doc_id(lineage[0]["doc"]))
        line = json.loads(base64.b64decode(v["input"]["pin"]["bytes_b64"]))
        self.assertEqual((line["genesis"], line["spec"]), (inputs.doc_id(lineage[1]["doc"]), lineage[1]["doc"]["profile"]))
        got = json.loads(v["anchor"])
        self.assertEqual((got["reason"], got["rechecked"]), ("ok", True))

    def test_the_render_row_attaches_a_change_that_names_the_newer_edition_and_the_older_original(self):   # RN-09
        v = self.v["prf/render-change-across-editions"]
        attached = v["input"]["attachments"]
        self.assertEqual(attached["previous"]["profile"], profile_of(P1, FIXTURE))
        self.assertEqual(attached["document"]["profile"], profile_of(P2, FIXTURE))
        self.assertIn("Profile: " + profile_of(P2, FIXTURE), json.loads(v["anchor"])["text"])

    def test_the_catalog_rows_name_the_same_codes(self):
        for name, code in FOLD_ERROR.items():
            self.assertIn("`%s`" % code, catalog.ROWS[name]["expected"], name)


if __name__ == "__main__":
    unittest.main()
