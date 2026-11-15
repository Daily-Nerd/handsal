"""T15.3 vectors hed/*: the head a signer names (VR-19, CF-03, CF-04, CF-07, VR-12) and the whole-set guard of SH6.

`head` answers which position a producer names as `head` (ACT-08). VR-19 states the equality with `check-act`: the
answered head is exactly one that `check-act` of an otherwise perfect non-chain act naming it accepts at steps 6 and
14, and a refusal is the code `check-act` gives at one of those steps. The generator holds its own second statement
of those two steps (`lib/checkact_model.py`, written from the spec over `lib/foldmodel.py`, no checker code), and the
guard below asks it about every vector of the group: it signs a fixture decision at the answered head (at the root of
the pinned organization where the answer is a refusal) and the model must agree on `ok` or on the code.
"""
import json
import tempfile
import unittest
from pathlib import Path

import generate
from lib import base, checkact_model, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
NOW = base.NOW
IDS = sorted(i for i in generate.shipping_ids() if i.startswith("hed/"))
PRIMARY = ("local:handsal.device.add", "local:handsal.device.remove", "local:handsal.member.add")
RESOLVE = "local:handsal.chain.resolve"

ROWS = ("hed/ok-tip", "hed/ok-root", "hed/ok-after-resolve", "hed/ok-two-epochs", "hed/fork",
        "hed/epoch-superseded", "hed/superseded-before-fork", "hed/superseded-before-stale-view",
        "hed/stale-view", "hed/view-in-future", "hed/age-exactly-max-ok", "hed/relay-witness-missing",
        "hed/relay-ok", "hed/mode-none-statement-supplied", "hed/pin-missing", "hed/pin-org-mismatch",
        "hed/lineage-broken", "hed/next-input-missing", "hed/org-input-missing")


def payload(jws):
    return json.loads(forge.parts(jws)[1])


def primaries(acts):
    """The chain primaries of a bag, as (receipt id, parent receipt hash)."""
    return [(inputs.receipt_id(a), payload(a)["parent_receipt_hash"]) for a in acts
            if payload(a)["method"] in PRIMARY]


class Hed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(["hed", "enr"], ["hed", "enr"])

    def head(self, name):
        return json.loads(self.v[name]["anchor"])["head"]

    def inp(self, name):
        return self.v[name]["input"]

    # ---- the id set and the shape of every row

    def test_the_group_ids_are_the_nineteen_of_vector_ids_json(self):
        self.assertEqual(len(IDS), 19)
        self.assertEqual(sorted(IDS), sorted(ROWS))
        self.assertEqual(sorted(n for n in self.v if n.startswith("hed/")), sorted(IDS))

    def test_every_row_is_a_head_command_with_the_catalog_code(self):
        for name in IDS:
            v = self.v[name]
            self.assertEqual(v["command"], "head", name)
            out = json.loads(v["anchor"])
            want = catalog.catalog_code(name)
            self.assertEqual(out.get("error", out.get("reason")), want, name)
            if "error" in out:
                self.assertEqual(v["anchor"], '{"error":"malformed_input"}', name)
            elif want == "ok":
                self.assertEqual(set(out), {"head", "reason"}, name)
                self.assertEqual(set(out["head"]), {"id", "kind"}, name)
                self.assertEqual(out["head"]["kind"], "chain", name)
                self.assertTrue(base.is_hashstr(out["head"]["id"]), name)
            else:
                self.assertEqual(v["anchor"], '{"head":null,"reason":"%s"}' % want, name)

    def test_every_input_is_the_conformance_head_input_unless_a_key_is_missing(self):
        keys = {"acts", "lineage", "next", "now", "org", "pin", "synced_at", "tip_statement"}
        for name in IDS:
            got = set(self.inp(name))
            if name == "hed/next-input-missing":
                self.assertEqual(got, keys - {"next"})
            elif name == "hed/org-input-missing":
                self.assertEqual(got, keys - {"org"})
            else:
                self.assertEqual(got, keys, name)   # no `device_kid`: `head` proves nothing about a person

    # ---- the whole-set guard (SH6), the test the spec cites

    def test_every_hed_vector_agrees_with_the_check_act_model(self):
        listed = json.loads((Path(generate.CONFORMANCE) / "vector-ids.json").read_text(encoding="utf-8"))["ids"]
        self.assertEqual(sorted(n for n in self.v if n.startswith("hed/")),
                         sorted(i for i in listed if i.startswith("hed/")))   # the id set of the group, both ways
        for name in IDS:
            with self.subTest(name):
                checkact_model.agree(FX, self.inp(name), self.v[name]["anchor"])

    def test_the_guard_has_teeth(self):
        ok = self.v["hed/ok-tip"]
        out = json.loads(ok["anchor"])

        def refuses(anchor, name="hed/ok-tip"):
            self.assertRaises(checkact_model.Disagreement, checkact_model.agree, FX, self.inp(name), anchor)
        checkact_model.agree(FX, ok["input"], ok["anchor"])
        # a head that is no position of the chain: check-act answers stale_view
        junk = '{"head":{"id":"%s","kind":"chain"},"reason":"ok"}' % base.hashstr(b"no such position")
        refuses(junk)
        # an older position is one check-act accepts, but it is not the tip the fold gives
        older = primaries(self.inp("hed/ok-tip")["acts"])[1][0]
        refuses('{"head":{"id":"%s","kind":"chain"},"reason":"ok"}' % older)
        self.assertNotEqual(older, out["head"]["id"])
        # a refusal under another code than the model's
        refuses('{"head":null,"reason":"stale_view"}', "hed/fork")
        # an ok answer where the model refuses (a stale view)
        refuses(ok["anchor"], "hed/stale-view")
        # a refusal where the model accepts, and an error where the input is whole
        refuses('{"head":null,"reason":"fork"}')
        refuses('{"error":"malformed_input"}')

    # ---- the ok rows

    def test_the_tip_of_a_chain_of_three_is_the_head(self):
        acts = primaries(self.inp("hed/ok-tip")["acts"])
        self.assertEqual(len(acts), 3)
        self.assertEqual(acts[0][1], FX.org_id)                      # the first hangs at the root
        self.assertEqual([a[1] for a in acts[1:]], [a[0] for a in acts[:2]])
        self.assertEqual(self.head("hed/ok-tip")["id"], acts[2][0])

    def test_no_primary_means_the_document_hash(self):
        v = self.inp("hed/ok-root")
        self.assertEqual(v["acts"], [])
        self.assertEqual(self.head("hed/ok-root")["id"], FX.org_id)
        self.assertEqual(self.head("hed/ok-root")["id"], inputs.doc_id(v["lineage"][0]["doc"]))

    def test_a_lifted_fork_names_the_tip_of_the_chosen_branch(self):
        acts = self.inp("hed/ok-after-resolve")["acts"]
        kids = [a for a in primaries(acts) if a[1] == FX.org_id]
        self.assertEqual(len(kids), 2)                               # the bag of ord/fork-before-vitni
        resolves = [payload(a) for a in acts if payload(a)["method"] == RESOLVE]
        self.assertEqual(len(resolves), 1)
        chosen = resolves[0]["ext"]["dev.handsal/act"]["body"]["choose"]
        self.assertIn(chosen, [k[0] for k in kids])
        self.assertEqual(self.head("hed/ok-after-resolve")["id"], chosen)
        self.assertEqual(self.inp("hed/ok-after-resolve")["next"], "no")

    def test_two_epochs_the_head_is_in_the_last_and_never_on_the_path_of_the_first(self):
        v = self.inp("hed/ok-two-epochs")
        lineage = v["lineage"]
        self.assertEqual(len(lineage), 2)
        self.assertEqual(v["org"], inputs.doc_id(lineage[0]["doc"]))
        self.assertEqual(v["pin"], inputs.probe_for(lineage))        # pinned at the change
        change = inputs.doc_id(lineage[1]["doc"])
        by_parent = {}
        for rid, parent in primaries(v["acts"]):
            by_parent.setdefault(parent, []).append(rid)
        self.assertEqual(len(by_parent[v["org"]]), 1)                # a primary in epoch 0, at the original root
        self.assertEqual(len(by_parent[change]), 1)                  # and one in epoch 1, at the change document
        self.assertEqual(self.head("hed/ok-two-epochs")["id"], by_parent[change][0])
        self.assertNotEqual(self.head("hed/ok-two-epochs")["id"], by_parent[v["org"]][0])

    # ---- the refusals of the fold and of the view

    def test_fork_rows_hold_the_bag_of_enr_fork_and_next_decides_the_code(self):
        bag = self.v["enr/fork"]["input"]["acts"]
        self.assertEqual(self.inp("hed/fork")["acts"], bag)
        self.assertEqual(self.inp("hed/superseded-before-fork")["acts"], bag)
        self.assertEqual((self.inp("hed/fork")["next"], self.inp("hed/superseded-before-fork")["next"]),
                         ("no", "yes"))

    def test_the_view_rows_differ_from_the_ok_row_by_the_one_fact_the_row_names(self):
        base_row = dict(self.inp("hed/ok-tip"))

        def only(name, **change):
            want = dict(base_row, **change)
            self.assertEqual(self.inp(name), want, name)
        only("hed/age-exactly-max-ok", synced_at=base.shift(NOW, -86400))
        only("hed/stale-view", synced_at=base.shift(NOW, -86401))
        only("hed/view-in-future", synced_at=base.shift(NOW, 301))
        only("hed/epoch-superseded", next="yes")
        only("hed/superseded-before-stale-view", next="yes", synced_at=base.shift(NOW, -86401))
        self.assertEqual(self.head("hed/age-exactly-max-ok")["id"], self.head("hed/ok-tip")["id"])

    # ---- the witness rows

    def test_relay_rows_run_under_the_witness_organization(self):
        for name, ok in (("hed/relay-witness-missing", False), ("hed/relay-ok", True)):
            v = self.inp(name)
            self.assertEqual(v["org"], FX.wit_org_id, name)
            self.assertEqual(v["pin"], FX.pin_ok(True), name)
            self.assertEqual(v["tip_statement"] is not None, ok, name)
        self.assertEqual(len(primaries(self.inp("hed/relay-ok")["acts"])), 3)
        body = payload(self.inp("hed/relay-ok")["tip_statement"])["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["tip"], self.head("hed/relay-ok")["id"])     # TIP_OK for its tip
        self.assertEqual((body["next"], body["epoch"]), ("no", FX.wit_org_id))

    def test_mode_none_with_a_statement_supplied(self):
        v = self.inp("hed/mode-none-statement-supplied")
        self.assertEqual(v["org"], FX.org_id)
        self.assertIsNotNone(v["tip_statement"])
        plain = dict(self.inp("hed/ok-tip"), tip_statement=v["tip_statement"])
        self.assertEqual(v, plain)

    # ---- the pin rows and the missing keys

    def test_the_pin_rows_change_one_thing_of_the_ok_input(self):
        ok = self.inp("hed/ok-tip")
        missing = self.inp("hed/pin-missing")["pin"]
        self.assertEqual((missing["owner_ok"], missing["reason"]), (False, "pin_missing"))
        other = self.inp("hed/pin-org-mismatch")["pin"]
        self.assertNotEqual(other["org"], ok["org"])
        self.assertEqual(self.inp("hed/lineage-broken")["lineage"], [])
        for name, key in (("hed/pin-missing", "pin"), ("hed/pin-org-mismatch", "pin"),
                          ("hed/lineage-broken", "lineage")):
            self.assertEqual({k: x for k, x in self.inp(name).items() if k != key},
                             {k: x for k, x in ok.items() if k != key}, name)

    def test_a_missing_key_is_the_ok_input_without_it(self):
        ok = self.inp("hed/ok-tip")
        for name, key in (("hed/next-input-missing", "next"), ("hed/org-input-missing", "org")):
            self.assertEqual(self.inp(name), {k: x for k, x in ok.items() if k != key}, name)


class ModelAgreesWithShippedRows(unittest.TestCase):
    """The model is a second statement of steps 6 and 14; the shipped `check-act` rows were authored by the group
    owners, so the two check each other. Only rows whose expected code the model states are compared: a row that
    fails at another step says nothing about steps 6 and 14."""
    GROUPS = ("ord", "frs", "wit", "chk", "org", "pin", "enr")

    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(cls.GROUPS, cls.GROUPS)

    def test_the_model_gives_the_code_of_every_shipped_check_act_row_it_states(self):
        compared = []
        for name, v in sorted(self.v.items()):
            if v["command"] != "check-act" or not isinstance(v.get("input"), dict):
                continue
            want = json.loads(v["anchor"]).get("reason")
            if want not in checkact_model.CODES:
                continue
            compared.append(name)
            with self.subTest(name):
                self.assertEqual(checkact_model.run(FX, v["input"], v["input"]["jws"]), want)
        self.assertGreater(len(compared), 40)


class OneRegistryEntry(unittest.TestCase):
    """The group leaves no trace in the others, and the others leave none in it."""

    def test_hed_changes_no_other_vector_and_is_the_same_alone_or_after_the_rest(self):
        import importlib
        mods = {n: importlib.import_module("groups." + n) for n in ("ord", "enr", "wit", "hed")}
        ids = generate.shipping_ids()

        def run(names):
            with tempfile.TemporaryDirectory() as d:
                generate.run(d, registry=[mods[n] for n in names], known_ids=ids)
                return {p.name: p.read_bytes() for p in Path(d).glob("*.json")}
        first = run(["hed", "ord", "enr", "wit"])
        rest = run(["ord", "enr", "wit"])
        alone = run(["hed"])
        after = run(["ord", "enr", "wit", "hed"])
        self.assertEqual({k: x for k, x in first.items() if not k.startswith("hed.")}, rest)
        self.assertEqual({k: x for k, x in first.items() if k.startswith("hed.")}, alone)
        self.assertEqual(after, first)
        self.assertEqual(len(alone), 19)


if __name__ == "__main__":
    unittest.main()
