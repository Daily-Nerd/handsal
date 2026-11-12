"""`fold` input (FO-01, GP-07, GP-14) and the command: the pin checks, then the lineage in GP-15 order
per document, then the result of the last epoch.

The render size check (GP-15 step 5) belongs to the render; tests that look past it may inject another
size step through the constructor.
"""
import base64
import io
import json
import unittest

from handsal_check import conformance, epoch, errors, foldcmd, genesis, org, pinfile, production, profiles, registry, verifier

from .act_builder import FakeVitni, Unavailable, genesis_sign, kid_of
from .genesis_fixtures import change, device, edit, org as make_org, policy

REG = registry.load()
PROFILES = profiles.load()
H = genesis.doc_hash(make_org(PROFILES.fixture, name="PREV"))


def probe_for(doc, org_id=None, **over):
    org_id = org_id or org.org_id(doc)
    line = pinfile.line(genesis.doc_hash(doc), org_id, doc["profile"])
    value = {"bytes_b64": base64.b64encode(line).decode(), "filename": org.pin_filename(org_id),
             "org": org_id, "owner_ok": True, "reason": "ok"}
    value.update(over)
    return value


def fold_input(docs, pin=None, **over):
    """Valid by default: the pin and the `org` input are those of the real original."""
    value = {"acts": [], "lineage": [{"doc": d, "sigs": []} for d in docs]}
    value["org"] = over["org"] if "org" in over else org.org_id(docs[0])
    value["pin"] = pin if pin is not None else probe_for(docs[-1], org.org_id(docs[0]))
    value.update(over)
    return value


def no_render(doc, previous):
    return None


def run(value, render=no_render, vitni=None):
    return foldcmd.run(foldcmd.parse_input(value), REG, PROFILES, True, vitni or FakeVitni(), render)


def signed(*docs):
    """Lineage entries with one `genesis.sign` per listed device (the fixture devices of the document)."""
    org_id = genesis.doc_hash(docs[0])
    names = {}
    from .genesis_fixtures import KEYS
    for key, value in KEYS.items():
        if key.endswith(".sign"):
            names[value["kid"]] = key[:-5]
    return [{"doc": d, "sigs": [genesis_sign(names[x["kid"]], d, org_id).jws for x in d["devices"]]} for d in docs]


def malformed(value, conformance_build=True):
    try:
        foldcmd.parse_input(value, conformance_build)
    except errors.Malformed:
        return True
    return False


ORIGINAL = make_org(PROFILES.fixture)


class Input(unittest.TestCase):
    def test_valid(self):
        self.assertFalse(malformed(fold_input([ORIGINAL])))
        self.assertFalse(malformed(fold_input([ORIGINAL], at="3")))

    def test_required_keys(self):
        for key in ("acts", "lineage", "org", "pin"):
            value = fold_input([ORIGINAL])
            del value[key]
            self.assertTrue(malformed(value), key)

    def test_types(self):
        for key, bad in (("acts", {}), ("lineage", {}), ("org", "nope"), ("org", None), ("pin", {}),
                         ("pin", "x"), ("at", "03"), ("at", 3), ("at", ""), ("at", None)):
            self.assertTrue(malformed(fold_input([ORIGINAL], **{key: bad})), (key, bad))

    def test_lineage_entries_are_doc_and_sigs(self):
        for entry in ({"doc": ORIGINAL}, {"sigs": []}, {"doc": ORIGINAL, "sigs": {}}, "x", None,
                      {"doc": ORIGINAL, "sigs": [], "extra": 1}):
            self.assertTrue(malformed(fold_input([ORIGINAL], lineage=[entry])), entry)

    def test_an_empty_lineage_is_not_malformed_it_is_lineage_broken(self):
        self.assertFalse(malformed(fold_input([ORIGINAL], lineage=[])))
        self.assertEqual(run(fold_input([ORIGINAL], lineage=[])), {"error": "lineage_broken"})

    def test_the_production_build_takes_no_pin(self):
        self.assertTrue(malformed(fold_input([ORIGINAL]), conformance_build=False))
        value = fold_input([ORIGINAL])
        del value["pin"]
        self.assertIsNone(foldcmd.parse_input(value, conformance_build=False).pin)

    def test_a_document_may_be_anything_here(self):
        # a malformed document is a fold result (`genesis_schema`), not a malformed input
        self.assertFalse(malformed(fold_input([ORIGINAL], lineage=[{"doc": 5, "sigs": []}])))


class Steps(unittest.TestCase):
    def test_pin_checks_come_first(self):
        other = org.org_id(make_org(PROFILES.fixture, name="OTHER"))
        bad_doc = edit(ORIGINAL, ["extra"], "x")
        value = fold_input([bad_doc], pin=probe_for(bad_doc, org.org_id(ORIGINAL)), org=other)
        self.assertEqual(run(value), {"error": "pin_org_mismatch"})

    def test_probe_reasons(self):
        value = fold_input([ORIGINAL], pin=probe_for(ORIGINAL, bytes_b64="", owner_ok=False, reason="pin_missing"))
        self.assertEqual(run(value), {"error": "pin_missing"})

    def test_pin_genesis_must_be_the_last_document(self):
        change_doc = change(PROFILES.fixture, org.org_id(ORIGINAL), genesis.doc_hash(ORIGINAL), H)
        value = fold_input([ORIGINAL, change_doc], pin=probe_for(ORIGINAL, org.org_id(ORIGINAL)))
        self.assertEqual(run(value), {"error": "genesis_pin_mismatch"})

    def test_a_document_that_cannot_be_hashed_cannot_match_the_pin(self):
        bad = edit(ORIGINAL, ["name"], 5)
        change_doc = change(PROFILES.fixture, org.org_id(ORIGINAL), genesis.doc_hash(ORIGINAL), H)
        last_bad = edit(change_doc, ["name"], 5)
        value = fold_input([ORIGINAL, last_bad], pin=probe_for(ORIGINAL, org.org_id(ORIGINAL)))
        self.assertEqual(run(value), {"error": "genesis_pin_mismatch"})   # as the last document (GP-07)
        value = fold_input([bad, change_doc], org=org.org_id(ORIGINAL), pin=probe_for(ORIGINAL))
        self.assertEqual(run(value), {"error": "lineage_broken"})   # as the first document (GP-07)

    def test_the_pins_org_must_be_the_first_document(self):
        other = make_org(PROFILES.fixture, name="OTHER")
        other_org = org.org_id(other)
        # the input org and the pin agree, the lineage starts at another document (GP-07)
        value = fold_input([other, ORIGINAL], org=org.org_id(ORIGINAL), pin=probe_for(ORIGINAL))
        self.assertEqual(run(value), {"error": "lineage_broken"})
        self.assertNotEqual(other_org, org.org_id(ORIGINAL))

    def test_a_document_failing_by_itself(self):
        cases = ((edit(ORIGINAL, ["extra"], "x"), "genesis_schema"),
                 (make_org(PROFILES.fixture, pol=policy("3")), "policy_unreachable"),
                 (make_org(PROFILES.fixture, pol=edit(policy(), ["freshness"], delete=True)), "policy_invalid"))
        for doc, code in cases:
            self.assertEqual(run(fold_input([doc])), {"error": code})

    def test_the_first_failing_document_wins(self):
        good = ORIGINAL
        chg = change(PROFILES.fixture, org.org_id(good), genesis.doc_hash(good), H, pol=policy("3"))
        value = fold_input([good, chg])
        value["lineage"] = signed(good)[:1] + [{"doc": chg, "sigs": []}]
        self.assertEqual(run(value), {"error": "policy_unreachable"})
        # an unsigned original fails first, whatever the later document looks like (GP-15)
        value["lineage"][0]["sigs"] = []
        self.assertEqual(run(value), {"error": "genesis_unsigned"})

    def test_a_lineage_mixing_the_two_profiles(self):
        change_doc = change(PROFILES.production, org.org_id(ORIGINAL), genesis.doc_hash(ORIGINAL), H)
        value = fold_input([ORIGINAL, change_doc])
        value["lineage"] = signed(ORIGINAL) + [{"doc": change_doc, "sigs": []}]
        self.assertEqual(run(value), {"error": "fixture_profile"})

    def test_the_default_render_size_step_is_the_genesis_render(self):
        got = foldcmd.run(foldcmd.parse_input(fold_input([ORIGINAL])), REG, PROFILES, True, FakeVitni())
        self.assertEqual(got, {"error": "genesis_unsigned"})   # past the size step, the possession step speaks
        big = make_org(PROFILES.fixture, people=("alice", "bob", "carol", "dave", "grace"),
                       devices=[device(n) for n in ("alice", "alice2", "alice3", "alice4", "bob", "bob2", "bob3",
                                                    "carol", "carol2", "dave", "dave2", "grace")])
        got = foldcmd.run(foldcmd.parse_input(fold_input([big])), REG, PROFILES, True, FakeVitni())
        self.assertEqual(got, {"error": "genesis_render_too_large"})

    def test_the_production_build_refuses_a_fixture_lineage(self):
        inp = foldcmd.parse_input(fold_input([ORIGINAL]))
        self.assertEqual(foldcmd.run(inp, REG, PROFILES, False, FakeVitni()), {"error": "fixture_profile"})


def good_input(**over):
    value = fold_input([ORIGINAL])
    value["lineage"] = signed(ORIGINAL)
    value.update(over)
    return value


class Result(unittest.TestCase):
    """What a lineage that passes every step folds to."""

    def test_a_signed_original_is_its_own_state(self):
        out = run(good_input())
        self.assertEqual(out["tip"], {"genesis": org.org_id(ORIGINAL), "id": org.org_id(ORIGINAL), "n": "0"})
        self.assertEqual(out["org"], org.org_id(ORIGINAL))
        self.assertIn(kid_of("alice"), out["keys"]["alice"])

    def test_at_is_read(self):
        self.assertEqual(run(good_input(at="1")), {"error": "at_beyond_tip"})
        self.assertEqual(run(good_input(at="0"))["tip"]["n"], "0")

    def test_a_verifier_that_cannot_answer_is_the_error_verifier_unavailable(self):
        self.assertEqual(run(good_input(), vitni=Unavailable()), {"error": "verifier_unavailable"})

    def test_a_fork_is_an_error_without_keys(self):
        from .fold_world import World
        w = World()
        c1 = w.device_add("alice2", ("alice", "bob"))
        c2 = w.device_add("alice3", ("alice", "carol"))
        value = fold_input([w.doc], acts=c1.acts + c2.acts)
        value["lineage"] = signed(w.doc)
        out = run(value)
        self.assertEqual(out["error"], "fork")
        self.assertNotIn("keys", out)

    def test_acts_and_signatures_must_be_texts(self):
        for bad in (3, None, {}, ["x"]):
            self.assertTrue(malformed(fold_input([ORIGINAL], acts=[bad])))
            self.assertTrue(malformed(fold_input([ORIGINAL], lineage=[{"doc": ORIGINAL, "sigs": [bad]}])))
        self.assertFalse(malformed(fold_input([ORIGINAL], acts=["junk"])))


def command(main, value):
    out = io.BytesIO()
    code = main(["fold"], io.BytesIO(json.dumps(value).encode()), out)
    return code, out.getvalue()


class Command(unittest.TestCase):
    def test_conformance_build(self):
        self.assertEqual(command(conformance.main, fold_input([make_org(PROFILES.fixture, pol=policy("3"))])),
                         (0, b'{"error":"policy_unreachable"}\n'))

    def test_missing_input_is_malformed(self):
        value = fold_input([ORIGINAL])
        del value["org"]
        self.assertEqual(command(conformance.main, value), (0, b'{"error":"malformed_input"}\n'))

    def test_production_build_offers_it_and_refuses_a_pin_input(self):
        self.assertEqual(command(production.main, fold_input([ORIGINAL])), (0, b'{"error":"malformed_input"}\n'))


if __name__ == "__main__":
    unittest.main()
