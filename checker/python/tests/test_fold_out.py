"""T3.35 fold outputs: `keys`, `devices`, `tip`, the `at` view, accepted vs unproven (FO-01, FO-02, FO-03, FO-16, KC-04).

`keys` is the one projection of `devices` to the vitni keys map: exactly the accepted devices, `active`
or `revoked`. A fork or any error carries no `keys`. The result is a function of the bag, so array
order changes nothing.
"""
import json
import random
import unittest

from handsal_check import emit, epoch, fold_out, genesis

from .act_builder import FakeVitni, kid_of
from .fold_world import PROFILES, World
from .genesis_fixtures import KEYS, device, point

ALL = ("alice", "bob", "carol")


NAMES = {v["kid"]: k[:-5] for k, v in KEYS.items() if k.endswith(".sign")}


def signed_lineage(w):
    return [{"doc": w.doc, "sigs": w.sigs(w.doc, [NAMES[d["kid"]] for d in w.doc["devices"]])}]


def folded(w, *steps, at=None, vitni=None):
    lineage = signed_lineage(w)
    texts = [t for s in steps for t in s.acts]
    epochs = epoch.fold_lineage(lineage, texts, PROFILES, True, vitni or FakeVitni(), lambda d, p: None)
    return fold_out.result(epochs, at)


class Shape(unittest.TestCase):
    def test_keys_of_the_output(self):
        w = World()
        out = folded(w)
        self.assertEqual(set(out), {"devices", "keys", "org", "org_name", "policy", "spec", "tip"})
        self.assertEqual(out["org"], w.id)
        self.assertEqual(out["org_name"], "ORG")
        self.assertEqual(out["policy"], w.doc["policy"])
        self.assertEqual(out["spec"], w.doc["profile"])
        self.assertEqual(out["tip"], {"genesis": w.id, "id": w.id, "n": "0"})

    def test_devices_shape(self):
        w = World()
        out = folded(w)
        entry = out["devices"]["alice"][kid_of("alice")]
        self.assertEqual(set(entry), {"accepted", "agree", "class", "label", "sign", "status"})
        self.assertEqual(entry["accepted"], True)
        self.assertEqual(entry["status"], "active")
        self.assertEqual(entry["sign"], point("alice.sign"))
        self.assertEqual(entry["agree"], point("alice.agree"))

    def test_keys_shape_is_the_vitni_one_and_has_no_agree_key(self):
        w = World()
        key = folded(w)["keys"]["alice"][kid_of("alice")]
        self.assertEqual(key, {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active",
                               "x": point("alice.sign")["x"], "y": point("alice.sign")["y"]})

    def test_the_tip_is_the_last_accepted_node(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        b = w.device_add("bob2", ("bob", "alice"), a)
        out = folded(w, a, b)
        self.assertEqual(out["tip"], {"genesis": w.id, "id": b.id, "n": "2"})
        self.assertIn(kid_of("bob2"), out["devices"]["bob"])

    def test_output_bytes_do_not_depend_on_array_order(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        b = w.device_add("bob2", ("bob", "alice"), a)
        texts = a.acts + b.acts
        seen = set()
        for seed in range(5):
            random.Random(seed).shuffle(texts)
            epochs = epoch.fold_lineage(signed_lineage(w), texts, PROFILES, True, FakeVitni(), lambda d, p: None)
            seen.add(emit.emit_result(fold_out.result(epochs, None)))
        self.assertEqual(len(seen), 1)


class Keys(unittest.TestCase):
    def dave_world(self):
        w = World(extra=("dave",), members=(("dave", "member"),))
        return w, w.device_add("dave2", ("dave", "alice", "bob"), cls="fixture-pin")

    def test_a_removed_device_is_revoked_in_keys_and_removed_in_devices(self):
        w = World()
        r = w.device_remove("carol", ("alice", "bob"))
        out = folded(w, r)
        self.assertEqual(out["keys"]["carol"][kid_of("carol")]["status"], "revoked")
        self.assertEqual(out["devices"]["carol"][kid_of("carol")]["status"], "removed")

    def test_a_device_whose_class_is_not_accepted_is_in_devices_only(self):
        w, step = self.dave_world()
        out = folded(w, step)
        self.assertFalse(out["devices"]["dave"][kid_of("dave2")]["accepted"])
        self.assertNotIn(kid_of("dave2"), out["keys"]["dave"])
        self.assertIn(kid_of("dave"), out["keys"]["dave"])

    def test_keys_is_a_projection_of_devices(self):
        w, step = self.dave_world()
        out = folded(w, step)
        projected = {p: {k: v for k, v in kids.items() if v["accepted"]} for p, kids in out["devices"].items()}
        self.assertEqual({p: sorted(k) for p, k in projected.items() if k},
                         {p: sorted(k) for p, k in out["keys"].items()})

    def test_a_person_with_no_accepted_device_has_no_entry(self):
        w = World()
        step = w.member_add("frank-pin", ("alice", "bob"), member="frank", role="member", cls="fixture-pin")
        out = folded(w, step)
        self.assertNotIn("frank", out["keys"])
        self.assertIn("frank", out["devices"])


class Errors(unittest.TestCase):
    def fork(self):
        w = World()
        c1 = w.device_add("alice2", ("alice", "bob"))
        c2 = w.device_add("alice3", ("alice", "carol"))
        return w, c1, c2

    def test_a_fork_is_an_error_without_keys(self):
        w, c1, c2 = self.fork()
        out = folded(w, c1, c2)
        self.assertEqual(out, {"error": "fork", "fork": {"candidates": sorted([c1.id, c2.id]), "parent": w.id}})

    def test_at_beyond_the_tip(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        self.assertEqual(folded(w, a, at="2"), {"error": "at_beyond_tip"})
        self.assertEqual(folded(w, a, at="1")["tip"]["n"], "1")

    def test_at_selects_a_prefix_state(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        b = w.device_add("bob2", ("bob", "alice"), a)
        out = folded(w, a, b, at="1")
        self.assertEqual(out["tip"], {"genesis": w.id, "id": a.id, "n": "1"})
        self.assertNotIn(kid_of("bob2"), out["devices"]["bob"])
        self.assertEqual(folded(w, a, b, at="0")["tip"]["id"], w.id)

    def test_at_the_fork_parent_is_the_state_there_and_beyond_is_a_fork(self):
        w = World()
        a = w.device_add("bob2", ("bob", "alice"))
        c1 = w.device_add("alice2", ("alice", "bob"), a)
        c2 = w.device_add("alice3", ("alice", "carol"), a)
        self.assertEqual(folded(w, a, c1, c2, at="1")["tip"]["id"], a.id)
        self.assertEqual(folded(w, a, c1, c2, at="2")["error"], "fork")
        self.assertEqual(folded(w, a, c1, c2, at="9")["error"], "fork")

    def test_the_fork_error_wins_over_no_at(self):
        w, c1, c2 = self.fork()
        self.assertEqual(folded(w, c1, c2)["error"], "fork")
        self.assertEqual(folded(w, c1, c2, at="0")["tip"]["n"], "0")


class ClassOf(unittest.TestCase):
    def test_the_class_of_a_header_kid_in_the_tip_state(self):
        w = World(extra=("dave",), members=(("dave", "member"),))
        step = w.device_add("dave2", ("dave", "alice", "bob"), cls="fixture-pin")
        epochs = epoch.fold_lineage(signed_lineage(w), step.acts, PROFILES, True, FakeVitni(), lambda d, p: None)
        view = fold_out.view(epochs, None)
        self.assertEqual(fold_out.class_of(view.node.state, kid_of("alice")), "apple-se-bio")
        self.assertEqual(fold_out.class_of(view.node.state, kid_of("dave2")), "fixture-pin")
        self.assertIsNone(fold_out.class_of(view.node.state, kid_of("carol2")))


if __name__ == "__main__":
    unittest.main()
