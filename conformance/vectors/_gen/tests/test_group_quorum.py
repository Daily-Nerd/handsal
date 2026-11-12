"""T3.23 vectors add/*, mem/*, rem/*, quo/*, cas/* (FO-07, FO-09, FO-13, FO-22, FO-23, FO-27).

Per row the test states, from the spec: the devices that end up in the state, the devices
removed, and which chain primaries of the bag are on the chain (by their order of appearance
among the primaries). The expected output is built with lib/state.py from that statement.

Not written, with the reason: add/kid-removed-in-earlier-epoch, mem/id-reused-across-epochs and
quo/two-lost-persons-unreachable (the change half only; they need a genesis change, see the chg groups);
rem/second-person-quorum-unmet, quo/policy-swap-2-vs-3 and quo/raised-floor-3-two-rejected
are written by groups/quorum4.py on the four-maintainer ORG4 (tests/test_group_quorum4.py).
"""
import json
import unittest

from lib import base, forge, state
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
PIN = "fixture-pin"
DAVE = ("dave", ("dave2", PIN))
CHAIN_METHODS = ("local:handsal.device.add", "local:handsal.device.remove",
                 "local:handsal.member.add")

# row -> (devices added, devices removed, applied primaries by order in the bag)
ROWS = {
    "add/ok": (("alice2",), (), (0,)),
    "add/ok-quorum-path": (("alice2",), (), (0,)),
    "add/ok-two-devices-same-person": (("alice2",), (), (0,)),
    "add/agree-reused": ((), (), ()),
    "add/cross-person": ((), (), ()),
    "add/kid-reused-active": ((), (), ()),
    "add/kid-reused-removed": ((), ("carol",), (0,)),
    "add/no-pop": ((), (), ()),
    "add/pop-by-other-key": ((), (), ()),
    "add/pop-performer-mismatch": ((), (), ()),
    "add/pop-not-counted": ((), (), ()),
    "add/same-device-twice": (("alice2",), (), (0,)),
    "add/signer-revoked": ((), ("bob",), (0,)),
    "add/signer-unaccepted-class": (DAVE, (), (0, 1)),
    "add/single-signer-not-on-chain": ((), (), ()),
    "add/stolen-key-alone-cannot-add": (("alice2",), (), (0,)),
    "add/two-devices-one-person-other-person-target": (("alice2",), (), (0,)),
    "mem/ok-2-of-3": (("dave",), (), (0,)),
    "mem/roles-from-quorum": (("dave",), ("carol",), (0, 1)),
    "mem/endorser-no-role": (("dave",), (), (0,)),
    "mem/id-reused": ((), (), ()),
    "mem/no-pop": ((), (), ()),
    "mem/one-of-3": ((), (), ()),
    "mem/two-devices-one-person": (("alice2",), (), (0,)),
    "rem/cross-person-single-sig": ((), (), ()),
    "rem/endorser-is-signer": ((), (), ()),
    "rem/fresh-key-with-senior-ok": (("alice2", "alice3", "X1"), (), (0, 1, 2)),
    "rem/fresh-keys-cannot-remove-older": (("alice2", "X1", "X2"), (), (0, 1, 2)),
    "rem/fresh-keys-quorum-path-ok": (("X1",), ("alice",), (0, 1)),
    "rem/remove-already-removed": ((), ("carol",), (0,)),
    "rem/remove-last-device": ((), ("carol",), (0,)),
    "rem/remove-unknown-kid": ((), (), ()),
    "rem/second-person-quorum-ok": ((), ("carol",), (0,)),
    "rem/self-removal-ok": (("alice2",), (), (0,)),
    "rem/self-removal-wrong-person": (("alice2",), (), (0,)),
    "rem/target-is-endorser": (("bob2",), ("bob2",), (0, 1)),
    "rem/thief-phone-alone": (("alice2",), (), (0,)),
    "rem/two-devices-one-person-other-target": (("alice2",), (), (0,)),
    "rem/two-devices-same-person-ok": (("alice2", "alice3"), (), (0, 1)),
    "quo/device-add-consent-from-removed-key-invalid": (("alice2",), ("alice",), (0, 1)),
    "quo/device-add-needs-own-key": ((), (), ()),
    "quo/device-add-own-key-as-endorser-ok": (("X1",), (), (0,)),
    "quo/devices-not-votes": (("alice2", "alice3"), (), (0, 1)),
    "quo/endorser-no-role-not-counted": (("dave",), (), (0,)),
    "quo/last-device-readded-by-others": (("carol2", "alice2"), ("carol",), (0, 1, 2)),
    "quo/last-device-removed-no-vote": ((), ("carol",), (0,)),
    "quo/one-left-unreachable": ((), ("carol", "bob"), (0, 1)),
    "quo/primary-unaccepted-key-invalid": (DAVE, (), (0, 1)),
    "quo/primary-without-role-ok": (("dave", "dave2"), (), (0, 1)),
    "quo/remove-then-add-replaces-keys": (("X1",), ("alice",), (0, 1)),
    "quo/role-not-in-from": (("dave",), (), (0,)),
    "quo/self-removal-needs-second-person": (("alice2",), ("alice2",), (0, 1)),
    "quo/single-person-act-rejected": (("alice2", "alice3"), (), (0, 1)),
    "quo/single-person-member-add-rejected": (("alice2",), (), (0,)),
    "quo/surplus-endorsement-same-output": (("X1",), (), (0,)),
    "quo/surplus-no-role-ignored": (("dave", "X1"), (), (0, 1)),
    "quo/surplus-removed-later-no-effect": (("bob2", "X1"), ("bob2",), (0, 1, 2)),
    "quo/two-left-reachable": (("dave",), ("carol",), (0, 1)),
    "quo/two-persons-device-add-ok": (("X1",), (), (0,)),
    "cas/removed-never-returns": (("alice2",), ("alice2",), (0, 1)),
}
FLAT = [("dave", None)]  # dave2 of the pin rows is spelled (name, class) in the table


def _ordinals(acts):
    ids = []
    for jws in acts:
        p = json.loads(forge.parts(jws)[1])
        if p["method"] in CHAIN_METHODS and p["method"] != "local:handsal.act.endorse":
            ids.append(base.hashstr(forge.parts(jws)[1]))
    return ids


def _expected(acts, added, removed, applied):
    s = state.State(FX.org)
    for item in added:
        name, cls = item if isinstance(item, tuple) else (item, None)
        e = FX.device_entry(name)
        e["class"] = cls or e["class"]
        s.add_device(e["person"], e)
    for name in removed:
        s.remove_device(FX.key(name).kid)
    s.n = len(applied)
    if applied:
        s.tip_id = _ordinals(acts)[applied[-1]]
    return state.anchor(s)


class Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = {}
        for group in ("add", "mem", "rem", "quo", "cas"):
            cls.v.update(catalog.generate_group(group, [group]))

    def test_rows(self):
        self.assertEqual(set(self.v), set(ROWS))

    def test_every_row_is_the_state_the_spec_gives_it(self):
        for name, (added, removed, applied) in ROWS.items():
            v = self.v[name]
            self.assertEqual(v["command"], "fold", name)
            self.assertEqual(v["anchor"], _expected(v["input"]["acts"], added, removed, applied),
                             name)

    def test_the_negative_rows_do_carry_the_act_they_reject(self):
        # a row that applied nothing still has a chain primary in its bag
        for name, (added, removed, applied) in ROWS.items():
            bag = self.v[name]["input"]["acts"]
            if len(applied) < len(_ordinals(bag)) or not applied:
                self.assertTrue(len(_ordinals(bag)) > len(applied), name)

    def test_the_proof_and_signer_defects_are_where_the_row_says(self):
        def payloads(name):
            return [json.loads(forge.parts(j)[1]) for j in self.v[name]["input"]["acts"]]
        self.assertEqual([p["method"] for p in payloads("add/no-pop")],
                         ["local:handsal.device.add", "local:handsal.act.endorse"])
        pops = payloads("add/pop-performer-mismatch")[2]
        self.assertEqual(pops["performer_id"], "bob")
        self.assertEqual(pops["ext"]["dev.handsal/act"]["kid"], FX.key("alice2").kid)
        other = payloads("add/pop-by-other-key")
        self.assertEqual(other[2]["ext"]["dev.handsal/act"]["kid"], FX.key("bob").kid)
        body = payloads("add/agree-reused")[0]["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["agree"], FX.key("carol", "agree").point())
        body = payloads("add/kid-reused-active")[0]["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["kid"], FX.key("alice").kid)
        body = payloads("add/cross-person")[0]["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["person"], "bob")
        body = payloads("rem/self-removal-wrong-person")[-2]["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body, {"kid": FX.key("alice2").kid, "person": "bob"})
        body = payloads("rem/remove-unknown-kid")[0]["ext"]["dev.handsal/act"]["body"]
        self.assertNotIn(body["kid"], [FX.key(n).kid for n in ("alice", "bob", "carol")])
        body = payloads("mem/id-reused")[0]["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["member"], "alice")

    def test_removed_kid_is_readded_in_cas_and_add_rows(self):
        # kid in a body: added, removed, added again (cas) or removed, added again (add)
        for name, device, times in (("cas/removed-never-returns", "alice2", 3),
                                    ("add/kid-reused-removed", "carol", 2)):
            kids = [json.loads(forge.parts(j)[1])["ext"]["dev.handsal/act"]["body"].get("kid")
                    for j in self.v[name]["input"]["acts"]]
            self.assertEqual(kids.count(FX.key(device).kid), times, name)

    def test_the_surplus_row_is_the_ok_row_plus_one_endorsement(self):
        bag = self.v["quo/surplus-endorsement-same-output"]["input"]["acts"]
        self.assertEqual(len(bag), 4)  # primary, two endorsements, proof
        ok = self.v["quo/two-persons-device-add-ok"]["input"]["acts"]
        self.assertEqual(len(ok), 3)
        self.assertEqual(self.v["quo/surplus-endorsement-same-output"]["anchor"],
                         self.v["quo/two-persons-device-add-ok"]["anchor"])


if __name__ == "__main__":
    unittest.main()
