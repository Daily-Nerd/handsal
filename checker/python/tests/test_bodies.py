"""T3.12 to T3.14 bodies: lifecycle methods, verdict, endorse and promotion, chain.resolve.

The registry holds every closed body schema and `schema` reads it, so one module
(`bodies`) adds only what the registry cannot say: keys and classes of an
introduced device, the role being listed, and `choose` being a candidate.
"""
import copy
import json
import unittest
from pathlib import Path

from handsal_check import bodies, encoding, errors, registry

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]
REG = registry.load()
M = "local:handsal.%s"
H = [encoding.hashstr(bytes([i])) for i in range(40)]
ROLES = ["maintainer", "member"]


def point(name):
    return {"x": KEYS[name]["x"], "y": KEYS[name]["y"]}


def device(name, cls="apple-se-bio"):
    return {"agree": point(name + ".agree"), "class": cls, "kid": KEYS[name + ".sign"]["kid"], "label": "laptop",
            "sign": point(name + ".sign")}


def device_add_body():
    d = device("alice2")
    d["link_code_hash"] = H[0]
    d["person"] = "alice"
    return d


def member_add_body():
    return {"device": device("dave"), "link_code_hash": H[0], "member": "dave", "role": "member"}


def resolve_body():
    cands = sorted(H[1:4])
    return {"candidates": cands, "choose": cands[0], "heads": sorted(H[4:6]), "overrides": []}


def verdict_of(method, body, **ctx):
    try:
        bodies.validate(M % method, body, REG, **ctx)
    except errors.Refused as err:
        return err.code
    return None


def edit(body, **changes):
    out = copy.deepcopy(body)
    for key, value in changes.items():
        if value is DELETE:
            del out[key]
        else:
            out[key] = value
    return out


DELETE = object()


class Lifecycle(unittest.TestCase):
    def test_valid_bodies(self):
        self.assertIsNone(verdict_of("genesis.sign", {}))
        self.assertIsNone(verdict_of("device.add", device_add_body(), fixture=False))
        self.assertIsNone(verdict_of("device.remove", {"kid": KEYS["bob.sign"]["kid"], "person": "bob"}))
        self.assertIsNone(verdict_of("member.add", member_add_body(), fixture=False, roles=ROLES))

    def test_genesis_sign_body_is_empty(self):
        self.assertEqual(verdict_of("genesis.sign", {"x": "y"}), "body_schema")

    def test_device_add_missing_or_extra_key(self):
        body = device_add_body()
        self.assertEqual(verdict_of("device.add", edit(body, link_code_hash=DELETE)), "body_schema")
        self.assertEqual(verdict_of("device.add", edit(body, extra="x")), "body_schema")
        self.assertEqual(verdict_of("device.add", edit(body, person=DELETE)), "body_schema")

    def test_device_remove_extra_key(self):
        body = {"kid": KEYS["bob.sign"]["kid"], "person": "bob"}
        self.assertEqual(verdict_of("device.remove", edit(body, extra="x")), "body_schema")
        self.assertEqual(verdict_of("device.remove", edit(body, kid=DELETE)), "body_schema")

    def test_label_alphabet(self):
        for bad in ('a"b', "a\\b", "café", "x" * 65, "", "a\x7fb"):
            body = device_add_body()
            body["label"] = bad
            self.assertEqual(verdict_of("device.add", body), "body_schema", repr(bad))
            self.assertEqual(verdict_of("member.add", edit(member_add_body(), device={**device("dave"), "label": bad}),
                                        roles=ROLES), "body_schema")

    def test_form_defects_the_registry_names_as_ACT_07_are_schema(self):
        self.assertEqual(verdict_of("device.add", edit(device_add_body(), link_code_hash="nope")), "schema")
        self.assertEqual(verdict_of("device.add", edit(device_add_body(), person="Alice")), "schema")
        self.assertEqual(verdict_of("member.add", edit(member_add_body(), member="Dave"), roles=ROLES), "schema")

    def test_coordinate_of_31_bytes_is_a_body_defect(self):
        body = device_add_body()
        body["sign"]["x"] = encoding.b64u_encode(encoding.b64u_decode(body["sign"]["x"])[1:])
        self.assertEqual(verdict_of("device.add", body), "body_schema")

    def test_kid_must_be_the_thumbprint(self):
        body = device_add_body()
        body["kid"] = KEYS["bob.sign"]["kid"]
        self.assertEqual(verdict_of("device.add", body), "body_schema")

    def test_point_off_the_curve(self):
        body = device_add_body()
        y = encoding.b64u_decode(body["sign"]["y"])
        body["sign"]["y"] = encoding.b64u_encode(y[:-1] + bytes([y[-1] ^ 1]))
        body["kid"] = encoding.thumbprint(body["sign"]["x"], body["sign"]["y"])
        self.assertEqual(verdict_of("device.add", body), "body_schema")

    def test_agree_equals_sign(self):
        body = device_add_body()
        body["agree"] = dict(body["sign"])
        self.assertEqual(verdict_of("device.add", body), "body_schema")

    def test_a_device_with_an_alg_member_is_not_a_body(self):
        body = device_add_body()
        body["sign"] = {**body["sign"], "alg": "ES256"}
        self.assertEqual(verdict_of("device.add", body), "body_schema")

    def test_class_must_be_in_the_registry_for_the_profile(self):
        self.assertEqual(verdict_of("device.add", edit(device_add_body(), **{"class": "yubikey-piv"})),
                         "body_schema")
        pin = edit(device_add_body(), **{"class": "fixture-pin"})
        self.assertEqual(verdict_of("device.add", pin, fixture=False), "body_schema")
        self.assertIsNone(verdict_of("device.add", pin, fixture=True))

    def test_a_class_the_policy_does_not_accept_is_still_a_valid_body(self):
        # acceptance is KC-04's business (the key is in `devices` with accepted:false), not the body's
        self.assertIsNone(verdict_of("device.add", edit(device_add_body(), **{"class": "fixture-pin"}), fixture=True))
        self.assertIsNone(verdict_of("device.add", edit(device_add_body(), **{"class": "test-sw-p256"})))

    def test_member_add_role_must_be_listed(self):
        self.assertEqual(verdict_of("member.add", edit(member_add_body(), role="admin"), roles=ROLES),
                         "body_schema")
        self.assertIsNone(verdict_of("member.add", edit(member_add_body(), role="maintainer"), roles=ROLES))

    def test_member_add_device_keys_and_class_are_checked(self):
        body = member_add_body()
        body["device"]["kid"] = KEYS["bob.sign"]["kid"]
        self.assertEqual(verdict_of("member.add", body, roles=ROLES), "body_schema")
        body = member_add_body()
        body["device"]["class"] = "yubikey-piv"
        self.assertEqual(verdict_of("member.add", body, roles=ROLES), "body_schema")

    def test_member_add_without_roles_is_a_caller_bug(self):
        with self.assertRaises(ValueError):
            verdict_of("member.add", member_add_body())

    def test_member_add_device_has_no_person_member(self):
        body = member_add_body()
        body["device"]["person"] = "dave"
        self.assertEqual(verdict_of("member.add", body, roles=ROLES), "body_schema")


class VerdictEndorsePromote(unittest.TestCase):
    def test_verdict_bodies_are_empty(self):
        for name in ("request.approve", "request.reject", "request.needs-info"):
            self.assertIsNone(verdict_of(name, {}))
            self.assertEqual(verdict_of(name, {"x": "y"}), "body_schema")
            self.assertEqual(verdict_of(name, []), "body_schema")

    def test_endorse_body(self):
        self.assertIsNone(verdict_of("act.endorse", {"act": H[0]}))
        self.assertEqual(verdict_of("act.endorse", {"act": "nope"}), "schema")
        self.assertEqual(verdict_of("act.endorse", {}), "body_schema")
        self.assertEqual(verdict_of("act.endorse", {"act": H[0], "x": "y"}), "body_schema")

    def test_promote_body(self):
        ok = {"anchors": ["a1"], "record_id": "rec-1"}
        self.assertIsNone(verdict_of("record.promote", ok))
        self.assertEqual(verdict_of("record.promote", edit(ok, anchors=["a"] * 17)), "body_schema")
        self.assertEqual(verdict_of("record.promote", edit(ok, anchors=[""])), "body_schema")
        self.assertEqual(verdict_of("record.promote", edit(ok, anchors=["café"])), "body_schema")
        self.assertEqual(verdict_of("record.promote", edit(ok, record_id="Rec")), "body_schema")
        self.assertEqual(verdict_of("record.promote", edit(ok, record_id=DELETE)), "body_schema")


class Resolve(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(verdict_of("chain.resolve", resolve_body()))
        body = resolve_body()
        a, b = sorted(H[10:12])
        body["overrides"] = [{"endorsements": sorted(H[12:14]), "resolve": a},
                             {"endorsements": [H[14]], "resolve": b}]
        self.assertIsNone(verdict_of("chain.resolve", body))

    def test_extra_key(self):
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), x="y")), "body_schema")

    def test_choose_must_be_a_hashstr_and_a_candidate(self):
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), choose="nope")), "schema")
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), choose=H[30])), "body_schema")

    def test_candidates_count_sort_distinct(self):
        body = resolve_body()
        one = edit(body, candidates=[body["candidates"][0]])
        self.assertEqual(verdict_of("chain.resolve", one), "body_schema")
        seventeen = sorted(H[:17])
        self.assertIsNone(verdict_of("chain.resolve", edit(body, candidates=seventeen, choose=seventeen[0])))
        eighteen = sorted(H[:18])
        self.assertEqual(verdict_of("chain.resolve", edit(body, candidates=eighteen, choose=eighteen[0])),
                         "body_schema")
        a, b, c = body["candidates"]
        self.assertEqual(verdict_of("chain.resolve", edit(body, candidates=[b, a, c])), "body_schema")
        self.assertEqual(verdict_of("chain.resolve", edit(body, candidates=[a, a, b], choose=a)), "body_schema")

    def test_heads_count(self):
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), heads=[])), "body_schema")
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), heads=sorted(H[:17]))), "body_schema")
        self.assertIsNone(verdict_of("chain.resolve", edit(resolve_body(), heads=sorted(H[:16]))))

    def test_override_entry_shape(self):
        a = H[10]
        for entry in ({"endorsements": [H[12]]}, {"resolve": a}, {"endorsements": [], "resolve": a},
                      {"endorsements": [H[12]], "resolve": a, "x": "y"}, "nope", None,
                      {"endorsements": sorted(H[:16]), "resolve": a}):
            self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), overrides=[entry])),
                             "body_schema", entry)

    def test_override_entry_hashstr_forms_are_schema(self):
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(),
                         overrides=[{"endorsements": ["nope"], "resolve": H[10]}])), "schema")
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(),
                         overrides=[{"endorsements": [H[12]], "resolve": "nope"}])), "schema")

    def test_override_order_and_distinctness(self):
        a, b = sorted(H[10:12])
        e = lambda r: {"endorsements": [H[12]], "resolve": r}
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), overrides=[e(b), e(a)])), "body_schema")
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(), overrides=[e(a), e(a)])), "body_schema")
        self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(),
                         overrides=[e(h) for h in sorted(H[10:27])])), "body_schema")

    def test_endorsements_sorted_and_distinct(self):
        a, b = sorted(H[12:14])
        for ends in ([b, a], [a, a]):
            self.assertEqual(verdict_of("chain.resolve", edit(resolve_body(),
                             overrides=[{"endorsements": ends, "resolve": H[10]}])), "body_schema")


class Dispatch(unittest.TestCase):
    def test_every_registry_method_has_a_validator(self):
        self.assertEqual(set(bodies._SEMANTICS), set(REG.methods))

    def test_unknown_method_is_a_bug_not_a_pass(self):
        with self.assertRaises(KeyError):
            bodies.validate("local:handsal.request.send", {}, REG)


if __name__ == "__main__":
    unittest.main()
