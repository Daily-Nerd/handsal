"""T2.7 base fixtures (GP-18, ACT-14, catalog-part2 21, catalog-part3 25).

ORG: three maintainers alice, bob, carol, persons 2, witness none, fixture
profile. The profile hash is an input to Fixtures; tests feed it the real
fixture profile from the core manifest (tools/manifest.py, T2.9), the single
owner of that value, and pin the ids derived from it.
"""
import base64
import hashlib
import json
import unittest
from pathlib import Path

from lib import base, es256, jcs, keys, p256

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
PROFILE = base.fixture_profile()

# Pinned, outside this code: the fixture profile hash and the two organization ids. They are
# computed with openssl from the files by `tools/repin.py` and written to `conformance/pins.json`,
# the one place they live. Any edit to a core file moves the profile hash and with it every id
# below: that is the spec's intent (CF-01), so they are re-pinned together, never by hand.
PINS = json.loads((FIXTURES.parent / "pins.json").read_text(encoding="utf-8"))
PINNED_FIXTURE_PROFILE = PINS["fixture_profile"]
# Deterministic keys, deterministic bytes: a change here is a change of every vector built on ORG.
PINNED_ORG_ID = PINS["org_id"]
PINNED_WIT_ORG_ID = PINS["wit_org_id"]


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parts(jws):
    h, p, s = jws.split(".")
    return unb64u(h), unb64u(p), unb64u(s)


def payload_of(jws):
    return json.loads(parts(jws)[1])


def act_of(jws):
    return payload_of(jws)["ext"]["dev.handsal/act"]


class Shape(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def test_org_validates_against_its_shape(self):
        self.assertEqual(base.check_genesis_shape(self.fx.org), [])

    def test_org_is_canonical_subset(self):
        raw = jcs.emit(self.fx.org)
        self.assertEqual(jcs.recognize(raw), (True, None))

    def test_org_content(self):
        org = self.fx.org
        self.assertEqual(sorted(org), ["devices", "members", "name", "org", "policy", "prev",
                                       "profile", "v"])
        self.assertIsNone(org["org"])
        self.assertIsNone(org["prev"])
        self.assertEqual(org["profile"], PROFILE)
        self.assertEqual(org["v"], "handsal-genesis/1")
        self.assertEqual(org["members"], [{"id": "alice", "role": "maintainer"},
                                          {"id": "bob", "role": "maintainer"},
                                          {"id": "carol", "role": "maintainer"}])
        self.assertEqual(sorted(d["person"] for d in org["devices"]), ["alice", "bob", "carol"])
        self.assertEqual({d["class"] for d in org["devices"]}, {"apple-se-bio"})
        self.assertEqual([d["kid"] for d in org["devices"]], sorted(d["kid"] for d in org["devices"]))

    def test_org_policy(self):
        pol = self.fx.org["policy"]
        rule = {"persons": "2", "roles": ["maintainer"]}
        self.assertEqual(pol["rules"], {"chain.resolve": rule, "device.remove": rule,
                                        "genesis.change": rule, "member.add": rule})
        self.assertEqual(pol["classes"], [{"class": "apple-se-bio",
                                           "user_verification": "biometric_only"}])
        self.assertEqual(pol["roles"], ["maintainer", "member"])
        self.assertEqual(pol["freshness"], {"clock_skew_s": "300", "max_validity_s": "604800",
                                            "max_view_age_s": "86400"})
        self.assertEqual(pol["witness"], {"mode": "none"})
        self.assertEqual(pol["relays"], [base.RELAY_HOST])   # GP-02, VR-08: the host a verdict names
        self.assertEqual(pol["v"], "handsal-policy/1")

    def test_the_org_doc_takes_the_relays_it_is_given(self):
        for relays in ([], ["r.example", "s.example"]):
            doc = self.fx.org_doc(relays=relays)
            self.assertEqual(doc["policy"]["relays"], relays)
            self.assertEqual(base.check_genesis_shape(doc), [])
        self.assertEqual(self.fx.wit_org["policy"]["relays"], [base.RELAY_HOST])

    def test_device_keys_come_from_fixtures(self):
        doc = json.loads((FIXTURES / "keys.json").read_text())["keys"]
        for dev in self.fx.org["devices"]:
            self.assertEqual(dev["sign"]["x"], doc[dev["person"] + ".sign"]["x"])
            self.assertEqual(dev["agree"]["y"], doc[dev["person"] + ".agree"]["y"])
            self.assertEqual(dev["kid"], doc[dev["person"] + ".sign"]["kid"])
            self.assertEqual(dev["kid"], keys.thumbprint(dev["sign"]["x"], dev["sign"]["y"]))

    def test_shape_refuses_defects(self):
        def mutate(fn):
            doc = json.loads(json.dumps(self.fx.org))
            fn(doc)
            return base.check_genesis_shape(doc)
        self.assertTrue(mutate(lambda d: d["members"].reverse()))
        self.assertTrue(mutate(lambda d: d["devices"].reverse()))
        self.assertTrue(mutate(lambda d: d.update(extra="x")))
        self.assertTrue(mutate(lambda d: d["devices"][0].update(kid="x" * 43)))
        self.assertTrue(mutate(lambda d: d["devices"][0].update(agree=d["devices"][0]["sign"])))
        self.assertTrue(mutate(lambda d: d["policy"].pop("witness")))
        self.assertTrue(mutate(lambda d: d["policy"].pop("relays")))
        self.assertTrue(mutate(lambda d: d["policy"].update(relays=["s.example", "r.example"])))
        self.assertTrue(mutate(lambda d: d["policy"].update(relays=["r.example", "r.example"])))
        self.assertTrue(mutate(lambda d: d["policy"].update(relays=["R.example"])))
        self.assertTrue(mutate(lambda d: d["policy"].update(relays=["a.example", "b.example", "c.example"])))
        self.assertTrue(mutate(lambda d: d["policy"]["rules"]["member.add"].update(persons="3")))
        self.assertTrue(mutate(lambda d: d["members"].pop()))
        self.assertTrue(mutate(lambda d: d.update(head=PROFILE)))

    def test_profile_is_required_and_a_hashstr(self):
        with self.assertRaises(ValueError):
            base.Fixtures(None)
        with self.assertRaises(ValueError):
            base.Fixtures("not a hashstr")


class Hashes(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def test_hashstr_known_answer(self):
        self.assertEqual(base.EMPTY_HASH, "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ")
        self.assertTrue(PROFILE.startswith("uEi") and len(PROFILE) == 47)

    def test_org_id_is_hash_of_jcs(self):
        want = "u" + base64.urlsafe_b64encode(
            b"\x12\x20" + hashlib.sha256(jcs.emit(self.fx.org)).digest()).rstrip(b"=").decode()
        self.assertEqual(self.fx.org_id, want)

    def test_stable_across_instances(self):
        other = base.Fixtures(PROFILE)
        self.assertEqual(other.org_id, self.fx.org_id)
        self.assertEqual(other.approve(), self.fx.approve())
        self.assertEqual(other.lineage(), self.fx.lineage())

    def test_fixture_profile_pinned(self):
        self.assertEqual(PROFILE, PINNED_FIXTURE_PROFILE)

    def test_profile_helpers_derive_from_the_manifest(self):
        self.assertEqual(base.fixture_profile(), PINNED_FIXTURE_PROFILE)
        self.assertNotEqual(base.production_profile(), base.fixture_profile())
        self.assertTrue(base.is_hashstr(base.production_profile()))

    def test_org_id_pinned(self):
        self.assertEqual(self.fx.org_id, PINNED_ORG_ID)

    def test_wit_org_id_pinned(self):
        self.assertEqual(self.fx.wit_org_id, PINNED_WIT_ORG_ID)

    def test_profile_changes_org_id(self):
        self.assertNotEqual(base.Fixtures(base.hashstr(b"other")).org_id, self.fx.org_id)


class Acts(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def assert_signed_by(self, jws, name):
        h, p, s = parts(jws)
        kid = self.fx.key(name).kid
        self.assertEqual(h, ('{"alg":"ES256","kid":"%s"}' % kid).encode())
        self.assertEqual(jcs.recognize(p), (True, None))
        self.assertEqual(act_of(jws)["kid"], kid)  # ACT-14
        self.assertTrue(es256.is_low_s(s))
        signing = jws.rsplit(".", 1)[0].encode("ascii")
        k = self.fx.key(name)
        self.assertTrue(es256.verify((k.x_int, k.y_int), signing, s))

    def assert_envelope(self, jws):
        p = payload_of(jws)
        self.assertEqual(sorted(p), sorted(
            "action_ref binding cost ext inputs_hash log_policy method nonce outputs_hash "
            "parent_performer_id parent_receipt_hash performer_id reason requester_id status ts v"
            .split()))
        self.assertEqual((p["v"], p["binding"], p["status"], p["log_policy"]),
                         ("vitni/0.2", "local", "OK", "best_effort"))
        self.assertEqual(p["cost"], {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"})
        self.assertEqual(list(p["ext"]), ["dev.handsal/act"])
        self.assertNotIn("added_by", json.dumps(p))

    def test_lineage_is_one_signature_per_device(self):
        lin = self.fx.lineage()
        self.assertEqual(len(lin), 1)
        self.assertEqual(lin[0]["doc"], self.fx.org)
        self.assertEqual(len(lin[0]["sigs"]), 3)
        seen = []
        for jws in lin[0]["sigs"]:
            self.assert_envelope(jws)
            p, a = payload_of(jws), act_of(jws)
            self.assertEqual(p["method"], "local:handsal.genesis.sign")
            self.assertEqual(p["inputs_hash"], self.fx.org_id)
            self.assertEqual(p["outputs_hash"], base.EMPTY_HASH)
            self.assertEqual((p["parent_receipt_hash"], p["parent_performer_id"]), (None, None))
            self.assertEqual(a["org"], self.fx.org_id)
            self.assertEqual(a["body"], {})
            self.assertNotIn("head", a)
            self.assertEqual(sorted(a), ["body", "kid", "org"])
            self.assertEqual(self.fx.person_of_kid(a["kid"]), p["performer_id"])
            seen.append(p["performer_id"])
        self.assertEqual(sorted(seen), ["alice", "bob", "carol"])
        for jws in lin[0]["sigs"]:
            name = self.fx.person_of_kid(act_of(jws)["kid"])
            self.assert_signed_by(jws, name)

    def test_pin_ok(self):
        probe = self.fx.pin_ok()
        self.assertEqual(sorted(probe), ["bytes_b64", "filename", "org", "owner_ok", "reason"])
        self.assertEqual((probe["owner_ok"], probe["reason"], probe["org"]),
                         (True, "ok", self.fx.org_id))
        raw = base64.b64decode(probe["bytes_b64"])
        self.assertTrue(raw.endswith(b"\n") and raw.count(b"\n") == 1 and len(raw) <= 512)
        line = raw[:-1]
        self.assertEqual(jcs.recognize(line), (True, None))
        self.assertEqual(json.loads(line), {"genesis": self.fx.org_id, "org": self.fx.org_id,
                                            "spec": PROFILE, "v": "handsal-pin/1"})
        digest = unb64u(self.fx.org_id[1:])[2:]
        self.assertEqual(probe["filename"], digest.hex() + ".pin")

    def test_approve(self):
        jws = self.fx.approve()
        self.assert_envelope(jws)
        self.assert_signed_by(jws, "alice")
        p, a = payload_of(jws), act_of(jws)
        self.assertEqual(p["method"], "local:handsal.request.approve")
        self.assertEqual(p["performer_id"], "alice")
        self.assertEqual(p["ts"], "2026-11-08T11:59:00Z")
        self.assertEqual((p["parent_receipt_hash"], p["parent_performer_id"]), (None, None))
        self.assertEqual(sorted(a), ["body", "expires", "head", "kid", "org", "recipient", "relay",
                                     "request_id"])
        self.assertEqual(a["expires"], "2026-11-08T12:59:00Z")
        self.assertEqual((a["recipient"], a["relay"], a["request_id"]),
                         ("alice", "r.example", "req-00000001"))
        self.assertEqual(a["head"], {"id": self.fx.org_id, "kind": "chain"})
        self.assertEqual(a["org"], self.fx.org_id)
        self.assertEqual(a["body"], {})
        self.assertEqual(p["inputs_hash"], base.hashstr(b"deploy v2"))
        self.assertEqual(p["outputs_hash"], base.hashstr(
            b'{"request_id":"req-00000001","verdict":"approve"}'))

    def test_approve_inputs_for_the_checker(self):
        self.assertEqual(base.NOW, "2026-11-08T12:00:00Z")
        self.assertEqual(base.REQUEST, b"deploy v2")
        self.assertEqual(self.fx.request_b64(), base64.b64encode(b"deploy v2").decode())

    def test_nonce_is_hashstr_of_32_bytes_and_distinct(self):
        a = payload_of(self.fx.approve())["nonce"]
        b = payload_of(self.fx.lineage()[0]["sigs"][0])["nonce"]
        for n in (a, b):
            self.assertEqual(len(n), 47)
            self.assertEqual(len(unb64u(n[1:])), 34)
        self.assertNotEqual(a, b)

    def test_device_add_two_persons(self):
        add = self.fx.device_add("alice2", signers=("alice", "bob"))
        self.assertEqual(len(add.acts), 3)  # primary, counted endorsement, proof of possession
        primary, endorse, pop = add.acts
        for jws in add.acts:
            self.assert_envelope(jws)
        self.assert_signed_by(primary, "alice")
        self.assert_signed_by(endorse, "bob")
        self.assert_signed_by(pop, "alice2")
        pp, pa = payload_of(primary), act_of(primary)
        self.assertEqual(pp["method"], "local:handsal.device.add")
        self.assertEqual(pp["performer_id"], "alice")
        self.assertEqual(pp["parent_receipt_hash"], self.fx.org_id)
        self.assertIsNone(pp["parent_performer_id"])
        self.assertEqual((pp["inputs_hash"], pp["outputs_hash"]), (base.EMPTY_HASH, base.EMPTY_HASH))
        self.assertEqual(sorted(pa), ["body", "kid", "org"])
        self.assertEqual(sorted(pa["body"]), ["agree", "class", "kid", "label", "link_code_hash",
                                              "person", "sign"])
        self.assertEqual(pa["body"]["person"], "alice")
        self.assertEqual(pa["body"]["kid"], self.fx.key("alice2").kid)
        self.assertEqual(add.id, base.hashstr(parts(primary)[1]))
        self.assertEqual(add.parent, self.fx.org_id)
        for jws, who in ((endorse, "bob"), (pop, "alice")):
            p, a = payload_of(jws), act_of(jws)
            self.assertEqual(p["method"], "local:handsal.act.endorse")
            self.assertEqual(p["performer_id"], who)
            self.assertEqual(p["parent_receipt_hash"], add.id)
            self.assertEqual(p["parent_performer_id"], "alice")
            self.assertEqual(a["body"], {"act": add.id})
            self.assertEqual(a["head"], {"id": self.fx.org_id, "kind": "chain"})
            self.assertEqual(sorted(a), ["body", "head", "kid", "org"])

    def test_chain_of_adds_links_parent_and_performer(self):
        a1 = self.fx.device_add("alice2", signers=("alice", "bob"))
        a2 = self.fx.device_add("alice3", signers=("alice", "carol"), parent=a1)
        p = payload_of(a2.acts[0])
        self.assertEqual(p["parent_receipt_hash"], a1.id)
        self.assertEqual(p["parent_performer_id"], "alice")
        self.assertEqual(act_of(a2.acts[1])["head"], {"id": a1.id, "kind": "chain"})

    def test_device_add_needs_two_distinct_persons(self):
        with self.assertRaises(ValueError):
            self.fx.device_add("alice2", signers=("alice", "alice"))
        with self.assertRaises(ValueError):
            self.fx.device_add("alice2", signers=("alice",))

    def test_device_person_map(self):
        self.assertEqual([self.fx.person_of_name(n) for n in ("alice2", "alice3", "bob2", "X1", "dave")],
                         ["alice", "alice", "bob", "alice", "dave"])


class Keyset(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def test_keyset_is_the_vitni_keys_shape(self):
        ks = self.fx.keyset(["alice", "bob", "carol"])
        self.assertEqual(sorted(ks), ["alice", "bob", "carol"])
        entry = ks["alice"][self.fx.key("alice").kid]
        self.assertEqual(sorted(entry), ["alg", "crv", "kty", "status", "x", "y"])
        self.assertEqual((entry["alg"], entry["crv"], entry["kty"], entry["status"]),
                         ("ES256", "P-256", "EC", "active"))

    def test_every_fixture_kid_is_listed(self):
        listed = set(json.loads((FIXTURES / "fixture-kids.json").read_text()))
        for name in ("alice", "bob", "carol", "alice2", "bob2", "dave", "X1"):
            self.assertIn(self.fx.key(name).kid, listed)
        self.assertIn(self.fx.relay.kid, listed)

    def test_keyset_status_revoked(self):
        ks = self.fx.keyset(["alice"], revoked=["alice"])
        self.assertEqual(ks["alice"][self.fx.key("alice").kid]["status"], "revoked")


class Witness(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def test_relay_fx(self):
        r = self.fx.relay
        self.assertEqual(r.kid, keys.thumbprint(r.x, r.y))
        self.assertEqual(self.fx.relay_jwk(), {"crv": "P-256", "kty": "EC", "x": r.x, "y": r.y})

    def test_wit_org(self):
        org = self.fx.wit_org
        self.assertEqual(base.check_genesis_shape(org), [])
        self.assertEqual(org["policy"]["witness"], {
            "max_tip_age_s": "3600", "mode": "relay", "relay_kid": self.fx.relay.kid,
            "relay_pub_jwk": self.fx.relay_jwk()})
        base_doc = json.loads(json.dumps(self.fx.org))
        wit = json.loads(json.dumps(org))
        base_doc["policy"].pop("witness")
        wit["policy"].pop("witness")
        self.assertEqual(base_doc, wit)
        self.assertNotEqual(self.fx.wit_org_id, self.fx.org_id)

    def test_wit_lineage_and_pin_built_from_it(self):
        lin = self.fx.lineage(wit=True)
        self.assertEqual(lin[0]["doc"], self.fx.wit_org)
        self.assertEqual(payload_of(lin[0]["sigs"][0])["inputs_hash"], self.fx.wit_org_id)
        self.assertEqual(self.fx.pin_ok(wit=True)["org"], self.fx.wit_org_id)


class MoreMethods(unittest.TestCase):
    """Builders for the methods the first batch could not build (ACT-09, ACT-13)."""

    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def envelope_ok(self, jws):
        p = payload_of(jws)
        self.assertEqual(jcs.recognize(parts(jws)[1]), (True, None))
        self.assertEqual((p["v"], p["binding"], p["status"]), ("vitni/0.2", "local", "OK"))
        return p, act_of(jws)

    def test_device_remove(self):
        rm = self.fx.device_remove("alice2", ["bob", "carol"])
        self.assertEqual(len(rm.acts), 2)  # primary and one counted endorsement, no possession
        p, a = self.envelope_ok(rm.acts[0])
        self.assertEqual(p["method"], "local:handsal.device.remove")
        self.assertEqual(p["performer_id"], "bob")
        self.assertEqual(p["parent_receipt_hash"], self.fx.org_id)
        self.assertIsNone(p["parent_performer_id"])
        self.assertEqual(sorted(a), ["body", "kid", "org"])
        self.assertEqual(a["body"], {"kid": self.fx.key("alice2").kid, "person": "alice"})
        self.assertEqual(rm.id, base.hashstr(parts(rm.acts[0])[1]))
        ep, ea = self.envelope_ok(rm.acts[1])
        self.assertEqual(ep["method"], "local:handsal.act.endorse")
        self.assertEqual(ep["performer_id"], "carol")
        self.assertEqual(ea["body"], {"act": rm.id})
        self.assertEqual(ea["head"], {"id": self.fx.org_id, "kind": "chain"})

    def test_device_remove_needs_two_distinct_persons(self):
        with self.assertRaises(ValueError):
            self.fx.device_remove("alice2", ["bob", "bob2"])

    def test_member_add(self):
        mem = self.fx.member_add("dave", ["alice", "bob"], role="member")
        self.assertEqual(len(mem.acts), 3)  # primary, counted endorsement, possession by the device
        p, a = self.envelope_ok(mem.acts[0])
        self.assertEqual(p["method"], "local:handsal.member.add")
        self.assertEqual(p["performer_id"], "alice")
        self.assertEqual(sorted(a["body"]), ["device", "link_code_hash", "member", "role"])
        self.assertEqual(sorted(a["body"]["device"]), ["agree", "class", "kid", "label", "sign"])
        self.assertEqual((a["body"]["member"], a["body"]["role"]), ("dave", "member"))
        self.assertEqual(a["body"]["device"]["kid"], self.fx.key("dave").kid)
        pp, pa = self.envelope_ok(mem.acts[2])
        self.assertEqual(pp["performer_id"], "dave")  # the new member (ACT-13)
        self.assertEqual(pa["body"], {"act": mem.id})

    def test_verdicts_differ_only_in_method_and_outputs(self):
        approve, reject, info = (self.fx.verdict(k) for k in ("approve", "reject", "needs-info"))
        self.assertEqual(self.fx.approve(), approve)
        for jws, kind in ((reject, "reject"), (info, "needs-info")):
            p, a = self.envelope_ok(jws)
            self.assertEqual(p["method"], "local:handsal.request.%s" % kind)
            self.assertEqual(p["outputs_hash"], base.hashstr(
                ('{"request_id":"req-00000001","verdict":"%s"}' % kind).encode()))
            self.assertEqual(p["inputs_hash"], base.hashstr(b"deploy v2"))
            self.assertEqual(sorted(a), ["body", "expires", "head", "kid", "org", "recipient",
                                         "relay", "request_id"])

    def test_verdict_kind_is_closed(self):
        with self.assertRaises(ValueError):
            self.fx.verdict("cancel")

    def test_no_builder_makes_the_retired_method(self):
        # ACT-09 S9: `lib/retired.py` is the one owner of its shape
        self.assertFalse(hasattr(self.fx, "record_promote"))
        self.assertFalse(hasattr(base, "RECORD_BODY"))

    def test_chain_resolve(self):
        c1 = self.fx.device_add("alice2", ["alice", "bob"])
        c2 = self.fx.device_add("bob2", ["alice", "bob"])
        res = self.fx.chain_resolve(["bob", "carol"], candidates=[c1.id, c2.id], choose=c1.id,
                                    heads=[c2.id])
        self.assertEqual(len(res.acts), 2)  # primary and one counted endorsement
        p, a = self.envelope_ok(res.acts[0])
        self.assertEqual(p["method"], "local:handsal.chain.resolve")
        self.assertEqual(p["performer_id"], "bob")
        self.assertEqual(p["parent_receipt_hash"], self.fx.org_id)
        self.assertIsNone(p["parent_performer_id"])
        self.assertEqual(sorted(a), ["body", "kid", "org"])  # never a head
        self.assertEqual(a["body"], {"candidates": sorted([c1.id, c2.id]), "choose": c1.id,
                                     "heads": [c2.id], "overrides": []})
        ep, ea = self.envelope_ok(res.acts[1])
        self.assertEqual(ea["body"], {"act": res.id})
        self.assertEqual(ea["head"], {"id": self.fx.org_id, "kind": "chain"})

    def test_chain_resolve_candidates_are_sorted_distinct(self):
        c1 = self.fx.device_add("alice2", ["alice", "bob"])
        with self.assertRaises(ValueError):
            self.fx.chain_resolve(["bob", "carol"], candidates=[c1.id, c1.id], choose=c1.id,
                                  heads=[c1.id])
        with self.assertRaises(ValueError):
            self.fx.chain_resolve(["bob", "carol"], candidates=[c1.id, base.EMPTY_HASH],
                                  choose="uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", heads=[c1.id])


class BuildHooks(unittest.TestCase):
    """Hooks that let a negative row differ from a valid act in exactly one place."""

    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def payloads(self, built):
        return [json.loads(base._unb64u(j.split(".")[1])) for j in built.acts]

    def act_obj(self, payload):
        return payload["ext"]["dev.handsal/act"]

    def test_body_edit_changes_the_body_and_the_endorsements_follow_the_new_id(self):
        built = self.fx.device_add("alice2", ("alice", "bob"),
                                   body_edit=lambda b: b.__setitem__("x", "y"))
        primary, endorse, _pop = self.payloads(built)
        self.assertEqual(self.act_obj(primary)["body"]["x"], "y")
        self.assertEqual(self.act_obj(endorse)["body"]["act"], built.id)

    def test_primary_head_adds_a_head_to_the_primary_only(self):
        head = {"id": self.fx.org_id, "kind": "chain"}
        built = self.fx.device_add("alice2", ("alice", "bob"), primary_head=head)
        primary, endorse, _pop = self.payloads(built)
        self.assertEqual(self.act_obj(primary)["head"], head)
        self.assertIn("head", self.act_obj(endorse))

    def test_endorse_head_false_leaves_the_counted_endorsements_without_head(self):
        built = self.fx.device_add("alice2", ("alice", "bob"), endorse_head=False)
        _primary, endorse, pop = self.payloads(built)
        self.assertNotIn("head", self.act_obj(endorse))
        self.assertIn("head", self.act_obj(pop))  # the proof of possession is not a counted one

    def test_short_allows_one_person_signers_and_the_default_still_refuses(self):
        with self.assertRaises(ValueError):
            self.fx.device_add("alice2", ("alice", "alice3"))
        built = self.fx.device_add("alice2", ("alice", "alice3"), short=True)
        self.assertEqual(len(built.acts), 3)

    def test_hooks_reach_remove_and_member_add(self):
        rm = self.fx.device_remove("carol", ("alice", "bob"),
                                   body_edit=lambda b: b.__setitem__("x", "y"))
        ma = self.fx.member_add("dave", ("alice", "bob"), role="member",
                                body_edit=lambda b: b.__setitem__("role", "admin"))
        self.assertEqual(self.act_obj(self.payloads(rm)[0])["body"]["x"], "y")
        self.assertEqual(self.act_obj(self.payloads(ma)[0])["body"]["role"], "admin")

    def test_primary_raw_edit_changes_the_signed_bytes_and_the_id_follows(self):
        built = self.fx.device_add(
            "alice2", ("alice", "bob"),
            body_edit=lambda b: b.__setitem__("label", "aQXQb"),
            primary_raw_edit=lambda raw: raw.replace(b"QXQ", b'\\"'))
        raw = base._unb64u(built.acts[0].split(".")[1])
        self.assertIn(b'a\\"b', raw)
        self.assertEqual(built.id, base.hashstr(raw))
        k = self.fx.key("alice")
        sig = base._unb64u(built.acts[0].split(".")[2])
        self.assertTrue(es256.verify((k.x_int, k.y_int), built.acts[0].rsplit(".", 1)[0].encode(), sig))
        endorse = json.loads(base._unb64u(built.acts[1].split(".")[1]))
        self.assertEqual(endorse["ext"]["dev.handsal/act"]["body"]["act"], built.id)

    def test_primary_edit_changes_an_envelope_field_and_the_id_follows(self):
        built = self.fx.device_add("alice2", ("alice", "bob"),
                                   primary_edit=lambda p: p.__setitem__("parent_receipt_hash", None))
        primary, endorse, _pop = self.payloads(built)
        self.assertIsNone(primary["parent_receipt_hash"])
        self.assertEqual(self.act_obj(endorse)["body"]["act"], built.id)
        self.assertEqual(endorse["parent_receipt_hash"], built.id)

    def test_pop_false_leaves_out_the_proof_of_possession(self):
        built = self.fx.device_add("alice2", ("alice", "bob"), pop=False)
        self.assertEqual(len(built.acts), 2)

    def test_pop_signer_and_pop_performer_change_the_proof_only(self):
        built = self.fx.device_add("alice2", ("alice", "bob"), pop_signer="bob")
        self.assertEqual(json.loads(base._unb64u(built.acts[2].split(".")[0]))["kid"],
                         self.fx.key("bob").kid)
        built = self.fx.device_add("alice2", ("alice", "bob"), pop_performer="bob")
        self.assertEqual(self.payloads(built)[2]["performer_id"], "bob")
        self.assertEqual(self.payloads(built)[1]["performer_id"], "bob")  # bob's own endorsement
        self.assertEqual(self.payloads(built)[2]["ext"]["dev.handsal/act"]["kid"],
                         self.fx.key("alice2").kid)

    def test_member_add_proof_performer_is_the_new_member_by_default(self):
        built = self.fx.member_add("dave", ("alice", "bob"), role="member", member="eve")
        self.assertEqual(self.payloads(built)[2]["performer_id"], "eve")

    def test_a_registered_device_is_a_fixture_device_with_its_own_keys(self):
        self.fx.register_device("alice5", "crafted/sign", "crafted/agree")
        key = self.fx.key("alice5")
        point = p256.mul(keys.derive_scalar("crafted/sign"))
        self.assertEqual((key.x_int, key.y_int), point)
        self.assertEqual(key.kid, keys.thumbprint(key.x, key.y))
        self.assertEqual(self.fx.name_of_kid(key.kid), "alice5")
        self.assertEqual(self.fx.person_of_kid(key.kid), "alice")
        built = self.fx.device_add("alice5", ("alice", "bob"))
        self.assertEqual(len(built.acts), 3)


class TipStatement(unittest.TestCase):
    """WT-02: the relay tip statement, an envelope with no act-object kid and no head."""

    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def parts(self, jws):
        h, p, s = jws.split(".")
        un = lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
        return un(h), un(p), un(s)

    def test_defaults_are_the_wt02_shape(self):
        fx = self.fx
        header, raw, sig = self.parts(fx.tip_statement())
        self.assertEqual(header, b'{"alg":"ES256","kid":"%s"}' % fx.relay.kid.encode())
        p = json.loads(raw)
        self.assertEqual(sorted(p), sorted(
            "action_ref binding cost ext inputs_hash log_policy method nonce outputs_hash "
            "parent_performer_id parent_receipt_hash performer_id reason requester_id status ts "
            "v".split()))
        self.assertEqual(p["method"], "local:handsal.relay.tip")
        self.assertEqual((p["performer_id"], p["parent_receipt_hash"], p["parent_performer_id"]),
                         ("relay", None, None))
        self.assertEqual((p["inputs_hash"], p["outputs_hash"]), (base.EMPTY_HASH, base.EMPTY_HASH))
        self.assertEqual(p["ts"], base.shift(base.NOW, -60))
        self.assertEqual(p["ext"], {"dev.handsal/act": {
            "body": {"epoch": fx.wit_org_id, "next": "no", "tip": fx.wit_org_id},
            "org": fx.wit_org_id}})
        self.assertEqual(raw, jcs.emit(p))

    def test_it_is_signed_by_the_relay_key_with_a_low_s(self):
        r = self.fx.relay
        jws = self.fx.tip_statement()
        self.assertTrue(es256.verify((r.x_int, r.y_int), jws.rsplit(".", 1)[0].encode(),
                                     self.parts(jws)[2]))
        self.assertTrue(es256.is_low_s(self.parts(jws)[2]))

    def test_the_nonce_is_a_function_of_the_rest_so_a_rerun_is_identical(self):
        self.assertEqual(self.fx.tip_statement(), self.fx.tip_statement())
        self.assertNotEqual(self.fx.tip_statement(), self.fx.tip_statement(tip=base.hashstr(b"x")))

    def test_each_field_is_settable(self):
        fx = self.fx
        other = base.hashstr(b"other")
        p = json.loads(self.parts(fx.tip_statement(
            epoch=other, tip=other, org=other, next_="yes", ts="2026-11-08T11:00:00Z"))[1])
        self.assertEqual(p["ext"]["dev.handsal/act"]["body"],
                         {"epoch": other, "next": "yes", "tip": other})
        self.assertEqual((p["ext"]["dev.handsal/act"]["org"], p["ts"]),
                         (other, "2026-11-08T11:00:00Z"))

    def test_another_signer_and_another_header_kid(self):
        fx = self.fx
        bob = fx.key("bob")
        header, _raw, sig = self.parts(fx.tip_statement(key=bob, header_kid=fx.relay.kid))
        self.assertEqual(json.loads(header)["kid"], fx.relay.kid)
        jws = fx.tip_statement(key=bob, header_kid=fx.relay.kid)
        self.assertTrue(es256.verify((bob.x_int, bob.y_int), jws.rsplit(".", 1)[0].encode(), sig))

    def test_hooks_edit_the_object_the_envelope_or_the_bytes(self):
        fx = self.fx
        p = json.loads(self.parts(fx.tip_statement(
            act_edit=lambda a: a["body"].__setitem__("time", "x")))[1])
        self.assertIn("time", p["ext"]["dev.handsal/act"]["body"])
        p = json.loads(self.parts(fx.tip_statement(
            payload_edit=lambda x: x.__setitem__("performer_id", "alice")))[1])
        self.assertEqual(p["performer_id"], "alice")
        raw = self.parts(fx.tip_statement(raw_edit=lambda b: b.replace(b'"next":"no"',
                                                                      b'"next":false')))[1]
        self.assertIn(b'"next":false', raw)
        p = json.loads(self.parts(fx.tip_statement(method="local:handsal.request.approve"))[1])
        self.assertEqual(p["method"], "local:handsal.request.approve")


class GenesisSignOverrides(unittest.TestCase):
    """`head` and `performer` let a row sign a change under the wrong head or person (GP-15, GP-19)."""

    def setUp(self):
        self.fx = base.Fixtures(PROFILE)
        self.change = {**self.fx.org, "org": self.fx.org_id, "prev": self.fx.org_id,
                       "head": self.fx.org_id}

    def act(self, jws):
        return json.loads(base._unb64u(jws.split(".")[1]))

    def test_default_names_the_document_head_and_the_signers_person(self):
        p = self.act(self.fx.genesis_sign("alice", self.change))
        self.assertEqual(p["ext"]["dev.handsal/act"]["head"],
                         {"id": self.fx.org_id, "kind": "chain"})
        self.assertEqual(p["performer_id"], "alice")

    def test_another_head_is_named_as_given(self):
        other = base.hashstr(b"another position")
        p = self.act(self.fx.genesis_sign("alice", self.change, head=other))
        self.assertEqual(p["ext"]["dev.handsal/act"]["head"], {"id": other, "kind": "chain"})
        self.assertEqual(p["inputs_hash"], base.hashstr(jcs.emit(self.change)))

    def test_no_head_leaves_the_key_out(self):
        p = self.act(self.fx.genesis_sign("alice", self.change, head=None))
        self.assertNotIn("head", p["ext"]["dev.handsal/act"])

    def test_another_performer_is_named_as_given(self):
        p = self.act(self.fx.genesis_sign("carol", self.change, performer="alice"))
        self.assertEqual(p["performer_id"], "alice")
        self.assertEqual(p["ext"]["dev.handsal/act"]["kid"], self.fx.key("carol").kid)

    def test_an_original_is_unchanged_by_the_new_defaults(self):
        jws = self.fx.genesis_sign("alice", self.fx.org)
        self.assertNotIn("head", self.act(jws)["ext"]["dev.handsal/act"])


if __name__ == "__main__":
    unittest.main()
