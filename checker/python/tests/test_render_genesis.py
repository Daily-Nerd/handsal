"""T3.50 genesis rendering (RN-04, RN-08, RN-10): an original in full, a change as a difference, and the
size bound the fold asks of the same render function (GP-15 step 5)."""
import copy
import unittest

from handsal_check import encoding, errors, genesis, profiles, render, render_genesis

from .genesis_fixtures import KEYS, change, device, edit, org as make_org, policy, relay_witness

PROFILES = profiles.load()
FIXTURE = PROFILES.fixture
HEX = render.hash12


def thumb(doc_device):
    return encoding.thumbprint(doc_device["agree"]["x"], doc_device["agree"]["y"])


def device_lines(entry):
    return ["  - %s of %s" % (entry["kid"], entry["person"]), "    Class: " + entry["class"],
            "    Label: " + entry["label"], "    Agree: " + thumb(entry)]


POLICY_LINES = [
    "Policy:", "  Roles: maintainer,member",
    "  Rule chain.resolve: 2 of maintainer", "  Rule device.remove: 2 of maintainer",
    "  Rule genesis.change: 2 of maintainer", "  Rule member.add: 2 of maintainer",
    "  Class apple-se-bio: biometric_only",
    "  Clock skew: 300 s", "  Max validity: 604800 s", "  Max view age: 86400 s",
    "  Relays: r.example",
    "  Witness: none"]


class Original(unittest.TestCase):
    DOC = make_org(FIXTURE)

    def test_it_lists_every_member_device_and_the_full_policy(self):
        doc = self.DOC
        expected = ["Org name: ORG", "Profile: " + FIXTURE, "Members:"]
        expected += ["  - %s %s" % (m["id"], m["role"]) for m in doc["members"]]
        expected.append("Devices:")
        for entry in doc["devices"]:
            expected += device_lines(entry)
        expected += POLICY_LINES
        expected.append("Document hash: " + HEX(genesis.doc_hash(doc)))
        self.assertEqual(render_genesis.lines(doc, None), expected)

    def test_summary_counts_members_and_devices(self):
        doc = self.DOC
        self.assertEqual(render_genesis.summary(doc, None),
                         "Sign genesis of ORG (%s): 3 members, 3 devices" % HEX(genesis.doc_hash(doc)))

    def test_class_is_on_its_own_line_per_device(self):
        text = "\n".join(render_genesis.lines(self.DOC, None))
        self.assertEqual(text.count("    Class: apple-se-bio"), 3)

    def test_the_witness_lines_name_the_relay_key_and_the_age(self):
        doc = make_org(FIXTURE, pol=policy(witness=relay_witness("3600")))
        got = render_genesis.lines(doc, None)
        i = got.index("  Witness: relay")
        self.assertEqual(got[i:i + 3], ["  Witness: relay", "  Relay key: " + KEYS["relay-fixture"]["kid"],
                                        "  Max tip age: 3600 s"])

    def test_the_relays_line_is_none_or_the_hosts_joined_by_commas(self):   # RN-04, RN-10
        for relays, line in (((), "  Relays: none"), (("r.example",), "  Relays: r.example"),
                             (("r.example", "s.example"), "  Relays: r.example,s.example")):
            got = render_genesis.lines(make_org(FIXTURE, pol=policy(relays=relays)), None)
            i = got.index("  Max view age: 86400 s")
            self.assertEqual(got[i + 1:i + 3], [line, "  Witness: none"], relays)

    def test_the_relays_line_sits_between_the_freshness_and_the_witness_lines(self):
        doc = make_org(FIXTURE, pol=policy(witness=relay_witness("3600")))
        got = render_genesis.lines(doc, None)
        self.assertEqual(got[got.index("  Max view age: 86400 s") + 1], "  Relays: r.example")
        self.assertLess(got.index("  Relays: r.example"), got.index("  Witness: relay"))

    def test_the_name_is_cut_in_line_1_but_whole_in_the_body(self):
        doc = make_org(FIXTURE, name="A" * 24)
        self.assertEqual(render_genesis.summary(doc, None),
                         "Sign genesis of %s (%s): 3 members, 3 devices" % ("A" * 11 + "~", HEX(genesis.doc_hash(doc))))
        self.assertEqual(render_genesis.lines(doc, None)[0], "Org name: " + "A" * 24)

    def test_multi_rule_roles_are_joined_in_the_document_order(self):
        doc = make_org(FIXTURE, pol=policy(rule_roles=("maintainer", "member")))
        self.assertIn("  Rule member.add: 2 of maintainer,member", render_genesis.lines(doc, None))


PREV = make_org(FIXTURE)
PREV_ID = genesis.doc_hash(PREV)
HEAD = encoding.hashstr(b"head")


def make_change(people=("alice", "bob", "carol"), devices=None, pol=None, name="ORG"):
    return change(FIXTURE, PREV_ID, PREV_ID, HEAD, people=people, devices=devices, pol=pol, name=name)


class Change(unittest.TestCase):
    def test_an_unchanged_document_is_all_unchanged(self):
        doc = make_change()
        self.assertEqual(render_genesis.summary(doc, PREV),
                         "Change ORG (%s): +0/-0 dev, 0 mem, policy same" % HEX(genesis.doc_hash(doc)))
        got = render_genesis.lines(doc, PREV)
        self.assertEqual(got[:4], ["Org name: ORG", "Profile: " + FIXTURE, "Previous: " + HEX(PREV_ID), "Head: " + HEAD])
        self.assertEqual(got[-1], "Unchanged: 3 devices, 3 members")
        self.assertEqual(got[4:-1], POLICY_LINES)

    def test_added_removed_and_role_changed_members_and_devices(self):
        new_dev = device("dave")
        devices = [device("alice"), device("bob"), new_dev]   # carol's device is dropped
        doc = make_change(people=("alice", "bob", "dave"), devices=devices)
        doc["members"] = [{"id": "alice", "role": "member"}, {"id": "bob", "role": "maintainer"},
                          {"id": "dave", "role": "maintainer"}]
        got = render_genesis.lines(doc, PREV)
        carol = device("carol")
        self.assertEqual(got[4:], [
            "Members added:", "  - dave maintainer",
            "Members removed:", "  - carol maintainer",
            "Role changed:", "  - alice maintainer -> member",
            "Devices added:", *device_lines(new_dev),
            "Devices removed:", "  - %s of carol" % carol["kid"],
            *POLICY_LINES, "Unchanged: 2 devices, 1 members"])
        self.assertEqual(render_genesis.summary(doc, PREV),
                         "Change ORG (%s): +1/-1 dev, 3 mem, policy same" % HEX(genesis.doc_hash(doc)))

    def test_a_policy_byte_difference_is_NEW_and_the_full_policy_is_shown(self):
        doc = make_change(pol=policy(persons="3"))
        self.assertTrue(render_genesis.summary(doc, PREV).endswith("policy NEW"))
        self.assertIn("  Rule genesis.change: 3 of maintainer", render_genesis.lines(doc, PREV))

    def test_line_1_is_bounded_at_maximum_lengths(self):
        doc = make_change(name="N" * 24)
        doc["members"] = [{"id": "m%02d" % i, "role": "r"} for i in range(30)]
        self.assertLessEqual(len(render_genesis.summary(doc, PREV)), 80)
        original = make_org(FIXTURE, name="N" * 24)
        self.assertLessEqual(len(render_genesis.summary(original, None)), 80)

    def test_a_rename_and_a_profile_change_are_never_hidden(self):
        doc = make_change(name="RENAMED")
        doc["profile"] = encoding.hashstr(b"another profile")
        self.assertEqual(render_genesis.lines(doc, PREV)[:2],
                         ["Org name: RENAMED", "Profile: " + doc["profile"]])

    def test_the_head_is_shown_in_full(self):
        self.assertIn("Head: " + HEAD, render_genesis.lines(make_change(), PREV))


def synthetic(members, devices=3):
    """A document of the right shape with `members` members, for counting lines. The render is a pure
    function of a document that already passed GP-15 steps 1 to 4, so it needs no valid keys."""
    doc = copy.deepcopy(make_org(FIXTURE))
    doc["members"] = [{"id": "m%03d" % i, "role": "maintainer"} for i in range(members)]
    doc["devices"] = [dict(doc["devices"][0], kid="k%03d" % i, person="m000") for i in range(devices)]
    return doc


def total_lines(doc):
    got = render_genesis.render_document(doc, None, org=genesis.doc_hash(doc), performer="p",
                                         kid=KEYS["alice.sign"]["kid"], ts="2026-01-01T00:00:00Z", head=None)
    return got.text.count("\n")


class Size(unittest.TestCase):
    def test_the_render_size_is_the_line_count_of_the_signed_render(self):
        base = total_lines(synthetic(1))
        self.assertEqual(total_lines(synthetic(1 + 72 - base)), 72)

    def test_72_lines_fit_and_73_is_genesis_render_too_large(self):
        base = total_lines(synthetic(1))
        self.assertIsNone(render_genesis.render_size(synthetic(1 + 72 - base), None))
        with self.assertRaises(errors.Refused) as ctx:
            render_genesis.render_size(synthetic(1 + 73 - base), None)
        self.assertEqual(ctx.exception.code, "genesis_render_too_large")

    def test_a_change_is_measured_as_a_difference(self):
        big = synthetic(60)
        big["prev"], big["org"], big["head"] = genesis.doc_hash(big), genesis.doc_hash(big), HEAD
        # the same members again: all unchanged, so the difference stays small
        nxt = copy.deepcopy(big)
        nxt["name"] = "ORG2"
        self.assertIsNone(render_genesis.render_size(nxt, big))
        with self.assertRaises(errors.Refused):
            render_genesis.render_size(big, None)   # shown in full it does not fit

    def test_the_ordinary_fixture_documents_fit(self):
        self.assertIsNone(render_genesis.render_size(make_org(FIXTURE), None))
        self.assertIsNone(render_genesis.render_size(make_change(), PREV))


if __name__ == "__main__":
    unittest.main()
