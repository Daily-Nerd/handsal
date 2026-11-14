"""The generator's own model of `render` (RN-01 to RN-12), checked against literal text.

The model authors the anchors of the `rnd/*` vectors. It is written from the spec
and shares no code with any checker (CF-06). These tests state the expected text
as literal lines, composing only the short forms with a helper written here, so
the model cannot agree with itself by construction.
"""
import json
import unittest

from lib import base, epochs, forge, inputs, keys, render

FX = base.Fixtures(base.fixture_profile())
AGREE2 = keys.thumbprint(FX.key("alice2", "agree").x, FX.key("alice2", "agree").y)


def h12(hashstr):
    text = hashstr[3:15]
    return " ".join((text[0:4], text[4:8], text[8:12]))


def k12(kid):
    return " ".join((kid[0:4], kid[4:8], kid[8:12]))


def payload_of(jws):
    return json.loads(forge.parts(jws)[1])


def request(jws, attachments, kid):
    p = payload_of(jws)
    return {"attachments": attachments, "kid": kid, "method": p["method"], "payload": p}


def verdict_input(kind="approve", **kw):
    jws = FX.verdict(kind, **kw)
    return jws, request(jws, {"request_b64": FX.request_b64()}, FX.key("alice").kid)


def lines(out):
    return out["text"].split("\n")


class ShortForms(unittest.TestCase):
    def test_hash12_skips_the_constant_prefix_and_groups_by_four(self):
        self.assertEqual(render.hash12("uEiABCDEFGHIJKLMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
                         "ABCD EFGH IJKL")

    def test_kid12_is_the_first_twelve_grouped_by_four(self):
        self.assertEqual(render.kid12("ABCDEFGHIJKLMNOP"), "ABCD EFGH IJKL")

    def test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four(self):
        """The separator is not a base64url character, so a `-` of the alphabet is never mistaken for it."""
        for at in range(12):
            twelve = "abcdefghijkl"[:at] + "-" + "abcdefghijkl"[at + 1:]
            for display in (render.kid12(twelve + "q" * 31), render.hash12("uEi" + twelve + "q" * 28)):
                self.assertEqual(display.split(" "), [twelve[0:4], twelve[4:8], twelve[8:12]], at)
                self.assertEqual(len(display), 14)

    def test_the_kids_seen_in_a_real_ceremony_are_not_ambiguous(self):
        self.assertEqual(render.kid12("pbubEyWn-20K" + "q" * 31), "pbub EyWn -20K")
        self.assertEqual(render.kid12("FpA-qzTN5X8O" + "q" * 31), "FpA- qzTN 5X8O")


class Verdict(unittest.TestCase):
    def test_approve_text_is_exactly_the_rn02_layout(self):
        jws, inp = verdict_input()
        p = payload_of(jws)
        act = p["ext"]["dev.handsal/act"]
        org, req = h12(act["org"]), h12(p["inputs_hash"])
        want = "\n".join([
            "APPROVE request req-00000001 (%s, 9 bytes)" % req,
            "Method: local:handsal.request.approve",
            "Org: %s" % org,
            "Signer: alice key %s" % k12(FX.key("alice").kid),
            "Request: req-00000001",
            "Recipient: alice",
            "Relay: r.example",
            "Request hash: %s" % req,
            "----- request (9 bytes, sha256 %s) -----" % req,
            "| deploy v2",
            "----- end -----",
            "Signed at: %s" % p["ts"],
            "Expires: %s" % act["expires"],
            "Head: %s" % org,
            "Sender: not proven"]) + "\n"
        out = render.render(inp)
        self.assertEqual(out["text"], want)
        self.assertEqual(out["first_line"], "APPROVE request req-00000001 (%s, 9 bytes)" % req)

    def test_reject_and_needs_info_change_only_line_one(self):
        for kind, word in (("reject", "REJECT request"), ("needs-info", "NEEDS-INFO on request")):
            _jws, inp = verdict_input(kind)
            self.assertTrue(render.render(inp)["first_line"].startswith(word + " req-00000001 ("))

    def test_a_request_id_over_twelve_characters_is_cut_to_eleven_and_a_tilde(self):
        rid = "req-" + "0" * 32
        jws = FX.approve(request_id=rid)
        out = render.render(request(jws, {"request_b64": FX.request_b64()}, FX.key("alice").kid))
        self.assertTrue(out["first_line"].startswith("APPROVE request req-0000000~ ("))
        self.assertIn("Request: " + rid, lines(out))

    def test_a_sender_attachment_changes_nothing(self):
        jws, inp = verdict_input()
        plain = render.render(inp)
        inp["attachments"]["sender"] = "mallory"
        self.assertEqual(render.render(inp), plain)
        self.assertEqual(lines(plain)[-2], "Sender: not proven")

    def test_the_text_ends_with_one_lf_and_no_blank_line(self):
        _jws, inp = verdict_input()
        text = render.render(inp)["text"]
        self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))


class RequestBlock(unittest.TestCase):
    def block(self, raw):
        jws = FX.approve(request=raw)
        out = render.render(request(jws, {"request_b64": FX.request_b64(raw)},
                                    FX.key("alice").kid))
        return out

    def body(self, out):
        ls = lines(out)
        return ls[ls.index(next(x for x in ls if x.startswith("----- request ("))) + 1:
                  ls.index("----- end -----")]

    def test_escapes_are_lowercase_hex_for_every_byte_outside_0x20_to_0x7e(self):
        got = self.body(self.block(b"a\x00\x1b\x7f\xff\xe2\x80\xae\tz\r"))
        self.assertEqual(got, ["| a\\x00\\x1b\\x7f\\xff\\xe2\\x80\\xae\\x09z\\x0d"])

    def test_a_line_that_looks_like_the_delimiter_stays_in_the_block(self):
        got = self.body(self.block(b"----- end -----"))
        self.assertEqual(got, ["| ----- end -----"])

    def test_zero_bytes_give_a_block_with_no_content_lines(self):
        self.assertEqual(self.body(self.block(b"")), [])

    def test_exactly_2048_bytes_in_32_lines_is_rendered(self):
        raw = b"\n".join([b"x" * 63] * 31 + [b"y" * 64])
        self.assertEqual(len(raw), 2048)
        self.assertEqual(len(self.body(self.block(raw))), 32)

    def test_2049_bytes_and_33_lines_are_refused(self):
        self.assertEqual(self.block(b"x" * 2049), {"error": "render_refused"})
        self.assertEqual(self.block(b"\n".join([b"x"] * 33)), {"error": "render_refused"})

    def test_the_real_request_bytes_are_the_attachment_not_the_payload(self):
        jws = FX.approve()
        out = render.render(request(jws, {"request_b64": FX.request_b64(b"other")},
                                    FX.key("alice").kid))
        self.assertEqual(out, {"error": "attachment_mismatch"})
        out = render.render(request(jws, {}, FX.key("alice").kid))
        self.assertEqual(out, {"error": "attachment_missing"})


class Refusals(unittest.TestCase):
    def test_unknown_method(self):
        _jws, inp = verdict_input()
        inp["method"] = inp["payload"]["method"] = "local:handsal.request.send"
        self.assertEqual(render.render(inp), {"error": "method_unknown"})

    def test_extra_payload_key_is_schema(self):
        _jws, inp = verdict_input()
        inp["payload"]["extra"] = "x"
        self.assertEqual(render.render(inp), {"error": "schema"})

    def test_label_with_a_quote_is_body_schema(self):
        # the signed subset cannot carry a quote (ACT-10), so the payload object is edited
        dev = FX.device_add("alice2", ("alice", "bob"))
        inp = request(dev.acts[0], {}, FX.key("alice").kid)
        inp["payload"]["ext"]["dev.handsal/act"]["body"]["label"] = 'a"b'
        self.assertEqual(render.render(inp), {"error": "body_schema"})


class DeviceAddAndEndorse(unittest.TestCase):
    def setUp(self):
        self.dev = FX.device_add("alice2", ("alice", "bob"))
        self.p = payload_of(self.dev.acts[0])

    def test_device_add_text(self):
        kid = FX.key("alice2").kid
        out = render.render(request(self.dev.acts[0], {}, FX.key("alice").kid))
        want = "\n".join([
            "Add device %s (apple-se-bio) to alice" % k12(kid),
            "Method: local:handsal.device.add",
            "Org: %s" % h12(FX.org_id),
            "Signer: alice key %s" % k12(FX.key("alice").kid),
            "Person: alice",
            "New device: %s" % kid,
            "Agree key: %s" % AGREE2,
            "Class: apple-se-bio",
            "Label: alice2 se-bio",
            "Link code: %s" % h12(base.hashstr(b"link-code/alice2")),
            "Signed at: %s" % self.p["ts"],
            "Parent: %s" % h12(FX.org_id)]) + "\n"
        self.assertEqual(out["text"], want)

    def test_endorse_shows_the_endorsed_id_and_the_method_lines(self):
        inp = request(self.dev.acts[1], {"act": self.dev.acts[0]}, FX.key("bob").kid)
        out = render.render(inp)
        ep = payload_of(self.dev.acts[1])
        kid = FX.key("alice2").kid
        want = "\n".join([
            "Endorse: Add device %s (apple-se-bio) to alice" % k12(kid),
            "Method: local:handsal.act.endorse",
            "Org: %s" % h12(FX.org_id),
            "Signer: bob key %s" % k12(FX.key("bob").kid),
            "Endorsed act: %s" % self.dev.id,
            "Person: alice",
            "New device: %s" % kid,
            "Agree key: %s" % AGREE2,
            "Class: apple-se-bio",
            "Label: alice2 se-bio",
            "Link code: %s" % h12(base.hashstr(b"link-code/alice2")),
            "Signed at: %s" % ep["ts"],
            "Parent: %s" % h12(self.dev.id),
            "Head: %s" % h12(FX.org_id)]) + "\n"
        self.assertEqual(out["text"], want)

    def test_endorse_line_one_is_cut_at_70_bytes_and_a_tilde(self):
        member = "m" * 32
        mem = FX.member_add("dave", ("alice", "bob"), role="r" * 32, member=member)
        inp = request(mem.acts[1], {"act": mem.acts[0]}, FX.key("bob").kid)
        first = render.render(inp)["first_line"]
        self.assertEqual(first, "Endorse: Add device %s as member mmmmmmmmmmm~ (rrrrrrrrrrr~)"
                         % k12(FX.key("dave").kid))
        # the cut applies once a line 1 is longer than 70 bytes
        self.assertEqual(render.cut("a" * 71, 70), "a" * 70 + "~")
        self.assertEqual(render.cut("a" * 70, 70), "a" * 70)

    def test_endorse_attachment_of_another_act_is_a_mismatch_and_none_is_missing(self):
        other = FX.device_add("alice3", ("alice", "bob"))
        inp = request(self.dev.acts[1], {"act": other.acts[0]}, FX.key("bob").kid)
        self.assertEqual(render.render(inp), {"error": "attachment_mismatch"})
        inp = request(self.dev.acts[1], {}, FX.key("bob").kid)
        self.assertEqual(render.render(inp), {"error": "attachment_missing"})

    def test_a_primary_endorsement_with_a_heads_attachment_is_a_mismatch(self):
        inp = request(self.dev.acts[1], {"act": self.dev.acts[0], "heads": [self.dev.acts[0]]},
                      FX.key("bob").kid)
        self.assertEqual(render.render(inp), {"error": "attachment_mismatch"})


class Resolve(unittest.TestCase):
    def setUp(self):
        self.a = FX.device_add("alice2", ("alice", "bob"))
        self.b = FX.device_add("alice3", ("alice", "bob"))
        cands = sorted([self.a.id, self.b.id])
        self.keep, self.lose = (self.a, self.b) if cands[0] == self.a.id else (self.b, self.a)
        self.resolve = FX.chain_resolve(("alice", "bob"), candidates=cands, choose=self.a.id,
                                        heads=[self.b.id])
        self.att = {"candidates": [self.a.acts[0], self.b.acts[0]], "heads": [self.b.acts[0]]}

    def inp(self, att=None):
        return request(self.resolve.acts[0], self.att if att is None else att,
                       FX.key("alice").kid)

    def test_resolve_text(self):
        out = render.render(self.inp())
        p = payload_of(self.resolve.acts[0])
        body = p["ext"]["dev.handsal/act"]["body"]
        line1 = lambda d, n: ("Add device %s (apple-se-bio) to alice" % k12(FX.key(n).kid))
        names = {self.a.id: ("alice2", self.a), self.b.id: ("alice3", self.b)}
        cand_lines = []
        for cid in body["candidates"]:
            mark = "  > " if cid == self.a.id else "    "
            cand_lines.append("%s%s %s" % (mark, h12(cid), line1(None, names[cid][0])))
        want = "\n".join(
            ["Resolve fork, keep: " + line1(None, "alice2"),
             "Method: local:handsal.chain.resolve",
             "Org: %s" % h12(FX.org_id),
             "Signer: alice key %s" % k12(FX.key("alice").kid),
             "Fork parent: %s" % FX.org_id,
             "Choose: %s" % self.a.id,
             "Candidates:"] + cand_lines +
            ["Heads:", "  - %s %s" % (h12(self.b.id), line1(None, "alice3")),
             "Overrides: none",
             "Signed at: %s" % p["ts"],
             "Parent: %s" % h12(FX.org_id)]) + "\n"
        self.assertEqual(out["text"], want)

    def test_missing_heads_list_is_missing_and_a_missing_id_is_not_this_code(self):
        no_heads = {"candidates": self.att["candidates"]}
        self.assertEqual(render.render(self.inp(no_heads)), {"error": "attachment_missing"})
        short = {"candidates": self.att["candidates"][:1], "heads": self.att["heads"]}
        # RN-09: a missing id inside a present list is attachment_mismatch
        self.assertEqual(render.render(self.inp(short)), {"error": "attachment_mismatch"})

    def test_an_extra_or_duplicate_jws_is_a_mismatch(self):
        extra = {"candidates": self.att["candidates"] + [self.a.acts[0]], "heads": self.att["heads"]}
        self.assertEqual(render.render(self.inp(extra)), {"error": "attachment_mismatch"})


class Wrapping(unittest.TestCase):
    """RN-02: a line over 100 bytes is its first 98 bytes, then `+ ` and at most 98 bytes each."""

    def test_a_253_character_relay_is_shown_in_full_over_three_lines(self):
        host = "r" * 253
        jws = FX.approve(relay=host)
        out = render.render(request(jws, {"request_b64": FX.request_b64()}, FX.key("alice").kid))
        ls = lines(out)
        at = ls.index(("Relay: " + host)[:98])
        self.assertEqual(ls[at + 1], "+ " + ("Relay: " + host)[98:196])
        self.assertEqual(ls[at + 2], "+ " + ("Relay: " + host)[196:])
        self.assertEqual(len(ls[at + 2]), 2 + 64)
        self.assertTrue(ls[at + 3].startswith("Request hash: "))

    def test_a_line_of_exactly_100_bytes_is_not_wrapped(self):
        host = "r" * 93  # "Relay: " is 7 bytes
        jws = FX.approve(relay=host)
        out = render.render(request(jws, {"request_b64": FX.request_b64()}, FX.key("alice").kid))
        self.assertIn("Relay: " + host, lines(out))


class RequestBlockLayout(unittest.TestCase):
    """RN-05: `|+` continuation, no split escape, the final LF, 32 content lines."""

    def block(self, raw):
        jws = FX.approve(request=raw)
        out = render.render(request(jws, {"request_b64": FX.request_b64(raw)},
                                    FX.key("alice").kid))
        if "error" in out:
            return out
        ls = lines(out)
        start = next(i for i, x in enumerate(ls) if x.startswith("----- request ("))
        return ls[start + 1:ls.index("----- end -----")]

    def test_a_300_byte_line_is_a_pipe_line_then_pipe_plus_lines_of_96(self):
        got = self.block(b"x" * 300)
        self.assertEqual(got, ["| " + "x" * 96, "|+" + "x" * 96, "|+" + "x" * 96, "|+" + "x" * 12])

    def test_exactly_96_escaped_bytes_stay_on_one_line(self):
        self.assertEqual(self.block(b"y" * 96), ["| " + "y" * 96])

    def test_an_escape_is_never_split_across_lines(self):
        got = self.block(b"x" * 95 + "é".encode("utf-8"))
        self.assertEqual(got, ["| " + "x" * 95, "|+\\xc3\\xa9"])

    def test_an_escape_that_ends_exactly_at_96_stays(self):
        got = self.block(b"x" * 91 + b"\xff" + b"z")
        self.assertEqual(got, ["| " + "x" * 91 + "\\xffz"])

    def test_a_final_lf_ends_the_last_line_and_starts_no_other(self):
        self.assertEqual(self.block(b"a\n"), ["| a"])
        self.assertEqual(self.block(b"\n"), ["| "])
        self.assertEqual(self.block(b"a\n\n"), ["| a", "| "])
        self.assertEqual(self.block(b"a\nb"), ["| a", "| b"])

    def test_the_32_line_limit_counts_continuation_lines(self):
        self.assertEqual(len(self.block(b"\n".join([b"x"] * 30 + [b"y" * 100]))), 32)
        self.assertEqual(self.block(b"\n".join([b"x"] * 31 + [b"y" * 100])),
                         {"error": "render_refused"})

    def test_a_record_body_block_has_the_same_layout(self):
        raw = b"z" * 200
        jws = FX.record_promote(record=raw)
        out = render.render(request(jws, {"record_body_b64": FX.request_b64(raw)},
                                    FX.key("alice").kid))
        ls = lines(out)
        start = next(i for i, x in enumerate(ls) if x.startswith("----- record body ("))
        self.assertEqual(ls[start + 1:start + 4], ["| " + "z" * 96, "|+" + "z" * 96, "|+" + "z" * 8])
        self.assertEqual(ls[start + 4], "----- end -----")


def _thumb(doc_device, which="agree"):
    return keys.thumbprint(doc_device[which]["x"], doc_device[which]["y"])


def device_lines(entry):
    return ["  - %s of %s" % (entry["kid"], entry["person"]), "    Class: " + entry["class"],
            "    Label: " + entry["label"], "    Agree: " + _thumb(entry)]


POLICY_NONE = [
    "Policy:", "  Roles: maintainer,member",
    "  Rule chain.resolve: 2 of maintainer", "  Rule device.remove: 2 of maintainer",
    "  Rule genesis.change: 2 of maintainer", "  Rule member.add: 2 of maintainer",
    "  Class apple-se-bio: biometric_only", "  Clock skew: 300 s", "  Max validity: 604800 s",
    "  Max view age: 86400 s", "  Witness: none"]


class GenesisOriginal(unittest.TestCase):
    """RN-04, RN-08: an original renders in full, with the policy and the document hash."""

    def render_of(self, doc, signer="alice"):
        jws = FX.genesis_sign(signer, doc)
        return payload_of(jws), render.render(request(jws, {"document": doc}, FX.key(signer).kid))

    def test_text_is_exactly_the_rn04_original_layout(self):
        doc = FX.org
        p, out = self.render_of(doc)
        want = ["Sign genesis of example (%s): 3 members, 3 devices" % h12(FX.org_id),
                "Method: local:handsal.genesis.sign",
                "Org: %s" % h12(FX.org_id),
                "Signer: alice key %s" % k12(FX.key("alice").kid),
                "Org name: example", "Profile: " + doc["profile"], "Members:",
                "  - alice maintainer", "  - bob maintainer", "  - carol maintainer", "Devices:"]
        for entry in doc["devices"]:
            want += device_lines(entry)
        want += POLICY_NONE + ["Document hash: " + h12(FX.org_id), "Signed at: " + p["ts"]]
        self.assertEqual(lines(out), want + [""])
        self.assertEqual(out["first_line"], want[0])

    def test_a_relay_witness_adds_its_key_and_age(self):
        p, out = self.render_of(FX.wit_org)
        ls = lines(out)
        at = ls.index("  Witness: relay")
        self.assertEqual(ls[at + 1:at + 3], ["  Relay key: " + FX.relay.kid, "  Max tip age: 3600 s"])
        self.assertEqual(ls[at + 3], "Document hash: " + h12(FX.wit_org_id))

    def test_a_long_name_is_cut_in_line_one_and_full_in_the_method_lines(self):
        doc = inputs.derive(FX.org, lambda d: d.update(name="n" * 24))
        p, out = self.render_of(doc)
        self.assertEqual(out["first_line"], "Sign genesis of nnnnnnnnnnn~ (%s): 3 members, 3 devices"
                         % h12(inputs.doc_id(doc)))
        self.assertIn("Org name: " + "n" * 24, lines(out))

    def test_a_document_over_72_lines_is_refused(self):
        members, devices = inputs.synthetic_members(17)
        doc = inputs.derive(FX.org, lambda d: d.update(
            members=sorted(d["members"] + members, key=lambda m: m["id"]),
            devices=sorted(d["devices"] + devices, key=lambda x: x["kid"])))
        self.assertEqual(self.render_of(doc)[1], {"error": "render_refused"})


class GenesisChange(unittest.TestCase):
    """RN-10: a change renders as a difference, then the full policy and `Unchanged`."""

    def setUp(self):
        self.prev = FX.org
        # frank and grace replace carol: carry alice and bob, drop carol
        self.doc = epochs.make_change(FX, self.prev, FX.org_id, carry=("alice", "bob"),
                                      new=("frank",))
        self.jws = FX.genesis_sign("alice", self.doc)
        self.att = {"document": self.doc, "previous": self.prev}

    def out(self, att=None):
        return render.render(request(self.jws, self.att if att is None else att,
                                     FX.key("alice").kid))

    def test_text_is_exactly_the_rn10_change_layout(self):
        p = payload_of(self.jws)
        doc, prev = self.doc, self.prev
        added = [d for d in doc["devices"] if d["kid"] not in {x["kid"] for x in prev["devices"]}]
        gone = [d for d in prev["devices"] if d["kid"] not in {x["kid"] for x in doc["devices"]}]
        want = ["Change example (%s): +1/-1 dev, 2 mem, policy same" % h12(inputs.doc_id(doc)),
                "Method: local:handsal.genesis.sign",
                "Org: %s" % h12(FX.org_id),
                "Signer: alice key %s" % k12(FX.key("alice").kid),
                "Org name: example", "Profile: " + doc["profile"],
                "Previous: " + h12(FX.org_id), "Head: " + FX.org_id,
                "Members added:", "  - frank maintainer",
                "Members removed:", "  - carol maintainer",
                "Devices added:"] + device_lines(added[0]) + [
                "Devices removed:", "  - %s of %s" % (gone[0]["kid"], gone[0]["person"])] + \
            POLICY_NONE + ["Unchanged: 2 devices, 2 members", "Signed at: " + p["ts"],
                           "Head: " + h12(FX.org_id)]
        self.assertEqual(lines(self.out()), want + [""])
        self.assertEqual(self.out()["first_line"], want[0])

    def test_no_document_hash_line(self):
        self.assertFalse(any(x.startswith("Document hash") for x in lines(self.out())))

    def test_a_rename_and_a_new_policy_are_shown(self):
        doc = epochs.make_change(FX, self.prev, FX.org_id, carry=("alice", "bob", "carol"), new=(),
                                 edit=lambda d: (d.update(name="renamed"),
                                                 d["policy"]["freshness"].update(clock_skew_s="60")))
        jws = FX.genesis_sign("alice", doc)
        out = render.render(request(jws, {"document": doc, "previous": self.prev},
                                    FX.key("alice").kid))
        ls = lines(out)
        self.assertEqual(out["first_line"],
                         "Change renamed (%s): +0/-0 dev, 0 mem, policy NEW" % h12(inputs.doc_id(doc)))
        self.assertEqual(ls[4:6], ["Org name: renamed", "Profile: " + doc["profile"]])
        self.assertIn("  Clock skew: 60 s", ls)
        self.assertNotIn("Members added:", ls)
        self.assertIn("Unchanged: 3 devices, 3 members", ls)

    def test_a_role_change_counts_as_a_member_entry_and_is_listed(self):
        doc = epochs.make_change(FX, self.prev, FX.org_id, carry=("alice", "bob", "carol"),
                                 new=("frank",))
        doc = inputs.derive(doc, lambda d: d["members"][2].update(role="member"))
        jws = FX.genesis_sign("alice", doc)
        out = render.render(request(jws, {"document": doc, "previous": self.prev},
                                    FX.key("alice").kid))
        ls = lines(out)
        self.assertEqual(ls[ls.index("Role changed:") + 1], "  - carol maintainer -> member")
        self.assertIn("+1/-0 dev, 2 mem,", out["first_line"])  # frank added, carol's role changed
        self.assertIn("Unchanged: 3 devices, 2 members", ls)

    def test_the_head_must_equal_the_documents_head(self):
        jws = FX.genesis_sign("alice", self.doc, head=FX.wit_org_id)
        out = render.render(request(jws, self.att, FX.key("alice").kid))
        self.assertEqual(out, {"error": "attachment_mismatch"})


class GenesisAttachments(unittest.TestCase):
    """RN-09: absent is missing; a bound document that is not valid alone is a mismatch."""

    def test_an_absent_document_or_previous_is_missing(self):
        change = inputs.change_doc(FX)
        jws = FX.genesis_sign("alice", change)
        self.assertEqual(render.render(request(jws, {}, FX.key("alice").kid)),
                         {"error": "attachment_missing"})
        self.assertEqual(render.render(request(jws, {"document": change}, FX.key("alice").kid)),
                         {"error": "attachment_missing"})

    def test_a_bound_document_that_is_not_valid_is_a_mismatch(self):
        bad = inputs.derive(FX.org, lambda d: d["members"][0].update(role="unlisted"))
        jws = FX.genesis_sign("alice", bad)
        self.assertEqual(render.render(request(jws, {"document": bad}, FX.key("alice").kid)),
                         {"error": "attachment_mismatch"})

    def test_a_bound_previous_that_is_not_valid_is_a_mismatch(self):
        bad = inputs.derive(FX.org, lambda d: d["members"][0].update(role="unlisted"))
        change = inputs.change_doc(FX, previous=bad)
        jws = FX.genesis_sign("alice", change)
        self.assertEqual(
            render.render(request(jws, {"document": change, "previous": bad}, FX.key("alice").kid)),
            {"error": "attachment_mismatch"})

    def test_a_change_without_a_head_is_a_schema_defect_before_previous_is_read(self):
        # RN-09 Order of checks: the form of the act object, head presence included, comes before
        # the attachments after `document`
        change = inputs.change_doc(FX)
        jws = FX.genesis_sign("alice", change, head=None)
        self.assertEqual(render.render(request(jws, {"document": change}, FX.key("alice").kid)),
                         {"error": "schema"})

    def test_an_original_with_a_head_is_a_schema_defect(self):
        jws = FX.genesis_sign("alice", FX.org, head=FX.wit_org_id)
        self.assertEqual(render.render(request(jws, {"document": FX.org}, FX.key("alice").kid)),
                         {"error": "schema"})

    def test_a_number_as_the_endorsed_act_is_a_mismatch(self):
        dev = FX.device_add("alice2", ("alice", "bob"))
        self.assertEqual(render.render(request(dev.acts[1], {"act": 7}, FX.key("bob").kid)),
                         {"error": "attachment_mismatch"})


class OrderInsideAttachments(unittest.TestCase):
    """RN-09 Order of checks: each attachment is read and bound before the next is looked at."""

    def test_an_endorsement_whose_attached_resolve_does_not_bind_is_a_mismatch_not_missing_heads(self):
        a = FX.device_add("alice2", ("alice", "bob"))
        b = FX.device_add("bob2", ("alice", "bob"))
        resolve = FX.chain_resolve(("alice", "bob"), candidates=sorted([a.id, b.id]), choose=a.id,
                                   heads=[b.id])
        other = FX.chain_resolve(("alice", "bob"), candidates=sorted([a.id, b.id]), choose=b.id,
                                 heads=[a.id])
        self.assertNotEqual(resolve.id, other.id)
        out = render.render(request(resolve.acts[1], {"act": other.acts[0]}, FX.key("bob").kid))
        self.assertEqual(out, {"error": "attachment_mismatch"})

    def test_a_resolve_whose_candidates_do_not_bind_is_a_mismatch_not_missing_heads(self):
        a = FX.device_add("alice2", ("alice", "bob"))
        b = FX.device_add("bob2", ("alice", "bob"))
        resolve = FX.chain_resolve(("alice", "bob"), candidates=sorted([a.id, b.id]), choose=a.id,
                                   heads=[b.id])
        out = render.render(request(resolve.acts[0], {"candidates": [a.acts[0]]}, FX.key("alice").kid))
        self.assertEqual(out, {"error": "attachment_mismatch"})


if __name__ == "__main__":
    unittest.main()
