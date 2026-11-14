"""T3.48 render core (RN-01, RN-02, RN-03, RN-06): the short forms, the layout frame, line 1 and the refusals.

Everything here reads signed bytes only. Attachments, method lines and genesis come later (T3.49 to T3.51).
"""
import string
import unittest

from handsal_check import encoding, errors, registry, render

from . import test_envelope as te

REG = registry.load()
H = encoding.hashstr(b"x")
LONG = "abcdefghijklmnopqrstuvwxyz0123456789"


def frame(**over):
    args = dict(first="line one", method="local:handsal.request.approve", org=te.ORG, performer="alice",
                kid=te.KID, body=["Request: req-00000001"], ts="2026-11-08T11:59:00Z", expires=None,
                parent=None, head=None, sender=False)
    args.update(over)
    return render.frame(**args)


def refused(fn, *args):
    try:
        fn(*args)
    except errors.Refused as err:
        return err.code
    return None


class ShortForms(unittest.TestCase):
    def test_hash12_skips_the_constant_prefix_and_groups(self):
        h = "uEi" + "ABCDEFGHIJKL" + "MNOPQRSTUV" + "W" * 21
        self.assertEqual(render.hash12(h), "ABCD EFGH IJKL")

    def test_kid12_is_the_first_twelve_characters_grouped(self):
        self.assertEqual(render.kid12("ABCDEFGHIJKLMNOP" + "q" * 27), "ABCD EFGH IJKL")

    def test_the_group_separator_is_never_a_character_of_the_grouped_alphabet(self):
        """Two people compare these aloud. base64url holds `-`, so a `-` separator made `pbub-EyWn--20K`
        (a kid starting `pbubEyWn-20K`) read as three groups of another size."""
        self.assertNotIn(render.GROUP_SEPARATOR, string.ascii_letters + string.digits + "-_")

    def test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four(self):
        for at in range(12):
            twelve = "abcdefghijkl"[:at] + "-" + "abcdefghijkl"[at + 1:]
            for display, source in ((render.kid12(twelve + "q" * 31), twelve),
                                    (render.hash12("uEi" + twelve + "q" * 28), twelve)):
                self.assertEqual(display.split(render.GROUP_SEPARATOR), [source[0:4], source[4:8], source[8:12]], at)
                self.assertEqual(display.replace(render.GROUP_SEPARATOR, ""), source)

    def test_the_kids_seen_in_a_real_ceremony_are_not_ambiguous(self):
        self.assertEqual(render.kid12("pbubEyWn-20K" + "q" * 31), "pbub EyWn -20K")
        self.assertEqual(render.kid12("FpA-qzTN5X8O" + "q" * 31), "FpA- qzTN 5X8O")

    def test_a_free_field_over_12_characters_is_cut_to_11_and_a_tilde(self):
        self.assertEqual(render.cut12("twelve-chars"), "twelve-chars")
        self.assertEqual(render.cut12("thirteen-char"), "thirteen-ch~")
        self.assertEqual(render.cut12(LONG), LONG[:11] + "~")

    def test_cut_to_a_byte_budget(self):
        self.assertEqual(render.cut_to("a" * 59, 59), "a" * 59)
        self.assertEqual(render.cut_to("a" * 60, 59), "a" * 59 + "~")


class Wrap(unittest.TestCase):
    def test_a_line_of_100_bytes_stays(self):
        self.assertEqual(render.wrap("x" * 100), ["x" * 100])

    def test_a_longer_line_wraps_into_98_byte_segments_with_a_plus_prefix(self):
        self.assertEqual(render.wrap("x" * 101), ["x" * 98, "+ xxx"])
        self.assertEqual(render.wrap("y" * 196 + "z"), ["y" * 98, "+ " + "y" * 98, "+ z"])

    def test_every_signed_byte_stays_visible(self):
        host = "a" * 253
        out = render.wrap("Relay: " + host)
        self.assertEqual("".join(out[:1] + [seg[2:] for seg in out[1:]]), "Relay: " + host)
        self.assertTrue(all(len(seg) <= 100 for seg in out))


class Frame(unittest.TestCase):
    def test_layout_order_for_a_verdict(self):
        got = frame(expires="2026-11-08T13:00:00Z", parent=H, head=H, sender=True)
        self.assertEqual(got.text.split("\n"), [
            "line one", "Method: local:handsal.request.approve", "Org: %s" % render.hash12(te.ORG),
            "Signer: alice key %s" % render.kid12(te.KID), "Request: req-00000001",
            "Signed at: 2026-11-08T11:59:00Z", "Expires: 2026-11-08T13:00:00Z",
            "Parent: %s" % render.hash12(H), "Head: %s" % render.hash12(H), "Sender: not proven", ""])
        self.assertEqual(got.first_line, "line one")

    def test_optional_lines_are_absent_when_their_field_is(self):
        lines = frame().text.split("\n")
        self.assertEqual([x.split(":")[0] for x in lines],
                         ["line one", "Method", "Org", "Signer", "Request", "Signed at", ""])

    def test_one_final_lf_and_no_trailing_blank_line(self):
        text = frame().text
        self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))

    def test_output_is_ascii_and_has_no_cr(self):
        text = frame().text
        self.assertTrue(text.isascii() and "\r" not in text)

    def test_the_same_input_twice_is_the_same_bytes(self):
        self.assertEqual(frame(), frame())

    def test_no_org_name_is_ever_shown_here(self):
        self.assertNotIn("name", frame().text.lower())

    def test_a_long_line_wraps_inside_the_frame(self):
        text = frame(body=["Relay: " + "r" * 253]).text
        self.assertTrue(all(len(line) <= 100 for line in text.split("\n")))
        self.assertIn("\n+ ", text)

    def test_72_lines_fit_and_73_are_render_refused(self):
        fixed = 1 + 3 + 1   # line 1, Method, Org, Signer, Signed at
        self.assertEqual(len(frame(body=["b"] * (72 - fixed)).text.split("\n")), 73)   # 72 lines and the final LF
        with self.assertRaises(errors.Refused) as ctx:
            frame(body=["b"] * (73 - fixed))
        self.assertEqual(ctx.exception.code, "render_refused")

    def test_wrapped_lines_count_toward_the_72(self):
        frame(body=["b"] * (72 - 5 - 2) + ["w" * 101])   # one wrapped line is two lines: 72 in all, fits
        with self.assertRaises(errors.Refused):
            frame(body=["b"] * (72 - 5 - 1) + ["w" * 101])


def payload_of(name):
    return {"approve": te.verdict, "device_add": te.device_add, "promote": te.promote,
            "endorse": te.endorse}[name]()


def act(payload):
    return payload["ext"]["dev.handsal/act"]


FACTS = render.Facts(raw=b"deploy v2", summary="Sign genesis of X (AAAA-BBBB-CCCC): 3 members, 3 devices",
                     candidates={}, heads={}, endorsed_line1="Add device AAAA-BBBB-CCCC (apple-se-bio) to alice",
                     endorsed_lines=[], genesis=None)


class FirstLine(unittest.TestCase):
    def line(self, payload, facts=FACTS):
        return render.first_line(payload["method"], payload, facts)

    def test_device_add(self):
        p = te.device_add()
        self.assertEqual(self.line(p), "Add device %s (apple-se-bio) to alice" % render.kid12(te.KEYS["alice2.sign"]["kid"]))

    def test_device_remove(self):
        p = te.edit(te.device_add(), ["method"], "local:handsal.device.remove")
        p = te.edit(p, te.ACT + ("body",), {"kid": te.KEYS["bob.sign"]["kid"], "person": "bob"})
        self.assertEqual(self.line(p), "Remove device %s of bob" % render.kid12(te.KEYS["bob.sign"]["kid"]))

    def test_member_add(self):
        body = {"device": {"agree": te.point("alice2.agree"), "class": "apple-se-bio", "kid": te.KEYS["alice2.sign"]["kid"],
                           "label": "x", "sign": te.point("alice2.sign")}, "link_code_hash": H, "member": "dave", "role": "member"}
        p = te.edit(te.edit(te.device_add(), ["method"], "local:handsal.member.add"), te.ACT + ("body",), body)
        self.assertEqual(self.line(p), "Add device %s as member dave (member)" % render.kid12(te.KEYS["alice2.sign"]["kid"]))

    def test_verdicts_share_the_tail_and_differ_in_the_verb(self):
        h12 = render.hash12(te.H)
        tail = "request req-00000001 (%s, 9 bytes)" % h12
        for method, verb in (("approve", "APPROVE"), ("reject", "REJECT"), ("needs-info", "NEEDS-INFO on")):
            p = te.verdict("local:handsal.request." + method)
            self.assertEqual(self.line(p), "%s %s" % (verb, tail))

    def test_record_promote(self):
        self.assertEqual(self.line(te.promote()),
                         "Promote record rec-1 (%s, 9 bytes)" % render.hash12(te.H))

    def test_genesis_sign_takes_its_summary_from_the_genesis_module(self):
        self.assertEqual(self.line(te.genesis_sign(False)), FACTS.summary)

    def test_endorse_cuts_the_endorsed_line_to_70_bytes_and_a_tilde(self):
        self.assertEqual(self.line(te.endorse()), "Endorse: " + FACTS.endorsed_line1)
        long = FACTS._replace(endorsed_line1="L" * 80)
        got = self.line(te.endorse(), long)
        self.assertEqual(got, "Endorse: " + "L" * 70 + "~")
        self.assertEqual(len(got), 80)

    def test_resolve_keeps_the_chosen_candidate_cut_to_59_bytes(self):
        chosen = encoding.hashstr(b"chosen")
        p = te.verdict("local:handsal.chain.resolve")
        p["ext"] = {"dev.handsal/act": {"body": {"candidates": sorted([chosen, H]), "choose": chosen, "heads": [H],
                                                   "overrides": []}, "kid": te.KID, "org": te.ORG}}
        facts = FACTS._replace(candidates={chosen: "C" * 80, H: "d"})
        got = self.line(p, facts)
        self.assertEqual(got, "Resolve fork, keep: " + "C" * 59 + "~")
        self.assertEqual(len(got), 80)
        self.assertEqual(self.line(p, FACTS._replace(candidates={chosen: "short", H: "d"})), "Resolve fork, keep: short")

    def test_every_template_is_bounded_by_80_bytes_at_maximum_field_lengths(self):
        big = "z" * 32
        facts = FACTS._replace(raw=b"x" * 2048, endorsed_line1="E" * 80)
        p = te.verdict()
        act(p)["request_id"] = "r" * 36
        for method in ("approve", "reject", "needs-info"):
            q = te.edit(p, ["method"], "local:handsal.request." + method)
            self.assertLessEqual(len(self.line(q, facts)), 80)
        r = te.promote()
        act(r)["body"]["record_id"] = big
        self.assertLessEqual(len(self.line(r, facts)), 80)
        d = te.device_add()
        act(d)["body"].update({"person": big, "class": "c" * 32})
        self.assertLessEqual(len(self.line(d, facts)), 80)
        self.assertLessEqual(len(self.line(te.endorse(), facts)), 80)

    def test_a_request_id_of_36_characters_shows_11_and_a_tilde(self):
        p = te.verdict()
        act(p)["request_id"] = LONG
        self.assertIn("request %s (" % (LONG[:11] + "~"), self.line(p))


class Input(unittest.TestCase):
    GOOD = {"attachments": {}, "kid": te.KID, "method": "local:handsal.request.approve", "payload": te.verdict()}

    def test_a_well_formed_input(self):
        got = render.parse_input(self.GOOD)
        self.assertEqual((got.kid, got.method), (te.KID, "local:handsal.request.approve"))

    def test_every_mistyped_or_missing_input_is_malformed(self):
        cases = [None, [], {}, {**self.GOOD, "extra": 1}, {**self.GOOD, "attachments": []}, {**self.GOOD, "kid": 1},
                 {**self.GOOD, "method": None}, {**self.GOOD, "payload": []}]
        cases += [{k: v for k, v in self.GOOD.items() if k != key} for key in self.GOOD]
        for case in cases:
            with self.assertRaises(errors.Malformed, msg=repr(case)):
                render.parse_input(case)


class Refusals(unittest.TestCase):
    def check(self, payload, method=None, head_present=None, kid=te.KID):
        method = method or payload["method"]
        try:
            render.check_envelope(payload, method, REG)
            render.check_act(payload, kid, REG, head_present)
        except errors.Refused as err:
            return err.code
        return None

    def test_a_valid_payload_passes(self):
        self.assertIsNone(self.check(te.verdict()))
        self.assertIsNone(self.check(te.promote()))
        self.assertIsNone(self.check(te.device_add()))

    def test_an_extra_key_is_schema(self):
        p = te.verdict()
        p["extra"] = 1
        self.assertEqual(self.check(p, "local:handsal.request.approve"), "schema")

    def test_an_unknown_method_is_method_unknown(self):
        p = te.verdict("local:handsal.nothing")
        self.assertEqual(self.check(p), "method_unknown")

    def test_the_method_input_must_be_the_payloads(self):
        self.assertEqual(self.check(te.verdict(), "local:handsal.request.reject"), "schema")

    def test_an_act_object_defect_is_schema_and_a_body_defect_is_body_schema(self):
        self.assertEqual(self.check(te.edit(te.verdict(), te.ACT + ("extra",), "x")), "schema")
        self.assertEqual(self.check(te.edit(te.device_add(), te.ACT + ("body", "label"), 'a"b')), "body_schema")

    def test_the_header_kid_must_be_the_act_kid(self):
        self.assertEqual(self.check(te.verdict(), kid=te.KEYS["bob.sign"]["kid"]), "schema")

    def test_a_resolve_must_choose_one_of_its_candidates(self):
        chosen = encoding.hashstr(b"chosen")
        body = {"candidates": sorted([H, encoding.hashstr(b"y")]), "choose": chosen, "heads": [H], "overrides": []}
        p = te.verdict("local:handsal.chain.resolve")
        p["ext"] = {"dev.handsal/act": {"body": body, "kid": te.KID, "org": te.ORG}}
        p["parent_receipt_hash"] = H
        self.assertEqual(self.check(p), "body_schema")


if __name__ == "__main__":
    unittest.main()
