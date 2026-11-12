"""T3.49 method lines (RN-04) and the request and record body blocks (RN-05, RN-12)."""
import unittest

from handsal_check import encoding, errors, render, render_methods

from . import test_envelope as te

H = te.H   # the fixture payloads use this hash everywhere
H2 = encoding.hashstr(b"y")
HEX = render.hash12


def act(payload):
    return payload["ext"]["dev.handsal/act"]


def lines(payload, facts=render.Facts()):
    return render_methods.method_lines(payload["method"], payload, facts)


def block(raw, title="request"):
    return render_methods.block(title, raw, encoding.hashstr(raw))


def refused(fn, *args):
    try:
        fn(*args)
    except errors.Refused as err:
        return err.code
    return None


class Escape(unittest.TestCase):
    def tokens(self, raw):
        return render_methods.escape(raw)

    def test_printable_ascii_is_as_is(self):
        self.assertEqual("".join(self.tokens(b" ~az09|")), " ~az09|")

    def test_every_other_byte_is_a_lowercase_hex_escape(self):
        self.assertEqual(self.tokens(b"\r\t\x00\x7f\xff\x1b"), ["\\x0d", "\\x09", "\\x00", "\\x7f", "\\xff", "\\x1b"])

    def test_a_multibyte_sequence_is_one_escape_per_byte_with_no_special_case(self):
        self.assertEqual("".join(self.tokens("é".encode())), "\\xc3\\xa9")
        self.assertEqual("".join(self.tokens("\U0001F600".encode())), "\\xf0\\x9f\\x98\\x80")
        self.assertEqual("".join(self.tokens("‮".encode())), "\\xe2\\x80\\xae")
        self.assertEqual("".join(self.tokens(b"\xff\xff")), "\\xff\\xff")


class Block(unittest.TestCase):
    def test_header_content_and_footer(self):
        raw = b"line one\nline two\n"
        got = block(raw)
        self.assertEqual(got, ["----- request (18 bytes, sha256 %s) -----" % HEX(encoding.hashstr(raw)),
                               "| line one", "| line two", "----- end -----"])

    def test_a_last_line_without_lf_is_a_line_and_a_trailing_lf_adds_none(self):
        self.assertEqual(block(b"a")[1:-1], ["| a"])
        self.assertEqual(block(b"a\n")[1:-1], ["| a"])
        self.assertEqual(block(b"a\n\n")[1:-1], ["| a", "| "])

    def test_zero_bytes_is_the_header_and_the_footer_only(self):
        got = block(b"")
        self.assertEqual(len(got), 2)
        self.assertTrue(got[0].startswith("----- request (0 bytes"))

    def test_a_hostile_delimiter_is_a_content_line(self):
        got = block(b"----- end -----\nmore")
        self.assertEqual(got[1], "| ----- end -----")
        self.assertEqual(got.count("----- end -----"), 1)

    def test_escapes_and_crlf(self):
        self.assertEqual(block(b"a\r\nb")[1:-1], ["| a\\x0d", "| b"])

    def test_a_long_line_continues_on_pipe_plus_lines_in_96_byte_segments(self):
        got = block(b"x" * 300)[1:-1]
        self.assertEqual(got, ["| " + "x" * 96, "|+" + "x" * 96, "|+" + "x" * 96, "|+" + "x" * 12])
        self.assertTrue(all(len(line) <= 98 for line in got))

    def test_a_break_never_splits_an_escape(self):
        got = block(b"x" * 94 + b"\xff")[1:-1]   # 94 + a 4-character escape = 98 > 96: the escape moves down
        self.assertEqual(got, ["| " + "x" * 94, "|+\\xff"])
        got = block(b"x" * 93 + b"\xff")[1:-1]   # 93 + 4 = 97 > 96
        self.assertEqual(got, ["| " + "x" * 93, "|+\\xff"])
        got = block(b"x" * 92 + b"\xff")[1:-1]   # exactly 96
        self.assertEqual(got, ["| " + "x" * 92 + "\\xff"])

    def test_2048_bytes_in_32_lines_is_rendered(self):
        raw = (b"y" * 63 + b"\n") * 32
        got = block(raw)
        self.assertEqual(len(got), 32 + 2)

    def test_over_2048_bytes_is_render_refused(self):
        self.assertEqual(refused(block, b"y" * 2049), "render_refused")
        self.assertIsNone(refused(block, b"y" * 2048))   # one source line: 22 block lines

    def test_33_block_lines_are_render_refused(self):
        self.assertEqual(refused(block, b"a\n" * 33), "render_refused")
        self.assertIsNone(refused(block, b"a\n" * 32))

    def test_continuation_lines_count_toward_the_32(self):
        self.assertIsNone(refused(block, b"a\n" * 29 + b"x" * 200))   # 29 + 3 continuation segments = 32
        self.assertEqual(refused(block, b"a\n" * 30 + b"x" * 200), "render_refused")   # 33
        self.assertIsNone(refused(block, b"\xff" * 500))   # 2000 escape characters: 21 lines
        self.assertEqual(refused(block, b"\xff" * 2048), "render_refused")   # 8192 characters: 86 lines

    def test_the_record_body_title(self):
        got = block(b"body", "record body")
        self.assertTrue(got[0].startswith("----- record body (4 bytes, sha256 "))


class MethodLines(unittest.TestCase):
    def test_device_add(self):
        p = te.device_add()
        body = act(p)["body"]
        self.assertEqual(lines(p), [
            "Person: alice", "New device: " + body["kid"],
            "Agree key: " + encoding.thumbprint(body["agree"]["x"], body["agree"]["y"]),
            "Class: apple-se-bio", "Label: laptop", "Link code: " + HEX(H)])

    def test_device_remove(self):
        p = te.edit(te.device_add(), ["method"], "local:handsal.device.remove")
        p = te.edit(p, te.ACT + ("body",), {"kid": te.KEYS["bob.sign"]["kid"], "person": "bob"})
        self.assertEqual(lines(p), ["Person: bob", "Remove device: " + te.KEYS["bob.sign"]["kid"]])

    def test_member_add(self):
        d = te.device_add()["ext"]["dev.handsal/act"]["body"]
        body = {"device": {k: d[k] for k in ("agree", "class", "kid", "label", "sign")},
                "link_code_hash": H, "member": "dave", "role": "member"}
        p = te.edit(te.edit(te.device_add(), ["method"], "local:handsal.member.add"), te.ACT + ("body",), body)
        self.assertEqual(lines(p), [
            "Member: dave", "Role: member", "New device: " + d["kid"],
            "Agree key: " + encoding.thumbprint(d["agree"]["x"], d["agree"]["y"]),
            "Class: apple-se-bio", "Label: laptop"])

    def test_a_verdict_shows_the_request_fields_then_the_block(self):
        raw = b"deploy v2"
        p = te.verdict()
        got = lines(p, render.Facts(raw=raw))
        self.assertEqual(got[:4], ["Request: req-00000001", "Recipient: alice", "Relay: r.example",
                                   "Request hash: " + HEX(p["inputs_hash"])])
        self.assertEqual(got[4:], render_methods.block("request", raw, p["inputs_hash"]))

    def test_record_promote(self):
        raw = b"record body v1"
        p = te.promote()
        act(p)["body"]["anchors"] = ["a1", "a2"]
        got = lines(p, render.Facts(raw=raw))
        self.assertEqual(got[:5], ["Record: rec-1", "Anchors:", "  - a1", "  - a2", "Body hash: " + HEX(p["inputs_hash"])])
        self.assertEqual(got[5:], render_methods.block("record body", raw, p["inputs_hash"]))

    def resolve(self, overrides=()):
        c1, c2 = sorted([encoding.hashstr(b"c1"), encoding.hashstr(b"c2")])
        h1 = encoding.hashstr(b"h1")
        p = te.verdict("local:handsal.chain.resolve")
        p["ext"] = {"dev.handsal/act": {"body": {"candidates": [c1, c2], "choose": c2, "heads": [h1],
                                                   "overrides": list(overrides)}, "kid": te.KID, "org": te.ORG}}
        p["parent_receipt_hash"] = H
        facts = render.Facts(candidates={c1: "Add device AAAA-AAAA-AAAA (k) to a", c2: "Remove device B of b"},
                             heads={h1: "Add device HHHH-HHHH-HHHH (k) to h"})
        return p, facts, (c1, c2, h1)

    def test_resolve_lists_candidates_marking_the_chosen_and_heads_and_no_overrides(self):
        p, facts, (c1, c2, h1) = self.resolve()
        self.assertEqual(lines(p, facts), [
            "Fork parent: " + H, "Choose: " + c2, "Candidates:",
            "    %s Add device AAAA-AAAA-AAAA (k) to a" % HEX(c1),
            "  > %s Remove device B of b" % HEX(c2),
            "Heads:", "  - %s Add device HHHH-HHHH-HHHH (k) to h" % HEX(h1), "Overrides: none"])

    def test_resolve_override_entries_show_the_resolve_and_the_decimal_endorsement_count(self):
        e = sorted(encoding.hashstr(bytes([i])) for i in range(2))
        r1, r2 = encoding.hashstr(b"r1"), encoding.hashstr(b"r2")
        p, facts, _ = self.resolve([{"endorsements": e, "resolve": r1}, {"endorsements": e[:1], "resolve": r2}])
        got = lines(p, facts)
        self.assertEqual(got[-3:], ["Overrides:", "  - %s (endorsements: 2)" % HEX(r1), "  - %s (endorsements: 1)" % HEX(r2)])

    def test_endorse_shows_the_endorsed_id_then_the_endorsed_method_lines(self):
        p = te.endorse()
        facts = render.Facts(endorsed_lines=["Person: alice", "Remove device: k"])
        self.assertEqual(lines(p, facts), ["Endorsed act: " + H, "Person: alice", "Remove device: k"])

    def test_the_envelope_constants_and_the_nonce_are_not_rendered(self):
        text = "\n".join(lines(te.device_add()))
        self.assertNotIn(te.NONCE, text)
        self.assertNotIn("vitni/0.2", text)

    def test_a_resolve_at_the_caps_is_54_method_lines(self):
        cands = sorted(encoding.hashstr(b"c%d" % i) for i in range(17))
        heads = sorted(encoding.hashstr(b"h%d" % i) for i in range(16))
        over = sorted(({"endorsements": [encoding.hashstr(b"e%d" % j) for j in range(15)], "resolve": encoding.hashstr(b"r%d" % i)}
                       for i in range(16)), key=lambda e: e["resolve"])
        p = te.verdict("local:handsal.chain.resolve")
        p["ext"] = {"dev.handsal/act": {"body": {"candidates": cands, "choose": cands[0], "heads": heads,
                                                   "overrides": over}, "kid": te.KID, "org": te.ORG}}
        p["parent_receipt_hash"] = H
        facts = render.Facts(candidates={c: "x" * 80 for c in cands}, heads={h: "y" * 80 for h in heads})
        got = lines(p, facts)
        self.assertEqual(len(got), 54)
        self.assertTrue(all(len(x) <= 100 for x in got))
        self.assertEqual({len(x) for x in got if x.startswith("  - ") and "endorsements" in x}, {37})


if __name__ == "__main__":
    unittest.main()
