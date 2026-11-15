"""T3.47 vectors rnd/*: the render text and its refusals (RN-01 to RN-12)."""
import base64
import json
import unittest

from lib import base
from tests import catalog

WRITTEN = {
    "rnd/approve", "rnd/reject", "rnd/needs-info", "rnd/no-org-name-non-genesis",
    "rnd/determinism", "rnd/line1-approve-size", "rnd/first-line-tilde", "rnd/sender-not-proven",
    "rnd/hash12-skips-uEi",
    "rnd/hostile-bidi", "rnd/hostile-control", "rnd/hostile-delimiter", "rnd/hostile-nul",
    "rnd/invalid-utf8", "rnd/non-ascii-escaped", "rnd/nonbmp-escape", "rnd/tab-escaped",
    "rnd/crlf-escaped", "rnd/empty-request", "rnd/request-exactly-2048-ok",
    "rnd/request-33-lines-refused", "rnd/request-32-lines-cap", "rnd/request-over-2048-refused",
    "rnd/oversize-truncated", "rnd/request-attachment-mismatch",
    "rnd/record-promote-retired-refused",
    "rnd/device-add", "rnd/device-add-agree-key-id", "rnd/device-remove", "rnd/member-add",
    "rnd/line1-device-add-class", "rnd/line1-member-add-kid-first",
    "rnd/endorse", "rnd/endorse-shows-endorsed-id", "rnd/endorse-attachment-mismatch",
    "rnd/endorse-attachment-missing", "rnd/endorse-primary-extra-attachment",
    "rnd/chain-resolve", "rnd/line1-resolve", "rnd/line1-resolve-keeps-kid12",
    "rnd/line1-endorse-bounded", "rnd/resolve-candidates-listed", "rnd/resolve-heads-attached",
    "rnd/resolve-override-entry-line", "rnd/resolve-override-entry-line-one",
    "rnd/endorse-resolve-nested-attached", "rnd/endorse-resolve-heads-missing",
    "rnd/endorse-resolve-candidate-mismatch", "rnd/attachment-act-kid-differs",
    "rnd/resolve-candidate-wrong-parent", "rnd/resolve-candidate-missing",
    "rnd/resolve-head-attachment-missing",
    "rnd/genesis-attachment-hash-mismatch", "rnd/genesis-change-previous-mismatch",
    "rnd/render-73-lines-refused",
    "rnd/refuse-extra-key", "rnd/refuse-unknown-method", "rnd/refuse-label-quote",
    "rnd/resolve-max-caps-fits", "rnd/endorse-resolve-max-caps-fits",
    # the texts of RN-02 to RN-05, RN-08, RN-10, RN-12 and the later ids
    "rnd/long-line-wrapped", "rnd/request-long-line-continuation",
    "rnd/truncate-not-inside-escape",
    "rnd/genesis-agree-key-id", "rnd/genesis-change-diff", "rnd/genesis-change-head-line",
    "rnd/genesis-class-own-line", "rnd/genesis-policy-lines", "rnd/genesis-profile-full",
    "rnd/genesis-sign-change", "rnd/genesis-sign-original", "rnd/line1-genesis-change-summary",
    "rnd/prompt-line-max-length", "rnd/prompt-line-max-device-remove",
    "rnd/prompt-line-max-member-add", "rnd/prompt-line-max-resolve",
    "rnd/prompt-line-max-approve", "rnd/prompt-line-max-reject", "rnd/prompt-line-max-needs-info",
    "rnd/prompt-line-max-genesis-original",
    "rnd/prompt-line-max-genesis-change", "rnd/genesis-head-mismatch",
    "rnd/genesis-document-invalid-bound", "rnd/genesis-previous-invalid-bound",
    "rnd/genesis-change-org-name-profile-lines", "rnd/attachment-wrong-type-mismatch",
    # RN-09 Order of checks
    "rnd/endorse-resolve-act-mismatch-before-heads-missing",
    "rnd/resolve-candidates-mismatch-before-heads-missing",
    "rnd/genesis-head-missing-before-previous-missing",
    # the decision act (VR-18)
    "rnd/decision", "rnd/decision-empty", "rnd/decision-block-hostile", "rnd/decision-attachment-mismatch",
    "rnd/decision-attachment-missing", "rnd/decision-over-2048-refused", "rnd/decision-33-lines-refused",
    "rnd/decision-exactly-2048-ok", "rnd/decision-action-grammar-refused", "rnd/prompt-line-max-decision",
    "rnd/decision-hash12-dash",
}
NOT_WRITTEN = set()


class Rnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("rnd", ["rnd"])

    def test_rows(self):
        self.assertEqual(set(self.v), WRITTEN)

    def test_written_and_skipped_ids_partition_the_catalog_group(self):
        group = {k for k in catalog.ROWS if k.startswith("rnd/")}
        self.assertEqual(WRITTEN | NOT_WRITTEN, group)
        self.assertFalse(WRITTEN & NOT_WRITTEN)

    def test_every_row_is_a_render_vector_with_the_four_input_keys(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "render", name)
            self.assertEqual(sorted(v["input"]), ["attachments", "kid", "method", "payload"], name)
            self.assertEqual(v["input"]["method"], v["input"]["payload"]["method"], name)

    def test_error_rows_carry_the_catalog_code(self):
        for name, v in self.v.items():
            obj = json.loads(v["anchor"])
            if "error" in obj:
                self.assertEqual(obj["error"], catalog.catalog_code(name), name)
            else:
                self.assertEqual(sorted(obj), ["first_line", "text"], name)

    def test_text_rows_obey_the_layout_bounds(self):
        for name, v in self.v.items():
            obj = json.loads(v["anchor"])
            if "error" in obj:
                continue
            ls = obj["text"].split("\n")
            self.assertEqual(ls[-1], "", name)
            self.assertEqual(ls[0], obj["first_line"], name)
            self.assertLessEqual(len(obj["first_line"]), 80, name)
            self.assertLessEqual(len(ls) - 1, 72, name)
            self.assertTrue(all(len(x) <= 100 for x in ls), name)
            self.assertTrue(obj["text"].isascii(), name)

    def test_every_prompt_line_max_row_is_a_method_at_most_80_bytes(self):
        names = [k for k in self.v if k.startswith("rnd/prompt-line-max-")]
        self.assertEqual(len(names), 10)
        for name in names:
            first = json.loads(self.v[name]["anchor"])["first_line"]
            self.assertLessEqual(len(first), 80, name)
        resolve = json.loads(self.v["rnd/prompt-line-max-resolve"]["anchor"])["first_line"]
        self.assertEqual(len(resolve), 80)
        decision = json.loads(self.v["rnd/prompt-line-max-decision"]["anchor"])["first_line"]
        self.assertEqual(len(decision), 80)   # RN-03: the 24-character action bound is exactly the room line 1 has

    def test_the_genesis_max_rows_have_two_digit_counts_and_fit_72_lines(self):
        original = json.loads(self.v["rnd/prompt-line-max-genesis-original"]["anchor"])
        self.assertIn(": 10 members, 10 devices", original["first_line"])
        self.assertLessEqual(original["text"].count("\n"), 72)
        change = json.loads(self.v["rnd/prompt-line-max-genesis-change"]["anchor"])
        self.assertIn("+2/-10 dev, 12 mem, policy same", change["first_line"])
        for out in (original, change):
            self.assertTrue(out["first_line"].startswith(("Sign genesis of nnnnnnnnnnn~ (",
                                                          "Change nnnnnnnnnnn~ (")))

    def test_the_order_rows_carry_two_defects_and_the_earlier_one_decides(self):
        # RN-09 Order of checks
        want = {"rnd/endorse-resolve-act-mismatch-before-heads-missing": "attachment_mismatch",
                "rnd/resolve-candidates-mismatch-before-heads-missing": "attachment_mismatch",
                "rnd/genesis-head-missing-before-previous-missing": "schema"}
        for name, code in want.items():
            self.assertEqual(json.loads(self.v[name]["anchor"]), {"error": code}, name)
        self.assertNotIn("heads", self.v["rnd/endorse-resolve-act-mismatch-before-heads-missing"]["input"]["attachments"])
        self.assertNotIn("heads", self.v["rnd/resolve-candidates-mismatch-before-heads-missing"]["input"]["attachments"])
        g = self.v["rnd/genesis-head-missing-before-previous-missing"]["input"]
        self.assertNotIn("previous", g["attachments"])
        self.assertNotIn("head", g["payload"]["ext"]["dev.handsal/act"])

    def test_every_id_and_relay_of_a_positive_act_fits_its_alphabet(self):
        """Section 2.2: a render row holds a legal act, so each id and the relay obey the grammar
        (a request id 8 to 36 characters, a hostname of labels 1 to 63)."""
        import re
        label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
        for name, v in self.v.items():
            if name in ("rnd/refuse-extra-key", "rnd/refuse-unknown-method", "rnd/refuse-label-quote"):
                continue
            act = v["input"]["payload"].get("ext", {}).get("dev.handsal/act", {})
            if "request_id" in act:
                self.assertRegex(act["request_id"], r"[a-z0-9][a-z0-9-]{7,35}", name)
            if "relay" in act:
                self.assertLessEqual(len(act["relay"]), 253, name)
                for part in act["relay"].split("."):
                    self.assertTrue(label.fullmatch(part), (name, part))

    def test_a_retired_payload_is_method_unknown_to_every_renderer(self):
        # ACT-09 S9: the payload as the old method signed it, with its attachment as a caller of it sends it
        v = self.v["rnd/record-promote-retired-refused"]
        self.assertEqual(v["input"]["method"], "local:handsal.record.promote")
        self.assertEqual(sorted(v["input"]["payload"]["ext"]["dev.handsal/act"]["body"]), ["anchors", "record_id"])
        self.assertEqual(base64.b64decode(v["input"]["attachments"]["record_body_b64"]), b"record body v1")
        self.assertEqual(json.loads(v["anchor"]), {"error": "method_unknown"})

    def test_the_hash12_dash_row_renders_the_content_hash_of_14_known_bytes(self):
        # RN-03 S3: a dash at the edge of a group, from content bytes alone, so no re-pin moves it
        v = self.v["rnd/decision-hash12-dash"]
        self.assertEqual(base64.b64decode(v["input"]["attachments"]["decision_b64"]), b"record body v1")
        self.assertEqual(v["input"]["payload"]["method"], "local:handsal.decision")
        out = json.loads(v["anchor"])
        self.assertIn("(AnLr sJDp -lmi, 14 bytes)", out["first_line"])
        self.assertIn("Decision hash: AnLr sJDp -lmi", out["text"].split("\n"))
        self.assertEqual("AnLr sJDp -lmi".split(" ")[2][0], "-")

    def test_the_253_character_relay_has_four_labels_of_63_63_63_and_61(self):
        relay = self.v["rnd/long-line-wrapped"]["input"]["payload"]["ext"]["dev.handsal/act"]["relay"]
        self.assertEqual([len(x) for x in relay.split(".")], [63, 63, 63, 61])

    def test_the_wrapped_and_continued_rows_show_every_byte(self):
        text = json.loads(self.v["rnd/long-line-wrapped"]["anchor"])["text"].split("\n")
        at = next(i for i, x in enumerate(text) if x.startswith("Relay: "))
        self.assertEqual([len(x) for x in text[at:at + 3]], [98, 100, 66])
        self.assertTrue(text[at + 1].startswith("+ ") and text[at + 2].startswith("+ "))
        block = json.loads(self.v["rnd/request-long-line-continuation"]["anchor"])["text"].split("\n")
        self.assertEqual([x[:2] for x in block if x[:1] == "|"], ["| ", "|+", "|+", "|+"])

    def test_the_escape_row_breaks_before_the_escape(self):
        ls = json.loads(self.v["rnd/truncate-not-inside-escape"]["anchor"])["text"].split("\n")
        at = next(i for i, x in enumerate(ls) if x.startswith("| x"))
        self.assertEqual(ls[at], "| " + "x" * 95)
        self.assertEqual(ls[at + 1], "|+\\xc3\\xa9")

    def test_the_genesis_change_rows_render_no_document_hash_and_the_original_does(self):
        for name in ("rnd/genesis-sign-change", "rnd/genesis-change-diff"):
            self.assertNotIn("Document hash", json.loads(self.v[name]["anchor"])["text"])
        self.assertIn("Document hash: ",
                      json.loads(self.v["rnd/genesis-sign-original"]["anchor"])["text"])

    def test_the_max_caps_resolve_renders_60_lines_and_its_endorsement_62(self):
        res = json.loads(self.v["rnd/resolve-max-caps-fits"]["anchor"])
        end = json.loads(self.v["rnd/endorse-resolve-max-caps-fits"]["anchor"])
        self.assertEqual(len(res["text"].split("\n")) - 1, 60)
        self.assertEqual(len(end["text"].split("\n")) - 1, 62)
        overrides = [x for x in res["text"].split("\n") if "(endorsements: " in x]
        self.assertEqual(len(overrides), 16)
        self.assertTrue(all(x.endswith("(endorsements: 15)") and len(x) == 37 for x in overrides))

    def test_the_max_caps_payload_is_the_size_the_catalog_names(self):
        from lib import jcs
        v = self.v["rnd/resolve-max-caps-fits"]
        self.assertEqual(len(jcs.emit(v["input"]["payload"])), 15787)

    def test_the_bounded_endorse_line_is_80_bytes_and_ends_in_a_tilde(self):
        first = json.loads(self.v["rnd/line1-endorse-bounded"]["anchor"])["first_line"]
        self.assertEqual(len(first), 80)
        self.assertTrue(first.endswith("~"))

    def test_the_resolve_line_one_is_cut_at_59_bytes_of_the_kept_line(self):
        first = json.loads(self.v["rnd/line1-resolve-keeps-kid12"]["anchor"])["first_line"]
        self.assertEqual(len(first), len("Resolve fork, keep: ") + 59 + 1)
        self.assertTrue(first.startswith("Resolve fork, keep: Add device "))
        self.assertTrue(first.endswith("~"))

    def test_the_max_caps_endorsement_carries_34_act_attachments(self):
        att = self.v["rnd/endorse-resolve-max-caps-fits"]["input"]["attachments"]
        self.assertEqual(sorted(att), ["act", "candidates", "heads"])
        self.assertEqual(1 + len(att["candidates"]) + len(att["heads"]), 34)

    def test_every_positive_act_is_recorded_for_the_vitni_cross_check(self):
        import tempfile
        import generate
        import groups.rnd as module
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=[module], known_ids=generate.shipping_ids(), stats=stats)
        self.assertGreater(stats["positives"], 40)
        self.assertEqual(stats["negatives"], 0)

    def test_the_request_the_vector_names_is_the_attachment(self):
        v = self.v["rnd/approve"]
        self.assertEqual(v["input"]["attachments"], {"request_b64": base.Fixtures.request_b64(
            None, base.REQUEST)})


if __name__ == "__main__":
    unittest.main()
