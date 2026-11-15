"""T3.51 attachments bound to the payload (RN-09), the whole render of every method, and the `render`
command (CF-03). An attachment is never a second, unbound source: the render checks every one against
the payload before it shows a word.
"""
import base64
import hashlib
import io
import json
import unittest

from handsal_check import core, cli, encoding, errors, genesis, profiles, registry, render, render_attach

from .act_builder import build, genesis_sign, head_of
from .fold_world import device_body, member_body
from .genesis_fixtures import KEYS, change, device, edit, org as make_org
from . import test_envelope as te

REG = registry.load()
PROFILES = profiles.load()
ORG = te.ORG
PARENT = encoding.hashstr(b"fork-parent")
HEX = render.hash12
RAW = b"deploy v2\n"


def decode(act):
    return json.loads(encoding.b64u_decode(act.jws.split(".")[1]))


def run(payload, kid, attachments, method=None):
    return render_attach.render_payload(render.Input(attachments, kid, method or payload["method"], payload), REG, PROFILES)


def code(payload, kid, attachments, method=None):
    try:
        run(payload, kid, attachments, method)
    except errors.Refused as err:
        return err.code
    return None


def b64(raw):
    return base64.b64encode(raw).decode()


def verdict_act(method="approve", raw=RAW, **over):
    body = dict(inputs_hash=encoding.hashstr(raw), outputs_hash=encoding.hashstr(b"o"), head=None,
                parent=None, extra={"expires": "2026-11-08T13:00:00Z", "recipient": "alice", "relay": "r.example",
                                    "request_id": "req-00000001"})
    body.update(over)
    body["head"] = {"id": PARENT, "kind": "chain"}
    return build("alice", "request." + method, org=ORG, body={}, **body)


def decision_act(raw=b"Ruling 0001: keep the retry limit at three.\n"):
    return build("alice", "decision", org=ORG,
                 body={"action": "ratify ruling", "consumer": "notes", "subject": "ruling-0001"},
                 inputs_hash=encoding.hashstr(raw), head={"id": PARENT, "kind": "chain"},
                 extra={"expires": "2026-11-08T13:00:00Z"})


def primary(name="alice2", person="alice", parent=PARENT, signer="alice", **kw):
    return build(signer, "device.add", org=ORG, body=device_body(name, person), parent=parent, **kw)


class Verdict(unittest.TestCase):
    def test_the_full_text_of_an_approve(self):
        act = verdict_act()
        p = decode(act)
        got = run(p, act.kid, {"request_b64": b64(RAW)})
        h = HEX(p["inputs_hash"])
        self.assertEqual(got.first_line, "APPROVE request req-00000001 (%s, 10 bytes)" % h)
        self.assertEqual(got.text.split("\n"), [
            got.first_line, "Method: local:handsal.request.approve", "Org: " + HEX(ORG),
            "Signer: alice key " + render.kid12(act.kid),
            "Request: req-00000001", "Recipient: alice", "Relay: r.example", "Request hash: " + h,
            "----- request (10 bytes, sha256 %s) -----" % h, "| deploy v2", "----- end -----",
            "Signed at: 2026-01-01T00:00:00Z", "Expires: 2026-11-08T13:00:00Z", "Head: " + HEX(PARENT),
            "Sender: not proven", ""])

    def test_the_request_must_be_supplied_and_bound(self):
        act = verdict_act()
        p = decode(act)
        self.assertEqual(code(p, act.kid, {}), "attachment_missing")
        self.assertEqual(code(p, act.kid, {"request_b64": b64(b"another request")}), "attachment_mismatch")

    def test_a_request_that_is_not_canonical_base64_is_a_malformed_input(self):
        act = verdict_act()
        p = decode(act)
        for bad in (5, None, "@@", "Zm9v\n", b64(RAW).rstrip("=")):
            with self.assertRaises(errors.Malformed, msg=repr(bad)):
                run(p, act.kid, {"request_b64": bad})

    def test_a_sender_attachment_changes_nothing(self):
        act = verdict_act()
        p = decode(act)
        plain = run(p, act.kid, {"request_b64": b64(RAW)})
        self.assertEqual(run(p, act.kid, {"request_b64": b64(RAW), "sender": "mallory"}), plain)
        self.assertIn("Sender: not proven", plain.text)
        self.assertNotIn("mallory", plain.text)

    def test_a_request_over_the_limits_is_render_refused(self):
        raw = b"x" * 2049
        act = verdict_act(raw=raw)
        self.assertEqual(code(decode(act), act.kid, {"request_b64": b64(raw)}), "render_refused")

    def test_reject_and_needs_info(self):
        for method, verb in (("reject", "REJECT request"), ("needs-info", "NEEDS-INFO on request")):
            act = verdict_act(method)
            self.assertTrue(run(decode(act), act.kid, {"request_b64": b64(RAW)}).first_line.startswith(verb))


class Decision(unittest.TestCase):
    def test_the_decision_block_follows_its_words(self):
        raw = b"Ruling 0001: keep the retry limit at three.\n"
        act = decision_act(raw)
        p = decode(act)
        got = run(p, act.kid, {"decision_b64": b64(raw)})
        h = HEX(p["inputs_hash"])
        lines = got.text.split("\n")
        self.assertIn("----- decision (%d bytes, sha256 %s) -----" % (len(raw), h), lines)
        self.assertEqual(lines[lines.index("Consumer: notes"):lines.index("Consumer: notes") + 4],
                         ["Consumer: notes", "Action: ratify ruling", "Subject: ruling-0001", "Decision hash: " + h])
        self.assertEqual(got.first_line, "notes: ratify ruling ruling-0001 (%s, %d bytes)" % (h, len(raw)))
        self.assertNotIn("Sender", got.text)

    def test_bound_missing_and_over_the_limit(self):
        act = decision_act()
        p = decode(act)
        self.assertEqual(code(p, act.kid, {}), "attachment_missing")
        self.assertEqual(code(p, act.kid, {"decision_b64": b64(b"other")}), "attachment_mismatch")
        big = b"y" * 2049
        act = decision_act(big)
        self.assertEqual(code(decode(act), act.kid, {"decision_b64": b64(big)}), "render_refused")


ORIGINAL = make_org(PROFILES.fixture)
ORIGINAL_ID = genesis.doc_hash(ORIGINAL)
H = encoding.hashstr(b"head")


def genesis_act(doc, **over):
    act = genesis_sign("alice", doc, ORIGINAL_ID)
    return act


class GenesisSign(unittest.TestCase):
    def test_an_original_renders_in_full(self):
        act = genesis_act(ORIGINAL)
        got = run(decode(act), act.kid, {"document": ORIGINAL})
        self.assertTrue(got.first_line.startswith("Sign genesis of ORG ("))
        self.assertIn("Org name: ORG", got.text)
        self.assertNotIn("Head:", got.text)
        self.assertEqual(got.text.count("    Class: apple-se-bio"), 3)

    def test_the_document_must_be_supplied_and_bound(self):
        act = genesis_act(ORIGINAL)
        p = decode(act)
        self.assertEqual(code(p, act.kid, {}), "attachment_missing")
        other = edit(ORIGINAL, ["name"], "OTHER")
        self.assertEqual(code(p, act.kid, {"document": other}), "attachment_mismatch")
        self.assertEqual(code(p, act.kid, {"document": 5}), "attachment_mismatch")

    def test_a_bound_document_that_is_not_valid_alone_is_attachment_mismatch(self):
        for bad in (edit(ORIGINAL, ["extra"], "x"),                                    # GP-15 step 1
                    edit(ORIGINAL, ["policy", "freshness", "clock_skew_s"], "x")):     # GP-15 step 3
            act = genesis_sign("alice", bad, ORIGINAL_ID)
            self.assertEqual(code(decode(act), act.kid, {"document": bad}), "attachment_mismatch")

    def test_the_profile_of_a_bound_document_is_the_folds_concern_not_the_renders(self):
        other = edit(ORIGINAL, ["profile"], encoding.hashstr(b"another profile"))
        act = genesis_sign("alice", other, ORIGINAL_ID)
        self.assertIsNone(code(decode(act), act.kid, {"document": other}))

    def test_a_previous_that_binds_but_is_not_valid_alone_is_attachment_mismatch(self):
        bad_previous = edit(ORIGINAL, ["extra"], "x")
        doc = change(PROFILES.fixture, ORIGINAL_ID, genesis.doc_hash(bad_previous), H)
        act = genesis_sign("alice", doc, ORIGINAL_ID)
        self.assertEqual(code(decode(act), act.kid, {"document": doc, "previous": bad_previous}),
                         "attachment_mismatch")

    def test_the_payload_head_must_be_the_document_head(self):
        doc = change(PROFILES.fixture, ORIGINAL_ID, ORIGINAL_ID, H)
        act = genesis_sign("alice", doc, ORIGINAL_ID, head=head_of(encoding.hashstr(b"another head")))
        self.assertEqual(code(decode(act), act.kid, {"document": doc, "previous": ORIGINAL}),
                         "attachment_mismatch")

    def test_a_change_renders_the_difference_and_binds_previous(self):
        doc = change(PROFILES.fixture, ORIGINAL_ID, ORIGINAL_ID, H)
        act = genesis_sign("alice", doc, ORIGINAL_ID)
        p = decode(act)
        got = run(p, act.kid, {"document": doc, "previous": ORIGINAL})
        self.assertTrue(got.first_line.startswith("Change ORG ("))
        self.assertIn("Head: " + H, got.text)
        self.assertIn("Previous: " + HEX(ORIGINAL_ID), got.text)
        self.assertIn("Unchanged: 3 devices, 3 members", got.text)
        self.assertEqual(code(p, act.kid, {"document": doc}), "attachment_missing")
        self.assertEqual(code(p, act.kid, {"document": doc, "previous": edit(ORIGINAL, ["name"], "OTHER")}),
                         "attachment_mismatch")

    def test_head_is_present_iff_the_document_is_a_change(self):
        doc = change(PROFILES.fixture, ORIGINAL_ID, ORIGINAL_ID, H)
        no_head = genesis_sign("alice", doc, ORIGINAL_ID, head=None)
        self.assertEqual(code(decode(no_head), no_head.kid, {"document": doc, "previous": ORIGINAL}), "schema")
        with_head = genesis_sign("alice", ORIGINAL, ORIGINAL_ID, head={"id": H, "kind": "chain"})
        self.assertEqual(code(decode(with_head), with_head.kid, {"document": ORIGINAL}), "schema")

    def test_head_presence_is_decided_before_previous_is_read(self):
        # RN-09 Order of checks: the act object's form comes before the attachments after `document`
        doc = change(PROFILES.fixture, ORIGINAL_ID, genesis.doc_hash(ORIGINAL), H)
        no_head = genesis_sign("alice", doc, ORIGINAL_ID, head=None)
        self.assertEqual(code(decode(no_head), no_head.kid, {"document": doc}), "schema")

    def test_a_document_over_72_lines_is_render_refused(self):
        big = make_org(PROFILES.fixture, people=("alice", "bob", "carol", "dave", "grace"),
                       devices=[device(n) for n in ("alice", "alice2", "alice3", "alice4", "bob", "bob2", "bob3",
                                                    "carol", "carol2", "dave", "dave2", "grace")])
        act = genesis_sign("alice", big, genesis.doc_hash(big))
        self.assertEqual(code(decode(act), act.kid, {"document": big}), "render_refused")


def resolve_fixture(n_candidates=2):
    """A resolve of the fork at PARENT over `n_candidates` device.add candidates; head acts are the losers."""
    names = [("alice2", "alice"), ("bob2", "bob"), ("carol2", "carol"), ("dave2", "dave"), ("alice3", "alice"),
             ("alice4", "alice"), ("bob3", "bob")]
    cands = [primary(n, p, signer=p, salt=str(i)) for i, (n, p) in enumerate(names[:n_candidates])]
    ordered = sorted(cands, key=lambda a: a.id)
    choose, losers = ordered[0], ordered[1:]
    body = {"candidates": [a.id for a in ordered], "choose": choose.id, "heads": sorted(a.id for a in losers),
            "overrides": []}
    res = build("alice", "chain.resolve", org=ORG, body=body, parent=PARENT)
    return res, ordered, losers


def attach(ordered, losers):
    return {"candidates": [a.jws for a in ordered], "heads": [a.jws for a in losers]}


class Resolve(unittest.TestCase):
    def test_candidates_and_heads_are_listed_with_line_1_of_each_attached_act(self):
        res, ordered, losers = resolve_fixture()
        got = run(decode(res), res.kid, attach(ordered, losers))
        lines = got.text.split("\n")
        l1 = lambda a: run_line1(a)
        self.assertTrue(got.first_line.startswith("Resolve fork, keep: Add device "))
        self.assertIn("  > %s %s" % (HEX(ordered[0].id), l1(ordered[0])), lines)
        self.assertIn("    %s %s" % (HEX(ordered[1].id), l1(ordered[1])), lines)
        self.assertIn("  - %s %s" % (HEX(losers[0].id), l1(losers[0])), lines)
        self.assertIn("Overrides: none", lines)
        self.assertNotIn("Head:", got.text)

    def test_a_missing_list_is_attachment_missing(self):
        res, ordered, losers = resolve_fixture()
        for name in ("candidates", "heads"):
            got = {k: v for k, v in attach(ordered, losers).items() if k != name}
            self.assertEqual(code(decode(res), res.kid, got), "attachment_missing", name)

    def test_a_list_must_hold_exactly_one_jws_per_id(self):
        res, ordered, losers = resolve_fixture(3)
        base = attach(ordered, losers)
        cases = {
            "duplicate copy": {**base, "candidates": base["candidates"] + [ordered[0].jws]},
            "extra act": {**base, "candidates": base["candidates"] + [primary("dave2", "dave", signer="dave").jws]},
            "missing id": {**base, "candidates": base["candidates"][:-1]},
            "heads missing id": {**base, "heads": base["heads"][:-1]},
            "not a list": {**base, "candidates": base["candidates"][0]},
            "not a string": {**base, "candidates": [5] * 3},
            "any order is fine": None}
        for label, got in cases.items():
            if got is None:
                shuffled = {**base, "candidates": list(reversed(base["candidates"]))}
                self.assertIsNone(code(decode(res), res.kid, shuffled), label)
            else:
                self.assertEqual(code(decode(res), res.kid, got), "attachment_mismatch", label)

    def test_a_candidate_with_another_parent_is_attachment_mismatch(self):
        res, ordered, losers = resolve_fixture()
        wrong = primary("alice2", "alice", parent=encoding.hashstr(b"elsewhere"))
        body = {"candidates": sorted([wrong.id, ordered[1].id]), "choose": wrong.id,
                "heads": [ordered[1].id], "overrides": []}
        res2 = build("alice", "chain.resolve", org=ORG, body=body, parent=PARENT)
        got = {"candidates": [wrong.jws, ordered[1].jws], "heads": [ordered[1].jws]}
        self.assertEqual(code(decode(res2), res2.kid, got), "attachment_mismatch")

    def test_an_attachment_that_is_not_a_valid_act_is_attachment_mismatch(self):
        res, ordered, losers = resolve_fixture()
        bad = primary("alice2", "alice", act_kid=KEYS["bob.sign"]["kid"], salt="0")   # act kid differs from header kid
        body = {"candidates": sorted([bad.id, ordered[1].id]), "choose": bad.id, "heads": [ordered[1].id], "overrides": []}
        res2 = build("alice", "chain.resolve", org=ORG, body=body, parent=PARENT)
        got = {"candidates": [bad.jws, ordered[1].jws], "heads": [ordered[1].jws]}
        self.assertEqual(code(decode(res2), res2.kid, got), "attachment_mismatch")
        for junk in ("junk", "a.b.c"):
            got = {"candidates": [junk, ordered[1].jws], "heads": [ordered[1].jws]}
            self.assertEqual(code(decode(res), res.kid, got), "attachment_mismatch")

    def test_a_head_must_be_a_chain_primary(self):
        res, ordered, losers = resolve_fixture()
        stray = decision_act()
        body = {"candidates": [a.id for a in ordered], "choose": ordered[0].id, "heads": [stray.id], "overrides": []}
        res2 = build("alice", "chain.resolve", org=ORG, body=body, parent=PARENT)
        got = {"candidates": [a.jws for a in ordered], "heads": [stray.jws]}
        self.assertEqual(code(decode(res2), res2.kid, got), "attachment_mismatch")


def run_line1(act):
    p = decode(act)
    return render.first_line(p["method"], p, render.Facts())


def endorse_act(target, signer="bob", **over):
    fields = dict(org=ORG, body={"act": target.id}, parent=target.id, parent_performer=target.performer,
                  head={"id": decode(target)["parent_receipt_hash"], "kind": "chain"})
    fields.update(over)
    return build(signer, "act.endorse", **fields)


class Endorse(unittest.TestCase):
    def test_an_endorsement_of_a_primary_shows_the_endorsed_id_and_its_lines(self):
        target = primary()
        e = endorse_act(target)
        got = run(decode(e), e.kid, {"act": target.jws})
        lines = got.text.split("\n")
        self.assertEqual(got.first_line, "Endorse: " + run_line1(target))
        self.assertEqual(lines[4:11], ["Endorsed act: " + target.id, "Person: alice",
                                       "New device: " + KEYS["alice2.sign"]["kid"], lines[7], "Class: apple-se-bio",
                                       "Label: phone", "Link code: " + HEX(device_body("alice2")["link_code_hash"])])
        self.assertEqual(lines[-4:], ["Signed at: 2026-01-01T00:00:00Z", "Parent: " + HEX(target.id),
                                      "Head: " + HEX(PARENT), ""])

    def test_the_attachment_is_required_and_must_bind(self):
        target = primary()
        e = endorse_act(target)
        p = decode(e)
        self.assertEqual(code(p, e.kid, {}), "attachment_missing")
        other = primary("bob2", "bob", signer="bob")
        self.assertEqual(code(p, e.kid, {"act": other.jws}), "attachment_mismatch")
        self.assertEqual(code(p, e.kid, {"act": "junk"}), "attachment_mismatch")
        self.assertEqual(code(p, e.kid, {"act": 5}), "attachment_mismatch")

    def test_every_binding_of_the_table(self):
        target = primary()
        cases = {
            "parent_receipt_hash": endorse_act(target, parent=encoding.hashstr(b"z")),
            "parent_performer_id": endorse_act(target, parent_performer="bob"),
            "head is not the endorsed act's parent": endorse_act(target, head={"id": encoding.hashstr(b"z"), "kind": "chain"}),
        }
        for label, e in cases.items():
            self.assertEqual(code(decode(e), e.kid, {"act": target.jws}), "attachment_mismatch", label)

    def test_the_endorsed_act_must_be_a_chain_primary_or_a_resolve(self):
        verdict = verdict_act()
        e = endorse_act(verdict, body={"act": verdict.id}, head={"id": PARENT, "kind": "chain"})
        self.assertEqual(code(decode(e), e.kid, {"act": verdict.jws}), "attachment_mismatch")

    def test_a_primary_with_a_candidates_or_heads_attachment_is_attachment_mismatch(self):
        target = primary()
        e = endorse_act(target)
        for extra in ({"heads": []}, {"candidates": []}):
            self.assertEqual(code(decode(e), e.kid, {"act": target.jws, **extra}), "attachment_mismatch")

    def test_an_endorsed_resolve_needs_its_nested_attachments_bound_like_the_resolve(self):
        res, ordered, losers = resolve_fixture()
        e = endorse_act(res, head={"id": PARENT, "kind": "chain"})
        p = decode(e)
        nested = attach(ordered, losers)
        got = run(p, e.kid, {"act": res.jws, **nested})
        self.assertTrue(got.first_line.startswith("Endorse: Resolve fork, keep: "))
        self.assertLessEqual(len(got.first_line), 80)
        lines = got.text.split("\n")
        i = lines.index("Candidates:")
        self.assertEqual(lines[4], "Endorsed act: " + res.id)
        self.assertEqual(lines[5], "Fork parent: " + PARENT)
        self.assertEqual(lines[i - 1], "Choose: " + ordered[0].id)
        self.assertIn("Overrides: none", lines)
        self.assertNotIn("Method: local:handsal.chain.resolve", got.text)
        for name in ("candidates", "heads"):
            part = {"act": res.jws, **{k: v for k, v in nested.items() if k != name}}
            self.assertEqual(code(p, e.kid, part), "attachment_missing", name)
        outside = primary("dave2", "dave", signer="dave")
        part = {"act": res.jws, **nested, "candidates": [outside.jws] + nested["candidates"][1:]}
        self.assertEqual(code(p, e.kid, part), "attachment_mismatch")

    def test_the_act_kid_of_an_attachment_must_equal_its_header_kid(self):
        target = primary(act_kid=KEYS["bob.sign"]["kid"])
        e = endorse_act(target)
        self.assertEqual(code(decode(e), e.kid, {"act": target.jws}), "attachment_mismatch")


class Caps(unittest.TestCase):
    def test_a_resolve_at_the_caps_is_60_lines_and_its_endorsement_62(self):
        cands = [build("alice", "device.add", org=ORG, parent=PARENT, salt=str(i), performer="a" * 32,
                       body={**device_body("alice2", "alice"), "kid": encoding.b64u_encode(hashlib.sha256(b"k%d" % i).digest()),
                             "label": "L" * 64, "class": "c" * 32, "person": "a" * 32})
                 for i in range(17)]
        ordered = sorted(cands, key=lambda a: a.id)
        heads = ordered[1:17]
        overrides = sorted(({"endorsements": sorted(encoding.hashstr(b"e%d.%d" % (i, j)) for j in range(15)),
                             "resolve": encoding.hashstr(b"r%d" % i)} for i in range(16)), key=lambda e: e["resolve"])
        body = {"candidates": [a.id for a in ordered], "choose": ordered[0].id, "heads": sorted(a.id for a in heads),
                "overrides": overrides}
        res = build("alice", "chain.resolve", org=ORG, body=body, parent=PARENT, performer="a" * 32)
        nested = {"candidates": [a.jws for a in ordered], "heads": [a.jws for a in heads]}
        got = run(decode(res), res.kid, nested)
        self.assertEqual(got.text.count("\n"), 60)
        self.assertTrue(all(len(x) <= 100 for x in got.text.split("\n")))
        e = endorse_act(res, performer="b" * 32, head={"id": PARENT, "kind": "chain"})
        got = run(decode(e), e.kid, {"act": res.jws, **nested})
        self.assertEqual(got.text.count("\n"), 62)
        self.assertLessEqual(len(got.first_line), 80)
        self.assertEqual({len(x) for x in got.text.split("\n") if "(endorsements: 15)" in x}, {37})


class Determinism(unittest.TestCase):
    def test_the_same_input_twice_is_the_same_bytes(self):
        act = verdict_act()
        p = decode(act)
        self.assertEqual(run(p, act.kid, {"request_b64": b64(RAW)}), run(p, act.kid, {"request_b64": b64(RAW)}))


class Refusals(unittest.TestCase):
    def test_schema_and_method_unknown_come_before_any_attachment_check(self):
        act = verdict_act()
        p = decode(act)
        p["extra"] = 1
        self.assertEqual(code(p, act.kid, {}), "schema")
        q = decode(act)
        q["method"] = "local:handsal.nothing"
        self.assertEqual(code(q, act.kid, {}), "method_unknown")


class Command(unittest.TestCase):
    def call(self, value):
        out = io.BytesIO()
        core.run(cli.PURE, ["render"], io.BytesIO(json.dumps(value).encode()), out)
        return json.loads(out.getvalue())

    def test_a_render_is_first_line_and_text(self):
        act = verdict_act()
        got = self.call({"attachments": {"request_b64": b64(RAW)}, "kid": act.kid, "method": decode(act)["method"],
                         "payload": decode(act)})
        self.assertEqual(set(got), {"first_line", "text"})
        self.assertTrue(got["text"].startswith(got["first_line"] + "\n"))

    def test_a_refusal_is_an_error_line(self):
        act = verdict_act()
        got = self.call({"attachments": {}, "kid": act.kid, "method": decode(act)["method"], "payload": decode(act)})
        self.assertEqual(got, {"error": "attachment_missing"})

    def test_a_missing_input_is_malformed_input(self):
        self.assertEqual(self.call({}), {"error": "malformed_input"})


if __name__ == "__main__":
    unittest.main()
