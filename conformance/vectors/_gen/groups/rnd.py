"""Vectors rnd/*: the render text and its refusals (RN-01 to RN-12, T3.47).

Every row is a `render` input `{attachments, kid, method, payload}` over a real act and
an anchor authored by `lib/render.py`, the generator's own model of the spec text
(CF-06), which `tests/test_render.py` pins against literal lines. A refusal row states
its code here and the model must agree before the row is written.

The input shape is the CF-03 `render` shape: `payload` is the signed payload as a JSON object,
`kid` the header kid, attachments keyed by the RN-09 names.

The texts follow RN-02 to RN-05, RN-08, RN-10 and RN-12 as `lib/render.py` writes them.
Ten `rnd/prompt-line-max-*` ids hold one method each (RN-03); the genesis rows use documents
that fit the 72-line bound with two-digit counts.

`rnd/resolve-candidate-missing` and `rnd/resolve-head-attachment-missing` follow RN-09: the list
is present and lacks an id, so `attachment_mismatch`; only an absent name is `attachment_missing`.
"""
from lib import base, epochs, forge, inputs, renderrows, retired
from lib.changes import AB as TWO, E0, add, remove

AB = ("alice", "bob")
LONG_MEMBER, LONG_ROLE = "m" * 32, "r" * 32
LONG_REQUEST_ID = "req-" + "0" * 32
LONG_RELAY = ".".join(["r" * 63] * 3 + ["r" * 61])  # 253 characters, labels of at most 63 (section 2.2)
LONG_PERSON = "p" * 32
LONG_CONSUMER = "consumer-" + "c" * 23  # a consumer_id is at most 32 characters (section 2.2)
LONG_SUBJECT = "subject-" + "0" * 56  # a subject_id is at most 64 characters (section 2.2)
FULL_REQUEST = b"\n".join([b"x" * 63] * 31 + [b"y" * 64])  # exactly 2048 bytes, 32 lines
CAPS_PERFORMER = "a" * 32 + "1"  # a device whose person is a 32-character performer id


_pos, _input, _add, _genesis_row = (renderrows.pos, renderrows.render_input, renderrows.add,
                                    renderrows.genesis_row)


def _verdict_row(ctx, name, kind="approve", *, request=base.REQUEST, attached=None, error=None,
                 extra=None, **kwargs):
    fx = ctx.fixtures
    jws = fx.verdict(kind, request=request, **kwargs)
    _pos(ctx, jws)
    attachments = {"request_b64": fx.request_b64(request if attached is None else attached)}
    attachments.update(extra or {})
    return _add(ctx, name, _input(jws, attachments), error)


def _request_rows(ctx):
    fx = ctx.fixtures
    _verdict_row(ctx, "rnd/approve")
    _verdict_row(ctx, "rnd/reject", "reject")
    _verdict_row(ctx, "rnd/needs-info", "needs-info")
    _verdict_row(ctx, "rnd/no-org-name-non-genesis", wit=True)
    _verdict_row(ctx, "rnd/determinism", request=b"render twice")
    _verdict_row(ctx, "rnd/line1-approve-size")
    _verdict_row(ctx, "rnd/first-line-tilde", request_id=LONG_REQUEST_ID)
    _verdict_row(ctx, "rnd/sender-not-proven", extra={"sender": "mallory"})
    _verdict_row(ctx, "rnd/hash12-skips-uEi", request=b"short forms skip the prefix")
    for name, raw in (
            ("hostile-bidi", b"ok \xe2\x80\xae evil"), ("hostile-control", b"a\x1b[31mred"),
            ("hostile-delimiter", b"----- end -----"), ("hostile-nul", b"a\x00b"),
            ("invalid-utf8", b"\xff\xff"), ("non-ascii-escaped", "café".encode("utf-8")),
            ("nonbmp-escape", "\U0001F600".encode("utf-8")), ("tab-escaped", b"a\tb"),
            ("crlf-escaped", b"a\r\nb"), ("empty-request", b"")):
        _verdict_row(ctx, "rnd/" + name, request=raw)
    _verdict_row(ctx, "rnd/request-exactly-2048-ok",
                 request=b"\n".join([b"x" * 63] * 31 + [b"y" * 64]))
    _verdict_row(ctx, "rnd/request-33-lines-refused", request=b"\n".join([b"x"] * 33),
                 error="render_refused")
    _verdict_row(ctx, "rnd/request-32-lines-cap", request=b"\n".join([b"x"] * 40),
                 error="render_refused")
    _verdict_row(ctx, "rnd/request-over-2048-refused", request=b"x" * 2049,
                 error="render_refused")
    _verdict_row(ctx, "rnd/oversize-truncated", request=b"x" * 5000, error="render_refused")
    _verdict_row(ctx, "rnd/request-attachment-mismatch", attached=b"another request",
                 error="attachment_mismatch")
    _verdict_row(ctx, "rnd/long-line-wrapped", relay=LONG_RELAY)  # RN-02: 98 + 98 + 64 bytes
    _verdict_row(ctx, "rnd/request-long-line-continuation", request=b"x" * 300)
    # RN-05: the sixth escape would end at byte 99, so the line breaks before it
    _verdict_row(ctx, "rnd/truncate-not-inside-escape",
                 request=b"x" * 95 + "\u00e9".encode("utf-8"))


def _decision_row(ctx, name, *, content=base.DECISION_BODY, attached=None, attachments=None, error=None,
                  **kwargs):
    """A `render` row over a decision (RN-03, RN-04, RN-09, RN-12, VR-18): the content is attached unless
    `attachments` says otherwise, and `attached` is other bytes than the ones the act binds."""
    fx = ctx.fixtures
    jws = fx.decision(content=content, **kwargs)
    _pos(ctx, jws)
    if attachments is None:
        attachments = {"decision_b64": fx.request_b64(content if attached is None else attached)}
    return _add(ctx, name, _input(jws, attachments), error)


def _decision_rows(ctx):
    _decision_row(ctx, "rnd/decision")
    _decision_row(ctx, "rnd/decision-empty", content=b"")
    _decision_row(ctx, "rnd/decision-block-hostile", content=b"----- end -----")
    _decision_row(ctx, "rnd/decision-attachment-mismatch", attached=b"another content",
                  error="attachment_mismatch")
    _decision_row(ctx, "rnd/decision-attachment-missing", attachments={}, error="attachment_missing")
    _decision_row(ctx, "rnd/decision-over-2048-refused", content=b"x" * 2049, error="render_refused")
    _decision_row(ctx, "rnd/decision-33-lines-refused", content=b"\n".join([b"x"] * 33),
                  error="render_refused")
    _decision_row(ctx, "rnd/decision-exactly-2048-ok", content=FULL_REQUEST)
    _decision_row(ctx, "rnd/decision-action-grammar-refused", action="Ratify ruling", error="body_schema")
    # RN-03: the longest consumer, action and subject and the largest block, line 1 is exactly 80 bytes
    _decision_row(ctx, "rnd/prompt-line-max-decision", content=FULL_REQUEST, consumer=LONG_CONSUMER,
                  action=base.DECISION_ACTION_24, subject=LONG_SUBJECT)
    # RN-03 S3: the 14 bytes `record body v1` hash to `AnLrsJDp-lmi` after `uEi`: a dash opens the third group,
    # and the hash depends on the content alone, so no re-pin moves it
    _decision_row(ctx, "rnd/decision-hash12-dash", content=retired.BODY)


def _chain_rows(ctx):
    fx = ctx.fixtures
    dev = fx.device_add("alice2", AB)
    for jws in dev.acts[:2]:
        _pos(ctx, jws)
    for name in ("rnd/device-add", "rnd/device-add-agree-key-id", "rnd/line1-device-add-class"):
        _add(ctx, name, _input(dev.acts[0], {}))
    rem = fx.device_remove("carol", AB)
    _pos(ctx, rem.acts[0])
    _add(ctx, "rnd/device-remove", _input(rem.acts[0], {}))
    for name, device in (("rnd/member-add", "dave"), ("rnd/line1-member-add-kid-first", "dave2")):
        mem = fx.member_add(device, AB, role="member")
        _pos(ctx, mem.acts[0])
        _add(ctx, name, _input(mem.acts[0], {}))

    for name in ("rnd/endorse", "rnd/endorse-shows-endorsed-id"):
        _add(ctx, name, _input(dev.acts[1], {"act": dev.acts[0]}))
    other = fx.device_add("alice3", AB)
    _pos(ctx, other.acts[0])
    _add(ctx, "rnd/endorse-attachment-mismatch", _input(dev.acts[1], {"act": other.acts[0]}),
         "attachment_mismatch")
    _add(ctx, "rnd/endorse-attachment-missing", _input(dev.acts[1], {}), "attachment_missing")
    _add(ctx, "rnd/attachment-wrong-type-mismatch", _input(dev.acts[1], {"act": 7}),
         "attachment_mismatch")
    _add(ctx, "rnd/endorse-primary-extra-attachment",
         _input(dev.acts[1], {"act": dev.acts[0], "heads": [dev.acts[0]]}), "attachment_mismatch")


class _Fork:
    """Two device.add children of the root, A and B, and the attachments of a resolve over them."""

    def __init__(self, ctx):
        fx = ctx.fixtures
        self.fx = fx
        self.a = fx.device_add("alice2", AB)
        self.b = fx.device_add("alice3", AB)
        for built in (self.a, self.b):
            _pos(ctx, built.acts[0])

    def resolve(self, choose, heads, signers=AB, **kwargs):
        return self.fx.chain_resolve(signers, candidates=[self.a.id, self.b.id], choose=choose,
                                     heads=heads, **kwargs)

    def attachments(self, head_acts):
        return {"candidates": [self.a.acts[0], self.b.acts[0]], "heads": list(head_acts)}


def _resolve_rows(ctx):
    fx = ctx.fixtures
    fork = _Fork(ctx)
    res = fork.resolve(fork.a.id, [fork.b.id])
    _pos(ctx, res.acts[0])
    _add(ctx, "rnd/chain-resolve", _input(res.acts[0], fork.attachments([fork.b.acts[0]])))
    res_b = fork.resolve(fork.b.id, [fork.a.id])
    _pos(ctx, res_b.acts[0])
    _add(ctx, "rnd/line1-resolve", _input(res_b.acts[0], fork.attachments([fork.a.acts[0]])))
    _add(ctx, "rnd/resolve-candidates-listed",
         _input(res_b.acts[0], fork.attachments([fork.a.acts[0]])))

    # a long member.add as the kept candidate: its line 1 is cut at 59 bytes
    long_member = fx.member_add("dave", AB, role=LONG_ROLE, member=LONG_MEMBER)
    plain = fx.device_add("alice2", AB)
    for built in (long_member, plain):
        _pos(ctx, built.acts[0])
    keep = fx.chain_resolve(AB, candidates=[long_member.id, plain.id], choose=long_member.id,
                            heads=[plain.id])
    _pos(ctx, keep.acts[0])
    keep_att = {"candidates": [long_member.acts[0], plain.acts[0]], "heads": [plain.acts[0]]}
    _add(ctx, "rnd/line1-resolve-keeps-kid12", _input(keep.acts[0], keep_att))
    _pos(ctx, keep.acts[1])
    _add(ctx, "rnd/line1-endorse-bounded", _input(keep.acts[1], dict(keep_att, act=keep.acts[0])))

    # the losing candidate B has two children: d1 and d2 are the heads
    d1 = fx.device_add("bob2", AB, parent=fork.b)
    d2 = fx.device_add("carol2", AB, parent=fork.b)
    for built in (d1, d2):
        _pos(ctx, built.acts[0])
    heads = [d1.acts[0], d2.acts[0]]
    two = fork.resolve(fork.a.id, [d1.id, d2.id], signers=("alice", "bob", "carol"))
    for jws in two.acts[:2]:
        _pos(ctx, jws)
    two_att = fork.attachments(heads)
    _add(ctx, "rnd/resolve-heads-attached", _input(two.acts[0], two_att))
    _add(ctx, "rnd/endorse-resolve-nested-attached",
         _input(two.acts[1], dict(two_att, act=two.acts[0])))
    _add(ctx, "rnd/endorse-resolve-heads-missing",
         _input(two.acts[1], {"act": two.acts[0], "candidates": two_att["candidates"]}),
         "attachment_missing")
    stranger = fx.device_add("alice4", AB)
    _pos(ctx, stranger.acts[0])
    _add(ctx, "rnd/endorse-resolve-candidate-mismatch",
         _input(two.acts[1], {"act": two.acts[0], "heads": heads,
                              "candidates": [fork.a.acts[0], stranger.acts[0]]}),
         "attachment_mismatch")

    # a head act whose act-object kid is not its header kid (ACT-14)
    bent = forge.resign(fx, d2.acts[0], forge.act_edit(
        lambda a: a.__setitem__("kid", fx.key("carol").kid)))
    resolve = fork.resolve(fork.a.id, sorted([d1.id, inputs.receipt_id(bent)]))
    _pos(ctx, resolve.acts[0])
    _add(ctx, "rnd/attachment-act-kid-differs",
         _input(resolve.acts[0], fork.attachments([d1.acts[0], bent])), "attachment_mismatch")

    # a candidate whose parent is not the resolve's parent
    child = fx.device_add("alice4", AB, parent=fork.a)
    _pos(ctx, child.acts[0])
    wrong = fx.chain_resolve(AB, candidates=[fork.a.id, child.id], choose=fork.a.id,
                             heads=[child.id])
    _pos(ctx, wrong.acts[0])
    _add(ctx, "rnd/resolve-candidate-wrong-parent",
         _input(wrong.acts[0], {"candidates": [fork.a.acts[0], child.acts[0]],
                                "heads": [child.acts[0]]}), "attachment_mismatch")

    # a list that is present and lacks an id is a mismatch; only an absent name is missing (RN-09)
    plain = fork.resolve(fork.a.id, [fork.b.id])
    _pos(ctx, plain.acts[0])
    _add(ctx, "rnd/resolve-candidate-missing",
         _input(plain.acts[0], {"candidates": [fork.a.acts[0]], "heads": [fork.b.acts[0]]}),
         "attachment_mismatch")
    _add(ctx, "rnd/resolve-head-attachment-missing",
         _input(two.acts[0], {"candidates": two_att["candidates"], "heads": [d1.acts[0]]}),
         "attachment_mismatch")

    # RN-09 Order of checks: an attachment is read and bound before the next one is asked for. The
    # attached act is another resolve, so `candidates` and `heads` would be asked for next and are
    # absent; the first defect, the act that does not bind, decides
    other = fork.resolve(fork.b.id, [fork.a.id])
    _pos(ctx, other.acts[0])
    _add(ctx, "rnd/endorse-resolve-act-mismatch-before-heads-missing",
         _input(two.acts[1], {"act": other.acts[0]}), "attachment_mismatch")
    # candidates that do not bind, and no heads at all: candidates come first
    _add(ctx, "rnd/resolve-candidates-mismatch-before-heads-missing",
         _input(plain.acts[0], {"candidates": [fork.a.acts[0]]}), "attachment_mismatch")

    # overrides entries: one with two endorsements, one with one (RN-04)
    first = fork.resolve(fork.a.id, [fork.b.id], signers=("alice", "bob", "carol"))
    for jws in first.acts[:3]:
        _pos(ctx, jws)
    ids = [inputs.receipt_id(first.acts[1]), inputs.receipt_id(first.acts[2])]
    for name, endorsements in (("rnd/resolve-override-entry-line", sorted(ids)),
                               ("rnd/resolve-override-entry-line-one", ids[:1])):
        newer = fork.resolve(fork.b.id, [fork.a.id], overrides=[
            {"endorsements": endorsements, "resolve": first.id}])
        _pos(ctx, newer.acts[0])
        _add(ctx, name, _input(newer.acts[0], fork.attachments([fork.a.acts[0]])))


def _bigger(fx, count):
    """ORG plus `count` synthetic maintainers, each with one device."""
    members, devices = inputs.synthetic_members(count)
    return inputs.derive(fx.org, lambda d: d.update(
        members=sorted(d["members"] + members, key=lambda m: m["id"]),
        devices=sorted(d["devices"] + devices, key=lambda x: x["kid"])))


def _genesis_text_rows(ctx):
    fx = ctx.fixtures
    original = fx.org
    for name in ("rnd/genesis-sign-original", "rnd/genesis-agree-key-id",
                 "rnd/genesis-class-own-line", "rnd/genesis-profile-full"):
        _genesis_row(ctx, name, original, {"document": original})

    # one member and one device replaced: carol out, frank in (RN-10)
    change = epochs.make_change(fx, original, fx.org_id, carry=("alice", "bob"), new=("frank",))
    att = {"document": change, "previous": original}
    for name in ("rnd/genesis-sign-change", "rnd/genesis-change-diff",
                 "rnd/genesis-change-head-line"):
        _genesis_row(ctx, name, change, att)

    # a rename opens the method lines with `Org name` and `Profile`
    renamed = epochs.make_change(fx, original, fx.org_id, carry=("alice", "bob", "carol"), new=(),
                                 edit=lambda d: d.update(name="renamed"))
    _genesis_row(ctx, "rnd/genesis-change-org-name-profile-lines", renamed,
                 {"document": renamed, "previous": original})

    # a rule lowered from 3 to 2 persons: the policy lines show the new value
    four = epochs.org4(fx, persons="3")
    lowered = epochs.make_change(
        fx, four, inputs.doc_id(four), carry=("alice", "bob", "carol", "erin"), new=(),
        edit=lambda d: d["policy"]["rules"]["member.add"].update(persons="2"))
    _genesis_row(ctx, "rnd/genesis-policy-lines", lowered, {"document": lowered, "previous": four})

    # a device swapped for the same person, nobody else touched: +1/-1 dev, 0 mem, policy same
    e0 = E0(ctx, [remove("carol", TWO), add("carol2", TWO)])
    swap = e0.change(2, carry=("alice", "bob", "carol"), new=())
    _genesis_row(ctx, "rnd/line1-genesis-change-summary", swap,
                 {"document": swap, "previous": original})

    # RN-09: the head, and documents that bind by hash and are not valid alone
    _genesis_row(ctx, "rnd/genesis-head-mismatch", change, att, "attachment_mismatch",
                 head=fx.wit_org_id)
    invalid = inputs.derive(original, lambda d: d["members"][0].update(role="unlisted"))
    _genesis_row(ctx, "rnd/genesis-document-invalid-bound", invalid, {"document": invalid},
                 "attachment_mismatch")
    over_invalid = inputs.change_doc(fx, previous=invalid)
    _genesis_row(ctx, "rnd/genesis-previous-invalid-bound", over_invalid,
                 {"document": over_invalid, "previous": invalid}, "attachment_mismatch")


def _max_rows(ctx):
    """One row per method at the longest fields, line 1 at most 80 bytes (RN-03)."""
    fx = ctx.fixtures
    fx.register_device(LONG_PERSON + "1", "rnd-max/sign", "rnd-max/agree")
    long_dev = LONG_PERSON + "1"
    dev = fx.device_add(long_dev, AB)
    _pos(ctx, dev.acts[0])
    _add(ctx, "rnd/prompt-line-max-length", _input(dev.acts[0], {}))
    rem = fx.device_remove(long_dev, AB)
    _pos(ctx, rem.acts[0])
    _add(ctx, "rnd/prompt-line-max-device-remove", _input(rem.acts[0], {}))
    mem = fx.member_add("dave", AB, role=LONG_ROLE, member=LONG_MEMBER)
    _pos(ctx, mem.acts[0])
    _add(ctx, "rnd/prompt-line-max-member-add", _input(mem.acts[0], {}))
    plain = fx.device_add("alice2", AB)
    _pos(ctx, plain.acts[0])
    keep = fx.chain_resolve(AB, candidates=[mem.id, plain.id], choose=mem.id, heads=[plain.id])
    _pos(ctx, keep.acts[0])
    _add(ctx, "rnd/prompt-line-max-resolve", _input(keep.acts[0], {
        "candidates": [mem.acts[0], plain.acts[0]], "heads": [plain.acts[0]]}))
    for kind in ("approve", "reject", "needs-info"):
        _verdict_row(ctx, "rnd/prompt-line-max-" + kind, kind, request=FULL_REQUEST,
                     request_id=LONG_REQUEST_ID)

    # ten members and ten devices: two-digit counts, 71 lines
    ten = inputs.derive(_bigger(fx, 7), lambda d: d.update(name="n" * 24))
    _genesis_row(ctx, "rnd/prompt-line-max-genesis-original", ten, {"document": ten})
    # a change that drops ten members and adds two: +2/-10 dev, 12 mem
    base_doc = inputs.derive(_bigger(fx, 10), lambda d: d.update(name="o" * 24))
    change = epochs.make_change(fx, base_doc, inputs.doc_id(base_doc), carry=("alice", "bob", "carol"),
                                new=("frank", "grace"), edit=lambda d: d.update(name="n" * 24))
    _genesis_row(ctx, "rnd/prompt-line-max-genesis-change", change,
                 {"document": change, "previous": base_doc})


def _genesis_rows(ctx):
    fx = ctx.fixtures
    original = fx.org
    jws = fx.genesis_sign("alice", original)
    _pos(ctx, jws)
    _add(ctx, "rnd/genesis-attachment-hash-mismatch", _input(jws, {"document": fx.wit_org}),
         "attachment_mismatch")

    change = inputs.change_doc(fx)
    jws = fx.genesis_sign("alice", change)
    _pos(ctx, jws)
    _add(ctx, "rnd/genesis-change-previous-mismatch",
         _input(jws, {"document": change, "previous": fx.wit_org}), "attachment_mismatch")

    # RN-09 Order of checks: head presence (the act object's form) comes before `previous` is read
    headless = fx.genesis_sign("alice", change, head=None)
    _pos(ctx, headless)
    _add(ctx, "rnd/genesis-head-missing-before-previous-missing",
         _input(headless, {"document": change}), "schema")

    _genesis_text_rows(ctx)
    extra_members, extra_devices = inputs.synthetic_members(17)

    def grow(doc):
        doc["members"] = sorted(doc["members"] + extra_members, key=lambda m: m["id"])
        doc["devices"] = sorted(doc["devices"] + extra_devices, key=lambda d: d["kid"])
    big = inputs.derive(original, grow)
    problems = base.check_genesis_shape(big)
    if problems:
        raise AssertionError("rnd/render-73-lines-refused: %s" % problems)
    jws = fx.genesis_sign("alice", big)
    _pos(ctx, jws)
    _add(ctx, "rnd/render-73-lines-refused", _input(jws, {"document": big}), "render_refused")


def _refusal_rows(ctx):
    fx = ctx.fixtures
    jws = fx.approve()
    _pos(ctx, jws)
    att = {"request_b64": fx.request_b64()}
    inp = _input(jws, att)
    inp["payload"]["extra"] = "x"
    _add(ctx, "rnd/refuse-extra-key", inp, "schema")
    inp = _input(jws, att)
    inp["method"] = inp["payload"]["method"] = "local:handsal.request.send"
    _add(ctx, "rnd/refuse-unknown-method", inp, "method_unknown")
    dev = fx.device_add("alice2", AB)
    _pos(ctx, dev.acts[0])
    inp = _input(dev.acts[0], {})  # a quote cannot be signed (ACT-10), so only the object has it
    inp["payload"]["ext"]["dev.handsal/act"]["body"]["label"] = 'a"b'
    _add(ctx, "rnd/refuse-label-quote", inp, "body_schema")


def _caps_rows(ctx):
    """A resolve at the ACT-09 caps and its endorsement (RN-04, 16.21)."""
    fx = ctx.fixtures
    fx.register_device(CAPS_PERFORMER, "rnd-caps/sign", "rnd-caps/agree")
    parent = fx.device_add("alice2", (CAPS_PERFORMER, "bob"))
    names = ["alice%d" % n for n in range(10, 27)]
    for name in names:
        fx.register_device(name, "rnd-caps/%s/sign" % name, "rnd-caps/%s/agree" % name)
    candidates = [fx.member_add(n, AB, role=LONG_ROLE, member=LONG_MEMBER, parent=parent)
                  for n in names]
    by_id = {c.id: c for c in candidates}
    ids = sorted(by_id)
    choose, heads = ids[0], ids[1:]
    entries = sorted(({"endorsements": sorted(base.hashstr(b"rnd-caps/endorse/%02d/%02d" % (r, e))
                                              for e in range(15)),
                       "resolve": base.hashstr(b"rnd-caps/resolve/%02d" % r)}
                      for r in range(16)), key=lambda e: e["resolve"])
    resolve = fx.chain_resolve((CAPS_PERFORMER, "alice"), candidates=ids, choose=choose,
                               heads=heads, overrides=entries, parent=parent)
    for built in [parent] + candidates + [resolve]:
        _pos(ctx, built.acts[0])
    _pos(ctx, resolve.acts[1])
    att = {"candidates": [by_id[i].acts[0] for i in ids], "heads": [by_id[i].acts[0] for i in heads]}
    _add(ctx, "rnd/resolve-max-caps-fits", _input(resolve.acts[0], att))
    _add(ctx, "rnd/endorse-resolve-max-caps-fits",
         _input(resolve.acts[1], dict(att, act=resolve.acts[0])))


def _retired_rows(ctx):
    """ACT-09 S9: a payload of the retired record method is `method_unknown` to every renderer, whatever
    attachment a caller of the old method still sends."""
    jws = retired.jws(ctx.fixtures)
    _add(ctx, "rnd/record-promote-retired-refused", _input(jws, retired.attachments()), "method_unknown")


def generate(ctx):
    _request_rows(ctx)
    _decision_rows(ctx)
    _retired_rows(ctx)
    _chain_rows(ctx)
    _resolve_rows(ctx)
    _genesis_rows(ctx)
    _max_rows(ctx)
    _refusal_rows(ctx)
    _caps_rows(ctx)
