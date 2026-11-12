"""Vectors bod/*: closed body schemas of the non-chain methods (ACT-09, VR-02 step 5).

`check-act` reaches `body_schema` only for verdicts and `record.promote`; a
chain method stops at `chain_method` (step 4). The body rows of the chain methods
are observed through the fold, whose expectation is a state: an act with one body
defect is not on the chain (FO-06), so the state is the genesis state.

The four label rows (quote, backslash, e-acute, del) hold bytes the canonical
subset cannot carry, so the recognizer refuses the payload before any alphabet
check (ACT-10) and the device is absent. The two resolve rows need a fork to be
observable: a resolve with one body defect is ignored, so the fork stays; the
same resolve without the defect would choose c1.
"""
from lib import chain, forge, inputs, state

PLACEHOLDER = "aQXQb"
_LABEL_BYTES = {
    "bod/label-quote": b'a\\"b',
    "bod/label-backslash": b"a\\\\b",
    "bod/label-e-acute": "a\u00e9b".encode("utf-8"),
    "bod/label-del": b"a\x7fb",
}



def _body(edit):
    return forge.act_edit(lambda a: edit(a["body"]))


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    jws = forge.resign(fx, fx.approve(), _body(lambda b: b.__setitem__("x", "y")))
    w.add("bod/approve-body-nonempty", "check-act", inputs.check_anchor(jws, "body_schema"),
          input=inputs.check_input(fx, jws))
    rows = (
        ("bod/record-anchor-empty", [""]),
        ("bod/record-anchors-17", ["anchor-%d" % i for i in range(1, 18)]),
    )
    for name, anchors in rows:
        jws = forge.resign(fx, fx.record_promote(),
                           _body(lambda b, anchors=anchors: b.__setitem__("anchors", anchors)))
        w.add(name, "check-act", inputs.check_anchor(jws, "body_schema"),
              input=inputs.check_input(fx, jws, method=inputs.RECORD_PROMOTE))
    generate_chain_bodies(ctx)


def _label(text):
    return lambda body: body.__setitem__("label", text)


def _raw_label(name):
    def edit(raw):
        if raw.count(b"QXQ") != 1:
            raise AssertionError("label placeholder not found once")
        return raw.replace(PLACEHOLDER.encode("ascii"), _LABEL_BYTES[name])
    return edit


def _add_rows():
    def extra(body):
        body["x"] = "y"

    def no_code(body):
        del body["link_code_hash"]
    return (("bod/device-add-extra-key", extra), ("bod/device-add-missing-link-code", no_code),
            ("bod/label-65", _label("a" * 65)), ("bod/label-empty", _label("")))


def _fork_with(ctx, edit):
    """Two valid children of the root and a resolve whose body `edit` ruins."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c1 = c.device_add("alice2", ("alice", "bob"), ok=False, valid=True, parent=None)
    c2 = c.device_add("carol2", ("carol", "bob"), ok=False, valid=True, parent=None)
    resolve = fx.chain_resolve(("alice", "bob"), candidates=[c1.id, c2.id], choose=c1.id,
                               heads=[c2.id], org=fx.org_id, body_edit=edit)
    return state.fork_anchor(fx.org_id, [c1.id, c2.id]), \
        inputs.fold_input(fx.lineage(), acts=c.acts + resolve.acts)


def generate_chain_bodies(ctx):
    fx, w = ctx.fixtures, ctx.writer
    for name, edit in _add_rows():
        c = chain.Chain(fx, ctx=ctx)
        c.device_add("alice2", ("alice", "bob"), ok=False, body_edit=edit)
        w.add(name, "fold", c.expect(), input=c.fold_input())
    for name in _LABEL_BYTES:
        c = chain.Chain(fx, ctx=ctx)
        c.device_add("alice2", ("alice", "bob"), ok=False, body_edit=_label(PLACEHOLDER),
                     primary_raw_edit=_raw_label(name))
        w.add(name, "fold", c.expect(), input=c.fold_input())
    c = chain.Chain(fx, ctx=ctx)
    c.device_remove("carol", ("alice", "bob"), ok=False,
                    body_edit=lambda b: b.__setitem__("x", "y"))
    w.add("bod/device-remove-extra-key", "fold", c.expect(), input=c.fold_input())
    c = chain.Chain(fx, ctx=ctx)
    c.member_add("dave", ("alice", "bob"), role="admin", ok=False)
    w.add("bod/member-add-role-unlisted", "fold", c.expect(), input=c.fold_input())
    for name, edit in (("bod/resolve-extra-key", lambda b: b.__setitem__("x", "y")),
                       ("bod/resolve-choose-not-hashstr",
                        lambda b: b.__setitem__("choose", "plain"))):
        anchor, data = _fork_with(ctx, edit)
        w.add(name, "fold", anchor, input=data)
