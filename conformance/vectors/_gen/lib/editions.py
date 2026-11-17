"""Cross-edition lineages: the one owner of the shapes a vector over two editions needs (GP-22 to GP-24, CF-08).

A `Pair` is the two editions such a vector spans: P1, the previous edition (the newest catalog row whose production
profile is not the current core, asked of tools/manifest.py through `base`), and P2, the current core. A vector
over production profiles (the owner-signed ones) and a vector over fixture profiles (the generated ones) are the
same shapes over a different kind, so each shape is written once here and `groups/prf.py` and `lib/prodk.py` both
call it. Every builder writes one named row through `ctx`, which records each act it makes for the vitni
cross-check. Nothing here asks a checker for an answer: each anchor is stated from the spec (CF-06).

There is no previous edition before a second edition exists, and then nothing here can be built: `Pair` says so
and stops, it never falls back to one edition.
"""
from . import base, epochs, inputs, renderrows, result, state
from .changes import AB, BC, E0, add, change_row, fold_row, record_sigs

FIXTURE, PRODUCTION = "fixture", "production"
ALL = ("alice", "bob", "carol")
UNKNOWN_CLASS = {"class": "yubikey-piv", "user_verification": "biometric_only"}   # no edition lists this class


class EditionError(Exception):
    pass


class Pair:
    """The previous edition (P1) and the current core (P2) over one kind of profile.

    `kind` is the kind of the profile each document names unless a row mixes kinds (`hash` gives the other). `overlay`
    puts in-memory keys over the fixture keys, as `base.Fixtures` takes it (the production-key vectors)."""

    def __init__(self, kind=FIXTURE, overlay=None):
        if base.previous_edition() is None:
            raise EditionError("no previous edition: a cross-edition vector needs two editions in the catalog and a "
                               "current core that is not the newest row")
        self.kind = kind
        self.p1, self.p2 = self.hash(1, kind), self.hash(2, kind)
        self.fx1 = base.Fixtures(self.p1, overlay=overlay)
        self.fx2 = base.Fixtures(self.p2, overlay=overlay)

    @staticmethod
    def hash(edition, kind):
        """The profile hash of `kind` for edition 1 (the previous one) or 2 (the current core)."""
        if edition == 1:
            return base.previous_profile(kind)
        return base.fixture_profile() if kind == FIXTURE else base.production_profile()


def _profile(profile, edit=None):
    """An `edit` for `make_change` that names `profile` and then applies `edit`."""
    def apply(doc):
        doc["profile"] = profile
        if edit:
            edit(doc)
    return apply


def migrate(e0, profile, *, n=0, carry=ALL, new=(), edit=None):
    """A change of epoch 0 of `e0`, at position `n`, that names `profile` (the carry is byte-identical, GP-20)."""
    return e0.change(n, carry=carry, new=new, edit=_profile(profile, edit))


def _signed(ctx, fx, e0, doc, **kwargs):
    sigs = epochs.sign_change(fx, doc, **kwargs)
    record_sigs(ctx, sigs)
    return epochs.lineage_with(e0.lineage, doc, sigs)


# ---- fold rows ---------------------------------------------------------------------------------------------

def p1_organization(ctx, name, pair):
    """GP-22, GP-07: a lineage of one P1 document, folded by a release whose current edition is P2."""
    e0 = E0(ctx, fx=pair.fx1)
    fold_row(ctx, name, e0.lineage, [])


def change_ok(ctx, name, pair):
    """GP-24, GP-23, GP-19: a P1 original and a P2 change that carries every device, authorized by the P1 policy."""
    e0 = E0(ctx, fx=pair.fx1)
    doc = migrate(e0, pair.p2)
    change_row(ctx, name, e0, doc, epochs.sign_change(pair.fx1, doc))


def change_quorum_unmet(ctx, name, pair):
    """GP-24, GP-19: the same change with one person of the P1 policy: the P1 quorum is unmet."""
    e0 = E0(ctx, fx=pair.fx1)
    doc = migrate(e0, pair.p2, carry=("alice",), new=("frank", "grace"))
    change_row(ctx, name, e0, doc, epochs.sign_change(pair.fx1, doc), error="genesis_change_unauthorized")


def change_fork_path(ctx, name, pair):
    """GP-19, GP-23: a P1 epoch with a second child of position 3, and a P2 change whose H is on the path."""
    fx = pair.fx1
    e0 = E0(ctx, [add("bob2"), add("alice2"), add("bob3")], fx=fx)
    e0.c.device_add("alice4", AB, ok=False, valid=True, parent=e0.built[3])
    e0.c.device_add("alice3", AB)
    e0.c.device_remove("alice", BC)
    doc = migrate(e0, pair.p2, n=3, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, name, e0, doc, epochs.sign_change(fx, doc))


def second_change(ctx, name, pair):
    """GP-24: a P1 original, a P2 change and a second P2 change: the epoch under P2."""
    fx = pair.fx1
    e0 = E0(ctx, fx=fx)
    first = migrate(e0, pair.p2)
    lineage = _signed(ctx, fx, e0, first)
    second = epochs.make_change(fx, first, inputs.doc_id(first), carry=ALL, new=(), st=state.State(first))
    lineage = epochs.lineage_with(lineage, second, epochs.sign_change(fx, second))
    fold_row(ctx, name, lineage, [])


def downgrade_refused(ctx, name, pair):
    """GP-24, GP-15: a P2 original and a P1 change, every other check passing."""
    e0 = E0(ctx, fx=pair.fx2)
    doc = migrate(e0, pair.p1)
    change_row(ctx, name, e0, doc, epochs.sign_change(pair.fx2, doc), error="profile_downgrade")


def downgrade_after_migration(ctx, name, pair):
    """GP-24: a P1 original, a P2 change and a P1 change: `profile_downgrade` for the third document."""
    fx = pair.fx1
    e0 = E0(ctx, fx=fx)
    first = migrate(e0, pair.p2)
    lineage = _signed(ctx, fx, e0, first)
    third = epochs.make_change(fx, first, inputs.doc_id(first), carry=ALL, new=(), st=state.State(first),
                               edit=_profile(pair.p1))
    lineage = epochs.lineage_with(lineage, third, epochs.sign_change(fx, third))
    fold_row(ctx, name, lineage, [], error="profile_downgrade")


def downgrade_before_class(ctx, name, pair):
    """GP-24, GP-15: a downgrade document that also lists a class no edition knows: step 2 before step 3."""
    def lists_unknown_class(doc):
        doc["policy"]["classes"] = sorted(doc["policy"]["classes"] + [UNKNOWN_CLASS], key=lambda c: c["class"])
    e0 = E0(ctx, fx=pair.fx2)
    doc = migrate(e0, pair.p1, edit=lists_unknown_class)
    change_row(ctx, name, e0, doc, epochs.sign_change(pair.fx2, doc), error="profile_downgrade")


def fixture_before_downgrade(ctx, name, pair):
    """GP-24, GP-15: a fixture-profile original and a production-profile change of an older edition: `fixture_profile`.
    Over a pair of fixture profiles."""
    e0 = E0(ctx, fx=pair.fx2)
    doc = migrate(e0, Pair.hash(1, PRODUCTION))
    change_row(ctx, name, e0, doc, epochs.sign_change(pair.fx2, doc), error="fixture_profile")


def mixed_kind(ctx, name, pair):
    """GP-24, GP-18: a fixture-profile P1 original and a production-profile P2 change: `fixture_profile`. Over a pair of
    fixture profiles."""
    e0 = E0(ctx, fx=pair.fx1)
    doc = migrate(e0, Pair.hash(2, PRODUCTION))
    change_row(ctx, name, e0, doc, epochs.sign_change(pair.fx1, doc), error="fixture_profile")


# ---- the other commands ------------------------------------------------------------------------------------

def reprofiled_document_valid(ctx, name, pair):
    """GP-24, I2: D' equals a valid P1 document D in every member but `profile`, `prev`, `org` and `head`."""
    fx = pair.fx1
    e0 = E0(ctx, fx=fx)
    doc = inputs.change_doc(fx, e0.doc, edit=_profile(pair.p2))
    lineage = _signed(ctx, fx, e0, doc)
    org = inputs.doc_id(e0.doc)
    pin = inputs.pin_line(org, inputs.doc_id(doc), pair.p2).decode("ascii")
    ctx.writer.add(name, "genesis-check", result.line({"pin": pin, "reason": "ok", "valid": True}),
                   input={"acts": [], "lineage": lineage})


def pin_names_older_edition(ctx, name, pair):
    """GP-05: a pin whose `spec` is the older edition, over a lineage whose last document names the newer one."""
    fx = pair.fx1
    e0 = E0(ctx, fx=fx)
    lineage = _signed(ctx, fx, e0, migrate(e0, pair.p2))
    org, last = inputs.doc_id(e0.doc), lineage[-1]["doc"]
    pin = inputs.probe(org, inputs.pin_line(org, inputs.doc_id(last), pair.p1))
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    ctx.writer.add(name, "check-act", inputs.check_anchor(approve, "pin_spec_mismatch"),
                   input=inputs.check_input(fx, approve, lineage=lineage, pin=pin))


def successor_supersedes_pin(ctx, name, pair):
    """GP-24, VR-12: a P1 pin and a known valid P2 successor of the pinned document (`next` is `"yes"`)."""
    fx = pair.fx1
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    ctx.writer.add(name, "check-act", inputs.check_anchor(approve, "epoch_superseded"),
                   input=inputs.check_input(fx, approve, next="yes"))


def recheck_after_repin(ctx, name, pair):
    """VR-17, GP-23: an approve whose head is in the P1 epoch, re-checked under a pin at the P2 document."""
    fx = pair.fx1
    e0 = E0(ctx, fx=fx)
    lineage = _signed(ctx, fx, e0, migrate(e0, pair.p2))
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    ctx.writer.add(name, "recheck-act", inputs.recheck_anchor(approve, "ok"),
                   input=inputs.recheck_input(fx, approve, lineage=lineage, pin=inputs.probe_for(lineage)))


def render_change(ctx, name, pair):
    """RN-09, RN-10: a change `genesis.sign` whose `previous` names P1 and whose `document` names P2."""
    fx = pair.fx1
    original = fx.org
    change = epochs.make_change(fx, original, fx.org_id, carry=("alice", "bob"), new=("frank",),
                                edit=_profile(pair.p2))
    renderrows.genesis_row(ctx, name, change, {"document": change, "previous": original})
