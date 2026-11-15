"""The generator's own fold of a snapshot (lib/foldmodel.py): the oracle of the whole-set guard (CF-06, CF-14).

It is a model stated from the spec (FO-21 to FO-26, GP-15, GP-19), never a call into the checker. Two proofs:
it agrees with the `fold` rows the generator already ships, whose anchors were authored from the spec with
`Chain` and `state.py` (so the model and the authored statements check each other), and the guard built on it
refuses a drop that changes an answer.
"""
import glob
import json
import unittest
from pathlib import Path

from lib import base, chain, epochs, foldmodel, forge, inputs, state
from lib.changes import E0, record_sigs
from lib.forks import AB, BC

HERE = Path(__file__).resolve()
VECTORS = HERE.parents[2]
FX = base.Fixtures(base.fixture_profile())

# Rows whose anchor rests on a rule the model does not state: the body schema of an act (ACT-09), a kind of
# genesis error beyond the three the model reads, a witness or a pin step. The model is asked about the three
# answers a drop can move: a state, a fork, and the three lineage codes of the closing head.
LINEAGE_CODES = ("genesis_head_unknown", "genesis_unsigned", "genesis_change_unauthorized")


# Rows whose anchor rests on a rule the model does not state. The model is asked about the answers a drop can
# move (a state, a fork, the three lineage codes); these rows are in that set and still differ, each for one reason.
BODY_SCHEMA = {   # the schema of an act body (ACT-09, ACT-11): the model reads the fields a rule uses, not their form
    "add/agree-reused",
    "bod/device-add-extra-key",
    "bod/device-add-missing-link-code",
    "bod/device-remove-extra-key",
    "bod/label-65",
    "bod/label-backslash",
    "bod/label-del",
    "bod/label-e-acute",
    "bod/label-empty",
    "bod/label-quote",
    "bod/resolve-extra-key",
    "fld/agree-equals-sign",
    "lnk/code-hash-format",
    "lnk/reused-code",
    "rsv/candidates-over-17-schema",
    "rsv/override-entry-bare-hashstr-schema",
    "rsv/override-entry-non-canonical-hashstr",
    "rsv/override-entry-shape-schema",
    "rsv/override-entry-sixteen-endorsements-schema",
    "rsv/override-resolve-non-canonical-hashstr",
    "rsv/overrides-missing-schema",
    "sch/chain-primary-with-head",
    "sch/resolve-with-head"}
ENVELOPE = {   # ACT-13 on a chain act: performer and parent performer are not compared
    "add/pop-performer-mismatch",
    "end/parent-performer-mismatch",
    "fld/parent-performer-mismatch",
    "fld/parent-performer-null-non-root",
    "fld/root-child-parent-performer-set",
    "fld/same-payload-other-key-not-counted"}
OTHER = {
    "add/kid-removed-in-earlier-epoch",   # GP-20: a kid removed in an earlier epoch is not carried again
    "key/x-leading-zero-ok",   # a crafted key that no fixture device holds, so its signature has no key to verify under
}
OUT_OF_SCOPE_ROWS = BODY_SCHEMA | ENVELOPE | OTHER


def fold_rows():
    for path in sorted(glob.glob(str(VECTORS / "*.json"))):
        v = json.loads(Path(path).read_text(encoding="utf-8"))
        if v["command"] == "fold" and isinstance(v.get("input"), dict) and "at" not in v["input"]:
            yield v


def in_scope(anchor):
    out = json.loads(anchor)
    return "error" not in out or out["error"] in ("fork",) + LINEAGE_CODES


class ModelReadsALinearChain(unittest.TestCase):
    def test_the_state_at_the_tip_is_the_state_the_chain_helper_states(self):
        c = chain.Chain(FX)
        c.device_add("alice2", AB)
        c.device_add("bob2", BC)
        c.device_remove("alice2", BC)
        model = foldmodel.Model(FX, c.acts, c.lineage)
        self.assertEqual(model.answer(inputs.doc_id(c.lineage[-1]["doc"])), c.expect())

    def test_a_fork_is_the_fork_with_its_sorted_candidates(self):
        c = chain.Chain(FX)
        one = c.device_add("alice2", AB)
        two = c.device_add("bob2", BC, parent=None, ok=False, valid=True)
        model = foldmodel.Model(FX, c.acts, c.lineage)
        self.assertEqual(model.answer(c.root), state.fork_anchor(c.root, [one.id, two.id]))

    def test_a_pending_primary_is_no_child(self):   # FO-24, FO-22: one touch is no quorum
        c = chain.Chain(FX)
        c.device_add("alice2", AB)
        c.device_add("bob2", ("bob",), ok=False, short=True)
        model = foldmodel.Model(FX, c.acts, c.lineage)
        self.assertEqual(model.answer(c.root), c.expect())

    def test_an_act_of_another_organization_is_ignored(self):   # FO-06
        c = chain.Chain(FX)
        c.device_add("alice2", AB)
        other = chain.Chain(FX, wit=True)
        other.device_add("alice3", AB)
        model = foldmodel.Model(FX, c.acts + other.acts, c.lineage)
        self.assertEqual(model.answer(c.root), c.expect())

    def test_an_act_of_another_organization_at_a_node_of_ours_is_ignored(self):   # FO-06, GP-04
        c = chain.Chain(FX)
        c.device_add("alice2", AB)
        foreign = chain.Chain(FX, org_id=FX.wit_org_id)
        foreign.device_add("bob2", AB, ok=False)   # a primary, an endorsement and a proof, all signed for the other org
        model = foldmodel.Model(FX, c.acts + foreign.acts, c.lineage)
        self.assertEqual(model.answer(c.root), c.expect())

    def test_an_endorsement_of_another_organization_does_not_count(self):   # FO-08, GP-04
        c = chain.Chain(FX)
        primary, endorsement, proof = c.device_add("alice2", AB, ok=False).acts
        other = forge.resign(FX, endorsement, forge.act_edit(lambda act: act.__setitem__("org", FX.wit_org_id)))
        model = foldmodel.Model(FX, [primary, other, proof], c.lineage)
        self.assertEqual(model.answer(c.root), chain.Chain(FX).expect())   # one person is no quorum
        applied = chain.Chain(FX)
        applied.device_add("alice2", AB)
        own = foldmodel.Model(FX, [primary, endorsement, proof], c.lineage)
        self.assertEqual(own.answer(c.root), applied.expect())   # control: only the endorsement's `org` differs

    def test_a_garbage_twin_never_shadows_the_valid_copy(self):   # FO-21
        c = chain.Chain(FX)
        built = c.device_add("alice2", AB)
        head, payload, _ = forge.parts(built.acts[0])
        garbage = forge.join(head, payload, bytes(64))
        model = foldmodel.Model(FX, [garbage] + c.acts, c.lineage)
        self.assertEqual(model.answer(c.root), c.expect())
        only = foldmodel.Model(FX, [garbage], c.lineage)
        self.assertEqual(only.answer(c.root), chain.Chain(FX).expect())


class ModelReadsEpochs(unittest.TestCase):
    def test_a_change_is_read_along_the_path_to_its_head_and_the_acts_above_it_are_not_read(self):
        class Ctx:   # the cross-check is not asked here
            fixtures = FX
            def positive(self, *a): pass
            def negative(self, *a): pass
        ctx = Ctx()
        e0 = E0(ctx, [lambda c: c.device_add("alice2", AB), lambda c: c.device_add("bob2", AB),
                      lambda c: c.device_add("alice3", AB)])
        doc = e0.change(2, carry=("alice", "bob"), new=("grace",))
        sigs = epochs.sign_change(FX, doc)
        lineage = epochs.lineage_with(e0.lineage, doc, sigs)
        leaf = inputs.doc_id(doc)
        whole = foldmodel.Model(FX, e0.c.acts, lineage).answer(leaf)
        self.assertEqual(whole, state.anchor(state.State(doc)))
        path_only = [a for built in e0.built[1:3] for a in built.acts]
        self.assertEqual(foldmodel.Model(FX, path_only, lineage).answer(leaf), whole)
        # the head is no node once a path node is gone
        cut = [a for a in path_only if a not in e0.built[2].acts]
        self.assertEqual(foldmodel.Model(FX, cut, lineage).answer(leaf), inputs.error_anchor("genesis_head_unknown"))
        # a possession receipt that a device needs is not droppable
        fewer = [{"doc": doc, "sigs": sigs[1:]}]
        got = foldmodel.Model(FX, path_only, e0.lineage + fewer).answer(leaf)
        self.assertIn(json.loads(got).get("error"), ("genesis_unsigned", "genesis_change_unauthorized"))


class ModelAgreesWithTheShippedFoldRows(unittest.TestCase):
    def test_every_fold_row_in_scope_has_the_anchor_the_spec_gives(self):
        agreed, out_of_scope, disagree = 0, 0, []
        for v in fold_rows():
            if not in_scope(v["anchor"]):
                out_of_scope += 1
                continue
            lineage = v["input"]["lineage"]
            try:
                got = foldmodel.Model(FX, v["input"]["acts"], lineage).answer(inputs.doc_id(lineage[-1]["doc"]))
            except foldmodel.Unsupported:
                out_of_scope += 1
                continue
            if got == v["anchor"]:
                agreed += 1
            else:
                disagree.append(v["name"])
        self.assertEqual(sorted(disagree), sorted(OUT_OF_SCOPE_ROWS))
        self.assertGreater(agreed, 150)


if __name__ == "__main__":
    unittest.main()
