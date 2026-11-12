"""T3.24 vectors frk/*, rsv/*, cln/* and sch/resolve-with-head: forks, resolves, cleanliness.

Per row the test states, from FO-24 to FO-26, what the walk gives: a fork (with how many
candidates, and whether its parent is the root) or the state at position n. The checks read
the vector against that statement: candidate ids are sorted ids of chain primaries of the
bag, the parent is the root or such a primary, a state's tip is a primary of the bag.
"""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
ROOT, NOT_ROOT = True, False
FORKS = {
    "frk/quorum-equivocation-freeze": (2, ROOT), "frk/two-identical-bodies-fork": (2, ROOT),
    "frk/two-valid-removals": (2, NOT_ROOT), "frk/mutual-disqualification": (2, ROOT),
    "frk/late-endorsement-stale-head-fork": (2, ROOT),
    "frk/revoked-key-old-parent-freeze": (2, NOT_ROOT),
    "frk/revoked-key-cannot-resolve": (2, NOT_ROOT),
    "frk/equivocators-conflicting-resolves-freeze": (2, ROOT),
    "rsv/candidate-not-at-parent": (2, ROOT), "rsv/choose-not-in-candidates": (2, ROOT),
    "rsv/choose-not-candidate-ignored": (2, ROOT), "rsv/quorum-unmet-ignored": (2, ROOT),
    "rsv/single-person-two-devices": (2, NOT_ROOT),
    "rsv/head-outside-losing-subtree-ignored": (2, ROOT),
    "rsv/heads-ancestor-pair-ignored": (2, ROOT), "rsv/candidates-over-17-schema": (18, ROOT),
    "rsv/single-candidate-schema": (2, ROOT), "rsv/overrides-missing-schema": (2, ROOT),
    "rsv/override-entry-shape-schema": (2, ROOT),
    "rsv/revoked-on-branch-not-counted": (2, NOT_ROOT),
    "rsv/clean-on-examined-paths-required": (2, NOT_ROOT),
    "rsv/fresh-key-on-chosen-branch-not-counted": (2, ROOT),
    "rsv/conflicting-resolves-freeze": (2, ROOT), "rsv/unlisted-leaf-dropped": (3, ROOT),
    "rsv/override-wrong-id-not-current": (2, ROOT),
    "rsv/endorsement-head-must-be-parent": (2, ROOT),
    "rsv/override-evidence-insufficient-not-current": (2, NOT_ROOT),
    "cln/tainted-on-one-branch": (2, NOT_ROOT), "sch/resolve-with-head": (2, ROOT),
    "cln/nested-resolved-fork-all-branches": (2, NOT_ROOT),
    # the stages of one scenario, one id per stage
    "frk/stale-proposal-second-stale-refreezes": (3, ROOT),
    "frk/losing-branch-extension-refreezes": (2, ROOT), "frk/resolve-new-child-refreezes": (3, ROOT),
    "frk/stale-resolve-completed-forks": (2, ROOT),
    "frk/stale-resolve-late-endorsement-still-forks": (2, ROOT),
    "frk/two-stale-artifacts-stale-primary-forks": (2, ROOT),
    "frk/two-stale-artifacts-cannot-replace-winner": (2, ROOT),
    "frk/pending-name-override-cannot-replace": (2, NOT_ROOT),
    "frk/ancestor-override-cannot-discard-unseen-resolve": (2, ROOT),
    "frk/finality-added-leaf-only-forks": (2, NOT_ROOT),
    "frk/finality-added-branch-only-forks": (2, NOT_ROOT),
    "frk/bc1-two-person-variant-forks": (2, NOT_ROOT),
    "frk/r11-resolve-above-removal-costs-override": (2, NOT_ROOT),
    "frk/r11-minted-person-branch-freezes": (2, NOT_ROOT),
    "rsv/stale-head-not-current": (2, NOT_ROOT), "rsv/poisoned-unliftable": (2, NOT_ROOT),
    "rsv/override-evidence-bad-signature-not-effective": (2, ROOT),
    "rsv/override-entry-bare-hashstr-schema": (2, ROOT),
    "rsv/override-entry-sixteen-endorsements-schema": (2, ROOT),
    # ACT-07 S2: one hashstr of an otherwise lifting resolve is not canonical, the resolve is ignored
    "rsv/override-entry-non-canonical-hashstr": (2, ROOT),
    "rsv/override-resolve-non-canonical-hashstr": (2, ROOT),
    "rsv/candidate-non-canonical-hashstr": (2, ROOT), "rsv/head-non-canonical-hashstr": (2, ROOT),
    "rsv/choose-non-canonical-hashstr": (2, ROOT),
    # FO-25 S1: heads that cover K's removal, so the resolve is not applicable
    "rsv/stale-head-covers-removal-ignored": (2, NOT_ROOT),
}
STATES = {
    "frk/single-touch-cannot-fork": 1, "frk/two-self-removals-no-fork": 1,
    "frk/two-adds-one-key": 0, "frk/revocation-race": 2, "frk/own-revocation-not-counted": 2,
    "frk/stale-proposal-at-tip-applies": 1, "frk/late-endorsement-new-head-no-fork": 1,
    "frk/two-endorsement-sets-one-primary-no-fork": 1, "frk/pending-superseded-no-fork": 1,
    "frk/single-grade-withdrawn-vs-two-signer": 2, "frk/equal-effect-merged": 2,
    "frk/revoked-key-cannot-freeze-at-old-parent": 6,
    "frk/revoked-key-single-self-removals-old-parents": 6,
    "frk/retroactive-candidate-by-revoked-key": 6, "frk/revoked-key-old-parent-lifted": 6,
    "frk/resolve-not-voided-by-later-acts": 3,
    "rsv/lifts-fork": 1, "rsv/same-choice-two-resolves-ok": 1, "rsv/no-fork-ignored": 1,
    "rsv/takes-no-position": 2, "rsv/two-heads-one-losing-candidate-current": 1,
    "rsv/lifts-revocation-race": 2, "rsv/lifts-two-self-removals": 1,
    "rsv/equivocator-counts": 1, "rsv/choose-disqualified-ok": 2,
    "rsv/chosen-branch-removal-not-read": 3, "rsv/overriding-resolve-lifts-conflict": 1,
    "rsv/override-with-completion-evidence-current": 1,
    "cln/losing-branch-no-effect": 3, "cln/invalid-act-removal-no-effect": 2,
    # the stages of one scenario, one id per stage
    "frk/stale-proposal-first-resolve-lifts": 1, "frk/stale-proposal-refreeze-lifted-again": 1,
    "frk/losing-branch-extension-lifted": 1, "frk/resolve-new-child-lifted": 1,
    "frk/stale-resolve-lifted-by-override": 2, "frk/two-stale-artifacts-winner-applied": 1,
    "frk/two-stale-artifacts-override-lifts": 1,
    "frk/pending-name-override-first-resolve-applies": 2, "frk/pending-name-override-lifted": 2,
    "frk/ancestor-override-before-completion-applies": 2, "frk/ancestor-override-lifted": 2,
    "frk/finality-base-bag-applies": 3, "frk/bc1-sequence-rejected": 3,
    "frk/bc1-two-person-variant-lifted": 3, "frk/r11-honest-resolve-applies": 6,
    "frk/r11-override-lifts": 6,
    "rsv/override-names-discarded-subtree-resolve-current": 1,
    "rsv/override-completion-evidence-first-resolve-applies": 1,
    "rsv/override-evidence-key-added-below-p-counts": 1,
}
OTHER = {"frk/check-act-refuses", "frk/enrolled-false"}
CHAIN_METHODS = {"local:handsal.device.add", "local:handsal.device.remove",
                 "local:handsal.member.add"}
CHANGE_ROWS = {"frk/r11-minted-person-change-recovers"}
WRITTEN = set(FORKS) | set(STATES) | OTHER | CHANGE_ROWS
NOT_WRITTEN = {
    # no command output of its own: nothing shows a key as clean or not apart from the rows that use it
    "cln/active-everywhere-ok", "cln/unaccepted-never-clean",
    # the row text names no mechanism for "a ground nonce" and no id for the extra act `t`
    "frk/a-c1-self-removal-variant-rejected",
    # written in groups/chg_auth.py (they need a genesis change)
    "frk/genesis-change-recovers", "frk/conflicting-resolves-genesis-exit",
}


def primaries(acts):
    out = {}
    for jws in acts:
        p = json.loads(forge.parts(jws)[1])
        if p["method"] in CHAIN_METHODS:
            out[inputs.receipt_id(jws)] = p
    return out


class Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(["frk", "frk_stage", "rsv", "cln"],
                                         ["frk", "rsv", "cln", "sch"])

    def test_rows(self):
        self.assertEqual({k for k in self.v if not k.startswith("sch/")} |
                         ({"sch/resolve-with-head"} if "sch/resolve-with-head" in self.v else set()),
                         WRITTEN)

    def test_the_bob2_add_of_the_losing_branch_row_is_signed_by_bob_himself(self):
        """FO-22 consent: bob has an active key at that parent, so one of bob's keys signs."""
        fx = base.Fixtures(base.fixture_profile())
        want = fx.key("bob2").kid
        v = self.v["cln/losing-branch-no-effect"]
        acts = v["input"]["acts"]
        signers = set()
        for jws in acts:
            payload = json.loads(forge.parts(jws)[1])
            act = payload["ext"]["dev.handsal/act"]
            if payload["method"] == "local:handsal.device.add" and act["body"]["kid"] == want:
                signers.add(json.loads(forge.parts(jws)[0])["kid"])
                for other in acts:
                    o = json.loads(forge.parts(other)[1])
                    if (o["method"] == "local:handsal.act.endorse"
                            and o["ext"]["dev.handsal/act"]["body"]["act"] == inputs.receipt_id(jws)):
                        signers.add(json.loads(forge.parts(other)[0])["kid"])
        self.assertIn(fx.key("bob").kid, signers)

    def test_written_and_skipped_ids_are_catalog_ids(self):
        self.assertTrue(WRITTEN <= set(catalog.ROWS))
        self.assertTrue(NOT_WRITTEN <= set(catalog.ROWS))
        self.assertFalse(WRITTEN & NOT_WRITTEN)

    def test_fork_rows_are_a_fork_of_the_stated_candidates(self):
        for name, (count, at_root) in FORKS.items():
            v = self.v[name]
            self.assertEqual(v["command"], "fold", name)
            out = json.loads(v["anchor"])
            self.assertEqual(out["error"], "fork", name)
            self.assertNotIn("keys", out, name)
            cands = out["fork"]["candidates"]
            self.assertEqual(len(cands), count, name)
            self.assertEqual(cands, sorted(cands), name)
            prims = primaries(v["input"]["acts"])
            for cid in cands:
                self.assertIn(cid, prims, name)
            root = inputs.doc_id(v["input"]["lineage"][0]["doc"])
            parent = out["fork"]["parent"]
            if at_root:
                self.assertEqual(parent, root, name)
            else:
                self.assertIn(parent, prims, name)
            for cid in cands:
                self.assertEqual(prims[cid]["parent_receipt_hash"], parent, name)

    def test_state_rows_are_the_state_at_the_stated_position(self):
        for name, n in STATES.items():
            v = self.v[name]
            self.assertEqual(v["command"], "fold", name)
            out = json.loads(v["anchor"])
            self.assertNotIn("error", out, name)
            self.assertEqual(out["tip"]["n"], str(n), name)
            root = inputs.doc_id(v["input"]["lineage"][0]["doc"])
            if n == 0:
                self.assertEqual(out["tip"]["id"], root, name)
            else:
                self.assertIn(out["tip"]["id"], primaries(v["input"]["acts"]), name)

    def test_the_change_row_is_the_state_of_the_change_after_the_honest_head(self):
        from lib import state
        v = self.v["frk/r11-minted-person-change-recovers"]
        lineage = v["input"]["lineage"]
        self.assertEqual(len(lineage), 2)
        self.assertEqual(v["anchor"], state.anchor(state.State(lineage[-1]["doc"])))
        prims = primaries(v["input"]["acts"])
        self.assertIn(lineage[-1]["doc"]["head"], prims)  # H = node 6 of the honest chain
        self.assertEqual(json.loads(v["anchor"])["tip"]["n"], "0")

    def test_the_check_act_and_enrolled_rows_refuse_a_frozen_bag(self):
        v = self.v["frk/check-act-refuses"]
        self.assertEqual((v["command"], catalog.anchor_code(v)), ("check-act", "fork"))
        w = self.v["frk/enrolled-false"]
        self.assertEqual(w["command"], "enrolled")
        self.assertEqual(json.loads(w["anchor"]), {"enrolled": False, "reason": "fork"})
        self.assertEqual(primaries(v["input"]["acts"]).keys(), primaries(w["input"]["acts"]).keys())

    def test_the_resolve_rows_carry_a_resolve_act_and_the_frk_rows_name_signers(self):
        for name in ("rsv/lifts-fork", "rsv/conflicting-resolves-freeze", "sch/resolve-with-head"):
            methods = [json.loads(forge.parts(j)[1])["method"] for j in self.v[name]["input"]["acts"]]
            self.assertIn("local:handsal.chain.resolve", methods, name)
        two = [json.loads(forge.parts(j)[1]) for j in
               self.v["rsv/conflicting-resolves-freeze"]["input"]["acts"]]
        resolves = [p for p in two if p["method"] == "local:handsal.chain.resolve"]
        self.assertEqual(len(resolves), 2)
        chosen = {p["ext"]["dev.handsal/act"]["body"]["choose"] for p in resolves}
        self.assertEqual(len(chosen), 2)  # each chooses another candidate

    def test_each_non_canonical_row_has_one_non_canonical_hashstr_in_the_named_field(self):
        """ACT-07 S2: `check-act` never reads a resolve (VR-02 step 4), so the five rows are fold
        rows. Each is the resolve of `rsv/lifts-fork` with one hashstr written with nonzero
        trailing bits (the same 32 bytes), so a loose reader would lift the fork."""
        import base64

        def canonical(h):
            raw = base64.urlsafe_b64decode(h[1:] + "=" * (-len(h[1:]) % 4))
            return "u" + base64.urlsafe_b64encode(raw).decode().rstrip("=")

        def body_of(name):
            for jws in self.v[name]["input"]["acts"]:
                p = json.loads(forge.parts(jws)[1])
                if p["method"] == "local:handsal.chain.resolve":
                    return p["ext"]["dev.handsal/act"]["body"]
            raise AssertionError(name)

        lifts = body_of("rsv/lifts-fork")
        fields = {
            "rsv/candidate-non-canonical-hashstr": lambda b: b["candidates"],
            "rsv/head-non-canonical-hashstr": lambda b: b["heads"],
            "rsv/choose-non-canonical-hashstr": lambda b: [b["choose"]],
            "rsv/override-entry-non-canonical-hashstr": lambda b: b["overrides"][0]["endorsements"],
            "rsv/override-resolve-non-canonical-hashstr": lambda b: [b["overrides"][0]["resolve"]],
        }
        for name, pick in fields.items():
            body = body_of(name)
            every = (list(body["candidates"]) + list(body["heads"]) + [body["choose"]]
                     + [x for o in body["overrides"] for x in o["endorsements"] + [o["resolve"]]])
            bad = [h for h in every if canonical(h) != h]
            self.assertEqual(len(bad), 1, name)
            self.assertIn(bad[0], pick(body), name)
            for key in ("candidates", "heads"):
                self.assertEqual(sorted(map(canonical, body[key])), lifts[key], (name, key))
            self.assertEqual(canonical(body["choose"]), lifts["choose"], name)
            self.assertEqual(body["candidates"], sorted(body["candidates"]), name)

    def test_the_stale_head_rows_differ_only_in_where_the_heads_stop(self):
        """FO-25 S1: heads [5] leave K's removal (node 6) off the examined path, heads [6] cover it."""
        a, b = (self.v[n]["input"]["acts"] for n in ("rsv/stale-head-not-current",
                                                      "rsv/stale-head-covers-removal-ignored"))
        ids = lambda acts: {inputs.receipt_id(j) for j in acts}
        self.assertEqual(len(a), len(b))
        self.assertEqual(len(ids(a) - ids(b)), 2)  # the resolve and its completing endorsement
        self.assertEqual(primaries(a).keys(), primaries(b).keys())
        node = lambda acts, n: [json.loads(forge.parts(j)[1]) for j in acts
                                if json.loads(forge.parts(j)[1])["method"] == "local:handsal.chain.resolve"][0][
            "ext"]["dev.handsal/act"]["body"]["heads"]
        self.assertNotEqual(node(a, 0), node(b, 0))
        self.assertEqual(json.loads(self.v["rsv/stale-head-not-current"]["anchor"])["fork"]["candidates"],
                         json.loads(self.v["rsv/stale-head-covers-removal-ignored"]["anchor"])["fork"]["candidates"])

    def test_the_resolve_with_head_carries_a_head_the_act_must_not_have(self):
        for jws in self.v["sch/resolve-with-head"]["input"]["acts"]:
            p = json.loads(forge.parts(jws)[1])
            if p["method"] == "local:handsal.chain.resolve":
                self.assertIn("head", p["ext"]["dev.handsal/act"])

    def test_the_catalog_ids_of_the_rows_not_written_are_still_in_the_catalog(self):
        group = {k for k in catalog.ROWS if k.split("/")[0] in ("frk", "rsv", "cln")}
        self.assertEqual(group - WRITTEN - NOT_WRITTEN, set())


if __name__ == "__main__":
    unittest.main()
