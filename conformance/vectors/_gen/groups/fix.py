"""Vectors fix/*: fixture profile and fixture keys (GP-18, CF-08).

The conformance build accepts both profiles. Rows over the production profile
(PRODP) use ORG_PROD: the same organization under the production profile hash,
still listing fixture kids. The PRODK rows need production keys generated once
per tag with their scalars destroyed (CF-08); they are not written here but by
lib/prodk.py (run through make_prodk.py by the owner, into `conformance/vectors/prod/`):
fix/prodk-check-act-fixture-kid-unknown, fix/prodk-check-act-ok,
fix/prodk-fixture-kid-add-not-on-chain, fix/prodk-fold-ok,
fix/prodk-relay-fixture-kid.
"""
from lib import base, inputs


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    prod = base.Fixtures(base.production_profile())

    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    w.add("fix/fix-profile-check-act-ok", "check-act", inputs.check_anchor(approve, "ok"),
          input=inputs.check_input(fx, approve))
    w.add("fix/fix-profile-enrolled", "enrolled", inputs.enrolled_anchor(False, "fixture_profile"),
          input=inputs.enrolled_input(fx))

    change = inputs.change_doc(
        fx, edit=lambda d: d.update(profile=base.production_profile()))
    original = inputs.original_lineage(fx, fx.org)[0]
    sigs = [fx.genesis_sign(n, change) for n in ("alice", "bob", "carol")]
    w.add("fix/mixed-profile-lineage", "fold", inputs.error_anchor("fixture_profile"),
          input=inputs.fold_input([original, {"doc": change, "sigs": sigs}]))

    prod_approve = prod.approve()
    w.add("fix/prod-check-act-fixture-pin-refused", "check-act",
          inputs.check_anchor(prod_approve, "fixture_key"),
          input=inputs.check_input(prod, prod_approve))
    w.add("fix/prod-genesis-fixture-kid", "fold", inputs.error_anchor("fixture_key"),
          input=inputs.fold_input(prod.lineage()))
