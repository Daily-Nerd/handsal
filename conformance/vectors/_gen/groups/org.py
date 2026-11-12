"""Vectors org/*: the org id binds every act and every probe (GP-04, GP-13, GP-14, VR-01).

ORG is org A and WIT_ORG, a different valid organization, is org B. Each row
puts exactly one thing of org B where org A is expected.
"""
from lib import forge, inputs

ORG_B_MISMATCH = "pin_org_mismatch"


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    approve = fx.approve()

    w.add("org/check-act-org-input-missing", "check-act", inputs.error_anchor("malformed_input"),
          input=inputs.check_input(fx, approve, org=inputs.DROP))
    w.add("org/enrolled-org-mismatch", "enrolled", inputs.enrolled_anchor(False, ORG_B_MISMATCH),
          input=inputs.enrolled_input(fx, pin=fx.pin_ok(wit=True)))
    w.add("org/fold-org-mismatch", "fold", inputs.error_anchor(ORG_B_MISMATCH),
          input=inputs.fold_input(fx.lineage(), org=fx.wit_org_id))

    other = fx.approve(org=fx.wit_org_id)
    w.add("org/other-org", "check-act", inputs.check_anchor(other, "org_mismatch"),
          input=inputs.check_input(fx, other))

    wrong_filename = dict(fx.pin_ok(), filename=inputs.filename_of(fx.wit_org_id))
    w.add("org/probe-filename-mismatch", "fold", inputs.error_anchor(ORG_B_MISMATCH),
          input=inputs.fold_input(fx.lineage(), pin=wrong_filename))
    w.add("org/probe-other-org", "check-act", inputs.check_anchor(approve, ORG_B_MISMATCH),
          input=inputs.check_input(fx, approve, pin=fx.pin_ok(wit=True)))

    resigned = forge.resign(fx, approve, forge.act_edit(
        lambda a: a.__setitem__("org", fx.wit_org_id)))
    w.add("org/sig-valid-wrong-org", "check-act", inputs.check_anchor(resigned, "org_mismatch"),
          input=inputs.check_input(fx, resigned))
