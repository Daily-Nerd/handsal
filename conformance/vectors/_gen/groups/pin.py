"""Vectors pin/*: the pin file and its checks, VR-02 step 6 (GP-05, GP-14).

The pin-parse and pin-comparison rows ride on `fold`, which runs the same pin
checks before the fold (GP-13 steps 1 to 3). `pin/ok` and `pin/missing` are the
accepted and probe-failed ends of the same path. The ancestor symlink case of
GP-10 is a probe test of the checker (CF-07), not a vector the pure core can run.
"""
from lib import base, inputs, jcs


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    org, profile = fx.org_id, fx.profile
    good = inputs.pin_line(org, org, profile)
    lineage = fx.lineage()

    def fold(name, code, pin):
        w.add(name, "fold", inputs.error_anchor(code),
              input=inputs.fold_input(lineage, pin=pin))

    def malformed(name, raw):
        fold(name, "pin_malformed", inputs.probe(org, raw))

    size_pad = b" " * (513 - len(good))
    malformed("pin/513-bytes", good[:-1] + size_pad + b"\n")
    malformed("pin/crlf", good[:-1] + b"\r\n")
    malformed("pin/duplicate-key", ('{"genesis":"%s","org":"%s","org":"%s","spec":"%s",'
                                    '"v":"handsal-pin/1"}\n' % (org, org, org, profile)).encode())
    malformed("pin/duplicate-key-differing-values",
              ('{"genesis":"%s","org":"%s","org":"%s","spec":"%s","v":"handsal-pin/1"}\n'
               % (org, org, fx.wit_org_id, profile)).encode())
    malformed("pin/empty", b"")
    malformed("pin/extra-line", good + good)
    malformed("pin/no-trailing-lf", good[:-1])
    malformed("pin/non-ascii", ('{"genesis":"%s","org":"%s","spec":"%sé",'
                                '"v":"handsal-pin/1"}\n' % (org, org, profile)).encode("utf-8"))
    malformed("pin/reordered", ('{"org":"%s","genesis":"%s","spec":"%s","v":"handsal-pin/1"}\n'
                                % (org, org, profile)).encode())
    malformed("pin/unknown-key", jcs.emit({"foo": "bar", "genesis": org, "org": org,
                                           "spec": profile, "v": "handsal-pin/1"}) + b"\n")
    malformed("pin/v-wrong", jcs.emit({"genesis": org, "org": org, "spec": profile,
                                       "v": "handsal-pin/2"}) + b"\n")

    fold("pin/filename-mismatch", "pin_org_mismatch",
         inputs.probe(org, good, filename=inputs.filename_of(fx.wit_org_id)))
    fold("pin/genesis-mismatch", "genesis_pin_mismatch",
         inputs.probe(org, inputs.pin_line(org, fx.wit_org_id, profile)))
    # GP-07: the pin names org X, the input says X, the last document matches the pin's
    # `genesis`; only the first lineage document hashes to another org (VR-02 step 6 (g)).
    other = fx.wit_org_id
    w.add("pin/lineage-original-not-org", "fold", inputs.error_anchor("lineage_broken"),
          input=inputs.fold_input(lineage, org=other,
                                  pin=inputs.probe(other, inputs.pin_line(other, org, profile))))
    fold("pin/missing", "pin_missing",
         inputs.probe(org, b"", owner_ok=False, reason="pin_missing"))
    fold("pin/org-not-original", "pin_org_mismatch",
         inputs.probe(org, inputs.pin_line(fx.wit_org_id, org, profile)))
    fold("pin/spec-mismatch", "profile_mismatch",
         inputs.probe(org, inputs.pin_line(org, org, base.hashstr(b"unimplemented profile"))))
    fold("pin/spec-not-last-profile", "pin_spec_mismatch",
         inputs.probe(org, inputs.pin_line(org, org, base.production_profile())))

    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    w.add("pin/ok", "check-act", inputs.check_anchor(approve, "ok"),
          input=inputs.check_input(fx, approve))
