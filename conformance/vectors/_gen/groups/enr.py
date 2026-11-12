"""Vectors enr/*: the `enrolled` predicate, first failure wins (GP-13, GP-14, GP-17, KC-07).

Every row is a conformance `enrolled` input `{acts, device_kid, lineage, now, org, pin,
synced_at, tip_statement}` with one thing wrong, so the answer is `enrolled:false` and the reason
is the step that fails. The fixture keys make every row that passes steps 1 to 6 end at
`fixture_profile` (step 7, GP-18): `enr/ok` is that case and `enr/device-kid-not-presence`
shows that another person's kid on this machine changes nothing (`device_kid` is caller-supplied).

Not written:
- `enr/prodk-fixture-kid-unknown` needs ORG_PRODK, whose production keys are generated once per
  tag with their scalars destroyed (CF-08); no stand-in is built here (T7.3).
- `pin/probe-symlink-ancestor`, `cli/prod-*`, `cli/conformance-not-on-admin-path`,
  `cli/windows-gate-isolated-python` are retired ids, not rows: they are platform and
  production-build tests. CF-08 says every vector runs against the conformance build, which takes
  `pin` and `now` as data, so a row that expects the production build's refusal of `pin` or `now`
  can never pass there. They are implementation tests named in CF-07.
- `enrolled:true` is shown by no vector: GP-13 step 7 answers `fixture_profile` under the fixture
  profile, so a `true` needs production keys (CF-07). The checker's `test_enrolled.py` proves it.
"""
from lib import base, chain, inputs, keys, p256
from lib.forks import AB, BC, child

NOW = base.NOW


def _kid_of(label):
    x, y = p256.mul(keys.derive_scalar(label))
    return keys.thumbprint(keys.b64u(x.to_bytes(32, "big")), keys.b64u(y.to_bytes(32, "big")))


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    org = fx.org_id

    def row(name, reason, **override):
        device = override.pop("device", "alice")
        w.add(name, "enrolled", inputs.enrolled_anchor(False, reason),
              input=inputs.enrolled_input(override.pop("fixtures", fx), device=device, **override))

    def probe(raw, **kwargs):
        return inputs.probe(org, raw, **kwargs)

    row("enr/ok", "fixture_profile")
    row("enr/device-kid-not-presence", "fixture_profile", device="bob")
    row("enr/fixture-kid", "fixture_key", fixtures=base.Fixtures(base.production_profile()))

    c = chain.Chain(fx, ctx=ctx)
    child(c, "alice2", AB, None, applied=True)
    child(c, "bob2", BC, None)
    row("enr/fork", "fork", acts=list(c.acts))

    row("enr/genesis-pin-mismatch", "genesis_pin_mismatch",
        pin=probe(inputs.pin_line(org, fx.wit_org_id, fx.profile)))

    c = chain.Chain(fx, ctx=ctx)
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls="fixture-pin")
    row("enr/local-class-not-accepted", "local_class_not_accepted", device="dave2",
        acts=list(c.acts))

    c = chain.Chain(fx, ctx=ctx)
    c.device_remove("carol", AB)
    row("enr/local-key-revoked", "local_key_not_active", device="carol", acts=list(c.acts))

    w.add("enr/local-key-unknown", "enrolled", inputs.enrolled_anchor(False, "local_key_unknown"),
          input=inputs.enrolled_input(fx, device="alice2"))
    w.add("enr/no-secure-enclave-machine", "enrolled",
          inputs.enrolled_anchor(False, "local_key_unknown"),
          input=inputs.enrolled_input(fx, device_kid=_kid_of("enr/no-secure-enclave")))

    row("enr/pin-malformed", "pin_malformed", pin=probe(b"this is not a pin\n"))
    row("enr/pin-missing", "pin_missing", pin=probe(b"", owner_ok=False, reason="pin_missing"))
    row("enr/pin-owner", "pin_owner", pin=probe(inputs.pin_line(org, org, fx.profile),
                                                owner_ok=False, reason="pin_owner"))
    row("enr/pin-probe-unavailable", "pin_probe_unavailable",
        pin=probe(b"", owner_ok=False, reason="pin_probe_unavailable"))
    row("enr/wsl-unprotected", "pin_probe_unprotected",
        pin=probe(b"", owner_ok=False, reason="pin_probe_unprotected"))

    row("enr/stale-view", "stale_view", synced_at=base.shift(NOW, -86401))
    row("enr/view-in-future", "view_in_future", synced_at=base.shift(NOW, 301))

    unsigned = [{"doc": fx.org, "sigs": []}]
    row("enr/state-error", "genesis_unsigned", lineage=unsigned, pin=inputs.probe_for(unsigned))
