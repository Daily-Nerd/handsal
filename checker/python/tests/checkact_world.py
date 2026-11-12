"""A world for `check-act` tests: one organization with a signed original, a verdict or promotion
signed (in stand-in form) by an accepted device, and the whole input of VR-01. Every test changes one
thing. Nothing here calls a checker rule: the act is valid because of how it is built."""
import base64
import calendar
import time

from handsal_check import emit, encoding, genesis, org as orgmod, pinfile

from .act_builder import GOOD, FakeVitni, build, head_of
from .fold_world import World
from .genesis_fixtures import policy

NOW = "2026-01-01T00:30:00Z"
TS = "2026-01-01T00:00:00Z"
EXPIRES = "2026-01-01T01:00:00Z"
RAW = b"deploy v2"
BODY = b"record body v1"
REQUEST_ID = "req-00000001"
RELAY = "r.example"
ALL = ("alice", "bob", "carol")
APPROVE = "local:handsal.request.approve"
PROMOTE = "local:handsal.record.promote"


def at(seconds_before_now):
    """The time `seconds_before_now` before NOW (negative: after)."""
    t = calendar.timegm(time.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ")) - seconds_before_now
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def outputs(verdict, request_id=REQUEST_ID):
    return encoding.hashstr(emit.emit_subset({"request_id": request_id, "verdict": verdict}))


def b64(raw):
    return base64.b64encode(raw).decode()


def probe_for(doc, org_id):
    line = pinfile.line(genesis.doc_hash(doc), org_id, doc["profile"])
    return {"bytes_b64": b64(line), "filename": orgmod.pin_filename(org_id), "org": org_id, "owner_ok": True,
            "reason": "ok"}


class Scenario:
    def __init__(self, world=None, signers=ALL, **world_kw):
        self.w = world or World(**world_kw)
        self.lineage = [{"doc": self.w.doc, "sigs": self.w.sigs(self.w.doc, signers)}]

    def verdict(self, method="approve", signer="alice", head=None, **over):
        fields = dict(org=self.w.id, body={}, head=head or head_of(self.w.id), inputs_hash=encoding.hashstr(RAW),
                      outputs_hash=outputs(method), ts=TS,
                      extra={"expires": EXPIRES, "recipient": "alice", "relay": RELAY, "request_id": REQUEST_ID})
        extra = over.pop("extra", None)
        if extra:
            fields["extra"] = {**fields["extra"], **extra}
        fields.update(over)
        return build(signer, "request." + method, **fields)

    def promote(self, signer="alice", head=None, **over):
        fields = dict(org=self.w.id, body={"anchors": ["a1"], "record_id": "rec-1"},
                      head=head or head_of(self.w.id), inputs_hash=encoding.hashstr(BODY), ts=TS,
                      extra={"expires": EXPIRES})
        extra = over.pop("extra", None)
        if extra:
            fields["extra"] = {**fields["extra"], **extra}
        fields.update(over)
        return build(signer, "record.promote", **fields)

    def value(self, act=None, **over):
        act = act or self.verdict()
        value = {"acts": [], "expect_method": APPROVE, "jws": act.jws, "lineage": self.lineage, "now": NOW,
                 "org": self.w.id, "pin": probe_for(self.w.doc, self.w.id), "recipient": "alice", "relay": RELAY,
                 "request_b64": b64(RAW), "request_id": REQUEST_ID, "seen": [], "synced_at": NOW,
                 "tip_statement": None}
        value.update(over)
        return value

    def promote_value(self, act=None, **over):
        value = self.value(act or self.promote(), expect_method=PROMOTE, **over)
        for key in ("recipient", "relay", "request_b64", "request_id"):
            del value[key]
        value["record_body_b64"] = b64(BODY)
        value.update(over)
        return value


def check(value, vitni=None, allow_fixture=True):
    """The `check-act` result of the command input `value`."""
    from handsal_check import checkact, profiles, registry
    return checkact.run(checkact.parse_input(value), registry.load(), profiles.load(), allow_fixture,
                        vitni or FakeVitni())


class Stub:
    """A verifier that answers one fixed reason for the human act under test and records what it was asked.
    Every other question (the genesis and endorsement signatures of the fold) is answered like vitni."""

    def __init__(self, reason):
        self.reason, self.calls, self.fake = reason, [], FakeVitni()

    def verify(self, jws, keys, method):
        if method.startswith("local:handsal.request.") or method == PROMOTE:
            self.calls.append((keys, method))
            return self.reason
        return self.fake.verify(jws, keys, method)


def dave_world():
    """ORG plus dave, whose second device is of a class the policy does not accept (not `accepted`)."""
    w = World(extra=("dave",), members=(("dave", "member"),))
    return w, w.device_add("dave2", ("dave", "alice", "bob"), cls="fixture-pin")
