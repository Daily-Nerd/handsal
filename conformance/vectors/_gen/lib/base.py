"""Base fixtures (catalog base fixtures, catalog-part2 21, catalog-part3 25).

ORG, LINEAGE, PIN_OK, NOW, APPROVE, KEYSET, WIT_ORG and RELAY_FX, built from
the published fixture keys with the amendments of the catalog:

- the fixture profile (GP-18): the profile hash is an INPUT. It comes from the
  core manifest (tools/manifest.py, the single owner of the computation);
  `fixture_profile()` and `production_profile()` below read it from there and
  keep no value of their own. Every document names it in `profile`;
- the `org` input: ORG's org id is exposed (`org_id`), and PIN_OK carries the
  `filename` and `org` the probe object needs;
- the two-signer `device.add` (FO-09, catalog-part3 25): one primary, one
  counted endorsement by a second person, and the new key's proof of
  possession (FO-07);
- the signer kid inside the signed object (ACT-14) on every act;
- no `added_by` anywhere (FO-03).

Everything is deterministic: RFC 6979 signatures, low-S, and nonces derived
from the payload, so a rerun is byte-identical (CF-06). Standard library plus
the sibling lib modules; independent of the checker.
"""
import base64
import hashlib
import importlib.util
import json
import re
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import es256, jcs, keys, p256

NOW = "2026-11-08T12:00:00Z"
RELAY_HOST = "r.example"
REQUEST = b"deploy v2"
REQUEST_ID = "req-00000001"
ORG_NAME = "example"
CLASS = "apple-se-bio"
RECORD_BODY = b"record body v1"
RECORD_ID = "rec-0001"
VERDICTS = ("approve", "reject", "needs-info")
RELAY_TIP = "local:handsal.relay.tip"

_FIXTURES = Path(__file__).resolve().parents[2].parent / "fixtures"
_MANIFEST = Path(__file__).resolve().parents[4] / "tools" / "manifest.py"
_NONCE_DOMAIN = b"handsal-fixture-nonce/v1/"

def _manifest():
    spec = importlib.util.spec_from_file_location("handsal_manifest", _MANIFEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_profile():
    """The fixture profile hash, computed by tools/manifest.py."""
    return _manifest().fixture_profile()


def production_profile():
    """The production profile hash, computed by tools/manifest.py."""
    return _manifest().production_profile()


KEEP = object()  # genesis_sign: the document's own head
Act = namedtuple("Act", "jws id performer")
DeviceAdd = namedtuple("DeviceAdd", "acts id parent performer name")


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hashstr(raw):
    """`u` + base64url(0x12 0x20 || sha256(raw)): the profile's hash-string."""
    return "u" + _b64u(b"\x12\x20" + hashlib.sha256(raw).digest())


EMPTY_HASH = hashstr(b"")


def is_hashstr(text):
    if not (isinstance(text, str) and len(text) == 47 and text.startswith("uEi")):
        return False
    try:
        raw = _unb64u(text[1:])
    except ValueError:
        return False
    return _b64u(raw) == text[1:] and raw[:2] == b"\x12\x20"


def shift(time, seconds):
    """`time` (YYYY-MM-DDTHH:MM:SSZ) moved by `seconds`."""
    dt = datetime.strptime(time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (dt + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Key:
    def __init__(self, name, entry):
        self.name = name
        self.d = int(entry["d"], 16)
        self.x = entry["x"]
        self.y = entry["y"]
        self.kid = entry.get("kid")
        self.x_int = int.from_bytes(_unb64u(self.x), "big")
        self.y_int = int.from_bytes(_unb64u(self.y), "big")

    def point(self):
        return {"x": self.x, "y": self.y}

    def jwk(self):
        return {"crv": "P-256", "kty": "EC", "x": self.x, "y": self.y}


def person_of_name(name):
    """Person of a catalog device name: alice2 -> alice, X1 -> alice, alice-pin -> alice."""
    if name in ("X1", "X2"):
        return "alice"
    name = re.sub(r"-pin$", "", name)
    return re.sub(r"\d+$", "", name)


# ---- shape of a genesis document (GP-01, GP-02, WT-01) ---------------------

_MEMBER = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
_ROLE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]{0,8})$")
_TEXT = re.compile(r"^[\x20\x21\x23-\x5b\x5d-\x7e]+$")
_POINT = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _decimal(text, lo, hi):
    return isinstance(text, str) and _DECIMAL.match(text) is not None and lo <= int(text) <= hi


def check_genesis_shape(doc):
    """The problems of `doc` against GP-01, GP-02 and WT-01 (empty list: none).

    A structural check owned by the generator, so a base fixture that drifts
    from the spec fails here and not later in a checker.
    """
    bad = []
    if not isinstance(doc, dict):
        return ["document is not an object"]
    want = {"devices", "members", "name", "org", "policy", "prev", "profile", "v"}
    if doc.get("prev") is not None:
        want = want | {"head"}
    if set(doc) != want:
        bad.append("keys %s != %s" % (sorted(doc), sorted(want)))
        return bad
    if doc["v"] != "handsal-genesis/1":
        bad.append("v")
    if not is_hashstr(doc["profile"]):
        bad.append("profile")
    for key in ("org", "prev", "head"):
        if key in doc and doc[key] is not None and not is_hashstr(doc[key]):
            bad.append(key)
    if not (isinstance(doc["name"], str) and 1 <= len(doc["name"]) <= 24
            and _TEXT.match(doc["name"])):
        bad.append("name")

    pol = doc["policy"]
    roles, rules = [], {}
    if not isinstance(pol, dict) or set(pol) != {"classes", "freshness", "roles", "rules", "v",
                                                 "witness"}:
        bad.append("policy keys")
    else:
        if pol["v"] != "handsal-policy/1":
            bad.append("policy v")
        roles = pol["roles"]
        if not (isinstance(roles, list) and roles and roles == sorted(set(roles))
                and all(_ROLE.match(r) for r in roles)):
            bad.append("roles")
        classes = pol["classes"]
        if not (isinstance(classes, list) and classes
                and all(isinstance(c, dict) and set(c) == {"class", "user_verification"}
                        for c in classes)
                and [c["class"] for c in classes] == sorted({c["class"] for c in classes})):
            bad.append("classes")
        fr = pol["freshness"]
        if not (isinstance(fr, dict) and set(fr) == {"clock_skew_s", "max_validity_s", "max_view_age_s"}
                and _decimal(fr["clock_skew_s"], 0, 3600)
                and _decimal(fr["max_validity_s"], 60, 2592000)
                and _decimal(fr["max_view_age_s"], 60, 2592000)):
            bad.append("freshness")
        rules = pol["rules"]
        if not (isinstance(rules, dict)
                and set(rules) == {"chain.resolve", "device.remove", "genesis.change", "member.add"}):
            bad.append("rules keys")
            rules = {}
        wit = pol["witness"]
        if wit == {"mode": "none"}:
            pass
        elif (isinstance(wit, dict)
              and set(wit) == {"max_tip_age_s", "mode", "relay_kid", "relay_pub_jwk"}
              and wit["mode"] == "relay" and _decimal(wit["max_tip_age_s"], 60, 86400)
              and isinstance(wit["relay_pub_jwk"], dict)
              and set(wit["relay_pub_jwk"]) == {"crv", "kty", "x", "y"}
              and wit["relay_pub_jwk"]["crv"] == "P-256" and wit["relay_pub_jwk"]["kty"] == "EC"
              and _POINT.match(str(wit["relay_pub_jwk"]["x"]))
              and _POINT.match(str(wit["relay_pub_jwk"]["y"]))
              and wit["relay_kid"] == keys.thumbprint(wit["relay_pub_jwk"]["x"],
                                                      wit["relay_pub_jwk"]["y"])):
            pass
        else:
            bad.append("witness")

    members = doc["members"]
    ids = []
    if not (isinstance(members, list) and members
            and all(isinstance(m, dict) and set(m) == {"id", "role"} for m in members)):
        bad.append("members")
    else:
        ids = [m["id"] for m in members]
        if ids != sorted(set(ids)):
            bad.append("members not sorted or not unique")
        if not all(_MEMBER.match(i) for i in ids):
            bad.append("member id")
        if roles and not all(m["role"] in roles for m in members):
            bad.append("member role")

    devices = doc["devices"]
    if not (isinstance(devices, list) and devices):
        bad.append("devices")
    else:
        entry_keys = {"agree", "class", "kid", "label", "person", "sign"}
        if not all(isinstance(d, dict) and set(d) == entry_keys for d in devices):
            bad.append("device entry keys")
        else:
            kids = [d["kid"] for d in devices]
            if kids != sorted(kids):
                bad.append("devices not sorted by kid")
            if len(set(kids)) != len(kids):
                bad.append("duplicate kid")
            points = [(d["sign"]["x"], d["sign"]["y"]) for d in devices]
            points += [(d["agree"]["x"], d["agree"]["y"]) for d in devices]
            if len(set(points)) != len(points):
                bad.append("duplicate or equal sign/agree key")
            for d in devices:
                if d["kid"] != keys.thumbprint(d["sign"]["x"], d["sign"]["y"]):
                    bad.append("kid is not the thumbprint of sign")
                if d["person"] not in ids:
                    bad.append("device person not a member")
                if not (isinstance(d["label"], str) and 1 <= len(d["label"]) <= 64
                        and _TEXT.match(d["label"])):
                    bad.append("label")
                for k in ("sign", "agree"):
                    if not all(_POINT.match(str(d[k].get(c, ""))) for c in ("x", "y")):
                        bad.append("point encoding")
            if not set(ids) <= {d["person"] for d in devices}:
                bad.append("member without a device")

    # GP-02: each rule's persons is 2..15 and smaller than its role holders
    for rule_id, rule in rules.items():
        if not (isinstance(rule, dict) and set(rule) == {"persons", "roles"}
                and _decimal(rule["persons"], 2, 15) and isinstance(rule["roles"], list)
                and rule["roles"] and rule["roles"] == sorted(set(rule["roles"]))):
            bad.append("rule %s" % rule_id)
            continue
        if isinstance(members, list):
            holders = sum(1 for m in members if isinstance(m, dict) and m.get("role") in rule["roles"])
            if int(rule["persons"]) >= holders:
                bad.append("rule %s unreachable" % rule_id)
    return bad


# ---- the fixtures ----------------------------------------------------------

class Fixtures:
    """All base fixtures for one profile hash."""

    def __init__(self, profile, keys_path=None):
        if not is_hashstr(profile):
            raise ValueError("profile must be a canonical hashstr")
        self.profile = profile
        path = Path(keys_path) if keys_path else _FIXTURES / "keys.json"
        self._entries = json.loads(path.read_text(encoding="utf-8"))["keys"]
        self.relay = Key("relay-fixture", self._entries["relay-fixture"])  # RELAY_FX
        self._kid_person = {}
        self._extra_kids = {}  # kid -> name of a registered device
        for dev in keys.DEVICES:
            kid = self._entries[dev + ".sign"]["kid"]
            self._kid_person[kid] = person_of_name(dev)
        self.org = self._org_doc(witness={"mode": "none"})
        self.org_id = hashstr(jcs.emit(self.org))
        self.wit_org = self._org_doc(witness=self._relay_witness())
        self.wit_org_id = hashstr(jcs.emit(self.wit_org))

    # keys
    def key(self, name, usage="sign"):
        return Key(name, self._entries["%s.%s" % (name, usage)])

    def person_of_name(self, name):
        return person_of_name(name)

    def person_of_kid(self, kid):
        return self._kid_person[kid]

    def relay_jwk(self):
        return self.relay.jwk()

    def keyset(self, names, revoked=()):
        """The vitni `keys` map {person: {kid: key}} for the named devices."""
        out = {}
        for name in names:
            k = self.key(name)
            entry = dict(k.jwk(), alg="ES256",
                         status="revoked" if name in revoked else "active")
            out.setdefault(person_of_name(name), {})[k.kid] = entry
        return out

    # documents
    def _relay_witness(self):
        return {"max_tip_age_s": "3600", "mode": "relay", "relay_kid": self.relay.kid,
                "relay_pub_jwk": self.relay.jwk()}

    def register_device(self, name, sign_label, agree_label):
        """Add a device whose keys derive from the given labels (lib/keys.py).

        For a row the fixture devices cannot serve (a crafted key, ACT-11). `name`
        must end the way fixture names do so its person is derived the same way
        (`alice5` is a device of alice). Published test material, like every
        fixture scalar.
        """
        for use, label in (("sign", sign_label), ("agree", agree_label)):
            d = keys.derive_scalar(label)
            x, y = p256.mul(d)
            xs, ys = keys.b64u(x.to_bytes(32, "big")), keys.b64u(y.to_bytes(32, "big"))
            entry = {"d": "%064x" % d, "x": xs, "y": ys}
            if use == "sign":
                entry["kid"] = keys.thumbprint(xs, ys)
                self._kid_person[entry["kid"]] = person_of_name(name)
                self._extra_kids[entry["kid"]] = name
            self._entries["%s.%s" % (name, use)] = entry

    def device_entry(self, name, cls=CLASS):
        """The genesis-document device entry of fixture device `name`."""
        return self._device_entry(name, cls)

    def _device_entry(self, name, cls=CLASS):
        sign, agree = self.key(name, "sign"), self.key(name, "agree")
        return {"agree": agree.point(), "class": cls, "kid": sign.kid,
                "label": "%s se-bio" % name, "person": person_of_name(name),
                "sign": sign.point()}

    def org_doc(self, maintainers=("alice", "bob", "carol"), persons="2", witness=None):
        """An original document: `maintainers` (fixture or registered devices), every rule at
        `persons`, witness `none` unless given."""
        return self._org_doc(witness or {"mode": "none"}, maintainers, persons)

    def _org_doc(self, witness, maintainers=("alice", "bob", "carol"), persons="2"):
        rule = {"persons": persons, "roles": ["maintainer"]}
        devices = sorted((self._device_entry(m) for m in maintainers), key=lambda d: d["kid"])
        return {
            "devices": devices,
            "members": sorted(({"id": m, "role": "maintainer"} for m in maintainers),
                              key=lambda m: m["id"]),
            "name": ORG_NAME,
            "org": None,
            "policy": {
                "classes": [{"class": CLASS, "user_verification": "biometric_only"}],
                "freshness": {"clock_skew_s": "300", "max_validity_s": "604800",
                              "max_view_age_s": "86400"},
                "roles": ["maintainer", "member"],
                "rules": {"chain.resolve": dict(rule), "device.remove": dict(rule),
                          "genesis.change": dict(rule), "member.add": dict(rule)},
                "v": "handsal-policy/1",
                "witness": witness,
            },
            "prev": None,
            "profile": self.profile,
            "v": "handsal-genesis/1",
        }

    # acts
    def _act(self, signer, method, *, org, body, parent, parent_performer, performer=None,
             inputs_hash=EMPTY_HASH, outputs_hash=EMPTY_HASH, ts, head=None, extra=None,
             raw_edit=None, payload_edit=None, key=None, header_kid=None, act_kid=True,
             high_s=False):
        """One act. `key` signs instead of device `signer`; `header_kid` names another kid in
        the header; `act_kid=False` leaves the act object without `kid` (a tip statement)."""
        key = key or self.key(signer)
        performer = performer or person_of_name(signer)
        obj = {"body": body, "org": org}
        if act_kid:
            obj["kid"] = key.kid  # ACT-14
        if head is not None:
            obj["head"] = head
        obj.update(extra or {})
        payload = {
            "action_ref": None, "binding": "local",
            "cost": {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"},
            "ext": {"dev.handsal/act": obj},
            "inputs_hash": inputs_hash, "log_policy": "best_effort", "method": method,
            "outputs_hash": outputs_hash,
            "parent_performer_id": parent_performer, "parent_receipt_hash": parent,
            "performer_id": performer, "reason": None, "requester_id": None, "status": "OK",
            "ts": ts, "v": "vitni/0.2",
        }
        if payload_edit is not None:  # an envelope field a negative row sets wrong
            payload_edit(payload)
        # deterministic stand-in for 32 random bytes: a function of everything else
        seed = hashlib.sha256(_NONCE_DOMAIN + jcs.emit(payload)).digest()
        payload["nonce"] = hashstr(seed)
        raw = jcs.emit(payload)
        if raw_edit is not None:  # bytes the subset cannot express (a negative row only)
            raw = raw_edit(raw)
        header = jcs.emit({"alg": "ES256", "kid": header_kid or key.kid})
        jws = es256.sign_jws(key.d, header, raw, high_s=high_s)
        return Act(jws, hashstr(raw), performer)

    def tip_statement(self, *, epoch=None, tip=None, org=None, next_="no", ts=None, key=None,
                      header_kid=None, performer="relay", method=RELAY_TIP, act_edit=None,
                      payload_edit=None, raw_edit=None, high_s=False):
        """A relay tip statement (WT-02): by RELAY_FX unless `key` says otherwise.

        Defaults: epoch and org WIT_ORG, tip the epoch root, `next` `"no"`, ts NOW minus 60 s.
        `act_edit(act object)` and `payload_edit(payload)` edit before the nonce is derived,
        `raw_edit(bytes)` after (content the subset cannot express), `header_kid` puts another
        kid in the header, `high_s` signs the high form.
        """
        epoch = epoch or self.wit_org_id

        def edit(payload):
            if act_edit is not None:
                act_edit(payload["ext"]["dev.handsal/act"])
            if payload_edit is not None:
                payload_edit(payload)
        return self._act(
            None, method, org=org or self.wit_org_id,
            body={"epoch": epoch, "next": next_, "tip": tip or epoch}, parent=None,
            parent_performer=None, performer=performer, ts=ts or shift(NOW, -60),
            raw_edit=raw_edit, payload_edit=edit, key=key or self.relay, header_kid=header_kid,
            act_kid=False, high_s=high_s).jws

    def genesis_sign(self, signer, doc, ts=None, head=KEEP, performer=None):
        """`genesis.sign` over `doc` by device `signer` (ACT-09, GP-03).

        `head`: KEEP names the document's own head for a change and none for an original;
        a hashstr names that head; None leaves `head` out. `performer` sets `performer_id`
        (the signer's person by default).
        """
        change = doc["prev"] is not None
        if head is KEEP:
            head = doc["head"] if change else None
        return self._act(
            signer, "local:handsal.genesis.sign",
            org=doc["org"] if change else hashstr(jcs.emit(doc)), body={},
            parent=None, parent_performer=None, performer=performer,
            inputs_hash=hashstr(jcs.emit(doc)),
            head={"id": head, "kind": "chain"} if head is not None else None,
            ts=ts or shift(NOW, -7200)).jws

    def lineage(self, wit=False):
        """LINEAGE: the original document and one genesis.sign per listed device."""
        doc = self.wit_org if wit else self.org
        names = [self._name_of_kid(d["kid"]) for d in doc["devices"]]
        return [{"doc": doc, "sigs": [self.genesis_sign(n, doc) for n in names]}]

    def name_of_kid(self, kid):
        """The fixture device name whose signing kid is `kid`."""
        return self._name_of_kid(kid)

    def _name_of_kid(self, kid):
        for dev in keys.DEVICES:
            if self._entries[dev + ".sign"]["kid"] == kid:
                return dev
        return self._extra_kids[kid]

    def pin_ok(self, wit=False):
        """PIN_OK: a passing probe whose bytes are the JCS pin line plus LF (GP-05, GP-14)."""
        org_id = self.wit_org_id if wit else self.org_id
        line = jcs.emit({"genesis": org_id, "org": org_id, "spec": self.profile,
                         "v": "handsal-pin/1"}) + b"\n"
        digest = _unb64u(org_id[1:])[2:]
        return {"bytes_b64": base64.b64encode(line).decode("ascii"),
                "filename": digest.hex() + ".pin", "org": org_id, "owner_ok": True,
                "reason": "ok"}

    def request_b64(self, request=REQUEST):
        return base64.b64encode(request).decode("ascii")

    def verdict(self, kind, signer="alice", *, request=REQUEST, request_id=REQUEST_ID, ts=None,
                expires=None, recipient=None, relay=RELAY_HOST, tip=None, org=None, wit=False,
                verdict=None):
        """A valid `request.<kind>` (ACT-09). ts NOW-60 s, expires ts+3600 s.

        `verdict` names the verdict inside `outputs_hash`; it is `kind` unless a
        vector needs the two to differ (vrd/outputs-verdict-swapped).
        """
        if kind not in VERDICTS:
            raise ValueError("verdict kind must be one of %s" % (VERDICTS,))
        org = org or (self.wit_org_id if wit else self.org_id)
        ts = ts or shift(NOW, -60)
        return self._act(
            signer, "local:handsal.request.%s" % kind, org=org, body={}, parent=None,
            parent_performer=None, performer=recipient or person_of_name(signer),
            inputs_hash=hashstr(request),
            outputs_hash=hashstr(jcs.emit({"request_id": request_id,
                                           "verdict": verdict or kind})),
            head={"id": tip or org, "kind": "chain"}, ts=ts,
            extra={"expires": expires or shift(ts, 3600),
                   "recipient": recipient or person_of_name(signer), "relay": relay,
                   "request_id": request_id}).jws

    def approve(self, signer="alice", **kwargs):
        """APPROVE: a valid request.approve (ACT-09). ts NOW-60 s, expires ts+3600 s."""
        return self.verdict("approve", signer, **kwargs)

    def record_promote(self, signer="alice", *, record=RECORD_BODY, record_id=RECORD_ID,
                       anchors=("anchor-1",), ts=None, expires=None, tip=None, org=None,
                       wit=False, outputs_hash=EMPTY_HASH):
        """A valid `record.promote` (ACT-09, ACT-13). ts NOW-60 s, expires ts+3600 s.

        `outputs_hash` is EMPTY_HASH (VR-07); a row about the outputs check sets another.
        """
        org = org or (self.wit_org_id if wit else self.org_id)
        ts = ts or shift(NOW, -60)
        return self._act(
            signer, "local:handsal.record.promote", org=org,
            body={"anchors": list(anchors), "record_id": record_id}, parent=None,
            parent_performer=None, inputs_hash=hashstr(record), outputs_hash=outputs_hash,
            head={"id": tip or org, "kind": "chain"}, ts=ts,
            extra={"expires": expires or shift(ts, 3600)}).jws

    def _chain_primary(self, method, body, signers, *, parent, ts, org, possession=None,
                       body_edit=None, primary_head=None, endorse_head=True, short=False,
                       primary_raw_edit=None, primary_edit=None, pop_performer=None, root=None):
        """A chain primary by `signers[0]` plus a counted act.endorse per other signer.

        `possession` is a device name whose proof of possession (FO-07) is added
        after the counted endorsements. The signers' persons must be at least two
        distinct ones (FO-22, FO-23) unless `short` says a quorum shortfall is the
        point of the vector.

        Hooks for a negative row that differs from a valid act in one place:
        `body_edit(body)` edits the body before anything is signed, so the
        endorsements follow the edited primary's id; `primary_head` puts a `head`
        on the primary (ACT-08 forbids it); `endorse_head=False` leaves the
        counted endorsements without `head` (the proof of possession keeps it);
        `primary_raw_edit(raw)` replaces bytes of the emitted payload before it is
        signed, for content the canonical subset cannot express (ACT-10);
        `primary_edit(payload)` edits the primary's envelope before its nonce is
        derived (a parent field set wrong, ACT-13); `pop_performer` is the
        `performer_id` of the proof of possession (ACT-13 names it, a row sets it wrong);
        `root` is the id an act with no `parent` links to: the epoch's document hash, which is
        the org id only in epoch 0 (FO-04).
        """
        signers = tuple(signers)
        distinct = len({person_of_name(s) for s in signers})
        if not signers or (not short and (len(signers) < 2 or distinct < 2)):
            raise ValueError("a %s needs signers of at least two distinct persons" % method)
        org = org or self.org_id
        ts = ts or shift(NOW, -3600)
        parent_id = parent.id if parent else (root or org)
        parent_performer = parent.performer if parent else None
        body = json.loads(json.dumps(body))
        if body_edit is not None:
            body_edit(body)
        primary = self._act(signers[0], method, org=org, body=body, parent=parent_id,
                            parent_performer=parent_performer, ts=ts, head=primary_head,
                            raw_edit=primary_raw_edit, payload_edit=primary_edit)
        head = {"id": parent_id, "kind": "chain"}

        def endorse(who, with_head=True, performer=None):
            return self._act(who, "local:handsal.act.endorse", org=org, body={"act": primary.id},
                             parent=primary.id, parent_performer=primary.performer,
                             performer=performer, head=head if with_head else None, ts=ts).jws

        acts = [primary.jws] + [endorse(s, endorse_head) for s in signers[1:]]
        if possession:
            acts.append(endorse(possession, performer=pop_performer))
        return primary, acts, parent_id

    def device_add(self, name, signers, *, parent=None, ts=None, org=None, label=None,
                   pop=True, pop_signer=None, **hooks):
        """Two-person `device.add` of device `name` (FO-09, catalog-part3 25).

        `signers` are device names: the first signs the primary, the others sign
        counted endorsements (act.endorse, FO-08). Their persons must be at least
        two distinct ones. The new key adds its proof of possession (FO-07), whose
        performer is the person of `name`. `parent` is a previous chain primary,
        or None for the root. `pop=False` leaves the proof out, `pop_signer` has
        another device sign it, `pop_performer` (a hook) sets its performer.
        """
        entry = self._device_entry(name)
        body = {"agree": entry["agree"], "class": entry["class"], "kid": entry["kid"],
                "label": label or entry["label"],
                "link_code_hash": hashstr(b"link-code/" + name.encode("ascii")),
                "person": entry["person"], "sign": entry["sign"]}
        primary, acts, parent_id = self._chain_primary(
            "local:handsal.device.add", body, signers, parent=parent, ts=ts, org=org,
            possession=(pop_signer or name) if pop else None, **hooks)
        return DeviceAdd(acts, primary.id, parent_id, primary.performer, name)

    def device_remove(self, name, signers, *, parent=None, ts=None, org=None, **hooks):
        """Two-person `device.remove` of device `name` (ACT-09, FO-22).

        The body names the kid and its person; there is no possession proof.
        """
        entry = self._device_entry(name)
        body = {"kid": entry["kid"], "person": entry["person"]}
        primary, acts, parent_id = self._chain_primary(
            "local:handsal.device.remove", body, signers, parent=parent, ts=ts, org=org, **hooks)
        return DeviceAdd(acts, primary.id, parent_id, primary.performer, name)

    def member_add(self, name, signers, *, role, member=None, parent=None, ts=None, org=None,
                   label=None, pop=True, pop_signer=None, **hooks):
        """Two-person `member.add` of device `name` for `member` (ACT-09, FO-10).

        `member` is the person of `name` unless given. The new device adds its
        proof of possession, whose performer is the new member (ACT-13).
        """
        entry = self._device_entry(name)
        member = member or entry["person"]
        device = {"agree": entry["agree"], "class": entry["class"], "kid": entry["kid"],
                  "label": label or entry["label"], "sign": entry["sign"]}
        body = {"device": device,
                "link_code_hash": hashstr(b"link-code/" + name.encode("ascii")),
                "member": member, "role": role}
        primary, acts, parent_id = self._chain_primary(
            "local:handsal.member.add", body, signers, parent=parent, ts=ts, org=org,
            possession=(pop_signer or name) if pop else None,
            **dict({"pop_performer": member}, **hooks))
        return DeviceAdd(acts, primary.id, parent_id, primary.performer, name)

    def chain_resolve(self, signers, *, candidates, choose, heads, overrides=(), parent=None,
                      ts=None, org=None, **hooks):
        """Two-person `chain.resolve` at `parent` (ACT-09, FO-25).

        Candidates and heads are sorted here; duplicates and a `choose` outside
        the candidates are refused. Negative shapes are built by editing the
        emitted payload, never by a looser builder.
        """
        candidates, heads = sorted(candidates), sorted(heads)
        if len(set(candidates)) != len(candidates) or len(set(heads)) != len(heads):
            raise ValueError("candidates and heads must be distinct")
        if choose not in candidates:
            raise ValueError("choose must be one of the candidates")
        body = {"candidates": candidates, "choose": choose, "heads": heads,
                "overrides": list(overrides)}
        primary, acts, parent_id = self._chain_primary(
            "local:handsal.chain.resolve", body, signers, parent=parent, ts=ts, org=org, **hooks)
        return DeviceAdd(acts, primary.id, parent_id, primary.performer, "resolve")


def vitni_policy(method):
    """The vitni `policy` for an act of `method` (binding pinned to `local`)."""
    return {"expected_binding": "local", "expected_method": method}
