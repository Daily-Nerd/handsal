"""The pin file and the pin checks (GP-05, GP-14), VR-02 step 6 (a) to (h) and GP-13 steps 1 to 3.

`parse` reads the bytes of a pin file: one line of canonical-subset JSON
`{"genesis":..,"org":..,"spec":..,"v":"handsal-pin/1"}` and one LF, at most 512
bytes; anything else wrong with the bytes is `pin_malformed`. `line` writes it
(the single source for the pin helper). `Probe` is the data a platform probe
returns (GP-14). `check` runs the ordered comparisons of probe, pin, input and
the last lineage document and returns the pin, or raises Refused with the first
failing code:

  (a) probe org or file name differs from the input org   `pin_org_mismatch`
  (b) `owner_ok` false                                    the probe's reason
  (c) the bytes                                           `pin_malformed`
  (d) the pin's org differs from the input org            `pin_org_mismatch`
  (e) `spec` is not an implemented profile                `profile_mismatch`
  (f) production build and `spec` is the fixture profile  `fixture_profile`, then the store's reason
                                                          (`store_missing` ..., CF-09), when it has one
  (g) empty lineage, the pin's `org` is not the first document's hash, then `genesis`
      is not the last document's hash                     `lineage_broken` (twice), `genesis_pin_mismatch`
  (h) `spec` is not the last document's profile           `pin_spec_mismatch`

The fold (step 6 (i)) comes after, in the caller. No file is read here.
"""
import base64
import binascii
from collections import namedtuple

from . import emit, encoding, errors, genesis, org, schema, subset

MAX_BYTES = 512
VERSION = "handsal-pin/1"
KEYS = {"genesis", "org", "spec", "v"}
PROBE_KEYS = {"bytes_b64", "filename", "org", "owner_ok", "reason"}
PROBE_FAILURES = ("pin_missing", "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected")

Pin = namedtuple("Pin", "genesis org spec")
# The two ends of a lineage: the hash of its first document and of its last (None for a document that
# has none), and the last document's profile.
Ends = namedtuple("Ends", "first last profile")


def _hash(doc):
    try:
        return genesis.doc_hash(doc)
    except emit.EmitError:
        return None


def ends(lineage):
    """The `Ends` of a lineage `[{doc, sigs}]`, or None for an empty one. The ONE place that reads the
    ends of a lineage, shared by `fold`, `check-act` and `enrolled` (GP-07)."""
    if not lineage:
        return None
    last = lineage[-1]["doc"]
    return Ends(_hash(lineage[0]["doc"]), _hash(last), last.get("profile") if type(last) is dict else None)


def line(genesis, org_id, spec):
    """The pin file bytes: one canonical line and one LF."""
    for value in (genesis, org_id, spec):
        if not encoding.is_hashstr(value):
            raise ValueError("a pin member is not a hashstr")
    doc = {"genesis": genesis, "org": org_id, "spec": spec, "v": VERSION}
    return emit.emit_subset(doc) + b"\n"


def _malformed():
    return errors.Refused("pin_malformed")


def parse(raw):
    """The Pin in the bytes `raw` of a pin file, or Refused `pin_malformed`."""
    if len(raw) > MAX_BYTES or not raw.endswith(b"\n"):
        raise _malformed()
    try:
        doc = subset.parse(raw[:-1])   # CR, a second line or non-ASCII fail the grammar
    except subset.SubsetError:
        raise _malformed() from None
    if type(doc) is not dict or set(doc) != KEYS or doc["v"] != VERSION:
        raise _malformed()
    if not all(schema.is_hashstr(doc[key]) for key in ("genesis", "org", "spec")):
        raise _malformed()
    return Pin(doc["genesis"], doc["org"], doc["spec"])


class Probe(namedtuple("Probe", "raw filename org owner_ok reason")):
    """What a platform probe returns (GP-14), with `bytes_b64` decoded."""
    __slots__ = ()

    @classmethod
    def from_json(cls, value):
        """The Probe of the JSON object `value`, or Malformed (`malformed_input`).

        `bytes_b64` is standard base64 with padding, canonical. `reason` is `ok` exactly when
        `owner_ok` is true, otherwise one of the four probe failures.
        """
        if type(value) is not dict or set(value) != PROBE_KEYS:
            raise errors.Malformed()
        text, filename, org_id = value["bytes_b64"], value["filename"], value["org"]
        owner_ok, reason = value["owner_ok"], value["reason"]
        if type(text) is not str or type(filename) is not str or type(org_id) is not str:
            raise errors.Malformed()
        if type(owner_ok) is not bool or type(reason) is not str:
            raise errors.Malformed()
        reason_fits = reason == "ok" if owner_ok else reason in PROBE_FAILURES
        if not reason_fits:
            raise errors.Malformed()
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raise errors.Malformed() from None
        if base64.b64encode(raw).decode("ascii") != text:
            raise errors.Malformed()
        return cls(raw, filename, org_id, owner_ok, reason)


def check(probe, expected_org, profiles, lineage_ends, allow_fixture, store_reason=None):
    """Steps (a) to (h) for `probe` against the input org `expected_org` and the ends of the lineage
    `lineage_ends` (`ends`, or None for an empty lineage: `lineage_broken`, reached where the
    comparison with it would be). `allow_fixture` is false for the production build.
    `expected_org` is a hashstr: the command checked it (VR-01).

    `store_reason` is the production build's store failure (CF-09), a code or None: it is the answer at (f),
    after `fixture_profile` and before the lineage comparisons, because the lineage is what the store holds."""
    if probe.org != expected_org or probe.filename != org.pin_filename(expected_org):
        raise errors.Refused("pin_org_mismatch")
    if not probe.owner_ok:
        raise errors.Refused(probe.reason)
    pin = parse(probe.raw)
    if pin.org != expected_org:
        raise errors.Refused("pin_org_mismatch")
    profile = profiles.resolve(pin.spec)
    if profile is None:
        raise errors.Refused("profile_mismatch")
    if profile.fixture and not allow_fixture:
        raise errors.Refused("fixture_profile")
    if store_reason is not None:
        raise errors.Refused(store_reason)
    if lineage_ends is None or lineage_ends.first is None or pin.org != lineage_ends.first:
        raise errors.Refused("lineage_broken")
    if lineage_ends.last is None or pin.genesis != lineage_ends.last:
        raise errors.Refused("genesis_pin_mismatch")
    if pin.spec != lineage_ends.profile:
        raise errors.Refused("pin_spec_mismatch")
    return pin
