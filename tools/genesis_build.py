"""Build the draft of a genesis document and assemble the receipts that sign it.

Usage: genesis_build.py draft OUT          (input JSON on stdin)
       genesis_build.py assemble DRAFT RECEIPT... [--out DIR]

The tool constructs a document from public data and asks the checker of this checkout about every rule, byte
and hash. It decides nothing itself: a refusal is the checker's own code.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER_SRC = ROOT / "checker" / "python" / "src"

# The checker of this checkout, never an installed copy: a module already imported from elsewhere would win over
# the path inserted here, so the identity of what was imported is checked.
sys.path.insert(0, str(CHECKER_SRC))
import handsal_check  # noqa: E402

_IMPORTED = Path(handsal_check.__file__).resolve().parent.parent
if _IMPORTED != CHECKER_SRC.resolve():
    raise ImportError("handsal_check was imported from %s, this checkout's checker is at %s" % (_IMPORTED, CHECKER_SRC))

from handsal_check import devicekey, emit, encoding, genesis, genesis_check, ijson, render, verifier  # noqa: E402  (only after the identity check: a decoy has no submodules)

THROWAWAY_PREFIX = "tmp-"
ROLES = ["maintainer", "member"]
RULE_ROLES = ["maintainer"]
RULES = ("chain.resolve", "device.remove", "genesis.change", "member.add")
FRESHNESS = {"clock_skew_s": "300", "max_validity_s": "604800", "max_view_age_s": "86400"}
POLICY_VERSION = "handsal-policy/1"
SIGN_METHOD = "local:handsal.genesis.sign"
UNSIGNED = "genesis_unsigned"   # the answer of the fold to a valid document that carries no signature
LF = b"\n"


def production_profile(profile_set):
    """The production hash of the current edition: the one a new document names."""
    return profile_set.production_hashes()[-1]


class Refusal(Exception):
    """A refusal with its code. The code is the checker's own except for the four the checker has no word for."""

    def __init__(self, code, **extra):
        super().__init__(code)
        self.code = code
        self.extra = extra


INPUT_KEYS = {"name", "members", "devices", "persons", "relays"}
REQUIRED_KEYS = {"name", "members", "devices"}
PUBKEY_KEYS = {"agree", "class", "kid", "sign"}
DEFAULT_PERSONS = "2"


def _malformed():
    return Refusal("malformed_input")


def _strings(value):
    return type(value) is list and all(type(item) is str for item in value)


def _member(value):
    return type(value) is dict and set(value) == {"id", "role"} and _strings(list(value.values()))


def _pubkey(value):
    return (type(value) is dict and set(value) == PUBKEY_KEYS and type(value["class"]) is str
            and type(value["kid"]) is str and type(value["agree"]) is dict and type(value["sign"]) is dict)


def _device(value):
    return (type(value) is dict and set(value) == {"person", "label", "pubkey"}
            and type(value["person"]) is str and type(value["label"]) is str and _pubkey(value["pubkey"]))


def read_text(raw):
    """The value of the input bytes `raw`, framed by the checker's I-JSON reader (size, UTF-8, no duplicate name)."""
    try:
        return ijson.loads(raw)
    except ijson.Unparseable:
        raise Refusal("unparseable_input") from None


def read_input(value):
    """The input of a draft: a closed object, types only, defaults filled in. Grammar, bounds, curve points and
    policy are the checker's (R1.3), so a value that has the right type goes through unjudged."""
    if type(value) is not dict or not REQUIRED_KEYS <= set(value) <= INPUT_KEYS:
        raise _malformed()
    persons = value.get("persons", DEFAULT_PERSONS)
    relays = value.get("relays", [])
    if (type(value["name"]) is not str or type(persons) is not str or not _strings(relays)
            or type(value["members"]) is not list or not all(_member(m) for m in value["members"])
            or type(value["devices"]) is not list or not all(_device(d) for d in value["devices"])):
        raise _malformed()
    return {"name": value["name"], "members": value["members"], "devices": value["devices"],
            "persons": persons, "relays": relays}


def document(spec, production, reg):
    """The original genesis document of `spec`, sorted as GP-15 reads it. Pure: it validates nothing."""
    classes = []
    for name in sorted({d["pubkey"]["class"] for d in spec["devices"]}):
        found = reg.lookup_class(name, False)
        if found is None:
            raise Refusal("class_unknown")
        classes.append({"class": name, "user_verification": found.user_verification})
    devices = [{**d["pubkey"], "label": d["label"], "person": d["person"]} for d in spec["devices"]]
    return {
        "devices": sorted(devices, key=lambda d: d["kid"]),
        "members": sorted(spec["members"], key=lambda m: m["id"]),
        "name": spec["name"],
        "org": None,
        "policy": {
            "classes": classes,
            "freshness": dict(FRESHNESS),
            "relays": sorted(spec["relays"]),
            "roles": list(ROLES),
            "rules": {rule: {"persons": spec["persons"], "roles": list(RULE_ROLES)} for rule in RULES},
            "v": POLICY_VERSION,
            "witness": {"mode": "none"},
        },
        "prev": None,
        "profile": production,
        "v": genesis.VERSION,
    }


def new_document(spec, profile_set):
    """The document of `spec` under the current edition of `profile_set`: its production hash and its registry."""
    production = production_profile(profile_set)
    return document(spec, production, profile_set.resolve(production).version.reg)


def sign_input(doc):
    """The exact input of the signer's `sign` command for `doc`."""
    return {"attachments": {"document": doc},
            "draft": {"body": {}, "method": SIGN_METHOD, "org": genesis.doc_hash(doc)}}


def draft_bytes(doc):
    """The bytes of `draft.json`: the checker's canonical emitter over the sign input, then one LF."""
    return emit.emit_subset(sign_input(doc)) + LF


def validate_draft(doc, profile_set):
    """The checker's code for `doc` with no signature: `genesis_unsigned` is the pass, anything else is the
    refusal, unchanged. The fold has no verifier to call on an empty signature list."""
    inp = genesis_check.GenesisInput([], [{"doc": doc, "sigs": []}])
    epochs, code = genesis_check.fold(inp, profile_set, False, verifier.Absent())
    if epochs is not None:
        raise RuntimeError("the fold accepted a document with no signature: the draft contract is broken")
    return code


def _key_defect(spec):
    """Which input device the fold's key check names, and why: the same function the fold calls."""
    for index, device in enumerate(spec["devices"]):
        key = device["pubkey"]
        defect = devicekey.defect(key["kid"], key["sign"], key["agree"])
        if defect is not None:
            return {"device": index, "defect": defect}
    return {}


def compose(spec, profile_set):
    """The draft of `spec`: the document, its bytes and its hashes. Raises Refusal with the checker's code."""
    doc = new_document(spec, profile_set)
    code = validate_draft(doc, profile_set)
    if code != UNSIGNED:
        raise Refusal(code, **(_key_defect(spec) if code == "genesis_key_invalid" else {}))
    raw = draft_bytes(doc)
    document_hash = genesis.doc_hash(doc)
    return {"document": doc, "draft_bytes": raw, "document_hash": document_hash,
            "hash12": render.hash12(document_hash), "draft_hash": encoding.hashstr(raw)}
