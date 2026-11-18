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

from handsal_check import ijson  # noqa: E402  (only after the identity check: a decoy has no submodules)


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
