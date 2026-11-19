"""Build the draft of a genesis document and assemble the receipts that sign it.

Usage: genesis_build.py draft OUT          (input JSON on stdin)
       genesis_build.py assemble DRAFT RECEIPT... [--out DIR]

The tool constructs a document from public data and asks the checker of this checkout about every rule, byte
and hash. It decides nothing itself: a refusal is the checker's own code, printed as one JSON line
{"error": CODE} with exit status 2.

draft reads the input from stdin and writes the exact input of the signer's sign command to OUT. OUT must not
exist (the file is created, never replaced). It prints {document_hash, draft_hash, hash12}.

  {"name": "acme",
   "members": [{"id": "alice", "role": "maintainer"}, ...],
   "devices": [{"person": "alice", "label": "alice mac", "pubkey": {"agree": ..., "class": ..., "kid": ..., "sign": ...}}, ...],
   "persons": "2", "relays": []}

  genesis_build.py draft draft.json < acme.json

assemble reads the draft and the receipt files ({jws, receipt_id}, as the signer prints them) and prints where
the signing stands as one JSON line: state (unsigned, partial or complete), signed, of, the kids still missing,
a label for every file, and when complete the pin line. The checker decides which receipts count, through the
verifier at its fixed path; no verifier is a refusal, never a guess. With --out DIR (which must not exist) a
complete result also writes lineage.json, original.json and one ceremony-KID.json per device, all or nothing.
original.json is the admit item for the original, {doc, sigs}, and the org id is the document_hash. It exits 0
for any state and 2 for a refusal. A DRAFT or RECEIPT path that does not exist is a refusal too: malformed_input with the
path, and nothing is written.

  genesis_build.py assemble draft.json receipt-*.json --out ceremony
"""
import argparse
import errno
import os
import shutil
import sys
import tempfile
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

from handsal_check import (devicekey, emit, encoding, genesis, genesis_check, genesis_sigs, ijson,  # noqa: E402
                           profiles, render, verifier)   # only after the identity check: a decoy has no submodules

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
    epochs, code = genesis_check.fold(inp, profile_set, False, verifier.Memoized(verifier.Absent()))
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


def build(value, profile_set):
    """The founding entry: `read_input`, the refusal of a throwaway name, then `compose`."""
    spec = read_input(value)
    if spec["name"].startswith(THROWAWAY_PREFIX):
        raise Refusal("name_is_throwaway")
    return compose(spec, profile_set)


def write_once(path, data):
    """Create `path` with `data`. A path that exists in any form, a symlink included, is never touched."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        raise Refusal("file_exists", path=str(path)) from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def read_file(path):
    """The bytes of a file the caller named. One that is not there is the caller's error: a refusal, not a crash."""
    try:
        return Path(path).read_bytes()
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise
        raise Refusal("malformed_input", path=str(path)) from None


def read_draft(raw):
    """The document of a draft file, iff the file is byte for byte what `draft` writes for that document."""
    value = read_text(raw)
    try:
        doc = value["attachments"]["document"]
        same = draft_bytes(doc) == raw
    except (KeyError, TypeError, emit.EmitError):
        raise Refusal("malformed_input") from None
    if not same:
        raise Refusal("malformed_input")
    return doc


def _read_receipt(raw, doc, doc_hash, wire):
    """`(label, text, kid)` for one receipt file, by the checker's own reading. The label is None for a file that
    reads as a genesis.sign of this document by a listed device: only the verifier can say more, and then `text`
    and `kid` are its JWS and its signer."""
    try:
        value = ijson.loads(raw)
    except ijson.Unparseable:
        return "unparseable_input", None, None
    if type(value) is not dict or set(value) != {"jws", "receipt_id"} or not _strings(list(value.values())):
        return "malformed_input", None, None
    act = genesis_sigs.read(value["jws"], doc, doc_hash, doc_hash, wire)
    if act is None:
        return "not_this_document", None, None
    if act.kid not in {d["kid"] for d in doc["devices"]}:
        return "kid_not_listed", None, None
    return None, value["jws"], act.kid


def lineage(doc, files, report):
    """The lineage `[{doc, sigs}]` of the files that `report` says count, sigs sorted bytewise."""
    return [{"doc": doc, "sigs": sorted(ijson.loads(files[name])["jws"]
                                        for name, label in report["files"].items() if label == "counts")}]


def assemble(doc, files, profile_set, vitni):
    """Where the receipts in `files` ({name: bytes}) leave the signing of `doc`. Originals only. A receipt counts
    only if the checker's `counting` says so; the first counting file of a kid wins. `complete` is the answer of
    the checker's `genesis-check` run, whose pin line is returned as it is. One call, one memo: the `counting` loop
    and the `genesis-check` run share it."""
    vitni = verifier.Memoized(vitni)
    code = validate_draft(doc, profile_set)
    if code != UNSIGNED:
        raise Refusal(code)
    document_hash = genesis.doc_hash(doc)
    counted, labels = set(), {}
    for name in sorted(files):
        label, text, kid = _read_receipt(files[name], doc, document_hash, profile_set.wire)
        if label is None and kid in counted:
            label = "duplicate_kid"
        elif label is None:
            try:
                counts = genesis_sigs.counting(doc, [text], document_hash, profile_set.wire, vitni)
            except verifier.VerifierUnavailable:
                raise Refusal("verifier_unavailable") from None
            label = "counts" if counts else "not_counting"
            counted |= counts
        labels[name] = label
    kids = sorted(d["kid"] for d in doc["devices"])
    missing = [kid for kid in kids if kid not in counted]
    report = {"document_hash": document_hash, "hash12": render.hash12(document_hash),
              "state": "unsigned" if not counted else "partial" if missing else "complete",
              "signed": len(counted), "of": len(kids), "missing": missing, "files": labels}
    if report["state"] == "complete":
        run = genesis_check.run(genesis_check.GenesisInput([], lineage(doc, files, report)), profile_set, False, vitni)
        if not run["valid"]:
            raise Refusal(run["reason"])
        report["pin"] = run["pin"]
    return report


def ceremony_files(doc, lineage_):
    """The files `assemble --out` writes: the lineage, the admit item of the original (the first element of the
    lineage, exactly `{doc, sigs}`), and one signer input per device (SG-12 step 1)."""
    out = {"lineage.json": emit.emit_subset({"acts": [], "lineage": lineage_}) + LF,
           "original.json": emit.emit_subset(lineage_[0]) + LF}
    for kid in sorted(d["kid"] for d in doc["devices"]):
        out["ceremony-%s.json" % kid] = emit.emit_subset({"acts": [], "device_kid": kid, "lineage": lineage_}) + LF
    return out


def make_directory(path):
    """Create the directory `path`, which must not exist in any form."""
    try:
        os.mkdir(path)
    except FileExistsError:
        raise Refusal("file_exists", path=str(path)) from None


def write_directory(path, files):
    """Create the directory `path`, which must not exist, with `files` ({name: bytes}) in it.
    All or nothing: the files go into a temporary sibling that is renamed to `path` when complete, and removed
    when any write fails."""
    path = Path(path)
    if os.path.lexists(path):
        raise Refusal("file_exists", path=str(path))
    staging = Path(tempfile.mkdtemp(prefix=".%s-" % path.name, dir=path.parent))
    try:
        os.chmod(staging, 0o755)
        for name, data in files.items():
            write_once(staging / name, data)
        os.rename(staging, path)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _say(stdout, value):
    stdout.write(emit.emit_result(value) + LF)


def _draft(args, stdin, stdout):
    made = build(read_text(stdin.read()), profiles.load())
    write_once(args.out, made["draft_bytes"])
    _say(stdout, {key: made[key] for key in ("document_hash", "draft_hash", "hash12")})


def _assemble(args, stdin, stdout, vitni):
    doc = read_draft(read_file(args.draft))
    files = {name: read_file(name) for name in args.receipts}
    report = assemble(doc, files, profiles.load(), vitni)
    if args.out is not None and report["state"] == "complete":
        write_directory(args.out, ceremony_files(doc, lineage(doc, files, report)))
    _say(stdout, report)


def _parser():
    parser = argparse.ArgumentParser(prog="genesis_build.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    draft = commands.add_parser("draft", help="write the draft of a genesis document")
    draft.add_argument("out", metavar="OUT")
    draft.set_defaults(run=lambda args, stdin, stdout, vitni: _draft(args, stdin, stdout))
    assembled = commands.add_parser("assemble", help="report where the receipts leave the signing of a draft")
    assembled.add_argument("draft", metavar="DRAFT")
    assembled.add_argument("receipts", metavar="RECEIPT", nargs="*")
    assembled.add_argument("--out", metavar="DIR", help="when complete, write the lineage, the original and the signer inputs here")
    assembled.set_defaults(run=_assemble)
    return parser


def main(argv=None, stdin=None, stdout=None, vitni=None):
    """0 when the command did its job, 2 when it printed a refusal. A broken checkout is a crash, never caught.
    `vitni` is the verifier `assemble` asks; none means the one at the checker's fixed path."""
    args = _parser().parse_args(argv)
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout.buffer if stdout is None else stdout
    try:
        args.run(args, stdin, stdout, verifier.VitniCli.installed() if vitni is None else vitni)
    except Refusal as refusal:
        _say(stdout, {"error": refusal.code, **refusal.extra})
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
