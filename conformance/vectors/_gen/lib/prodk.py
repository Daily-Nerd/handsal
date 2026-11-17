"""The production-key vectors (PRODK, CF-08, GP-18, T7.2).

ORG_PRODK is ORG (catalog base fixtures) under the production profile with three role holders, alice,
bob and carol, whose keys are drawn fresh from the operating system's random source in the memory of one
process. Nothing here ever writes a private scalar: not to a key file, not to a vector, not to the report.
The process signs the vectors that need production keys, the single-edition ones and the two that span two
editions, and ends; the keys are gone with it.

The invariants, and where each is enforced:

- A scalar is never on disk: it lives in `entries` (a dict in memory) and `Fixtures(overlay=...)` reads it
  from there, so there is no key file to forget to delete. `scan` proves, for the paths a run names, that no
  output holds one, in the six forms a scalar is written in.
- The keys sign once: `build` refuses a directory that already holds a file, so a second run cannot add or
  replace a vector beside the first. The directory (`conformance/vectors/prod/`) is one the generator never
  writes, so a regeneration cannot touch it either (CF-08: the bytes are committed, not regenerated).
- The ids are the `pending` list of vector-ids.json, which is exactly the owner-signed ids (their case name begins
  with `prodk-`, CF-08), as tools/check_catalog.py reads it, and nothing else: `build` fails when what it wrote
  differs from that list.
- Agreement keys (`*.agree`) are never used to sign or to agree anything in a vector, so their scalar is
  drawn only to compute the public point and is not kept (`d` is zero in `entries`).

Limits, stated so no report claims more (`README` of the owner kit repeats them): CPython integers cannot
be overwritten, so a scalar stays in the freed memory of the process until the operating system reuses the
page; the arithmetic is the generator's variable-time pure Python, acceptable for one local run of keys that
protect nothing once their scalars are gone; the scan covers the paths it is given and six encodings.

Standard library only; imports the generator driver lazily (it is the owner of `Context`).
"""
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import sys
from pathlib import Path

from . import base, editions, inputs, keys, p256, writer
from .chain import Chain
from .rows import AB

PEOPLE = ("alice", "bob", "carol")
_CONFORMANCE = Path(__file__).resolve().parents[3]
_CHECK_CATALOG = _CONFORMANCE.parent / "tools" / "check_catalog.py"
_CHUNK = 1 << 20


class ProdkError(Exception):
    pass


# ---- the keys ---------------------------------------------------------------

def _scalar(randbelow):
    return randbelow(p256.N - 1) + 1


def _entry(d, with_kid):
    x, y = p256.mul(d)
    xs, ys = keys.b64u(x.to_bytes(32, "big")), keys.b64u(y.to_bytes(32, "big"))
    entry = {"d": "%064x" % d if with_kid else "0" * 64, "x": xs, "y": ys}
    if with_kid:
        entry["kid"] = keys.thumbprint(xs, ys)
    return entry


def random_entries(randbelow=secrets.randbelow):
    """`{label: entry}` for the three people: a signing key with its scalar, an agreement key without one."""
    out = {}
    for name in PEOPLE:
        out[name + ".sign"] = _entry(_scalar(randbelow), True)
        out[name + ".agree"] = _entry(_scalar(randbelow), False)
    return out


def scalars(entries):
    """The private scalars `entries` holds: the signing ones (the agreement keys hold none)."""
    return [int(entries[name + ".sign"]["d"], 16) for name in PEOPLE]


# ---- the scan ---------------------------------------------------------------

def _forms(d):
    raw = d.to_bytes(32, "big")
    return [raw, b"%064x" % d, ("%064X" % d).encode("ascii"), base64.urlsafe_b64encode(raw).rstrip(b"="),
            base64.b64encode(raw), str(d).encode("ascii")]


def _files(roots):
    for root in roots:
        root = Path(root)
        if not root.exists():
            raise ProdkError("scan root does not exist: %s" % root)
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if not path.is_symlink():
                    yield path


def files_scanned(roots):
    return sum(1 for _ in _files(roots))


def _holds(path, needles):
    overlap = max(len(n) for n in needles) - 1
    tail = b""
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(_CHUNK)
                if not block:
                    return False
                window = tail + block
                if any(n in window for n in needles):
                    return True
                tail = window[-overlap:]
    except OSError as err:
        raise ProdkError("cannot read %s while scanning (%s)" % (path, err)) from err


def scan(scalar_values, roots):
    """The files under `roots` that hold any of the scalars in any of six forms (raw 32 bytes, lower and upper
    hex, base64url and base64, decimal). Empty means none found. A root that does not exist is an error."""
    needles = [form for d in scalar_values for form in _forms(d)]
    return [path for path in _files(roots) if _holds(path, needles)]


# ---- the vectors ------------------------------------------------------------

def catalog_check():
    """tools/check_catalog.py, the one owner of what `pending` means. Loaded by path, like tools/manifest.py."""
    spec = importlib.util.spec_from_file_location("handsal_check_catalog", _CHECK_CATALOG)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pending_ids():
    """The ids of the owner run: the pending ids, which are the owner-signed ids (CF-08 S9)."""
    return sorted(catalog_check().owner_signed_ids(_CONFORMANCE.parent))


def _vectors(ctx, entries):
    """The owner-signed vectors, authored from the spec (GP-18, GP-13, CF-08), never from a checker's answer: six over
    one edition, and two over two editions, where the same keys sign the original under the previous edition's
    production profile and the change under the current one (the wire is the same, I3)."""
    fx, w = ctx.fixtures, ctx.writer

    # fix/prodk-fold-ok: ORG_PRODK under the production profile folds to its state.
    c = Chain(fx, ctx=ctx)
    w.add("fix/prodk-fold-ok", "fold", c.expect(), input=c.fold_input())

    # fix/prodk-check-act-ok: an approve by the production alice is valid.
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    w.add("fix/prodk-check-act-ok", "check-act", inputs.check_anchor(approve, "ok"),
          input=inputs.check_input(fx, approve))

    # fix/prodk-fixture-kid-add-not-on-chain: a device.add of a fixture kid (alice2, a device of alice
    # with every proof a fixture profile would accept) is not on the chain, so the state is unchanged.
    c = Chain(fx, ctx=ctx)
    c.device_add("alice2", AB, ok=False, valid=True)
    w.add("fix/prodk-fixture-kid-add-not-on-chain", "fold", c.expect(), input=c.fold_input())

    # fix/prodk-check-act-fixture-kid-unknown: an approve by that fixture kid is `unknown_key`, class null.
    jws = fx.verdict("approve", "alice2", recipient="alice")
    ctx.negative(jws, inputs.APPROVE, list(PEOPLE), "unknown_key")
    w.add("fix/prodk-check-act-fixture-kid-unknown", "check-act",
          inputs.check_anchor(jws, "unknown_key", None),
          input=inputs.check_input(fx, jws, acts=list(c.acts)))

    # fix/prodk-relay-fixture-kid: a production policy whose relay_kid is the fixture relay key is `fixture_key`.
    c = Chain(fx, wit=True, ctx=ctx)
    w.add("fix/prodk-relay-fixture-kid", "fold", inputs.error_anchor("fixture_key"), input=c.fold_input())

    # enr/prodk-fixture-kid-unknown: the fixture kid is not a device of ORG_PRODK.
    w.add("enr/prodk-fixture-kid-unknown", "enrolled", inputs.enrolled_anchor(False, "local_key_unknown"),
          input=inputs.enrolled_input(fx, device="alice2"))

    # prf/prodk-*: a lineage over the previous edition's production profile and the current one's
    pair = editions.Pair(editions.PRODUCTION, overlay=entries)
    editions.change_ok(ctx, "prf/prodk-change-p1-to-p2-ok", pair)
    editions.recheck_after_repin(ctx, "prf/prodk-recheck-p1-epoch-after-repin", pair)


def build(out_dir, entries, crosscheck=None):
    """Sign the owner-signed vectors with `entries`, write them to `out_dir`, return the ids written.

    `out_dir` must be absent or empty: the keys sign once. On any failure nothing stays behind."""
    import generate  # the driver owns Context; imported here because it imports this package
    out_dir = Path(out_dir)
    existed = out_dir.exists()
    if existed and (not out_dir.is_dir() or any(out_dir.iterdir())):
        raise ProdkError("%s already holds files: the production keys sign once" % out_dir)
    ids = pending_ids()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        profile = base.production_profile()
        fixtures = base.Fixtures(profile, overlay=entries)
        vector_writer = writer.VectorWriter(out_dir, known_ids=ids)
        ctx = generate.Context(vector_writer, profile, crosscheck, fixtures=fixtures)
        _vectors(ctx, entries)
        if sorted(vector_writer.names) != ids:
            raise ProdkError("wrote %s, the pending list is %s" % (sorted(vector_writer.names), ids))
    except BaseException:
        _clear(out_dir, remove_dir=not existed)
        raise
    return list(vector_writer.names)


def _clear(out_dir, remove_dir):
    if remove_dir:
        shutil.rmtree(out_dir, ignore_errors=True)
        return
    for path in Path(out_dir).glob("*.json"):
        path.unlink()


def run(out_dir, scan_roots, entries=None, crosscheck=None):
    """Draw keys (or take `entries`), sign, scan, and return the public report.

    The scan covers `scan_roots` and `out_dir`. A scalar found anywhere removes the vectors and fails the run."""
    entries = entries if entries is not None else random_entries()
    out_dir = Path(out_dir)
    existed = out_dir.exists()
    names = build(out_dir, entries, crosscheck)
    roots = [Path(r) for r in scan_roots] + [out_dir]
    try:
        found = scan(scalars(entries), roots)
        counted = files_scanned(roots)
    except BaseException:
        _clear(out_dir, remove_dir=not existed)
        raise
    if found:
        _clear(out_dir, remove_dir=not existed)
        raise ProdkError("a private scalar was found in: %s" % ", ".join(str(p) for p in found))
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out_dir.glob("*.json"))}
    return {
        "created_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
        "files_scanned": counted,
        "ids": sorted(names),
        "kids": sorted(entries[n + ".sign"]["kid"] for n in PEOPLE),
        "people": {n: entries[n + ".sign"]["kid"] for n in PEOPLE},
        "pid": os.getpid(),
        "production_profile": base.production_profile(),
        "python": sys.version.split()[0],
        "scalars_found": [],
        "scalars_held": len(scalars(entries)),
        "scan_roots": [str(r) for r in roots],
    }
