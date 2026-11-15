"""The snapshot `{acts, docs, org}` (CF-13): what a source serves, read once for `sync`, `admit` and `pool`.

`parse` is the only reader. It checks the closed object, then returns the snapshot in its canonical form, so the
three commands cannot disagree about what a snapshot is:

  acts   the strings, sorted and unique (a text that is no act is the fold's to ignore, FO-06)
  docs   one `{doc, sigs}` entry per document hash: entries for one document are one entry with `sigs` united,
         sorted and unique, and the entries are sorted by document hash
  org    a hashstr

A `doc` is a genesis document: an object the canonical subset can express, so it has a hash (GP-04). Anything
else cannot be keyed, and is `malformed_input` here, never a fold result. `canonical_size` is the size of the JCS
of that form (RS9): the one measure of "what every machine can `sync`". `by_hash` indexes the entries and
`path_to` walks `prev` through that index from a document back to its original, the one walk `sync` (the pinned
path) and the server's store checks share; the index is made once per snapshot, so no walk hashes a document.

This module is pure and reads no rule of the fold: it holds the shape and nothing else.
"""
from collections import namedtuple

from . import emit, errors, foldcmd, genesis, schema

Snapshot = namedtuple("Snapshot", "acts docs org")

KEYS = {"acts", "docs", "org"}


def canonical(items):
    """The strictly increasing list of the set of `items`. Python orders strings by code point, which is the
    byte order of their UTF-8."""
    return sorted(set(items))


def _keyed(value):
    """`(document hash, doc, sigs)` of one `{doc, sigs}` entry `value`, or raise Malformed."""
    foldcmd.check_lineage([value])
    doc = value["doc"]
    if type(doc) is not dict:
        raise errors.Malformed()
    try:
        return genesis.doc_hash(doc), doc, value["sigs"]
    except emit.EmitError:
        raise errors.Malformed() from None


def entry(value):
    """The canonical `{doc, sigs}` of one entry `value` (`sigs` sorted and unique), or raise Malformed."""
    _, doc, sigs = _keyed(value)
    return {"doc": doc, "sigs": canonical(sigs)}


def _entries(docs):
    """The entries of the list `docs`, united by document hash, sorted by it."""
    if type(docs) is not list:
        raise errors.Malformed()
    united = {}
    for value in docs:
        key, doc, sigs = _keyed(value)
        united.setdefault(key, {"doc": doc, "sigs": set()})["sigs"].update(sigs)
    return [{"doc": united[key]["doc"], "sigs": canonical(united[key]["sigs"])} for key in sorted(united)]


def parse(value, extra=()):
    """`(Snapshot, {name: value})` of the command JSON `value`: the closed object of `KEYS` and the members
    `extra` that the command adds (they are required, and returned untouched for it to read). Raises Malformed."""
    if type(value) is not dict or set(value) != KEYS | set(extra):
        raise errors.Malformed()
    acts, org = value["acts"], value["org"]
    if type(acts) is not list or not schema.is_hashstr(org):
        raise errors.Malformed()
    foldcmd.check_texts(acts)
    return Snapshot(canonical(acts), _entries(value["docs"]), org), {name: value[name] for name in extra}


def canonical_size(snap, extra_acts=(), extra_docs=()):
    """The bytes of the JCS of `snap` with `extra_acts` and `extra_docs` (entries) added: the size of the
    snapshot a source would serve after them (RS9, CF-13)."""
    docs = _entries(snap.docs + list(extra_docs))
    return len(emit.emit_result({"acts": canonical(list(snap.acts) + list(extra_acts)), "docs": docs,
                                 "org": snap.org}))


def by_hash(snap):
    """`{document hash: entry}` of the snapshot."""
    return {genesis.doc_hash(entry["doc"]): entry for entry in snap.docs}


def path_to(index, tip):
    """The entries from the original to the document whose hash is `tip` in `index` (`by_hash`, made once by the
    caller: hashing every document is the cost, and a walk must not pay it), each linked to the one before by
    `prev`. None when `tip` is no document of the index, and `[]` when a link is missing (the walk reaches a
    document whose `prev` is neither null nor a stored hash)."""
    if tip not in index:
        return None
    path, seen = [], set()
    while tip is not None:
        entry = index.get(tip) if type(tip) is str else None
        if entry is None or tip in seen:
            return []
        seen.add(tip)
        path.append(entry)
        tip = entry["doc"].get("prev")
    return path[::-1]
