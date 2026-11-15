"""The per-machine store, its format and its reader (CF-09).

`handsal-store/1` is one line of JCS and one LF:
`{"acts":[...],"lineage":[{doc,sigs}...],"synced_at":T,"v":"handsal-store/1","witness":null}`, at most
MAX_INPUT bytes. `acts` is strictly increasing in byte order, and so is each `sigs` of the lineage, so a store
holds sets and two encodings of one set cannot exist; `encode` is the only writer of the form and sorts and
deduplicates itself. `parse` reads the bytes
with the CF-03 reader and then compares them with their own JCS, so any form `encode` would not write is
`store_malformed`: a CRLF, a missing LF, a second line, unsorted or duplicate acts, an extra or missing key,
another `v`, a non-null `witness`, a non-string act, unsorted or repeated sigs, or more than MAX_INPUT bytes. There is no `org` member: the
first lineage document's hash is the org, and the pin checks compare it.

This module is pure. A store port (`store_posix.PosixStore`, or a test's) hands it bytes: `read(org)` returns the
bytes of the store or raises Refused with `store_missing`, `store_owner` or `store_unavailable`. `load` is what a
reader (the production `fill`) gets from a port: a `Stored`, whose `reason` is the code that stops VR-02 step 6
(f), or None.
"""
from collections import namedtuple

from . import emit, errors, foldcmd, ijson, schema
from .snapshot import canonical

VERSION = "handsal-store/1"
KEYS = {"acts", "lineage", "synced_at", "v", "witness"}
# Every time is 20 bytes, so a candidate store can be measured before the clock is read.
SIZING_TIME = "1970-01-01T00:00:00Z"

Stored = namedtuple("Stored", "acts lineage synced_at witness reason")
NOTHING = Stored([], [], None, None, None)


def encode(acts, lineage, synced_at):
    """The bytes of a store: the set `acts`, `lineage` and `synced_at`, `witness` null."""
    lineage = [{"doc": entry["doc"], "sigs": canonical(entry["sigs"])} for entry in lineage]
    body = {"acts": canonical(acts), "lineage": lineage, "synced_at": synced_at, "v": VERSION, "witness": None}
    return emit.emit_result(body) + b"\n"


def _malformed():
    return errors.Refused("store_malformed")


def parse(raw):
    """The `Stored` in the bytes `raw`, or Refused `store_malformed`."""
    try:
        value = ijson.loads(raw)
        if type(value) is not dict or set(value) != KEYS:
            raise _malformed()
        acts, lineage, synced_at = value["acts"], value["lineage"], value["synced_at"]
        if type(acts) is not list or type(lineage) is not list or type(synced_at) is not str:
            raise _malformed()
        foldcmd.check_texts(acts)
        foldcmd.check_lineage(lineage)
        if not schema.is_time(synced_at) or value["v"] != VERSION or value["witness"] is not None:
            raise _malformed()
        if encode(acts, lineage, synced_at) != raw:   # sorted, unique, canonical: the one form `encode` writes
            raise _malformed()
    except (ijson.Unparseable, errors.Malformed, emit.EmitError):
        raise _malformed() from None
    return Stored(acts, lineage, synced_at, None, None)


def load(port, org):
    """What a reader gets from `port` for `org`: the store's `Stored`, or an empty one whose `reason` is the
    code that refuses it (`store_missing`, `store_owner`, `store_malformed`, `store_unavailable`)."""
    try:
        return parse(port.read(org))
    except errors.Refused as err:
        return NOTHING._replace(reason=err.code)
