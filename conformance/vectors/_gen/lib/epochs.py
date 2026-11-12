"""Documents and lineages beyond ORG: ORG4 and chains over any epoch (catalog-part3 ORG4, GP-07).

ORG4 is ORG plus a fourth maintainer `erin` with an `apple-se-bio` device, the document
every row uses that needs `persons "3"` with a spare role holder (GP-02). Erin's keys are
derived like every fixture key (lib/keys.py, labels `erin.sign` and `erin.agree`) and
registered on the fixtures when first asked for.
"""
from . import chain, inputs, state

ERIN = "erin"


def _erin(fx):
    try:
        fx.key(ERIN)
    except KeyError:
        fx.register_device(ERIN, ERIN + ".sign", ERIN + ".agree")


def org4(fx, persons="3", edit=None):
    """ORG4 with every rule at `persons`, then `edit(document)` (a deep copy is returned)."""
    _erin(fx)
    doc = fx.org_doc(maintainers=("alice", "bob", "carol", ERIN), persons=persons)
    return inputs.derive(doc, edit) if edit else doc


def original_chain(fx, doc, *, ctx=None):
    """A `Chain` over the original document `doc`, with every listed device's genesis.sign."""
    return chain.Chain(fx, doc=doc, lineage=inputs.original_lineage(fx, doc), ctx=ctx)


# ---- genesis changes (GP-19, GP-20; CHG-NEW and CHG-VALID of catalog-part3) ----------------

def _newcomer(fx, name):
    """A new maintainer's device entry; `frank` and `grace` are fixtures, others are derived."""
    try:
        fx.key(name)
    except KeyError:
        fx.register_device(name, name + ".sign", name + ".agree")
    return fx.device_entry(name)


def _carried(st, person, include_removed):
    out = []
    for kid, d in st.devices.get(person, {}).items():
        if d["status"] == "active" or include_removed:
            out.append({"agree": d["agree"], "class": d["class"], "kid": kid,
                        "label": d["label"], "person": person, "sign": d["sign"]})
    return out


def make_change(fx, previous, head, *, carry, new=("frank", "grace"), st=None,
                include_removed=False, edit=None):
    """A change of `previous` at position `head` carrying the named persons' devices.

    The carried entries are copied byte-identical from `st`, the state at H (default: the
    state of `previous` itself), active devices only unless `include_removed`. Each carried
    person keeps the role the previous document gives them (else `maintainer`); `new` are
    new maintainers with fresh keys; every other member is dropped and the policy is kept.
    `edit(document)` runs last.
    """
    st = st or state.State(previous)
    roles = {m["id"]: m["role"] for m in previous["members"]}
    entries = [e for person in carry for e in _carried(st, person, include_removed)]
    entries += [_newcomer(fx, name) for name in new]
    members = [{"id": p, "role": roles.get(p, "maintainer")} for p in carry]
    members += [{"id": name, "role": "maintainer"} for name in new]
    org = previous["org"] or inputs.doc_id(previous)

    def apply(doc):
        doc.update({"org": org, "prev": inputs.doc_id(previous), "head": head})
        doc["members"] = sorted(members, key=lambda m: m["id"])
        doc["devices"] = sorted(entries, key=lambda d: d["kid"])
        if edit:
            edit(doc)
    return inputs.derive(previous, apply)


def sign_change(fx, doc, *, skip=(), also=()):
    """The genesis.sign set of change `doc`: every listed device signs with the head.

    `skip`: device names that do not sign. `also`: devices that sign without being listed,
    each a name or `(name, overrides)` where the overrides go to `genesis_sign` (`head`,
    `performer`).
    """
    sigs = []
    for entry in doc["devices"]:
        name = fx.name_of_kid(entry["kid"])
        if name not in skip:
            sigs.append(fx.genesis_sign(name, doc))
    for item in also:
        name, kwargs = item if isinstance(item, tuple) else (item, {})
        sigs.append(fx.genesis_sign(name, doc, **kwargs))
    return sigs


def lineage_with(lineage, doc, sigs):
    """`lineage` followed by the document `doc` with its signatures."""
    return list(lineage) + [{"doc": doc, "sigs": sigs}]
