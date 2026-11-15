"""The lineage: every document in GP-15 order, and a genesis change read against its previous epoch
(GP-07, GP-09, GP-15, GP-19, GP-20).

`fold_lineage` takes the documents from the original to the pinned one and returns one `Epoch` per
document. Per document, the first failure of the first failing document wins, in this order:
  1-3  structure, profile, policy and devices (`genesis.check_document`)
  4    link (`genesis.check_link`)
  5    render size (`render_size`, owned by the render: `render_genesis.render_size`)
  6    possession (`genesis_sigs`)
  7    change only: `genesis_head_unknown`: H is no node of the previous act tree
  8    change only: `genesis_change_unauthorized`: too few previous role holders, clean at H, signed
  9    change only: `genesis_device_revoked`, then `genesis_device_changed` (carried devices)

A change reads only the path to its head H in the epoch before it, each primary validated against its
prefix state: the fork rule is never applied there, so a fork in an old epoch never fails a later one,
and nothing after or beside H counts (clean(k, H) is the state at H). The last epoch is the fold;
earlier epochs are read only along the path to each H. Acts of every epoch sit in one bag and sort
themselves into epochs by the root they name as parent.
"""
from . import chain, genesis, genesis_sigs, render_genesis, tree, verifier
from .errors import Refused
from .fold import NO_EARLIER, Earlier, Epoch
from .state import point


class Cursor:
    """What the documents before one tell about it: the original's kind and org id, the document before."""

    def __init__(self):
        self.first_kind = self.previous = self.original_org = None

    def structure(self, doc, ctx):
        """GP-15 steps 1 to 4 for `doc`; returns its profile kind."""
        kind = genesis.check_document(doc, ctx, self.first_kind)
        if self.original_org is None:
            self.original_org = genesis.doc_hash(doc)
        genesis.check_link(doc, self.previous, self.original_org)
        self.first_kind, self.previous = self.first_kind or kind, doc
        return kind


def _extend(earlier, doc, state):
    """The pool after one more epoch: its document and its state at the head that closed it."""
    kids, points, members = set(earlier.kids), set(earlier.points), set(earlier.members)
    for entry in doc["devices"]:
        kids.add(entry["kid"])
        points.update((point(entry["sign"]), point(entry["agree"])))
    members.update(m["id"] for m in doc["members"])
    for kid, device in state.devices.items():
        kids.add(kid)
        points.update((device.sign, device.agree))
    members.update(state.members)
    return Earlier(frozenset(kids), frozenset(points), frozenset(members))


def authority_person(act, text, node, roles, vitni):
    """The person whose receipt `text` (read as `act`) counts as authority at the node H of the previous epoch,
    or None: a clean device of the state at H, its person holding one of `roles`, vitni `ok` and a low S.
    The one rule of GP-19, used by the fold here and by `admit` to choose which receipts to keep."""
    device = node.state.devices.get(act.kid)
    if device is None or not tree.clean(node, act.kid):
        return None
    if node.state.members.get(device.person) not in roles:
        return None
    keys = {device.person: {act.kid: verifier.key_entry({"x": device.sign[0], "y": device.sign[1]}, "active")}}
    if vitni.verify(text, keys, act.method) == "ok" and verifier.is_low_s(act.signature):
        return device.person
    return None


def _authorized(doc, sigs, node, previous, original_org, reg, vitni):
    """GP-19: persons whose signature counts as authority for `doc` at the node H of the previous epoch."""
    doc_hash = genesis.doc_hash(doc)
    needed, roles = previous.rule("genesis.change")
    persons = set()
    for text in sigs:
        act = genesis_sigs.read(text, doc, doc_hash, original_org, reg)
        person = authority_person(act, text, node, roles, vitni) if act is not None else None
        if person is not None:
            persons.add(person)
    return len(persons) >= needed


def _check_carried(doc, node, pool):
    """GP-20: a device whose kid occurs in an earlier epoch must be active at H (`genesis_device_revoked`)
    and unchanged (`genesis_device_changed`). Being removed in the closing state of an earlier epoch
    needs no test of its own: such a kid is in no later document (it would be refused here) and no later
    act introduces it (FO-07), so it is never in the state at H."""
    carried = [entry for entry in doc["devices"] if entry["kid"] in pool.kids]
    for entry in carried:
        device = node.state.devices.get(entry["kid"])
        if device is None or device.status != "active":
            raise Refused("genesis_device_revoked")
    for entry in carried:
        device = node.state.devices[entry["kid"]]
        same = (device.person == entry["person"] and device.cls == entry["class"]
                and device.label == entry["label"] and device.sign == point(entry["sign"])
                and device.agree == point(entry["agree"]))
        if not same:
            raise Refused("genesis_device_changed")


def _check_change(doc, sigs, previous, original_org, earlier, reg, vitni):
    """GP-15 steps 7 to 9 for the change `doc` against the epoch before it. Returns the pool for the
    new epoch."""
    previous.build()
    node = previous.nodes.get(doc["head"])
    if node is None:
        raise Refused("genesis_head_unknown")
    pool = _extend(earlier, previous.doc, node.state)
    if not _authorized(doc, sigs, node, previous, original_org, reg, vitni):
        raise Refused("genesis_change_unauthorized")
    _check_carried(doc, node, pool)
    return pool


def fold_lineage(lineage, acts, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The epochs of `lineage` (a list of `{doc, sigs}`) over the bag of act texts `acts`, or raise
    Refused with the first failure in GP-15 order. A verifier that cannot answer raises
    VerifierUnavailable."""
    vitni = verifier.Memoized(vitni)
    bag = chain.Bag(acts, reg)
    ctx = genesis.Context(reg, profiles, allow_fixture)
    cursor = Cursor()
    epochs, pool = [], NO_EARLIER
    for entry in lineage:
        doc, sigs = entry["doc"], entry["sigs"]
        previous_doc = cursor.previous
        kind = cursor.structure(doc, ctx)
        render_size(doc, previous_doc)
        genesis_sigs.check_possession(doc, sigs, cursor.original_org, reg, vitni)
        if epochs:
            pool = _check_change(doc, sigs, epochs[-1], cursor.original_org, pool, reg, vitni)
        epochs.append(Epoch(doc, bag, reg, profiles, vitni, kind == "fixture", pool))
    return epochs
