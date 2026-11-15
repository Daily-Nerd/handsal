"""The bag of chain acts and the link rules (FO-04, FO-06, FO-08, FO-15, FO-21).

`Bag` reads every text once (`acts.parse`), keeps the chain acts and drops everything else: a text
that is junk, a non-chain act, a `genesis.sign`, an unknown method or a body that
breaks its closed schema is ignored without a reason (FO-06, FO-15). Texts of one receipt id are
one `Group` (ACT-12): they differ only by signature, and which one verifies is decided later,
against the right keys, so an invalid twin never shadows a valid one (FO-21).

The bag indexes what the fold asks for: the primaries and resolves by the position id they name as
their parent, and the endorsements by the act they endorse. It decides nothing about validity.
"""
from collections import namedtuple

from . import acts, errors

PRIMARIES = frozenset(("local:handsal.device.add", "local:handsal.device.remove", "local:handsal.member.add"))
RESOLVE = "local:handsal.chain.resolve"
ENDORSE = "local:handsal.act.endorse"
CHAIN_ACTS = PRIMARIES | {RESOLVE, ENDORSE}

Group = namedtuple("Group", "act copies")   # `copies`: the ParsedAct of every distinct text, one per signature


class Bag:
    def __init__(self, texts, reg):
        groups = {}
        for text in texts:
            try:
                act = acts.parse(text, reg, CHAIN_ACTS)
            except errors.Refused:
                continue
            found = groups.get(act.id)
            if found is None:
                groups[act.id] = Group(act, [act])
            elif all(copy.jws != act.jws for copy in found.copies):
                found.copies.append(act)
        self.groups = groups
        self._at = {}
        self._endorsing = {}
        for group in groups.values():
            act = group.act
            if act.method in PRIMARIES or act.method == RESOLVE:
                self._at.setdefault(act.parent, []).append(group)
            else:
                self._endorsing.setdefault(act.body["act"], []).append(group)

    def acts_at(self, position_id):
        """The primaries and resolves whose parent is the position `position_id`, in receipt id order."""
        return sorted(self._at.get(position_id, ()), key=lambda g: g.act.id)

    def endorsements_of(self, target):
        """The endorsements of the chain act `target` (a ParsedAct) that pass FO-08, in receipt id order.

        `parent_receipt_hash` and `body.act` are the target's id, `parent_performer_id` its performer,
        and `head` names the target's parent: the endorser saw the same state. Endorsements of
        endorsements and of unknown ids never meet a target, and any other head is ignored.
        """
        found = []
        for group in self._endorsing.get(target.id, ()):
            act = group.act
            if (act.parent == target.id and act.parent_performer == target.performer
                    and act.head == {"id": target.parent, "kind": "chain"}):
                found.append(group)
        return sorted(found, key=lambda g: g.act.id)


def linked(act, parent_node):
    """FO-04: `parent_performer_id` is null exactly when the parent is the root and the parent
    primary's `performer_id` otherwise. `acts_at` only offers an act at the node it names, so the
    parent id is already right. The cycle rule needs no code: a receipt id is a hash of its own
    parent, so no act can be its own ancestor."""
    expected = None if parent_node.parent is None else parent_node.performer
    return act.parent_performer == expected
