"""Children, fork and refreeze: the walk of the accepted chain (FO-24).

The accepted chain is walked from the root. At a node with no child the chain ends (the tip); with
one child that child is next; with two or more, the resolves current at the node decide: none leave a fork
(candidates: the children); the current resolves choose one child, and it is the next node. Two current
resolves never choose different children, so the walk raises if it meets that. The walk is recomputed from the
whole tree on every call, so a new valid primary that a resolve did not examine turns the node back
into a fork, and no act signed by fewer than Q persons has any effect.
"""
from collections import namedtuple

from . import resolve

Fork = namedtuple("Fork", "parent candidates")      # candidates: sorted receipt ids
Walk = namedtuple("Walk", "chain fork")             # chain: accepted nodes from the root; fork: Fork or None


def walk(epoch):
    resolves = resolve.Resolves(epoch)
    node = epoch.root
    accepted = [node]
    while node.children:
        if len(node.children) == 1:
            node = node.children[0]
        else:
            chosen = resolves.chosen(node)
            if len(chosen) > 1:
                raise RuntimeError("two current resolves choose different children")   # impossible (FO-24)
            if not chosen:
                return Walk(accepted, Fork(node, sorted(child.id for child in node.children)))
            node = epoch.nodes[next(iter(chosen))]
        accepted.append(node)
    return Walk(accepted, None)
