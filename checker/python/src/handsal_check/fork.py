"""Children, fork and refreeze: the walk of the accepted chain (FO-24).

The accepted chain is walked from the root. At a node with no child the chain ends (the tip); with
one child that child is next; with two or more, the resolves current at the node decide: none, or
resolves that choose different children, leave a fork (candidates: the children, or the distinct
chosen ids); resolves that all choose one child make it the next node. The walk is recomputed from the
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
            if len(chosen) == 1:
                node = epoch.nodes[next(iter(chosen))]
            else:
                candidates = chosen or {child.id for child in node.children}
                return Walk(accepted, Fork(node, sorted(candidates)))
        accepted.append(node)
    return Walk(accepted, None)
