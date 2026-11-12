"""The act tree: nodes, paths and the past cone (FO-24, FO-26).

A `Node` is the root of an epoch (id hashstr(document), position 0) or a valid chain primary. It
holds the `State` after it; resolves and endorsements are never nodes. A node's parent and children
are the only links, so a path, an ancestor test and the nodes of a subtree are walks over them.
Cleanliness is read from the state of a node and from the removals on a path, nowhere else.
"""
DEVICE_REMOVE = "local:handsal.device.remove"


class Node:
    __slots__ = ("id", "parent", "performer", "act", "state", "n", "children")

    def __init__(self, node_id, parent, performer, act, state):
        self.id = node_id
        self.parent = parent
        self.performer = performer      # performer_id of the primary; None for the root
        self.act = act                  # the ParsedAct; None for the root
        self.state = state
        self.n = 0 if parent is None else parent.n + 1
        self.children = []


def path_from_root(node):
    """The nodes from the root to `node`, both included."""
    out = []
    while node is not None:
        out.append(node)
        node = node.parent
    return out[::-1]


def positions(node):
    """The ids of the accepted chain up to `node`: what a view, a head or a witness tip is compared with."""
    return frozenset(item.id for item in path_from_root(node))


def is_ancestor(ancestor, node):
    """True iff `ancestor` is `node` or lies on the path from the root to it."""
    while node is not None:
        if node is ancestor:
            return True
        node = node.parent
    return False


def path_below(top, node):
    """The nodes after `top` down to `node` inclusive (the examined path of FO-25), or None when
    `node` is not below `top`."""
    out = []
    while node is not None and node is not top:
        out.append(node)
        node = node.parent
    return out[::-1] if node is top else None


def subtree(node):
    """Every node below `node`, `node` excluded."""
    out, stack = [], list(node.children)
    while stack:
        item = stack.pop()
        out.append(item)
        stack.extend(item.children)
    return out


def removed_kids(nodes):
    """The kids that a `device.remove` among `nodes` removes: the keys that are not clean on that path."""
    return {node.act.body["kid"] for node in nodes if node.act is not None and node.act.method == DEVICE_REMOVE}


def clean(node, kid):
    """clean(k, H) (GP-19, FO-26): `kid` is active and accepted in the state at `node`. Nothing after
    or beside `node` is read."""
    device = node.state.devices.get(kid)
    return device is not None and device.status == "active" and device.accepted
