"""`chain.resolve`: applicable, effective override entries, current (FO-25).

A resolve X at a fork parent P has body `{candidates, choose, heads, overrides}`. It is
**applicable** (validity, past cone only) iff its candidates are children of P, its heads are valid
primaries in losing subtrees that cover every losing candidate and are no ancestors of one another,
and its counted signatures meet the `chain.resolve` rule where a key counts only if it is in `S_P`
(FO-23) and is removed on no examined path. An `overrides` entry is **effective** iff the resolve it
names is applicable, hangs at P or on X's examined paths, and the named endorsements plus that
resolve's primary count to its quorum. X is **current** iff (a) its candidates are exactly the
children of P, (b) every valid primary in a losing subtree lies on an examined path, and (c) every
applicable resolve it overturns at P or discards below is named by an effective entry. Only current
resolves rank children (fork.walk); the chosen subtree is never read.
"""
from collections import namedtuple

from . import bodies, chain, errors, quorum, tree

Applicable = namedtuple("Applicable", "group parent choose candidates losing examined removed primary endorsements")


class Resolves:
    """The resolves of one epoch, judged once each."""

    def __init__(self, epoch):
        self.epoch = epoch
        self._applicable = {}

    def at(self, node):
        """The applicable resolves whose parent is `node`."""
        found = []
        for group in self.epoch.bag.acts_at(node.id):
            if group.act.method == chain.RESOLVE:
                resolve = self.applicable(group, node)
                if resolve is not None:
                    found.append(resolve)
        return found

    def applicable(self, group, parent):
        key = group.act.id
        if key not in self._applicable:
            self._applicable[key] = self._judge(group, parent)
        return self._applicable[key]

    def _judge(self, group, parent):
        epoch, act = self.epoch, group.act
        if not chain.linked(act, parent):
            return None
        try:
            bodies.validate(act.method, act.body, epoch.profile.version.reg, epoch.fixture, epoch.roles)
        except errors.Refused:
            return None
        body = act.body
        children = {child.id for child in parent.children}
        if not set(body["candidates"]) <= children:
            return None
        losing = frozenset(body["candidates"]) - {body["choose"]}
        examined = self._examined(parent, losing, body["heads"])
        if examined is None:
            return None
        removed = tree.removed_kids(examined.values())
        found = quorum.verified_signatures(epoch, group, parent.state)
        if found is None:
            return None
        primary, endorsements = found
        signed = [primary] + list(endorsements.values())
        needed = epoch.rule("chain.resolve")[0]
        if len(quorum.counted_persons(epoch, "chain.resolve", parent.state, signed, removed)) < needed:
            return None
        return Applicable(group, parent, body["choose"], frozenset(body["candidates"]), losing, examined,
                          frozenset(removed), primary, endorsements)

    def _examined(self, parent, losing, head_ids):
        """`{id: node}` of the examined paths from `parent` (exclusive) to each head (inclusive), or None
        if the heads break FO-25: a head must be a losing candidate or a valid primary below one, every
        losing candidate needs a head, and no head is an ancestor of another."""
        heads = [self.epoch.nodes.get(head_id) for head_id in head_ids]
        if any(head is None or head is self.epoch.root for head in heads):
            return None
        covered, examined = set(), {}
        for head in heads:
            top = head
            while top.parent is not None and top.parent is not parent:
                top = top.parent
            if top.parent is not parent or top.id not in losing:
                return None
            covered.add(top.id)
            for node in tree.path_below(parent, head):
                examined[node.id] = node
        if covered != losing:
            return None
        for a in heads:
            for b in heads:
                if a is not b and tree.is_ancestor(a, b):
                    return None
        return examined

    def _by_id(self, resolve_id):
        group = self.epoch.bag.groups.get(resolve_id)
        parent = self.epoch.nodes.get(group.act.parent) if group is not None else None
        if group is None or group.act.method != chain.RESOLVE or parent is None:
            return None
        return self.applicable(group, parent)

    def _effective(self, x):
        """The ids of the resolves that effective entries of `x` name."""
        named = set()
        for entry in x.group.act.body["overrides"]:
            other = self._by_id(entry["resolve"])
            if other is None or not (other.parent is x.parent or other.parent.id in x.examined):
                continue
            if not set(entry["endorsements"]) <= set(other.endorsements):
                continue
            signed = [other.primary] + [other.endorsements[i] for i in entry["endorsements"]]
            if len(quorum.counted_persons(self.epoch, "chain.resolve", other.parent.state, signed,
                                          other.removed)) >= self.epoch.rule("chain.resolve")[0]:
                named.add(entry["resolve"])
        return named

    def current(self, x):
        """FO-25: is the applicable resolve `x` current?"""
        if x.candidates != {child.id for child in x.parent.children}:
            return False
        for candidate in x.losing:
            node = self.epoch.nodes[candidate]
            if any(below.id not in x.examined for below in [node] + tree.subtree(node)):
                return False
        required = {r.group.act.id for r in self.at(x.parent) if r.choose != x.choose}
        for node in x.examined.values():
            required.update(r.group.act.id for r in self.at(node))
        return required <= self._effective(x)

    def chosen(self, node):
        """The children of `node` that the current resolves at it choose."""
        return {x.choose for x in self.at(node) if self.current(x)}
