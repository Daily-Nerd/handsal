"""One epoch: a genesis document and the act tree rooted at it (FO-04 to FO-06, FO-21, FO-26).

An `Epoch` holds what every rule of the fold reads: the document and its policy, the bag of acts, the
registry and profiles, one memoized verifier, and the keys that earlier epochs used. `build` grows
the act tree from the root: a primary becomes a child of its parent node iff it is valid against the
state there (`quorum.check_primary`). Only acts that reach a node are ever examined, so junk costs
nothing. Resolves, endorsements and invalid acts are never nodes. The tree depends only on the bag
and the document: no fork rule, no resolve and no later act changes which primaries are valid
(validity is permanent, section 6).

`Earlier` is what earlier lineage epochs used, for FO-07, FO-22 and GP-20: kids, key points and member
ids of each earlier document and of its state at the head that closed it.
"""
from collections import namedtuple

from . import chain, genesis, quorum, verifier
from .state import State
from .tree import Node

Earlier = namedtuple("Earlier", "kids points members")
NO_EARLIER = Earlier(frozenset(), frozenset(), frozenset())


class Epoch:
    def __init__(self, doc, bag, profile, vitni, earlier=NO_EARLIER):
        self.doc, self.bag, self.profile = doc, bag, profile
        self.earlier = earlier
        self.vitni = verifier.call_memo(vitni)
        self.policy = doc["policy"]
        self.roles = self.policy["roles"]
        self.accepted_classes = frozenset(entry["class"] for entry in self.policy["classes"])
        self.holder_roles = frozenset(role for rule in self.policy["rules"].values() for role in rule["roles"])
        witness = self.policy["witness"]
        self.relay = None
        if witness["mode"] == "relay":
            jwk = witness["relay_pub_jwk"]
            self.relay = (witness["relay_kid"], (jwk["x"], jwk["y"]))
        self.root = Node(genesis.doc_hash(doc), None, None, None, State.from_document(doc, self.accepted_classes))
        self.nodes = {self.root.id: self.root}
        self._built = False

    @property
    def fixture(self):
        """True under a fixture profile: the one fact of the document's profile that the act rules read."""
        return self.profile.fixture

    def rule(self, name):
        """`(persons, roles)` of the policy rule `name`: Q as an int and the set of roles."""
        rule = self.policy["rules"][name]
        return int(rule["persons"]), frozenset(rule["roles"])

    def build(self):
        """Grow the act tree from the root. Idempotent."""
        if self._built:
            return
        stack = [self.root]
        while stack:
            node = stack.pop()
            for group in self.bag.acts_at(node.id):
                if group.act.method not in chain.PRIMARIES:
                    continue
                state = quorum.check_primary(self, group, node)
                if state is None:
                    continue
                child = Node(group.act.id, node, group.act.performer, group.act, state)
                node.children.append(child)
                self.nodes[child.id] = child
                stack.append(child)
        self._built = True
