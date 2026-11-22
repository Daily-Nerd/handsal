"""The named organizations the `sync` tests run over (CF-09, CF-13).

One production organization (alice, bob, carol, Q = 2), its original document D1, and the acts and change documents
that the refusal rule, the retained set and the source duties of `sync` are tested on. Each world is built once, on
first use, from the organization of a `Scenario`:

  `wsync`  the removal world. c1 adds alice2; rm removes alice's key at c1 (a primary and its endorsement).
           A reader that stores c1 but not rm still answers `ok` to alice at c1, which is the loss to prevent.
  `wsib`   the sibling world. Change C1 at head c1 and change C0 at the root are both successors of D1, each with
           its own epoch of acts; a reader pinned at C1 holds C0's nodes only as an off-lineage cache.
  `wdesc`  descendants of the original: D2 at head c1 with acts x2, y2; D3 at head x2 with act x3.
  `wpin`   a change DH at head a, with the sibling acts f (beside the path) and g (child of f) in the epoch of D1.
  `wforeign`  direct successors of D1 under an edition no catalog lists.

`pinned_at(doc)` is the probe of a machine whose pin names `doc`.
"""
import random
from functools import cached_property

from handsal_check import encoding, genesis

from . import store_world as SW
from .act_builder import head_of
from .checkact_world import probe_for
from .genesis_fixtures import change, policy
from .profile_sets import production_of
from .store_world import AB, later_world
from .test_enrolled import FIXTURE

THREE = ("alice", "bob", "carol")
UNKNOWN = encoding.hashstr(b"an edition this release does not implement")
NO_NODE = encoding.hashstr(b"no node of this epoch")


class SyncWorlds:
    """The worlds above over the organization of the `Scenario` `s`."""

    def __init__(self, s):
        self.s, self.w = s, s.w

    @property
    def docs(self):
        """The `docs` of a snapshot that holds only the original, D1."""
        return self.s.lineage

    def doc_at(self, head, prev=None, profile=None, name="NEXT", signers=THREE):
        """`(doc, entry)`: a change of the organization at `head`, after `prev` (default the original), receipts
        by `signers`."""
        doc = change(profile or production_of(FIXTURE), self.w.id, prev or genesis.doc_hash(self.w.doc), head,
                     people=THREE, pol=policy(), name=name)
        return doc, {"doc": doc, "sigs": self.w.sigs(doc, signers)}

    def pinned_at(self, doc):
        """The wire object of the pin that names `doc`."""
        return probe_for(doc, self.w.id)

    def epoch_of(self, doc):
        """A world whose acts hang at `doc`, with the profile of `doc`."""
        later = later_world(self.w, doc)
        later.profile = doc["profile"]
        return later

    # ---- the removal world
    @cached_property
    def c1(self):
        return self.w.device_add("alice2", AB)

    @cached_property
    def rm(self):
        return self.w.device_remove("alice", ("bob", "carol"), self.c1)

    def alice_at_rm(self):
        """The verdict by alice at the head the removal made: `revoked_key` once the removal is stored."""
        return self.s.verdict(head=head_of(self.rm.id))

    # ---- descendants of the original
    @cached_property
    def d2(self):
        return self.doc_at(self.c1.id, name="D2")

    @cached_property
    def w2(self):
        return self.epoch_of(self.d2[0])

    @cached_property
    def x2(self):
        return self.w2.device_add("alice4", AB)

    @cached_property
    def y2(self):
        return self.w2.device_add("bob3", AB, self.x2)

    @cached_property
    def d3(self):
        return self.doc_at(self.x2.id, prev=genesis.doc_hash(self.d2[0]), name="D3")

    @cached_property
    def x3(self):
        return self.epoch_of(self.d3[0]).device_add("bob3", AB)

    @cached_property
    def thin_d2(self):
        """D2 with one receipt of its three."""
        return {"doc": self.d2[0], "sigs": self.d2[1]["sigs"][:1]}

    # ---- a change at a node of the original epoch, and acts beside the path to it
    @cached_property
    def a(self):
        return self.w.device_add("bob2", AB)

    @cached_property
    def f(self):
        return self.w.device_add("carol2", ("alice", "carol"))

    @cached_property
    def g(self):
        return self.w.device_add("dave2", ("alice", "carol"), self.f)

    @cached_property
    def dh(self):
        return self.doc_at(self.a.id, name="AT-A")

    @cached_property
    def h_act(self):
        return self.epoch_of(self.dh[0]).device_add("alice3", AB)

    # ---- the sibling world
    @cached_property
    def c1_doc(self):
        return self.doc_at(self.c1.id, name="C1")

    @cached_property
    def c0_doc(self):
        return self.doc_at(self.w.id, name="C0")

    @cached_property
    def w0(self):
        return self.epoch_of(self.c0_doc[0])

    @cached_property
    def x0(self):
        return self.w0.device_add("alice4", AB)

    @cached_property
    def y0(self):
        return self.w0.device_add("bob3", AB, self.x0)

    @cached_property
    def z0(self):
        return self.w0.device_add("alice3", AB, self.y0)

    @property
    def sib_docs(self):
        return self.docs + [self.c1_doc[1], self.c0_doc[1]]

    # ---- a sibling admitted after a reader dropped its head
    @cached_property
    def beside(self):
        """A node of the original epoch beside c1 (not on the path to it)."""
        return self.w.device_add("bob2", AB)

    @cached_property
    def late_doc(self):
        """A successor of D1 at head `beside`, the head a reader pinned at C1 drops as off the path to c1."""
        return self.doc_at(self.beside.id, name="C0L")

    @cached_property
    def late_world(self):
        return self.epoch_of(self.late_doc[0])

    @cached_property
    def lx(self):
        return self.late_world.device_add("alice4", AB)

    @cached_property
    def ly(self):
        return self.late_world.device_add("bob3", AB, self.lx)

    @cached_property
    def lz(self):
        return self.late_world.device_add("alice3", AB, self.ly)

    # ---- forged documents: signed by one person, below the quorum
    @cached_property
    def forged_off(self):
        """`(doc, entry, act)`: a successor of D1 at the root signed by alice only, with an act below it."""
        doc, entry = self.doc_at(self.w.id, name="FORGED-OFF", signers=("alice",))
        return doc, entry, self.epoch_of(doc).device_add("alice4", AB)

    @cached_property
    def forged_descendant(self):
        """`(doc, entry, act)`: a successor of C1 at head c1 signed by alice only, with an act below it."""
        doc, entry = self.doc_at(self.c1.id, prev=genesis.doc_hash(self.c1_doc[0]), name="FORGED-DESC", signers=("alice",))
        return doc, entry, self.epoch_of(doc).device_add("alice4", AB)

    # ---- foreign successors
    @cached_property
    def foreign(self):
        """A successor of D1 at head c1 under an edition no catalog lists, signed by all three."""
        return self.doc_at(self.c1.id, profile=UNKNOWN, name="F")

    @cached_property
    def foreign_random_head(self):
        """The same shape at a head that is no node of the epoch."""
        return self.doc_at(NO_NODE, profile=UNKNOWN, name="FB")


def sibling_store(seed, profile=None):
    """`store_world.Store` of an organization whose original has three sibling changes at random heads (GP-21 allows
    them; `compact` keeps each), each grown, and below each a second-level change with probability 0.6. Its own
    random stream, so it never moves a seed of `random_store`."""
    rng = random.Random(seed * 104729 + 17)
    w = SW.World(profile=profile)
    docs = [SW.entry(w.doc, w.sigs(w.doc, SW.ALL))]
    acts, valid = SW.grow(w, rng, SW.POOLS[0], rng.randint(4, 12), SW.MEMBERS[0])
    ids = [w.id] + [step.id for step in valid]
    for i in range(3):
        doc = w.change_doc(rng.choice(ids[:1 + len(valid)]), name="S%d" % i)
        docs.append(SW.entry(doc, w.sigs(doc, SW.ALL)))
        w1 = SW.later_world(w, doc)
        more, valid1 = SW.grow(w1, rng, SW.POOLS[1], rng.randint(2, 7), SW.MEMBERS[1])
        acts += more
        ids += [w1.id] + [step.id for step in valid1]
        if rng.random() < 0.6:
            head = rng.choice([w1.id] + [step.id for step in valid1])
            doc2 = change(w.profile, w.org, genesis.doc_hash(doc), head, people=SW.ALL, pol=policy(), name="T%d" % i)
            docs.append(SW.entry(doc2, w.sigs(doc2, SW.ALL)))
            w2 = SW.later_world(w, doc2)
            more, valid2 = SW.grow(w2, rng, SW.POOLS[2], rng.randint(1, 4), SW.MEMBERS[2])
            acts += more
            ids += [w2.id] + [step.id for step in valid2]
    acts += ["junk", "", "a.b.c"] + w.sigs(w.doc, ("alice",))
    return SW.Store(acts, docs, w.org, ids)
