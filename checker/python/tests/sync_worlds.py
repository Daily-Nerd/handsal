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

from handsal_check import chain, encoding, errors, genesis, retain

from . import store_world as SW
from . import v042_tree
from .act_builder import head_of
from .checkact_world import probe_for
from .genesis_fixtures import change, policy
from .store_world import AB, later_world

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
        by `signers`, naming the edition of the original unless `profile` says another."""
        doc = change(profile or self.w.doc["profile"], self.w.id, prev or genesis.doc_hash(self.w.doc), head,
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


def _opens(acts, docs, org):
    """Whether the store of `acts` and `docs` is a lineage the checker opens."""
    try:
        SW.opened(SW.snap_of(acts, docs, org))
    except errors.Refused:
        return False
    return True


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
            # a step of a grown epoch is valid under the state at the root of its own epoch, which a change at a later
            # head can make invalid (a member added twice): the head is a node only if the store opens, so try the
            # steps in a drawn order, the root of the epoch last (it always is a node). Growing the epoch from the
            # state the fold has at the change's head would draw no discarded store, but `grow` builds its acts for a
            # world that starts at the original's state and takes no other: a state-carrying world is a rewrite of
            # `grow` and of `later_world`, which `random_store` shares, so the filter asks the checker instead
            heads = [step.id for step in valid1]
            rng.shuffle(heads)
            for head in heads + [w1.id]:
                doc2 = change(w.profile, w.org, genesis.doc_hash(doc), head, people=SW.ALL, pol=policy(), name="T%d" % i)
                if head == w1.id or _opens(acts, docs + [SW.entry(doc2, w.sigs(doc2, SW.ALL))], w.org):
                    break
            docs.append(SW.entry(doc2, w.sigs(doc2, SW.ALL)))
            w2 = SW.later_world(w, doc2)
            more, valid2 = SW.grow(w2, rng, SW.POOLS[2], rng.randint(1, 4), SW.MEMBERS[2])
            acts += more
            ids += [w2.id] + [step.id for step in valid2]
    acts += ["junk", "", "a.b.c"] + w.sigs(w.doc, ("alice",))
    return SW.Store(acts, docs, w.org, ids)


# ---- what a reader reads, by the last release

TAG = "v0.4.2"


def _release(name):
    """The module `name` of the package at the last release."""
    return v042_tree.module(v042_tree.load(TAG), name)


def release_profiles():
    """The editions of the last release with no fixture kid, as the production table builds them."""
    profiles = _release("profiles")
    return profiles.ProfileSet([profiles.Edition(profiles.Version(v.position, v.label, v.reg, frozenset()), production, fixture)
                                for v, production, fixture in profiles.load().editions()])


def read_oracle(acts, docs, pin_doc, org):
    """READ: the texts a fresh reader pinned at `pin_doc` reads, now or after a re-pin, given every string of `acts` and
    `docs` at once (CF-14 over what is offered), computed by the package of the last release so that it does not depend
    on the tree under test. None if the path to the pin does not fold."""
    sync_, retain_, epoch_, snapshot_ = (_release(name) for name in ("sync", "retain", "epoch", "snapshot"))
    errors_, verifier_, render_ = _release("errors"), _release("verifier"), _release("render_genesis")
    inp = sync_.parse_input({"acts": sorted(set(acts)), "docs": docs, "org": org})
    index = snapshot_.by_hash(inp)
    path = snapshot_.path_to(index, genesis.doc_hash(pin_doc))
    if not path:
        return None
    from .act_builder import FakeVitni
    try:
        tip = epoch_.Lineage.empty(list(inp.acts), release_profiles(), False, verifier_.Memoized(FakeVitni()),
                                   render_.render_size).extend_all(path)
    except errors_.Refused:
        return None
    epochs = tip.epochs()
    below, _ = sync_._descendants(index, genesis.doc_hash(path[-1]["doc"]), tip)
    anchors = {genesis.doc_hash(entry["doc"]): found for entry, found in zip(path, epochs)}
    entries = {genesis.doc_hash(entry["doc"]): entry for entry in path}
    for key, (entry, found) in below.items():
        anchors[key], entries[key] = found, entry
    everything = snapshot_.Snapshot(list(inp.acts), [entries[key] for key in sorted(entries)], org)
    return frozenset(retain_.retained(anchors, retain_.closing_heads(path), everything).acts)


def position(documents, pin_doc, root):
    """Where the document `root` sits for a reader pinned at `pin_doc`, among `documents` (`{hash: doc}`): "cone" (the
    pin or below it), "path" (an ancestor of the pin), "off" (elsewhere), "none" (no document of `documents`)."""
    pin = genesis.doc_hash(pin_doc)
    if root not in documents:
        return "none"
    at = root
    while at is not None:
        if at == pin:
            return "cone"
        at = documents[at].get("prev")
    at = pin
    while at is not None:
        if at == root:
            return "path"
        at = documents[at].get("prev")
    return "off"


def parsed(texts, org, wire):
    """`{receipt id: act}` of the strings of `texts` that read as acts of the organization `org`."""
    return {act.id: act for act in (chain.read(text, wire, org) for text in texts) if act is not None}


def admit_closed(snap):
    """The store a relay holds for the strings of `snap`: every node and every applicable resolve of every epoch with the
    signatures that count, nothing pending and nothing whose parent is no node, every document whole."""
    kept = retain.retained(SW.opened(snap), {}, snap)
    docs = [{"doc": e["doc"], "sigs": sorted(kept.receipts[genesis.doc_hash(e["doc"])])} for e in snap.docs]
    return SW.snap_of(sorted(kept.acts), docs, snap.org)


def dependents_first(snap, texts):
    """`texts` (strings of `snap`) in the order a relay may delete them: a string only after every listed string whose
    `parent` is its receipt id."""
    acts = {act.jws: act for act in (chain.read(text, SW.REG.wire, snap.org) for text in texts) if act is not None}
    depth = {}

    def below(text):
        if text not in depth:
            depth[text] = 1 + max([below(other) for other, act in acts.items() if act.parent == acts[text].id], default=-1)
        return depth[text]

    return sorted(texts, key=lambda text: (below(text) if text in acts else 0, text))
