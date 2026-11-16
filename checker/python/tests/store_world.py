"""Stores for the retention tests (CF-14): an organization over several epochs as the snapshot of CF-13.

A second-level change is either signed by the persons it names, or hands the organization over: bob leaves it and
signs for authority only, so a receipt that counts for authority and not for possession is in the store.
`grow` builds a random act tree in one epoch (valid children, forks, resolves, and everything a store may hold that
no reader reads: pending primaries, unanchored acts, strangers' endorsements, twins), `random_store` puts epochs
and sibling changes around it. Nothing here calls a checker rule: an act is valid because of how it is built, and
the property tests of `test_retain` ask the checker whether the answers change. All of it is seeded, so a failing
store is reproduced by its seed.
"""
import random
from collections import namedtuple

from handsal_check import admit, encoding, genesis, profiles, registry, render_genesis, retain, snapshot, verifier

from .act_builder import BAD, HIGH, FakeVitni, genesis_sign, with_signature
from .fold_world import World
from .genesis_fixtures import change, device, policy
from .profile_sets import without_fixture_kids

REG = registry.load()
PROFILES = profiles.load()
PRODUCTION_ONLY = without_fixture_kids(profiles.load())   # no kid is a fixture kid: the fixture keys sign a production document
ALL = ("alice", "bob", "carol")
AB = ("alice", "bob")
PAIRS = (AB, ("alice", "carol"), ("bob", "carol"))
LOW = b"\x02" * 64   # a second low-S signature over one payload: a twin of one receipt id
POOLS = (("alice2", "alice3", "bob2", "carol2", "dave2"), ("alice4", "bob3", "frank", "grace"), ("X1", "X2"))
MEMBERS = (("frank", "grace"), ("frank", "grace"), ())   # member names per epoch: a key may come back in a later epoch
KINDS = ("add", "remove", "pending", "stranger", "twin", "bad twin", "high twin", "orphan", "member")
WEIGHTS = (46, 10, 8, 6, 8, 5, 4, 6, 8)

Orphan = namedtuple("Orphan", "id performer")
Store = namedtuple("Store", "acts docs org ids")   # `ids`: every node id the store was built with, for heads


class Counting:
    """A verifier that counts the questions that reach it: the structural measure of cost (design risk 6)."""

    def __init__(self):
        self.inner, self.calls = FakeVitni(), 0

    def verify(self, jws, keys, method):
        self.calls += 1
        return self.inner.verify(jws, keys, method)


def entry(doc, sigs):
    return {"doc": doc, "sigs": list(sigs)}


def snap_of(acts, docs, org):
    """The `Snapshot` of CF-13 for these acts and document entries."""
    return snapshot.parse({"acts": list(acts), "docs": list(docs), "org": org})[0]


def opened(snap, vitni=None):
    """`{document hash: Epoch}` of the store `snap`, as `admit` and `compact` open it."""
    return admit.open_store(snap, REG, PRODUCTION_ONLY, True, verifier.Memoized(vitni or FakeVitni()),
                            render_genesis.render_size)


def retained_of(snap, vitni=None):
    """The `Retained` of the whole store `snap` (every document in it, closing from the documents)."""
    return retain.retained(opened(snap, vitni), retain.closing_heads(snap.docs), snap)


def after(snap, acts_gone=(), sigs_gone=()):
    """The snapshot with the strings `acts_gone` removed from `acts` and `sigs_gone` from every document's `sigs`."""
    gone, off = set(acts_gone), set(sigs_gone)
    docs = [{"doc": e["doc"], "sigs": [s for s in e["sigs"] if s not in off]} for e in snap.docs]
    return snap_of([a for a in snap.acts if a not in gone], docs, snap.org)


def compacted(snap, vitni=None):
    """The store `snap` after one full compaction."""
    return after(snap, *retain.dropped(snap, retained_of(snap, vitni)))


def later_world(root, doc):
    """A world whose acts hang at the change document `doc` of the organization of the world `root`."""
    w = World()
    w.doc, w.id, w.org, w.profile = doc, genesis.doc_hash(doc), root.org, root.profile
    return w


# ---- one epoch

def grow(w, rng, pool, steps, members=()):
    """`(acts, valid steps)`: a random act tree under the root of the world `w` (devices from `pool`, members from
    `members`), plus what a store may hold that no reader reads."""
    acts, valid, children = [], [], {}   # children: parent id -> its valid steps
    entries = [(None, {}, frozenset())]  # (parent step, {device name: person} on the path, removed names)

    def kids(parent):
        return children.setdefault(parent.id if parent else w.id, [])

    for _ in range(steps):
        parent, used, removed = rng.choice(entries)
        kind = rng.choices(KINDS, WEIGHTS)[0]
        signers = rng.choice(PAIRS)
        person = rng.choice(signers)
        free = [name for name in pool if name not in used]
        newcomers = [name for name in members if name not in used]
        if kind == "member" and newcomers:
            name = rng.choice(newcomers)
            step = w.member_add(name, signers, parent, role=rng.choice(("maintainer", "member")))
            entries.append((step, {**used, name: name}, removed))
        elif kind == "add" and free:
            name = rng.choice(free)
            step = w.device_add(name, signers, parent, person=person)
            entries.append((step, {**used, name: person}, removed))
        elif kind == "remove" and [name for name in used if name not in removed]:
            name = rng.choice([name for name in used if name not in removed])
            step = w.device_remove(name, signers, parent, person=used[name])
            entries.append((step, used, removed | {name}))
        elif kind == "pending" and free:
            acts += w.device_add(rng.choice(free), signers[:1], parent, person=person).acts   # one person: no quorum
            continue
        elif kind == "orphan" and free:
            nobody = Orphan(encoding.hashstr(b"orphan/%d" % rng.getrandbits(32)), "alice")
            acts += w.device_add(rng.choice(free), signers, nobody, person=person).acts
            continue
        elif kind in ("stranger", "twin", "bad twin", "high twin") and valid:
            step = rng.choice(valid)
            if kind == "stranger":
                acts.append(w.endorse("dave", step.primary, step.parent_id).jws)   # a key no state holds
            else:
                sig = {"twin": LOW, "bad twin": BAD, "high twin": HIGH}[kind]
                acts.append(with_signature(step.primary, sig).jws)
            continue
        else:
            continue
        acts += step.acts
        valid.append(step)
        kids(parent).append(step)
    for node in [None] + valid:
        found = kids(node)
        if len(found) >= 2 and rng.random() < 0.6:
            chosen = rng.choice(found)
            acts += w.resolve(AB, found, chosen, [c for c in found if c is not chosen], node).acts
    return acts, valid


# ---- a store

def random_store(seed, profile=None):
    """A store of one organization (under the profile `profile`, the fixture one by default) with up to two
    changes at random heads of epoch 0, a later epoch under each change and a second-level change, every epoch
    grown at random, and junk besides."""
    rng = random.Random(seed)
    w = World(profile=profile)
    docs = [entry(w.doc, w.sigs(w.doc, ALL))]
    acts, valid = grow(w, rng, POOLS[0], rng.randint(4, 12), MEMBERS[0])
    ids = [w.id] + [s.id for s in valid]
    for i in range(rng.randint(0, 2)):
        doc = w.change_doc(rng.choice(ids[:1 + len(valid)]), name="C%d" % i)
        # receipts: the counting ones, a stranger's, and a low-S twin of one of them (one receipt id)
        docs.append(entry(doc, w.sigs(doc, ALL) + w.sigs(doc, ("dave",)) + w.sigs(doc, ("alice",), sig=LOW)))
        if rng.random() < 0.8:
            w1 = later_world(w, doc)
            more, valid1 = grow(w1, rng, POOLS[1], rng.randint(2, 6), MEMBERS[1])
            acts += more
            ids += [w1.id] + [s.id for s in valid1]
            if rng.random() < 0.5:
                head = rng.choice([w1.id] + [s.id for s in valid1])
                handover = random.Random(seed * 7919 + i).random() < 0.5   # its own stream: the stores above stay what they were
                people, devices = (ALL, None) if not handover else (
                    ("alice", "dave", "zed"), [device("alice"), device("dave"), device("X1", person="zed")])
                doc2 = change(w.profile, w.org, genesis.doc_hash(doc), head, people=people, devices=devices,
                              pol=policy(), name="D%d" % i)
                # a handover: bob and carol leave the document, dave and zed enter it. The receipts of the three new
                # devices count for possession, alice's for both, and bob's for authority only: with alice's he makes
                # the two persons the change needs, so a store that lost his receipt would not be a lineage
                receipts = w.sigs(doc2, ("alice", "dave", "bob")) + [genesis_sign("X1", doc2, w.id, performer="zed").jws] \
                    if handover else w.sigs(doc2, ALL)
                docs.append(entry(doc2, receipts))
                w2 = later_world(w, doc2)
                more, valid2 = grow(w2, rng, POOLS[2], rng.randint(1, 4), MEMBERS[2])
                acts += more
                ids += [w2.id] + [s.id for s in valid2]
    acts += ["junk", "", "a.b.c"] + w.sigs(w.doc, ("alice",))   # strings no chain item, a receipt among the acts
    return Store(acts, docs, w.org, ids)
