"""The resolve world of the admission tests: one organization (alice, bob, carol, two persons make a quorum), a fork at
the root with two children, a resolve R1 that chooses the first, and a resolve S that chooses the second and names R1
in an `overrides` entry together with the endorsement `e_alice` that R1 needs for that entry to count.

Nothing here calls an admission rule. A step is valid because of how it is built; `answer` is the fold's own."""
import itertools

from handsal_check import admit, fork, profiles, render_genesis

from .act_builder import memo
from .fold_world import World

PROFILES = profiles.load()
ALL = ("alice", "bob", "carol")
AB = ("alice", "bob")
LOW = b"\x02" * 64   # another low-S signature over one payload: a twin of one receipt id


def item_of(step, *extra, sigs=None):
    """The item of the act group of `step`: its primary and, unless `sigs` says otherwise, every other act it holds,
    then `extra` texts."""
    return {"act": step.primary.jws, "sigs": (list(step.acts[1:]) if sigs is None else list(sigs)) + list(extra)}


def entries_of(pairs):
    """The `overrides` of a resolve naming each `(resolve step, [endorsement acts])` of `pairs`: sorted by resolve."""
    return sorted(({"endorsements": sorted(e.id for e in found), "resolve": step.id} for step, found in pairs),
                  key=lambda entry_: entry_["resolve"])


class Adm:
    """The world: `c1` and `c2` are the two children of the root; `r1` (bob signs, carol endorses) chooses `c1`; `s` (alice
    signs, bob endorses) chooses `c2` and names `r1` with `e_alice`; `e_bob` is a text that cannot complete `r1`
    (bob signed it)."""

    def __init__(self):
        self.w = w = World()
        self.docs = [{"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}]
        self.c1 = w.device_add("alice2", AB)
        self.c2 = w.device_add("alice3", ("alice", "carol"))
        self.r1 = w.resolve(("bob", "carol"), [self.c1, self.c2], self.c1, [self.c2])
        self.e_alice = w.endorse("alice", self.r1.primary, self.r1.parent_id)
        self.e_bob = w.endorse("bob", self.r1.primary, self.r1.parent_id, salt="bob-self")
        self.s = self.over([(self.r1, [self.e_alice])], "")
        self.names = {self.c1.id: "c1", self.c2.id: "c2"}

    # ---- steps
    def minimal(self, step):
        """The offer of `step` as the publisher of the primary sends it: its own endorsements only."""
        return item_of(step)

    def over(self, pairs, salt="x", choose=None, signers=AB):
        """A resolve at the root that chooses `c2` (or `choose`) and names each `(resolve step, [endorsements])`."""
        choose = self.c2 if choose is None else choose
        losing = self.c1 if choose is self.c2 else self.c2
        return self.w.resolve(signers, [self.c1, self.c2], choose, [losing], overrides=entries_of(pairs), salt=salt)

    def resolve_at_root(self, salt, signers=("bob", "carol")):
        """Another resolve choosing `c1`, applicable like `r1`."""
        return self.w.resolve(signers, [self.c1, self.c2], self.c1, [self.c2], salt=salt)

    def base(self):
        return [item_of(self.c1), item_of(self.c2)]

    # ---- the call
    def snap(self, acts):
        return {"acts": sorted(set(acts)), "docs": self.docs, "org": self.w.id}

    def admit(self, acts, item, vitni=None, allow_fixture=True):
        inp = admit.parse_input(dict(self.snap(acts), item=item))
        return admit.run(inp, PROFILES, allow_fixture, memo(vitni), render_genesis.render_size)

    def reason(self, acts, item, vitni=None):
        return self.admit(acts, item, vitni)["reason"]

    def stored(self, *offers):
        """The strings of a store after `offers` were offered in turn, one pass, and the reason of each."""
        acts, reasons = [], []
        for item in offers:
            got = self.admit(acts, item)
            reasons.append(got["reason"])
            if got["reason"] == "ok":
                acts = sorted(set(acts) | {got["store"]["act"], *got["store"]["sigs"]})
        return acts, reasons

    def retried(self, offers):
        """Every offer in order, each refused one again after any success, until nothing is new: an honest publisher
        that answers a refusal by publishing again."""
        acts, waiting, progress = [], list(offers), True
        while progress:
            progress, rest = False, []
            for item in waiting:
                got = self.admit(acts, item)
                if got["reason"] == "ok":
                    acts = sorted(set(acts) | {got["store"]["act"], *got["store"]["sigs"]})
                    progress = True
                elif got["reason"] != "already_stored":
                    rest.append(item)
            waiting = rest
        return acts

    def answer(self, acts):
        """The fold's answer over `acts`: `("chain", ["c2"])` or `("fork", [candidates])`, named as the world names."""
        walked = fork.walk(self.w.epoch(*acts))
        if walked.fork:
            return "fork", sorted(self.names.get(c, c[:6]) for c in walked.fork.candidates)
        return "chain", [self.names.get(n.id, n.id[:6]) for n in walked.chain][1:]

    def every_order(self, offers):
        """`{(answer, store): count}` over every order of `offers`, each run until nothing is new."""
        found = {}
        for perm in itertools.permutations(range(len(offers))):
            acts = tuple(self.retried([offers[i] for i in perm]))
            key = (self.answer(list(acts)), acts)
            found[key] = found.get(key, 0) + 1
        return found
