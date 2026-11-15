"""The generator's own fold of a snapshot: the oracle of the whole-set guard (CF-06, CF-14).

A `compact` vector states a drop list. Nothing in the generator may take that list from the checker, so the
claim "this drop changes no answer" is proved here, by a second statement of the fold written from the spec
(FO-21 to FO-26, GP-15, GP-19) over the same signed strings. `Model` reads a CF-13 snapshot the way a reader
of the chain does, and `guard` asks it every question a drop could move: for every leaf document (a document
no other document names as `prev`, the pin a machine can hold) the answer over the whole input and over the
input without the drop must be the same line.

What it reads, and so what a guard can protect:
- a string counts if it is a JWS whose signature verifies under the fixture key of its header kid, low S
  (FO-21); of several valid copies of one receipt id the smallest text stands for all;
- a chain act counts only if its signed `org` is the organization's (GP-04, FO-06): a primary or resolve of
  another organization is no node and no resolve, and an endorsement of another organization counts for nothing;
- a chain primary is a node when it is of this organization, its parent is a node, and it is valid against
  the state at the parent (FO-22, FO-23 through lib/rules.py, the proof of possession of FO-07);
- a `chain.resolve` is applicable, current and effective as FO-25 says, so an override entry reads the
  endorsements it names;
- the accepted chain of the last epoch is walked as FO-24 says; the earlier epochs are read along the path
  to the head of the change that follows (GP-19, FO-24 is not applied there);
- a document needs a counting `genesis.sign` for every listed device (GP-15), and a change needs the
  authority of the previous policy at its head (GP-19).

What it does not read: the schema of an act body (ACT-09), vitni's own rules, classes, witnesses and pins. A
row whose answer rests on those is outside its scope, and `Unsupported` says so for a store it cannot judge.
"""
import json
from collections import defaultdict

from . import base, es256, forge, inputs, keys, rules, state

METHOD = "local:handsal."
ENDORSE = METHOD + "act.endorse"
GENESIS_SIGN = METHOD + "genesis.sign"
RESOLVE = METHOD + "chain.resolve"
PRIMARY = (METHOD + "device.add", METHOD + "device.remove", METHOD + "member.add")


class Unsupported(ValueError):
    """The snapshot asks the model something it does not state (a missing document, a lineage that is no chain)."""


class GuardError(AssertionError):
    """A drop changes an answer: the author's drop list contradicts the fold."""


class Act:
    """A JWS the model can read, with the fields every rule reads."""

    def __init__(self, jws, kid, raw, payload):
        obj = payload["ext"]["dev.handsal/act"]
        self.jws, self.kid = jws, kid
        self.id = base.hashstr(raw)
        self.method = payload["method"]
        self.parent = payload["parent_receipt_hash"]
        self.inputs_hash = payload["inputs_hash"]
        self.performer = payload["performer_id"]
        self.org, self.body, self.act_kid = obj["org"], obj["body"], obj.get("kid")
        head = obj.get("head")
        self.head = head.get("id") if isinstance(head, dict) else None


_PARSED = {}   # jws -> (Act, signing input, signature) or None: parsing is cheap, ECDSA is not
_VERIFIED = {}  # (jws, x, y) -> bool: ECDSA in pure Python costs 20 ms and the same strings recur in every row


def parse(jws):
    """The `Act` of `jws` with its signing input and signature, or None when it is no compact JWS of an act."""
    if jws not in _PARSED:
        try:
            header, raw, sig = forge.parts(jws)
            kid = json.loads(header)["kid"]
            _PARSED[jws] = (Act(jws, kid, raw, json.loads(raw)), jws.rsplit(".", 1)[0].encode("ascii"), sig)
        except (ValueError, KeyError, TypeError, AttributeError):
            _PARSED[jws] = None   # a string that is no chain item is ignored by the fold (FO-06, FO-15)
    return _PARSED[jws]


def _unb64u(text):
    return int.from_bytes(forge._unb64u(text), "big")


def public_keys(fx, docs):
    """{kid: (x, y)}: every fixture key and every device a document lists. A kid is the thumbprint of its key, so
    one kid names one key whichever document lists it."""
    out = {}
    for name in keys.DEVICES:
        key = fx.key(name)
        out[key.kid] = (key.x_int, key.y_int)
    for entry in docs:
        for d in entry["doc"]["devices"]:
            out[d["kid"]] = (_unb64u(d["sign"]["x"]), _unb64u(d["sign"]["y"]))
    return out


def decode(public, jws):
    """The `Act` of `jws` when it is a compact JWS of an act whose signature verifies under the key of its header
    kid, low S (FO-21), else None. `public` is `public_keys`."""
    parsed = parse(jws)
    if parsed is None or parsed[0].kid not in public:
        return None
    act, message, sig = parsed
    point = public[act.kid]
    if (jws, *point) not in _VERIFIED:
        _VERIFIED[(jws, *point)] = es256.verify(point, message, sig) and es256.is_low_s(sig)
    return act if _VERIFIED[(jws, *point)] else None


class Epoch:
    """The act tree of one epoch (FO-26) and the walk of its accepted chain (FO-24, FO-25)."""

    def __init__(self, model, doc, earlier):
        self.model = model
        self.doc = doc
        self.root = inputs.doc_id(doc)
        self.org = doc["org"] or self.root
        self.nodes = {self.root: state.State(doc)}   # node id -> state at the node
        self.parent = {}                             # node id -> parent id (the root has none)
        self.act = {}                                # node id -> its primary
        self.earlier = earlier                       # member ids of earlier lineage epochs (FO-22)
        self._grow()
        self.resolves = [a for a in model.acts.values()
                         if a.method == RESOLVE and a.org == self.org and a.parent in self.nodes]
        self._applicable = {}

    # ---- the act tree
    def _grow(self):
        pending = [a for a in self.model.acts.values() if a.method in PRIMARY and a.org == self.org]
        grew = True
        while grew:
            grew = False
            for a in pending:
                if a.id in self.nodes or a.parent not in self.nodes:
                    continue
                after = self._apply(a, self.nodes[a.parent])
                if after is not None:
                    self.nodes[a.id], self.parent[a.id], self.act[a.id] = after, a.parent, a
                    grew = True

    def _apply(self, a, st):
        """The state after primary `a` at a node of state `st`, or None when `a` is no valid primary (FO-22, FO-23)."""
        endorsers = self.model.endorsers(a)
        kids = [a.kid] + [e.kid for e in endorsers]
        pop = {e.kid for e in endorsers}
        try:
            after = st.snapshot()
            if a.method == METHOD + "device.add":
                entry = {k: a.body[k] for k in ("agree", "class", "kid", "label", "sign")}
                rules.device_add(st, a.body["person"], entry["class"], kids)
                if entry["kid"] not in pop:
                    return None   # FO-07: no proof of possession by the new key
                after.add_device(a.body["person"], entry)
            elif a.method == METHOD + "member.add":
                device = a.body["device"]
                rules.member_add(st, a.body["member"], a.body["role"], device["class"], kids, self.earlier)
                if device["kid"] not in pop:
                    return None
                after.add_member(a.body["member"], a.body["role"])
                after.add_device(a.body["member"], {k: device[k] for k in ("agree", "class", "kid", "label", "sign")})
            else:
                rules.device_remove(st, a.body["person"], a.body["kid"], kids)
                after.remove_device(a.body["kid"])
        except (rules.Refused, ValueError, KeyError, TypeError):
            return None   # not valid against S_P: no child, no node (FO-06, FO-24)
        after.advance(a.id)
        return after

    def children(self, node):
        return sorted(n for n, p in self.parent.items() if p == node)

    def subtree(self, node):
        out, todo = set(), [node]
        while todo:
            n = todo.pop()
            if n not in out:
                out.add(n)
                todo.extend(self.children(n))
        return out

    def path(self, top, bottom):
        """The nodes from `top` (exclusive) down to `bottom` (inclusive), or None when `bottom` is not below `top`."""
        out, at = [], bottom
        while at != top:
            if at not in self.parent:
                return None
            out.append(at)
            at = self.parent[at]
        return out

    # ---- chain.resolve (FO-25)
    def _removed(self, nodes):
        return {self.act[n].body["kid"] for n in nodes if self.act[n].method == METHOD + "device.remove"}

    def _examined(self, r):
        paths = [self.path(r.parent, h) for h in r.body["heads"]]
        return None if any(p is None for p in paths) else {n for p in paths for n in p}

    def _counted(self, st, rule, kids, banned=frozenset()):
        """FO-23: the persons of the keys active and accepted in `st` whose role the rule lists, bar `banned` kids."""
        listed = st.policy["rules"][rule]["roles"]
        out = set()
        for kid in kids:
            person = None if kid in banned else rules._live(st, kid)
            if person is not None and st.members[person] in listed:
                out.add(person)
        return out

    def _meets(self, r, kids, examined):
        """The counted signatures of resolve `r` meet its rule, the primary being live in S_P (FO-23, FO-25)."""
        st = self.nodes[r.parent]
        if rules._live(st, r.kid) is None:
            return False
        need = int(st.policy["rules"]["chain.resolve"]["persons"])
        return len(self._counted(st, "chain.resolve", kids, self._removed(examined))) >= need

    def applicable(self, r):
        if r.id not in self._applicable:
            self._applicable[r.id] = self._is_applicable(r)
        return self._applicable[r.id]

    def _is_applicable(self, r):
        try:
            body = r.body
            candidates, choose, heads = body["candidates"], body["choose"], body["heads"]
            children = set(self.children(r.parent))
            if not set(candidates) <= children or choose not in candidates:
                return False
            losing = [c for c in candidates if c != choose]
            subtrees = {c: self.subtree(c) for c in losing}
            if any(not any(h in s for h in heads) for s in subtrees.values()):
                return False
            if any(h not in set().union(*subtrees.values()) for h in heads):
                return False
            if any(a != b and b in self.subtree(a) for a in heads for b in heads):
                return False
            examined = self._examined(r)
        except (KeyError, TypeError):
            return False
        return examined is not None and self._meets(
            r, [r.kid] + [e.kid for e in self.model.endorsers(r)], examined)

    def _effective(self, x, entry, examined):
        try:
            r = next(a for a in self.resolves if a.id == entry["resolve"])
            if not self.applicable(r) or not (r.parent == x.parent or r.parent in examined):
                return False
            named = [self.model.acts.get(i) for i in entry["endorsements"]]
            valid = {e.id for e in self.model.endorsers(r)}
            if any(e is None or e.id not in valid for e in named):
                return False
            return self._meets(r, [r.kid] + [e.kid for e in named], self._examined(r))
        except (KeyError, TypeError, StopIteration):
            return False

    def current(self, x):
        if not self.applicable(x):
            return False
        examined = self._examined(x)
        children = set(self.children(x.parent))
        if set(x.body["candidates"]) != children:
            return False
        losing = [c for c in x.body["candidates"] if c != x.body["choose"]]
        if any(n not in examined for c in losing for n in self.subtree(c)):
            return False
        for r in self.resolves:
            if r.id == x.id or not self.applicable(r):
                continue
            owed = ((r.parent == x.parent and r.body["choose"] != x.body["choose"]) or r.parent in examined)
            if owed and not any(self._effective(x, e, examined) and e["resolve"] == r.id
                                for e in x.body["overrides"]):
                return False
        return True

    # ---- the accepted chain (FO-24)
    def walk(self):
        """The `fold` answer of this epoch: the state at the tip, or the fork."""
        at = self.root
        while True:
            kids = self.children(at)
            if len(kids) < 2:
                if not kids:
                    return state.anchor(self.nodes[at])
                at = kids[0]
                continue
            chosen = sorted({r.body["choose"] for r in self.resolves if r.parent == at and self.current(r)})
            if len(chosen) == 1:
                at = chosen[0]
            else:
                return state.fork_anchor(at, chosen or kids)


class Model:
    """A CF-13 snapshot read as the fold reads it: `acts` as signed strings, `docs` as `{doc, sigs}` entries."""

    def __init__(self, fx, acts, docs):
        self.public = public_keys(fx, docs)
        self.acts = {}   # receipt id -> the smallest valid text's act (FO-21)
        for jws in sorted(set(acts)):
            act = decode(self.public, jws)
            if act is not None and act.id not in self.acts:
                self.acts[act.id] = act
        self.docs = {}   # document hash -> [document, receipts]
        for entry in docs:
            slot = self.docs.setdefault(inputs.doc_id(entry["doc"]), [entry["doc"], set()])
            slot[1].update(entry["sigs"])
        self._by_target = defaultdict(list)
        for a in self.acts.values():
            if a.method == ENDORSE and isinstance(a.body, dict) and isinstance(a.body.get("act"), str):
                self._by_target[a.body["act"]].append(a)

    def endorsers(self, act):
        """The valid endorsements of `act`: `body.act` is the act, `head.id` its parent (FO-08, FO-23), and the
        endorsement names the organization of the act it endorses (GP-04, FO-06)."""
        return [e for e in self._by_target.get(act.id, ()) if e.head == act.parent and e.org == act.org]

    def leaves(self):
        named = {d["prev"] for d, _ in self.docs.values()}
        return sorted(h for h in self.docs if h not in named)

    def lineage(self, leaf):
        out, at = [], leaf
        while at is not None:
            if at not in self.docs:
                raise Unsupported("document %s is not in the snapshot" % at)
            doc = self.docs[at][0]
            out.append(doc)
            at = doc["prev"]
        return out[::-1]

    # ---- documents (GP-15, GP-19)
    def _receipts(self, doc, head):
        """The `genesis.sign` acts over `doc` that name `head` (a change) or none (an original), in the form ACT-13
        and ACT-14 give a receipt: no parent, an empty body, the act's `kid` the header kid."""
        did = inputs.doc_id(doc)
        out = []
        for jws in sorted(self.docs[did][1]):
            act = decode(self.public, jws)
            if (act is not None and act.method == GENESIS_SIGN and act.inputs_hash == did and act.head == head
                    and act.parent is None and act.body == {} and act.act_kid == act.kid):
                out.append(act)
        return out

    def _document_error(self, doc, closed):
        """The code `doc` earns from its receipts and, for a change, from the epoch it closes, else None."""
        head = doc["head"] if doc["prev"] is not None else None
        receipts = self._receipts(doc, head)
        signed = {a.kid for a in receipts if a.performer == next(
            (d["person"] for d in doc["devices"] if d["kid"] == a.kid), None)}
        if any(d["kid"] not in signed for d in doc["devices"]):
            return "genesis_unsigned"
        if closed is None:
            return None
        if head not in closed.nodes:
            return "genesis_head_unknown"
        st = closed.nodes[head]
        rule = st.policy["rules"]["genesis.change"]
        counted = {a.performer for a in receipts
                   if rules._live(st, a.kid) == a.performer and st.members[a.performer] in rule["roles"]}
        return None if len(counted) >= int(rule["persons"]) else "genesis_change_unauthorized"

    def answer(self, leaf):
        """The `fold` line for the lineage that ends at document `leaf`: a code of the lineage, the fork or the state."""
        epochs, earlier, closed = [], set(), None
        for doc in self.lineage(leaf):
            code = self._document_error(doc, closed)
            if code is not None:
                return inputs.error_anchor(code)
            if closed is not None:
                earlier |= set(closed.nodes[doc["head"]].members)
            earlier |= {m["id"] for m in doc["members"]}
            closed = Epoch(self, doc, set(earlier))
        return closed.walk()

    def answers(self):
        """{leaf document hash: fold line} for every leaf of the snapshot."""
        return {leaf: self.answer(leaf) for leaf in self.leaves()}


def without(snapshot, drop):
    """`snapshot` (`{acts, docs, org}`) minus a `drop` (`{acts, sigs}`): the store a deletion job leaves."""
    gone, sigs = set(drop["acts"]), set(drop["sigs"])
    return {"acts": [a for a in snapshot["acts"] if a not in gone],
            "docs": [{"doc": e["doc"], "sigs": [s for s in e["sigs"] if s not in sigs]} for e in snapshot["docs"]],
            "org": snapshot["org"]}


def guard(fx, snapshot, drop):
    """The whole-set guard: refuse a `drop` that changes any answer (CF-14).

    A drop names only strings of the snapshot (a name that matches nothing is an author's mistake), and for every
    leaf document the fold of the whole snapshot and of the snapshot without the drop are the same line.
    """
    held = set(snapshot["acts"]) | {s for e in snapshot["docs"] for s in e["sigs"]}
    stray = sorted((set(drop["acts"]) | set(drop["sigs"])) - held)
    if stray:
        raise GuardError("the drop names strings the snapshot does not hold: %d" % len(stray))
    whole = Model(fx, snapshot["acts"], snapshot["docs"]).answers()
    rest = without(snapshot, drop)
    kept = Model(fx, rest["acts"], rest["docs"]).answers()
    if whole != kept:
        moved = sorted(h for h in whole if whole[h] != kept.get(h))
        raise GuardError("the drop changes the answer for %s" % ", ".join(moved))
    return whole
