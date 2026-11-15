"""A world for fold tests: one organization, its fixture keys and a builder for chain acts.

Acts carry stand-in signatures (`act_builder`); `FakeVitni` answers like vitni would from the keys
the fold sends. Nothing here calls a fold rule: an act is valid because of how it is built.
"""
from collections import namedtuple

from handsal_check import chain, encoding, fold, genesis, profiles, registry

from .act_builder import BAD, GOOD, FakeVitni, build, genesis_sign, head_of, kid_of, person_of
from .genesis_fixtures import change, device, org as make_org, point, policy

REG = registry.load()
PROFILES = profiles.load()

ROLE = "maintainer"


class Step(namedtuple("Step", "primary endorsements pop parent_id")):
    @property
    def id(self):
        return self.primary.id

    @property
    def performer(self):
        return self.primary.performer

    @property
    def acts(self):
        out = [self.primary.jws] + [a.jws for a in self.endorsements.values()]
        if self.pop:
            out.append(self.pop.jws)
        return out


def link_code(name):
    return encoding.hashstr(b"link/" + name.encode())


def device_body(name, person=None, cls="apple-se-bio", label="phone", code=None):
    return {"agree": point(name + ".agree"), "class": cls, "kid": kid_of(name), "label": label,
            "link_code_hash": code or link_code(name), "person": person or person_of(name),
            "sign": point(name + ".sign")}


def member_body(name, member=None, role=ROLE, cls="apple-se-bio", code=None):
    entry = device_body(name, member, cls)
    return {"device": {k: entry[k] for k in ("agree", "class", "kid", "label", "sign")},
            "link_code_hash": code or link_code(name), "member": member or person_of(name), "role": role}


class World:
    def __init__(self, people=("alice", "bob", "carol"), extra=(), persons="2", pol=None, members=None,
                 name="ORG", prev_doc=None, profile=None):
        self.profile = profile or PROFILES.fixture
        self.doc = make_org(self.profile, people=people, name=name, pol=pol or policy(persons=persons))
        if extra or members:
            self.doc["devices"] = sorted(self.doc["devices"] + [device(d) for d in extra], key=lambda d: d["kid"])
        if members:
            self.doc["members"] = sorted(self.doc["members"] + [{"id": m, "role": r} for m, r in members],
                                         key=lambda m: m["id"])
        self.id = genesis.doc_hash(self.doc)
        self.org = self.id

    # ---- acts
    def primary(self, method, body, signers, parent=None, *, pop=None, pop_performer=None, skip=(), salt="",
                **over):
        """A chain primary by `signers[0]` and a counted `act.endorse` by each other signer."""
        parent_id = parent.id if parent else self.id
        parent_performer = parent.performer if parent else None
        fields = dict(org=self.org, body=body, parent=parent_id, parent_performer=parent_performer, salt=salt)
        fields.update(over)
        primary = build(signers[0], method, **fields)
        endorsements = {s: self.endorse(s, primary, parent_id) for s in signers[1:] if s not in skip}
        pop_act = self.endorse(pop, primary, parent_id, performer=pop_performer) if pop else None
        return Step(primary, endorsements, pop_act, parent_id)

    def endorse(self, signer, target, parent_id, **over):
        fields = dict(org=self.org, body={"act": target.id}, parent=target.id, parent_performer=target.performer,
                      head=head_of(parent_id))
        fields.update(over)
        return build(signer, "act.endorse", **fields)

    def device_add(self, name, signers, parent=None, *, person=None, pop=True, **kw):
        body = kw.pop("body", None) or device_body(name, person, **{k: kw.pop(k) for k in ("cls", "label", "code") if k in kw})
        return self.primary("device.add", body, signers, parent, pop=name if pop else None,
                            pop_performer=kw.pop("pop_performer", person or person_of(name)), **kw)

    def device_remove(self, name, signers, parent=None, *, person=None, **kw):
        body = {"kid": kid_of(name), "person": person or person_of(name)}
        return self.primary("device.remove", body, signers, parent, **kw)

    def member_add(self, name, signers, parent=None, *, member=None, role=ROLE, cls="apple-se-bio", pop=True, **kw):
        body = member_body(name, member, role, cls, kw.pop("code", None))
        return self.primary("member.add", body, signers, parent, pop=name if pop else None,
                            pop_performer=kw.pop("pop_performer", member or person_of(name)), **kw)

    def resolve(self, signers, candidates, choose, heads, parent=None, overrides=(), **kw):
        body = {"candidates": sorted(c.id if hasattr(c, "id") else c for c in candidates),
                "choose": choose.id if hasattr(choose, "id") else choose,
                "heads": sorted(h.id if hasattr(h, "id") else h for h in heads), "overrides": list(overrides)}
        return self.primary("chain.resolve", body, signers, parent, **kw)

    # ---- genesis changes
    def change_doc(self, head, people=("alice", "bob", "carol"), devices=None, name="NEXT", pol=None, prev=None):
        """A change document of this organization at `head` (a node id), `prev` the document before it."""
        doc = change(self.profile, self.id, genesis.doc_hash(prev or self.doc), head, people=people,
                     devices=devices, pol=pol or policy(), name=name)
        return doc

    def sigs(self, doc, names, **over):
        """`genesis.sign` texts over `doc` by the fixture devices `names`."""
        return [genesis_sign(n, doc, self.id, **over).jws for n in names]

    # ---- the fold
    def bag(self, *items):
        texts = []
        for item in items:
            texts.extend(item.acts if hasattr(item, "acts") else [item] if isinstance(item, str) else [item.jws])
        return chain.Bag(texts, REG, self.id)

    def epoch(self, *items, vitni=None, doc=None, earlier=None):
        vitni = vitni or FakeVitni()
        epoch = fold.Epoch(doc or self.doc, self.bag(*items), REG, PROFILES, vitni, True,
                           earlier or fold.NO_EARLIER)
        epoch.build()
        return epoch


def ids(epoch):
    return set(epoch.nodes)
