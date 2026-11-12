"""A bag of chain acts plus the state its valid acts give (FO-01, FO-22).

`Chain` builds acts with the base builders (lib/base.py) at the current tip and
records, for each act the vector author declares valid (`ok=True`), the effect the
spec gives it on a `State` (lib/state.py). An act built with `ok=False` goes into
the bag and changes nothing: the author states which acts are not on the chain,
and the anchor is that statement, never a checker's answer (CF-06). `valid=True`
records an act for the vitni cross-check without applying it (a valid act off the
tip, a branch).

`parent=` builds at another position (a fork, a stale proposal); an act off the
tip is never applied by this helper, whatever `ok` says, because its place in
the accepted chain is a fork or a resolve question the vector states itself.
"""
import json

from . import forge, inputs, rules, state

_TIP = object()
GENESIS_SIGN = "local:handsal.genesis.sign"
ENDORSE = "local:handsal.act.endorse"
RESOLVE = "local:handsal.chain.resolve"


class Chain:
    """`doc` is the epoch's genesis document (default ORG, or WIT_ORG with `wit`) and
    `lineage` the `[{doc, sigs}]` ending in it; a chain over a change document roots its first
    act at that document's hash and names the original org in every act (GP-07, FO-04)."""

    def __init__(self, fx, *, wit=False, ctx=None, doc=None, lineage=None):
        self.fx = fx
        self.wit = wit
        self.ctx = ctx
        self.doc = doc or (fx.wit_org if wit else fx.org)
        self.lineage = lineage if lineage is not None else fx.lineage(wit)
        self.root = inputs.doc_id(self.doc)
        self.org_id = self.doc["org"] or self.root
        self.state = state.State(self.doc)
        self.history = [self.state.snapshot()]  # history[n]: the state at node n
        self._at = {self.root: self.state}  # the state after each valid act, by act id
        self.acts = []
        self.tip = None  # the last applied primary; None at the root
        if ctx is not None:
            self._record_lineage()

    def _record_lineage(self):
        """Every genesis.sign of the lineage goes to the vitni cross-check."""
        for entry in self.lineage:
            for jws in entry["sigs"]:
                kid = json.loads(forge.parts(jws)[0])["kid"]
                self.ctx.positive(jws, GENESIS_SIGN, [self.fx.name_of_kid(kid)])

    def _org(self):
        return self.org_id

    def state_at(self, built):
        """The state after `built` (None: the root): any act the author called valid, applied
        or beside the tip. An act declared not ok has none (KeyError)."""
        return self._at[self.root if built is None else built.id]

    def _build(self, make, parent, ok, effect, method, signers, check, possession=None,
               valid=None):
        """Build the act, refuse a claim the spec contradicts (lib/rules.py), then apply it.

        `check(S_P)` raises `rules.Refused`; it runs for every act the author calls valid, on
        the tip or beside it. The state after the act is kept for its children.
        """
        at_tip = parent is _TIP
        at = self.tip if at_tip else parent
        built = make(at)
        self.acts.extend(built.acts)
        if ok or valid:
            before = self.state_at(at)
            check(before)
            self._record(built, method, signers, possession)
            after = before.snapshot()
            effect(built, after)
            after.advance(built.id)
            self._at[built.id] = after
        if ok and at_tip:
            self.state = after
            self.history.append(after.snapshot())
            self.tip = built
        elif ok:
            raise ValueError("an act off the tip cannot be applied by the helper")
        return built

    def _kids(self, signers):
        return [self.fx.key(n).kid for n in signers]

    def _record(self, built, method, signers, possession):
        """Hand each act of a valid chain act to the vitni cross-check."""
        if self.ctx is None:
            return
        who = [(method, signers[0])] + [(ENDORSE, n) for n in signers[1:]]
        if possession:
            who.append((ENDORSE, possession))
        for jws, (act_method, signer) in zip(built.acts, who):
            self.ctx.positive(jws, act_method, [signer])

    def device_add(self, name, signers, *, ok=True, valid=None, parent=_TIP, label=None,
                   cls=None, **hooks):
        edit = hooks.get("body_edit")
        if cls is not None:  # the body names another class than the fixture device's own
            def edit_class(body, inner=edit):
                body["class"] = cls
                if inner:
                    inner(body)
            hooks["body_edit"] = edit_class
        entry = self.fx.device_entry(name)

        def make(p):
            return self.fx.device_add(name, signers, parent=p, org=self._org(), label=label,
                                      root=self.root, **hooks)

        def check(st):
            rules.device_add(st, entry["person"], cls or entry["class"], self._kids(signers))

        def effect(built, st):
            e = self.fx.device_entry(name)
            e["label"] = label or e["label"]
            e["class"] = cls or e["class"]
            st.add_device(e["person"], e)
        return self._build(make, parent, ok, effect, "local:handsal.device.add", signers, check,
                           name, valid)

    def device_remove(self, name, signers, *, ok=True, valid=None, parent=_TIP, **hooks):
        entry = self.fx.device_entry(name)

        def make(p):
            return self.fx.device_remove(name, signers, parent=p, org=self._org(),
                                         root=self.root, **hooks)

        def check(st):
            rules.device_remove(st, entry["person"], entry["kid"], self._kids(signers))

        def effect(built, st):
            st.remove_device(entry["kid"])
        return self._build(make, parent, ok, effect, "local:handsal.device.remove", signers,
                           check, valid=valid)

    def member_add(self, name, signers, *, role, ok=True, valid=None, member=None, parent=_TIP,
                   label=None, **hooks):
        entry = self.fx.device_entry(name)
        who = member or entry["person"]
        earlier = {m["id"] for e in self.lineage[:-1] for m in e["doc"]["members"]}

        def make(p):
            return self.fx.member_add(name, signers, role=role, member=member, parent=p,
                                      org=self._org(), label=label, root=self.root, **hooks)

        def check(st):
            rules.member_add(st, who, role, entry["class"], self._kids(signers), earlier)

        def effect(built, st):
            e = self.fx.device_entry(name)
            e["label"] = label or e["label"]
            st.add_member(who, role)
            st.add_device(who, e)
        return self._build(make, parent, ok, effect, "local:handsal.member.add", signers, check,
                           name, valid)

    def resolve(self, signers, *, candidates, choose, heads, parent, overrides=(), **hooks):
        """A `chain.resolve` at `parent` (a built act, or None for the root).

        It joins the bag and is recorded for the vitni cross-check, but takes no position
        (FO-24): the state and the tip stay as they are, so the author builds the branch the
        resolve chooses as the applied one and the others with `ok=False, valid=True`.
        """
        built = self.fx.chain_resolve(signers, candidates=candidates, choose=choose, heads=heads,
                                      overrides=overrides, parent=parent, org=self._org(),
                                      root=self.root, **hooks)
        self.acts.extend(built.acts)
        self._record(built, RESOLVE, tuple(signers), None)
        return built

    def edit_act(self, built, index, jws):
        """Replace act `index` of `built` by `jws`, in the built list and in the bag."""
        at = self.acts.index(built.acts[index])
        self.acts[at] = jws
        built.acts[index] = jws

    def fold_input(self, *, at=None, extra_acts=()):
        data = inputs.fold_input(self.lineage, acts=list(self.acts) + list(extra_acts))
        if at is not None:
            data["at"] = str(at)
        return data

    def expect(self, *, at=None):
        """The `fold` anchor: the state at the tip, or at node `at` of the accepted chain."""
        return state.anchor(self.state if at is None else self.history[at])
