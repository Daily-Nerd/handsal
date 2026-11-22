"""The answers of the fold commands are the answers of the last release, over generated stores.

The package at tag v0.4.2 is imported next to the current one (`v042_tree`) and both answer the same inputs, line for
line: over `random_store(seed)` as the store is and as one full compaction leaves it, the commands `fold`, `head`,
`check-act`, `recheck-act`, `enrolled`, `pool`, `agree-points`, `compact`, `genesis-check` and `genesis-aids`, with one stand-in verifier class behind
each package's own memo. An answer that differs by one byte is a failure. Where `test_fold_identity` shows the
code of the fold is the code of the tag, this shows the answers are, and it is the one that covers a change outside
that code (a new import path, the data a rule reads, a command that wraps one).

A store holds the documents of the profile the tag calls current, because that is the edition both packages accept.
The default run covers `DEFAULT_SEEDS` stores; `HANDSAL_DIFF_SEEDS` names a larger count for the evidence run, and it
is the only place a count is set.
"""
import json
import os
import random
import unittest
from collections import namedtuple

import handsal_check as current
from handsal_check import errors, snapshot

from . import v042_tree
from .act_builder import FakeVitni, head_of, kid_of
from .checkact_world import NOW, Scenario, probe_for
from .fold_commands import COMMAND_MODULES
from .fold_world import World
from .genesis_fixtures import point
from .store_world import compacted, random_store, snap_of

TAG = "v0.4.2"
DEFAULT_SEEDS = 8
SEEDS = int(os.environ.get("HANDSAL_DIFF_SEEDS", DEFAULT_SEEDS))
CONTROL_SEEDS = (4, 18)   # plain stores in which the planted edit of `Control` changes answers: about one in ten does
OVERRIDE_SEEDS = (37, 47)   # `overrides` stores in which an override's effectiveness decides the answers: about one in ten
OPENING_FLOOR = 0.9   # of the store forms, at least this share must open: a generator that refused most would compare refusals
MODULES = COMMAND_MODULES   # the list `test_fold_identity` computes its closure from
OPEN_STORE = ("pool", "agree-points", "compact")   # these read a store of the profile whose documents it holds
TIMED = ("now", "seen", "synced_at", "tip_statement", "next")
DEVICES = ("alice", "alice2", "bob2", "alice3", "frank")   # a device of the original and keys the generator adds


class Side:
    """One package, asked through the `parse_input` and `run` of each command module."""

    def __init__(self, package):
        self.name = package.__name__
        self.modules = {command: v042_tree.module(package, name) for command, name in MODULES.items()}
        self.verifier = v042_tree.module(package, "verifier")
        self.errors = v042_tree.module(package, "errors")
        self.render_size = v042_tree.module(package, "render_genesis").render_size
        profiles = v042_tree.module(package, "profiles")
        self.profiles = profiles.ProfileSet([
            profiles.Edition(profiles.Version(v.position, v.label, v.reg, frozenset()), production, fixture)
            for v, production, fixture in profiles.load().editions()])

    def answer(self, command, value):
        """The line `command` answers for `value`: its output as sorted JSON, or the refusal that stopped it."""
        module = self.modules[command]
        memo = self.verifier.Memoized(FakeVitni())
        try:
            out = module.run(module.parse_input(value), self.profiles, command in OPEN_STORE, memo, self.render_size)
        except (self.errors.Malformed, self.errors.Refused) as err:
            return "%s %s" % (type(err).__name__, getattr(err, "code", err))
        return json.dumps(out, sort_keys=True)


def newest_production(package):
    """The production hash the package calls current: the profile a store of this test is built for."""
    return v042_tree.module(package, "profiles").load().production_hashes()[-1]


def inputs(snap, heads, scenario):
    """`(command, value)` for every command over the store `snap`: the store-level commands once, and the pin-level
    ones for every open document, with a view at each of `heads` (two real heads and one that is no node)."""
    out = []
    closed = {e["doc"].get("prev") for e in snap.docs}
    index = snapshot.by_hash(snap)
    base = {"acts": list(snap.acts), "docs": list(snap.docs), "org": snap.org}
    out.append(("compact", base))
    out.append(("pool", dict(base, agree=point("alice.agree"))))
    out.append(("agree-points", base))
    for key in index:
        if key in closed:
            continue
        path = snapshot.path_to(index, key)
        lineage = [{"doc": e["doc"], "sigs": e["sigs"]} for e in path]
        pin = probe_for(path[-1]["doc"], snap.org)
        out.append(("fold", {"acts": list(snap.acts), "lineage": lineage, "org": snap.org, "pin": pin}))
        out.append(("genesis-check", {"acts": list(snap.acts), "lineage": lineage}))
        out.append(("genesis-aids", {"acts": list(snap.acts), "lineage": lineage}))
        asked = {"acts": list(snap.acts), "lineage": lineage, "now": NOW, "org": snap.org, "next": "no", "pin": pin,
                 "synced_at": NOW, "tip_statement": None}
        out.append(("head", asked))
        for device in DEVICES:
            out.append(("enrolled", dict(asked, device_kid=kid_of(device))))
        for head in heads:
            value = scenario.value(scenario.verdict(head=head_of(head)), acts=list(snap.acts), lineage=lineage, pin=pin,
                                   next="no")
            out.append(("check-act", value))
            out.append(("recheck-act", {k: v for k, v in value.items() if k not in TIMED}))
    return out


def stores(seeds, profile, shapes=(False, True)):
    """`(seed, form, snapshot, heads)` for each of the `seeds`: the store the generator draws, and the same seed with
    the `overrides` shape added (`shapes` says which of the two), each raw and compacted when a full compaction
    accepts it."""
    for seed in seeds:
        for overrides in shapes:
            store = random_store(seed, profile, overrides=overrides)
            snap = snap_of(store.acts, store.docs, store.org)
            rng = random.Random(seed)
            heads = rng.sample(store.ids, min(2, len(store.ids))) + ["A" * 43]
            name = "overrides " if overrides else ""
            yield seed, name + "raw", snap, heads
            try:
                gone = compacted(snap)
            except errors.Refused:
                continue   # a store that compaction refuses has no compacted form: its raw form is all there is
            yield seed, name + "compacted", gone, heads


def answered(line):
    """Whether an `answer` line is an answer and not a refusal: a refused store does not raise, it answers JSON with
    a `reason` and a null `active`, where a store that opens answers a list (the answer of an open store carries the
    reason `ok`, so the reason alone does not tell)."""
    return not line.startswith(("Refused", "Malformed")) and json.loads(line).get("active") is not None


Compared = namedtuple("Compared", "answers differences forms opened")


def compare(old, new, seeds, shapes=(False, True)):
    """The `Compared` of the packages `old` and `new` over the stores of the `seeds`: how many answers, the
    differences, how many store forms and how many of them `old` opened (its `agree-points` gave an answer, not a `reason`)."""
    sides = Side(old), Side(new)
    scenario = Scenario(World(profile=newest_production(old)))
    result = Compared(0, [], 0, 0)
    compared, differences, forms, opened = 0, [], 0, 0
    for seed, form, snap, heads in stores(seeds, newest_production(old), shapes):
        forms += 1
        for command, value in inputs(snap, heads, scenario):
            then, now = (side.answer(command, value) for side in sides)
            compared += 1
            if command == "agree-points" and answered(then):
                opened += 1
            if then != now:
                differences.append({"seed": seed, "form": form, "command": command, "old": then[:160], "new": now[:160]})
    return Compared(compared, differences, forms, opened)


class Loading(unittest.TestCase):
    def test_the_tag_is_a_package_of_its_own_with_its_own_data(self):
        old = v042_tree.load(TAG)
        self.assertEqual(old.__name__, "handsal_check_v042")
        self.assertIsNot(v042_tree.module(old, "verifier"), v042_tree.module(current, "verifier"))
        self.assertNotEqual(v042_tree.module(old, "coredata").DATA_DIR, v042_tree.module(current, "coredata").DATA_DIR)
        self.assertEqual(v042_tree.module(old, "coredata").PACKAGED.joinpath("core-manifest.json").read_bytes(),
                         (v042_tree.module(old, "coredata").DATA_DIR / "core-manifest.json").read_bytes())


    def test_an_edit_that_matches_nothing_is_an_error(self):
        for old in ("no such text in the module", "def "):
            with self.subTest(old=old), self.assertRaises(ValueError):
                v042_tree.load_edited(TAG, "resolve", old, "x")


class Differential(unittest.TestCase):
    def test_the_answers_of_the_tag_and_of_this_tree_are_the_same(self):
        result = compare(v042_tree.load(TAG), current, range(SEEDS))
        self.assertGreater(result.answers, 0)
        self.assertEqual(result.differences, [], "%d of %d answers differ" % (len(result.differences), result.answers))
        self.assertGreaterEqual(result.opened, OPENING_FLOOR * result.forms,
                                "only %d of %d store forms open" % (result.opened, result.forms))

    def test_the_overrides_stores_in_which_effectiveness_decides_the_answers_are_the_same(self):
        """The default seeds hold no `overrides` store whose answers depend on whether an override is effective, so
        two that do are named: the control below shows the comparison reacts when that judgement is wrong."""
        result = compare(v042_tree.load(TAG), current, OVERRIDE_SEEDS, shapes=(True,))
        self.assertEqual(result.differences, [], "%d of %d answers differ" % (len(result.differences), result.answers))


class Control(unittest.TestCase):
    """A comparison is real if a changed rule makes it fail."""

    def test_a_copy_of_the_tag_whose_resolves_ignore_whether_they_are_current_gives_different_answers(self):
        edited = v042_tree.load_edited(TAG, "resolve", "{x.choose for x in self.at(node) if self.current(x)}",
                                       "{x.choose for x in self.at(node)}")
        result = compare(v042_tree.load(TAG), edited, CONTROL_SEEDS)
        self.assertGreater(len(result.differences), 0, "no answer of %d changed" % result.answers)
        self.assertIn("fold", {d["command"] for d in result.differences})

    def test_a_copy_of_the_tag_in_which_no_override_is_effective_gives_different_answers_on_the_overrides_stores(self):
        """`_effective` always empty: a resolve that overturns another is then never current. Only a store whose
        resolve names its overrides and has no other resolve at its fork reacts, and the draw makes about one in ten."""
        edited = v042_tree.load_edited(TAG, "resolve", "        return named\n", "        return set()\n")
        result = compare(v042_tree.load(TAG), edited, OVERRIDE_SEEDS, shapes=(True,))
        self.assertGreater(len(result.differences), 0, "no answer of %d changed" % result.answers)
        self.assertIn("fold", {d["command"] for d in result.differences})


if __name__ == "__main__":
    unittest.main()
