"""The generated stores (`store_world.random_store`) that the property and differential tests read.

A store is a function of its seed, so a test that reproduces a failure by seed needs the old seeds to keep meaning
what they meant: the digest pins the first fifty. The shapes a generator never draws are shapes no property test
covers: the second test asks for the one that the first version of the generator left out.
"""
import hashlib
import json
import unittest

from handsal_check import chain, errors

from .profile_sets import production_of
from .store_world import PROFILES, REG, opened, random_store, snap_of

PINNED_SEEDS = 50
# The digest covers the documents and the receipt ids of the stores, which hash the profile of the current core, so it
# moves with every edit of a core file and is pinned again then (the shape of the fifty stores, the count of acts and
# documents and the methods of each, is the same on the parent: that is what "what they were" means).
PINNED_DIGEST = "9d4e9fa34db3ac9d55d5286fbea7af8b47f1d95e6a7254a32831ae8f0b8618f9"
PINNED_SHAPE = "e58894ae3d56970b78876367251725e8c7e8a44fe8bf597c9ef2306cd721d0dd"
SEEDS_WITH_OVERRIDES = 500
OPENED_SEEDS = 40


def digest(seeds):
    out = hashlib.sha256()
    for seed in seeds:
        store = random_store(seed)
        out.update(json.dumps([store.acts, store.docs, store.org, store.ids], sort_keys=True).encode())
    return out.hexdigest()


def shape(seeds):
    """What does not depend on any hash: the number of acts and documents of each store and the methods of its acts."""
    out = []
    for seed in seeds:
        store = random_store(seed)
        bag = chain.Bag(store.acts, REG.wire, store.org)
        out.append([len(store.acts), len(store.docs), sorted(g.act.method for g in bag.groups.values())])
    return hashlib.sha256(json.dumps(out).encode()).hexdigest()


def overrides_with_one_kid_twice(store):
    """The `overrides` entries of the resolves of `store` that name two endorsements signed by one kid."""
    bag = chain.Bag(store.acts, REG.wire, store.org)
    found = []
    for group in bag.groups.values():
        if group.act.method != chain.RESOLVE:
            continue
        for entry in group.act.body["overrides"]:
            kids = [bag.groups[i].act.kid for i in entry["endorsements"] if i in bag.groups]
            if len(kids) != len(set(kids)):
                found.append(entry)
    return found


def opens(store):
    """The documents `open_store` opens the store to, or the code it refuses with."""
    try:
        return sorted(opened(snap_of(store.acts, store.docs, store.org)))
    except errors.Refused as err:
        return err.code


class GeneratedStores(unittest.TestCase):
    def test_the_first_fifty_stores_are_what_they_were(self):
        self.assertEqual(digest(range(PINNED_SEEDS)), PINNED_DIGEST)

    def test_the_first_fifty_stores_keep_their_shape_whatever_the_hashes_of_the_core_are(self):
        self.assertEqual(shape(range(PINNED_SEEDS)), PINNED_SHAPE)

    def test_random_stores_include_an_overrides_entry_with_two_endorsements_of_one_kid(self):
        hits = (seed for seed in range(SEEDS_WITH_OVERRIDES)
                if overrides_with_one_kid_twice(random_store(seed, production_of(PROFILES), overrides=True)))
        seed = next(hits, None)
        self.assertIsNotNone(seed, "no store of seeds 0 to %d names two endorsements of one kid" % (SEEDS_WITH_OVERRIDES - 1))
        self.assertNotIsInstance(opens(random_store(seed, production_of(PROFILES), overrides=True)), str,
                                 "the first such store, seed %d, does not open" % seed)

    def test_the_extra_acts_change_what_a_store_opens_to_in_no_case(self):
        """Some seeds give a store that `open_store` refuses (a change document at a head no node holds); with the
        extra resolves a store opens or is refused exactly as without them."""
        for seed in range(OPENED_SEEDS):
            with self.subTest(seed=seed):
                plain = opens(random_store(seed, production_of(PROFILES)))
                extra = opens(random_store(seed, production_of(PROFILES), overrides=True))
                self.assertEqual(extra, plain)
