"""A linear chain of `device.add` steps in one open epoch, for the tests that measure what a call asks vitni.

Each step hangs under the one before it, so the state at the top holds every device added so far. The devices are
the fixture ones that no genesis document lists, so the chain is as long as those keys allow (`MAX`). Persons
alternate between alice and bob, and alice and bob sign every step.
"""
AB = ("alice", "bob")
NAMES = ("alice2", "alice3", "alice4", "bob2", "bob3", "carol2", "dave2", "frank", "grace", "X1", "X2")
MAX = len(NAMES) - 1   # one name is kept for the item on top of the longest chain


def chain(w, steps):
    """The `steps` linear `device.add` steps of the world `w`, each under the one before."""
    out, prev = [], None
    for i in range(steps):
        prev = w.device_add(NAMES[i], AB, prev, person=AB[i % 2])
        out.append(prev)
    return out


def top(w, below):
    """The step after the chain `below`: the act an `admit` call is asked about."""
    return w.device_add(NAMES[len(below)], AB, below[-1] if below else None, person=AB[len(below) % 2])


def acts_of(steps):
    return [text for step in steps for text in step.acts]
