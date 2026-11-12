"""Liveness (FO-27): which rules can still reach their quorum at a node.

A rule is reachable at a node iff the role-holding persons with an active accepted key in the state at
that node number at least `Q_r`. This is a reading of a state, not a rule the fold enforces: quorum
(FO-22, FO-23) already refuses an act that has fewer than `Q_r` persons, and the fold never invents
authority to leave a deadlock. The one exit from an epoch whose `genesis.change` is unreachable is a
new original genesis, which no fold can model.
"""


def reachable(epoch, state, rule):
    """True iff enough role-holding persons of `state` have a usable key to meet the rule `rule`."""
    needed, roles = epoch.rule(rule)
    holders = {person for person, role in state.members.items() if role in roles and state.usable_devices(person)}
    return len(holders) >= needed


def unreachable(epoch, state):
    """The sorted names of the policy rules that are not reachable in `state`."""
    return sorted(name for name in epoch.policy["rules"] if not reachable(epoch, state, name))
