"""The commands whose answers read a fold, the one list the fold guards share.

`test_fold_identity` computes the files an answer depends on from the modules named here, and `test_fold_differential`
asks each of them over generated stores. They import the same mapping, so a name removed from it leaves both tests at
once and a name added reaches both. It is not derived from the command table because no property of it picks exactly these
modules: it holds closures, not modules, and `admit` and `sync` are wired the same way. What is derived is the check that
the list is complete: `test_fold_identity` reads `commands.py` and every module that imports it, and fails on a command
module they run that is neither here nor named in `NOT_FOLD_COMMANDS`, so a new command cannot be missed.
"""

# command name -> the module of the package that implements it
COMMAND_MODULES = {"fold": "foldcmd", "head": "head", "check-act": "checkact", "recheck-act": "recheck",
                   "enrolled": "enrolled", "pool": "pool", "agree-points": "agreepoints", "compact": "compact",
                   "genesis-check": "genesis_check", "genesis-aids": "genesis_aids"}

ENTRY_POINTS = tuple(sorted(COMMAND_MODULES.values()))

# modules a build runs that are not compared here, each with its reason
NOT_FOLD_COMMANDS = {
    "admit": "answers about an offered act; its file is in the identity closure through `pool` (asserted by "
             "`HELD_BY_THE_CLOSURE`), its answers are the concern of its own tests",
    "sync": "runs through the host's ports (probe, store, clock) and writes the store, so comparing two packages "
            "would need stand-in ports for each, which this test does not build; it is outside the identity "
            "closure as well",
}

# the excuses above that rest on the module being in the closure: `test_fold_identity` asserts each is
HELD_BY_THE_CLOSURE = ("admit",)
