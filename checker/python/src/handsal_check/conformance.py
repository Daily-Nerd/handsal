"""Conformance build: takes pin and now as input data, never installed.

`build_commands` wires the commands through `commands.table`, the one table the builds share, plus `admit`, `pool`
and `compact` (`commands.admission`, CF-03); `BUILD` is all that makes this the conformance build (CF-08): `pin` and
`now` are input data and both profiles are accepted. The verifier is a constructor argument: the default is the one fixed at the SG-14 path, and
a test runner (the harness, CI) gives its own with `--vitni <absolute path>` options before the command,
once per argv item (`--vitni /usr/bin/node --vitni /path/cli.js`). Either way the verifier is a `VitniBatch`, so the
questions of `admit`, `pool` and `compact` go to vitni `verify-batch` and a conformance run proves the batch path.
The production build has no such option (CF-05, CF-08). The render size step (GP-15 step 5) is the genesis render; `render_size` is a parameter so
a test can give another.
"""
import sys

from . import commands, core, profiles, render_genesis, verifier

OPTION = "--vitni"
BUILD = commands.Build(conformance=True, allow_fixture=True)


def build_commands(vitni, render_size=render_genesis.render_size, load_profiles=profiles.load):
    """The command table of the conformance build over the verifier `vitni`."""
    table = commands.table(BUILD, vitni, render_size, load_profiles)
    table.update(commands.admission(BUILD, vitni, render_size, load_profiles))
    return table


VERIFIER = verifier.VitniBatch.installed()
COMMANDS = build_commands(VERIFIER)


def _options(argv):
    """`(vitni argv or None, the rest)`: leading `--vitni <item>` pairs are the verifier argv."""
    items, rest = [], list(argv)
    while rest and rest[0] == OPTION:
        if len(rest) < 2:
            raise ValueError("%s needs a value" % OPTION)
        items.append(rest[1])
        rest = rest[2:]
    return (items or None), rest


def main(argv=None, stdin=None, stdout=None):
    given, rest = _options(sys.argv[1:] if argv is None else argv)
    table = COMMANDS if given is None else build_commands(verifier.VitniBatch(given, owner_check=None))
    if argv is None:
        stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    return core.run(table, rest, stdin, stdout)
