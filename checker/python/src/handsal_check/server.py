"""Server build: `handsal-check-server`, for automation hosts that decide admission and key-pool membership (CF-10).

The same pure core as the other builds (`commands.admission`), and exactly four commands, `admit` (CF-11),
`pool` (CF-12), `compact` (CF-14) and `agree-points`; every other command is `unsupported_command`. It reads no pin, no clock and
no store, takes no `--vitni` option, no environment override and no fixture profile (`BUILD` refuses it, GP-18),
and finds vitni only at the fixed Linux path (CF-05, SG-14), asking it for the questions of a call in one
`verify-batch` process: a vitni without that command answers `verifier_unavailable`, never one question at a time.
It has no command that decides a human act and its outputs carry no `valid`, `rechecked` or `enrolled`, so nothing
it says can be read as proof of a person (I1).

`handsal-check-server serve` is one process that answers many requests in this table, each with the bytes the one-shot
command gives (`serve.py`); the verifier it asks is the same one and it remembers verdicts between calls.

The verifier is the Linux one whatever the host runs the module: a server build never spawns a macOS or Windows
administrator path. Nothing from `host`, `probe_posix` or `store_posix` is imported, so no pin probe and no store
port exist in this process.
"""
from . import commands, core, profiles, render_genesis, serve, verifier

BUILD = commands.Build(conformance=False, allow_fixture=False)
VERIFIER = verifier.VitniBatch.installed("linux")


def build_commands(vitni, render_size=render_genesis.render_size, load_profiles=profiles.load, verdicts=None):
    """The command table of the server build over the verifier `vitni`, remembering verdicts across calls in
    `verdicts` (a `verifier.Verdicts`) when a long-lived process gives one."""
    return commands.admission(BUILD, vitni, render_size, load_profiles, verdicts=verdicts)


COMMANDS = build_commands(VERIFIER)


def serving(stdin, stdout):
    """One process that answers many requests in the table of this build (`serve.run`)."""
    return serve.run(build_commands, VERIFIER, stdin, stdout)


def main(argv=None, stdin=None, stdout=None):
    if argv is None:
        return core.entry(COMMANDS, serving)
    return core.run(COMMANDS, argv, stdin, stdout, serving)
