"""Server build: `handsal-check-server`, for automation hosts that decide admission and key-pool membership (CF-10).

The same pure core as the other builds (`commands.admission`), and exactly the table and the modes CF-10 names: `admit`
(CF-11), `pool` (CF-12), `compact` (CF-14), `agree-points` (CF-16), `version` (CF-03), and the mode `serve` (`serve.py`);
every other command, and every other argument list, is `unsupported_command` (`test_spec_tables.py` reads the names
from the spec text). It reads no pin, no clock and
no store, takes no `--vitni` option, no environment override and no fixture profile (`BUILD` refuses it, GP-18),
and finds vitni only at the fixed Linux path (CF-05, SG-14), asking it for the questions of a call in one
`verify-batch` process: a vitni without that command answers `verifier_unavailable`, never one question at a time.
It has no command that decides a human act and its outputs carry no `valid`, `rechecked` or `enrolled`, so nothing
it says can be read as proof of a person (I1).

The verifier is the Linux one whatever the host runs the module: a server build never spawns a macOS or Windows
administrator path. Nothing from `host`, `probe_posix` or `store_posix` is imported, so no pin probe and no store
port exist in this process.
"""
from . import commands, core, profiles, render_genesis, serve, verifier, version

BUILD = commands.Build(conformance=False, allow_fixture=False)
VERIFIER = verifier.VitniBatch.installed("linux")


def build_commands(vitni, render_size=render_genesis.render_size, load_profiles=profiles.load, verdicts=None):
    """The command table of the server build over the verifier `vitni`, remembering verdicts across calls in
    `verdicts` (a `verifier.Verdicts`) when a long-lived process gives one."""
    table = commands.admission(BUILD, vitni, render_size, load_profiles, verdicts=verdicts)
    table["version"] = version.command(load_profiles)
    return table


COMMANDS = build_commands(VERIFIER)


def main(argv=None, stdin=None, stdout=None):
    serving = serve.serving(build_commands, VERIFIER)
    if argv is None:
        return core.entry(COMMANDS, serving)
    return core.run(COMMANDS, argv, stdin, stdout, serving)
