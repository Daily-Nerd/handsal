"""Server build: `handsal-check-server`, for automation hosts that decide admission and key-pool membership (CF-10).

The same pure core as the other builds (`commands.admission`), and exactly three commands, `admit` (CF-11),
`pool` (CF-12) and `compact` (CF-14); every other command is `unsupported_command`. It reads no pin, no clock and
no store, takes no `--vitni` option, no environment override and no fixture profile (`BUILD` refuses it, GP-18),
and finds vitni only at the fixed Linux path (CF-05, SG-14). It has no command that decides a human act and its
outputs carry no `valid`, `rechecked` or `enrolled`, so nothing it says can be read as proof of a person (I1).

The verifier is the Linux one whatever the host runs the module: a server build never spawns a macOS or Windows
administrator path. Nothing from `host`, `probe_posix` or `store_posix` is imported, so no pin probe and no store
port exist in this process.
"""
from . import commands, core, profiles, render_genesis, verifier

BUILD = commands.Build(conformance=False, allow_fixture=False)
VERIFIER = verifier.VitniCli.installed("linux")


def build_commands(vitni, render_size=render_genesis.render_size, load_profiles=profiles.load):
    """The command table of the server build over the verifier `vitni`."""
    return commands.admission(BUILD, vitni, render_size, load_profiles)


COMMANDS = build_commands(VERIFIER)


def main(argv=None, stdin=None, stdout=None):
    if argv is None:
        return core.entry(COMMANDS)
    return core.run(COMMANDS, argv, stdin, stdout)
