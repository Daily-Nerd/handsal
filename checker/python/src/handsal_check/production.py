"""Production build: the only build installed at the administrator path (CF-08, SG-14).

The same pure core as the conformance build (`commands.table`), fed differently: the pin comes from the
platform probe of this host (`host.host_probe`, called in process at the fixed pin path) and `now` from the
system clock, so an input that carries `pin` or `now` is `malformed_input`; the fixture profile is refused.
The probe and the clock are constructor arguments of `build_commands` for tests only: `COMMANDS`, which the
entry point runs, takes the host's, and nothing on the command line or in the input reaches them. There is
no `--vitni` option: the verifier is the one at the SG-14 path.
"""
from . import commands, core, host, profiles, render_genesis, verifier

BUILD = commands.Build(conformance=False, allow_fixture=False)


def build_commands(vitni, probe, clock, render_size=render_genesis.render_size, load_profiles=profiles.load):
    """The command table of the production build over the verifier `vitni`, the pin `probe` and the `clock`."""

    def fill(inp):
        """The parsed input with the probe's answer for its `org` and, where it takes one, the time now."""
        found = {"pin": probe.read(inp.org)}
        if "now" in inp._fields:
            found["now"] = clock()
        return inp._replace(**found)

    return commands.table(BUILD, vitni, render_size, load_profiles, fill)


COMMANDS = build_commands(verifier.VitniCli.installed(), host.host_probe(), host.system_now)


def main(argv=None, stdin=None, stdout=None):
    if argv is None:
        return core.entry(COMMANDS)
    return core.run(COMMANDS, argv, stdin, stdout)
