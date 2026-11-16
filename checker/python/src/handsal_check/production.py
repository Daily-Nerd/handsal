"""Production build: the only build installed at the administrator path (CF-08, SG-14).

The same pure core as the conformance build (`commands.table`), fed differently: the pin comes from the
platform probe of this host (`host.host_probe`, called in process at the fixed pin path), `now` from the
system clock, and, for `check-act`, `recheck-act`, `enrolled` and `head`, the chain (`acts`, `lineage`, `next`,
`synced_at`, the witness slot as `tip_statement`) from the user's store (`host.host_store`, CF-09), so an input
that carries any of those keys is `malformed_input` (`recheck-act` takes no `next` or `synced_at`: it reads no
view); the fixture profile is refused. A store that cannot be read is not an
exception here: `fill` hands its reason to the core, which answers it at VR-02 step 6 (f), after the pin reasons.
The probe, the clock and the store are constructor arguments of `build_commands` for tests only: `COMMANDS`,
which the entry point runs, takes the host's, and nothing on the command line or in the input reaches them. There
is no `--vitni` option: the verifier is the one at the SG-14 path.

`sync` (CF-09) is wired here and nowhere else: the production table is the shared table (nine commands, `head`
among them) plus `sync`, ten commands. `fill` is the one caller of `store.load` (CF-08 S4).
"""
from . import commands, core, host, profiles, render_genesis, store, sync, verifier

BUILD = commands.Build(conformance=False, allow_fixture=False)


def build_commands(vitni, probe, clock, store_port, render_size=render_genesis.render_size,
                   load_profiles=profiles.load):
    """The command table of the production build over the verifier `vitni`, the pin `probe`, the `clock` and the
    `store_port`."""

    def fill(inp):
        """The parsed input with the probe's answer for its `org`, the time now where it takes one, and the
        store's view where it takes a chain (one read of each, after parsing)."""
        found = {"pin": probe.read(inp.org)}
        if "now" in inp._fields:
            found["now"] = clock()
        if "store_reason" in inp._fields:
            held = store.load(store_port, inp.org)
            found.update(acts=held.acts, lineage=held.lineage, store_reason=held.reason)
            if "synced_at" in inp._fields:
                found.update(next=held.next, synced_at=held.synced_at, tip_statement=held.witness)
        return inp._replace(**found)

    def sync_command(value):
        loaded = load_profiles()
        return sync.run(sync.parse_input(value), loaded, vitni, render_size, probe,
                        store_port, clock)

    table = commands.table(BUILD, vitni, render_size, load_profiles, fill)
    table["sync"] = core.Command(sync_command, False)
    return table


COMMANDS = build_commands(verifier.VitniCli.installed(), host.host_probe(), host.system_now, host.host_store())


def main(argv=None, stdin=None, stdout=None):
    if argv is None:
        return core.entry(COMMANDS)
    return core.run(COMMANDS, argv, stdin, stdout)
