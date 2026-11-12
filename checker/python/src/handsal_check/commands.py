"""The command table of both builds (CF-03, CF-08): one pure core, two ways of feeding it.

`table` is the ONE place that wires the seven commands. A `Build` says only what differs between the two
builds, and is chosen by nothing but the entry point that names it (`conformance.BUILD`,
`production.BUILD`); there is no run-time switch:

  conformance  takes `pin` and `now` as input data (parsed with `conformance_build=True`) and accepts
               both profiles; the input is used as parsed
  production   refuses an input that carries either key (`malformed_input`), refuses the fixture profile,
               and `fill` puts the probe's answer and the clock into the parsed input before the core
               sees it

`fill` runs after parsing, so a malformed input never reaches the probe or the clock, and before the
steps, so the pure core is the same function in both. `genesis-check` and the stateless commands read
neither pin nor clock. `vitni` is the verifier (CF-05), `render_size` the GP-15 step 5 check and
`load_profiles` the profiles; those two are parameters so a test can give others.
"""
from collections import namedtuple

from . import (checkact, cli, core, enrolled, foldcmd, genesis_check, profiles as profile_data, registry,
               render_genesis)

Build = namedtuple("Build", "conformance allow_fixture")


def table(build, vitni, render_size=render_genesis.render_size, load_profiles=profile_data.load,
          fill=lambda inp: inp):
    """The command table of `build` over the verifier `vitni`. `fill` completes a parsed input with the
    `pin` and `now` the host supplies (production); the conformance build leaves the input as it is."""
    commands = dict(cli.PURE)

    def check_act(value):
        inp = fill(checkact.parse_input(value, build.conformance))
        return checkact.run(inp, registry.load(), load_profiles(), build.allow_fixture, vitni, render_size)

    def fold(value):
        inp = fill(foldcmd.parse_input(value, build.conformance))
        return foldcmd.run(inp, registry.load(), load_profiles(), build.allow_fixture, vitni, render_size)

    def enrolled_command(value):
        inp = fill(enrolled.parse_input(value, build.conformance))
        return enrolled.run(inp, registry.load(), load_profiles(), build.allow_fixture, vitni, render_size)

    def genesis_check_command(value):
        return genesis_check.run(genesis_check.parse_input(value), registry.load(), load_profiles(),
                                 build.allow_fixture, vitni, render_size)

    commands["check-act"] = core.Command(check_act, False)
    commands["fold"] = core.Command(fold, False)
    commands["enrolled"] = core.Command(enrolled_command, False)
    commands["genesis-check"] = core.Command(genesis_check_command, False)
    return commands
