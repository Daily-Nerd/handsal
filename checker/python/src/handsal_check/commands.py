"""The command tables of the three builds (CF-03, CF-08, CF-10): one pure core, three ways of feeding it.

`table` is the ONE place that wires the nine commands (`head` among them), `admission` the one place that wires `admit`, `pool` and
`compact`.
A `Build` says only what differs between the builds, and is chosen by nothing but the entry point that names it
(`conformance.BUILD`, `production.BUILD`, `server.BUILD`); there is no run-time switch:

  conformance  takes `pin` and `now` as input data (parsed with `conformance_build=True`) and accepts
               both profiles; the input is used as parsed
  production   refuses an input that carries either key (`malformed_input`), refuses the fixture profile,
               and `fill` puts the probe's answer and the clock into the parsed input before the core
               sees it
  server       has only `admission`: no pin, no clock, no store, no fixture profile (`server.py`)

`fill` runs after parsing, so a malformed input never reaches the probe or the clock, and before the
steps, so the pure core is the same function in both. `genesis-check` and the stateless commands read
neither pin nor clock. `vitni` is the verifier (CF-05), `render_size` the GP-15 step 5 check and
`load_profiles` the profile set (the one value every command reads: each epoch's registry comes from it); those two are parameters so a test can give others.
"""
from collections import namedtuple

from . import (admit, checkact, cli, compact, core, enrolled, foldcmd, genesis_check, head, pool,
               profiles as profile_data, recheck, render_genesis)

Build = namedtuple("Build", "conformance allow_fixture")


def table(build, vitni, render_size=render_genesis.render_size, load_profiles=profile_data.load,
          fill=lambda inp: inp):
    """The command table of `build` over the verifier `vitni`. `fill` completes a parsed input with the
    `pin` and `now` the host supplies (production); the conformance build leaves the input as it is."""
    commands = dict(cli.PURE)

    def check_act(value):
        inp = fill(checkact.parse_input(value, build.conformance))
        return checkact.run(inp, load_profiles(), build.allow_fixture, vitni, render_size)

    def recheck_act(value):
        inp = fill(recheck.parse_input(value, build.conformance))
        return recheck.run(inp, load_profiles(), build.allow_fixture, vitni, render_size)

    def fold(value):
        inp = fill(foldcmd.parse_input(value, build.conformance))
        return foldcmd.run(inp, load_profiles(), build.allow_fixture, vitni, render_size)

    def enrolled_command(value):
        inp = fill(enrolled.parse_input(value, build.conformance))
        return enrolled.run(inp, load_profiles(), build.allow_fixture, vitni, render_size)

    def head_command(value):
        inp = fill(head.parse_input(value, build.conformance))
        return head.run(inp, load_profiles(), build.allow_fixture, vitni, render_size)

    def genesis_check_command(value):
        return genesis_check.run(genesis_check.parse_input(value), load_profiles(),
                                 build.allow_fixture, vitni, render_size)

    commands["check-act"] = core.Command(check_act, False)
    commands["recheck-act"] = core.Command(recheck_act, False)
    commands["fold"] = core.Command(fold, False)
    commands["enrolled"] = core.Command(enrolled_command, False)
    commands["head"] = core.Command(head_command, False)
    commands["genesis-check"] = core.Command(genesis_check_command, False)
    return commands


def admission(build, vitni, render_size=render_genesis.render_size, load_profiles=profile_data.load):
    """`admit` (CF-11), `pool` (CF-12) and `compact` (CF-14) of `build` over the verifier `vitni`: the whole table
    of the server build, and the three commands the conformance build adds. Their whole input is the snapshot of
    CF-13 and the item or the key (`compact`: the snapshot alone), so no `fill` exists for them: they read no pin,
    no clock and no store."""

    def admit_command(value):
        return admit.run(admit.parse_input(value), load_profiles(), build.allow_fixture, vitni,
                         render_size)

    def pool_command(value):
        return pool.run(pool.parse_input(value), load_profiles(), build.allow_fixture, vitni,
                        render_size)

    def compact_command(value):
        return compact.run(compact.parse_input(value), load_profiles(), build.allow_fixture, vitni,
                           render_size)

    return {"admit": core.Command(admit_command, False), "pool": core.Command(pool_command, False),
            "compact": core.Command(compact_command, False)}
