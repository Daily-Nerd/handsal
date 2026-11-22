"""The command tables of the three builds (CF-03, CF-08, CF-10): one pure core, three ways of feeding it.

`table` is the ONE place that wires the ten commands (`head` and `genesis-aids` among them), `admission_handlers` the one place that wires `admit`, `pool`
and `compact`, the whole table of the server build, and `agree_points` the one handler of `agree-points`, which the
conformance build alone adds: the spec text does not name it yet, and the server build exposes exactly what the spec
names for it (CF-10).
A `Build` says only what differs between the builds, and is chosen by nothing but the entry point that names it
(`conformance.BUILD`, `production.BUILD`, `server.BUILD`); there is no run-time switch:

  conformance  takes `pin` and `now` as input data (parsed with `conformance_build=True`) and accepts
               both profiles; the input is used as parsed
  production   refuses an input that carries either key (`malformed_input`), refuses the fixture profile,
               and `fill` puts the probe's answer and the clock into the parsed input before the core
               sees it
  server       has only `admission`: no pin, no clock, no store, no fixture profile (`server.py`)

`fill` runs after parsing, so a malformed input never reaches the probe or the clock, and before the
steps, so the pure core is the same function in both. `genesis-check`, `genesis-aids` and the stateless commands read
neither pin nor clock. `vitni` is the verifier (CF-05), `render_size` the GP-15 step 5 check and
`load_profiles` the profile set (the one value every command reads: each epoch's registry comes from it); those two are parameters so a test can give others.
"""
from collections import namedtuple

from . import (admit, agreepoints, checkact, cli, compact, core, enrolled, foldcmd, genesis_aids, genesis_check, head,
               pool, profiles as profile_data, recheck, render_genesis, verifier)

Build = namedtuple("Build", "conformance allow_fixture")


def whole(handler):
    """The `opened` of a handler that does all of its work before it answers: `handler(value, memo)` runs in
    `opened`, and its `finish` returns what it found and asks nothing."""

    def opened(value, memo):
        out = handler(value, memo)
        return lambda: out

    return opened


def per_call(vitni, opened):
    """The `core.Command` that answers `opened(value, memo)()` with a new `verifier.Memoized(vitni)` for
    each call: the one place inside the checker where a call's memo is made. Every question of the
    call goes through it and nothing outlives the call (profile: verified once per call)."""

    def answer(value):
        return opened(value, verifier.Memoized(vitni))()

    return core.Command(answer, False)


def per_batch(vitni, opened, verdicts=None):
    """The `core.Command` that answers `opened(value, memo)()` in one verifier round when it can.

    A speculative pass runs `opened` and `finish` over a `verifier.Speculating` memo, which answers `ok` to a question
    it has no answer for and notes it, in the order it was first read: that finds the call's questions without a
    second copy of any rule, and `Malformed` or `Unparseable` leave it exactly as they leave one pass. One
    `verify_many` then answers every noted question. If all of them were `ok` the speculative pass read the real
    answers, so its output is the output. If only the questions `opened` read were all `ok`, what `opened` built is
    the real state: the memo settles on the real answers and `finish` runs again, over the state already built.
    Otherwise `opened` and `finish` run again over the real answers, in which a `Failed` is raised only where the
    fold reads it and a question the round did not hold is asked singly.
    `verdicts` (a `verifier.Verdicts`, or `None`) answers questions across calls and learns the verdicts of each
    round, never a `Failed`."""

    def answer(value):
        guess = verifier.Speculating(vitni, verdicts)
        finish = opened(value, guess)
        exact = len(guess.speculated)   # the questions the state `opened` built rests on
        out = finish()
        if not guess.speculated:
            return out   # nothing was guessed: this was the real fold
        results = vitni.verify_many(guess.speculated)
        answers = dict(zip(guess.speculated, results))
        if verdicts is not None:
            verdicts.learn(answers)
        if all(result == "ok" for result in results):
            return out
        if all(result == "ok" for result in results[:exact]):
            guess.settle(answers)
            return finish()
        return opened(value, verifier.Memoized(vitni, verdicts, answers))()

    return core.Command(answer, False)


def table(build, vitni, render_size=render_genesis.render_size, load_profiles=profile_data.load,
          fill=lambda inp: inp):
    """The command table of `build` over the verifier `vitni`. `fill` completes a parsed input with the
    `pin` and `now` the host supplies (production); the conformance build leaves the input as it is."""
    commands = dict(cli.PURE)

    def check_act(value, memo):
        inp = fill(checkact.parse_input(value, build.conformance))
        return checkact.run(inp, load_profiles(), build.allow_fixture, memo, render_size)

    def recheck_act(value, memo):
        inp = fill(recheck.parse_input(value, build.conformance))
        return recheck.run(inp, load_profiles(), build.allow_fixture, memo, render_size)

    def fold(value, memo):
        inp = fill(foldcmd.parse_input(value, build.conformance))
        return foldcmd.run(inp, load_profiles(), build.allow_fixture, memo, render_size)

    def enrolled_command(value, memo):
        inp = fill(enrolled.parse_input(value, build.conformance))
        return enrolled.run(inp, load_profiles(), build.allow_fixture, memo, render_size)

    def head_command(value, memo):
        inp = fill(head.parse_input(value, build.conformance))
        return head.run(inp, load_profiles(), build.allow_fixture, memo, render_size)

    def genesis_check_command(value, memo):
        return genesis_check.run(genesis_check.parse_input(value), load_profiles(),
                                 build.allow_fixture, memo, render_size)

    def genesis_aids_command(value, memo):
        return genesis_aids.run(genesis_aids.parse_input(value), load_profiles(),
                                build.allow_fixture, memo, render_size)

    commands["check-act"] = per_call(vitni, whole(check_act))
    commands["recheck-act"] = per_call(vitni, whole(recheck_act))
    commands["fold"] = per_call(vitni, whole(fold))
    commands["enrolled"] = per_call(vitni, whole(enrolled_command))
    commands["head"] = per_call(vitni, whole(head_command))
    commands["genesis-check"] = per_call(vitni, whole(genesis_check_command))
    commands["genesis-aids"] = per_call(vitni, whole(genesis_aids_command))
    return commands


def admission_handlers(build, render_size=render_genesis.render_size, load_profiles=profile_data.load):
    """The `opened(value, memo)` of `admit` (CF-11), `pool` (CF-12) and `compact` (CF-14) of `build`: the one place
    that wires them, under whichever strategy makes the call's memo. Their whole input is the snapshot of CF-13 and
    the item or the key (`compact`: the snapshot alone), so no `fill` exists for them: they read no pin, no clock
    and no store."""

    def admit_command(value, memo):
        return admit.opened(admit.parse_input(value), load_profiles(), build.allow_fixture, memo,
                            render_size)

    def pool_command(value, memo):
        return pool.run(pool.parse_input(value), load_profiles(), build.allow_fixture, memo,
                        render_size)

    def compact_command(value, memo):
        return compact.run(compact.parse_input(value), load_profiles(), build.allow_fixture, memo,
                           render_size)

    return {"admit": admit_command, "pool": whole(pool_command), "compact": whole(compact_command)}


def agree_points(build, render_size=render_genesis.render_size, load_profiles=profile_data.load):
    """The `opened(value, memo)` of `agree-points` of `build`: its input is the snapshot of CF-13 alone, like `compact`.
    It is no command of the server build until the spec text names it there (CF-10); wiring it is moving it into
    `admission_handlers`, in the change that publishes that text."""

    def agree_points_command(value, memo):
        return agreepoints.run(agreepoints.parse_input(value), load_profiles(), build.allow_fixture, memo,
                               render_size)

    return whole(agree_points_command)


def admission(build, vitni, render_size=render_genesis.render_size, load_profiles=profile_data.load, verdicts=None):
    """`admit`, `pool` and `compact` of `build` over the verifier `vitni`: the whole table of the server build, and
    the three commands the conformance build adds. Each asks `vitni` in one round (`per_batch`): they are called
    on stores that verify, where the speculative pass is the real one. `verdicts` is the memo across calls of a
    long-lived process, or `None`."""
    return {name: per_batch(vitni, handler, verdicts)
            for name, handler in admission_handlers(build, render_size, load_profiles).items()}
