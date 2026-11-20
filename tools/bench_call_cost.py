"""Measure what one `admit`, `pool` or `compact` call costs over a long chain of `device.add` acts.

A store is one open epoch holding N linear `device.add` steps (three acts each, four verifier questions each). The
numbers that matter are the questions asked, the questions that reach the verifier, the bytes of the largest `keys`
object, the trees built, the verifier memos made and the wall time. Results go outside the repo and are never
committed: this script refuses to write inside it.

  bench_call_cost.py gen MAXN OUT            build a store of MAXN steps (plus one for the item), real ES256
  bench_call_cost.py measure STORE N --mode stub|count|real [--reps 3] [--commands admit,pool,compact,admit-refused]
  bench_call_cost.py cross STORE N --memo shared|fresh --mode stub|real
  bench_call_cost.py spawn STORE --sizes 10,100,1000 [--calls 40]
  bench_call_cost.py table RESULTS.jsonl...

Run it with the checker's environment and no ambient path:

  uv run --project checker/python python -I tools/bench_call_cost.py --help

`stub` is a verifier that answers `ok` with no instrumentation (CPU only). `count` runs the same stub with counters:
every question asked of a memo (`q_total`), every question that reaches the verifier under it (`q_unique`), the
memos made, the trees really built and the epochs made. `real` is the installed vitni, counted the same way, and
exits 2 when it is not installed. Every command prints JSON lines on stdout and progress on stderr.
"""
import argparse
import json
import sys
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CHECKER_SRC = ROOT / "checker" / "python" / "src"

# The checker of this checkout, never an installed copy: a module already imported from elsewhere would win over
# the path inserted here, so the identity of what was imported is checked.
sys.path.insert(0, str(CHECKER_SRC))
import handsal_check  # noqa: E402

_IMPORTED = Path(handsal_check.__file__).resolve().parent.parent
if _IMPORTED != CHECKER_SRC.resolve():
    raise ImportError("handsal_check was imported from %s, this checkout's checker is at %s" % (_IMPORTED, CHECKER_SRC))

from handsal_check import commands, encoding, fold, verifier  # noqa: E402   only after the identity check

COMMANDS = ("admit", "pool", "compact")
CASES = COMMANDS + ("admit-refused",)   # `admit-refused`: an item a verdict refuses, so the call folds twice (`per_batch`)
# the phase-1 CPU gate of `measure --mode stub`: seconds per command at N, with a verifier that costs nothing
LIMITS = {1000: 1.5, 3000: 5.0}
CLOCK = time.perf_counter   # the clock of every wall time; a test gives its own
SIGNERS = ("alice", "bob")   # sign every step; the new device belongs to one of them in turn
MODES = ("stub", "count", "real")


class Stub(verifier.Verifier):
    """A verifier that answers `ok` to everything: the cost of the checker alone."""

    def verify(self, jws, keys, method):
        return "ok"


class Refusing(verifier.Verifier):
    """`inner`, except that a text in `refused` is answered `bad_signature` whatever the keys: a verdict that refuses
    an item the one question about its primary."""

    def __init__(self, inner, refused):
        self.inner, self.refused = inner, frozenset(refused)

    def verify(self, jws, keys, method):
        return "bad_signature" if jws in self.refused else self.inner.verify(jws, keys, method)


class Tally:
    """What one call did, read from the counters below."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.total = self.unique = self.memos = self.builds = self.epochs = self.widest = 0
        self.rounds = self.singles = 0

    def counts(self):
        return {"q_total": self.total, "q_unique": self.unique, "rounds": self.rounds, "singles": self.singles,
                "memos": self.memos, "builds": self.builds, "epochs": self.epochs, "max_keys_bytes": self.widest}


class Counting(verifier.Verifier):
    """The verifier under the call's memo: it sees a question only when the memo had not seen it. A question asked
    singly is a `single`, a call of `verify_many` is a `round` (its questions count as unique ones, and go to `inner`
    as one round, so an `inner` that batches really batches)."""

    def __init__(self, inner, tally):
        self.inner, self.tally = inner, tally

    def verify(self, jws, keys, method):
        self.tally.unique += 1
        self.tally.singles += 1
        self.tally.widest = max(self.tally.widest, len(json.dumps(keys)))
        return self.inner.verify(jws, keys, method)

    def verify_many(self, questions):
        self.tally.rounds += 1
        self.tally.unique += len(questions)
        self.tally.widest = max([self.tally.widest] + [len(asked.keys) for asked in questions])
        return self.inner.verify_many(questions)


def instrumented(tally):
    """The patches that count, at runtime only: the memo classes (questions asked and memos made, the guess of a
    batched call and its real pass alike), `Epoch.build` (trees really built, a tree built twice counts twice) and
    `Epoch.__init__` (epochs made)."""
    real_build, real_init = fold.Epoch.build, fold.Epoch.__init__
    real_memo_init = verifier.Memoized.__init__

    def memo_init(memo, *args, **kwargs):
        tally.memos += 1
        real_memo_init(memo, *args, **kwargs)

    def counted(real):
        def verify(memo, jws, keys, method):
            tally.total += 1
            return real(memo, jws, keys, method)
        return verify

    def build(epoch):
        if not epoch._built:
            tally.builds += 1
        return real_build(epoch)

    def init(epoch, *args, **kwargs):
        tally.epochs += 1
        return real_init(epoch, *args, **kwargs)

    return (mock.patch.object(verifier.Memoized, "__init__", memo_init),
            mock.patch.object(verifier.Memoized, "verify", counted(verifier.Memoized.verify)),
            mock.patch.object(verifier.Speculating, "verify", counted(verifier.Speculating.verify)),
            mock.patch.object(fold.Epoch, "build", build), mock.patch.object(fold.Epoch, "__init__", init))


# ---- the store

def die(message):
    """Say why on stderr and exit 2: a refusal, never a crash."""
    print(message, file=sys.stderr)
    sys.exit(2)


def outside_repo(path):
    """`path` resolved, or exit 2 when it lies inside this repository."""
    resolved = Path(path).expanduser().resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        die("refused: %s is inside the repository, results are written outside it" % resolved)
    return resolved


def load(path, n=None):
    store = json.loads(Path(path).read_text())
    if n is not None and not 0 <= n < len(store["steps"]):
        die("N is %d, the store holds steps 0 to %d" % (n, len(store["steps"]) - 1))
    return store


def inputs_at(store, n):
    """The input of each command over the first `n` steps, the item being step `n`."""
    snap = {"acts": [act for step in store["steps"][:n] for act in step], "docs": store["docs"], "org": store["org"]}
    item = {"act": store["steps"][n][0], "sigs": store["steps"][n][1:]}
    return {"admit": {**snap, "item": item}, "pool": {**snap, "agree": store["agree"]["d0"]}, "compact": snap}


def generate(args):
    out = outside_repo(args.out)
    if out.exists():
        die("refused: %s exists" % out)
    sys.path[:0] = [str(ROOT / "checker" / "python"), str(ROOT / "conformance" / "vectors" / "_gen")]
    from lib import es256, keys as keygen, p256   # noqa: E402
    from tests import fold_world, genesis_fixtures   # noqa: E402

    registry = genesis_fixtures.KEYS   # this process's copy of the fixture keys: never written back
    scalars = {entry["kid"]: int(entry["d"], 16) for label, entry in registry.items() if label.endswith(".sign")}

    def add_key(label):
        d = keygen.derive_scalar(label)
        px, py = p256.mul(d)
        x, y = keygen.b64u(px.to_bytes(32, "big")), keygen.b64u(py.to_bytes(32, "big"))
        entry = {"d": "%064x" % d, "x": x, "y": y}
        if not label.endswith(".agree"):
            entry["kid"] = keygen.thumbprint(x, y)
            scalars[entry["kid"]] = d
        registry[label] = entry

    def resign(text):
        """The same act under a real ES256 signature of its own kid. A receipt id hashes the payload alone, so the
        ids and the links of the act survive."""
        head, payload, _ = text.split(".")
        kid = json.loads(encoding.b64u_decode(head))["kid"]
        sig = es256.sign(scalars[kid], (head + "." + payload).encode("ascii"))
        return ".".join((head, payload, encoding.b64u_encode(sig)))

    world = fold_world.World()
    docs = [{"doc": world.doc, "sigs": [resign(t) for t in world.sigs(world.doc, ("alice", "bob", "carol"))]}]
    steps, previous, started = [], None, time.time()
    for i in range(args.maxn + 1):   # step maxn is the item of a store of maxn steps
        name = "d%d" % i
        add_key(name + ".sign")
        add_key(name + ".agree")
        step = world.device_add(name, SIGNERS, previous, person=SIGNERS[i % 2])
        steps.append([resign(text) for text in step.acts])   # primary, endorsement, proof of the new key
        previous = step
        if i % 250 == 0:
            print("step %d, %.1f s" % (i, time.time() - started), file=sys.stderr, flush=True)
    agree = {n: {"x": registry[n + ".agree"]["x"], "y": registry[n + ".agree"]["y"]}
             for n in ("d0", "d%d" % (args.maxn // 2), "d%d" % args.maxn)}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"org": world.id, "docs": docs, "steps": steps, "agree": agree}))
    print(json.dumps({"stored": str(out), "steps": len(steps), "seconds": round(time.time() - started, 1)}))
    return 0


# ---- measure

def verifier_for(mode):
    if mode == "real":
        found = verifier.VitniCli.installed()
        if not isinstance(found, verifier.VitniCli):
            die("no vitni is installed at the path of this platform")
        return found
    return Stub()


def table_of(vitni):
    """The commands of the server build over `vitni`. The fixture profile is allowed: the store is made under it."""
    return commands.admission(commands.Build(conformance=False, allow_fixture=True), vitni)


def reason_of(out):
    return out.get("reason") if isinstance(out, dict) else None


def case_of(name, store, n, inner):
    """`(command, the verifier it runs over)` of the case `name`: `admit-refused` is `admit` over a verifier that
    answers `bad_signature` to the item's primary."""
    if name == "admit-refused":
        return "admit", Refusing(inner, {store["steps"][n][0]})
    return name, inner


def measure(args):
    store = load(args.store, args.n)
    inputs = inputs_at(store, args.n)
    wanted = [name for name in args.commands.split(",") if name]
    if not set(wanted) <= set(CASES):
        die("commands are among %s" % ", ".join(CASES))
    tally, inner = Tally(), verifier_for(args.mode)
    counted = args.mode != "stub"   # stub is pure CPU: no instrumentation
    limit = LIMITS.get(args.n) if args.mode == "stub" else None   # the CPU gate is a stub-mode check
    over = False
    for name in wanted:
        cmd, under = case_of(name, store, args.n, inner)
        table = table_of(Counting(under, tally) if counted else under)
        walls, best = [], None
        for _ in range(args.reps):
            tally.reset()
            patches = instrumented(tally) if counted else ()
            for patch in patches:
                patch.start()
            try:
                started = CLOCK()
                out = table[cmd].handler(inputs[cmd])
                wall = CLOCK() - started
            finally:
                for patch in reversed(patches):
                    patch.stop()
            walls.append(round(wall, 4))
            if best is None or wall < best[0]:
                best = (wall, tally.counts() if counted else {}, out)
        row = {"n": args.n, "cmd": name, "mode": args.mode, "wall_s": round(best[0], 4), "walls": walls,
               **best[1], "reason": reason_of(best[2])}
        if limit is not None:
            row["limit_s"], row["within"] = limit, best[0] <= limit
            over = over or not row["within"]
        print(json.dumps(row), flush=True)
    return 1 if over else 0


# ---- cross

class Spawns(verifier.Verifier):
    """Counts the questions that reach the verifier under every memo."""

    def __init__(self, inner):
        self.inner, self.n = inner, 0

    def verify(self, jws, keys, method):
        self.n += 1
        return self.inner.verify(jws, keys, method)


def cross(args):
    store = load(args.store, args.n + 1)
    base = Spawns(verifier_for(args.mode))
    vitni = verifier.Memoized(base) if args.memo == "shared" else base   # shared: one memo outlives the calls
    table = table_of(vitni)
    for label, cmd, at in (("admit@N", "admit", args.n), ("admit@N+1", "admit", args.n + 1),
                           ("pool@N+1", "pool", args.n + 1), ("compact@N+1", "compact", args.n + 1)):
        before, started = base.n, time.perf_counter()
        out = table[cmd].handler(inputs_at(store, at)[cmd])
        print(json.dumps({"n": args.n, "memo": args.memo, "mode": args.mode, "call": label,
                          "wall_s": round(time.perf_counter() - started, 3), "spawns": base.n - before,
                          "reason": reason_of(out)}), flush=True)
    return 0


# ---- spawn

class Capture(verifier.Verifier):
    """Keeps the last `device.add` question of a call and answers `ok`."""

    def __init__(self):
        self.last = None

    def verify(self, jws, keys, method):
        if method.endswith("device.add"):
            self.last = (jws, keys, method)
        return "ok"


def spawn(args):
    store, real = load(args.store), verifier_for("real")
    for size in (int(part) for part in args.sizes.split(",")):
        if size >= len(store["steps"]):
            die("size %d is past the store (%d steps)" % (size, len(store["steps"])))
        capture = Capture()
        table_of(capture)["pool"].handler(inputs_at(store, size)["pool"])
        jws, keys, method = capture.last
        stdin = json.dumps({"keys": keys, "policy": {"expected_binding": "local", "expected_method": method},
                            "signed_receipt": jws}, sort_keys=True, separators=(",", ":"))
        started = time.perf_counter()
        answers = {real.verify(jws, keys, method) for _ in range(args.calls)}
        per = (time.perf_counter() - started) / args.calls * 1000
        print(json.dumps({"n": size, "entries": sum(len(entries) for entries in keys.values()),
                          "stdin_bytes": len(stdin), "ms_per_spawn": round(per, 2), "answers": sorted(answers)}),
              flush=True)
    return 0


# ---- table

def table(args):
    rows = {}
    for path in args.results:
        for line in Path(path).read_text().splitlines():
            row = json.loads(line)
            if "cmd" not in row or "n" not in row:
                continue
            found = rows.setdefault((row["n"], row["cmd"]), {})
            if row["mode"] == "count":
                found["q_total"], found["q_unique"] = row["q_total"], row["q_unique"]
                found["max_keys_bytes"], found["memos"], found["builds"] = (
                    row["max_keys_bytes"], row["memos"], row["builds"])
            else:
                found[row["mode"]] = row["wall_s"]
    head = ("N", "cmd", "q total", "q unique", "stub (s)", "real (s)", "ms/spawn", "spawn share", "keys bytes", "memos",
            "builds")
    lines = [head]
    for (n, cmd), found in sorted(rows.items()):
        stub, real, unique = found.get("stub"), found.get("real"), found.get("q_unique")
        implied = share = None
        if None not in (stub, real, unique) and unique:
            implied, share = (real - stub) / unique * 1000, (real - stub) / real * 100
        lines.append((n, cmd, found.get("q_total"), unique, stub, real,
                      None if implied is None else "%.1f" % implied, None if share is None else "%.0f%%" % share,
                      found.get("max_keys_bytes"), found.get("memos"), found.get("builds")))
    cells = [["-" if cell is None else str(cell) for cell in line] for line in lines]
    widths = [max(len(line[i]) for line in cells) for i in range(len(head))]
    for line in cells:
        print("  ".join(cell.rjust(width) for cell, width in zip(line, widths)))
    return 0


def parser():
    top = argparse.ArgumentParser(prog="bench_call_cost.py", description=__doc__.split("\n")[0])
    sub = top.add_subparsers(dest="command", required=True)
    one = sub.add_parser("gen", help="build a store of MAXN steps plus the item step, outside the repo")
    one.add_argument("maxn", type=int)
    one.add_argument("out")
    one.set_defaults(run=generate)
    two = sub.add_parser("measure", help="time and count admit, pool and compact over the first N steps")
    two.add_argument("store")
    two.add_argument("n", type=int)
    two.add_argument("--mode", choices=MODES, required=True)
    two.add_argument("--reps", type=int, default=3)
    two.add_argument("--commands", default=",".join(CASES))
    two.set_defaults(run=measure)
    three = sub.add_parser("cross", help="admit at N and N+1, pool and compact on the grown store, one memo or fresh ones")
    three.add_argument("store")
    three.add_argument("n", type=int)
    three.add_argument("--memo", choices=("shared", "fresh"), required=True)
    three.add_argument("--mode", choices=("stub", "real"), required=True)
    three.set_defaults(run=cross)
    four = sub.add_parser("spawn", help="time real vitni spawns of the last device.add question of a pool call")
    four.add_argument("store")
    four.add_argument("--sizes", default="10,100,1000")
    four.add_argument("--calls", type=int, default=40)
    four.set_defaults(run=spawn)
    five = sub.add_parser("table", help="join measure rows of the three modes into one table")
    five.add_argument("results", nargs="+")
    five.set_defaults(run=table)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
