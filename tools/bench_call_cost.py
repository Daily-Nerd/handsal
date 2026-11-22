"""Measure what one call of each command of the server build costs over a long chain of `device.add` acts.

A store is one open epoch holding N linear `device.add` steps (three acts each, four verifier questions each). The
numbers that matter are the questions asked, the questions that reach the verifier, the bytes of the largest `keys`
object, the trees built, the verifier memos made and the wall time. Results go outside the repo and are never
committed: this script refuses to write inside it.

  bench_call_cost.py gen MAXN OUT            build a store of MAXN steps (plus one for the item), real ES256
  bench_call_cost.py measure STORE N --mode stub|count|real|batch [--reps 3] [--commands admit,pool,compact,admit-refused]
                                     [--vitni ABSOLUTE_ITEM]...
  bench_call_cost.py cross STORE N --memo shared|fresh --mode stub|real
  bench_call_cost.py spawn STORE --sizes 10,100,1000 [--calls 40]
  bench_call_cost.py bound OUT --mode stub [--cap BYTES] [--reps 3]
  bench_call_cost.py table RESULTS.jsonl...

Run it with the checker's environment and no ambient path:

  uv run --project checker/python python -I tools/bench_call_cost.py --help

`stub` is a verifier that answers `ok` with no instrumentation (CPU only). `count` runs the same stub with counters:
every question asked of a memo (`q_total`), every question that reaches the verifier under it (`q_unique`), the
memos made, the trees really built and the epochs made. `real` is the installed vitni, counted the same way, and
exits 2 when it is not installed. `batch` is the installed vitni asked through `VitniBatch`, one round per call:
its wall times are taken without the counting patches (a question left unanswered in any timed run still counts
as `failed`), the counts come from one counted run, and each row carries the
wall of the same call over `stub` (`stub_wall_s`) and c, `c_s = (wall_s - stub_wall_s) / q_unique`, the cost of one
verification over the cost of the checker alone. `--vitni` (once per argv item, as the conformance build takes it)
replaces the installed path for `real` and `batch`, for a test or a build outside the install path. A run in which
any question got no answer (`failed` above 0) exits 1: its numbers measure a failure. Every command prints JSON
lines on stdout and progress on stderr.
"""
import argparse
import importlib
import importlib.util
import json
import resource
import subprocess
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

from handsal_check import commands, encoding, fold, ijson, profiles, snapshot, verifier  # noqa: E402   only after the identity check

BUILD = commands.Build(conformance=False, allow_fixture=True)   # the server build; the fixture profile is allowed: the store is made under it
COMMANDS = tuple(commands.admission_handlers(BUILD))   # every command of the server's table, read from it: none can be missing here
CASES = COMMANDS + ("admit-refused",)   # `admit-refused`: an item a verdict refuses, so the finish stage runs again over the real answers (`per_batch`)
# the CPU gate of `measure --mode stub`: seconds per command at N, with a verifier that costs nothing
LIMITS = {1000: 1.5, 3000: 5.0}
CLOCK = time.perf_counter   # the clock of every wall time; a test gives its own
SIGNERS = ("alice", "bob")   # sign every step; the new device belongs to one of them in turn
MODES = ("stub", "count", "real", "batch")


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

    def verify_many(self, questions):
        """One inner round for the questions that are not refused, so a batching `inner` still batches."""
        live = iter(self.inner.verify_many([asked for asked in questions if asked.jws not in self.refused]))
        return ["bad_signature" if asked.jws in self.refused else next(live) for asked in questions]


class Tally:
    """What one call did, read from the counters below."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.total = self.unique = self.memos = self.builds = self.epochs = self.widest = 0
        self.rounds = self.singles = self.failed = 0

    def ask(self, questions):
        """`questions` reached the verifier: unique ones, and the widest `keys` among them (the canonical JSON the
        memo keys by and the process reads)."""
        self.unique += len(questions)
        self.widest = max([self.widest] + [len(asked.keys) for asked in questions])

    def process(self, command):
        """The verifier's process was asked `command`: `verify-batch` is a round, `verify` a single."""
        if command == "verify-batch":
            self.rounds += 1
        else:
            self.singles += 1

    def counts(self):
        return {"q_total": self.total, "q_unique": self.unique, "rounds": self.rounds, "singles": self.singles,
                "failed": self.failed, "memos": self.memos, "builds": self.builds, "epochs": self.epochs, "max_keys_bytes": self.widest}


class Counting(verifier.Verifier):
    """The verifier under the call's memo: it sees a question only when the memo had not seen it, and counts the
    questions that reach `inner` (its widest `keys`, its failures), however they arrive. Whether they cost one
    process or many is not known here, whatever the class of `inner`: `instrumented` counts the processes where
    they are spawned. Questions go to `inner` as they came, so an `inner` that batches really batches."""

    def __init__(self, inner, tally):
        self.inner, self.tally = inner, tally

    def verify(self, jws, keys, method):
        self.tally.ask([verifier.question(jws, keys, method)])
        try:
            return self.inner.verify(jws, keys, method)
        except verifier.VerifierUnavailable:
            self.tally.failed += 1
            raise

    def verify_many(self, questions):
        self.tally.ask(questions)
        got = self.inner.verify_many(questions)
        self.tally.failed += sum(type(item) is verifier.Failed for item in got)
        return got


def instrumented(tally):
    """The patches that count, at runtime only: the memo classes (questions asked and memos made, the guess of a
    batched call and its real pass alike), `Epoch.build` (trees really built, a tree built twice counts twice),
    `Epoch.__init__` (epochs made) and `VitniCli._run`, the one place a verifier process is spawned (rounds and
    singles: a count of the calls of an interface would not be one of the work done)."""
    real_build, real_init = fold.Epoch.build, fold.Epoch.__init__
    real_memo_init, real_run = verifier.Memoized.__init__, verifier.VitniCli._run

    def run(cli, command, stdin):
        tally.process(command)
        return real_run(cli, command, stdin)

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
            mock.patch.object(fold.Epoch, "build", build), mock.patch.object(fold.Epoch, "__init__", init),
            mock.patch.object(verifier.VitniCli, "_run", run))


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


def checker_tests(*names):
    """The test builders of the checker (`checker/python/tests`) as modules of a package of a private name: the
    package is called `tests` there, and so is the one of the tools' own tests, which may be running."""
    folder = ROOT / "checker" / "python" / "tests"
    spec = importlib.util.spec_from_file_location("_checker_tests", folder / "__init__.py",
                                                  submodule_search_locations=[str(folder)])
    package = importlib.util.module_from_spec(spec)
    sys.modules["_checker_tests"] = package
    spec.loader.exec_module(package)
    return [importlib.import_module("_checker_tests." + name) for name in names]


class Builder:
    """Real ES256 `device.add` steps of one organization, one after the other: step i adds the device `d<i>` under
    step i-1, signed by alice or bob in turn. Keys are made as they are needed and this process's copy of the fixture
    registry is never written back."""

    def __init__(self):
        sys.path.insert(0, str(ROOT / "conformance" / "vectors" / "_gen"))
        from lib import es256, keys as keygen, p256   # noqa: E402
        fold_world, genesis_fixtures = checker_tests("fold_world", "genesis_fixtures")

        self.es256, self.keygen, self.p256 = es256, keygen, p256
        self.registry = genesis_fixtures.KEYS
        self.scalars = {entry["kid"]: int(entry["d"], 16)
                        for label, entry in self.registry.items() if label.endswith(".sign")}
        self.world = fold_world.World()
        self.docs = [{"doc": self.world.doc,
                      "sigs": [self.resign(t) for t in self.world.sigs(self.world.doc, ("alice", "bob", "carol"))]}]
        self.previous = None
        self.made = 0

    def add_key(self, label):
        d = self.keygen.derive_scalar(label)
        px, py = self.p256.mul(d)
        x, y = self.keygen.b64u(px.to_bytes(32, "big")), self.keygen.b64u(py.to_bytes(32, "big"))
        entry = {"d": "%064x" % d, "x": x, "y": y}
        if not label.endswith(".agree"):
            entry["kid"] = self.keygen.thumbprint(x, y)
            self.scalars[entry["kid"]] = d
        self.registry[label] = entry

    def resign(self, text):
        """The same act under a real ES256 signature of its own kid. A receipt id hashes the payload alone, so the
        ids and the links of the act survive."""
        head, payload, _ = text.split(".")
        kid = json.loads(encoding.b64u_decode(head))["kid"]
        sig = self.es256.sign(self.scalars[kid], (head + "." + payload).encode("ascii"))
        return ".".join((head, payload, encoding.b64u_encode(sig)))

    def step(self):
        """The acts of the next step: primary, endorsement, proof of the new key."""
        name = "d%d" % self.made
        self.add_key(name + ".sign")
        self.add_key(name + ".agree")
        step = self.world.device_add(name, SIGNERS, self.previous, person=SIGNERS[self.made % 2])
        self.previous = step
        self.made += 1
        return [self.resign(text) for text in step.acts]

    def agree(self, names):
        return {n: {"x": self.registry[n + ".agree"]["x"], "y": self.registry[n + ".agree"]["y"]} for n in names}

    def store(self, steps, agree):
        return {"org": self.world.id, "docs": self.docs, "steps": steps, "agree": agree}


def write_store(out, store):
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(store))


def snapshot_bytes(snap):
    """The bytes of the JCS of the snapshot `{acts, docs, org}`: the size CF-11 and CF-13 bound."""
    return snapshot.canonical_size(snapshot.parse(snap)[0])


def step_bytes(step):
    """What the acts of one step add to a snapshot: each text, its quotes and a comma."""
    return sum(len(act) + 3 for act in step)


def generate(args):
    out = outside_repo(args.out)
    if out.exists():
        die("refused: %s exists" % out)
    builder, steps, started = Builder(), [], time.time()
    for i in range(args.maxn + 1):   # step maxn is the item of a store of maxn steps
        steps.append(builder.step())
        if i % 250 == 0:
            print("step %d, %.1f s" % (i, time.time() - started), file=sys.stderr, flush=True)
    write_store(out, builder.store(steps, builder.agree(("d0", "d%d" % (args.maxn // 2), "d%d" % args.maxn))))
    print(json.dumps({"stored": str(out), "steps": len(steps), "seconds": round(time.time() - started, 1)}))
    return 0


# ---- measure

def verifier_for(mode, argv=None):
    """The verifier of `mode`: `real` and `batch` are the installed vitni, or the one at `argv` (no owner check:
    the caller named it). `stub` and `count` need none."""
    if argv is not None and mode not in ("real", "batch"):
        die("--vitni is for --mode real or batch")
    if mode in ("real", "batch"):
        kind = verifier.VitniBatch if mode == "batch" else verifier.VitniCli
        found = kind(argv, owner_check=None) if argv else kind.installed()
        if not isinstance(found, kind):
            die("no vitni is installed at the path of this platform")
        return found
    return Stub()


def table_of(vitni):
    """The commands of the server build over `vitni`."""
    return commands.admission(BUILD, vitni)


def reason_of(out):
    return out.get("reason") if isinstance(out, dict) else None


def peak_rss_mib():
    """The peak resident memory of this process so far, in MiB (macOS counts bytes, Linux KiB)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round((peak if sys.platform == "darwin" else peak * 1024) / 1048576, 1)


def case_of(name, store, n, inner):
    """`(command, the verifier it runs over)` of the case `name`: `admit-refused` is `admit` over a verifier that
    answers `bad_signature` to the item's primary. `inner` is the verifier that counts, so the refused question,
    answered here, is not counted as one that reached it."""
    if name == "admit-refused":
        return "admit", Refusing(inner, {store["steps"][n][0]})
    return name, inner


def attempt(table, cmd, inputs, tally, counted, watched=False):
    """`(wall, counts, output)` of one call of `cmd` over `table`, with the counters on when `counted`. `watched`
    keeps the counts of a table whose verifier is a `Counting` without the patches that slow the call."""
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
    return wall, (tally.counts() if counted or watched else {}), out


def best_of(reps, table, cmd, inputs, tally, counted, watched=False):
    """`(all walls, the fastest attempt, the most questions left unanswered in any attempt)` of `reps` attempts."""
    walls, best, failed = [], None, 0
    for _ in range(reps):
        got = attempt(table, cmd, inputs, tally, counted, watched)
        walls.append(round(got[0], 4))
        failed = max(failed, got[1].get("failed", 0))
        if best is None or got[0] < best[0]:
            best = got
    return walls, best, failed


def batch_row(name, store, n, inner, inputs, tally, reps):
    """The row of one case through a batching verifier: uninstrumented walls, the same call over the stub, then one
    counted run for the questions (in that order, so a test can script the clock)."""
    cmd, under = case_of(name, store, n, Counting(inner, tally))
    walls, best, failed = best_of(reps, table_of(under), cmd, inputs, tally, False, True)
    stub_cmd, stub_under = case_of(name, store, n, Stub())
    _, stub, _ = best_of(reps, table_of(stub_under), stub_cmd, inputs, tally, False)
    _, counts, _ = attempt(table_of(under), cmd, inputs, tally, True)
    counts["failed"] = max(failed, counts["failed"])   # a timed run that got no answer is a failed measurement too
    return {"wall_s": round(best[0], 4), "walls": walls, "stub_wall_s": round(stub[0], 4),
            "c_s": round((best[0] - stub[0]) / counts["q_unique"], 6), **counts, "reason": reason_of(best[2])}


def measure(args):
    store = load(args.store, args.n)
    inputs = inputs_at(store, args.n)
    wanted = [name for name in args.commands.split(",") if name]
    if not set(wanted) <= set(CASES):
        die("commands are among %s" % ", ".join(CASES))
    tally, inner = Tally(), verifier_for(args.mode, args.vitni)
    counted = args.mode in ("count", "real")   # stub is pure CPU: no instrumentation; batch counts in a run of its own
    limit = LIMITS.get(args.n) if args.mode == "stub" else None   # the CPU gate is a stub-mode check
    over = False
    for name in wanted:
        if args.mode == "batch":
            row = {"n": args.n, "cmd": name, "mode": args.mode, **batch_row(name, store, args.n, inner, inputs, tally, args.reps)}
        else:
            cmd, under = case_of(name, store, args.n, Counting(inner, tally) if counted else inner)
            table = table_of(under)
            walls, best, failed = best_of(args.reps, table, cmd, inputs, tally, counted)
            row = {"n": args.n, "cmd": name, "mode": args.mode, "wall_s": round(best[0], 4), "walls": walls,
                   **best[1], "reason": reason_of(best[2])}
            if counted:
                row["failed"] = failed   # a failed run is a failed measurement even when it was not the fastest
        row["peak_rss_mib"] = peak_rss_mib()
        if limit is not None:
            row["limit_s"], row["within"] = limit, row["wall_s"] <= limit
            over = over or not row["within"]
        over = over or row.get("failed", 0) > 0   # a question that got no answer: the numbers measure a failure
        print(json.dumps(row), flush=True)
    return 1 if over else 0


# ---- bound

def default_cap():
    """The bytes an act group is admitted under (CF-11): the input limit less two reserves, read from the registry."""
    return ijson.MAX_INPUT - 2 * profiles.load().wire.number("ADMIT_RESERVE")


def measured(store, n, cmd, mode, reps):
    """The row `measure` prints for `cmd` over the first `n` steps, from a process of its own, so that its peak
    memory is that of the call (and the store it reads) and not of whatever ran before it."""
    done = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "measure", str(store), str(n),
                           "--mode", mode, "--reps", str(reps), "--commands", cmd],
                          capture_output=True, text=True, check=False)
    if done.returncode not in (0, 1) or not done.stdout.strip():   # 1 is a missed CPU limit, still a measurement
        die("measure %s failed (status %d): %s" % (cmd, done.returncode, done.stderr.strip()))
    return json.loads(done.stdout.strip().splitlines()[-1])


def bound(args):
    """The largest admit-closed store whose snapshot, item included, is at most `--cap` bytes, and what each command
    costs over it. Steps are made until the next one would not fit; the last one that fits is the item."""
    out = outside_repo(args.out)
    if out.exists():
        die("refused: %s exists" % out)
    builder, steps, started = Builder(), [], time.time()
    empty = snapshot_bytes({"acts": [], "docs": builder.docs, "org": builder.world.id})
    used = empty - 1   # the acts array of n texts holds sum(len + 2) + (n - 1) bytes: step_bytes counts one comma too many
    while True:
        step = builder.step()
        if used + step_bytes(step) > args.cap:
            break
        steps.append(step)
        used += step_bytes(step)
        if len(steps) % 250 == 0:
            print("step %d, %.1f s" % (len(steps), time.time() - started), file=sys.stderr, flush=True)
    if len(steps) < 2:
        die("the cap of %d bytes holds no store and item" % args.cap)
    store = builder.store(steps, builder.agree(("d0",)))
    store_bytes = snapshot_bytes({"acts": [act for step in steps for act in step], "docs": store["docs"],
                                  "org": store["org"]})
    if store_bytes != used:
        die("internal: the size of the store is %d, counted %d" % (store_bytes, used))
    write_store(out, store)
    n = len(steps) - 1
    texts = [act for step in steps[:n] for act in step] + [sig for entry in store["docs"] for sig in entry["sigs"]]
    for cmd in COMMANDS:
        timed, counted = measured(out, n, cmd, "stub", args.reps), measured(out, n, cmd, "count", 1)
        print(json.dumps({"cmd": cmd, "mode": "stub", "cap_bytes": args.cap, "store_bytes": store_bytes, "steps": n,
                          "kept_sigs": len(texts), "s_min": min(len(text) for text in texts),
                          "q_unique": counted["q_unique"], "wall_best_s": timed["wall_s"],
                          "wall_worst_s": max(timed["walls"]), "peak_rss_mib": timed["peak_rss_mib"],
                          "reason": timed["reason"]}), flush=True)
    return 0


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
    two = sub.add_parser("measure", help="time and count each server command over the first N steps")
    two.add_argument("store")
    two.add_argument("n", type=int)
    two.add_argument("--mode", choices=MODES, required=True)
    two.add_argument("--reps", type=int, default=3)
    two.add_argument("--commands", default=",".join(CASES))
    two.add_argument("--vitni", action="append", help="one item of the vitni argv, the first absolute (real, batch)")
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
    six = sub.add_parser("bound", help="the largest admit-closed store under a byte cap, and what a call over it costs")
    six.add_argument("out")
    six.add_argument("--mode", choices=("stub",), required=True)   # the real batch verifier is measured on the relay host
    six.add_argument("--cap", type=int, default=default_cap())
    six.add_argument("--reps", type=int, default=3)
    six.set_defaults(run=bound)
    five = sub.add_parser("table", help="join measure rows of the three modes into one table")
    five.add_argument("results", nargs="+")
    five.set_defaults(run=table)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
