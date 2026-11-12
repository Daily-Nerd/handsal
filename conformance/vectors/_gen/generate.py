"""Vector generator driver (CF-06, T2.8).

    uv run --no-project --with ecdsa --with cryptography python -I \\
        conformance/vectors/_gen/generate.py [--out DIR] [--check]

Runs every module of `groups.REGISTRY` in order against one writer, so a vector
name is unique across groups and, with the shipping id list, must be one of the
shipped ids. Anchors are authored here from the expected behaviour, never by
running a checker (CF-06).

`--check` generates into a scratch directory and compares it with DIR: a
missing, extra (stale) or changed file is reported and the exit status is 1.
Without `--out` the target is `conformance/vectors`.

Every positive act a group writes is recorded through `ctx.positive`. Given
`--vitni-go` and `--vitni-ts` (absolute paths, both or neither), both vitni
binaries judge each one and the run aborts unless both say `ok` (CF-06). Without
them the run says how many positives were not judged, so the gap is never silent.
"""
import argparse
import importlib
import json
import sys
import shlex
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import groups  # noqa: E402
from lib import base, vitni, writer  # noqa: E402

CONFORMANCE = HERE.parents[1]
VECTORS = CONFORMANCE / "vectors"
IDS = CONFORMANCE / "vector-ids.json"


class Context:
    """What a group module gets: the writer and the base fixtures."""

    def __init__(self, vector_writer, profile, crosscheck=None):
        self.writer = vector_writer
        self.profile = profile
        self.crosscheck = crosscheck
        self.positives = 0
        self.negatives = 0
        self._judged = set()
        self._fixtures = None

    @property
    def fixtures(self):
        if self._fixtures is None:
            self._fixtures = base.Fixtures(self.profile)
        return self._fixtures


    def positive(self, jws, method, signers):
        """Record a positive act: vitni must say `ok` for it under `signers`' keys.

        An act already recorded is not judged again (many vectors share a lineage).
        """
        self._positive(jws, self.fixtures.keyset(signers), base.vitni_policy(method))

    def _positive(self, jws, keys, policy):
        if jws in self._judged:
            return
        self._judged.add(jws)
        self.positives += 1
        if self.crosscheck is not None:
            self.crosscheck.positive(jws, keys, policy)

    def _relay_keys(self):
        """WT-05 step 4: the one-entry map vitni gets for a tip statement."""
        relay = self.fixtures.relay
        return {"relay": {relay.kid: dict(relay.jwk(), alg="ES256", status="active")}}

    def positive_statement(self, jws):
        """Record a tip statement whose signature must verify under the relay key."""
        self._positive(jws, self._relay_keys(), base.vitni_policy(base.RELAY_TIP))

    def negative_statement(self, jws, reason):
        """A tip statement vitni must refuse with `reason` under the relay key (WT-05 step 4)."""
        self.negatives += 1
        if self.crosscheck is not None:
            got = self.crosscheck.negative(jws, self._relay_keys(),
                                           base.vitni_policy(base.RELAY_TIP))
            if got != reason:
                raise vitni.VitniAbort("vitni says %s, the vector expects %s" % (got, reason))


    def negative(self, jws, method, signers, reason, revoked=()):
        """Record a negative act: both vitni binaries must give `reason` (CF-06).

        `signers` name the devices whose keys vitni gets, `revoked` the ones marked
        revoked. A different verdict aborts the run, so a vitni divergence or a
        wrong expectation is found at generation time.
        """
        self.negatives += 1
        if self.crosscheck is not None:
            got = self.crosscheck.negative(jws, self.fixtures.keyset(signers, revoked=revoked),
                                           base.vitni_policy(method))
            if got != reason:
                raise vitni.VitniAbort("vitni says %s, the vector expects %s" % (got, reason))


def shipping_ids():
    return frozenset(json.loads(IDS.read_text(encoding="utf-8"))["ids"])


def load_registry():
    return [importlib.import_module("groups." + name) for name in groups.REGISTRY]


def run(out_dir, registry=None, known_ids=None, profile=None, crosscheck=None, stats=None):
    """Write every vector into `out_dir`; return the names in write order.

    `crosscheck` (a lib.vitni.CrossCheck) judges every positive act. `stats`, a
    dict, receives `positives`: how many positive acts the groups recorded.

    Existing `*.json` files directly inside `out_dir` are removed first, so the
    directory holds exactly this run's output and a dropped vector cannot linger.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.json"):
        stale.unlink()
    registry = load_registry() if registry is None else registry
    vector_writer = writer.VectorWriter(out_dir, known_ids)
    ctx = Context(vector_writer, profile or base.fixture_profile(), crosscheck)
    for module in registry:
        module.generate(ctx)
    if stats is not None:
        stats["positives"] = ctx.positives
        stats["negatives"] = ctx.negatives
    return list(vector_writer.names)


def compare_dirs(a, b):
    """Differences of the `*.json` files of `a` against `b`.

    `missing X`: only in b. `extra X`: only in a. `differs X`: bytes differ.
    """
    a, b = Path(a), Path(b)
    in_a = {p.name for p in a.glob("*.json")}
    in_b = {p.name for p in b.glob("*.json")}
    out = ["missing " + n for n in sorted(in_b - in_a)]
    out += ["extra " + n for n in sorted(in_a - in_b)]
    out += ["differs " + n for n in sorted(in_a & in_b)
            if (a / n).read_bytes() != (b / n).read_bytes()]
    return out


def check_reproducible(registry=None, known_ids=None):
    """Run twice into scratch directories; the differences (empty: identical)."""
    with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
        run(one, registry, known_ids)
        run(two, registry, known_ids)
        return compare_dirs(one, two)


def check_dir(target, registry=None, known_ids=None, crosscheck=None, stats=None):
    """Differences between `target` and a fresh run (empty: it is up to date)."""
    with tempfile.TemporaryDirectory() as fresh:
        run(fresh, registry, known_ids if known_ids is not None else shipping_ids(),
            crosscheck=crosscheck, stats=stats)
        return compare_dirs(target, fresh)


def _crosscheck(args):
    """A CrossCheck from the two binary options, None when neither is given."""
    if args.vitni_go is None and args.vitni_ts is None:
        return None
    crosscheck = vitni.CrossCheck(shlex.split(args.vitni_go), shlex.split(args.vitni_ts))
    crosscheck.preflight()
    return crosscheck


def main(argv=None):
    parser = argparse.ArgumentParser(prog="generate.py")
    parser.add_argument("--out", default=str(VECTORS))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--vitni-go", default=None, help="absolute argv of the Go vitni verifier")
    parser.add_argument("--vitni-ts", default=None, help="absolute argv of the TypeScript verifier")
    args = parser.parse_args(argv)
    if (args.vitni_go is None) != (args.vitni_ts is None):
        print("--vitni-go and --vitni-ts are given together or not at all", file=sys.stderr)
        return 2
    stats = {}
    try:
        crosscheck = _crosscheck(args)
        if args.check:
            problems = check_dir(args.out, crosscheck=crosscheck, stats=stats)
            for line in problems:
                print(line)
            status = 1 if problems else 0
        else:
            names = run(args.out, known_ids=shipping_ids(), crosscheck=crosscheck, stats=stats)
            print("%d vectors written to %s" % (len(names), args.out))
            status = 0
    except vitni.VitniAbort as err:
        print("vitni cross-check aborted the run: %s" % err, file=sys.stderr)
        return 1
    if crosscheck is None:
        print("vitni cross-check not run: %d positive and %d negative acts not judged (CF-06)"
              % (stats["positives"], stats["negatives"]), file=sys.stderr)
    else:
        print("vitni cross-check: %d positive acts judged ok by both binaries, "
              "%d negative acts judged with the expected reason"
              % (stats["positives"], stats["negatives"]), file=sys.stderr)
    return status


if __name__ == "__main__":
    sys.exit(main())
