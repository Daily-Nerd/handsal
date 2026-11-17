"""Sign the owner-signed production-key vectors once (PRODK, CF-08).

    uv run --project conformance/vectors/_gen python -I \\
        conformance/vectors/_gen/make_prodk.py --out DIR --evidence FILE \\
        --vitni-go ARGV --vitni-ts ARGV [--scan-root DIR ...]

Draws three production signing keys in the memory of this process, signs the vectors named by the
`pending` list of conformance/vector-ids.json, has both vitni builds judge every act, scans DIR and each
`--scan-root` for the scalars, writes the public report to FILE and ends. The scalars exist in no file and
no argument; they are gone with the process. DIR must be absent or empty. See lib/prodk.py for the
invariants and the limits.

Exit 0 done, 1 a check or the scan failed (nothing is left in DIR), 2 usage.
"""
import argparse
import json
import resource
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from lib import prodk, vitni  # noqa: E402


def no_core_dumps():
    """A crash must not write the process memory to disk. Only the soft limit moves, so a test can restore it."""
    _soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, hard))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="make_prodk.py")
    parser.add_argument("--out", required=True)
    parser.add_argument("--evidence", required=True, help="where the public report goes; must not exist")
    parser.add_argument("--scan-root", action="append", default=[])
    parser.add_argument("--vitni-go", default=None, help="absolute argv of the Go vitni verifier")
    parser.add_argument("--vitni-ts", default=None, help="absolute argv of the TypeScript verifier")
    args = parser.parse_args(argv)
    if args.vitni_go is None or args.vitni_ts is None:
        print("both --vitni-go and --vitni-ts are required: production vectors are never signed unjudged",
              file=sys.stderr)
        return 2
    evidence = Path(args.evidence)
    if evidence.exists():
        print("%s exists: the report of an earlier run is not overwritten" % evidence, file=sys.stderr)
        return 2
    no_core_dumps()
    try:
        crosscheck = vitni.CrossCheck(shlex.split(args.vitni_go), shlex.split(args.vitni_ts))
        crosscheck.preflight()
        report = prodk.run(args.out, args.scan_root, crosscheck=crosscheck)
    except (prodk.ProdkError, vitni.VitniAbort) as err:
        print("production vectors not written: %s" % err, file=sys.stderr)
        return 1
    evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("signed %d vectors into %s" % (len(report["files"]), args.out))
    for person, kid in sorted(report["people"].items()):
        print("  %-6s kid %s" % (person, kid))
    print("scanned %d files for %d scalars in six encodings: none found" % (report["files_scanned"], report["scalars_held"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
