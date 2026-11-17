"""Turn the public report of make_prodk.py into the evidence note of a PRODK run. Public values only.

    python -I prodk_evidence.py REPORT.json OUT.md --commit SHA --branch NAME --harness LINE --proof LINE [--task ID]

Everything that belongs to one release comes in with the run: the date and the production profile from the
report, the commit and the branch, the harness line and the final-proof line the run printed, and the task row
when the caller names one. OUT must not exist: the note of an earlier run is never overwritten.

Exit 0 written, 2 usage, a report or a value that cannot be used, or an OUT that exists.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPORT_KEYS = ("created_utc", "production_profile", "python", "pid", "people", "files", "files_scanned", "scan_roots",
               "scalars_held")


class EvidenceError(Exception):
    pass


def _check(label, value, pattern):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise EvidenceError("%s is not usable in the note: %r" % (label, value))
    return value


def _field(report, key, kind, pattern=None):
    value = report[key]
    if kind == "int":
        ok = isinstance(value, int) and not isinstance(value, bool) and value >= 0
    else:
        ok = isinstance(value, str) and re.fullmatch(pattern, value) is not None
    if not ok:
        raise EvidenceError("the report: %s is not usable in the note: %r" % (key, value))


def _mapping(report, key, key_pattern, value_pattern):
    value = report[key]
    if not isinstance(value, dict) or not all(
            isinstance(k, str) and re.fullmatch(key_pattern, k) and isinstance(v, str) and re.fullmatch(value_pattern, v)
            for k, v in value.items()):
        raise EvidenceError("the report: %s is not usable in the note: %r" % (key, value))


def check_report(report):
    """The shape of the report, checked once where it comes in. Everything below may then assume it."""
    missing = [k for k in REPORT_KEYS if k not in report]
    if missing:
        raise EvidenceError("the report lacks %s" % ", ".join(missing))
    _field(report, "created_utc", "str", r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
    _field(report, "production_profile", "str", r"[A-Za-z0-9_-]+")
    _field(report, "python", "str", r"[0-9A-Za-z.+-]+")
    for key in ("pid", "files_scanned", "scalars_held"):
        _field(report, key, "int")
    _mapping(report, "people", r"[A-Za-z0-9_-]+", r"[A-Za-z0-9_-]+")
    _mapping(report, "files", r"[A-Za-z0-9._-]+", r"[0-9a-f]{64}")
    roots = report["scan_roots"]
    if not isinstance(roots, list) or not all(isinstance(r, str) and re.fullmatch(r"[^\n\r`]+", r) for r in roots):
        raise EvidenceError("the report: scan_roots is not usable in the note: %r" % (roots,))


def render(report, commit, branch, harness, proof, task=None):
    check_report(report)
    _check("commit", commit, r"[0-9a-f]{40}")
    _check("branch", branch, r"[A-Za-z0-9._/-]+")
    _check("harness line", harness, r"[^\n\r`]+")
    _check("proof line", proof, r"[^\n\r`]+")
    if task is not None:
        _check("task", task, r"[A-Za-z0-9.]+")
    rows = "\n".join("| %s | `%s` |" % (p, k) for p, k in sorted(report["people"].items()))
    files = "\n".join("| `%s` | `%s` |" % (n, d) for n, d in sorted(report["files"].items()))
    roots = ", ".join("`%s`" % r for r in report["scan_roots"])
    task_line = "task: %s\n" % task if task is not None else ""
    return """---
type: evidence
status: final
date: %(day)s
project: "[[handsal]]"
change: profile-spec
%(task)s---

# PRODK evidence: production keys generated, used once, destroyed

- Signed at (UTC): %(when)s
- Repo base: branch `%(branch)s`, commit `%(commit)s` (the vectors are in the working tree, not committed: the run never commits)
- Production profile named by every vector: `%(profile)s`
- Signing process: one Python %(python)s process (pid %(pid)s), now ended

## Public keys (thumbprints, RFC 7638)

| Person | kid |
|---|---|
%(rows)s

These kids are not in `conformance/fixtures/fixture-kids.json` (a test checks it) and no private scalar is in the repository.

## Vector files (SHA-256)

| File | sha256 |
|---|---|
%(files)s

## What was destroyed, and how

- Three signing scalars (alice, bob, carol), drawn from the operating system's random source (`secrets`) in the memory of the signing process. They were never written by the process: not to a key file, a vector, the report, a log, an argument or the environment. The vitni verifiers received only public keys.
- The three agreement keys of the organization were drawn the same way, only to compute their public points. No scalar of theirs was kept (nothing in any vector uses one).
- Destruction method: the process ended. Core dumps were disabled for it (`ulimit -c 0` in the script, and the process sets its own soft limit to 0).
- Check before it ended: the process scanned %(scanned)s files under %(roots)s for the %(held)s scalars in six encodings (raw 32 bytes, lower and upper hex, base64url, base64, decimal) and found none.
- Check of the owner-signed vectors: the checker harness and both vitni builds passed every one of them before they were installed. Harness result at install time: `%(harness)s`.
- Final proof of the tree with the vectors installed, as the run printed it: `%(proof)s`.

## What cannot be guaranteed

- CPython integers cannot be overwritten. The scalars stay in freed process memory until the operating system reuses those pages. They were never put on disk by this program, but the operating system may swap process memory (macOS encrypts swap), and this note cannot prove a negative about RAM or swap on the machine.
- The scan covers the paths and encodings named above. It is not a proof about the whole disk or about a scalar embedded in another encoding.
- The arithmetic is the generator's pure Python (variable time). That is acceptable for one local run of keys that protect nothing once the scalars are gone, and it is not constant-time cryptography.
- Whoever ran the command could have copied the memory of the process while it ran. The control is the person at the keyboard and the machine, not this note.
""" % {
        "day": report["created_utc"][:10], "when": report["created_utc"], "branch": branch, "commit": commit,
        "profile": report["production_profile"], "python": report["python"], "pid": report["pid"], "rows": rows,
        "files": files, "scanned": report["files_scanned"], "roots": roots, "held": report["scalars_held"],
        "harness": harness, "proof": proof, "task": task_line,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="prodk_evidence.py", add_help=False)
    parser.add_argument("report")
    parser.add_argument("out")
    for flag in ("--commit", "--branch", "--harness", "--proof"):
        parser.add_argument(flag, required=True)
    parser.add_argument("--task", default=None)
    parser.error = lambda message: (_ for _ in ()).throw(EvidenceError("usage: %s" % message))
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
        out = Path(args.out)
        if out.exists():
            raise EvidenceError("%s exists: the note of an earlier run is not overwritten" % out)
        try:
            report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            raise EvidenceError("cannot read the report %s: %s" % (args.report, err)) from err
        if not isinstance(report, dict):
            raise EvidenceError("the report is not an object")
        text = render(report, args.commit, args.branch, args.harness, args.proof, args.task)
    except EvidenceError as err:
        print("prodk_evidence: %s" % err, file=sys.stderr)
        return 2
    except SystemExit:
        print("prodk_evidence: usage: prodk_evidence.py REPORT OUT --commit SHA --branch NAME --harness LINE --proof LINE [--task ID]", file=sys.stderr)
        return 2
    out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
