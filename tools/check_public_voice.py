"""Public-voice gate.

Scans text files for things that must not appear in a public repo:
em-dashes, tool or assistant attribution, session links, request-id
shapes, and internal names. The internal-name list is read from a file
given by --terms and must live outside the scanned tree.

Terms file: one term per line, case-insensitive. A line starting with
"=" matches whole words only; any other line matches as a substring.
Blank lines and lines starting with "#" are ignored.

Exit codes: 0 clean, 1 violations found, 2 usage or setup error.
"""

import argparse
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".claude", ".venv", ".build", "target", "__pycache__", "node_modules"}

EM_DASH = chr(0x2014)
ROBOT = chr(0x1F916)

# Written so that none of these patterns matches its own source text.
ATTRIBUTION = re.compile(
    r"co-author(?:ed)|generated\s+with|created\s+by\s+cla(?:ude)|"
    r"cla(?:ude)\.(?:ai|com)/|anthrop(?:ic)|"
    r"(?<![.\w/])cla(?:ude)(?!\w)|" + ROBOT,
    re.IGNORECASE,
)
REQUEST_ID = re.compile(r"\bq-[0-9a-f]{12}\b")

# An opaque token (a signature, a hash) is random base64url: a short internal
# name can occur in it by chance. Runs this long with a digit, an upper-case
# and a lower-case letter are treated as opaque for the internal-name check
# only. Every other check still reads the whole line.
OPAQUE_MIN = 40
OPAQUE_RUN = re.compile(r"[A-Za-z0-9_-]{%d,}" % OPAQUE_MIN)


def opaque_spans(line):
    return [
        m.span()
        for m in OPAQUE_RUN.finditer(line)
        if re.search(r"[0-9]", m.group(0))
        and re.search(r"[A-Z]", m.group(0))
        and re.search(r"[a-z]", m.group(0))
    ]


class SetupError(Exception):
    pass


def load_terms(path):
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise SetupError("cannot read terms file: %s" % e.strerror)
    patterns = []
    for line in raw.splitlines():
        term = line.strip()
        if not term or term.startswith("#"):
            continue
        if term.startswith("="):
            term = term[1:].strip()
            if not term:
                continue
            patterns.append(re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE))
        else:
            patterns.append(re.compile(re.escape(term), re.IGNORECASE))
    if not patterns:
        raise SetupError("terms file has no terms")
    return patterns


def iter_files(root):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel[:-1]) or (p.is_dir() and p.name in SKIP_DIRS):
            continue
        if p.is_file():
            yield p


def read_text(path):
    data = path.read_bytes()
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(text, terms):
    for n, line in enumerate(text.splitlines(), 1):
        if EM_DASH in line:
            yield n, "em-dash", EM_DASH_LABEL
        if ATTRIBUTION.search(line):
            yield n, "attribution", "attribution or session link"
        if REQUEST_ID.search(line):
            yield n, "request-id", "request id shape"
        spans = opaque_spans(line)
        for pat in terms:
            for m in pat.finditer(line):
                if any(a <= m.start() and m.end() <= b for a, b in spans):
                    continue
                yield n, "internal-name", m.group(0)
                break


EM_DASH_LABEL = "U+2014"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Public-voice gate")
    ap.add_argument("--terms", required=True, help="internal-name list, kept outside the repo")
    ap.add_argument("paths", nargs="*", help="files or directories (default: repo root)")
    args = ap.parse_args(argv)

    try:
        terms = load_terms(args.terms)
        roots = [Path(p) for p in args.paths] or [Path(__file__).resolve().parent.parent]
        for r in roots:
            if not r.exists():
                raise SetupError("no such path: %s" % r)
        terms_path = Path(args.terms).resolve()
        for r in roots:
            rr = r.resolve()
            if terms_path == rr or (rr.is_dir() and rr in terms_path.parents):
                raise SetupError("terms file is inside the scanned tree")
    except SetupError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    hits = 0
    for root in roots:
        for f in iter_files(root):
            text = read_text(f)
            if text is None:
                continue
            for n, cls, detail in scan_text(text, terms):
                print("%s:%d: %s: %s" % (f, n, cls, detail))
                hits += 1
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
