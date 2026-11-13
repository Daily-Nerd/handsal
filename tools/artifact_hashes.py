"""Print the SHA-256 of each artifact of the production checker (SG-15, T7.3).

Usage: artifact_hashes.py [FILE ...]

With files, prints `<sha256>  <name>` for each, in the order given (the
`sha256sum` line form). With no argument, builds the artifacts of this tree in
a fresh temporary directory and prints:

  handsal-check.pyz   the zipapp (checker/python/packaging/build_zipapp.py)
  handsal-check       the macOS launcher text (checker/python/packaging/launcher.py)

then one line for each pinned interpreter archive of
`checker/python/packaging/interpreter.json`, whose values are the publisher's
(copied from its SHA256SUMS, not computed here). The upstream notices archive
(.tar.zst) is a packaging input, not an artifact: the installer reads the
gzip tar that `tools/pack_licenses.py` makes from it, and that tool prints the
line to publish for it. Two runs on one tree print the same text. Exit 0 on
success, 2 when a file cannot be read.

Standard library only.
"""
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "checker" / "python" / "packaging"


def _load(name):
    spec = importlib.util.spec_from_file_location("handsal_packaging_" + name, PACKAGING / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _line(digest, name):
    return "%s  %s\n" % (digest, name)


def built_lines():
    """The lines for a fresh build of this tree, then the pinned interpreter archive lines."""
    build_zipapp, launcher = _load("build_zipapp"), _load("launcher")
    lines = []
    with tempfile.TemporaryDirectory() as tmp:
        pyz = Path(tmp) / "handsal-check.pyz"
        build_zipapp.build(build_zipapp.SRC, pyz)
        script = Path(tmp) / "handsal-check"
        script.write_bytes(launcher.render_macos().encode("ascii"))
        lines.append(_line(sha256_of(pyz), pyz.name))
        lines.append(_line(sha256_of(script), script.name))
    pin = json.loads((PACKAGING / "interpreter.json").read_text(encoding="utf-8"))
    for platform in sorted(pin["platforms"]):
        item = pin["platforms"][platform]["archive"]
        lines.append(_line(item["sha256"], item["file"]))
    return lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        lines = [_line(sha256_of(p), Path(p).name) for p in argv] if argv else built_lines()
    except Exception as err:  # unreadable file or failed build: say so, print nothing
        print("artifact_hashes failed: %s" % err, file=sys.stderr)
        return 2
    sys.stdout.write("".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
