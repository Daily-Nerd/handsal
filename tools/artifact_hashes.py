"""Print the SHA-256 of each artifact of the production checker (SG-15, T7.3).

Usage: artifact_hashes.py [FILE ...]
       artifact_hashes.py --release DIR --platform macos-arm64

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

`--release DIR --platform P` prints the lines to publish for a tag: exactly the six artifacts the installer's
closed list names (tools/install/install-lib.sh), in the order it checks them, read from DIR. DIR must hold
those six regular files and nothing else. The zipapp and the launcher must be the bytes this tree builds,
and the interpreter archive the pinned one (its SHA-256 is the publisher's, from `interpreter.json`); the
other three (the verifier, the pin helper, the packed licences) are built elsewhere and printed as they are.
Anything else is a refusal with nothing on stdout: exit 2 when DIR is not the closed list, 1 when an
artifact is not what this tree builds or pins.

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


class ReleaseError(Exception):
    """A refusal. `code` is the exit status: 2 for a directory that is not the closed list, 1 for an artifact
    that is not what this tree builds or pins."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


# The first four names of the installer's closed list; the other two come from the pin file, per platform.
# tools/tests/test_artifact_hashes.py compares this with the loop in tools/install/install-lib.sh.
FIXED_ARTIFACTS = ("vitni-verify", "handsal-pin", "handsal-check", "handsal-check.pyz")


def release_lines(directory, platform, pin=None):
    """The lines to publish for the tag, in installer order, after the checks of the module note."""
    directory = Path(directory)
    pin = pin if pin is not None else json.loads((PACKAGING / "interpreter.json").read_text(encoding="utf-8"))
    row = pin["platforms"].get(platform)
    if row is None or "packed_licenses" not in row:
        raise ReleaseError("no pinned interpreter and packed licences for platform %r (one of %s)"
                           % (platform, ", ".join(sorted(p for p, r in pin["platforms"].items() if "packed_licenses" in r))))
    names = list(FIXED_ARTIFACTS) + [row["archive"]["file"], row["packed_licenses"]["file"]]
    try:
        present = sorted(entry.name for entry in directory.iterdir())
    except OSError as err:
        raise ReleaseError("cannot read %s: %s" % (directory, err)) from err
    missing = [n for n in names if n not in present]
    extra = [n for n in present if n not in names]
    if missing or extra:
        raise ReleaseError("%s is not the installer's closed list (missing: %s; not on the list: %s)"
                           % (directory, ", ".join(missing) or "none", ", ".join(extra) or "none"))
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ReleaseError("%s is not a regular file" % name)
    build_zipapp, launcher = _load("build_zipapp"), _load("launcher")
    with tempfile.TemporaryDirectory() as tmp:
        built = Path(tmp) / "handsal-check.pyz"
        build_zipapp.build(build_zipapp.SRC, built)
        if sha256_of(built) != sha256_of(directory / "handsal-check.pyz"):
            raise ReleaseError("handsal-check.pyz is not the zipapp this tree builds", 1)
    if (directory / "handsal-check").read_bytes() != launcher.render_macos().encode("ascii"):
        raise ReleaseError("handsal-check is not the launcher this tree renders", 1)
    if sha256_of(directory / row["archive"]["file"]) != row["archive"]["sha256"]:
        raise ReleaseError("%s is not the pinned interpreter archive" % row["archive"]["file"], 1)
    return [_line(sha256_of(directory / name), name) for name in names]


def build_into(directory):
    """Build the zipapp and the macOS launcher of this tree into DIRECTORY; return (zipapp path, launcher path)."""
    build_zipapp, launcher = _load("build_zipapp"), _load("launcher")
    pyz = Path(directory) / "handsal-check.pyz"
    build_zipapp.build(build_zipapp.SRC, pyz)
    script = Path(directory) / "handsal-check"
    script.write_bytes(launcher.render_macos().encode("ascii"))
    script.chmod(0o755)
    return pyz, script


def built_lines():
    """The lines for a fresh build of this tree, then the pinned interpreter archive lines."""
    lines = []
    with tempfile.TemporaryDirectory() as tmp:
        pyz, script = build_into(tmp)
        lines.append(_line(sha256_of(pyz), pyz.name))
        lines.append(_line(sha256_of(script), script.name))
    pin = json.loads((PACKAGING / "interpreter.json").read_text(encoding="utf-8"))
    for platform in sorted(pin["platforms"]):
        item = pin["platforms"][platform]["archive"]
        lines.append(_line(item["sha256"], item["file"]))
    return lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--release":
        if len(argv) != 4 or argv[2] != "--platform":
            print("usage: artifact_hashes.py --release DIR --platform macos-arm64", file=sys.stderr)
            return 2
        try:
            sys.stdout.write("".join(release_lines(argv[1], argv[3])))
        except ReleaseError as err:
            print("artifact_hashes refused: %s" % err, file=sys.stderr)
            return err.code
        return 0
    try:
        lines = [_line(sha256_of(p), Path(p).name) for p in argv] if argv else built_lines()
    except Exception as err:  # unreadable file or failed build: say so, print nothing
        print("artifact_hashes failed: %s" % err, file=sys.stderr)
        return 2
    sys.stdout.write("".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
