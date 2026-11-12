"""Build the production checker zipapp, byte for byte reproducible (T4.5, SG-15).

    uv run --project checker/python python -I checker/python/packaging/build_zipapp.py OUT.pyz

The archive holds the `handsal_check` package and an entry point that runs the
production build (CF-08). Nothing else: the conformance build is left out, so
the administrator path never holds it. The bytes depend on the source files
only:

- members in sorted order by name, with a fixed time (1980-01-01 00:00:00),
  fixed mode, a fixed creator system and no extra fields;
- stored, not compressed, so the output does not depend on the zlib version of
  the machine that builds it;
- no bytecode caches and no hidden files; a symlink in the tree is refused.

Prints the SHA-256 of the archive. Standard library only.
"""
import hashlib
import sys
import zipfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
PACKAGE = "handsal_check"
LEFT_OUT = frozenset(("handsal_check/conformance.py",))
MAIN = "import sys\nfrom handsal_check import production\nsys.exit(production.main())\n"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
FIXED_MODE = 0o644 << 16
UNIX = 3


class BuildError(Exception):
    pass


def _members(src):
    """[(archive name, bytes)] for the package, in sorted order, plus the entry point."""
    package = Path(src) / PACKAGE
    if not package.is_dir():
        raise BuildError("no %s package under %s" % (PACKAGE, src))
    members = {"__main__.py": MAIN.encode("utf-8")}
    for path in sorted(package.rglob("*")):
        rel = path.relative_to(src)
        if "__pycache__" in rel.parts or path.suffix == ".pyc" or any(p.startswith(".") for p in rel.parts):
            continue
        if path.is_symlink():
            raise BuildError("symlink in the source tree: %s" % rel)
        if not path.is_file():
            continue
        name = rel.as_posix()
        if name in LEFT_OUT:
            continue
        try:
            members[name] = path.read_bytes()
        except OSError as err:
            raise BuildError("unreadable source file: %s (%s)" % (rel, err)) from err
    if PACKAGE + "/production.py" not in members:
        raise BuildError("the package has no production module")
    return sorted(members.items())


def build(src, out):
    """Write the zipapp for the tree `src` to `out`; return its SHA-256 as lowercase hex."""
    members = _members(Path(src))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = FIXED_MODE
            info.create_system = UNIX
            archive.writestr(info, data)
    return hashlib.sha256(Path(out).read_bytes()).hexdigest()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: build_zipapp.py OUT.pyz", file=sys.stderr)
        return 2
    try:
        digest = build(SRC, argv[0])
    except BuildError as err:
        print("build failed: %s" % err, file=sys.stderr)
        return 2
    print("%s  %s" % (digest, Path(argv[0]).name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
