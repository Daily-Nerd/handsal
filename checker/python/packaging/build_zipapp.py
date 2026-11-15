"""Build a checker zipapp, byte for byte reproducible (T4.5, T13.5, SG-15).

    uv run --project checker/python python -I checker/python/packaging/build_zipapp.py [--entry ENTRY] OUT.pyz

The archive holds the `handsal_check` package and an entry point that runs one
build (CF-08): the production build by default, or the server build with
`--entry handsal_check.server:main` (CF-10). Nothing else: the entry modules of
the other builds are left out (the conformance build is never zipped), so an
administrator path never holds a build it was not meant to run. The bytes
depend on the source files only:

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
PRODUCTION = "handsal_check.production:main"
SERVER = "handsal_check.server:main"
ENTRIES = (PRODUCTION, SERVER)
# every build's entry module; a zipapp keeps its own and leaves out the rest
ENTRY_MODULES = frozenset(("handsal_check/production.py", "handsal_check/server.py", "handsal_check/conformance.py"))
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
FIXED_MODE = 0o644 << 16
UNIX = 3


class BuildError(Exception):
    pass


def _entry(entry):
    """(module name, archive name of the module, `__main__` text) of one of the two zipapp builds."""
    if entry not in ENTRIES:
        raise BuildError("entry must be one of %s, not %r" % (", ".join(ENTRIES), entry))
    module = entry.split(":")[0].rsplit(".", 1)[1]
    text = "import sys\nfrom %s import %s\nsys.exit(%s.main())\n" % (PACKAGE, module, module)
    return "%s/%s.py" % (PACKAGE, module), text


def _members(src, entry):
    """[(archive name, bytes)] for the package, in sorted order, plus the entry point."""
    entry_file, main_text = _entry(entry)
    left_out = ENTRY_MODULES - {entry_file}
    package = Path(src) / PACKAGE
    if not package.is_dir():
        raise BuildError("no %s package under %s" % (PACKAGE, src))
    members = {"__main__.py": main_text.encode("utf-8")}
    for path in sorted(package.rglob("*")):
        rel = path.relative_to(src)
        if "__pycache__" in rel.parts or path.suffix == ".pyc" or any(p.startswith(".") for p in rel.parts):
            continue
        if path.is_symlink():
            raise BuildError("symlink in the source tree: %s" % rel)
        if not path.is_file():
            continue
        name = rel.as_posix()
        if name in left_out:
            continue
        try:
            members[name] = path.read_bytes()
        except OSError as err:
            raise BuildError("unreadable source file: %s (%s)" % (rel, err)) from err
    if entry_file not in members:
        raise BuildError("the package has no %s" % entry_file)
    return sorted(members.items())


def build(src, out, entry=PRODUCTION):
    """Write the zipapp of `entry` for the tree `src` to `out`; return its SHA-256 as lowercase hex.
    Nothing is written when the entry or the tree is refused."""
    members = _members(Path(src), entry)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = FIXED_MODE
            info.create_system = UNIX
            archive.writestr(info, data)
    return hashlib.sha256(Path(out).read_bytes()).hexdigest()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    entry = PRODUCTION
    if argv[:1] == ["--entry"]:
        if len(argv) < 2:
            argv = []
        else:
            entry, argv = argv[1], argv[2:]
    if len(argv) != 1 or argv[0].startswith("-"):   # a flag is never the output path
        print("usage: build_zipapp.py [--entry %s] OUT.pyz" % SERVER, file=sys.stderr)
        return 2
    try:
        digest = build(SRC, argv[0], entry)
    except BuildError as err:
        print("build failed: %s" % err, file=sys.stderr)
        return 2
    print("%s  %s" % (digest, Path(argv[0]).name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
