"""Repack the interpreter's licence texts into a gzip tar a stock macOS reads (SG-15).

Usage: pack_licenses.py --platform macos-arm64 NOTICES_ARCHIVE OUT_DIR

NOTICES_ARCHIVE is the python-build-standalone `pgo+lto-full.tar.zst` pinned in
`checker/python/packaging/interpreter.json`. Stock macOS `tar` cannot read zstd and the installer runs with a
fixed `PATH`, so the installer never reads that archive. This packaging step does, on the builder's machine
(it needs `tar` with a `zstd` it can run): it checks the pinned SHA-256 first, unpacks `python/licenses/` only,
and writes the pinned `handsal-python-licenses-*.tar.gz` into OUT_DIR. The bytes depend only on the texts
(sorted members, owner root, no times, fixed modes, no gzip name or time), so two builders get one hash.

Prints `<sha256>  <name>` for the packed archive (the line to publish beside the other artifacts, T7.3) and exits
0. Exit 2, nothing on stdout, when anything is wrong. Standard library only.
"""
import argparse
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ROOT / "checker" / "python" / "packaging" / "interpreter.json"
LICENSES = "python/licenses"


class PackError(Exception):
    pass


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unpack_notices(archive, dest, which=shutil.which):
    """Extract `python/licenses` of the notices archive into DEST with the system `tar`, which needs a `zstd`."""
    tar = which("tar")
    if not tar or not which("zstd"):
        raise PackError("packaging needs tar and a zstd it can run (the notices archive is .tar.zst); zstd was not found")
    result = subprocess.run([tar, "-xf", str(archive), "-C", str(dest), LICENSES],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise PackError("tar could not unpack %s: %s" % (archive, result.stderr.decode("utf-8", "replace").strip()))


def _entries(tree):
    """The files of TREE/python/licenses, sorted by name, each a plain file; anything else is an error."""
    top = Path(tree)
    base = top / "python"
    extra = sorted(p.name for p in top.iterdir() if p.name != "python")
    inside = sorted(p.name for p in base.iterdir() if p.name != "licenses") if base.is_dir() else []
    if extra or inside or base.is_symlink():
        raise PackError("the notices archive holds more than python/licenses: %s" % ", ".join(extra + inside))
    folder = base / "licenses"
    if folder.is_symlink() or not folder.is_dir():
        raise PackError("python/licenses is not a directory")
    names = sorted(p.name for p in folder.iterdir())
    for name in names:
        path = folder / name
        if path.is_symlink() or not path.is_file():
            raise PackError("python/licenses/%s is a link or not a regular file" % name)
    if not names:
        raise PackError("python/licenses holds no file")
    return folder, names


def pack_tree(tree, out):
    """Write the deterministic gzip tar of TREE/python/licenses to OUT (nothing is left at OUT on an error)."""
    folder, names = _entries(tree)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, kind in (("python", tarfile.DIRTYPE), (LICENSES, tarfile.DIRTYPE)):
            info = tarfile.TarInfo(name)
            info.type, info.mode = kind, 0o755
            tar.addfile(info)
        for name in names:
            data = (folder / name).read_bytes()
            info = tarfile.TarInfo("%s/%s" % (LICENSES, name))
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=packed, compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())
    Path(out).write_bytes(packed.getvalue())


def pack(archive, entry, out_dir, unpack=unpack_notices):
    """Check ARCHIVE against the pinned hash of ENTRY, unpack it, pack the licences; the packed path."""
    archive = Path(archive)
    if sha256_of(archive) != entry["notices"]["sha256"]:
        raise PackError("%s is not the pinned notices archive (SHA-256 differs from interpreter.json)" % archive.name)
    out = Path(out_dir) / entry["packed_licenses"]["file"]
    with tempfile.TemporaryDirectory() as scratch:
        unpack(archive, Path(scratch))
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        try:
            pack_tree(scratch, out)
        except Exception:
            out.unlink(missing_ok=True)
            raise
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pack_licenses.py", add_help=False)
    parser.add_argument("--platform", required=True)
    parser.add_argument("archive")
    parser.add_argument("out_dir")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit:
        return 2
    try:
        pin = json.loads(PIN_FILE.read_text(encoding="utf-8"))
        if args.platform not in pin["platforms"]:
            raise PackError("unknown platform %s (pinned: %s)" % (args.platform, ", ".join(sorted(pin["platforms"]))))
        out = pack(args.archive, pin["platforms"][args.platform], args.out_dir)
        line = "%s  %s\n" % (sha256_of(out), out.name)
    except (PackError, OSError) as err:
        print("pack_licenses failed: %s" % err, file=sys.stderr)
        return 2
    sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
