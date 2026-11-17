"""Make the Linux assets a release publishes, from a finished and gated release set.

    publish_linux.py SRC RELEASE_DIR LINES OUT TAR_NAME

SRC is the unpacked `git archive` of the commit being released (the installer scripts are read from it, never
from a working tree), RELEASE_DIR holds the five files of the closed list, LINES their `<sha256>  <name>` lines in
installer order (what tools/artifact_hashes.py --release printed) and OUT the empty directory that receives:

    install-linux-server.sh, install-lib.sh   the installer, byte for byte as the commit holds it
    TAR_NAME                                  the five files, in the order of LINES, and nothing else
    SHA256SUMS                                the five lines, then the two scripts, then the tar

SHA256SUMS is `sha256sum` form, so it is the PUBLISHED_HASHES file the installer reads: the installer looks every
name up on its own (published_for in install-lib.sh) and the names of the scripts and of the tar are never asked for.

The tar is written here, with the standard library, so that it is the same bytes on every machine: bsdtar and GNU tar
disagree on the flags that drop owners, extended attributes and ACLs, and on the format of the header. Every member
has a fixed time, root as owner and group, a mode that depends only on the executable bit, and ustar headers (which
carry nothing else, and refuse a name that does not fit rather than adding an extended header).
"""
import hashlib
import os
import shutil
import sys
import tarfile
from pathlib import Path

SCRIPTS = ("install-linux-server.sh", "install-lib.sh")


class PublishError(Exception):
    pass


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_lines(path):
    rows = []
    for text in Path(path).read_text(encoding="utf-8").splitlines():
        digest, sep, name = text.partition("  ")
        if not sep or len(digest) != 64 or not name or "/" in name:
            raise PublishError("not a `<sha256>  <name>` line: %r" % text)
        rows.append((digest, name))
    if not rows:
        raise PublishError("%s holds no lines" % path)
    return rows


def write_tar(path, release_dir, names):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name in names:
            source = Path(release_dir) / name
            info = tarfile.TarInfo(name)
            info.size = source.stat().st_size
            info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            with open(source, "rb") as handle:
                archive.addfile(info, handle)


def publish(src, release_dir, lines, out, tar_name):
    if "/" in tar_name or not tar_name:
        raise PublishError("not a file name: %r" % tar_name)
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise PublishError("%s is not empty" % out)
    rows = read_lines(lines)
    for digest, name in rows:
        if sha256_of(Path(release_dir) / name) != digest:
            raise PublishError("%s is not the file its line names" % name)
    out.mkdir(parents=True, exist_ok=True)
    for script in SCRIPTS:
        source = Path(src) / "tools" / "install" / script
        if not source.is_file():
            raise PublishError("%s is not in the release commit" % script)
        shutil.copyfile(source, out / script)
        os.chmod(out / script, 0o644)
    write_tar(out / tar_name, release_dir, [name for _, name in rows])
    rows += [(sha256_of(out / name), name) for name in SCRIPTS + (tar_name,)]
    (out / "SHA256SUMS").write_text("".join("%s  %s\n" % row for row in rows), encoding="utf-8", newline="\n")


def main(argv):
    if len(argv) != 5:
        print("usage: publish_linux.py SRC RELEASE_DIR LINES OUT TAR_NAME", file=sys.stderr)
        return 2
    try:
        publish(*argv)
    except (PublishError, OSError) as err:
        print("publish_linux: %s" % err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
