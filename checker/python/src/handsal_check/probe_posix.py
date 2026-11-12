"""The macOS pin probe (GP-10, GP-14): read the pin file and check who owns it, in one impure function.

`PosixProbe(root, owner_uid).read(org)` returns the `pinfile.Probe` of the file
`<root>/Library/Application Support/handsal/orgs/<hex64>.pin`. The checks are those of GP-10, in order:

  open      `O_NOFOLLOW` (and `O_NONBLOCK`, so a FIFO cannot hang the probe), read only
  fstat     the open descriptor: a regular file, owned by `owner_uid`, `mode & 0o022 == 0`, one link
  lstat     every ancestor from `root` (the virtual `/`) down: a directory that is not a symlink,
            owned by `owner_uid`, `mode & 0o022 == 0`
  read      at most MAX_BYTES + 1 bytes, which is enough for `pinfile.parse` to refuse an oversize file

A failed check is `pin_owner`; an absent file is `pin_missing`, unless an ancestor that does exist
already fails its check (a dangling symlink in place of a directory is an ownership failure, not an
absent pin); any other I/O failure is `pin_probe_unavailable`. A failed probe carries no bytes.

`root` and `owner_uid` are constructor arguments for tests only (`root` stands for `/`, `owner_uid` for
root, which a test cannot be). The production build constructs `PosixProbe()` with neither; no command
line flag or input reaches either (GP-14, CF-08). The standard library only.
"""
import errno
import os
import stat

from . import org as org_ids
from .pinfile import MAX_BYTES, Probe

PIN_DIRECTORY = ("Library", "Application Support", "handsal", "orgs")
_NOT_WRITABLE = 0o022
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NOT_A_PIN = (errno.ELOOP, errno.ENOTDIR)   # a symlink as the file, a non-directory as an ancestor


class _Failed(Exception):
    """A check of the probe failed; `reason` is the probe's reason code."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class PosixProbe:
    def __init__(self, root="/", owner_uid=0):
        self._root = root
        self._owner_uid = owner_uid

    def _owned(self, info):
        """Owned by the expected user and writable by neither group nor others."""
        return info.st_uid == self._owner_uid and info.st_mode & _NOT_WRITABLE == 0

    def _check_ancestors(self, tolerate_missing):
        """lstat the virtual `/` and every directory below it. An ancestor that is absent ends the walk
        when `tolerate_missing` (the file is absent anyway), else it is a failure of the probe; one that
        cannot be inspected is `pin_probe_unavailable`."""
        path = self._root
        for step in (None,) + PIN_DIRECTORY:
            if step is not None:
                path = os.path.join(path, step)
            try:
                info = os.lstat(path)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    raise _Failed("pin_probe_unavailable") from None
                if tolerate_missing:
                    return
                raise _Failed("pin_missing") from None
            if not stat.S_ISDIR(info.st_mode) or not self._owned(info):   # a symlink is not S_ISDIR
                raise _Failed("pin_owner")

    def _open(self, path):
        try:
            return os.open(path, _OPEN_FLAGS)
        except OSError as err:
            if err.errno == errno.ENOENT:
                self._check_ancestors(tolerate_missing=True)
                raise _Failed("pin_missing") from None
            raise _Failed("pin_owner" if err.errno in _NOT_A_PIN else "pin_probe_unavailable") from None

    def _checked_bytes(self, path):
        """The bytes of the pin at `path` after every ownership check, or `_Failed`."""
        fd = self._open(path)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not self._owned(info) or info.st_nlink != 1:
                raise _Failed("pin_owner")
            self._check_ancestors(tolerate_missing=False)
            try:
                return os.read(fd, MAX_BYTES + 1)
            except OSError:
                raise _Failed("pin_probe_unavailable") from None
        finally:
            os.close(fd)

    def read(self, org_id):
        """The `Probe` for the org id `org_id` (a hashstr, checked by the command)."""
        name = org_ids.pin_filename(org_id)
        try:
            raw = self._checked_bytes(os.path.join(self._root, *PIN_DIRECTORY, name))
        except _Failed as failed:
            return Probe(b"", name, org_id, False, failed.reason)
        return Probe(raw, name, org_id, True, "ok")
