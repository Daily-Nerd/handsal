"""The macOS store port (CF-09): where the store is, who owns it, the one lock and the atomic write.

`PosixStore(root, uid)` keeps the store of an org at
`<home>/Library/Application Support/handsal-check/<hex64>.store`, with `<home>` the home directory of the process's
real uid from the directory service (`pwd`), never `$HOME` or any environment variable, so every consumer of one
user sees one store. The lock `<hex64>.lock` and the temporary file `<hex64>.tmp` are beside it. The directory is
mode 0700 and the files 0600, all owned by the user.

Reading (`read`) takes no lock: one `rename` in one directory gives a reader the whole old file or the whole new
one. The checks are those of GP-10 with the user's uid, and each failure is one code:

  absent directory or file                                      `store_missing`
  a symlink, not a directory or regular file, another owner,
  writable by group or others, a file with a second link        `store_owner`
  any other I/O failure                                         `store_unavailable`

Writing happens only under `lock(org)`: one blocking exclusive `flock`, held from before the old store is read
until the lock object is left, so two writers never both read the same old store (SS5). The held object reads the
old bytes (None when absent) and writes the new ones: a leftover temporary file is removed, a new one is created
exclusively without following links, written, `fsync`ed and renamed over the store, then the directory is
`fsync`ed. An I/O failure removes the temporary file, leaves the old store as it was and is `store_unavailable`.

`root` (the home) and `uid` (the user) are constructor arguments for tests only; the production build constructs
the port with neither and no command line flag or input reaches them (GP-14, CF-08). The standard library only.
"""
import contextlib
import errno
import fcntl
import os
import pwd
import stat

from . import errors, ijson
from .org import digest_hex

DIRECTORY = ("Library", "Application Support", "handsal-check")
_NOT_WRITABLE = 0o022
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NOT_THE_FILE = (errno.ELOOP, errno.ENOTDIR)   # a symlink as the file, a non-directory in the path


def _refused(code):
    return errors.Refused(code)


class PosixStore:
    def __init__(self, root=None, uid=None):
        self._root = root
        self._uid = os.getuid() if uid is None else uid

    def _directory_path(self):
        home = self._root if self._root is not None else pwd.getpwuid(os.getuid()).pw_dir
        return os.path.join(home, *DIRECTORY)

    def _named(self, org, suffix):
        return os.path.join(self._directory_path(), digest_hex(org) + suffix)

    def path(self, org):
        """The store file of the org id `org`."""
        return self._named(org, ".store")

    def _owned(self, info):
        return info.st_uid == self._uid and info.st_mode & _NOT_WRITABLE == 0

    def _directory(self, create):
        """Check the store directory, creating it 0700 when `create`; Refused if it is not the user's."""
        path = self._directory_path()
        try:
            info = os.lstat(path)
        except OSError as err:
            if err.errno != errno.ENOENT:
                raise _refused("store_unavailable") from None
            if not create:
                raise _refused("store_missing") from None
            info = self._create(path)
        if not stat.S_ISDIR(info.st_mode) or not self._owned(info):   # a symlink is not S_ISDIR
            raise _refused("store_owner")

    def _create(self, path):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            try:
                os.mkdir(path, 0o700)
                os.chmod(path, 0o700)
            except FileExistsError:
                pass   # another process created it first: it is judged like any existing directory
            return os.lstat(path)
        except OSError:
            raise _refused("store_unavailable") from None

    def _check_file(self, fd):
        try:
            info = os.fstat(fd)
        except OSError:
            raise _refused("store_unavailable") from None
        if not stat.S_ISREG(info.st_mode) or not self._owned(info) or info.st_nlink != 1:
            raise _refused("store_owner")

    def _open(self, path, flags, mode=0o600):
        try:
            return os.open(path, flags, mode)
        except OSError as err:
            if err.errno == errno.ENOENT:
                return None
            raise _refused("store_owner" if err.errno in _NOT_THE_FILE else "store_unavailable") from None

    def _contents(self, org):
        """The bytes of the store file (at most one more than MAX_INPUT, which the parser refuses), or None
        when there is no such file."""
        fd = self._open(self.path(org), _OPEN)
        if fd is None:
            return None
        try:
            self._check_file(fd)
            chunks, size = [], 0
            while size <= ijson.MAX_INPUT:
                chunk = os.read(fd, ijson.MAX_INPUT + 1 - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            return b"".join(chunks)
        except OSError:
            raise _refused("store_unavailable") from None
        finally:
            os.close(fd)

    def read(self, org):
        """The bytes of the store of `org`, or Refused `store_missing`, `store_owner` or `store_unavailable`."""
        self._directory(create=False)
        raw = self._contents(org)
        if raw is None:
            raise _refused("store_missing")
        return raw

    @contextlib.contextmanager
    def lock(self, org):
        """Hold the one exclusive lock of `org` (blocking), creating the directory and the lock file if need be;
        yields the object that reads the old store and writes the new one."""
        self._directory(create=True)
        fd = self._open(self._named(org, ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC)
        if fd is None:   # the directory went away between the check and the open
            raise _refused("store_unavailable")
        try:
            self._check_file(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                raise _refused("store_unavailable") from None
            yield _Held(self, org)
        finally:
            os.close(fd)   # closing the descriptor releases the lock, also for a crashed holder


class _Held:
    """The store of one org while its lock is held."""

    def __init__(self, port, org):
        self._port, self._org = port, org

    def read(self):
        """The bytes of the old store, or None when there is none."""
        return self._port._contents(self._org)

    def write(self, raw):
        """Replace the store by `raw`, atomically and durably."""
        port = self._port
        path, tmp = port.path(self._org), port._named(self._org, ".tmp")
        try:
            if os.path.lexists(tmp):
                os.unlink(tmp)   # a killed writer's leftover, removed under the lock
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(raw)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, path)
            directory = os.open(port._directory_path(), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)   # best effort: the failure reported is the first one
            raise _refused("store_unavailable") from None
