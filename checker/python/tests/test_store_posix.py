"""CF-09 the POSIX store port: location, ownership checks, the lock and the atomic write.

`PosixStore(root, uid)` takes the home directory and the uid it treats as the user for tests only (the GP-14
pattern); the production build constructs it with neither, so the home is the directory service's answer for the
real uid. Every test here works in a temporary directory: nothing touches the real home.
"""
import errno
import os
import pwd
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import encoding, errors, store, store_posix

ORG = encoding.hashstr(b"an org")
BAG = store.encode(["aaa"], [{"doc": {}, "sigs": []}], "2026-01-01T00:00:00Z")
OTHER = store.encode(["aaa", "bbb"], [{"doc": {}, "sigs": []}], "2026-01-02T00:00:00Z")
ME = os.getuid()


def code_of(call, *args):
    try:
        call(*args)
    except errors.Refused as err:
        return err.code
    return None


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.port = store_posix.PosixStore(self.root, ME)

    def put(self, raw=BAG):
        """A store written through the port."""
        with self.port.lock(ORG) as held:
            held.write(raw)
        return Path(self.port.path(ORG))

    def lock_and_read(self, port=None):
        with (port or self.port).lock(ORG) as held:
            return held.read()


class Reading(Case):
    def test_an_absent_directory_or_file_is_store_missing(self):
        self.assertEqual(code_of(self.port.read, ORG), "store_missing")
        os.makedirs(Path(self.port.path(ORG)).parent, mode=0o700)
        self.assertEqual(code_of(self.port.read, ORG), "store_missing")
        self.assertIsNone(self.lock_and_read())   # under the lock an absent file is the empty set, not an error

    def test_a_written_store_reads_back_its_bytes(self):
        self.put()
        self.assertEqual(self.port.read(ORG), BAG)

    def test_a_symlink_a_loose_mode_another_owner_or_a_second_link_is_store_owner(self):
        def symlinked_file(path):
            real = path.with_name("real")
            real.write_bytes(BAG)
            os.chmod(real, 0o600)
            path.unlink()
            os.symlink(real, path)

        def symlinked_directory(path):
            real = path.parent.with_name("real")
            path.parent.rename(real)
            os.symlink(real, path.parent)

        def second_link(path):
            os.link(path, path.with_name("other"))

        def a_directory_for_the_file(path):
            path.unlink()
            os.mkdir(path, 0o700)

        cases = {
            "a symlinked file": symlinked_file,
            "a symlinked directory": symlinked_directory,
            "a group-writable file": lambda path: os.chmod(path, 0o660),
            "a file writable by others": lambda path: os.chmod(path, 0o602),
            "a group-writable directory": lambda path: os.chmod(path.parent, 0o770),
            "a directory writable by others": lambda path: os.chmod(path.parent, 0o707),
            "a second link": second_link,
            "a directory in place of the file": a_directory_for_the_file,
        }
        for name, damage in cases.items():
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as home:
                    port = store_posix.PosixStore(home, ME)
                    with port.lock(ORG) as held:
                        held.write(BAG)
                    damage(Path(port.path(ORG)))
                    self.assertEqual(code_of(port.read, ORG), "store_owner")
                    self.assertEqual(code_of(self.lock_and_read, port), "store_owner")
                    os.chmod(Path(port.path(ORG)).parent, 0o700)   # so the temporary directory can be removed
        with self.subTest(case="another owner"):
            self.put()
            stranger = store_posix.PosixStore(self.root, ME + 1)
            self.assertEqual(code_of(stranger.read, ORG), "store_owner")
            self.assertEqual(code_of(self.lock_and_read, stranger), "store_owner")

    def test_a_failed_read_or_write_is_store_unavailable(self):
        path = self.put()
        os.chmod(path, 0)   # owned, not writable by others, and unreadable: an I/O failure, not an ownership one
        self.addCleanup(os.chmod, path, 0o600)
        self.assertEqual(code_of(self.port.read, ORG), "store_unavailable")
        self.assertEqual(code_of(self.lock_and_read), "store_unavailable")
        os.chmod(path, 0o600)
        with mock.patch.object(store_posix.os, "fsync", side_effect=OSError(errno.EIO, "disk")):
            self.assertEqual(code_of(self.put, OTHER), "store_unavailable")
        self.assertEqual(path.read_bytes(), BAG)   # the old store is intact
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), sorted([path.name, path.name[:-5] + "lock"]))

    def test_a_write_into_a_directory_that_refuses_it_is_store_unavailable_and_changes_nothing(self):
        path = self.put()
        os.chmod(path.parent, 0o500)
        self.addCleanup(os.chmod, path.parent, 0o700)
        self.assertEqual(code_of(self.put, OTHER), "store_unavailable")
        self.assertEqual(path.read_bytes(), BAG)

    def test_the_home_comes_from_the_directory_service_not_the_environment(self):
        real = pwd.getpwuid(ME).pw_dir
        with mock.patch.dict(os.environ, {"HOME": "/somewhere/else", "LOCALAPPDATA": "/also/else"}):
            path = store_posix.PosixStore().path(ORG)
        self.assertEqual(path, os.path.join(real, "Library", "Application Support", "handsal-check",
                                            encoding.b64u_decode(ORG[1:])[2:].hex() + ".store"))
        asked = []

        def service(uid):
            asked.append(uid)
            return mock.Mock(pw_dir="/the/directory/service")

        with mock.patch.object(store_posix.pwd, "getpwuid", service):
            self.assertTrue(store_posix.PosixStore().path(ORG).startswith("/the/directory/service/Library/"))
        self.assertEqual(asked, [ME])


class Writing(Case):
    def test_the_first_write_creates_the_directory_0700_and_the_file_0600(self):
        path = self.put()
        self.assertEqual(stat.S_IMODE(os.stat(path.parent).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(path.with_suffix(".lock")).st_mode), 0o600)
        self.assertEqual(path.parent.name, "handsal-check")

    def test_the_write_syncs_the_file_then_renames_then_syncs_the_directory(self):
        events = []
        real_fsync, real_rename = os.fsync, os.rename

        def fsync(fd):
            events.append("fsync dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync file")
            real_fsync(fd)

        def rename(src, dst):
            events.append("rename")
            real_rename(src, dst)

        self.put()   # the directory and the lock exist
        with mock.patch.object(store_posix.os, "fsync", fsync), mock.patch.object(store_posix.os, "rename", rename):
            self.put(OTHER)
        self.assertEqual(events, ["fsync file", "rename", "fsync dir"])

    def test_a_leftover_temporary_file_is_removed_under_the_lock_and_never_followed(self):
        path = self.put()
        tmp = path.with_suffix(".tmp")
        victim = path.parent.with_name("victim")
        victim.write_bytes(b"keep")
        os.symlink(victim, tmp)
        self.put(OTHER)
        self.assertEqual((path.read_bytes(), victim.read_bytes(), tmp.exists()), (OTHER, b"keep", False))

    def test_the_second_writer_waits_for_the_first_and_reads_what_it_wrote(self):
        entered, got = threading.Event(), []

        def second():
            with self.port.lock(ORG) as held:
                got.append(held.read())
                entered.set()

        with self.port.lock(ORG) as first:
            thread = threading.Thread(target=second)
            thread.start()
            self.assertFalse(entered.wait(0.3), "the second lock was granted while the first was held")
            first.write(BAG)
        self.assertTrue(entered.wait(10))
        thread.join()
        self.assertEqual(got, [BAG])

    def test_a_refused_write_leaves_no_store_when_there_was_none(self):
        with mock.patch.object(store_posix.os, "fsync", side_effect=OSError(errno.EIO, "disk")):
            self.assertEqual(code_of(self.put), "store_unavailable")
        self.assertEqual(code_of(self.port.read, ORG), "store_missing")


if __name__ == "__main__":
    unittest.main()
