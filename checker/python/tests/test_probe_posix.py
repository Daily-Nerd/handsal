"""T3.53 the macOS pin probe (GP-10, GP-14): one impure function that returns the probe object as data.

Every test builds a small tree under a temporary directory that stands for `/` (the constructor's test
only `root`) and owns it by the current user (the constructor's `owner_uid`, the stand-in for root:wheel).
The default owner is uid 0, so the production constructor takes no argument at all.
"""
import base64
import errno
import os
import stat
import tempfile
import unittest
from unittest import mock

from handsal_check import encoding, org, pinfile, probe_posix

ORG = encoding.hashstr(b"an org")
OTHER_ORG = encoding.hashstr(b"another org")
LINE = pinfile.line(encoding.hashstr(b"genesis"), ORG, encoding.hashstr(b"spec"))
DIRS = ("Library", "Application Support", "handsal", "orgs")
ME = os.getuid()


class Tree(unittest.TestCase):
    """A temporary `/` with the pin directories, 0755, and a pin file for ORG, 0644."""

    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = os.path.realpath(holder.name)
        os.chmod(self.root, 0o755)
        self.dirs = [self.root]
        for name in DIRS:
            self.dirs.append(os.path.join(self.dirs[-1], name))
            os.mkdir(self.dirs[-1])
            os.chmod(self.dirs[-1], 0o755)
        self.pin_dir = self.dirs[-1]
        self.path = os.path.join(self.pin_dir, org.pin_filename(ORG))
        self.write(LINE)

    def write(self, data, mode=0o644):
        if os.path.exists(self.path):
            os.chmod(self.path, 0o600)
        with open(self.path, "wb") as handle:
            handle.write(data)
        os.chmod(self.path, mode)

    def probe(self, org_id=ORG, owner_uid=ME):
        return probe_posix.PosixProbe(root=self.root, owner_uid=owner_uid).read(org_id)

    def assertFails(self, reason, **kw):
        got = self.probe(**kw)
        self.assertEqual((got.owner_ok, got.reason), (False, reason))
        self.assertEqual(got.raw, b"")   # nothing unproven is handed on
        return got


class Passing(Tree):
    def test_a_well_owned_pin_is_returned_as_data(self):
        got = self.probe()
        self.assertIsInstance(got, pinfile.Probe)
        self.assertEqual((got.raw, got.filename, got.org, got.owner_ok, got.reason),
                         (LINE, org.pin_filename(ORG), ORG, True, "ok"))

    def test_the_result_is_the_wire_object_of_gp_14(self):
        got = self.probe()
        wire = {"bytes_b64": base64.b64encode(got.raw).decode(), "filename": got.filename, "org": got.org,
                "owner_ok": got.owner_ok, "reason": got.reason}
        self.assertEqual(pinfile.Probe.from_json(wire), got)

    def test_the_org_asked_for_is_echoed_with_the_file_name_it_opened(self):
        got = self.assertFails("pin_missing", org_id=OTHER_ORG)
        self.assertEqual((got.org, got.filename), (OTHER_ORG, org.pin_filename(OTHER_ORG)))

    def test_the_default_owner_is_root(self):
        if ME == 0:
            self.skipTest("running as root")
        got = probe_posix.PosixProbe(root=self.root).read(ORG)
        self.assertEqual((got.owner_ok, got.reason), (False, "pin_owner"))

    def test_only_the_first_513_bytes_are_read(self):
        self.write(b"x" * 100000)
        self.assertEqual(len(self.probe().raw), pinfile.MAX_BYTES + 1)


class Missing(Tree):
    def test_an_absent_file_is_pin_missing(self):
        os.unlink(self.path)
        self.assertFails("pin_missing")

    def test_an_absent_directory_is_pin_missing(self):
        os.unlink(self.path)
        os.rmdir(self.pin_dir)
        self.assertFails("pin_missing")


class Owner(Tree):
    def test_a_file_of_another_owner_is_pin_owner(self):
        self.assertFails("pin_owner", owner_uid=ME + 1)

    def test_a_group_or_world_writable_file_is_pin_owner(self):
        for mode in (0o664, 0o646, 0o666):
            self.write(LINE, mode)
            self.assertFails("pin_owner")

    def test_a_group_or_world_writable_ancestor_is_pin_owner(self):
        for index in range(len(self.dirs)):   # the virtual `/` itself and every directory below it
            for mode in (0o775, 0o757):
                os.chmod(self.dirs[index], mode)
                self.assertFails("pin_owner")
                os.chmod(self.dirs[index], 0o755)
        self.assertTrue(self.probe().owner_ok)

    def test_a_file_with_two_links_is_pin_owner(self):
        os.link(self.path, os.path.join(self.root, "second-name"))
        self.assertFails("pin_owner")

    def test_a_file_that_is_a_symlink_is_pin_owner(self):
        real = os.path.join(self.root, "real.pin")
        os.rename(self.path, real)
        os.symlink(real, self.path)
        self.assertFails("pin_owner")

    def test_an_ancestor_that_is_a_symlink_is_pin_owner(self):
        moved = os.path.join(self.root, "moved-orgs")
        os.rename(self.pin_dir, moved)
        os.symlink(moved, self.pin_dir)
        self.assertFails("pin_owner")

    def test_a_dangling_ancestor_symlink_is_pin_owner_not_pin_missing(self):
        os.unlink(self.path)
        os.rmdir(self.pin_dir)
        os.symlink(os.path.join(self.root, "nowhere"), self.pin_dir)
        self.assertFails("pin_owner")

    def test_a_directory_in_place_of_the_file_is_pin_owner(self):
        os.unlink(self.path)
        os.mkdir(self.path)
        os.chmod(self.path, 0o755)
        self.assertFails("pin_owner")

    def test_a_fifo_in_place_of_the_file_is_pin_owner_and_does_not_block(self):
        os.unlink(self.path)
        os.mkfifo(self.path, 0o644)
        self.assertFails("pin_owner")

    def test_a_file_in_place_of_a_directory_is_pin_owner(self):
        os.unlink(self.path)
        os.rmdir(self.pin_dir)
        with open(self.pin_dir, "wb") as handle:
            handle.write(b"")
        os.chmod(self.pin_dir, 0o644)
        self.assertFails("pin_owner")


class Unreadable(Tree):
    def test_an_ancestor_that_cannot_be_searched_is_pin_probe_unavailable(self):
        if ME == 0:
            self.skipTest("running as root")
        self.addCleanup(os.chmod, self.pin_dir, 0o755)
        os.chmod(self.pin_dir, 0o000)
        self.assertFails("pin_probe_unavailable")

    def test_an_ancestor_that_cannot_be_inspected_after_the_open_is_pin_probe_unavailable_not_a_crash(self):
        with mock.patch.object(os, "lstat", side_effect=PermissionError(errno.EACCES, "denied")):
            self.assertFails("pin_probe_unavailable")

    def test_an_ancestor_that_vanishes_after_the_open_is_pin_missing(self):
        with mock.patch.object(os, "lstat", side_effect=OSError(errno.ENOENT, "gone")):
            self.assertFails("pin_missing")

    def test_a_file_that_cannot_be_read_is_pin_probe_unavailable(self):
        if ME == 0:
            self.skipTest("running as root")
        self.write(LINE, 0o000)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0)
        self.assertFails("pin_probe_unavailable")


if __name__ == "__main__":
    unittest.main()
