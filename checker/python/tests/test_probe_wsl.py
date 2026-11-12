"""T3.55 the WSL2 pin probe (GP-17 step 1): always unprotected, reads and runs nothing.

On WSL2 an agent can usually obtain distribution root, so no WSL2-side check is protected, the call to
`pin-read` included. The probe therefore returns `{owner_ok: false, reason: pin_probe_unprotected}` and
does not look at the file system or start a process: the Windows-side gate and the `pin-read` call are
the consumer's wiring (GP-11), not the checker's.
"""
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from handsal_check import encoding, org, pinfile, probe_wsl

ORG = encoding.hashstr(b"an org")


class WslProbe(unittest.TestCase):
    def test_it_is_always_unprotected(self):
        got = probe_wsl.WslProbe().read(ORG)
        self.assertIsInstance(got, pinfile.Probe)
        self.assertEqual((got.raw, got.filename, got.org, got.owner_ok, got.reason),
                         (b"", org.pin_filename(ORG), ORG, False, "pin_probe_unprotected"))

    def test_it_is_a_valid_probe_object_of_gp_14(self):
        got = probe_wsl.WslProbe().read(ORG)
        wire = {"bytes_b64": "", "filename": got.filename, "org": got.org, "owner_ok": False,
                "reason": "pin_probe_unprotected"}
        self.assertEqual(pinfile.Probe.from_json(wire), got)

    def test_a_pin_read_executable_next_to_it_is_never_started(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = os.path.join(folder, "ran")
            exe = os.path.join(folder, "pin-read.exe")
            with open(exe, "w") as handle:
                handle.write("#!/bin/sh\ntouch %s\n" % marker)
            os.chmod(exe, 0o755)
            with mock.patch.dict(os.environ, {"PATH": folder + os.pathsep + os.environ["PATH"]}), \
                    mock.patch.object(subprocess, "Popen", side_effect=AssertionError("started a process")), \
                    mock.patch.object(os, "system", side_effect=AssertionError("started a process")):
                got = probe_wsl.WslProbe().read(ORG)
            self.assertEqual(got.reason, "pin_probe_unprotected")
            self.assertFalse(os.path.exists(marker))

    def test_the_org_is_echoed_for_any_org(self):
        other = encoding.hashstr(b"another org")
        got = probe_wsl.WslProbe().read(other)
        self.assertEqual((got.org, got.filename), (other, org.pin_filename(other)))


if __name__ == "__main__":
    unittest.main()
