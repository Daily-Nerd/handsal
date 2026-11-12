"""T3.57 the impure edges of the production build: the platform probe it picks and the clock (CF-08, GP-10,
GP-11, GP-17). The pick is a function of two strings, so it is tested without any platform."""
import calendar
import time
import unittest

from handsal_check import encoding, host, org, probe_posix, probe_wsl, schema

ORG = encoding.hashstr(b"an org")


class Select(unittest.TestCase):
    def test_macos_reads_the_pin_with_the_posix_checks(self):
        self.assertIsInstance(host.select_probe("darwin", "25.0.0"), probe_posix.PosixProbe)

    def test_wsl2_is_always_unprotected(self):
        for release in ("5.15.153.1-microsoft-standard-WSL2", "6.6.36.3-Microsoft-standard-WSL2"):
            self.assertIsInstance(host.select_probe("linux", release), probe_wsl.WslProbe, release)

    def test_any_other_host_has_no_probe_and_says_so(self):
        for name, release in (("linux", "6.1.0-generic"), ("win32", "10"), ("freebsd14", "14.0")):
            got = host.select_probe(name, release).read(ORG)
            self.assertEqual((got.raw, got.filename, got.org, got.owner_ok, got.reason),
                             (b"", org.pin_filename(ORG), ORG, False, "pin_probe_unavailable"), name)

    def test_the_default_posix_probe_has_the_real_root_and_owner(self):
        got = host.select_probe("darwin", "25.0.0")
        self.assertEqual((got._root, got._owner_uid), ("/", 0))


class Clock(unittest.TestCase):
    def test_the_system_clock_is_a_whole_second_utc_time_of_section_2_2(self):
        before = calendar.timegm(time.gmtime())
        got = host.system_now()
        self.assertTrue(schema.is_time(got), got)
        self.assertGreaterEqual(schema.seconds(got), before)
        self.assertLessEqual(schema.seconds(got), before + 5)


if __name__ == "__main__":
    unittest.main()
