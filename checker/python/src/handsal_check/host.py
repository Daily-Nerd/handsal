"""The impure edges of the production build (CF-08): which pin probe this host has, and the clock.

The pure core never calls either. The production entry point passes `select_probe(...)` and `system_now`
to its command table; a test passes recorders, and no flag or input reaches them (GP-14).

  macOS    `probe_posix.PosixProbe`: the GP-10 checks over `/Library/Application Support/handsal/orgs`
  WSL2     `probe_wsl.WslProbe`: always `pin_probe_unprotected` (GP-17)
  others   `Unavailable`: the checker has no Windows path (GP-11), and GP-10 names no other platform,
           so the pin cannot be read and the reason is `pin_probe_unavailable`

WSL2 is recognised by the kernel release, which carries `microsoft` there.
"""
import calendar
import platform
import sys
import time

from . import org as org_ids
from .pinfile import Probe
from .probe_posix import PosixProbe
from .probe_wsl import WslProbe


class Unavailable:
    """The probe of a host with no pin location the checker can read."""

    def read(self, org_id):
        return Probe(b"", org_ids.pin_filename(org_id), org_id, False, "pin_probe_unavailable")


def select_probe(sys_platform, kernel_release):
    """The probe of the host named by `sys.platform` and `platform.release()`."""
    if sys_platform == "darwin":
        return PosixProbe()
    if sys_platform.startswith("linux") and "microsoft" in kernel_release.lower():
        return WslProbe()
    return Unavailable()


def host_probe():
    """The probe of the machine this process runs on."""
    return select_probe(sys.platform, platform.release())


def system_now():
    """The system clock as a whole-second UTC time, `YYYY-MM-DDTHH:MM:SSZ`."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
