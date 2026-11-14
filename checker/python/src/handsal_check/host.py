"""The impure edges of the production build (CF-08): which pin probe this host has, and the clock.

The pure core never calls either. The production entry point passes `select_probe(...)` and `system_now`
to its command table; a test passes recorders, and no flag or input reaches them (GP-14).

  macOS    `probe_posix.PosixProbe`: the GP-10 checks over `/Library/Application Support/handsal/orgs`
  WSL2     `probe_wsl.WslProbe`: always `pin_probe_unprotected` (GP-17)
  others   `Unavailable`: the checker has no Windows path (GP-11), and GP-10 names no other platform,
           so the pin cannot be read and the reason is `pin_probe_unavailable`

The store port (CF-09) is picked the same way: `select_store`, macOS the user's `store_posix.PosixStore`, every
other host `UnavailableStore`.

WSL2 is recognised by the kernel release, which carries `microsoft` there.
"""
import calendar
import platform
import sys
import time

from . import errors, org as org_ids
from .pinfile import Probe
from .probe_posix import PosixProbe
from .probe_wsl import WslProbe
from .store_posix import PosixStore


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


class UnavailableStore:
    """The store port of a host with no store the checker can keep (CF-09, SS9): every read and every lock is
    `store_unavailable`. Such a host answers its pin code first (`pin_probe_unavailable`, `pin_probe_unprotected`),
    and `sync` checks the pin before it asks for a lock, so this is reached only through a defect."""

    def read(self, org_id):
        raise errors.Refused("store_unavailable")

    def lock(self, org_id):
        raise errors.Refused("store_unavailable")


def select_store(sys_platform):
    """The store port of the host named by `sys.platform`: macOS keeps the user's store (CF-09); the checker
    has no Windows path yet (GP-11) and WSL2 never writes a store (GP-17)."""
    if sys_platform == "darwin":
        return PosixStore()
    return UnavailableStore()


def host_store():
    """The store port of the machine this process runs on."""
    return select_store(sys.platform)


def system_now():
    """The system clock as a whole-second UTC time, `YYYY-MM-DDTHH:MM:SSZ`."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
