"""The WSL2 pin probe (GP-17 step 1): always `pin_probe_unprotected`.

An agent running as the user can usually obtain distribution root on WSL2, and with it redirect every
path a WSL2 process uses (bind mounts over `/mnt/c`, replaced binaries). No WSL2-side check is then
protected, the interop call to `pin-read` included, so this probe never reports a machine enrolled: it
reads no file and starts no process. The Windows-side gate (GP-17 step 2) and the `pin-read` call
(GP-11) are the consumer's wiring, outside the checker.
"""
from . import org as org_ids
from .pinfile import Probe


class WslProbe:
    def read(self, org_id):
        """The `Probe` for the org id `org_id`: no bytes, `owner_ok` false, `pin_probe_unprotected`."""
        return Probe(b"", org_ids.pin_filename(org_id), org_id, False, "pin_probe_unprotected")
