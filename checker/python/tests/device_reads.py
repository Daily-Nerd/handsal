"""A count of the reads of a device's fields, for the tests that say a call reads a constant number per node."""
from unittest import mock

from handsal_check import state


class DeviceReads:
    """While active, every device made is a `Device` that counts each read of a field: `reads`."""

    def __enter__(self):
        self.reads = 0
        fields = {name: self.counted(name) for name in state.Device._fields}
        self.patch = mock.patch.object(state, "Device", type("Device", (state.Device,), {"__slots__": (), **fields}))
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()

    def counted(self, name):
        original = getattr(state.Device, name)

        def read(device):
            self.reads += 1
            return original.__get__(device)
        return property(read)
