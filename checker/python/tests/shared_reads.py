"""A count of how a state's maps are read, for the tests that say a question reads one entry and walks none."""
from unittest import mock

from handsal_check import state

LOOKUPS = ("get", "__contains__", "__getitem__")
WALKS = ("__iter__", "items", "values", "keys")


class Reads:
    """While active, counts every lookup (`get`, `in`, `[]`) and every walk (iteration, `items`, `values`, `keys`) of
    any `state.Shared`: `looked` and `walked`."""

    def __enter__(self):
        self.looked = self.walked = 0
        self.patches = [mock.patch.object(state.Shared, name, self.counting(name, "looked")) for name in LOOKUPS]
        self.patches += [mock.patch.object(state.Shared, name, self.counting(name, "walked")) for name in WALKS]
        for patch in self.patches:
            patch.start()
        return self

    def __exit__(self, *exc):
        for patch in reversed(self.patches):
            patch.stop()

    def counting(self, name, field):
        original = getattr(state.Shared, name)

        def read(shared, *args):
            setattr(self, field, getattr(self, field) + 1)
            return original(shared, *args)
        return read

    def reset(self):
        self.looked = self.walked = 0
