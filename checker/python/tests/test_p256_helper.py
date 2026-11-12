"""The test point helper agrees with the checker's curve check and with the fixture keys."""
import unittest

from handsal_check import devicekey

from . import p256_helper
from .genesis_fixtures import KEYS


class Helper(unittest.TestCase):
    def test_it_reproduces_a_fixture_public_key(self):
        d = int(KEYS["alice.sign"]["d"], 16)
        self.assertEqual(p256_helper.public_point(d),
                         {"x": KEYS["alice.sign"]["x"], "y": KEYS["alice.sign"]["y"]})

    def test_production_devices_are_valid_and_unlisted(self):
        dev = p256_helper.production_device("alice", "alice")
        self.assertIsNone(devicekey.defect(dev["kid"], dev["sign"], dev["agree"]))
        listed = {k["kid"] for k in KEYS.values() if "kid" in k}
        self.assertNotIn(dev["kid"], listed)

    def test_two_labels_give_two_devices(self):
        a = p256_helper.production_device("alice", "alice")
        b = p256_helper.production_device("bob", "bob")
        self.assertNotEqual(a["kid"], b["kid"])


if __name__ == "__main__":
    unittest.main()
