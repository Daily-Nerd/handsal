"""Crafted keys for key and kid rows (ACT-11): a point whose x starts with 0x00."""
import unittest

from lib import crafted, keys, p256


class LeadingZero(unittest.TestCase):
    def test_point_is_on_curve_with_a_zero_first_byte_in_x(self):
        x, y, label = crafted.leading_zero_point()
        self.assertEqual(x[0], 0)
        self.assertEqual(len(x), 32)
        self.assertTrue(p256.on_curve((int.from_bytes(x, "big"), int.from_bytes(y, "big"))))

    def test_it_is_derived_from_its_label_and_is_the_first_such_counter(self):
        x, y, label = crafted.leading_zero_point()
        px, py = p256.mul(keys.derive_scalar(label))
        self.assertEqual((px.to_bytes(32, "big"), py.to_bytes(32, "big")), (x, y))
        counter = int(label.rsplit("/", 1)[1])
        for n in range(counter):
            qx, _ = p256.mul(keys.derive_scalar("crafted-leading-zero/%d" % n))
            self.assertNotEqual(qx >> 248, 0)

    def test_deterministic(self):
        self.assertEqual(crafted.leading_zero_point(), crafted.leading_zero_point())


if __name__ == "__main__":
    unittest.main()
