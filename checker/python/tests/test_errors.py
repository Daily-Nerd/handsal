"""One exception for 'the input is refused with this reason code'."""
import unittest

from handsal_check import core, errors


class Refusals(unittest.TestCase):
    def test_refused_carries_its_code(self):
        err = errors.Refused("schema")
        self.assertEqual(err.code, "schema")
        self.assertEqual(str(err), "schema")

    def test_refused_is_not_malformed_input(self):
        self.assertFalse(issubclass(errors.Refused, errors.Malformed))
        self.assertFalse(issubclass(errors.Malformed, errors.Refused))

    def test_core_and_errors_share_one_malformed(self):
        self.assertIs(core.Malformed, errors.Malformed)


if __name__ == "__main__":
    unittest.main()
