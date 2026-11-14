"""The short forms in the committed render vectors (section 2.1): `kid12` and `hash12` are three
groups of four joined by one space, because the separator must not be a character of base64url.

The implementations are compared with these vectors (CF-04), so a vector that shows a `-` next to
the separator is the cross-implementation proof that a hyphen of the alphabet is not read as one.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = sorted((ROOT / "conformance" / "vectors").glob("rnd.*.json"))

ALPHABET = r"[A-Za-z0-9_-]"
FORM = r"(%s{4} %s{4} %s{4})(?!%s)" % ((ALPHABET,) * 4)
HASH_LINE = re.compile(r"(?:Body hash|Request hash|Link code|Org|Parent|Head): " + FORM)
KID_LINE = re.compile(r"(?:Signer: \w+ key |(?:Add|Remove) device )" + FORM)
# a short form written with a hyphen separator would be `xxxx-xxxx-xxxx` right after one of those labels
HYPHEN_FORM = re.compile(r"(?:Body hash|Request hash|Link code|Org|Parent|Head|Signer: \w+ key|(?:Add|Remove) device)"
                         r"(?::)? %s{4}-%s{4}-%s{4}(?!%s)" % ((ALPHABET,) * 4))


def forms(pattern):
    found = []
    for path in VECTORS:
        found += [(path.name, m.group(1)) for m in pattern.finditer(path.read_text(encoding="utf-8"))]
    return found


def edge_dash(form):
    return any(group.startswith("-") or group.endswith("-") for group in form.split(" "))


class VectorShortForms(unittest.TestCase):
    def test_the_render_vectors_exist(self):
        self.assertGreater(len(VECTORS), 90)

    def test_no_vector_writes_a_short_form_with_a_hyphen_separator(self):
        self.assertEqual([], forms(HYPHEN_FORM))

    def test_a_hash12_with_a_dash_at_the_edge_of_a_group_is_in_the_vector_set(self):
        self.assertTrue([f for _, f in forms(HASH_LINE) if edge_dash(f)])

    def test_a_kid12_with_a_dash_at_the_edge_of_a_group_is_in_the_vector_set(self):
        self.assertTrue([f for _, f in forms(KID_LINE) if edge_dash(f)])


if __name__ == "__main__":
    unittest.main()
