"""CONTRACT.md restates CF-03 for implementers. This test keeps it equal to the spec."""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("tools_manifest", ROOT / "tools" / "manifest.py")
_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_manifest)
SPEC = _manifest.read_profile(ROOT)
CONTRACT = (ROOT / "conformance" / "CONTRACT.md").read_text(encoding="utf-8")

TICKED = re.compile(r"`([^`\n]+)`")


def section(text, heading, level):
    """Body of the section whose heading line starts with `heading`, up to the next heading
    of the same or a higher level."""
    marker = "#" * level + " "
    lines = text.split("\n")
    start = next(i for i, l in enumerate(lines) if l.startswith(marker + heading))
    body = []
    for l in lines[start + 1:]:
        hashes = len(l) - len(l.lstrip("#"))
        if 0 < hashes <= level and l[hashes:hashes + 1] == " ":
            break
        body.append(l)
    return "\n".join(body)


def table_first_column(body):
    out = []
    for l in body.split("\n"):
        if l.startswith("|") and not l.startswith("|---"):
            cell = l.split("|")[1].strip()
            m = re.fullmatch(r"`([^`]+)`", cell)
            if m:
                out.append(m.group(1))
    return out


def spec_commands():
    return set(table_first_column(section(SPEC, "CF-03 Commands", 3)))


def spec_checker_codes():
    """Codes whose 'Where' cell in section 11 names the checker command line."""
    codes = set()
    for l in section(SPEC, "11. Reason codes", 2).split("\n"):
        if l.startswith("|") and "checker command line" in l:
            codes |= set(TICKED.findall(l.split("|")[1]))
    return codes


def spec_all_codes():
    body = section(SPEC, "11. Reason codes", 2)
    return {t for t in TICKED.findall(body) if re.fullmatch(r"[a-z]+(_[a-z]+)*", t)}


class ContractMatchesSpec(unittest.TestCase):
    def test_spec_parse_finds_what_we_expect(self):
        self.assertEqual(spec_checker_codes(),
                         {"unsupported_command", "unparseable_input", "malformed_input"})
        self.assertIn("check-act", spec_commands())
        self.assertIn("sync", spec_commands())   # production build only (CF-09)
        self.assertIn("admit", spec_commands())  # CF-11, conformance and server builds
        self.assertIn("pool", spec_commands())   # CF-12, conformance and server builds
        self.assertEqual(len(spec_commands()), 11)

    def test_every_cf03_command_is_in_the_contract(self):
        have = set(table_first_column(section(CONTRACT, "Commands", 2)))
        self.assertEqual(spec_commands() - have, set())

    def test_contract_names_no_command_absent_from_the_spec(self):
        have = set(table_first_column(section(CONTRACT, "Commands", 2)))
        self.assertEqual(have - spec_commands(), set())
        for m in re.finditer(r"`handsal-check(?:-conformance)? ([a-z][a-z-]*)[ `]", CONTRACT):
            self.assertIn(m.group(1), spec_commands())

    def test_every_checker_error_code_is_in_the_contract(self):
        body = section(CONTRACT, "Error codes", 2)
        have = set(table_first_column(body))
        self.assertEqual(spec_checker_codes() - have, set())

    def test_contract_names_no_code_absent_from_the_spec(self):
        body = section(CONTRACT, "Error codes", 2)
        named = set(table_first_column(body))
        self.assertEqual(named - spec_all_codes(), set())
        for code in re.findall(r'"error":"([a-z_]+)"', CONTRACT):
            self.assertIn(code, spec_all_codes())

    def test_contract_states_the_fixed_rules(self):
        for needle in ("MAX_INPUT", "exit 0", "one line", "JCS", "handsal-check-conformance",
                       "vector_schema.py", "CF-08"):
            self.assertIn(needle, CONTRACT)

    def test_max_input_value_matches_the_spec(self):
        self.assertIn("16777216", SPEC)
        self.assertIn("16777216", CONTRACT)

    def test_max_nesting_is_one_number_in_the_spec_the_registry_and_the_contract(self):
        import json
        registry = json.loads((ROOT / "spec" / "registry.json").read_text(encoding="utf-8"))
        value = registry["constants"]["MAX_NESTING"]["value"]
        self.assertEqual(value, "64")
        self.assertIn("| MAX_NESTING | %s |" % value, SPEC)
        self.assertIn("MAX_NESTING is %s" % value, CONTRACT)
        self.assertIn("unparseable_input", section(CONTRACT, "Input framing", 2))


if __name__ == "__main__":
    unittest.main()
