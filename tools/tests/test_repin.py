"""The re-pin tool (CF-01): one owner for the pins that must stay.

Expected values are computed here with hashlib and json only, a different path from the tool's
openssl calls, so a tool that agreed with itself would still fail.
"""
import base64
import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import repin  # noqa: E402


def hashstr(raw):
    digest = b"\x12\x20" + hashlib.sha256(raw).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


CORE = {
    "conformance/CONTRACT.md": b"contract\n",
    "conformance/fixtures/fixture-kids.json": b'["k1"]\n',
    "conformance/fixtures/keys.json": b'{"alice":"x"}\n',
    "spec/profile.md": b"# profile\n",
    "spec/registry.json": b'{"methods":[]}\n',
}
SWIFT = """public struct Profiles {
    public static let coreManifest: [String: String] = [
        "conformance/CONTRACT.md": "old",
        "conformance/fixtures/fixture-kids.json": "old",
        "conformance/fixtures/keys.json": "old",
        "spec/profile.md": "old",
        "spec/registry.json": "old",
    ]
}
"""


def expected(core_bytes):
    core = {rel: hashstr(raw) for rel, raw in core_bytes.items()}
    fixture = hashstr(jcs({"core": core, "kind": "fixture"}))
    org = {"devices": [], "org": None, "profile": fixture}
    wit = {"devices": [], "org": None, "policy": "relay", "profile": fixture}
    pins = {"fixture_profile": fixture, "org_id": hashstr(jcs(org)),
            "production_profile": hashstr(jcs({"core": core, "kind": "production"})),
            "wit_org_id": hashstr(jcs(wit))}
    return core, pins, org, wit


def make_tree(root, core_bytes=CORE):
    root = Path(root)
    core, pins, org, wit = expected(core_bytes)
    for rel, raw in core_bytes.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(raw)
    for rel, doc in ((repin.ORG_VECTOR, org), (repin.WIT_ORG_VECTOR, wit)):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(json.dumps({"input": {"lineage": [{"doc": doc, "sigs": []}]}}), encoding="utf-8")
    (root / repin.SWIFT).parent.mkdir(parents=True, exist_ok=True)
    (root / repin.SWIFT).write_text(SWIFT, encoding="utf-8")
    (root / repin.CHECKER_CORE).parent.mkdir(parents=True, exist_ok=True)
    (root / repin.CHECKER_CORE).write_text(json.dumps(core), encoding="utf-8")
    (root / repin.PINS).write_text("{}\n", encoding="utf-8")
    return core, pins


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.core, self.pins = make_tree(self.tmp)

    def run_tool(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = repin.main(list(argv) + ["--root", str(self.tmp)])
        return code, out.getvalue()

    def test_compute_matches_hashlib(self):
        pins, core = repin.compute(self.tmp)
        self.assertEqual(core, self.core)
        self.assertEqual(pins, self.pins)

    def test_write_sets_the_pins_file_and_the_swift_rows_and_nothing_else(self):
        before = (self.tmp / repin.CHECKER_CORE).read_bytes()
        self.assertEqual(self.run_tool("--write")[0], 0)
        self.assertEqual((self.tmp / repin.PINS).read_text(), json.dumps(self.pins, indent=2, sort_keys=True) + "\n")
        swift = (self.tmp / repin.SWIFT).read_text()
        for rel, digest in self.core.items():
            self.assertIn('"%s": "%s",' % (rel, digest), swift)
        self.assertIn("public static let coreManifest", swift)
        self.assertEqual((self.tmp / repin.CHECKER_CORE).read_bytes(), before)

    def test_check_is_clean_after_write_and_reports_each_drift(self):
        self.run_tool("--write")
        self.assertEqual(self.run_tool("--check"), (0, "pins ok\n"))
        (self.tmp / "spec/profile.md").write_bytes(b"# profile, edited\n")
        code, text = self.run_tool("--check")
        self.assertEqual(code, 2, text)   # the vectors still name the old profile: regenerate first

    def test_check_names_the_file_that_drifted(self):
        self.run_tool("--write")
        (self.tmp / repin.PINS).write_text("{}\n")
        code, text = self.run_tool("--check")
        self.assertEqual(code, 1)
        self.assertIn("drift: " + repin.PINS, text)
        self.assertNotIn(repin.SWIFT, text)

    def test_a_stale_checker_copy_points_to_sync_core(self):
        self.run_tool("--write")
        (self.tmp / repin.CHECKER_CORE).write_text("{}")
        code, text = self.run_tool("--check")
        self.assertEqual(code, 1)
        self.assertIn("sync_core.py", text)

    def test_a_stale_swift_table_is_a_drift(self):
        self.run_tool("--write")
        (self.tmp / repin.SWIFT).write_text(SWIFT)
        code, text = self.run_tool("--check")
        self.assertEqual((code, repin.SWIFT in text), (1, True))

    def test_vectors_that_name_another_profile_are_refused(self):
        doc = json.loads((self.tmp / repin.ORG_VECTOR).read_text())
        doc["input"]["lineage"][0]["doc"]["profile"] = "uEiOld"
        (self.tmp / repin.ORG_VECTOR).write_text(json.dumps(doc))
        code, _ = self.run_tool("--write")
        self.assertEqual(code, 2)
        self.assertEqual((self.tmp / repin.PINS).read_text(), "{}\n")

    def test_a_missing_core_file_is_exit_two(self):
        (self.tmp / "spec/profile.md").unlink()
        self.assertEqual(self.run_tool("--check")[0], 2)

    def test_a_swift_table_with_an_unknown_row_is_refused(self):
        (self.tmp / repin.SWIFT).write_text(SWIFT.replace('        "spec/registry.json": "old",\n',
                                                          '        "spec/registry.json": "old",\n        "spec/other.md": "old",\n'))
        self.assertEqual(self.run_tool("--write")[0], 2)

    def test_the_tool_needs_a_mode(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            repin.main(["--root", str(self.tmp)])


class RealTree(unittest.TestCase):
    def test_the_pins_are_what_the_files_give(self):
        """The one place a core edit turns red until `repin.py --write` and `sync_core.py` have run."""
        self.assertEqual(repin.drift(ROOT), [])

    def test_the_pins_file_holds_the_four_values_and_nothing_else(self):
        pins = json.loads((ROOT / repin.PINS).read_text(encoding="utf-8"))
        self.assertEqual(sorted(pins), ["fixture_profile", "org_id", "production_profile", "wit_org_id"])
        self.assertEqual(len(set(pins.values())), 4)


if __name__ == "__main__":
    unittest.main()
