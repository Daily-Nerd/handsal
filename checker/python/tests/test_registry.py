"""T3.8 packaged registry, hash-checked against the core manifest (KC-01, KC-02, KC-03, KC-05, ACT-09)."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from handsal_check import coredata, encoding, ijson, registry, subset

ROOT = Path(__file__).resolve().parents[3]


def load_tools_manifest():
    spec = importlib.util.spec_from_file_location("tools_manifest", ROOT / "tools" / "manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PackagedDataIsTheRepoData(unittest.TestCase):
    """The checker carries copies of the core files it needs. They are the repo files."""

    def test_registry_copy_is_byte_identical(self):
        self.assertEqual((coredata.DATA_DIR / "spec" / "registry.json").read_bytes(),
                         (ROOT / "spec" / "registry.json").read_bytes())

    def test_fixture_kids_copy_is_byte_identical(self):
        rel = "conformance/fixtures/fixture-kids.json"
        self.assertEqual((coredata.DATA_DIR / rel).read_bytes(), (ROOT / rel).read_bytes())

    def test_packaged_manifest_equals_the_core_manifest_of_the_repo(self):
        manifest = load_tools_manifest()
        self.assertEqual(coredata.load_manifest(), manifest.core_manifest(ROOT))

    def test_the_packaged_root_is_the_data_dir_when_unpacked(self):
        self.assertEqual(Path(str(coredata.PACKAGED)).resolve(), coredata.DATA_DIR)
    def test_core_file_list_equals_the_tools_list(self):
        self.assertEqual(coredata.CORE_FILES, load_tools_manifest().CORE_FILES)


class Tampering(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / "data"
        shutil.copytree(coredata.DATA_DIR, self.data)

    def test_untouched_copy_loads(self):
        registry.load(self.data)

    def test_a_changed_registry_byte_is_refused(self):
        path = self.data / "spec" / "registry.json"
        path.write_bytes(path.read_bytes().replace(b'"1"', b'"2"', 1))
        with self.assertRaises(coredata.CoreDataError):
            registry.load(self.data)

    def test_a_changed_manifest_entry_is_refused(self):
        path = self.data / "core-manifest.json"
        doc = json.loads(path.read_text())
        doc["spec/registry.json"] = encoding.EMPTY_HASH
        path.write_text(json.dumps(doc))
        with self.assertRaises(coredata.CoreDataError):
            registry.load(self.data)

    def test_a_missing_registry_is_refused(self):
        (self.data / "spec" / "registry.json").unlink()
        with self.assertRaises(coredata.CoreDataError):
            registry.load(self.data)

    def test_a_manifest_missing_a_core_path_is_refused(self):
        path = self.data / "core-manifest.json"
        doc = json.loads(path.read_text())
        del doc["spec/profile.md"]
        path.write_text(json.dumps(doc))
        with self.assertRaises(coredata.CoreDataError):
            coredata.load_manifest(self.data)

    def test_a_manifest_entry_that_is_not_a_hashstr_is_refused(self):
        path = self.data / "core-manifest.json"
        doc = json.loads(path.read_text())
        doc["spec/profile.md"] = "uEiAAAA"
        path.write_text(json.dumps(doc))
        with self.assertRaises(coredata.CoreDataError):
            coredata.load_manifest(self.data)

    def test_a_registry_with_another_algorithm_is_refused_even_if_hash_matches(self):
        # A registry that passes the hash check but breaks the closed shape still fails.
        path = self.data / "spec" / "registry.json"
        raw = path.read_bytes().replace(b'"alg": "ES256",\n      "hardware_bound": true',
                                        b'"alg": "EdDSA",\n      "hardware_bound": true', 1)
        self.assertNotEqual(raw, path.read_bytes())
        path.write_bytes(raw)
        manifest = json.loads((self.data / "core-manifest.json").read_text())
        manifest["spec/registry.json"] = encoding.hashstr(raw)
        (self.data / "core-manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(registry.RegistryError):
            registry.load(self.data)


class Contents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = registry.load()

    def test_version_and_binding(self):
        self.assertEqual(self.reg.version, "1")
        self.assertEqual(self.reg.binding, "local")

    def test_production_classes(self):
        self.assertEqual(sorted(self.reg.classes(fixture=False)),
                         ["apple-se-bio", "test-sw-p256"])
        apple = self.reg.lookup_class("apple-se-bio", fixture=False)
        self.assertEqual((apple.alg, apple.user_verification, apple.status, apple.hardware_bound),
                         ("ES256", "biometric_only", "active", True))

    def test_the_first_tag_ships_no_pending_class_and_no_windows_class(self):
        for cls in self.reg.classes(fixture=True).values():
            self.assertNotEqual(cls.status, "pending-spike", cls.id)
        self.assertIsNone(self.reg.lookup_class("win-hello-hw", fixture=False))
        self.assertIsNone(self.reg.lookup_class("win-hello-hw", fixture=True))

    def test_test_only_is_data(self):
        self.assertEqual(self.reg.lookup_class("test-sw-p256", fixture=False).status, "test-only")
        self.assertEqual(self.reg.lookup_class("test-sw-p256", fixture=False).user_verification, "none")

    def test_fixture_only_class_exists_only_under_the_fixture_profile(self):
        self.assertIsNone(self.reg.lookup_class("fixture-pin", fixture=False))
        pin = self.reg.lookup_class("fixture-pin", fixture=True)
        self.assertEqual((pin.user_verification, pin.status), ("biometric_or_pin", "active"))
        self.assertIn("fixture-pin", self.reg.classes(fixture=True))
        self.assertIn("apple-se-bio", self.reg.classes(fixture=True))

    def test_unknown_class_is_none(self):
        self.assertIsNone(self.reg.lookup_class("yubikey-piv", fixture=True))

    def test_methods_are_the_ten_of_act_09(self):
        self.assertEqual(sorted(self.reg.methods), sorted([
            "local:handsal.genesis.sign", "local:handsal.device.add", "local:handsal.device.remove",
            "local:handsal.member.add", "local:handsal.chain.resolve", "local:handsal.act.endorse",
            "local:handsal.request.approve", "local:handsal.request.reject",
            "local:handsal.request.needs-info", "local:handsal.decision"]))

    def test_method_lookup_is_byte_exact(self):
        self.assertIsNone(self.reg.method("Local:Handsal.request.approve"))
        self.assertIsNone(self.reg.method("local:handsal.request.send"))
        approve = self.reg.method("local:handsal.request.approve")
        self.assertEqual(approve.head, "always")
        self.assertEqual(approve.act_extra_keys, ("expires", "recipient", "relay", "request_id"))
        self.assertEqual(approve.outputs_hash, "verdict:approve")

    def test_head_column(self):
        heads = {m: self.reg.method(m).head for m in self.reg.methods}
        self.assertEqual(heads["local:handsal.genesis.sign"], "conditional")
        self.assertEqual(heads["local:handsal.device.add"], "never")
        self.assertEqual(heads["local:handsal.chain.resolve"], "never")
        self.assertEqual(heads["local:handsal.act.endorse"], "always")
        self.assertEqual(heads["local:handsal.decision"], "always")

    def test_constants_agree_with_the_modules_that_use_them(self):
        self.assertEqual(self.reg.number("MAX_PAYLOAD"), subset.MAX_PAYLOAD)
        self.assertEqual(self.reg.number("MAX_DEPTH"), subset.MAX_DEPTH)
        self.assertEqual(self.reg.number("MAX_INPUT"), ijson.MAX_INPUT)
        self.assertEqual(self.reg.number("MAX_NESTING"), ijson.MAX_NESTING)

    def test_bounds(self):
        self.assertEqual((self.reg.number("persons", "min"), self.reg.number("persons", "max")), (2, 15))
        self.assertEqual(self.reg.number("max_tip_age_s", "max"), 86400)
        self.assertEqual(self.reg.number("chain_resolve_caps", "candidates", "max"), 17)

    def test_unknown_constant_is_an_error_not_a_default(self):
        with self.assertRaises(KeyError):
            self.reg.number("no_such_constant")


if __name__ == "__main__":
    unittest.main()
