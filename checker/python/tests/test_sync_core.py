"""The refresh script writes exactly the packaged data the checker ships."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

from handsal_check import coredata

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parents[1]


def load_script():
    spec = importlib.util.spec_from_file_location("sync_core", PROJECT / "sync_core.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Sync(unittest.TestCase):
    def test_a_fresh_sync_equals_the_packaged_data(self):
        script = load_script()
        dest = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, dest, True)
        script.sync(ROOT, dest)
        for rel in ("core-manifest.json", "spec/registry.json",
                    "conformance/fixtures/fixture-kids.json"):
            self.assertEqual((dest / rel).read_bytes(), (coredata.DATA_DIR / rel).read_bytes(), rel)

    def test_sync_refuses_a_missing_core_file(self):
        script = load_script()
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty, True)
        with self.assertRaises(SystemExit):
            script.sync(empty, empty / "out")


if __name__ == "__main__":
    unittest.main()
