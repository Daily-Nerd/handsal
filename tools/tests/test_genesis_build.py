"""The genesis draft builder: it constructs a document and asks the checker, it owns no rule of its own.

Every scenario here names a fact the checker answers (a code, a hash, a byte string). The tools never decide
valid or invalid, so a test compares against the checker or against an independent reference.
"""
import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import manifest  # noqa: E402
import genesis_build  # noqa: E402
from handsal_check import profiles  # noqa: E402

BUILDER = TOOLS / "genesis_build.py"


def imported_modules(path):
    """The top-level module name of every import in the source at `path` (ast, never a text search)."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def isolated(code):
    """Run `code` in a fresh interpreter in isolated mode; return the completed process."""
    return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)


class Bootstrap(unittest.TestCase):
    def test_the_draft_names_the_production_profile_of_this_checkout(self):   # XC-1b
        self.assertEqual(genesis_build.production_profile(profiles.load()), manifest.production_profile(ROOT))

    def test_foreign_handsal_check_is_refused_and_no_crypto_loaded(self):   # XC-1c
        with tempfile.TemporaryDirectory() as tmp:
            decoy = Path(tmp) / "decoy"
            (decoy / "handsal_check").mkdir(parents=True)
            (decoy / "handsal_check" / "__init__.py").write_text("", encoding="utf-8")
            done = isolated("import sys; sys.path.insert(0, %r); import handsal_check; sys.path.insert(0, %r); "
                            "import genesis_build" % (str(decoy), str(TOOLS)))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("ImportError", done.stderr)
        self.assertIn(str(decoy), done.stderr)
        self.assertIn(str(ROOT / "checker" / "python" / "src"), done.stderr)
        clean = isolated("import sys; sys.path.insert(0, %r); import genesis_build; "
                         "print(sorted(m for m in ('cryptography', 'genesis_throwaway') if m in sys.modules))"
                         % str(TOOLS))
        self.assertEqual((clean.returncode, clean.stdout.strip()), (0, "[]"), clean.stderr)

    def test_builder_imports_no_cryptography_and_no_throwaway(self):   # XC-1a
        found = imported_modules(BUILDER)
        self.assertNotIn("cryptography", found)
        self.assertNotIn("genesis_throwaway", found)


if __name__ == "__main__":
    unittest.main()
