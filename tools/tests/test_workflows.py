"""The CI workflows run third-party code with a token, so what they may do is pinned here.

Text checks only (the repo tools use the standard library): a tag can be moved by its owner, a
commit SHA cannot; a write permission or a secret turns a compromised action into a compromised
repository.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.MULTILINE)
SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def workflow_files():
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


class WindowsWorkflow(unittest.TestCase):
    def test_the_windows_workflow_exists(self):
        self.assertTrue((WORKFLOWS / "windows.yml").is_file())

    def test_it_runs_on_real_windows_for_the_msvc_target(self):
        text = (WORKFLOWS / "windows.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"runs-on:\s*windows-latest\b")
        self.assertIn("x86_64-pc-windows-msvc", text)


class EveryWorkflow(unittest.TestCase):
    def test_there_is_a_workflow_to_check(self):
        self.assertTrue(workflow_files())

    def test_every_uses_is_pinned_to_a_full_commit_sha(self):
        for path in workflow_files():
            refs = USES.findall(path.read_text(encoding="utf-8"))
            for ref in refs:
                with self.subTest(path=path.name, uses=ref):
                    self.assertRegex(ref, SHA_REF)

    def test_permissions_are_read_only(self):
        for path in workflow_files():
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                top = re.search(r"^permissions:[ \t]*\n((?:[ \t]+\S.*\n?)+)", text, re.MULTILINE)
                self.assertIsNotNone(top, "no top-level permissions block")
                self.assertEqual([l.strip() for l in top.group(1).splitlines() if l.strip()], ["contents: read"])
                self.assertNotRegex(text, r":\s*write\b")

    def test_no_secret_is_referenced(self):
        for path in workflow_files():
            with self.subTest(path=path.name):
                self.assertNotIn("secrets.", path.read_text(encoding="utf-8"))

    def test_a_workflow_that_gets_secrets_from_forks_is_not_used(self):
        for path in workflow_files():
            with self.subTest(path=path.name):
                self.assertNotIn("pull_request_target", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
