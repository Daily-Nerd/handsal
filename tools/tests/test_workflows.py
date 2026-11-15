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


class LinuxServerWorkflow(unittest.TestCase):
    """T13.5 (RS4, CF-10): the server build is proven on real Linux amd64, not on a Mac."""

    @classmethod
    def setUpClass(cls):
        cls.path = WORKFLOWS / "linux-server.yml"
        cls.text = cls.path.read_text(encoding="utf-8") if cls.path.is_file() else ""

    def test_the_linux_workflow_exists(self):
        self.assertTrue(self.path.is_file())

    def test_it_runs_on_a_linux_amd64_runner(self):
        self.assertRegex(self.text, r"runs-on:\s*ubuntu-24\.04\b")
        self.assertNotRegex(self.text, r"ubuntu-[\d.]+-arm|arm64\b")

    def test_it_builds_vitni_for_linux_amd64_without_cgo_from_a_pinned_source(self):
        self.assertIn("CGO_ENABLED=0", self.text)
        self.assertIn("GOOS=linux", self.text)
        self.assertIn("GOARCH=amd64", self.text)
        self.assertRegex(self.text, r"VITNI_COMMIT:\s*[0-9a-f]{40}\b")
        self.assertIn("repository: Daily-Nerd/vitni", self.text)
        self.assertIn("ref: ${{ env.VITNI_COMMIT }}", self.text)

    def test_it_builds_the_server_zipapp_twice_and_compares(self):
        self.assertIn("build_zipapp.py", self.text)
        self.assertIn("--entry handsal_check.server:main", self.text)

    def test_it_runs_the_server_tests_and_the_checker_harness_with_that_vitni(self):
        self.assertIn("-p test_server.py", self.text)
        self.assertIn("conformance/run.py", self.text)
        self.assertIn("--role checker", self.text)
        self.assertIn("--vitni", self.text)

    def test_it_runs_the_linux_installer_test(self):
        self.assertIn("tools/install/test-install-linux.sh", self.text)


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
