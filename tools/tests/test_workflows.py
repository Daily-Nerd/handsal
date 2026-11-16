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

    def test_it_builds_vitni_for_linux_amd64_through_the_one_build_command(self):
        """T15.10: no `go build` here. The command holds the flags and reads the commit and the Go version."""
        self.assertIn("sh tools/release/build-vitni.sh linux amd64", self.text)
        for local in ("go build", "CGO_ENABLED", "-trimpath", "-buildvcs", "GOOS=", "GOARCH="):
            self.assertNotIn(local, self.text)

    def test_the_go_version_is_the_one_of_the_pin_file(self):
        self.assertRegex(self.text, r"go-version-file:\s*tools/release/go-version\b")
        self.assertNotRegex(self.text, re.compile(r"^\s*go-version:\s*\S", re.MULTILINE))
        self.assertNotIn("vitni-src/go/go.mod", self.text)

    def test_the_vitni_commit_has_one_source_that_no_workflow_or_script_copies(self):
        """T15.8, T15.10: the release scripts, the CI job and the vitni command use one commit, read from one file."""
        source = ROOT / "tools" / "release" / "vitni-commit"
        self.assertTrue(source.is_file())
        commit = source.read_text(encoding="utf-8")
        self.assertRegex(commit, r"\A[0-9a-f]{40}\n\Z")
        for path in [self.path] + sorted((ROOT / "tools" / "release").glob("*.sh")):
            with self.subTest(path=path.name):
                self.assertNotIn(commit.strip(), path.read_text(encoding="utf-8"))
        command = (ROOT / "tools" / "release" / "build-vitni.sh").read_text(encoding="utf-8")
        self.assertIn("vitni-commit", command)

    def test_the_job_does_not_check_out_vitni_itself(self):
        self.assertNotIn("Daily-Nerd/vitni", self.text)
        self.assertNotIn("VITNI_COMMIT", self.text)

    def test_it_runs_the_tests_of_the_vitni_command(self):
        self.assertIn("sh tools/release/test-build-vitni.sh", self.text)

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


RELEASE = ROOT / "tools" / "release"


class OneVitniBuild(unittest.TestCase):
    """T15.10: one pin gives one binary per platform and Go version. The CI job and both release scripts reach vitni
    only through `tools/release/build-vitni.sh`, so the build flags and the pins exist in one place."""

    SCRIPTS = ("build-macos.sh", "build-linux-server.sh")

    def untested_files(self):
        files = sorted(WORKFLOWS.glob("*.yml")) + sorted(p for p in RELEASE.glob("*.sh") if not p.name.startswith("test-"))
        return [p for p in files if p.is_file()]

    def test_the_flags_of_the_build_are_in_one_file(self):
        holders = [p.name for p in self.untested_files() if "-buildvcs" in p.read_text(encoding="utf-8")]
        self.assertEqual(holders, ["build-vitni.sh"])

    def test_go_build_is_run_in_one_file(self):
        holders = [p.name for p in self.untested_files() if "go build" in p.read_text(encoding="utf-8")]
        self.assertEqual(holders, ["build-vitni.sh"])

    def test_the_flags_the_build_needs_are_there(self):
        text = (RELEASE / "build-vitni.sh").read_text(encoding="utf-8")
        for flag in ("-trimpath", "-buildvcs=false", "CGO_ENABLED=0", "GOTOOLCHAIN"):
            self.assertIn(flag, text)

    def test_both_release_scripts_and_the_job_call_it(self):
        self.assertIn("build-vitni.sh", (WORKFLOWS / "linux-server.yml").read_text(encoding="utf-8"))
        library = (RELEASE / "release-lib.sh").read_text(encoding="utf-8")
        self.assertIn("build-vitni.sh", library)
        for name in self.SCRIPTS:
            with self.subTest(script=name):
                text = (RELEASE / name).read_text(encoding="utf-8")
                self.assertIn("release-lib.sh", text)
                self.assertIn("rl_build_all", text)

    def test_the_go_version_is_pinned_in_one_file_of_one_line(self):
        self.assertRegex((RELEASE / "go-version").read_text(encoding="utf-8"), r"\A[0-9]+\.[0-9]+\.[0-9]+\n\Z")
        for path in self.untested_files():
            with self.subTest(path=path.name):
                self.assertNotRegex(path.read_text(encoding="utf-8"), r"go1\.[0-9]+\.[0-9]+")

    def test_the_release_scripts_hold_no_vitni_source_url_or_checkout(self):
        for name in self.SCRIPTS:
            text = (RELEASE / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                self.assertNotIn("git clone", text)
                self.assertNotIn("Daily-Nerd/vitni", text)


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
