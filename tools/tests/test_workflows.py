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

    def test_it_runs_the_throwaway_suite_so_a_checker_change_cannot_break_it_unseen(self):
        """A suite no gate runs is a hidden link: the checker can change under it. The step is the runner of
        tools/release/final-proof.sh, unconditional and not soft. Where no vitni is installed its real-vitni
        test asserts verifier_unavailable, so nothing is skipped."""
        command = "uv run --project tools/throwaway python -I -m unittest discover -s tools/throwaway/tests -t tools/throwaway"
        found = [s for s in steps_of(self.text) if command in s]
        self.assertEqual(len(found), 1)
        self.assertNotRegex(found[0], r"(?m)^\s+if:")
        for soft in ("|| true", "|| echo", "|| :", "set +e", "continue-on-error"):
            self.assertNotIn(soft, found[0])
        proof = (ROOT / "tools" / "release" / "final-proof.sh").read_text(encoding="utf-8")
        self.assertIn(command, proof)

    def proof_command(self, name):
        """The command of a final-proof.sh step, with its `$pl_uv` wrapper read as plain `uv`: the one source of
        the runner, so the CI step and the local proof cannot drift."""
        proof = (ROOT / "tools" / "release" / "final-proof.sh").read_text(encoding="utf-8")
        lines = [l for l in proof.splitlines() if l.startswith("step %s " % name)]
        self.assertEqual(len(lines), 1)
        return lines[0][len("step %s " % name):].replace("$pl_uv", "uv", 1)

    def test_every_unit_suite_of_the_final_proof_runs_in_the_job_by_the_same_command(self):
        """A suite no gate runs is a hidden link: a checker change can break it unseen."""
        for name in ("tools-tests", "throwaway-tests", "checker-tests", "conformance-tests", "gen-tests"):
            with self.subTest(suite=name):
                command = self.proof_command(name)
                self.assertTrue(command.startswith("uv run "), command)
                # the whole command: the narrower runs of the same suite (-p, -k) are not this step
                found = [s for s in steps_of(self.text) if re.search(re.escape(command) + r"(?!\S)(?!\s+(?:-p|-k)\b)", " ".join(s.split()))]
                self.assertEqual(len(found), 1)
                self.assertNotRegex(found[0], r"(?m)^\s+if:")
                for soft in ("|| true", "|| echo", "|| :", "set +e", "continue-on-error", "-k skip"):
                    self.assertNotIn(soft, found[0])

    def test_it_runs_the_catalog_check_so_a_published_reason_class_cannot_change_unseen(self):
        """The check compares the class table with the one of the previous tag (a published class never changes). No
        other step runs it, so a pull request could change a class and pass. The step is the `catalog` step of
        tools/release/final-proof.sh, unconditional and not soft; the checkout it needs fetches every tag."""
        command = self.proof_command("catalog")
        self.assertTrue(command.startswith("uv run "), command)
        found = [s for s in steps_of(self.text) if re.search(re.escape(command) + r"(?!\S)(?!\s+--)", " ".join(s.split()))]
        self.assertEqual(len(found), 1)
        self.assertNotRegex(found[0], r"(?m)^\s+if:")
        for soft in ("|| true", "|| echo", "|| :", "set +e", "continue-on-error", "2>/dev/null"):
            self.assertNotIn(soft, found[0])

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

    def test_the_go_pin_is_not_older_than_the_stdlib_fixes_a_scan_reported(self):
        # The binary carries the Go standard library of its toolchain. A scan of the v0.2.0 build (go1.25.1) found
        # a CRITICAL and 25 HIGH issues in it; a later scan of go1.25.14, the last of a line Go no longer patches,
        # still found four HIGH that only 1.26.9, 1.26.10, 1.27.2 and 1.27.3 fixed. The release gate (vuln-gate.sh)
        # is what finds the next ones; this keeps the pin from being moved back to a version known to be flagged.
        pin = tuple(int(n) for n in (RELEASE / "go-version").read_text(encoding="utf-8").strip().split("."))
        self.assertGreaterEqual(pin, (1, 26, 10))

    def test_the_release_scripts_hold_no_vitni_source_url_or_checkout(self):
        for name in self.SCRIPTS:
            text = (RELEASE / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                self.assertNotIn("git clone", text)
                self.assertNotIn("Daily-Nerd/vitni", text)


def steps_of(text):
    """The steps of a one-job workflow as text blocks, split at each `      - ` line (the job's step list)."""
    blocks, current = [], None
    for line in text.splitlines():
        if re.match(r"^      - ", line):
            current = [line]
            blocks.append(current)
        elif current is not None and (line.startswith("        ") or not line.strip()):
            current.append(line)
        else:
            current = None
    return ["\n".join(b) for b in blocks]


class ConformanceTagRun(unittest.TestCase):
    """(CF-15, GP-22 S3): the Linux job also runs the vectors of every older edition from its tag, and the
    catalog prefix test. A job that finds no tag must fail, so nothing in it may make a step soft or conditional."""

    @classmethod
    def setUpClass(cls):
        cls.text = (WORKFLOWS / "linux-server.yml").read_text(encoding="utf-8")
        cls.steps = steps_of(cls.text)

    def tag_steps(self):
        return [step for step in self.steps if "--tags" in step or "test_profile_set.py" in step]

    def test_the_checkout_fetches_the_full_history_and_the_tags(self):
        checkout = [s for s in self.steps if "actions/checkout" in s]
        self.assertEqual(len(checkout), 1)
        self.assertRegex(checkout[0], r"fetch-depth:\s*0\b")
        self.assertRegex(checkout[0], r"fetch-tags:\s*true\b")

    def test_the_tag_run_uses_the_checker_conformance_build_over_the_catalog_tags(self):
        runs = [s for s in self.steps if "conformance/run.py" in s and "--tags" in s]
        self.assertEqual(len(runs), 1)
        self.assertIn("--role checker", runs[0])
        self.assertIn("--vitni", runs[0])

    def test_the_catalog_prefix_test_runs_in_the_job(self):
        steps = [s for s in self.steps if "test_profile_set.py" in s]
        self.assertEqual(len(steps), 1)
        for name in ("test_a_release_keeps_every_edition_the_previous_tag_listed",
                     "test_this_release_extends_the_catalog_of_the_previous_tag"):
            self.assertIn(name, steps[0])

    def test_nothing_in_the_job_continues_on_error(self):
        for path in workflow_files():
            with self.subTest(path=path.name):
                self.assertNotIn("continue-on-error", path.read_text(encoding="utf-8"))

    def test_no_tag_step_is_conditional_or_soft(self):
        found = self.tag_steps()
        self.assertEqual(len(found), 2)
        for step in found:
            with self.subTest(step=step.splitlines()[0]):
                self.assertNotRegex(step, r"(?m)^\s+if:")
                for soft in ("|| true", "|| echo", "|| :", "set +e", "2>/dev/null", "-k skip"):
                    self.assertNotIn(soft, step)

    def test_the_job_has_no_condition_that_skips_a_missing_tag(self):
        self.assertNotRegex(self.text, r"(?m)^\s+if:.*(tag|refs)")
        self.assertNotRegex(self.text, r"(?i)git (tag|rev-parse|show-ref)[^\n]*(\|\||&&)\s*(exit 0|true|echo)")


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
