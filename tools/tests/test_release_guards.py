"""Release guards for the profile set (design risk 1, GP-22, CF-09, SG-17).

A founding release must not ship without three things that nothing else would notice missing: the tests that
prove the foreign-successor rule, the catalog prefix test in the tag job, and the Rust obligation that a future
`sign` resolves profiles. Each guard is a function over text, so it is seen red against a planted drift in a
throwaway copy (a test renamed, a step dropped, a `sign` written without the obligation) and then run over the
real files.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

SPEC = "spec/profile-interfaces.md"
SYNC_TESTS = "checker/python/tests/test_sync.py"
SET_TESTS = "checker/python/tests/test_profile_set.py"
WORKFLOW = ".github/workflows/linux-server.yml"
RUST_CLI = "signer/windows/core/cli.rs"
RUST_CLI_TESTS = "signer/windows/tests/cli.rs"
RUST_CORE = "signer/windows/core"
PREFIX_TESTS = ("test_a_release_keeps_every_edition_the_previous_tag_listed",
                "test_this_release_extends_the_catalog_of_the_previous_tag")
FOREIGN_SCENARIOS = range(29, 36)   # CF-09 S29 to S35, the foreign-successor rule
LOCK = "sign_is_still_the_internal_stub_until_a_rust_signer_resolves_profiles"


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def foreign_successor_tests(spec):
    """The `test_sync.py` names that CF-09 S29 to S35 cite, from the spec text itself (no second list)."""
    names = []
    for number in FOREIGN_SCENARIOS:
        line = re.search(r"^- S%d:.*$" % number, spec, re.M)
        names += re.findall(r"checker/python/tests/test_sync\.py::(\w+)", line.group(0)) if line else []
    return names


def missing_definitions(names, source):
    """The names that `source` does not define as a test function."""
    return [n for n in names if not re.search(r"^\s*def %s\(" % re.escape(n), source, re.M)]


def tag_job_problems(workflow, set_tests):
    """What the tag job lacks: the `--tags` run, each catalog prefix test by name, and the test it names."""
    problems = []
    if not re.search(r"conformance/run\.py .*--tags\b", workflow):
        problems.append("no step runs conformance/run.py --tags")
    for name in PREFIX_TESTS:
        if not re.search(r"^\s*-k %s\s*$" % name, workflow, re.M):
            problems.append("the job does not run %s" % name)
    problems += ["%s is not defined" % n for n in missing_definitions(PREFIX_TESTS, set_tests)]
    return problems


def rust_sign_problems(cli, cli_tests, core):
    """The Rust obligation: while `sign` is the `internal` stub the lock test stays and names the obligation; once a
    `sign` exists the core resolves profiles through `Profiles::resolve` and answers `profile_not_current`."""
    stub = re.search(r'"sign"\s*=>\s*outcome_for\(Refusal::new\("internal"\)\)', cli)
    if stub:
        problems = []
        body = re.search(r"fn %s\(\) \{(.*?)\n\}" % LOCK, cli_tests, re.S)
        if not body:
            return ["the lock test %s is gone while sign is still the internal stub" % LOCK]
        for words in ("Profiles::resolve", "profile_not_current"):
            if words not in body.group(1):
                problems.append("the lock test no longer names %s" % words)
        return problems
    problems = []
    if not re.search(r"Profiles::resolve|\.resolve\(", core):
        problems.append("a Rust sign exists and never calls Profiles::resolve")
    if "profile_not_current" not in core:
        problems.append("a Rust sign exists and never answers profile_not_current")
    return problems


class ForeignSuccessorTests(unittest.TestCase):
    def test_the_seven_cf09_names_exist_in_test_sync(self):
        names = foreign_successor_tests(read(SPEC))
        self.assertEqual(len(names), 7, names)
        self.assertEqual(missing_definitions(names, read(SYNC_TESTS)), [])

    def test_a_renamed_or_deleted_test_is_seen(self):
        names = foreign_successor_tests(read(SPEC))
        source = read(SYNC_TESTS)
        renamed = source.replace("def %s(" % names[0], "def %s_renamed(" % names[0])
        self.assertEqual(missing_definitions(names, renamed), [names[0]])
        self.assertEqual(missing_definitions(names, source.replace("def %s(" % names[3], "def x(")), [names[3]])
        self.assertEqual(missing_definitions(names, "# " + " ".join(names)), names, "a comment is no definition")

    def test_a_spec_that_cites_fewer_than_seven_is_seen(self):
        spec = read(SPEC)
        thin = re.sub(r"(^- S31:.*?)T: .*$", r"\1T: none", spec, flags=re.M)
        self.assertNotEqual(len(foreign_successor_tests(thin)), 7)


class TagJob(unittest.TestCase):
    def test_the_tag_job_runs_the_tag_sets_and_the_catalog_prefix_tests(self):
        self.assertEqual(tag_job_problems(read(WORKFLOW), read(SET_TESTS)), [])

    def test_a_dropped_step_or_a_renamed_test_is_seen(self):
        workflow, set_tests = read(WORKFLOW), read(SET_TESTS)
        plants = {
            "the tag run dropped": (workflow.replace("--role checker --tags", "--role checker"), set_tests),
            "a prefix test dropped from the job": (workflow.replace("-k %s\n" % PREFIX_TESTS[1], ""), set_tests),
            "a prefix test renamed in the job": (workflow.replace(PREFIX_TESTS[0], PREFIX_TESTS[0] + "_x"), set_tests),
            "a prefix test renamed in the suite": (workflow, set_tests.replace("def %s(" % PREFIX_TESTS[1], "def other(")),
        }
        for what, (flow, tests) in plants.items():
            with self.subTest(what):
                self.assertNotEqual(tag_job_problems(flow, tests), [])


class RustSignObligation(unittest.TestCase):
    def core(self):
        return "\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / RUST_CORE).glob("*.rs")))

    def test_the_rust_sign_is_the_stub_with_its_lock_or_it_resolves_profiles(self):
        self.assertEqual(rust_sign_problems(read(RUST_CLI), read(RUST_CLI_TESTS), self.core()), [])

    def test_a_sign_written_without_the_obligation_is_seen(self):
        cli = read(RUST_CLI)
        written = cli.replace('"keygen" | "pubkey" | "sign" => outcome_for(Refusal::new("internal"))',
                              '"keygen" | "pubkey" => outcome_for(Refusal::new("internal")),\n        "sign" => finish(Ok(JValue::Null))')
        self.assertNotEqual(written, cli)
        self.assertEqual(len(rust_sign_problems(written, read(RUST_CLI_TESTS), "fn sign() {}")), 2)
        ok = rust_sign_problems(written, read(RUST_CLI_TESTS), "Profiles::resolve(h) ... profile_not_current")
        self.assertEqual(ok, [])

    def test_a_deleted_or_blunted_lock_is_seen(self):
        tests = read(RUST_CLI_TESTS)
        self.assertNotEqual(rust_sign_problems(read(RUST_CLI), tests.replace("fn %s(" % LOCK, "fn renamed("), ""), [])
        blunt = tests.replace("Profiles::resolve", "the resolver")
        self.assertEqual(rust_sign_problems(read(RUST_CLI), blunt, ""), ["the lock test no longer names Profiles::resolve"])


if __name__ == "__main__":
    unittest.main()
