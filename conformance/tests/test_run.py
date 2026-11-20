import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import run

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STUB = os.path.join(DATA, "stub_impl.py")


REPO = os.path.dirname(os.path.dirname(HERE))


def _manifest():
    """tools/manifest.py, the owner of the bundle hash (CF-01), loaded by path under -I."""
    spec = importlib.util.spec_from_file_location("handsal_manifest_for_tests", os.path.join(REPO, "tools", "manifest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def impl(mode):
    return [sys.executable, STUB, mode]


def write_vector(directory, name, **fields):
    path = os.path.join(directory, name.replace("/", "_") + ".json")
    with open(path, "w") as fh:
        json.dump(dict(name=name, **fields), fh)
    return path


class LoadTests(unittest.TestCase):
    def test_vector_without_anchor_is_rejected(self):
        # cf/anchor-required
        with tempfile.TemporaryDirectory() as d:
            path = write_vector(d, "cf/no-anchor", command="fold", input={})
            with self.assertRaises(run.VectorError):
                run.load_vector(path)

    def test_vector_needs_exactly_one_input_form(self):
        with tempfile.TemporaryDirectory() as d:
            both = write_vector(d, "cf/both", command="fold", input={}, input_raw="{}", anchor="x")
            none = write_vector(d, "cf/none", command="fold", anchor="x")
            for path in (both, none):
                with self.assertRaises(run.VectorError):
                    run.load_vector(path)

    def test_vector_needs_name_and_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.json")
            with open(path, "w") as fh:
                json.dump({"input": {}, "anchor": "x"}, fh)
            with self.assertRaises(run.VectorError):
                run.load_vector(path)

    def test_generator_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "_gen"))
            write_vector(os.path.join(d, "_gen"), "x/y", command="fold", input={})
            write_vector(d, "a/b", command="fold", input={}, anchor="x")
            names = [v["name"] for v in run.load_vectors(d)]
            self.assertEqual(names, ["a/b"])

    def test_missing_anchor_aborts_the_run_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cf/no-anchor", command="fold", input={})
            code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))], out=_Sink())
            self.assertEqual(code, 2)


class _Sink:
    def __init__(self):
        self.text = ""

    def write(self, s):
        self.text += s


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def run_harness(self, impls, *extra):
        out = _Sink()
        args = ["--vectors", self.dir]
        for i in impls:
            args += ["--impl", " ".join(i)]
        code = run.main(args + list(extra), out=out)
        return code, out.text

    def test_pass(self):
        write_vector(self.dir, "cf/pass", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("ok")])
        self.assertEqual(code, 0)
        self.assertIn("PASS cf/pass", text)

    def test_anchor_fail(self):
        write_vector(self.dir, "cf/anchor", command="fold", input={"a": 1},
                     anchor='{"bytes":999,"command":"fold"}')
        code, text = self.run_harness([impl("ok")])
        self.assertEqual(code, 1)
        self.assertIn("ANCHOR-FAIL cf/anchor", text)

    def test_diverge(self):
        # cf/harness-diverge-selftest
        write_vector(self.dir, "cf/harness-diverge-selftest", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("ok"), impl("diverge")])
        self.assertEqual(code, 1)
        self.assertIn("DIVERGE cf/harness-diverge-selftest", text)

    def test_two_agreeing_impls_pass(self):
        write_vector(self.dir, "cf/two", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("ok"), impl("ok")])
        self.assertEqual(code, 0)
        self.assertIn("PASS cf/two", text)

    def test_two_impls_agreeing_on_a_wrong_answer_is_anchor_fail(self):
        write_vector(self.dir, "cf/wrong", command="fold", input={"a": 1},
                     anchor='{"bytes":1,"command":"fold"}')
        code, text = self.run_harness([impl("ok"), impl("ok")])
        self.assertIn("ANCHOR-FAIL cf/wrong", text)
        self.assertEqual(code, 1)

    def test_crash_is_not_a_pass(self):
        write_vector(self.dir, "cf/crash", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("crash")])
        self.assertEqual(code, 1)
        self.assertIn("ANCHOR-FAIL cf/crash", text)

    def test_group_filter(self):
        write_vector(self.dir, "jcs/a", command="fold", input={}, anchor='{"bytes":3,"command":"fold"}')
        write_vector(self.dir, "cli/b", command="fold", input={}, anchor='{"bytes":999,"command":"fold"}')
        code, text = self.run_harness([impl("ok")], "--group", "jcs")
        self.assertEqual(code, 0)
        self.assertIn("PASS jcs/a", text)
        self.assertNotIn("cli/b", text)

    def test_zero_selected_vectors_is_a_failure(self):
        write_vector(self.dir, "jcs/a", command="fold", input={}, anchor="x")
        code, _ = self.run_harness([impl("ok")], "--group", "nothing")
        self.assertEqual(code, 2)


class ImplTests(unittest.TestCase):
    def test_relative_command_is_refused(self):
        # no PATH lookup
        code = run.main(["--vectors", DATA, "--impl", "python3 stub"], out=_Sink())
        self.assertEqual(code, 2)

    def test_impl_is_required(self):
        self.assertEqual(run.main(["--vectors", DATA], out=_Sink()), 2)

    def test_parse_impl_accepts_absolute_argv(self):
        self.assertEqual(run.parse_impl("/bin/echo a b"), ["/bin/echo", "a", "b"])

    def test_environment_does_not_choose_the_command(self):
        os.environ["HANDSAL_IMPL"] = "/nonexistent"
        self.addCleanup(os.environ.pop, "HANDSAL_IMPL")
        self.assertEqual(run.main(["--vectors", DATA], out=_Sink()), 2)


class PaddingTests(unittest.TestCase):
    def test_padded_stdin_is_one_byte_over_max_input(self):
        vector = {"name": "cli/over", "command": "fold", "input": {"acts": [], "note": ""},
                  "pad": ["note"], "anchor": "x"}
        data = run.build_stdin(vector)
        self.assertEqual(len(data), run.MAX_INPUT + 1)
        self.assertEqual(data[-1:], b"\n")
        parsed = json.loads(data)
        self.assertEqual(parsed["acts"], [])
        self.assertEqual(set(parsed["note"]), {"a"})

    def test_padding_reaches_a_nested_string(self):
        vector = {"name": "cli/over", "command": "fold", "input": {"x": {"y": ["", "s"]}},
                  "pad": ["x", "y", 1], "anchor": "x"}
        data = run.build_stdin(vector)
        self.assertEqual(len(data), run.MAX_INPUT + 1)
        self.assertTrue(json.loads(data)["x"]["y"][1].startswith("s"))

    def test_pad_target_must_be_a_string(self):
        vector = {"name": "cli/over", "command": "fold", "input": {"n": 1},
                  "pad": ["n"], "anchor": "x"}
        with self.assertRaises(run.VectorError):
            run.build_stdin(vector)

    def test_pad_needs_input_not_input_raw(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_vector(d, "cli/bad", command="fold", input_raw="{}", pad=["a"], anchor="x")
            with self.assertRaises(run.VectorError):
                run.load_vector(path)

    def test_nothing_is_stored(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cli/over", command="fold", input={"note": ""}, pad=["note"], anchor="x")
            total = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
            self.assertLess(total, 1024)

    def test_padded_vector_reaches_the_stub(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cli/over", command="fold", input={"note": ""}, pad=["note"],
                         anchor='{"bytes":%d,"command":"fold"}' % (run.MAX_INPUT + 1))
            out = _Sink()
            code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))], out=out)
            self.assertEqual(code, 0, out.text)


class StdinTests(unittest.TestCase):
    def test_input_is_compact_json_plus_lf(self):
        vector = {"name": "a/b", "command": "fold", "input": {"b": 1, "a": "é"}, "anchor": "x"}
        self.assertEqual(run.build_stdin(vector), '{"b":1,"a":"é"}\n'.encode("utf-8"))

    def test_input_raw_is_passed_through_byte_for_byte(self):
        raw = '{"a":1,"a":2}'
        vector = {"name": "a/b", "command": "fold", "input_raw": raw, "anchor": "x"}
        self.assertEqual(run.build_stdin(vector), raw.encode("utf-8"))

    def test_input_raw_reaches_the_impl_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "a/raw", command="subset", input_raw='{"a":1,"a":2}',
                         anchor='{"bytes":13,"command":"subset"}')
            out = _Sink()
            code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))], out=out)
            self.assertEqual(code, 0, out.text)


class CommandsSubsetTests(unittest.TestCase):
    def test_commands_subset_skips_checker_only_commands(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "rnd/a", command="render", input={}, anchor='{"bytes":3,"command":"render"}')
            write_vector(d, "fld/b", command="fold", input={}, anchor='{"bytes":999,"command":"fold"}')
            out = _Sink()
            code = run.main(["--vectors", d, "--commands", "render,emit",
                             "--impl", " ".join(impl("ok"))], out=out)
            self.assertEqual(code, 0, out.text)
            self.assertIn("PASS rnd/a", out.text)
            self.assertNotIn("fld/b", out.text)


class RoleTests(unittest.TestCase):
    """CF-04: the harness owns which vectors a checker and a signer run."""

    def _dir(self, d):
        for name, command in (("rnd/a", "render"), ("sgn/e", "emit"), ("fld/f", "fold"),
                              ("cli/x", "x"), ("jcs/s", "subset"), ("rck/r", "recheck-act")):
            write_vector(d, name, command=command, input={},
                         anchor='{"bytes":3,"command":"%s"}' % command)

    def _run(self, d, *extra):
        out = _Sink()
        code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))] + list(extra), out=out)
        return code, out.text

    def test_signer_role_runs_render_and_emit_only(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, text = self._run(d, "--role", "signer")
            self.assertIn("PASS rnd/a", text)
            self.assertIn("PASS sgn/e", text)
            for other in ("fld/f", "cli/x", "jcs/s", "rck/r"):
                self.assertNotIn(other, text)

    def test_checker_role_runs_every_command_but_emit(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, text = self._run(d, "--role", "checker")
            self.assertNotIn("sgn/e", text)
            for name in ("rnd/a", "fld/f", "cli/x", "jcs/s", "rck/r"):   # `recheck-act` (VR-17) is a checker command
                self.assertIn(name, text)

    def test_commands_still_filters_within_a_role(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, text = self._run(d, "--role", "signer", "--commands", "emit")
            self.assertIn("sgn/e", text)
            self.assertNotIn("rnd/a", text)

    def test_unknown_role_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, _ = self._run(d, "--role", "both")
            self.assertEqual(code, 2)


class IsolatedScriptTests(unittest.TestCase):
    """The harness is run as a script under -I, which drops the script dir from sys.path."""

    def test_run_py_works_under_isolated_mode(self):
        # Discover adds the conformance dir to sys.path, which hid a missing path setup.
        script = os.path.join(os.path.dirname(HERE), "run.py")
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cf/pass", command="fold", input={"a": 1},
                         anchor='{"bytes":8,"command":"fold"}')
            proc = subprocess.run(
                [sys.executable, "-I", script, "--vectors", d, "--impl", " ".join(impl("ok"))],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=d)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn("PASS cf/pass", proc.stdout.decode())


PASSING = '{"bytes":8,"command":"fold"}'     # what the stub answers to the input {"a": 1}
WRONG = '{"bytes":999,"command":"fold"}'


class TagRepo:
    """A temporary git repository that stands for the project: editions are tagged commits holding a core and a
    vector set, and the working tree holds the catalog, the pins and the current vectors (CF-15)."""

    def __init__(self, test):
        self.manifest = _manifest()
        self.root = tempfile.mkdtemp()
        test.addCleanup(shutil.rmtree, self.root)
        self.git("init", "-q", "-b", "main")
        self.rows = []

    def git(self, *args, check=True):
        proc = subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "tag.gpgsign=false", "-C", self.root] + list(args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)
        return proc.stdout.decode().strip()

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)

    def vectors(self, vectors, folder="conformance/vectors"):
        """Replace the vector files of `folder` with `{name: anchor}`."""
        full = os.path.join(self.root, folder)
        os.makedirs(full, exist_ok=True)
        for old in os.listdir(full):
            if old.endswith(".json"):
                os.remove(os.path.join(full, old))
        for name, anchor in vectors.items():
            self.write("%s/%s.json" % (folder, name.replace("/", ".")),
                       json.dumps(dict(name=name, command="fold", input={"a": 1}, anchor=anchor)))

    def core(self, text):
        for rel in self.manifest.CORE_FILES:
            self.write(rel, "%s %s\n" % (text, rel))

    def edition(self, label, tag, vectors, core=None, extra=()):
        """Commit a core and a vector set, write the bundle manifest, tag it and record the catalog row."""
        self.core(core or label)
        self.vectors(vectors)
        for rel, text in extra:
            self.write(rel, text)
        self.manifest.write_bundle_manifest(self.root)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", label)
        self.git("tag", tag)
        self.rows.append({"label": label, "production": self.manifest.production_profile(self.root),
                          "fixture": self.manifest.fixture_profile(self.root),
                          "bundle": self.manifest.bundle_hash(self.root), "tag": tag})
        return self.rows[-1]

    def publish(self, current=None, rows=None):
        """The working tree after the last tag: the catalog, and the pins of the unreleased current core."""
        self.write("profiles/catalog.json", json.dumps(self.rows if rows is None else rows))
        self.write("conformance/pins.json", json.dumps({"production_profile": current or "uUnreleasedCore"}))

    def run(self, *extra, vectors=None):
        out = _Sink()
        directory = vectors or os.path.join(self.root, "conformance", "vectors")
        args = ["--root", self.root, "--vectors", directory, "--impl", " ".join(impl("ok")), "--tags"] + list(extra)
        return run.main(args, out=out), out.text


class TagRunTests(unittest.TestCase):
    def setUp(self):
        self.repo = TagRepo(self)

    def two_editions(self):
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING, "cf/shared": PASSING})
        self.repo.edition("edition-2", "v2", {"cf/shared": PASSING, "cf/two": PASSING})
        self.repo.vectors({"cf/shared": PASSING})      # the current tree's own set, after the last tag
        self.repo.publish()

    def test_every_catalog_tag_vector_set_runs_against_the_current_build(self):   # CF-15 S1
        self.two_editions()
        head, status = self.repo.git("rev-parse", "HEAD"), self.repo.git("status", "--porcelain")
        code, text = self.repo.run()
        self.assertEqual(code, 0, text)
        for line in ("PASS cf/shared", "[edition-1] PASS cf/one", "[edition-1] PASS cf/shared",
                     "[edition-2] PASS cf/two", "[edition-2] PASS cf/shared"):
            self.assertIn(line, text)
        for label, tag in (("edition-1", "v1"), ("edition-2", "v2")):
            self.assertIn("edition %s (%s): bundle hash matches, 2 vectors, 0 not passing" % (label, tag), text)
        self.assertIn("2 tag sets run", text)
        self.assertEqual(self.repo.git("rev-parse", "HEAD"), head)
        self.assertEqual(self.repo.git("status", "--porcelain"), status)

    def test_the_run_reads_the_tag_and_never_the_working_tree(self):
        self.two_editions()
        before = sorted(os.listdir(os.path.join(self.repo.root, "conformance", "vectors")))
        code, text = self.repo.run()
        self.assertEqual(code, 0, text)
        self.assertEqual(sorted(os.listdir(os.path.join(self.repo.root, "conformance", "vectors"))), before)
        self.assertNotIn("[edition-1] PASS cf/two", text)
        self.assertNotIn("[edition-2] PASS cf/one", text)

    def test_an_entry_the_current_core_equals_runs_from_the_tree_only(self):
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING})
        self.repo.edition("edition-2", "v2", {"cf/two": PASSING})
        self.repo.publish(current=self.repo.rows[1]["production"])
        code, text = self.repo.run()
        self.assertEqual(code, 0, text)
        self.assertIn("[edition-1] PASS cf/one", text)
        self.assertNotIn("[edition-2]", text)
        self.assertIn("1 tag sets run", text)

    def test_the_generator_directory_and_a_non_vector_file_of_a_tag_are_no_vectors(self):
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING}, extra=[
            ("conformance/vectors/_gen/notes.json", "[]"), ("conformance/vectors/README.txt", "not a vector")])
        self.repo.publish()
        code, text = self.repo.run()
        self.assertEqual(code, 0, text)
        self.assertIn("edition edition-1 (v1): bundle hash matches, 1 vectors, 0 not passing", text)

    def test_the_owner_signed_directory_of_a_tag_runs_too(self):
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING})
        self.repo.vectors({"pro/signed": PASSING}, folder="conformance/vectors/prod")
        self.repo.manifest.write_bundle_manifest(self.repo.root)
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", "signed")
        self.repo.git("tag", "-f", "v1")
        self.repo.rows[0]["bundle"] = self.repo.manifest.bundle_hash(self.repo.root)
        self.repo.publish()
        code, text = self.repo.run()
        self.assertEqual(code, 0, text)
        self.assertIn("[edition-1] PASS pro/signed", text)

    def test_an_old_tag_is_read_by_its_own_bundle_list_not_the_current_rule(self):   # CF-15 S5
        repo = self.repo
        repo.core("edition-1")
        repo.vectors({"cf/one": PASSING})
        repo.write("conformance/vectors/cf.unlisted.json",
                   json.dumps(dict(name="cf/unlisted", command="fold", input={"a": 1}, anchor=WRONG)))
        manifest = repo.manifest
        files = dict(manifest.core_manifest(repo.root))
        with open(os.path.join(repo.root, "conformance/vectors/cf.one.json"), "rb") as fh:
            files["conformance/vectors/cf.one.json"] = manifest.hashstr(fh.read())
        bundle = manifest.bundle_hash_of(files)
        repo.write("spec/MANIFEST.json", json.dumps({"bundle": bundle, "files": files}))
        repo.git("add", "-A")
        repo.git("commit", "-q", "-m", "edition-1")
        repo.git("tag", "v1")
        repo.rows.append({"label": "edition-1", "production": "uOldCore", "fixture": "uOldFixture",
                          "bundle": bundle, "tag": "v1"})
        repo.vectors({"cf/one": PASSING})
        repo.publish()
        code, text = repo.run()
        self.assertEqual(code, 0, text)
        self.assertIn("[edition-1] PASS cf/one", text)
        self.assertNotIn("cf/unlisted", text)
        self.assertIn("edition edition-1 (v1): bundle hash matches, 1 vectors, 0 not passing", text)

    def test_a_tag_set_the_filter_selects_nothing_from_is_reported_not_failed(self):   # CF-15 S6
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING, "cf/two": PASSING})
        self.repo.vectors({"prf/now": PASSING})
        self.repo.publish()
        code, text = self.repo.run("--group", "prf")
        self.assertEqual(code, 0, text)
        self.assertIn("edition edition-1 (v1): bundle hash matches, 0 of 2 selected", text)
        self.assertNotIn("[edition-1]", text)
        self.assertIn("1 tag sets run", text)
        # the bundle hash is still checked under a filter
        self.repo.publish(rows=[dict(self.repo.rows[0], bundle="uWrong")])
        code, text = self.repo.run("--group", "prf")
        self.assertEqual(code, 2, text)
        self.assertRegex(text, r"ERROR .*edition-1")

    def test_a_tag_with_no_vector_fails_the_run(self):   # CF-15 S4
        self.repo.edition("edition-1", "v1", {})
        self.repo.vectors({"cf/now": PASSING})
        self.repo.publish()
        for extra in ((), ("--group", "cf")):
            with self.subTest(extra=extra):
                code, text = self.repo.run(*extra)
                self.assertEqual(code, 2, text)
                self.assertRegex(text, r"ERROR .*edition-1.*v1")

    def test_a_missing_tag_or_a_changed_bundle_fails_the_run_loudly(self):   # CF-15 S2
        self.two_editions()
        good = [dict(r) for r in self.repo.rows]
        base = self.repo.git("rev-parse", "v1")

        def refused(case, rows, label):
            self.repo.publish(rows=rows)
            code, text = self.repo.run()
            with self.subTest(case=case):
                self.assertEqual(code, 2, text)
                self.assertRegex(text, r"ERROR .*%s" % label)
                self.assertNotIn("[%s] PASS" % label, text)

        refused("a tag that does not exist", [dict(good[0], tag="v9"), good[1]], "edition-1")
        refused("a recorded bundle that is wrong", [good[0], dict(good[1], bundle=good[0]["bundle"])], "edition-2")
        refused("a branch of the same name is no tag", [dict(good[0], tag="main"), good[1]], "edition-1")
        refused("a tag name that climbs out of refs/tags", [dict(good[0], tag="../heads/main"), good[1]], "edition-1")
        refused("an entry with no tag", [{k: v for k, v in good[0].items() if k != "tag"}, good[1]], "edition-1")
        refused("an entry with an empty bundle", [dict(good[0], bundle=""), good[1]], "edition-1")
        # a re-pointed tag: v1 now names a commit whose vector set (and so whose bundle) is another one
        self.repo.vectors({"cf/one": PASSING, "cf/sneaked": PASSING})
        self.repo.manifest.write_bundle_manifest(self.repo.root)
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", "other")
        self.repo.git("tag", "-f", "v1")
        self.assertNotEqual(self.repo.git("rev-parse", "v1"), base)
        refused("a tag that was re-pointed", good, "edition-1")

    def test_a_catalog_with_no_tag_fetched_at_all_fails_and_is_never_skipped(self):
        self.two_editions()
        for tag in ("v1", "v2"):
            self.repo.git("tag", "-d", tag)
        self.assertEqual(self.repo.git("tag", "--list"), "")
        code, text = self.repo.run()
        self.assertEqual(code, 2, text)
        self.assertIn("edition-1", text)
        self.assertIn("v1", text)
        self.assertNotIn("0 tag sets run", text)

    def test_a_tag_whose_objects_were_not_fetched_fails_the_run(self):
        self.two_editions()
        tree = self.repo.git("rev-parse", "v1^{tree}")
        os.remove(os.path.join(self.repo.root, ".git", "objects", tree[:2], tree[2:]))
        code, text = self.repo.run()
        self.assertEqual(code, 2, text)
        self.assertRegex(text, r"ERROR .*edition-1")

    def test_an_older_tag_vector_answered_differently_fails(self):   # CF-15 S3
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING, "cf/drifted": WRONG})
        self.repo.edition("edition-2", "v2", {"cf/two": PASSING})
        self.repo.vectors({"cf/two": PASSING})
        self.repo.publish()
        code, text = self.repo.run()
        self.assertEqual(code, 1, text)
        self.assertIn("[edition-1] ANCHOR-FAIL cf/drifted", text)
        self.assertIn("edition edition-1 (v1): bundle hash matches, 2 vectors, 1 not passing", text)
        self.assertIn("FAILED edition-1", text)
        self.assertIn("[edition-2] PASS cf/two", text)
        self.assertNotIn("FAILED edition-2", text)

    def test_a_catalog_whose_only_entry_is_the_current_one_runs_zero_tag_sets_and_exits_zero(self):
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING})
        self.repo.git("tag", "-d", "v1")        # nothing to fetch: not even the tag of the one entry
        self.repo.publish(current=self.repo.rows[0]["production"])
        code, text = self.repo.run()
        self.assertEqual(code, 0, text)
        self.assertIn("0 tag sets run", text)
        self.assertIn("PASS cf/one", text)

    def test_a_tree_before_founding_has_no_catalog_and_runs_zero_tag_sets(self):
        self.repo.vectors({"cf/one": PASSING})
        out_code, text = self.repo.run()
        self.assertEqual((out_code, "0 tag sets run" in text), (0, True), text)

    def test_a_build_describing_vector_is_left_out_by_its_group_and_never_by_its_id(self):
        self.repo.edition("edition-1", "v1", {"cf/one": PASSING, "bld/version": WRONG, "other/bld": WRONG})
        self.repo.vectors({"cf/one": PASSING})
        self.repo.publish()
        self.assertTrue(all("/" not in group for group in run.BUILD_DESCRIBING_GROUPS))
        original = run.BUILD_DESCRIBING_GROUPS
        run.BUILD_DESCRIBING_GROUPS = frozenset(("bld",))
        self.addCleanup(setattr, run, "BUILD_DESCRIBING_GROUPS", original)
        code, text = self.repo.run()
        self.assertEqual(code, 1, text)
        self.assertNotIn("bld/version", text)
        self.assertIn("[edition-1] ANCHOR-FAIL other/bld", text)

    def test_the_tag_run_works_under_isolated_mode(self):
        self.two_editions()
        script = os.path.join(REPO, "conformance", "run.py")
        proc = subprocess.run(
            [sys.executable, "-I", script, "--root", self.repo.root, "--vectors",
             os.path.join(self.repo.root, "conformance", "vectors"), "--impl", " ".join(impl("ok")), "--tags"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.repo.root)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode() + proc.stderr.decode())
        self.assertIn("[edition-2] PASS cf/two", proc.stdout.decode())

    def test_without_the_flag_no_catalog_is_read(self):
        self.two_editions()
        out = _Sink()
        code = run.main(["--root", self.repo.root, "--vectors", os.path.join(self.repo.root, "conformance", "vectors"),
                         "--impl", " ".join(impl("ok"))], out=out)
        self.assertEqual(code, 0)
        self.assertNotIn("tag sets", out.text)




ANCHOR_8 = '{"bytes":8,"command":"fold"}'


class FailureEvidenceTests(unittest.TestCase):
    """A run that does not pass must say which vectors, and why, on lines that survive any cut of the output."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def run_harness(self, impls, *extra):
        out = _Sink()
        args = ["--vectors", self.dir]
        for i in impls:
            args += ["--impl", " ".join(i)]
        return run.main(args + list(extra), out=out), out.text

    def two_vectors(self):
        write_vector(self.dir, "cf/good", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        write_vector(self.dir, "cf/bad", command="fold", input={"a": 1}, anchor='{"bytes":999,"command":"fold"}')

    def test_ids_line_comes_right_before_the_summary_and_names_every_failure(self):
        self.two_vectors()
        write_vector(self.dir, "cf/bad2", command="fold", input={"a": 1}, anchor="nope")
        code, text = self.run_harness([impl("ok")])
        lines = text.splitlines()
        self.assertEqual(code, 1)
        self.assertEqual(lines[-1], "3 vectors, 2 not passing")
        self.assertEqual(lines[-2], "not passing: cf/bad, cf/bad2")

    def test_tail_of_two_lines_is_enough_to_find_the_failure(self):
        self.two_vectors()
        _, text = self.run_harness([impl("ok")])
        self.assertIn("cf/bad", "\n".join(text.splitlines()[-2:]))

    def test_expected_and_actual_are_printed_under_the_failing_vector(self):
        self.two_vectors()
        _, text = self.run_harness([impl("ok")])
        self.assertIn('ANCHOR-FAIL cf/bad\n', text)
        self.assertIn('expected: exit 0, {"bytes":999,"command":"fold"}', text)
        self.assertIn('impl 1: exit 0, {"bytes":8,"command":"fold"}', text)

    def test_diverging_impls_each_show_their_own_answer(self):
        write_vector(self.dir, "cf/d", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        _, text = self.run_harness([impl("ok"), impl("diverge")])
        self.assertIn('impl 1: exit 0, {"bytes":8,"command":"fold"}', text)
        self.assertIn('impl 2: exit 0, {"bytes":9,"command":"fold"}', text)

    def test_stderr_of_a_failing_vector_is_shown_and_bounded(self):
        write_vector(self.dir, "cf/n", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        code, text = self.run_harness([impl("noisy")])
        self.assertEqual(code, 1)
        self.assertIn("stub-stderr-start", text)
        self.assertNotIn("stub-stderr-end", text)
        self.assertIn("truncated", text)
        self.assertLess(len(text), 4000)

    def test_stderr_of_a_passing_vector_is_not_printed(self):
        write_vector(self.dir, "cf/c", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        code, text = self.run_harness([impl("chatty")])
        self.assertEqual(code, 0)
        self.assertEqual(text, "PASS cf/c\n1 vectors, 0 not passing\n")

    def test_a_clean_run_is_byte_identical(self):
        write_vector(self.dir, "cf/a", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        write_vector(self.dir, "cf/b", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        code, text = self.run_harness([impl("ok"), impl("ok")])
        self.assertEqual((code, text), (0, "PASS cf/a\nPASS cf/b\n2 vectors, 0 not passing\n"))

    def test_output_that_is_not_one_line_is_shown_not_hidden(self):
        write_vector(self.dir, "cf/c", command="fold", input={"a": 1}, anchor=ANCHOR_8)
        _, text = self.run_harness([impl("crash")])
        self.assertIn("impl 1: exit 3, no single line", text)


class EditionFailureEvidenceTests(unittest.TestCase):
    def test_an_edition_block_names_its_failures_before_its_summary(self):
        repo = TagRepo(self)
        repo.edition("edition-1", "v1", {"cf/one": PASSING, "cf/drifted": WRONG})
        repo.edition("edition-2", "v2", {"cf/two": PASSING})
        repo.vectors({"cf/two": PASSING})
        repo.publish()
        code, text = repo.run()
        lines = text.splitlines()
        self.assertEqual(code, 1, text)
        i = lines.index("edition edition-1 (v1): bundle hash matches, 2 vectors, 1 not passing")
        self.assertEqual(lines[i - 1], "[edition-1] not passing: cf/drifted")
        self.assertEqual(lines[i + 1], "FAILED edition-1")
        self.assertNotIn("[edition-2] not passing", text)

    def test_a_clean_tags_run_is_byte_identical(self):
        repo = TagRepo(self)
        repo.edition("edition-1", "v1", {"cf/one": PASSING})
        repo.vectors({"cf/one": PASSING})
        repo.publish()
        code, text = repo.run()
        self.assertEqual((code, text), (0, "PASS cf/one\n1 vectors, 0 not passing\n[edition-1] PASS cf/one\n"
                                           "edition edition-1 (v1): bundle hash matches, 1 vectors, 0 not passing\n"
                                           "1 tag sets run\n"))


if __name__ == "__main__":
    unittest.main()
