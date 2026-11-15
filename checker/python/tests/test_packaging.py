"""T4.6: the production artifact (T4.5 decision, SG-14, SG-15, GP-17, CF-08).

Two builds of one source tree are the same bytes; the zipapp runs under the
isolated interpreter and gives the answer the unpacked checker gives; the
launcher names the interpreter and the zipapp by absolute path and takes
nothing from the environment.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKAGING = ROOT / "checker" / "python" / "packaging"
SRC = ROOT / "checker" / "python" / "src"


def load(name):
    spec = importlib.util.spec_from_file_location("pk_" + name, PACKAGING / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_zipapp = load("build_zipapp")
launcher = load("launcher")
sys.path.insert(0, str(SRC))
from handsal_check import verifier  # noqa: E402


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)


class Deterministic(TmpCase):
    def copy_src(self, name, mtime):
        dst = self.tmp / name
        shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for path in dst.rglob("*"):
            os.utime(path, (mtime, mtime))
        return dst

    def test_two_builds_of_two_copies_are_the_same_bytes(self):
        a = build_zipapp.build(self.copy_src("a", 1_000_000_000), self.tmp / "a.pyz")
        b = build_zipapp.build(self.copy_src("b", 1_700_000_000), self.tmp / "b.pyz")
        self.assertEqual((self.tmp / "a.pyz").read_bytes(), (self.tmp / "b.pyz").read_bytes())
        self.assertEqual(a, b)
        self.assertEqual(a, sha(self.tmp / "a.pyz"))

    def test_a_build_ignores_bytecode_caches_in_the_tree(self):
        src = self.copy_src("a", 1)
        clean = build_zipapp.build(src, self.tmp / "clean.pyz")
        (src / "handsal_check" / "__pycache__").mkdir()
        (src / "handsal_check" / "__pycache__" / "core.cpython-313.pyc").write_bytes(b"x")
        (src / "handsal_check" / "stray.pyc").write_bytes(b"x")
        self.assertEqual(build_zipapp.build(src, self.tmp / "again.pyz"), clean)

    def test_members_are_sorted_stored_dated_and_fixed(self):
        build_zipapp.build(SRC, self.tmp / "x.pyz")
        with zipfile.ZipFile(self.tmp / "x.pyz") as z:
            infos = z.infolist()
        names = [i.filename for i in infos]
        self.assertEqual(names, sorted(names))
        for info in infos:
            self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0), info.filename)
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED, info.filename)
            self.assertEqual(info.external_attr, 0o644 << 16, info.filename)
            self.assertEqual(info.create_system, 3, info.filename)
            self.assertEqual(info.extra, b"", info.filename)
            self.assertFalse(info.filename.endswith(".pyc") or "__pycache__" in info.filename)

    def test_contents_are_the_production_entry_and_the_core_data_and_not_the_conformance_build(self):
        build_zipapp.build(SRC, self.tmp / "x.pyz")
        with zipfile.ZipFile(self.tmp / "x.pyz") as z:
            names = set(z.namelist())
            main = z.read("__main__.py").decode()
        for needed in ("__main__.py", "handsal_check/production.py", "handsal_check/core.py",
                       "handsal_check/data/core-manifest.json", "handsal_check/data/spec/registry.json",
                       "handsal_check/data/conformance/fixtures/fixture-kids.json"):
            self.assertIn(needed, names)
        self.assertNotIn("handsal_check/conformance.py", names)
        self.assertIn("import production", main)
        self.assertNotIn("conformance", main)

    def test_one_source_byte_moves_the_hash(self):
        src = self.copy_src("a", 1)
        before = build_zipapp.build(src, self.tmp / "a.pyz")
        with open(src / "handsal_check" / "core.py", "ab") as fh:
            fh.write(b"\n# x\n")
        self.assertNotEqual(build_zipapp.build(src, self.tmp / "b.pyz"), before)

    def test_a_missing_source_or_package_fails_loudly(self):
        with self.assertRaises(build_zipapp.BuildError):
            build_zipapp.build(self.tmp / "nope", self.tmp / "x.pyz")
        (self.tmp / "empty").mkdir()
        with self.assertRaises(build_zipapp.BuildError):
            build_zipapp.build(self.tmp / "empty", self.tmp / "x.pyz")

    def test_the_default_source_is_this_checker(self):
        self.assertEqual(Path(build_zipapp.SRC).resolve(), SRC.resolve())


class Runs(TmpCase):
    def run_pyz(self, pyz, command, stdin, extra_env=None):
        env = {"PATH": os.environ.get("PATH", "")}
        env.update(extra_env or {})
        return subprocess.run([sys.executable, "-I", str(pyz), command], input=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=self.tmp)

    def test_the_zipapp_reads_its_packaged_core_data_and_answers_like_the_unpacked_checker(self):
        pyz = self.tmp / "x.pyz"
        build_zipapp.build(SRC, pyz)
        # `render` loads the registry and the profiles before it looks at the input.
        packed = self.run_pyz(pyz, "render", b"{}\n")
        self.assertEqual(packed.stderr, b"")
        self.assertEqual((packed.returncode, packed.stdout), (0, b'{"error":"malformed_input"}\n'))
        unpacked = subprocess.run(
            [sys.executable, "-I", "-c",
             "import sys; sys.path.insert(0, %r); from handsal_check import production; sys.exit(production.main())"
             % str(SRC), "render"],
            input=b"{}\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.tmp)
        self.assertEqual((unpacked.returncode, unpacked.stdout), (packed.returncode, packed.stdout))

    def test_a_zipapp_missing_its_registry_crashes_loudly_and_answers_nothing(self):
        pyz = self.tmp / "x.pyz"
        build_zipapp.build(SRC, pyz)
        broken = self.tmp / "broken.pyz"
        with zipfile.ZipFile(pyz) as src, zipfile.ZipFile(broken, "w") as dst:
            for info in src.infolist():
                if info.filename != "handsal_check/data/spec/registry.json":
                    dst.writestr(info, src.read(info.filename))
        out = self.run_pyz(broken, "render", b"{}\n")
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(out.stdout, b"")
        self.assertIn(b"CoreDataError", out.stderr)

    def test_the_zipapp_is_the_production_build(self):
        pyz = self.tmp / "x.pyz"
        build_zipapp.build(SRC, pyz)
        out = self.run_pyz(pyz, "kid", b'{"x":"a","y":"b"}\n')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(out.stdout.startswith(b'{"kid":"'))
        # production takes no `now`: a conformance-only input is malformed (CF-08)
        out = self.run_pyz(pyz, "check-act", b'{"acts":[],"now":"0","pin":null}\n')
        self.assertEqual(out.stdout, b'{"error":"malformed_input"}\n')

    def test_the_zipapp_ignores_the_environment_and_the_working_directory(self):
        pyz = self.tmp / "x.pyz"
        build_zipapp.build(SRC, pyz)
        evil = self.tmp / "evil"
        evil.mkdir()
        (evil / "json.py").write_text("raise SystemExit('planted json')\n")
        (self.tmp / "json.py").write_text("raise SystemExit('planted json in cwd')\n")
        out = self.run_pyz(pyz, "render", b"{}\n", {"PYTHONPATH": str(evil), "PYTHONHOME": str(evil)})
        self.assertEqual((out.returncode, out.stdout), (0, b'{"error":"malformed_input"}\n'), out.stderr)


class Launcher(TmpCase):
    def install(self, interpreter_body=None):
        """A fake installation root: launcher, zipapp path and an interpreter under `root`."""
        root = self.tmp / "Application Support" / "handsal"
        (root / "bin").mkdir(parents=True)
        (root / "lib").mkdir()
        (root / "python" / "bin").mkdir(parents=True)
        interp = root / "python" / "bin" / "python3"
        if interpreter_body is None:
            interp.symlink_to(Path(sys.executable).resolve())
        else:
            interp.write_text(interpreter_body)
            interp.chmod(0o755)
        script = root / "bin" / "handsal-check"
        script.write_text(launcher.render(str(root)))
        script.chmod(0o755)
        return root, script

    def test_it_runs_the_pinned_interpreter_isolated_on_the_zipapp_with_the_arguments(self):
        root, script = self.install("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n")
        out = subprocess.run([str(script), "kid", "two words"], stdout=subprocess.PIPE, check=True)
        self.assertEqual(out.stdout.decode().splitlines(),
                         ["-I", "-E", "-s", str(root / "lib" / "handsal-check.pyz"), "kid", "two words"])

    def test_stdin_and_exit_status_pass_through(self):
        root, script = self.install("#!/bin/sh\ncat\nexit 7\n")
        out = subprocess.run([str(script), "x"], input=b"hello", stdout=subprocess.PIPE)
        self.assertEqual((out.returncode, out.stdout), (7, b"hello"))

    def test_the_text_has_no_path_lookup_and_no_environment_reference(self):
        text = launcher.render("/Library/Application Support/handsal")
        self.assertNotIn("PATH", text)
        self.assertNotIn("$0", text)
        self.assertNotIn("${", text)
        self.assertNotIn("env ", text)
        self.assertIn("exec '/Library/Application Support/handsal/python/bin/python3' -I -E -s ", text)
        self.assertEqual(text.count("\n"), len(text.splitlines()))

    def test_the_environment_cannot_redirect_it(self):
        root, script = self.install()
        build_zipapp.build(SRC, root / "lib" / "handsal-check.pyz")
        evil = self.tmp / "evil"
        evil.mkdir()
        (evil / "json.py").write_text("raise SystemExit('planted json')\n")
        marker = self.tmp / "marker"
        hook = self.tmp / "hook.sh"
        hook.write_text("touch %s\n" % marker)
        fake_bin = self.tmp / "fakebin"
        fake_bin.mkdir()
        (fake_bin / "python3").write_text("#!/bin/sh\necho planted interpreter\n")
        (fake_bin / "python3").chmod(0o755)
        env = {"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""), "PYTHONPATH": str(evil),
               "PYTHONHOME": str(evil), "BASH_ENV": str(hook), "ENV": str(hook)}
        out = subprocess.run([str(script), "render"], input=b"{}\n", stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, cwd=evil)
        self.assertEqual((out.returncode, out.stdout), (0, b'{"error":"malformed_input"}\n'), out.stderr)
        self.assertFalse(marker.exists())

    def test_a_root_that_cannot_be_quoted_or_is_not_absolute_is_refused(self):
        for bad in ("relative/path", "", "/a'b", "/a\nb", "/a\x00b"):
            with self.assertRaises(launcher.LauncherError, msg=repr(bad)):
                launcher.render(bad)

    def test_the_macos_launcher_is_rendered_for_the_sg14_root(self):
        self.assertEqual(launcher.MACOS_ROOT, "/Library/Application Support/handsal")
        self.assertEqual(launcher.render(launcher.MACOS_ROOT), launcher.render_macos())
        self.assertEqual(launcher.LAUNCHER_PATH, "/Library/Application Support/handsal/bin/handsal-check")

    def test_the_rendered_script_is_ascii_text_with_a_shebang(self):
        text = launcher.render(launcher.MACOS_ROOT)
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertTrue(text.isascii())


SERVER_ENTRY = "handsal_check.server:main"


class ServerZipapp(TmpCase):
    """T13.5 (CF-10, RS2, RS4): the server build is the same builder with another entry, and each
    zipapp leaves out the entry modules of the other builds."""

    def server_src(self, name, mtime=1):
        """A copy of the source tree with a stand-in `server.py`, so these tests do not wait for the module."""
        dst = self.tmp / name
        shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        module = dst / "handsal_check" / "server.py"
        if not module.exists():
            module.write_text("def main():\n    return 0\n")
        for path in dst.rglob("*"):
            os.utime(path, (mtime, mtime))
        return dst

    def names(self, pyz):
        with zipfile.ZipFile(pyz) as z:
            return set(z.namelist()), z.read("__main__.py").decode()

    def test_two_builds_of_two_copies_are_one_hash(self):
        a = build_zipapp.build(self.server_src("a", 1_000_000_000), self.tmp / "a.pyz", SERVER_ENTRY)
        b = build_zipapp.build(self.server_src("b", 1_700_000_000), self.tmp / "b.pyz", SERVER_ENTRY)
        self.assertEqual(a, b)
        self.assertEqual((self.tmp / "a.pyz").read_bytes(), (self.tmp / "b.pyz").read_bytes())

    def test_the_entry_is_the_server_and_the_other_builds_entry_modules_are_absent(self):
        build_zipapp.build(self.server_src("a"), self.tmp / "s.pyz", SERVER_ENTRY)
        names, main = self.names(self.tmp / "s.pyz")
        self.assertIn("handsal_check/server.py", names)
        self.assertIn("handsal_check/core.py", names)
        self.assertNotIn("handsal_check/production.py", names)
        self.assertNotIn("handsal_check/conformance.py", names)
        self.assertEqual(main, "import sys\nfrom handsal_check import server\nsys.exit(server.main())\n")

    def test_the_production_zipapp_leaves_out_the_server_and_the_conformance_modules(self):
        build_zipapp.build(self.server_src("a"), self.tmp / "p.pyz")
        names, main = self.names(self.tmp / "p.pyz")
        self.assertIn("handsal_check/production.py", names)
        self.assertNotIn("handsal_check/server.py", names)
        self.assertNotIn("handsal_check/conformance.py", names)
        self.assertIn("from handsal_check import production", main)

    def test_an_entry_that_is_not_one_of_the_two_zipapp_builds_is_refused(self):
        src = self.server_src("a")
        for bad in ("handsal_check.conformance:main", "handsal_check.core:main", "os:system", "", "handsal_check.server"):
            with self.assertRaises(build_zipapp.BuildError, msg=bad):
                build_zipapp.build(src, self.tmp / "x.pyz", bad)
            self.assertFalse((self.tmp / "x.pyz").exists(), bad)

    def test_a_server_entry_without_its_module_fails_loudly(self):
        src = self.server_src("a")
        (src / "handsal_check" / "server.py").unlink()
        with self.assertRaises(build_zipapp.BuildError):
            build_zipapp.build(src, self.tmp / "x.pyz", SERVER_ENTRY)

    def test_the_command_line_takes_the_entry(self):
        self.assertEqual(build_zipapp.main(["--entry", "handsal_check.conformance:main", str(self.tmp / "x.pyz")]), 2)
        self.assertEqual(build_zipapp.main(["--entry"]), 2)

    def test_a_flag_is_never_an_output_path(self):
        """A token that starts with a dash is an option, never a file name: the stray `--entry` archive came from
        a flag read as OUT."""
        here = Path.cwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, here)
        for argv in (["--entry"], ["--help"], ["-x"], ["--entry", SERVER_ENTRY, "--entry"], ["--entry", SERVER_ENTRY, "-o"]):
            self.assertEqual(build_zipapp.main(argv), 2, argv)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), [])


class LinuxLauncher(TmpCase):
    def test_it_is_rendered_for_opt_handsal_and_the_server_zipapp(self):
        self.assertEqual(launcher.LINUX_ROOT, "/opt/handsal")
        self.assertEqual(launcher.render_linux_server(),
                         "#!/bin/sh\nexec '/opt/handsal/python/bin/python3' -I -E -s "
                         "'/opt/handsal/lib/handsal-check-server.pyz' \"$@\"\n")

    def test_it_has_no_path_lookup_and_no_environment_reference(self):
        text = launcher.render_linux_server()
        for bad in ("PATH", "$0", "${", "env ", "handsal-check.pyz"):
            self.assertNotIn(bad, text)
        self.assertTrue(text.isascii())

    def test_the_macos_launcher_text_does_not_move(self):
        self.assertEqual(launcher.render_macos(),
                         "#!/bin/sh\nexec '/Library/Application Support/handsal/python/bin/python3' -I -E -s "
                         "'/Library/Application Support/handsal/lib/handsal-check.pyz' \"$@\"\n")

    def test_the_launcher_and_the_zipapp_names_are_the_ones_the_installer_lists(self):
        self.assertEqual((launcher.LINUX_LAUNCHER_NAME, launcher.LINUX_ZIPAPP_NAME),
                         ("handsal-check-server", "handsal-check-server.pyz"))

    def test_it_runs_the_interpreter_isolated_on_the_server_zipapp(self):
        root = self.tmp / "opt" / "handsal"
        (root / "bin").mkdir(parents=True)
        (root / "python" / "bin").mkdir(parents=True)
        interp = root / "python" / "bin" / "python3"
        interp.write_text("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n")
        interp.chmod(0o755)
        script = root / "bin" / "handsal-check-server"
        script.write_text(launcher.render(str(root), launcher.LINUX_ZIPAPP_NAME))
        script.chmod(0o755)
        out = subprocess.run([str(script), "admit"], stdout=subprocess.PIPE, check=True)
        self.assertEqual(out.stdout.decode().splitlines(),
                         ["-I", "-E", "-s", str(root / "lib" / "handsal-check-server.pyz"), "admit"])


class LinuxVitniPath(unittest.TestCase):
    """One path, four owners. The hidden link: /opt/handsal/bin/vitni-verify is the verifier's fixed Linux path
    (CF-05), the launcher's root, the installer's destination and the spec text. Red until T13.2 adds
    `verifier.INSTALLED["linux"]`."""

    PATH = "/opt/handsal/bin/vitni-verify"

    def test_the_verifier_the_launcher_the_installer_and_the_spec_name_one_path(self):
        self.assertEqual(launcher.LINUX_ROOT + "/bin/vitni-verify", self.PATH)
        lib = (ROOT / "tools" / "install" / "install-lib.sh").read_text(encoding="utf-8")
        script = (ROOT / "tools" / "install" / "install-linux-server.sh").read_text(encoding="utf-8")
        self.assertIn("DEST_ROOT='%s'" % launcher.LINUX_ROOT, script)
        self.assertRegex(lib, r"ARTIFACT_BINS=\"vitni-verify [^\"]*\"")  # installed under DEST_ROOT/bin
        spec = (ROOT / "spec" / "profile-interfaces.md").read_text(encoding="utf-8")
        self.assertIn("`%s`" % self.PATH, spec)
        # last, so the other three are checked now and only this one waits for T13.2
        self.assertEqual(verifier.INSTALLED.get("linux"), [self.PATH])


class InterpreterPin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads((PACKAGING / "interpreter.json").read_text(encoding="utf-8"))

    def test_the_pin_names_one_release_and_one_cpython_for_three_platforms(self):
        self.assertRegex(self.pin["release"], r"^\d{8}$")
        self.assertRegex(self.pin["cpython"], r"^3\.13\.\d+$")
        self.assertEqual(sorted(self.pin["platforms"]), ["linux-x86_64", "macos-arm64", "macos-x86_64", "windows-x64"])
        self.assertEqual(self.pin["source"], "https://github.com/astral-sh/python-build-standalone")

    def test_each_platform_pins_an_archive_and_a_notices_archive_by_sha256(self):
        for name, entry in self.pin["platforms"].items():
            for key in ("archive", "notices"):
                item = entry[key]
                self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$", name)
                self.assertIn(self.pin["release"], item["file"], name)
                self.assertIn(self.pin["cpython"], item["file"], name)
                self.assertEqual(item["url"],
                                 "https://github.com/astral-sh/python-build-standalone/releases/download/%s/%s"
                                 % (self.pin["release"], item["file"].replace("+", "%2B")), name)

    def test_the_pin_records_the_sums_file_and_the_license_notices(self):
        self.assertRegex(self.pin["sums"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.pin["sums"]["file"], "SHA256SUMS")
        self.assertIn("Python-2.0", self.pin["licenses"]["interpreter"])
        self.assertTrue(self.pin["licenses"]["ship"])


    def test_the_linux_row_is_the_publishers_x86_64_gnu_install_only_build(self):
        row = self.pin["platforms"]["linux-x86_64"]
        triple = "x86_64-unknown-linux-gnu"
        base = "cpython-%s+%s-%s" % (self.pin["cpython"], self.pin["release"], triple)
        self.assertEqual(row["archive"]["file"], base + "-install_only.tar.gz")
        self.assertEqual(row["notices"]["file"], base + "-pgo+lto-full.tar.zst")
        self.assertEqual(row["packed_licenses"]["file"],
                         "handsal-python-licenses-%s+%s-%s.tar.gz" % (self.pin["cpython"], self.pin["release"], triple))
        self.assertEqual(row["archive"]["sha256"], "50c774f6674740739f791c05a9177ed03e2fe02abebda9bca3512eb7309b37cc")
        self.assertEqual(row["notices"]["sha256"], "dec4f6d23031233beddfe91b99751977ef96e90642109836b1f9ad80b0019a68")

    def test_the_linux_row_is_not_marked_verified_until_the_owner_reads_its_notices(self):
        self.assertNotIn("verified", self.pin["platforms"]["linux-x86_64"])
        self.assertTrue(self.pin["licenses"]["verified"].startswith("macos-arm64 only"))


if __name__ == "__main__":
    unittest.main()
