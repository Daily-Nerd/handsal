"""T3.21 the verifier (VR-03, VR-04, CF-05, SG-14): vitni behind one interface, fail closed.

The checker never does ES256. `VitniCli` runs a vitni binary and returns its reason. A path is
fixed per platform, never taken from the environment, and checked for administrator ownership
before each spawn; tests and the conformance build inject an argv through the constructor only.
Every failure to get an answer is `VerifierUnavailable`, never a skip.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from handsal_check import verifier

STUB = str(Path(__file__).resolve().parent / "data" / "stub_vitni.py")
ARGV = [sys.executable, STUB]
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
KEYS = {"alice": {"k" * 43: {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active", "x": "a", "y": "b"}}}


def cli(**kw):
    return verifier.VitniCli(ARGV, owner_check=kw.pop("owner_check", None), **kw)


class Protocol(unittest.TestCase):
    def test_returns_the_vitni_reason(self):
        self.assertEqual(cli().verify("ok", KEYS, "local:handsal.request.approve"), "ok")
        self.assertEqual(cli().verify("bad", KEYS, "local:handsal.request.approve"), "bad_signature")

    def test_binding_and_method_are_always_set(self):
        reason = cli().verify("echo", KEYS, "local:handsal.act.endorse")
        sent = json.loads(reason[len("echo:"):])
        self.assertEqual(sent["policy"], {"expected_binding": "local", "expected_method": "local:handsal.act.endorse"})
        self.assertEqual(sent["keys"], KEYS)

    def test_a_missing_method_is_refused_not_sent_as_null(self):
        for method in (None, "", 3):
            with self.assertRaises(ValueError):
                cli().verify("ok", KEYS, method)

    def test_the_parent_environment_does_not_reach_the_child(self):
        os.environ["HANDSAL_TEST_SENTINEL"] = "1"
        try:
            self.assertEqual(cli().verify("env", KEYS, "m"), "env:")
        finally:
            del os.environ["HANDSAL_TEST_SENTINEL"]

    def test_every_failure_to_answer_is_unavailable(self):
        for mode in ("garbage", "error", "extra", "mismatch", "exit3"):
            with self.assertRaises(verifier.VerifierUnavailable, msg=mode):
                cli().verify(mode, KEYS, "m")

    def test_a_timeout_is_unavailable(self):
        with self.assertRaises(verifier.VerifierUnavailable):
            cli(timeout=0.3).verify("sleep", KEYS, "m")

    def test_a_missing_binary_is_unavailable(self):
        with self.assertRaises(verifier.VerifierUnavailable):
            verifier.VitniCli(["/nonexistent/vitni-verify"], owner_check=None).verify("ok", KEYS, "m")

    def test_the_path_must_be_absolute(self):
        for argv in ([], ["vitni-verify"], "x", None):
            with self.assertRaises(ValueError):
                verifier.VitniCli(argv, owner_check=None)


class Installed(unittest.TestCase):
    FIXED = "/Library/Application Support/handsal/bin/vitni-verify"

    def test_the_environment_is_never_read(self):
        """SG-14: the path is fixed and no variable changes it. The test looks at the path the verifier
        resolves and at what it would spawn (the spawn is replaced), so its verdict does not depend on
        whether this machine has an installation."""
        spawned = []

        def fake_run(argv, **kw):
            spawned.append((argv, kw.get("env")))
            return subprocess.CompletedProcess(argv, 0, stdout=b'{"reason":"ok","valid":true}\n', stderr=b"")

        os.environ["HANDSAL_VITNI_CLI"] = STUB
        os.environ["VITNI_VERIFY"] = STUB
        try:
            cli_ = verifier.VitniCli.installed(platform="darwin")
            self.assertEqual(cli_.argv, [self.FIXED])
            cli_.owner_check = None          # the ownership check is proven on its own; here only the path matters
            with mock.patch.object(verifier.subprocess, "run", fake_run):
                cli_.verify("ok", KEYS, "m")
        finally:
            del os.environ["HANDSAL_VITNI_CLI"], os.environ["VITNI_VERIFY"]
        self.assertEqual(spawned, [([self.FIXED, "verify"], {})])

    def test_the_installed_verifier_is_ownership_checked_before_any_spawn(self):
        """The default check runs on the fixed path first; a refusal means nothing is spawned."""
        seen = []

        def refuse(path):
            seen.append(path)
            raise verifier.VerifierUnavailable("not administrator owned")

        cli_ = verifier.VitniCli.installed(platform="darwin")
        cli_.owner_check = refuse
        with mock.patch.object(verifier.subprocess, "run", side_effect=AssertionError("spawned")):
            with self.assertRaises(verifier.VerifierUnavailable):
                cli_.verify("ok", KEYS, "m")
        self.assertEqual(seen, [self.FIXED])

    def test_a_platform_without_a_fixed_path_is_always_unavailable(self):
        with self.assertRaises(verifier.VerifierUnavailable):
            verifier.VitniCli.installed(platform="plan9").verify("ok", KEYS, "m")

    def test_the_default_owner_check_runs_before_a_spawn(self):
        with self.assertRaises(verifier.VerifierUnavailable):
            verifier.VitniCli(ARGV).verify("ok", KEYS, "m")   # the stub is owned by the test user, not root


class Ownership(unittest.TestCase):
    """GP-10 chain: the file is regular, owned, not group or other writable, one link; every
    ancestor below `top` is owned, not a symlink and not group or other writable."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = Path(os.path.realpath(tmp.name))
        self.me = os.getuid()
        self.dir = self.top / "bin"
        self.dir.mkdir()
        os.chmod(self.dir, 0o755)
        os.chmod(self.top, 0o755)
        self.file = self.dir / "vitni-verify"
        self.file.write_text("#!/bin/sh\n")
        os.chmod(self.file, 0o755)

    def check(self, path=None):
        verifier.check_admin_owned(str(path or self.file), uid=self.me, top=str(self.top))

    def refused(self, path=None, **kw):
        with self.assertRaises(verifier.VerifierUnavailable):
            verifier.check_admin_owned(str(path or self.file), **{"uid": self.me, "top": str(self.top), **kw})

    def test_a_well_formed_chain_passes(self):
        self.check()

    def test_another_owner_is_refused(self):
        self.refused(uid=self.me + 1)

    def test_a_group_or_other_writable_file_is_refused(self):
        for mode in (0o775, 0o757):
            os.chmod(self.file, mode)
            self.refused()

    def test_a_group_writable_ancestor_is_refused(self):
        os.chmod(self.dir, 0o775)
        self.refused()

    def test_a_symlink_file_is_refused(self):
        link = self.dir / "link"
        os.symlink(self.file, link)
        self.refused(link)

    def test_a_symlink_ancestor_is_refused(self):
        real = self.top / "real"
        real.mkdir()
        (real / "vitni-verify").write_text("x")
        os.chmod(real / "vitni-verify", 0o755)
        os.symlink(real, self.top / "via")
        self.refused(self.top / "via" / "vitni-verify")

    def test_a_second_hard_link_is_refused(self):
        os.link(self.file, self.dir / "twin")
        self.refused()

    def test_a_directory_is_refused(self):
        self.refused(self.dir)

    def test_a_missing_file_is_refused(self):
        self.refused(self.dir / "absent")

    def test_a_non_executable_file_is_refused(self):
        os.chmod(self.file, 0o644)
        self.refused()

    def test_the_check_runs_before_every_spawn(self):
        calls = []

        def owner(path):
            calls.append(path)
        cli(owner_check=owner).verify("ok", KEYS, "m")
        cli(owner_check=owner).verify("ok", KEYS, "m")
        self.assertEqual(calls, [sys.executable] * 2)

    def test_a_refusing_check_prevents_the_spawn(self):
        def owner(path):
            raise verifier.VerifierUnavailable("no")
        with self.assertRaises(verifier.VerifierUnavailable):
            cli(owner_check=owner).verify("ok", KEYS, "m")


def sig(s):
    return (b"\x07" * 32) + s.to_bytes(32, "big")


class LowS(unittest.TestCase):
    HALF = N // 2

    def test_boundary(self):
        self.assertTrue(verifier.is_low_s(sig(1)))
        self.assertTrue(verifier.is_low_s(sig(self.HALF)))
        self.assertFalse(verifier.is_low_s(sig(self.HALF + 1)))
        self.assertFalse(verifier.is_low_s(sig(N - 1)))

    def test_the_normalized_form_of_a_high_s_signature_is_low(self):
        high = self.HALF + 12345
        self.assertFalse(verifier.is_low_s(sig(high)))
        self.assertTrue(verifier.is_low_s(sig(N - high)))

    def test_only_a_64_byte_signature_has_an_s(self):
        for raw in (b"", b"\x01" * 63, b"\x01" * 65):
            with self.assertRaises(ValueError):
                verifier.is_low_s(raw)


class KeyEntry(unittest.TestCase):
    def test_is_the_vitni_keys_shape(self):
        self.assertEqual(verifier.key_entry({"x": "X", "y": "Y"}, "revoked"),
                         {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "revoked", "x": "X", "y": "Y"})


class Counting:
    def __init__(self, reason="ok"):
        self.calls, self.reason = 0, reason

    def verify(self, jws, keys, method):
        self.calls += 1
        if self.reason is None:
            raise verifier.VerifierUnavailable("down")
        return self.reason


class Memoized(unittest.TestCase):
    """One fold call asks vitni once per distinct question and keeps nothing afterwards."""

    def test_the_same_question_is_asked_once(self):
        inner = Counting()
        memo = verifier.Memoized(inner)
        for _ in range(3):
            self.assertEqual(memo.verify("j", KEYS, "m"), "ok")
        self.assertEqual(inner.calls, 1)

    def test_another_act_key_map_or_method_is_another_question(self):
        inner = Counting()
        memo = verifier.Memoized(inner)
        other = {"alice": {"k" * 43: dict(KEYS["alice"]["k" * 43], status="revoked")}}
        memo.verify("j", KEYS, "m")
        memo.verify("j2", KEYS, "m")
        memo.verify("j", other, "m")
        memo.verify("j", KEYS, "m2")
        self.assertEqual(inner.calls, 4)

    def test_a_failure_to_answer_is_not_remembered(self):
        inner = Counting(None)
        memo = verifier.Memoized(inner)
        for _ in range(2):
            with self.assertRaises(verifier.VerifierUnavailable):
                memo.verify("j", KEYS, "m")
        self.assertEqual(inner.calls, 2)


class Classify(unittest.TestCase):
    def test_four_reasons_pass_through_and_the_rest_is_unexpected(self):
        for reason in ("unknown_key", "revoked_key", "bad_signature", "context_mismatch", "ok"):
            self.assertEqual(verifier.classify(reason), reason)
        for reason in ("malformed", "header_key_material", "alg_not_allowed", "non_canonical_payload",
                       "something_new", ""):
            self.assertEqual(verifier.classify(reason), "verifier_unexpected")


if __name__ == "__main__":
    unittest.main()
