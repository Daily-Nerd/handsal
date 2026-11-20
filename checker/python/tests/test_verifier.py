"""T3.21 the verifier (VR-03, VR-04, CF-05, SG-14): vitni behind one interface, fail closed.

The checker never does ES256. `VitniCli` runs a vitni binary and returns its reason. A path is
fixed per platform, never taken from the environment, and checked for administrator ownership
before each spawn; tests and the conformance build inject an argv through the constructor only.
Every failure to get an answer is `VerifierUnavailable`, never a skip.
"""
import ast
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from handsal_check import server, verifier

from .test_enrolled import PRODUCTION_ONLY, production_world
from .test_server import run

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


class Predicate(unittest.TestCase):
    """What a valid vitni answer looks like is said once (`verifier._verdict`); `verify` applies exactly it."""

    VALID = ({"reason": "ok", "valid": True}, {"reason": "bad_signature", "valid": False},
             {"reason": "malformed", "valid": False})
    INVALID = ({"error": "invalid_input"}, {"reason": "ok"}, {"valid": True}, {}, {"reason": "ok", "valid": True, "extra": 1},
               {"reason": "bad_signature", "valid": True}, {"reason": "ok", "valid": False},
               {"reason": "ok", "valid": 1}, {"reason": 1, "valid": False}, {"reason": None, "valid": False},
               [], "ok", None, 3, True)

    def test_a_verdict_is_its_reason(self):
        for obj in self.VALID:
            self.assertEqual(verifier._verdict(obj), obj["reason"])

    def test_anything_else_is_unavailable(self):
        for obj in self.INVALID:
            with self.assertRaises(verifier.VerifierUnavailable, msg=repr(obj)):
                verifier._verdict(obj)

    def test_verify_accepts_and_refuses_exactly_what_the_predicate_does(self):
        for obj in self.VALID + self.INVALID:
            receipt = "raw:" + json.dumps(obj)
            try:
                want = verifier._verdict(obj)
            except verifier.VerifierUnavailable:
                with self.assertRaises(verifier.VerifierUnavailable, msg=repr(obj)):
                    cli().verify(receipt, KEYS, "m")
            else:
                self.assertEqual(cli().verify(receipt, KEYS, "m"), want)


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

    def test_the_linux_path_is_the_server_build_path(self):   # CF-05, SG-14: root-owned, under /opt/handsal
        self.assertEqual(verifier.INSTALLED["linux"], ["/opt/handsal/bin/vitni-verify"])
        self.assertEqual(verifier.VitniCli.installed(platform="linux").argv, ["/opt/handsal/bin/vitni-verify"])
        self.assertIs(verifier.VitniCli.installed(platform="linux").owner_check, verifier.check_admin_owned)

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


class Batch(unittest.TestCase):
    """`VitniBatch.verify_many`: one vitni process for many questions, each element the verdict `verify` gives alone,
    and a failure of the process never a verdict."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = os.path.join(tmp.name, "spawns")

    def batch(self, owner_check=None, **kw):
        return verifier.VitniBatch([sys.executable, STUB, self.log], owner_check=owner_check, **kw)

    def spawns(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as handle:
            return [json.loads(line) for line in handle]

    @staticmethod
    def asks(*receipts, method="m"):
        return [verifier.question(r, KEYS, method) for r in receipts]

    def failed(self, got, n):
        self.assertEqual(len(got), n)
        for item in got:
            self.assertIs(type(item), verifier.Failed)

    def test_it_is_a_vitni_cli_and_a_verifier(self):
        self.assertTrue(issubclass(verifier.VitniBatch, verifier.VitniCli))
        self.assertIs(verifier.VitniBatch.verify, verifier.VitniCli.verify)

    def test_each_element_is_the_raw_reason_of_its_question(self):
        got = self.batch().verify_many(self.asks("ok", "bad", "malformed", "ok"))
        self.assertEqual(got, ["ok", "bad_signature", "malformed", "ok"])
        self.assertEqual(self.spawns(), [{"command": "verify-batch", "count": 4}])

    def test_the_questions_go_out_as_verify_inputs_with_their_own_keys_and_method(self):
        other = {"bob": KEYS["alice"]}
        qs = [verifier.question("echo", KEYS, "local:a"), verifier.question("echo", other, "local:b")]
        got = self.batch().verify_many(qs)
        seen = [json.loads(r[len("echo:"):]) for r in got]
        self.assertEqual(seen[0], {"keys": KEYS, "policy": {"expected_binding": "local", "expected_method": "local:a"}})
        self.assertEqual(seen[1], {"keys": other, "policy": {"expected_binding": "local", "expected_method": "local:b"}})

    def test_the_parent_environment_does_not_reach_the_child(self):
        os.environ["HANDSAL_TEST_SENTINEL"] = "1"
        try:
            self.assertEqual(self.batch().verify_many(self.asks("env")), ["env:"])
        finally:
            del os.environ["HANDSAL_TEST_SENTINEL"]

    def test_a_missing_method_is_refused_before_any_spawn(self):
        for method in (None, "", 3):
            with self.assertRaises(ValueError):
                self.batch().verify_many([verifier.question("ok", KEYS, "m"), verifier.question("ok", KEYS, method)])
        self.assertEqual(self.spawns(), [])

    def test_an_element_that_is_not_a_verdict_is_failed_and_the_others_stand(self):
        for bad in ("error", "extra", "mismatch", "raw:[]", 'raw:{"reason":"ok"}'):
            got = self.batch().verify_many(self.asks("ok", bad, "bad"))
            self.assertEqual((got[0], got[2]), ("ok", "bad_signature"), msg=bad)
            self.assertIs(type(got[1]), verifier.Failed, msg=bad)

    def test_a_batch_element_is_what_verify_gives_that_question_alone(self):
        one = self.batch()
        receipts = ("ok", "bad", "malformed", "echo", "env", "error", "extra", "mismatch",
                    'raw:{"reason":"unknown_key","valid":false}', "raw:null")
        qs = self.asks(*receipts)
        together = one.verify_many(qs)
        for asked, got in zip(qs, together):
            try:
                alone = one.verify(asked.jws, json.loads(asked.keys), asked.method)
            except verifier.VerifierUnavailable:
                self.assertIs(type(got), verifier.Failed, msg=asked.jws)
            else:
                self.assertEqual(got, alone, msg=asked.jws)

    def test_a_process_failure_fails_every_element_never_one_of_them(self):
        for fault in ("garbage", "exit3", "short", "long", "toplevel", "notdict", "notlist", "extramember"):
            got = self.batch().verify_many(self.asks("ok", fault, "bad"))
            self.failed(got, 3)
            self.assertIn("vitni", got[0].why, msg=fault)

    def test_a_timeout_fails_every_element(self):
        self.failed(self.batch(timeout=0.3).verify_many(self.asks("ok", "sleep")), 2)

    def test_a_missing_binary_fails_every_element(self):
        got = verifier.VitniBatch(["/nonexistent/vitni-verify"], owner_check=None).verify_many(self.asks("ok", "ok"))
        self.failed(got, 2)

    def test_a_vitni_without_verify_batch_fails_every_element_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old_vitni.py"
            old.write_text("import sys\nsys.stdin.read()\nprint('{\"error\":\"unsupported_command\"}')\n")
            got = verifier.VitniBatch([sys.executable, str(old)], owner_check=None).verify_many(self.asks("ok", "bad"))
        self.failed(got, 2)

    def test_no_question_is_no_spawn_and_no_owner_check(self):
        calls = []
        self.assertEqual(self.batch(owner_check=calls.append).verify_many([]), [])
        self.assertEqual((self.spawns(), calls), ([], []))

    def test_the_owner_check_runs_once_for_the_round(self):
        calls = []
        self.batch(owner_check=calls.append).verify_many(self.asks("ok", "bad", "ok"))
        self.assertEqual(calls, [sys.executable])

    def test_a_failed_owner_check_fails_every_element_without_raising_or_spawning(self):
        def owner(path):
            raise verifier.VerifierUnavailable("not owned")
        got = self.batch(owner_check=owner).verify_many(self.asks("ok", "bad"))
        self.failed(got, 2)
        self.assertEqual(got[0].why, "not owned")
        self.assertEqual(self.spawns(), [])

    def test_the_limit_is_the_one_in_the_vitni_contract(self):
        self.assertEqual(verifier.BATCH_LIMIT, 65536)

    def test_a_long_list_is_sent_in_rounds_of_at_most_the_limit_in_order(self):
        calls = []
        receipts = ("ok", "bad", "malformed", "ok", "bad")
        with mock.patch.object(verifier, "BATCH_LIMIT", 2):
            got = self.batch(owner_check=calls.append).verify_many(self.asks(*receipts))
        self.assertEqual(got, ["ok", "bad_signature", "malformed", "ok", "bad_signature"])
        self.assertEqual([s["count"] for s in self.spawns()], [2, 2, 1])
        self.assertEqual(len(calls), 3)

    def test_a_list_of_exactly_the_limit_is_one_round(self):
        with mock.patch.object(verifier, "BATCH_LIMIT", 3):
            self.batch().verify_many(self.asks("ok", "ok", "ok"))
            self.assertEqual([s["count"] for s in self.spawns()], [3])
            self.batch().verify_many(self.asks("ok", "ok", "ok", "ok"))
        self.assertEqual([s["count"] for s in self.spawns()], [3, 3, 1])

    def test_a_round_that_fails_leaves_the_other_rounds_alone(self):
        calls = []

        def owner(path):
            calls.append(path)
            if len(calls) == 2:
                raise verifier.VerifierUnavailable("gone")
        with mock.patch.object(verifier, "BATCH_LIMIT", 2):
            got = self.batch(owner_check=owner).verify_many(self.asks("ok", "bad", "ok", "bad", "malformed"))
        self.assertEqual(got[:2], ["ok", "bad_signature"])
        self.assertEqual([type(g) for g in got[2:4]], [verifier.Failed] * 2)
        self.assertEqual(got[4], "malformed")
        self.assertEqual([s["count"] for s in self.spawns()], [2, 1])

    def test_a_results_member_that_is_not_a_list_fails_every_element_whatever_its_value(self):
        for results in ("3", "null", "true", '"abc"', '{"a":1,"b":2,"c":3}', "{}", "[]"):
            got = self.batch().verify_many(self.asks("ok", "bad", "rawbatch:" + '{"results":%s}' % results))
            self.failed(got, 3)

    def test_installed_is_a_batch_verifier_with_the_default_owner_check(self):
        got = verifier.VitniBatch.installed(platform="linux")
        self.assertIs(type(got), verifier.VitniBatch)
        self.assertEqual(got.argv, ["/opt/handsal/bin/vitni-verify"])
        self.assertIs(got.owner_check, verifier.check_admin_owned)
        self.assertIs(type(verifier.VitniBatch.installed(platform="plan9")), verifier.Absent)


class Depth(unittest.TestCase):
    """vitni refuses a text nested over 128 deep, and judges a whole batch once: an element sits two levels deeper
    than a lone `verify` input, and a refusal fails the whole batch. So the depth of a question the checker builds
    is held to a small constant, and a key entry that grows nested fails here and not silently in a batch."""

    LONE = 4    # the input, the keys map, a person's keys, a key entry
    BATCH = 6   # the same question as an element of {"questions": [...]}

    class Recording(verifier.Verifier):
        def __init__(self):
            self.asked = []

        def verify(self, jws, keys, method):
            self.asked.append(verifier.VitniCli._input(jws, keys, method))
            return "ok"

    @staticmethod
    def depth(value):
        if isinstance(value, dict):
            return 1 + max([Depth.depth(v) for v in value.values()] + [0])
        if isinstance(value, list):
            return 1 + max([Depth.depth(v) for v in value] + [0])
        return 0

    def questions(self):
        w = production_world()
        step = w.device_add("alice2", ("alice", "bob"))
        snap = {"acts": [], "docs": [{"doc": w.doc, "sigs": w.sigs(w.doc, ("alice", "bob", "carol"))}], "org": w.id}
        recorder = self.Recording()
        table = server.build_commands(recorder, load_profiles=lambda: PRODUCTION_ONLY)
        run(table, "admit", {**snap, "item": {"act": step.primary.jws, "sigs": step.acts[1:]}})
        run(table, "pool", {**snap, "agree": {"x": "A" * 43, "y": "A" * 43}})
        run(table, "compact", snap)
        return recorder.asked

    def test_a_key_entry_is_flat(self):
        self.assertEqual(self.depth(verifier.key_entry({"x": "a", "y": "b"}, "active")), 1)

    def test_every_question_the_checker_builds_is_shallow_alone_and_in_a_batch(self):
        asked = self.questions()
        self.assertGreater(len(asked), 5)
        deepest = max(self.depth(q) for q in asked)
        self.assertEqual(deepest, self.LONE)   # keys are really in the questions, so the bound is measured
        self.assertEqual(max(self.depth({"questions": [q]}) for q in asked) - 1, self.LONE + 1)
        self.assertLessEqual(self.depth({"questions": asked}), self.BATCH)


class Counting(verifier.Verifier):
    def __init__(self, reason="ok"):
        self.calls, self.reason = 0, reason

    def verify(self, jws, keys, method):
        self.calls += 1
        if self.reason is None:
            raise verifier.VerifierUnavailable("down")
        return self.reason


class Many(unittest.TestCase):
    """`verify_many` is one verifier round: the default asks one by one and turns a refusal to answer into a value."""

    class Scripted(verifier.Verifier):
        def __init__(self, script):
            self.script, self.asked = script, []

        def verify(self, jws, keys, method):
            self.asked.append((jws, keys, method))
            got = self.script[jws]
            if got is None:
                raise verifier.VerifierUnavailable("down on " + jws)
            return got

    def test_a_question_is_the_text_the_canonical_keys_and_the_method(self):
        got = verifier.question("j", {"b": 1, "a": {"y": 2, "x": 1}}, "m")
        self.assertEqual(got, verifier.Question("j", '{"a":{"x":1,"y":2},"b":1}', "m"))
        self.assertEqual(tuple(got), ("j", '{"a":{"x":1,"y":2},"b":1}', "m"))
        self.assertEqual(verifier.question("j", {"a": 1, "b": 2}, "m"), verifier.question("j", {"b": 2, "a": 1}, "m"))

    def test_the_default_returns_what_verify_returns_in_order(self):
        inner = self.Scripted({"a": "ok", "b": "bad_signature", "c": "unknown_key"})
        qs = [verifier.question(j, KEYS, "m") for j in ("c", "a", "b", "a")]
        self.assertEqual(inner.verify_many(qs), ["unknown_key", "ok", "bad_signature", "ok"])
        self.assertEqual([a[0] for a in inner.asked], ["c", "a", "b", "a"])
        self.assertEqual(inner.asked[0][1], KEYS)

    def test_an_element_that_cannot_be_answered_is_failed_and_the_others_stand(self):
        inner = self.Scripted({"a": "ok", "b": None, "c": "revoked_key"})
        got = inner.verify_many([verifier.question(j, KEYS, "m") for j in ("a", "b", "c")])
        self.assertEqual(got, ["ok", verifier.Failed("down on b"), "revoked_key"])
        self.assertIs(type(got[1]), verifier.Failed)

    def test_no_question_is_no_result(self):
        self.assertEqual(self.Scripted({}).verify_many([]), [])

    def test_the_default_identity_is_none(self):
        self.assertIsNone(self.Scripted({}).identity())
        self.assertIsNone(verifier.Absent().identity())
        self.assertIsNone(cli().identity())


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

    def test_a_question_with_the_key_and_one_without_it_are_two_questions_in_either_order(self):
        """Counting asks a text with the keys of the state and possession asks it with the new key added: one text,
        two answers, so a memo keyed by the text alone would let one answer stand for the other."""
        person, kid = "alice", "k" * 43
        entry = KEYS[person][kid]

        class Models(verifier.Verifier):
            """Answers like vitni: it reads `keys[performer][kid]` of the question and nothing else."""

            def __init__(self):
                self.calls = 0

            def verify(self, jws, keys, method):
                self.calls += 1
                return "ok" if (keys.get(person) or {}).get(kid) == entry else "unknown_key"

        for order in (({}, KEYS), (KEYS, {})):
            inner = Models()
            memo = verifier.Memoized(inner)
            got = [memo.verify("j", keys, "m") for keys in order]
            self.assertEqual(got, ["unknown_key" if not keys else "ok" for keys in order])
            self.assertEqual(inner.calls, 2)

    def test_the_checker_makes_a_memo_in_one_place_the_command_boundary(self):
        made = {}
        for path in sorted(Path(verifier.__file__).parent.glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
                    if name in ("Memoized", "Speculating"):
                        made[path.name] = made.get(path.name, 0) + 1
        self.assertEqual(made, {"commands.py": 3})   # per_call makes one, per_batch two (the guess and the real pass)


ROOT = Path(__file__).resolve().parents[3]
# where a verifier class can live: the package, its tests and doubles, the tools and their tests
VERIFIER_SOURCES = (ROOT / "checker" / "python" / "src" / "handsal_check", ROOT / "checker" / "python" / "tests",
                    ROOT / "tools", ROOT / "tools" / "tests", ROOT / "tools" / "throwaway" / "tests")


def _base_name(node):
    return node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", None)


class OneInterface(unittest.TestCase):
    """Every class that answers `verify` is a `verifier.Verifier`, so a seam added to the interface reaches it."""

    def test_every_verifier_class_and_test_double_is_a_Verifier(self):
        classes = {}
        for folder in VERIFIER_SOURCES:
            self.assertTrue(folder.is_dir(), folder)
            for path in sorted(folder.glob("*.py")):
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    if isinstance(node, ast.ClassDef):
                        classes.setdefault(node.name, []).append((path, node))

        def reaches_verifier(node, seen=()):
            for base in node.bases:
                name = _base_name(base)
                if name == "Verifier":
                    return True
                if name in classes and name not in seen and any(
                        reaches_verifier(other, seen + (name,)) for _, other in classes[name]):
                    return True
            return False

        loose = sorted("%s:%s" % (path.name, node.name) for group in classes.values() for path, node in group
                       if any(isinstance(n, ast.FunctionDef) and n.name == "verify" for n in node.body)
                       and not reaches_verifier(node))
        self.assertEqual(loose, [])

    def test_the_package_verifiers_are_Verifiers(self):
        for cls in (verifier.VitniCli, verifier.VitniBatch, verifier.Absent, verifier.Memoized):
            self.assertTrue(issubclass(cls, verifier.Verifier), cls)


def asked(jws, keys=KEYS, method="m"):
    return verifier.question(jws, keys, method)


class Seeded(unittest.TestCase):
    """A call's memo can start from answers a round gave, errors included, and from verdicts of earlier calls."""

    def test_a_seeded_answer_is_read_and_never_reaches_the_inner_verifier(self):
        inner = Counting()
        memo = verifier.Memoized(inner, answers={asked("j"): "bad_signature"})
        self.assertEqual(memo.verify("j", KEYS, "m"), "bad_signature")
        self.assertEqual(inner.calls, 0)

    def test_a_seeded_failure_raises_where_it_is_read_and_nowhere_else(self):
        inner = Counting()
        memo = verifier.Memoized(inner, answers={asked("j"): verifier.Failed("round down"), asked("k"): "ok"})
        self.assertEqual(memo.verify("k", KEYS, "m"), "ok")   # a failed question nobody reads changes nothing
        for _ in range(2):   # and it stays an error: it was never taken for a verdict
            with self.assertRaises(verifier.VerifierUnavailable) as caught:
                memo.verify("j", KEYS, "m")
            self.assertEqual(str(caught.exception), "round down")
        self.assertEqual(inner.calls, 0)

    def test_a_miss_goes_to_the_inner_verifier_once_and_is_put_in_known(self):
        inner, known = Counting("bad_signature"), verifier.Verdicts()
        memo = verifier.Memoized(inner, known)
        for _ in range(3):
            self.assertEqual(memo.verify("j", KEYS, "m"), "bad_signature")
        self.assertEqual(inner.calls, 1)
        self.assertEqual(known.get(asked("j")), "bad_signature")

    def test_a_known_verdict_answers_without_the_inner_verifier(self):
        inner, known = Counting(), verifier.Verdicts()
        known.put(asked("j"), "revoked_key")
        self.assertEqual(verifier.Memoized(inner, known).verify("j", KEYS, "m"), "revoked_key")
        self.assertEqual(inner.calls, 0)

    def test_a_failure_to_answer_a_miss_is_not_put_in_known(self):
        known = verifier.Verdicts()
        with self.assertRaises(verifier.VerifierUnavailable):
            verifier.Memoized(Counting(None), known).verify("j", KEYS, "m")
        self.assertIsNone(known.get(asked("j")))

    def test_the_seeded_answers_of_the_caller_are_not_changed_by_the_call(self):
        seeded = {asked("j"): "ok"}
        verifier.Memoized(Counting(), answers=seeded).verify("k", KEYS, "m")
        self.assertEqual(seeded, {asked("j"): "ok"})


class Speculating(unittest.TestCase):
    """The recording pass: it answers `ok` to what it does not know and notes the question once, in order."""

    def test_unknown_questions_are_recorded_once_in_order_and_answered_ok(self):
        inner = Counting("bad_signature")
        spec = verifier.Speculating(inner)
        got = [spec.verify(j, KEYS, "m") for j in ("b", "a", "b", "c", "a")]
        self.assertEqual(got, ["ok"] * 5)
        self.assertEqual(spec.speculated, [asked("b"), asked("a"), asked("c")])
        self.assertEqual(inner.calls, 0)

    def test_the_same_text_under_other_keys_or_method_is_another_question(self):
        spec = verifier.Speculating(Counting())
        spec.verify("j", {}, "m")
        spec.verify("j", KEYS, "m")
        spec.verify("j", KEYS, "m2")
        self.assertEqual(len(spec.speculated), 3)

    def test_a_question_known_from_answers_or_from_known_is_not_recorded_and_keeps_its_answer(self):
        known = verifier.Verdicts()
        known.put(asked("k"), "unknown_key")
        spec = verifier.Speculating(Counting(), known, {asked("j"): "bad_signature"})
        self.assertEqual(spec.verify("j", KEYS, "m"), "bad_signature")
        self.assertEqual(spec.verify("k", KEYS, "m"), "unknown_key")
        self.assertEqual(spec.speculated, [])

    def test_a_seeded_failure_still_raises_where_it_is_read(self):
        spec = verifier.Speculating(Counting(), answers={asked("j"): verifier.Failed("down")})
        with self.assertRaises(verifier.VerifierUnavailable):
            spec.verify("j", KEYS, "m")
        self.assertEqual(spec.speculated, [])

    def test_a_fold_accepts_it_as_the_calls_memo_and_a_raw_verifier_still_raises(self):
        spec = verifier.Speculating(Counting())
        self.assertIs(verifier.call_memo(spec), spec)
        with self.assertRaises(TypeError):
            verifier.call_memo(Counting())


class Verdicts(unittest.TestCase):
    """What was learned about a question survives the call that learned it: verdict strings only."""

    def test_a_verdict_is_put_and_got_by_its_question(self):
        known = verifier.Verdicts()
        self.assertIsNone(known.get(asked("j")))
        known.put(asked("j"), "ok")
        self.assertEqual(known.get(asked("j")), "ok")

    def test_the_same_text_under_other_keys_or_method_is_another_entry(self):
        known = verifier.Verdicts()
        known.put(asked("j", {}), "unknown_key")
        known.put(asked("j", KEYS), "ok")
        self.assertEqual(known.get(asked("j", {})), "unknown_key")
        self.assertEqual(known.get(asked("j", KEYS)), "ok")
        self.assertIsNone(known.get(asked("j", KEYS, "m2")))

    def test_learn_keeps_the_verdicts_and_skips_the_failures(self):
        known = verifier.Verdicts()
        known.learn({asked("a"): "ok", asked("b"): verifier.Failed("down"), asked("c"): "bad_signature"})
        self.assertEqual([known.get(asked(j)) for j in "abc"], ["ok", None, "bad_signature"])

    def test_nothing_but_a_verdict_string_is_stored(self):
        known = verifier.Verdicts()
        for bad in (verifier.Failed("down"), None, 7, verifier.VerifierUnavailable("down")):
            with self.assertRaises(TypeError):
                known.put(asked("j"), bad)
        self.assertIsNone(known.get(asked("j")))

    def test_clear_forgets_everything(self):
        known = verifier.Verdicts()
        known.put(asked("j"), "ok")
        known.clear()
        self.assertIsNone(known.get(asked("j")))


class Classify(unittest.TestCase):
    def test_four_reasons_pass_through_and_the_rest_is_unexpected(self):
        for reason in ("unknown_key", "revoked_key", "bad_signature", "context_mismatch", "ok"):
            self.assertEqual(verifier.classify(reason), reason)
        for reason in ("malformed", "header_key_material", "alg_not_allowed", "non_canonical_payload",
                       "something_new", ""):
            self.assertEqual(verifier.classify(reason), "verifier_unexpected")


if __name__ == "__main__":
    unittest.main()
