"""T2.4 vitni cross-check (CF-06, CF-05).

Both vitni binaries judge every positive JWS and both must say `ok`, else the
run aborts. Negative vectors record vitni's verdict. Binary paths come by
argument only, absolute, never looked up on PATH. Tests use fake binaries.
"""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from lib import vitni

KEYS = {"alice": {"k1": {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active",
                         "x": "AAAA", "y": "BBBB"}}}
POLICY = {"expected_binding": "local", "expected_method": "local:handsal.request.approve"}
JWS = "aaa.bbb.ccc"


class Fakes(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def fake(self, name, reason, valid=None, exit_code=0, raw=None, record=None):
        if valid is None:
            valid = reason == "ok"
        out = raw if raw is not None else json.dumps({"reason": reason, "valid": valid},
                                                     sort_keys=True, separators=(",", ":"))
        lines = ["#!/bin/sh"]
        if record:
            lines.append('echo "$1" >> %s' % record)
            lines.append("cat >> %s.in" % record)
        else:
            lines.append("cat >/dev/null")
        lines.append("printf '%%s\\n' '%s'" % out)
        lines.append("exit %d" % exit_code)
        path = self.dir / name
        path.write_text("\n".join(lines) + "\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)


class Positive(Fakes):
    def test_both_ok_passes(self):
        cc = vitni.CrossCheck(self.fake("go", "ok"), self.fake("ts", "ok"))
        cc.positive(JWS, KEYS, POLICY)

    def test_bad_signature_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "bad_signature"), self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort) as ctx:
            cc.positive(JWS, KEYS, POLICY)
        self.assertIn("bad_signature", str(ctx.exception))

    def test_ts_bad_signature_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok"), self.fake("ts", "bad_signature"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_both_failing_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "unknown_key"), self.fake("ts", "bad_signature"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_valid_true_with_other_reason_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok", valid=False), self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_input_shape_sent_to_binary(self):
        rec = str(self.dir / "rec")
        cc = vitni.CrossCheck(self.fake("go", "ok", record=rec), self.fake("ts", "ok"))
        cc.positive(JWS, KEYS, POLICY)
        self.assertEqual((self.dir / "rec").read_text().strip(), "verify")
        sent = json.loads((self.dir / "rec.in").read_text())
        self.assertEqual(sent, {"signed_receipt": JWS, "keys": KEYS, "policy": POLICY})


class Missing(Fakes):
    def test_missing_binary_aborts(self):
        cc = vitni.CrossCheck(str(self.dir / "nope"), self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_missing_ts_binary_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok"), str(self.dir / "nope"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_relative_path_refused(self):
        with self.assertRaises(vitni.VitniAbort):
            vitni.CrossCheck("vitni-verify-go", self.fake("ts", "ok"))

    def test_none_refused(self):
        with self.assertRaises(vitni.VitniAbort):
            vitni.CrossCheck(None, self.fake("ts", "ok"))

    def test_not_executable_aborts(self):
        plain = self.dir / "plain"
        plain.write_text("#!/bin/sh\n")
        plain.chmod(0o644)
        with self.assertRaises(vitni.VitniAbort):
            vitni.CrossCheck(str(plain), self.fake("ts", "ok")).positive(JWS, KEYS, POLICY)

    def test_directory_aborts(self):
        with self.assertRaises(vitni.VitniAbort):
            vitni.CrossCheck(str(self.dir), self.fake("ts", "ok")).positive(JWS, KEYS, POLICY)

    def test_never_uses_path_lookup(self):
        self.fake("vitni-on-path", "ok")
        old = os.environ["PATH"]
        os.environ["PATH"] = str(self.dir) + os.pathsep + old
        self.addCleanup(os.environ.__setitem__, "PATH", old)
        with self.assertRaises(vitni.VitniAbort):
            vitni.CrossCheck("vitni-on-path", self.fake("ts", "ok"))


class Garbage(Fakes):
    def test_nonzero_exit_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok", exit_code=2), self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_not_json_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok", raw="hello"), self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_error_object_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok", raw='{"error":"bad_input"}'),
                              self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)

    def test_extra_keys_abort(self):
        cc = vitni.CrossCheck(self.fake("go", "ok", raw='{"reason":"ok","valid":true,"x":1}'),
                              self.fake("ts", "ok"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)


class Negative(Fakes):
    def test_records_agreed_verdict(self):
        cc = vitni.CrossCheck(self.fake("go", "bad_signature"), self.fake("ts", "bad_signature"))
        self.assertEqual(cc.negative(JWS, KEYS, POLICY), "bad_signature")

    def test_records_ok_for_a_vector_that_is_not_a_signature_defect(self):
        cc = vitni.CrossCheck(self.fake("go", "ok"), self.fake("ts", "ok"))
        self.assertEqual(cc.negative(JWS, KEYS, POLICY), "ok")

    def test_disagreement_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "bad_signature"), self.fake("ts", "unknown_key"))
        with self.assertRaises(vitni.VitniAbort) as ctx:
            cc.negative(JWS, KEYS, POLICY)
        self.assertIn("disagree", str(ctx.exception))

    def test_positive_disagreement_aborts(self):
        cc = vitni.CrossCheck(self.fake("go", "ok"), self.fake("ts", "non_canonical_payload"))
        with self.assertRaises(vitni.VitniAbort):
            cc.positive(JWS, KEYS, POLICY)


class Spec(Fakes):
    def test_argv_list_form(self):
        go = self.fake("go", "ok")
        cc = vitni.CrossCheck([go], [self.fake("ts", "ok")])
        cc.positive(JWS, KEYS, POLICY)

    def test_empty_list_refused(self):
        with self.assertRaises(vitni.VitniAbort):
            vitni.CrossCheck([], self.fake("ts", "ok"))


class Preflight(Fakes):
    def test_a_missing_binary_aborts_before_any_act_is_judged(self):
        cc = vitni.CrossCheck([self.fake("go", "ok")], ["/nonexistent/ts"])
        with self.assertRaises(vitni.VitniAbort):
            cc.preflight()

    def test_two_runnable_binaries_pass(self):
        vitni.CrossCheck([self.fake("go", "ok")], [self.fake("ts", "ok")]).preflight()


if __name__ == "__main__":
    unittest.main()
