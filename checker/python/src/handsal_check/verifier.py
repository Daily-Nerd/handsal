"""The verifier: ES256 is vitni's, behind one interface (VR-03, VR-04, CF-05, SG-14).

The checker never computes ES256. A `Verifier` has one method, `verify(jws, keys, method)`, that
returns vitni's reason string (`ok`, `bad_signature`, ...). It never returns a guess: when no
answer can be had it raises `VerifierUnavailable`, which the fold reports as the error
`verifier_unavailable` and `check-act` as the reason of the same name (never a skip).

`VitniCli` runs `<argv> verify` with vitni's input on stdin. `policy.expected_binding` is always
`local` and `policy.expected_method` is always the method of the act, never null, so vitni never
skips the check (VR-03). The child runs with an empty environment, and the path is never read from
the environment or looked up on PATH: `VitniCli.installed()` fixes it per platform (SG-14), and
tests and the conformance build give an argv to the constructor, which is the only way to change it.
Before each spawn the default owner check walks the file and every ancestor like the pin reader does
(GP-10), so a user-writable verifier is never run.

`is_low_s` is the VR-04 rule on the 64 raw signature bytes: vitni accepts S above n/2, the profile
does not. `classify` is VR-03's reason table: four vitni reasons pass through, every other one is
`verifier_unexpected`.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections import namedtuple

TIMEOUT_S = 30
# the order of the P-256 group; S above half of it is the high form (VR-04)
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
PASS_THROUGH = frozenset(("unknown_key", "revoked_key", "bad_signature", "context_mismatch"))
INSTALLED = {"darwin": ["/Library/Application Support/handsal/bin/vitni-verify"],
             "linux": ["/opt/handsal/bin/vitni-verify"]}   # the server build only (CF-10); no pin lives there


class VerifierUnavailable(Exception):
    """No answer from vitni: spawn error, ownership failure, timeout, bad output, `{"error"}`."""


def classify(reason):
    """VR-03: `ok` and the four pass-through reasons as they are, anything else `verifier_unexpected`."""
    if reason == "ok" or reason in PASS_THROUGH:
        return reason
    return "verifier_unexpected"


def is_low_s(signature):
    """True iff S of the 64-byte raw signature R||S is at most n/2 (VR-04)."""
    if type(signature) is not bytes or len(signature) != 64:
        raise ValueError("a signature is 64 bytes")
    return int.from_bytes(signature[32:], "big") <= _N // 2


def _unavailable(why):
    return VerifierUnavailable(why)


def check_admin_owned(path, uid=0, top="/"):
    """Raise VerifierUnavailable unless `path` passes the GP-10 chain for owner `uid`.

    The file, opened without following a symlink: a regular executable file, owned by `uid`, not
    group or other writable, one link. Every ancestor from the file's directory up to `top`: a
    directory, not a symlink, owned by `uid`, not group or other writable. `uid` and `top` are the
    root and the owner of a real installation by default; tests give their own.
    """
    if type(path) is not str or not os.path.isabs(path):
        raise _unavailable("verifier path is not absolute")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, AttributeError) as err:
        raise _unavailable("verifier cannot be opened: %s" % err) from err
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022
            or info.st_nlink != 1 or not info.st_mode & stat.S_IXUSR):
        raise _unavailable("verifier file is not an administrator-owned executable")
    top = top.rstrip("/") or "/"
    here = os.path.dirname(path)
    while True:
        try:
            ancestor = os.lstat(here)
        except OSError as err:
            raise _unavailable("verifier ancestor unreadable: %s" % err) from err
        if (not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid != uid
                or ancestor.st_mode & 0o022):
            raise _unavailable("verifier ancestor is not an administrator-owned directory")
        if here == top:
            return
        parent = os.path.dirname(here)
        if parent == here:   # reached "/" without meeting `top`: the file is not under it
            raise _unavailable("verifier is not under the checked root")
        here = parent


Question = namedtuple("Question", "jws keys method")   # `keys`: the canonical JSON of the entry map, as the memo keys it
Failed = namedtuple("Failed", "why")   # one question that got no answer: a value that is never a verdict


def question(jws, keys, method):
    """The `Question` of a `verify(jws, keys, method)` call: the one key a verdict is remembered under."""
    return Question(jws, json.dumps(keys, sort_keys=True, separators=(",", ":")), method)


class Verifier:
    """The base of every verifier: the real ones and every test double. One round of questions is the
    verifier's to say (`verify_many`), never the fold's."""

    def verify_many(self, questions):
        """One result per question, in order: the reason `verify` gives, or `Failed` where it could not answer.
        The default asks one by one."""
        out = []
        for asked in questions:
            try:
                out.append(self.verify(asked.jws, json.loads(asked.keys), asked.method))
            except VerifierUnavailable as err:
                out.append(Failed(str(err)))
        return out

    def identity(self):
        """What a verdict remembered across calls depends on; `None` when no file stands behind this verifier."""
        return None


class Absent(Verifier):
    """The verifier of a platform that has no fixed path: it never answers."""

    def verify(self, jws, keys, method):
        raise _unavailable("no vitni path is fixed for this platform")


class VitniCli(Verifier):
    """vitni `verify` as a subprocess. See the module docstring."""

    def __init__(self, argv, owner_check=check_admin_owned, timeout=TIMEOUT_S):
        if (type(argv) not in (list, tuple) or not argv or not all(type(a) is str for a in argv)
                or not os.path.isabs(argv[0])):
            raise ValueError("a vitni argv is a list of strings whose first item is an absolute path")
        self.argv = list(argv)
        self.owner_check = owner_check
        self.timeout = timeout

    @classmethod
    def installed(cls, platform=None):
        """The verifier at the SG-14 path of `platform`, or one that is never available."""
        argv = INSTALLED.get(platform or sys.platform)
        return cls(argv) if argv else Absent()

    def verify(self, jws, keys, method):
        """vitni's reason for `jws` against the `keys` map, with the method pinned to `method`."""
        if type(method) is not str or not method:
            raise ValueError("the pinned method is required, never null")
        if self.owner_check is not None:
            self.owner_check(self.argv[0])
        stdin = json.dumps({"keys": keys, "policy": {"expected_binding": "local", "expected_method": method},
                            "signed_receipt": jws}, sort_keys=True, separators=(",", ":"))
        try:
            proc = subprocess.run(self.argv + ["verify"], input=stdin.encode("ascii"),
                                  capture_output=True, timeout=self.timeout, env={}, check=False)
        except (OSError, subprocess.SubprocessError) as err:
            raise _unavailable("vitni cannot run: %s" % err) from err
        return _verdict(_output(proc))


def _output(proc):
    """The JSON value vitni printed, or `VerifierUnavailable` when the process failed or printed no JSON."""
    if proc.returncode != 0:
        raise _unavailable("vitni exited %d" % proc.returncode)
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise _unavailable("vitni output is not JSON") from err


def _verdict(obj):
    """The one definition of a valid vitni answer, for a `verify` output and for a batch element: exactly
    `{"reason": str, "valid": bool}` with `valid` true iff the reason is `ok`. Returns the raw reason."""
    if (type(obj) is not dict or set(obj) != {"reason", "valid"} or type(obj["valid"]) is not bool
            or type(obj["reason"]) is not str or obj["valid"] != (obj["reason"] == "ok")):
        raise _unavailable("vitni output is not a verdict")
    return obj["reason"]


def key_entry(sign, status):
    """The vitni `keys` entry of the signing key `sign` (`{x, y}`): CONTRACT section 7, FO-02.
    `status` is `active` or `revoked`."""
    return {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": status, "x": sign["x"], "y": sign["y"]}


class Verdicts:
    """What earlier calls learned: verdict strings by question, never an error and never a `Failed` (a failure to
    answer is a fact about one round, not about the question). A hit only saves a question; it never decides an
    output, so what it holds changes cost and nothing else."""

    def __init__(self):
        self._held = {}

    @staticmethod
    def _key(asked):
        return hashlib.sha256(json.dumps(list(asked)).encode("utf-8")).digest()

    def get(self, asked):
        """The verdict held for the `Question` `asked`, or `None`."""
        return self._held.get(self._key(asked))

    def put(self, asked, verdict):
        if type(verdict) is not str:
            raise TypeError("only a verdict string is held, got %s" % type(verdict).__name__)
        self._held[self._key(asked)] = verdict

    def learn(self, answers):
        """Hold every verdict of `answers` (`{Question: verdict or Failed}`) and skip every `Failed`."""
        for asked, got in answers.items():
            if type(got) is not Failed:
                self.put(asked, got)

    def clear(self):
        self._held.clear()


class Memoized(Verifier):
    """A verifier that asks the inner one each distinct question once. One command call owns one, made at the
    command boundary (`commands.per_call`, `commands.per_batch`) and dropped with the call, so nothing survives
    between calls except what the call hands to `known` (design 6.2).

    `answers` seeds the call with what a round already said, `Failed` included: a `Failed` raises
    `VerifierUnavailable` only where the fold reads that question, which is where a single spawn would have failed.
    `known` (a `Verdicts`) answers a question before the inner verifier is asked and keeps what a miss learned."""

    def __init__(self, inner, known=None, answers=None):
        self.inner = inner
        self.known = known
        self._answers = {} if answers is None else dict(answers)

    def _learned(self, asked):
        return self.known.get(asked) if self.known is not None else None

    @staticmethod
    def _read(got):
        if type(got) is Failed:
            raise VerifierUnavailable(got.why)
        return got

    def verify(self, jws, keys, method):
        asked = question(jws, keys, method)
        if asked not in self._answers:
            got = self._learned(asked)
            if got is None:
                got = self.inner.verify(jws, keys, method)
                if self.known is not None:
                    self.known.put(asked, got)
            self._answers[asked] = got
        return self._read(self._answers[asked])


class Speculating(Memoized):
    """The recording pass of a batched call: a question it has no answer for is answered `ok` and noted once, in
    order, in `speculated`. It is a `Memoized`, so the fold takes it as the call's memo and runs unchanged."""

    def __init__(self, inner, known=None, answers=None):
        super().__init__(inner, known, answers)
        self.speculated = []

    def verify(self, jws, keys, method):
        asked = question(jws, keys, method)
        if asked not in self._answers:
            got = self._learned(asked)
            if got is None:
                self.speculated.append(asked)
                got = "ok"
            self._answers[asked] = got
        return self._read(self._answers[asked])


def call_memo(vitni):
    """`vitni` itself if it is a call's memo (`Memoized`), else raise TypeError: a fold is built only over
    the memo of its call (`commands.per_call`). A programming error, never a reason code."""
    if not isinstance(vitni, Memoized):
        raise TypeError("a fold needs the call's verifier.Memoized, got %s" % type(vitni).__name__)
    return vitni
