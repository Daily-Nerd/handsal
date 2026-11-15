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
import json
import os
import stat
import subprocess
import sys

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


class Absent:
    """The verifier of a platform that has no fixed path: it never answers."""

    def verify(self, jws, keys, method):
        raise _unavailable("no vitni path is fixed for this platform")


class VitniCli:
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
        return _reason(proc)


def _reason(proc):
    if proc.returncode != 0:
        raise _unavailable("vitni exited %d" % proc.returncode)
    try:
        out = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise _unavailable("vitni output is not JSON") from err
    if (type(out) is not dict or set(out) != {"reason", "valid"} or type(out["valid"]) is not bool
            or type(out["reason"]) is not str or out["valid"] != (out["reason"] == "ok")):
        raise _unavailable("vitni output is not a verdict")
    return out["reason"]


def key_entry(sign, status):
    """The vitni `keys` entry of the signing key `sign` (`{x, y}`): CONTRACT section 7, FO-02.
    `status` is `active` or `revoked`."""
    return {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": status, "x": sign["x"], "y": sign["y"]}


class Memoized:
    """A verifier that asks the inner one each distinct question once. One fold call owns one; it
    is dropped with the call, so nothing survives between calls (design 6.2)."""

    def __init__(self, inner):
        self.inner = inner
        self._answers = {}

    def verify(self, jws, keys, method):
        question = (jws, json.dumps(keys, sort_keys=True, separators=(",", ":")), method)
        if question not in self._answers:
            self._answers[question] = self.inner.verify(jws, keys, method)
        return self._answers[question]
