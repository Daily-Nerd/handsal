"""vitni cross-check (CF-06, CF-05).

vitni `verify` is the single ES256 owner. The generator runs BOTH vitni
binaries, Go and TypeScript, on every JWS it writes:

- a positive JWS must come back `{"valid":true,"reason":"ok"}` from both, or
  the run aborts;
- a negative vector records vitni's verdict, and the two binaries must agree
  on it, or the run aborts (a vitni divergence is found at generation time).

The cross-check is never skippable in silence. A missing, unrunnable or
garbled binary raises VitniAbort, and so does every disagreement. Binaries
are named by argument only: an absolute path (or an argv list whose first
element is one), never looked up on PATH, never read from an environment
variable. The child inherits PATH only because vitni's own TypeScript entry
point starts with `#!/usr/bin/env node`; this module never resolves a name.

Standard library only. Independent of the checker.
"""
import json
import os
import subprocess

TIMEOUT_S = 30


class VitniAbort(RuntimeError):
    """The cross-check cannot vouch for a signature. The run must stop."""


def _argv(spec, label):
    if isinstance(spec, (str, os.PathLike)):
        argv = [os.fspath(spec)]
    elif isinstance(spec, (list, tuple)) and spec and all(isinstance(a, (str, os.PathLike)) for a in spec):
        argv = [os.fspath(a) for a in spec]
    else:
        raise VitniAbort("%s: vitni binary must be given as an absolute path (or argv list)" % label)
    if not os.path.isabs(argv[0]):
        raise VitniAbort("%s: path must be absolute, got %r" % (label, argv[0]))
    return argv


def _preflight(argv, label):
    exe = argv[0]
    if not os.path.isfile(exe):
        raise VitniAbort("%s: not a file: %s" % (label, exe))
    if not os.access(exe, os.X_OK):
        raise VitniAbort("%s: not executable: %s" % (label, exe))


class Verifier:
    """One vitni binary: `<bin> verify < input.json`, one JSON line out."""

    def __init__(self, spec, label):
        self.label = label
        self.argv = _argv(spec, label)

    def verify(self, jws, keys, policy):
        _preflight(self.argv, self.label)
        stdin = json.dumps({"signed_receipt": jws, "keys": keys, "policy": policy},
                           sort_keys=True, separators=(",", ":"))
        try:
            proc = subprocess.run(
                self.argv + ["verify"], input=stdin.encode("utf-8"), capture_output=True,
                timeout=TIMEOUT_S, env={"PATH": os.environ.get("PATH", "")}, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise VitniAbort("%s: cannot run %s: %s" % (self.label, self.argv[0], exc)) from exc
        if proc.returncode != 0:
            raise VitniAbort("%s: exit %d: %s" % (self.label, proc.returncode,
                                                  proc.stderr.decode("utf-8", "replace")[:200]))
        try:
            out = json.loads(proc.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise VitniAbort("%s: output is not JSON: %r" % (self.label, proc.stdout[:200])) from exc
        if (not isinstance(out, dict) or set(out) != {"reason", "valid"}
                or not isinstance(out["valid"], bool) or not isinstance(out["reason"], str)
                or out["valid"] != (out["reason"] == "ok")):
            raise VitniAbort("%s: unexpected output %r" % (self.label, out))
        return out["reason"]


class CrossCheck:
    def __init__(self, go, ts):
        self.go = Verifier(go, "vitni-go")
        self.ts = Verifier(ts, "vitni-ts")

    def preflight(self):
        """Abort now if either binary is missing or not executable."""
        for verifier in (self.go, self.ts):
            _preflight(verifier.argv, verifier.label)

    def _both(self, jws, keys, policy):
        a = self.go.verify(jws, keys, policy)
        b = self.ts.verify(jws, keys, policy)
        if a != b:
            raise VitniAbort("vitni binaries disagree: go=%s ts=%s" % (a, b))
        return a

    def positive(self, jws, keys, policy):
        """Both binaries must say `ok`, else abort."""
        a = self.go.verify(jws, keys, policy)
        b = self.ts.verify(jws, keys, policy)
        if a != "ok" or b != "ok":
            raise VitniAbort("positive JWS not ok: go=%s ts=%s" % (a, b))

    def negative(self, jws, keys, policy):
        """vitni's verdict (a reason string), identical from both binaries."""
        return self._both(jws, keys, policy)
