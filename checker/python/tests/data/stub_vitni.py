"""A stand-in for the vitni binary, for `test_verifier.py`. Not part of the checker.

Run as `stub_vitni.py verify` or `stub_vitni.py verify-batch` with vitni's input on stdin. `verify` and
`verify-batch` share one table, so a batch element is answered by the same code as a lone question. The
`signed_receipt` string picks the behaviour: `ok`, `bad`, `malformed`, `echo` (the reason carries the exact
input), `env` (the reason says whether none of PATH, HOME and the test sentinel reached the process), `error`
(`{"error":"invalid_input"}`), `extra`, `mismatch`, `garbage`, `exit3` and `sleep`.
A receipt `raw:<text>` prints `<text>` as the whole answer (for a batch element, the text is the element).
In a batch, `garbage`, `exit3` and `sleep` in any element make the whole process behave that way, and these
make the batch shape wrong: `short` and `long` (one result too few or too many), `toplevel` (the top-level
`batch_too_large` error), `notdict`, `notlist` and `extramember`. A receipt `rawbatch:<text>` in any element makes
`<text>` the whole output of the process.
If the argv has an item between the script and the command, it is a file: one JSON line is appended to it per
process, `{"command": ..., "count": number of questions or null}`.
"""
import json
import os
import sys
import time

command = sys.argv[-1]
log = sys.argv[1] if len(sys.argv) > 2 else None
data = json.loads(sys.stdin.read())


def answer(item):
    """The object `verify` prints for the question `item`."""
    mode = item["signed_receipt"]
    if mode.startswith("raw:"):
        return json.loads(mode[4:])
    if mode == "ok":
        return {"reason": "ok", "valid": True}
    if mode == "bad":
        return {"reason": "bad_signature", "valid": False}
    if mode == "malformed":
        return {"reason": "malformed", "valid": False}
    if mode == "echo":
        seen = json.dumps({"keys": item["keys"], "policy": item["policy"]}, sort_keys=True, separators=(",", ":"))
        return {"reason": "echo:" + seen, "valid": False}
    if mode == "env":
        leaked = sorted(k for k in ("PATH", "HOME", "HANDSAL_TEST_SENTINEL") if k in os.environ)
        return {"reason": "env:" + ",".join(leaked), "valid": False}
    if mode == "error":
        return {"error": "invalid_input"}
    if mode == "extra":
        return {"reason": "ok", "valid": True, "extra": 1}
    if mode == "mismatch":
        return {"reason": "bad_signature", "valid": True}
    return {"error": "unknown_mode"}


def process(mode):
    """Behave as a failed process for `mode`; return when `mode` is not a process fault."""
    if mode == "garbage":
        print("not json")
        sys.exit(0)
    if mode == "exit3":
        sys.exit(3)
    if mode == "sleep":
        time.sleep(30)
        sys.exit(0)


if log:
    count = len(data["questions"]) if command == "verify-batch" else None
    with open(log, "a") as handle:
        handle.write(json.dumps({"command": command, "count": count}) + "\n")

if command == "verify":
    process(data["signed_receipt"])
    print(json.dumps(answer(data)))
elif command == "verify-batch":
    modes = [item["signed_receipt"] for item in data["questions"]]
    for mode in modes:
        process(mode)
        if mode.startswith("rawbatch:"):
            print(mode[len("rawbatch:"):])
            sys.exit(0)
    results = [answer(item) for item in data["questions"]]
    if "short" in modes:
        results = results[:-1]
    if "long" in modes:
        results = results + [{"reason": "ok", "valid": True}]
    out = {"results": results}
    if "toplevel" in modes:
        out = {"error": "batch_too_large"}
    if "notdict" in modes:
        out = []
    if "notlist" in modes:
        out = {"results": {}}
    if "extramember" in modes:
        out["extra"] = 1
    print(json.dumps(out))
else:
    print('{"error":"unsupported_command"}')
