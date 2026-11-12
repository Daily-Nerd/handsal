"""A stand-in for the vitni binary, for `test_verifier.py`. Not part of the checker.

Run as `stub_vitni.py verify` with vitni's input on stdin. The `signed_receipt` string picks the
behaviour: `ok`, `bad`, `echo` (the reason carries the exact input), `env` (the reason says whether
none of PATH, HOME and the test sentinel reached the process), `garbage`, `error`, `extra`, `exit3` and `sleep`.
"""
import json
import os
import sys
import time

command = sys.argv[1] if len(sys.argv) > 1 else None
data = json.loads(sys.stdin.read())
mode = data["signed_receipt"]
if command != "verify":
    print('{"error":"unsupported_command"}')
elif mode == "ok":
    print('{"reason":"ok","valid":true}')
elif mode == "bad":
    print('{"reason":"bad_signature","valid":false}')
elif mode == "echo":
    seen = json.dumps({"keys": data["keys"], "policy": data["policy"]}, sort_keys=True, separators=(",", ":"))
    print(json.dumps({"reason": "echo:" + seen, "valid": False}))
elif mode == "env":
    leaked = sorted(k for k in ("PATH", "HOME", "HANDSAL_TEST_SENTINEL") if k in os.environ)
    print(json.dumps({"reason": "env:" + ",".join(leaked), "valid": False}))
elif mode == "garbage":
    print("not json")
elif mode == "error":
    print('{"error":"invalid_input"}')
elif mode == "extra":
    print('{"reason":"ok","valid":true,"extra":1}')
elif mode == "mismatch":
    print('{"reason":"bad_signature","valid":true}')
elif mode == "exit3":
    sys.exit(3)
elif mode == "sleep":
    time.sleep(30)
