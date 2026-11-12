"""A stand-in vitni binary that answers from the keys it is sent (CONTRACT section 7), no ES256.

Used by `test_conformance.py` to run the checker end to end through a real subprocess. A signature of
64 zero bytes is `bad_signature`; any other signature is accepted, as the stand-in for a real one.
Not part of the checker.
"""
import base64
import json
import sys

data = json.loads(sys.stdin.read())


def b64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


parts = data["signed_receipt"].split(".")
header, payload, signature = json.loads(b64u(parts[0])), json.loads(b64u(parts[1])), b64u(parts[2])
entry = (data["keys"].get(payload["performer_id"]) or {}).get(header["kid"])
if entry is None:
    reason = "unknown_key"
elif entry["status"] == "revoked":
    reason = "revoked_key"
elif signature == b"\x00" * 64:
    reason = "bad_signature"
elif data["policy"]["expected_method"] != payload["method"]:
    reason = "context_mismatch"
else:
    reason = "ok"
print(json.dumps({"reason": reason, "valid": reason == "ok"}))
