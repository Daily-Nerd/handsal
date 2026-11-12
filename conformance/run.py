"""Conformance harness (CF-02, CF-04).

Loads vector files, feeds each to one or more implementations, and compares
each output line to the vector's anchor and to the other implementations.

Vector file: one JSON object per file,
  {name, command, input | input_raw | input_hex, anchor, pad?, exit?}
  The schema is owned by vector_schema.py, which the vector writer shares.
  anchor     REQUIRED. The exact expected stdout line, without the LF.
  input      a JSON value, sent as compact UTF-8 JSON plus one LF.
  input_raw  a string, sent as its UTF-8 bytes with nothing added.
  input_hex  lowercase hex, sent as the decoded bytes (non-UTF-8 input).
  pad        optional path (list of keys and indexes) to a string inside
             `input`; that string is grown with "a" so the whole stdin is
             MAX_INPUT + 1 bytes. Built at run time, never stored.
  exit       optional expected exit code, default 0.

An implementation is an absolute path or an argv whose first item is an
absolute path. It is never looked up on PATH and no environment variable
selects it. It is run as `<argv...> <command>` with the input on stdin.
"""

import argparse
import copy
import json
import os
import shlex
import subprocess
import sys

# -I drops the script directory from sys.path; vector_schema lives beside this file.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from vector_schema import VectorError, pad_slot, validate

MAX_INPUT = 16777216


def parse_impl(text):
    argv = shlex.split(text)
    if not argv or not os.path.isabs(argv[0]):
        raise VectorError("implementation must start with an absolute path: %r" % text)
    return argv


def load_vector(path):
    try:
        with open(path, "rb") as fh:
            vector = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as err:
        raise VectorError("%s: unreadable vector (%s)" % (path, err))
    validate(vector, path)
    return vector


def load_vectors(directory):
    found = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d != "_gen")
        for f in sorted(files):
            if f.endswith(".json"):
                found.append(load_vector(os.path.join(root, f)))
    return sorted(found, key=lambda v: v["name"])


def _encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _pad(vector):
    value = copy.deepcopy(vector["input"])
    parent, key = pad_slot(value, vector["pad"], vector["name"])
    target = parent[key]
    extra = MAX_INPUT + 1 - len(_encode(value))
    if extra < 0:
        raise VectorError("%s: input already exceeds MAX_INPUT + 1" % vector["name"])
    parent[key] = target + "a" * extra
    return _encode(value)


def build_stdin(vector):
    if "input_raw" in vector:
        return vector["input_raw"].encode("utf-8")
    if "input_hex" in vector:
        return bytes.fromhex(vector["input_hex"])
    if "pad" in vector:
        return _pad(vector)
    return _encode(vector["input"])


def run_impl(argv, vector):
    """Return (exit_code, first stdout line without LF or None)."""
    proc = subprocess.run(argv + [vector["command"]], input=build_stdin(vector),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = proc.stdout
    if not out.endswith(b"\n") or out.count(b"\n") != 1:
        return proc.returncode, None
    return proc.returncode, out[:-1].decode("utf-8", "replace")


def judge(vector, results):
    outputs = [r[1] for r in results]
    if len(set(outputs)) > 1:
        return "DIVERGE"
    expected_exit = vector.get("exit", 0)
    if outputs[0] == vector["anchor"] and all(r[0] == expected_exit for r in results):
        return "PASS"
    return "ANCHOR-FAIL"


def main(argv=None, out=None):
    out = out or sys.stdout
    parser = argparse.ArgumentParser(prog="run.py")
    parser.add_argument("--impl", action="append", default=[])
    parser.add_argument("--vectors", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors"))
    parser.add_argument("--group", default=None)
    parser.add_argument("--commands", default=None)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if not args.impl:
            raise VectorError("at least one --impl is required")
        impls = [parse_impl(i) for i in args.impl]
        vectors = load_vectors(args.vectors)
    except VectorError as err:
        out.write("ERROR %s\n" % err)
        return 2
    if args.group:
        vectors = [v for v in vectors if v["name"].startswith(args.group)]
    if args.commands:
        wanted = set(args.commands.split(","))
        vectors = [v for v in vectors if v["command"] in wanted]
    if not vectors:
        out.write("ERROR no vectors selected\n")
        return 2
    failed = 0
    for vector in vectors:
        try:
            results = [run_impl(i, vector) for i in impls]
        except (VectorError, OSError) as err:
            out.write("ERROR %s: %s\n" % (vector["name"], err))
            return 2
        status = judge(vector, results)
        out.write("%s %s\n" % (status, vector["name"]))
        failed += status != "PASS"
    out.write("%d vectors, %d not passing\n" % (len(vectors), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
