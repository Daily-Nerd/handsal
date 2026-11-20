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
import collections
import copy
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading

# -I drops the script directory from sys.path; vector_schema lives beside this file.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from vector_schema import VectorError, pad_slot, validate

MAX_INPUT = 16777216

# CF-04: the signer runs the render and emit vectors only; the checker runs every other command
# (derived from the vectors, never a list, so a new checker command needs no edit here).
SIGNER_COMMANDS = frozenset(("render", "emit"))


def role_selects(role, command):
    if role == "signer":
        return command in SIGNER_COMMANDS
    return command != "emit"


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


Result = collections.namedtuple("Result", "code line stdout stderr")

# How much of an implementation's stdout and stderr a failing vector prints. A run that does not pass must leave its
# evidence in the output, and the output of a crashing implementation has no size of its own.
EXCERPT = 2048


def run_impl(argv, vector):
    """Return Result(exit code, first stdout line without LF or None, raw stdout, raw stderr). Both pipes are read
    by subprocess.run (communicate), so a full pipe cannot stall the child."""
    proc = subprocess.run(argv + [vector["command"]], input=build_stdin(vector),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout
    if not out.endswith(b"\n") or out.count(b"\n") != 1:
        return Result(proc.returncode, None, out, proc.stderr)
    return Result(proc.returncode, out[:-1].decode("utf-8", "replace"), out, proc.stderr)


class ServeProcess:
    """One `<argv...> serve` process, asked one request at a time: the header line `<command> <length>` and the bytes
    of a one-shot call's stdin, answered by the one line a one-shot call would print. Its stderr goes to a file, so a
    full pipe cannot stall it and the evidence is there when it dies."""

    def __init__(self, argv):
        self.stderr = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(argv + ["serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)

    def _send(self, data):
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except OSError:   # the process ended: the read of its answer says so
            pass

    def ask(self, command, body):
        """The bytes the process answered to one request: one line with its LF, or what came before it ended."""
        data = b"%s %d\n" % (command.encode("ascii"), len(body)) + body
        writer = threading.Thread(target=self._send, args=(data,))   # a long body is written while the answer is read
        writer.start()
        line = self.proc.stdout.readline()
        writer.join()
        return line

    def evidence(self):
        self.stderr.seek(0)
        return _excerpt(self.stderr.read())

    def finish(self):
        """Close its stdin, which ends it at a request boundary, and return its exit code."""
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        code = self.proc.wait()
        self.proc.stdout.close()
        return code

    def abort(self):
        self.proc.kill()
        self.finish()


def _excerpt(data):
    """The first EXCERPT bytes, decoded with errors replaced, and a note when there was more."""
    text = data[:EXCERPT].decode("utf-8", "replace")
    if len(data) > EXCERPT:
        text += "\n... truncated, %d of %d bytes shown" % (EXCERPT, len(data))
    return text


def _indent(text, pad):
    return "".join(pad + line + "\n" for line in text.splitlines()) or pad + "\n"


def describe_failure(vector, results):
    """The lines under a failing vector: what was expected, what each implementation answered, and its stderr."""
    lines = ["  expected: exit %d, %s\n" % (vector.get("exit", 0), vector["anchor"])]
    for n, r in enumerate(results, 1):
        if r.line is not None:
            lines.append("  impl %d: exit %d, %s\n" % (n, r.code, r.line))
        else:
            lines.append("  impl %d: exit %d, no single line on stdout, got:\n" % (n, r.code))
            lines.append(_indent(_excerpt(r.stdout), "    | "))
        if r.stderr:
            lines.append("  impl %d stderr:\n" % n)
            lines.append(_indent(_excerpt(r.stderr), "    | "))
    return "".join(lines)


def evaluate(vector, results):
    outputs = [r[1] for r in results]
    if len(set(outputs)) > 1:
        return "DIVERGE"
    expected_exit = vector.get("exit", 0)
    if outputs[0] == vector["anchor"] and all(r[0] == expected_exit for r in results):
        return "PASS"
    return "ANCHOR-FAIL"


# Groups of vectors that describe a build and not a profile (`version` has none today): an older tag's vector of one
# of these groups is left out of a tag run, by its group and never by its id.
BUILD_DESCRIBING_GROUPS = frozenset()

REPO = os.path.dirname(_HERE)


class GitFailure(Exception):
    pass


def _git(root, *args, stdin=None):
    try:
        proc = subprocess.run(["git", "-C", root] + list(args), input=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as err:
        raise GitFailure("git cannot be run (%s)" % err)
    if proc.returncode:
        raise GitFailure("git %s failed: %s" % (args[0], proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout


def _manifest():
    """tools/manifest.py of this build, the one owner of the bundle hash (CF-01), loaded by path (under -I the
    script directory is not on the import path)."""
    path = os.path.join(REPO, "tools", "manifest.py")
    spec = importlib.util.spec_from_file_location("handsal_manifest", path)
    if spec is None or not os.path.isfile(path):
        raise VectorError("tools/manifest.py is not beside this harness: the bundle hash cannot be recomputed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_catalog(root):
    """The rows of `<root>/profiles/catalog.json`, oldest first; a tree before founding has none. Every row names
    its five fields (GP-22): a row that does not is an error, never a row the run leaves out."""
    path = os.path.join(root, "profiles", "catalog.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as fh:
            rows = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as err:
        raise VectorError("profiles/catalog.json unreadable (%s)" % err)
    if not isinstance(rows, list):
        raise VectorError("profiles/catalog.json is not a list")
    for index, row in enumerate(rows, 1):
        named = row.get("label") if isinstance(row, dict) else None
        who = "catalog entry %s" % (named if isinstance(named, str) and named else "#%d" % index)
        if not isinstance(row, dict):
            raise VectorError("%s is not an object" % who)
        for field in _manifest().CATALOG_ROW_FIELDS:
            if not isinstance(row.get(field), str) or not row[field]:
                raise VectorError("%s has no %s" % (who, field))
    return rows


def current_production(root):
    """The production profile of the unreleased current core, as `repin.py` wrote it to `conformance/pins.json`."""
    try:
        with open(os.path.join(root, "conformance", "pins.json"), "rb") as fh:
            value = json.loads(fh.read().decode("utf-8"))["production_profile"]
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise VectorError("conformance/pins.json has no production_profile (%s)" % err)
    if not isinstance(value, str):
        raise VectorError("conformance/pins.json: production_profile is not a string")
    return value


def _tree_blobs(root, commit, paths, recursive):
    """{path: blob id} of the blobs under `paths` at `commit`."""
    args = ["ls-tree", "-z"] + (["-r"] if recursive else []) + [commit, "--"] + list(paths)
    found = {}
    for entry in _git(root, *args).split(b"\0"):
        if entry:
            meta, path = entry.split(b"\t", 1)
            mode, kind, blob = meta.decode("ascii").split()
            if kind == "blob":
                found[path.decode("utf-8")] = blob
    return found


def _blobs(root, ids):
    """{blob id: bytes}; an object that is not there is an error."""
    ids = sorted(set(ids))
    if not ids:
        return {}
    data = _git(root, "cat-file", "--batch", stdin=("\n".join(ids) + "\n").encode("ascii"))
    out, pos = {}, 0
    for blob in ids:
        end = data.index(b"\n", pos)
        header = data[pos:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise GitFailure("object %s is not in this repository" % blob)
        size = int(header[2])
        out[blob] = data[end + 1:end + 1 + size]
        pos = end + 1 + size + 1
    return out


def read_edition(root, row, dest):
    """Read the edition's tag, check its bundle hash, write the tag's vectors under `dest`; return how many files.

    The tag is resolved by name under `refs/tags/` only, so a branch of the same name cannot stand in. The files of
    the bundle are the ones its own `spec/MANIFEST.json` lists, never the rule of the current tree (CF-15): their
    hash is recomputed from the tag's tree and must equal `row["bundle"]`, so a tag that was moved cannot pass. The
    listed `.json` files under the vectors directory are the vectors."""
    manifest = _manifest()
    ref = "refs/tags/" + row["tag"]
    try:
        _git(root, "check-ref-format", ref)
        commit = _git(root, "rev-parse", "--verify", "--quiet", ref + "^{commit}").decode("ascii").strip()
    except GitFailure as err:
        raise VectorError("catalog entry %s: tag %s cannot be resolved (%s)" % (row["label"], row["tag"], err))
    try:
        listed = _tree_blobs(root, commit, [], True)
        if manifest.BUNDLE_FILE not in listed:
            raise GitFailure("the tag has no %s" % manifest.BUNDLE_FILE)
        try:
            recorded = json.loads(_blobs(root, [listed[manifest.BUNDLE_FILE]])[listed[manifest.BUNDLE_FILE]])["files"]
            paths = sorted(recorded)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise GitFailure("%s of the tag is unreadable" % manifest.BUNDLE_FILE)
        missing = [path for path in paths if path not in listed]
        if missing:
            raise GitFailure("files missing from the tag: %s" % ", ".join(missing))
        data = _blobs(root, [listed[p] for p in paths])
    except GitFailure as err:
        raise VectorError("catalog entry %s (tag %s): %s" % (row["label"], row["tag"], err))
    computed = manifest.bundle_hash_of({p: manifest.hashstr(data[listed[p]]) for p in paths})
    if computed != row["bundle"]:
        raise VectorError("catalog entry %s (tag %s): the bundle hash of the tag is %s, the catalog records %s"
                          % (row["label"], row["tag"], computed, row["bundle"]))
    written = 0
    for path in paths:
        if not path.startswith(manifest.VECTORS_DIR + "/") or not path.endswith(".json"):
            continue
        target = os.path.join(dest, *path[len(manifest.VECTORS_DIR) + 1:].split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data[listed[path]])
        written += 1
    return written


def _run_serve(vectors, impls, out):
    """Each implementation answers every vector through ONE `serve` process, and the line must be the bytes the same
    implementation prints for that vector in a one-shot call (exit 0). The anchor is not read here: the normal pass
    holds the one-shot answer to it, this pass holds serve to the one-shot answer. Returns the names of the vectors
    some implementation answered differently. A process that ends early, or does not end at the end of the stream
    with exit 0, ends the run (VectorError), with its stderr."""
    servers, diverging = [ServeProcess(i) for i in impls], []
    try:
        for vector in vectors:
            if vector.get("exit", 0) != 0:
                raise VectorError("%s: expects exit %d, which serve has no way to give" % (vector["name"], vector["exit"]))
            body = build_stdin(vector)
            evidence, same = [], True
            for n, (impl, server) in enumerate(zip(impls, servers), 1):
                try:
                    one_shot = subprocess.run(impl + [vector["command"]], input=body, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
                    line = server.ask(vector["command"], body)
                except OSError as err:
                    raise VectorError("%s: %s" % (vector["name"], err))
                if not line.endswith(b"\n"):
                    raise VectorError("%s: the serve process of impl %d ended without an answer (exit %s): %s"
                                      % (vector["name"], n, server.proc.poll(), server.evidence().strip()))
                if line != one_shot.stdout:
                    same = False
                    evidence.append("  impl %d one-shot: exit %d, %s\n  impl %d serve: %s\n"
                                    % (n, one_shot.returncode, _excerpt(one_shot.stdout).rstrip("\n"), n,
                                       _excerpt(line).rstrip("\n")))
            out.write("serve %s %s\n" % ("PASS" if same else "DIVERGE", vector["name"]))
            if not same:
                out.write("".join(evidence))
                diverging.append(vector["name"])
        for n, server in enumerate(servers, 1):
            code = server.finish()
            if code != 0:
                raise VectorError("the serve process of impl %d exited %d at the end of the stream: %s"
                                  % (n, code, server.evidence().strip()))
    except BaseException:
        for server in servers:
            server.abort()
        raise
    return diverging


def _select(vectors, args):
    if args.group:
        vectors = [v for v in vectors if v["name"].startswith(args.group)]
    if args.role:
        vectors = [v for v in vectors if role_selects(args.role, v["command"])]
    if args.commands:
        wanted = set(args.commands.split(","))
        vectors = [v for v in vectors if v["command"] in wanted]
    return vectors


def _run_vectors(vectors, impls, out, prefix=""):
    """Run each vector, write one line each (and the evidence under a vector that did not pass), return the names of
    the vectors that did not pass; VectorError ends the run (exit 2)."""
    failed = []
    for vector in vectors:
        try:
            results = [run_impl(i, vector) for i in impls]
        except (VectorError, OSError) as err:
            raise VectorError("%s: %s" % (vector["name"], err))
        status = evaluate(vector, results)
        out.write("%s%s %s\n" % (prefix, status, vector["name"]))
        if status != "PASS":
            out.write(describe_failure(vector, results))
            failed.append(vector["name"])
    return failed


def _write_not_passing(out, failed, prefix=""):
    """One line naming every vector that did not pass, right before the summary line of its block, so that a
    summary that was cut away from the vector lines still says what failed."""
    if failed:
        out.write("%snot passing: %s\n" % (prefix, ", ".join(failed)))


def run_editions(root, args, impls, out):
    """CF-15: the vectors of every catalog entry that is not the current core, each from its tag. Returns the
    labels of the editions with a vector that did not pass. The loop is explicit: with no such entry it runs zero
    sets and says so."""
    rows = read_catalog(root)
    older = [row for row in rows if row["production"] != current_production(root)] if rows else []
    failed_editions = []
    for row in older:
        with tempfile.TemporaryDirectory() as dest:
            read_edition(root, row, dest)
            held = [v for v in load_vectors(dest) if v["name"].split("/", 1)[0] not in BUILD_DESCRIBING_GROUPS]
            vectors = _select(held, args)
            if not held:
                raise VectorError("catalog entry %s (tag %s): the tag holds no vector" % (row["label"], row["tag"]))
            failed = _run_vectors(vectors, impls, out, "[%s] " % row["label"])
        _write_not_passing(out, failed, "[%s] " % row["label"])
        if vectors:
            out.write("edition %s (%s): bundle hash matches, %d vectors, %d not passing\n"
                      % (row["label"], row["tag"], len(vectors), len(failed)))
        else:
            out.write("edition %s (%s): bundle hash matches, 0 of %d selected\n" % (row["label"], row["tag"], len(held)))
        if failed:
            out.write("FAILED %s\n" % row["label"])
            failed_editions.append(row["label"])
    out.write("%d tag sets run\n" % len(older))
    return failed_editions


def main(argv=None, out=None):
    out = out or sys.stdout
    parser = argparse.ArgumentParser(prog="run.py")
    parser.add_argument("--impl", action="append", default=[])
    parser.add_argument("--vectors", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors"))
    parser.add_argument("--group", default=None)
    parser.add_argument("--commands", default=None)
    parser.add_argument("--role", choices=("checker", "signer"), default=None,
                        help="CF-04 role: signer = render,emit; checker = every command but emit")
    parser.add_argument("--serve", action="store_true",
                        help="also run the whole selected set through one `serve` process of each implementation "
                             "and compare every line with its one-shot line (checker role only)")
    parser.add_argument("--tags", action="store_true",
                        help="CF-15: also run the vectors of every catalog entry that is not the current core, from its tag")
    parser.add_argument("--root", default=REPO, help="the repository whose catalog and tags --tags reads")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if not args.impl:
            raise VectorError("at least one --impl is required")
        if args.serve and args.role != "checker":
            raise VectorError("--serve needs --role checker: only the checker serves")
        impls = [parse_impl(i) for i in args.impl]
        vectors = _select(load_vectors(args.vectors), args)
    except VectorError as err:
        out.write("ERROR %s\n" % err)
        return 2
    if not vectors:
        out.write("ERROR no vectors selected\n")
        return 2
    try:
        failed = _run_vectors(vectors, impls, out)
        _write_not_passing(out, failed)
        out.write("%d vectors, %d not passing\n" % (len(vectors), len(failed)))
        diverging = _run_serve(vectors, impls, out) if args.serve else []
        if args.serve:
            if diverging:
                out.write("serve diverging: %s\n" % ", ".join(diverging))
            out.write("%d vectors through serve, %d diverging\n" % (len(vectors), len(diverging)))
        failed_editions = run_editions(args.root, args, impls, out) if args.tags else []
    except VectorError as err:
        out.write("ERROR %s\n" % err)
        return 2
    return 1 if failed or failed_editions or diverging else 0


if __name__ == "__main__":
    sys.exit(main())
