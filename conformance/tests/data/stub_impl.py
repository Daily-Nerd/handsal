"""Stub implementation for the harness tests.

Usage: stub_impl.py <mode> <command>. Reads stdin, writes one line that
reports the command and how many stdin bytes it saw. Mode "diverge" lies
about the byte count; mode "crash" exits nonzero; mode "noisy" writes a
long note to stderr and exits nonzero; mode "chatty" writes the same note to
stderr but answers correctly.

With the command `serve` it answers requests, each a header line
`<command> <length>` and `<length>` bytes, with the line it gives that command
and that many bytes in a one-shot call. Mode "servediverge" lies about the
byte count only when serving, "servecrash" ends after its first answer with a
note on stderr, and "servebadexit" answers everything and exits 4 at the end of
the stream.
"""

import sys

mode, command = sys.argv[1], sys.argv[2]


def answer(name, size, lie):
    return '{"bytes":%d,"command":"%s"}\n' % (size + (1 if lie else 0), name)


if command == "serve":
    stdin, stdout = sys.stdin.buffer, sys.stdout
    served = 0
    while True:
        header = stdin.readline()
        if not header:
            sys.exit(4 if mode == "servebadexit" else 0)
        name, length = header.decode().split()
        body = stdin.read(int(length))
        stdout.write(answer(name, len(body), mode == "servediverge"))
        stdout.flush()
        served += 1
        if mode == "servecrash":
            sys.stderr.write("stub-serve-stderr\n")
            sys.exit(3)

data = sys.stdin.buffer.read()
if mode in ("noisy", "chatty"):
    sys.stderr.write("stub-stderr-start\n" + "x" * 5000 + "stub-stderr-end\n")
if mode in ("crash", "noisy"):
    sys.exit(3)
sys.stdout.write(answer(command, len(data), mode == "diverge"))
