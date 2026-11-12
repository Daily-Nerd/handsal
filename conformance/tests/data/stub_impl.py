"""Stub implementation for the harness tests.

Usage: stub_impl.py <mode> <command>. Reads stdin, writes one line that
reports the command and how many stdin bytes it saw. Mode "diverge" lies
about the byte count; mode "crash" exits nonzero.
"""

import sys

mode, command = sys.argv[1], sys.argv[2]
data = sys.stdin.buffer.read()
count = len(data) + (1 if mode == "diverge" else 0)
if mode == "crash":
    sys.exit(3)
sys.stdout.write('{"bytes":%d,"command":"%s"}\n' % (count, command))
