#!/bin/sh
# Build the Linux server release set (amd64) of this checkout into DIR and print the lines to publish
# (SG-15, CF-10, RS4, T15.10).
#
#   sh tools/release/build-linux-server.sh DIR
#
# DIR must not exist or be empty. It ends up holding exactly the installer's closed list for linux-x86_64
# (tools/artifact_hashes.py owns the names; this script keeps no copy of them):
#
#   the vitni verifier        tools/release/build-vitni.sh linux amd64, the one vitni command, at the pinned commit
#   the server zipapp         checker/python/packaging/build_zipapp.py --entry handsal_check.server:main
#   the server launcher       checker/python/packaging/launcher.py linux-x86_64
#   the interpreter archive   downloaded from the pin in checker/python/packaging/interpreter.json, then
#                             tools/pack_licenses.py makes the licence archive from the notices
#
# then `tools/artifact_hashes.py --release DIR --platform linux-x86_64` checks DIR and its lines go to stdout,
# the only thing on stdout. Everything else goes to stderr, first the commit this was built from.
#
# Nothing in the set runs on the build machine, so any machine builds it (vitni is a cgo-free cross build, the zipapp
# is Python source). The refusals, the one commit everything is built from and the steps shared with the macOS
# build are in tools/release/release-lib.sh.
#
# Needs: git, go, uv, curl, tar with zstd.
set -eu

. "$(dirname "$0")/release-lib.sh"

build_other() { # NAME: every other name of the Linux list is a bug in the list, not a thing to guess at
    rl_refuse "no builder for $1 in the linux-x86_64 list"
}

rl_start build-linux-server linux-x86_64 linux amd64 "$@"
rl_build_all
rl_finish
