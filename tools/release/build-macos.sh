#!/bin/sh
# Build the macOS release set of this checkout into DIR and print the lines to publish (SG-15, CF-05, T15.8).
#
#   sh tools/release/build-macos.sh DIR
#
# DIR must not exist or be empty. It ends up holding exactly the installer's closed list for macos-arm64
# (tools/artifact_hashes.py owns the names; this script keeps no copy of them):
#
#   the Swift executables     swift build -c release --product NAME -Xswiftc -gnone  (signer/apple)
#   the vitni verifier        tools/release/build-vitni.sh darwin arm64, the one vitni command, at the pinned commit
#   the zipapp and launcher   checker/python/packaging/build_zipapp.py, launcher.py macos-arm64
#   the interpreter archive   downloaded from the pin in checker/python/packaging/interpreter.json, then
#                             tools/pack_licenses.py makes the licence archive from the notices
#
# then `tools/artifact_hashes.py --release DIR --platform macos-arm64` checks DIR and its lines go to stdout,
# the only thing on stdout. Everything else goes to stderr, first the commit this was built from.
#
# The refusals, the commit everything is built from and the steps shared with the Linux server build are in
# tools/release/release-lib.sh. This script adds one refusal, a machine that is not an Apple silicon Mac (status 2,
# nothing built), and the Swift build.
#
# Needs: git, swift, go, uv, curl, tar with zstd.
set -eu

. "$(dirname "$0")/release-lib.sh"

[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || {
    rl_tool=build-macos
    rl_refuse "this builds the macos-arm64 set and needs an Apple silicon Mac"
}

build_other() { # NAME: a Swift product of signer/apple
    (cd "$rl_src/signer/apple" && swift build -c release --product "$1" --scratch-path "$rl_work/swift" -Xswiftc -gnone) >&2
    cp "$rl_work/swift/release/$1" "$rl_dir/$1"
    chmod 755 "$rl_dir/$1"
}

rl_start build-macos macos-arm64 darwin arm64 "$@"
rl_build_all
rl_finish
