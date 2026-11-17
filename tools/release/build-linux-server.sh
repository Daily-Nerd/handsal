#!/bin/sh
# Build the Linux server release set (amd64) of this checkout into DIR, make the assets a release publishes, and
# print their SHA256SUMS (SG-15, CF-10, RS4).
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
# then `tools/artifact_hashes.py --release DIR --platform linux-x86_64` checks DIR, and the vulnerability gate scans it.
# Only then is DIR.publish made, the exact set of assets of the release, all from the archived commit:
#
#   install-linux-server.sh, install-lib.sh   the installer
#   handsal-<tag>-linux-amd64.tar             the five files of DIR, byte-reproducible (tools/release/publish_linux.py)
#   SHA256SUMS                                the five lines, the two scripts, the tar: also the PUBLISHED_HASHES file
#                                             the installer reads, so a consumer hashes nothing itself
#
# <tag> is `git describe --tags --always` of the commit: the tag itself when the release commit is tagged. The content
# of SHA256SUMS is the only thing on stdout. Everything else goes to stderr, first the commit this was built from.
#
# DIR.publish is beside DIR, not inside it, because DIR is the set the gate installs and scans and the closed list
# check accepts nothing else in it. A run refuses (status 2, nothing built) if DIR.publish exists and is not empty.
#
# Nothing in the set runs on the build machine, so any machine builds it (vitni is a cgo-free cross build, the zipapp
# is Python source). The refusals, the one commit everything is built from and the steps shared with the macOS
# build are in tools/release/release-lib.sh.
#
# Needs: git, go, uv, curl, tar with zstd (the tar of the release is written by Python, not by tar).
set -eu

. "$(dirname "$0")/release-lib.sh"

build_other() { # NAME: every other name of the Linux list is a bug in the list, not a thing to guess at
    rl_refuse "no builder for $1 in the linux-x86_64 list"
}

rl_publish() {
    rl_label=$(git -C "$rl_root" describe --tags --always "$rl_head")
    rl_py "$rl_src/tools/release/publish_linux.py" "$rl_src" "$rl_dir" "$rl_work/lines" "$rl_pub" "handsal-$rl_label-linux-amd64.tar" >&2 || exit 1
    cp "$rl_pub/SHA256SUMS" "$rl_published"
    rl_say "published set in $rl_pub"
}

rl_start build-linux-server linux-x86_64 linux amd64 "$@"
rl_build_all
rl_finish
