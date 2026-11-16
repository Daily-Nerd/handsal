#!/bin/sh
# The release gate: no CRITICAL or HIGH vulnerability in what a person installs from the release set.
#
#   sh tools/release/vuln-gate.sh PLATFORM DIR PUBLISHED
#
# PLATFORM is macos-arm64 or linux-x86_64. DIR holds the release set of that platform and PUBLISHED the
# `<sha256>  <name>` lines for it (what tools/artifact_hashes.py --release prints). The set is installed by the real
# installer (tools/install/install-lib.sh) into a temporary directory, as the person running it, and Trivy scans that
# tree, so the thing scanned is the thing a consumer scans: the installed vitni binary with the Go standard library of
# its toolchain, and the interpreter tree as the installer leaves it.
#
# Everything goes to stderr, because the release scripts keep stdout for the lines to publish. Exit 0: the scan is
# clean. Exit 1: there is a finding, or the gate could not run (Trivy missing, its database not fetched or not dated,
# an artifact that is not the published one). Exit 2: wrong arguments. Nothing is skipped quietly: Trivy's database is
# data from the network, and a gate that passes without it would pass every release.
#
# Needs: trivy, and the tools of the installer.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=

say() { printf 'vuln-gate: %s\n' "$*" >&2; }
refuse() {
    say "refused: $*"
    exit 2
}
stop() {
    say "$*"
    say "the release is not to be published"
    exit 1
}
cleanup() { [ -z "$work" ] || rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 130' INT HUP TERM

[ $# -eq 3 ] || refuse "usage: vuln-gate.sh PLATFORM DIR PUBLISHED"
platform=$1 dir=$2 published=$3
case $platform in
    macos-arm64) triple=aarch64-apple-darwin ;;
    linux-x86_64) triple=x86_64-unknown-linux-gnu ;;
    *) refuse "no gate for platform $platform (macos-arm64 or linux-x86_64)" ;;
esac
[ -d "$dir" ] && [ -f "$published" ] || refuse "$dir is not a directory or $published is not a file"

command -v trivy >/dev/null 2>&1 || stop "trivy is not installed: the scan cannot run, and a release without it is not checked"
trivy_version=$(trivy --version | sed -n 's/^Version: *//p' | head -n 1)
[ -n "$trivy_version" ] || stop "trivy does not say its version"

work=$(mktemp -d "${TMPDIR:-/tmp}/handsal-vuln-gate.XXXXXX")

# The installer as a person runs it on this platform, minus what needs root: no owner, and a copy of the staged tree
# that stays in the temporary directory. The quarantine mark is a macOS download matter and changes no byte scanned.
# shellcheck source=../install/install-lib.sh
. "$here/../install/install-lib.sh"
case $platform in
    linux-x86_64) profile_linux_server ;;
esac
TRIPLE=$triple
XATTR_TOOL=
if [ ! -x "$HASH_TOOL" ]; then
    if [ -x /usr/bin/sha256sum ]; then HASH_TOOL=/usr/bin/sha256sum HASH_ARGS=; else HASH_TOOL=/usr/bin/shasum HASH_ARGS='-a 256'; fi
fi
DEST_ROOT=$work/handsal
PRIV=/usr/bin/env
OWNER=
say "installing the $platform set from $dir"
install_run "$dir" "$published" >&2 || stop "the set does not install (an artifact is not the published one, or the installer failed)"

say "scanning $DEST_ROOT with trivy $trivy_version for CRITICAL and HIGH"
scan=0
trivy rootfs --scanners vuln --severity CRITICAL,HIGH --exit-code 1 --no-progress "$DEST_ROOT" >&2 || scan=$?
[ "$scan" -eq 0 ] || stop "trivy exited with status $scan: CRITICAL or HIGH findings above, or trivy could not run (the database is data fetched over the network)"

# The date comes after the scan, which is what fetches or refreshes the database; a scan that passed on a database
# nobody can date is not a result.
db_date=$(trivy --version | sed -n 's/^ *UpdatedAt: *//p' | head -n 1)
[ -n "$db_date" ] || stop "trivy does not report a vulnerability database date: the scan has no database behind it"
say "clean: trivy $trivy_version, vulnerability database updated $db_date, no CRITICAL or HIGH finding in the $platform set"
