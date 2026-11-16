#!/bin/sh
# Tests of the release vulnerability gate (tools/release/vuln-gate.sh). Trivy is a stand-in first on PATH: it logs what
# it was asked, lists the tree it was pointed at, and answers `--version` and a scan as the control files say. The
# installer is the real one (tools/install/install-lib.sh) with the stand-in privileged runner of its own tests, so
# the tree the stand-in sees is the tree an install makes. Run:  sh tools/release/test-vuln-gate.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-vuln-gate-test.XXXXXX") || exit 2
tmp=$(cd "$tmp" && pwd -P)
trap 'chmod -R u+rwx "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT HUP INT TERM

failures=0
checks=0
check() { # name, then a command that must succeed
    name=$1
    shift
    checks=$((checks + 1))
    if "$@"; then
        :
    else
        failures=$((failures + 1))
        printf 'FAIL: %s\n' "$name"
    fi
}
has_fixed() { grep -qF -- "$1" "$2" 2>/dev/null; }
lacks_fixed() { ! grep -qF -- "$1" "$2" 2>/dev/null; }
is_empty() { [ ! -s "$1" ]; }
is_status() { [ "$status" = "$1" ]; }
py() { uv run --no-project python -I "$@"; }
sha() {
    if [ -x /usr/bin/sha256sum ]; then /usr/bin/sha256sum "$1" | cut -d' ' -f1; else /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; fi
}

gate=$here/vuln-gate.sh
log=$tmp/trivy.log
ctl=$tmp/ctl
stubs=$tmp/stubs
mkdir -p "$ctl" "$stubs"

# --- the stand-in trivy ---------------------------------------------------------------------------------------
{
    printf "#!/bin/sh\nLOG='%s'\nCTL='%s'\n" "$log" "$ctl"
    cat <<'SH'
if [ "${1:-}" = --version ]; then
    printf 'Version: 0.70.0\n'
    if [ ! -f "$CTL/nodate" ]; then
        printf 'Vulnerability DB:\n  Version: 2\n  UpdatedAt: 2026-11-16 07:10:39.763774809 +0000 UTC\n  NextUpdate: 2026-11-17 07:10:39.763774549 +0000 UTC\n'
    fi
    exit 0
fi
printf 'trivy %s\n' "$*" >>"$LOG"
for last in "$@"; do :; done
printf 'target %s\n' "$last" >>"$LOG"
(cd "$last" && find . | sort | sed 's|^\./|tree |') >>"$LOG"
if [ -f "$CTL/nodb" ]; then
    echo 'FATAL failed to download vulnerability DB' >&2
    exit 1
fi
if [ -f "$CTL/findings" ]; then
    echo 'Total: 1 (HIGH: 1, CRITICAL: 0)' >&2
    exit 1
fi
exit 0
SH
} >"$stubs/trivy"
chmod +x "$stubs/trivy"

# --- the fixtures: the closed list of each platform, with a real interpreter archive and licences archive ------
mk_interpreter() { # TRIPLE
    b=$tmp/fx/build-$1
    mkdir -p "$b/python/bin" "$b/python/lib/python3.13/site-packages/pip/_vendor" "$b/python/lib/python3.13/site-packages/pip-26.3.dist-info" "$b/python/lib/python3.13/ensurepip/_bundled"
    printf 'interpreter' >"$b/python/bin/python3.13"
    ln -s python3.13 "$b/python/bin/python3"
    for f in pip pip3 pip3.13; do printf 'tool' >"$b/python/bin/$f"; done
    printf 'sbom' >"$b/python/lib/python3.13/site-packages/pip/_vendor/bom.cdx.json"
    printf 'meta' >"$b/python/lib/python3.13/site-packages/pip-26.3.dist-info/METADATA"
    printf 'wheel' >"$b/python/lib/python3.13/ensurepip/_bundled/pip-26.3-py3-none-any.whl"
    mkdir -p "$tmp/fx/notes/python/licenses"
    printf 'licence text' >"$tmp/fx/notes/python/licenses/LICENSE.txt"
    (cd "$b" && tar -czf "$tmp/fx/cpython-3.13.18+20261110-$1-install_only.tar.gz" python)
    # shellcheck disable=SC2016
    py -c 'import sys; sys.path.insert(0, sys.argv[1]); import pack_licenses; pack_licenses.pack_tree(sys.argv[2], sys.argv[3])' \
        "$root/tools" "$tmp/fx/notes" "$tmp/fx/handsal-python-licenses-3.13.18+20261110-$1.tar.gz" || { echo "cannot build the licences fixture (needs uv)"; exit 2; }
}
mk_interpreter x86_64-unknown-linux-gnu
mk_interpreter aarch64-apple-darwin

# make_world NAME PLATFORM TRIPLE NAMES...: DIR of artifacts and the published lines for them
make_world() {
    w=$tmp/$1 triple=$3
    shift 3
    rm -rf "$w"
    mkdir -p "$w/artifacts"
    : >"$w/published"
    for n in "$@"; do
        printf 'fixture %s' "$n" >"$w/artifacts/$n"
    done
    cp "$tmp/fx/cpython-3.13.18+20261110-$triple-install_only.tar.gz" "$tmp/fx/handsal-python-licenses-3.13.18+20261110-$triple.tar.gz" "$w/artifacts/"
    for f in "$w"/artifacts/*; do
        printf '%s  %s\n' "$(sha "$f")" "$(basename "$f")" >>"$w/published"
    done
}
make_world linux x "x86_64-unknown-linux-gnu" vitni-verify handsal-check-server handsal-check-server.pyz
make_world mac x "aarch64-apple-darwin" vitni-verify handsal-pin handsal-sign handsal-ceremony handsal-link handsal-check handsal-check.pyz

run() { # NAME PLATFORM [PATH]: the gate against the world NAME
    : >"$log"
    (cd "$tmp" && PATH="${3:-$stubs:$PATH}" sh "$gate" "$2" "$tmp/$1/artifacts" "$tmp/$1/published") >"$tmp/out" 2>"$tmp/err"
    status=$?
}

# --- a run that passes ------------------------------------------------------------------------------------------
check "the gate script exists" test -f "$gate"
run linux linux-x86_64
check "a clean scan passes (err: $(tail -n 3 "$tmp/err" 2>/dev/null))" is_status 0
check "nothing goes to stdout (stdout carries the lines to publish)" is_empty "$tmp/out"
check "trivy scans a root file system" has_fixed "trivy rootfs " "$log"
check "only CRITICAL and HIGH are asked for" has_fixed "--severity CRITICAL,HIGH" "$log"
check "a finding is a failing exit code" has_fixed "--exit-code 1" "$log"
check "the database is not left stale by a flag" lacks_fixed "--skip-db-update" "$log"
check "unfixed findings are not hidden" lacks_fixed "--ignore-unfixed" "$log"
check "the version of trivy is recorded" has_fixed "trivy 0.70.0" "$tmp/err"
check "the date of the database is recorded" has_fixed "2026-11-16" "$tmp/err"
check "the installed vitni is scanned" has_fixed "tree python/bin/python3.13" "$log"
check "the installed vitni binary is in the scanned tree" has_fixed "tree bin/vitni-verify" "$log"
check "the installed licences are in the scanned tree" has_fixed "tree python/licenses/LICENSE.txt" "$log"
check "pip is not in the scanned tree" lacks_fixed "site-packages/pip" "$log"
check "the pip command is not in the scanned tree" lacks_fixed "bin/pip" "$log"
check "the bundled pip wheel is not in the scanned tree" lacks_fixed "ensurepip/_bundled" "$log"
check "the scanned tree is removed afterwards" test ! -e "$(sed -n 's/^target //p' "$log" | head -n 1)"
check "the Linux set has no pin helper" lacks_fixed "tree bin/handsal-pin" "$log"

run mac macos-arm64
check "the macOS set passes too (err: $(tail -n 3 "$tmp/err" 2>/dev/null))" is_status 0
check "the macOS set has its pin helper in the scanned tree" has_fixed "tree bin/handsal-pin" "$log"
check "the macOS interpreter has no pip either" lacks_fixed "site-packages/pip" "$log"

# --- every way it must fail loudly -------------------------------------------------------------------------------
: >"$ctl/findings"
run linux linux-x86_64
rm -f "$ctl/findings"
check "a CRITICAL or HIGH finding fails the gate with status 1" is_status 1
check "the failure says it is the gate" has_fixed "vuln-gate" "$tmp/err"
check "the failure says the release is not to be published" has_fixed "not to be published" "$tmp/err"
check "a failing gate prints nothing to stdout" is_empty "$tmp/out"

: >"$ctl/nodb"
run linux linux-x86_64
rm -f "$ctl/nodb"
check "a database that cannot be fetched fails the gate with status 1" is_status 1
check "the failure of trivy itself is in the output" has_fixed "failed to download vulnerability DB" "$tmp/err"

: >"$ctl/nodate"
run linux linux-x86_64
rm -f "$ctl/nodate"
check "a trivy that cannot say its database date fails the gate" is_status 1
check "it says the database date is unknown" has_fixed "database" "$tmp/err"

run linux linux-x86_64 /usr/bin:/bin
check "no trivy on PATH fails the gate with status 1" is_status 1
check "it says trivy is missing" has_fixed "trivy is not installed" "$tmp/err"

printf 'tampered' >"$tmp/linux/artifacts/vitni-verify"
run linux linux-x86_64
check "an artifact that is not the published one fails the gate" is_status 1
check "trivy is not run on a tree that was not installed" lacks_fixed "trivy rootfs" "$log"
make_world linux x "x86_64-unknown-linux-gnu" vitni-verify handsal-check-server handsal-check-server.pyz

run linux no-such-platform
check "an unknown platform is refused with status 2" is_status 2
check "a refused platform runs no scan" lacks_fixed "trivy rootfs" "$log"
(cd "$tmp" && PATH="$stubs:$PATH" sh "$gate" linux-x86_64 >/dev/null 2>&1)
check "a missing argument is refused with status 2" test $? -eq 2

printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" = 0 ]
