#!/bin/sh
# Tests of the Linux server installer (SG-15, SG-14, RS4, CF-10, T13.5). No root: the privileged runner
# is a stand-in that logs the command and runs it as the current user, and the destination is a
# temporary directory. The artifact list, the tools and the interpreter triple are the ones of
# `profile_linux_server` in install-lib.sh, the code the installed script runs; the only values this test
# changes are tools a Mac does not have at the Linux path (sha256sum). Run:
#
#   sh tools/install/test-install-linux.sh
#
# The macOS installer has its own test, test-install.sh, which must stay green with the same library.
set -u

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-install-linux-test.XXXXXX") || exit 2
# a staging directory the model closed must be made readable again before it can be removed
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
has_no_line() { ! grep -q "$1" "$2" 2>/dev/null; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

triple=x86_64-unknown-linux-gnu
interpreter="cpython-3.13.18+20261110-$triple-install_only.tar.gz"
licenses="handsal-python-licenses-3.13.18+20261110-$triple.tar.gz"
stock_path=/usr/bin:/bin
artifact_list="vitni-verify handsal-check-server handsal-check-server.pyz $interpreter $licenses"

if [ -x /usr/bin/sha256sum ]; then
    sha() { /usr/bin/sha256sum "$1" | cut -d' ' -f1; }
else
    sha() { /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; }
fi

# A fake privileged runner: logs its arguments, then runs them as this user. PRIV_FAIL_ON is a case
# pattern for the command line; a command that matches fails without running. Like the macOS test it
# models the boundary: staging is closed (mode 000) to code outside the runner.
cat > "$tmp/fakepriv" <<'PRIV'
#!/bin/sh
printf '%s\n' "$*" >> "$PRIV_LOG"
open_staging() { for d in "$PRIV_GUARD_DIR"/*.staging.*; do [ -d "$d" ] && chmod 0700 "$d"; done; }
close_staging() { for d in "$PRIV_GUARD_DIR"/*.staging.*; do [ -d "$d" ] && chmod 0000 "$d"; done; }
open_staging
if [ -n "${PRIV_FAIL_ON:-}" ]; then
    # shellcheck disable=SC2254
    case "$*" in $PRIV_FAIL_ON) close_staging; exit 1 ;; esac
fi
"$@"
rc=$?
close_staging
exit "$rc"
PRIV
chmod +x "$tmp/fakepriv"

# The interpreter archive with the system tar; the licences archive by tools/pack_licenses.py, the code of the
# real packaging step.
mkdir -p "$tmp/fx/build/python/bin" "$tmp/fx/build/python/lib" "$tmp/fx/notes/python/licenses"
printf 'interpreter' > "$tmp/fx/build/python/bin/python3.13"
ln -s python3.13 "$tmp/fx/build/python/bin/python3"
printf 'stdlib' > "$tmp/fx/build/python/lib/os.py"
# pip ships in the upstream archive with a vendored setuptools 70.3.0 that scanners report (CVE-2025-47273). The
# server never runs pip, so the installer leaves it out; a package next to it stays.
sp="$tmp/fx/build/python/lib/python3.13/site-packages"
mkdir -p "$sp/pip/_vendor" "$sp/pip-26.3.dist-info" "$sp/keepme" "$tmp/fx/build/python/lib/python3.13/ensurepip/_bundled"
printf 'pip' > "$sp/pip/__init__.py"
printf 'sbom' > "$sp/pip/_vendor/bom.cdx.json"
printf 'meta' > "$sp/pip-26.3.dist-info/METADATA"
printf 'kept' > "$sp/keepme/__init__.py"
printf 'ensurepip' > "$tmp/fx/build/python/lib/python3.13/ensurepip/__init__.py"
printf 'wheel' > "$tmp/fx/build/python/lib/python3.13/ensurepip/_bundled/pip-26.3-py3-none-any.whl"
for f in pip pip3 pip3.13 pydoc3; do printf 'tool' > "$tmp/fx/build/python/bin/$f"; done
(cd "$tmp/fx/build" && tar -czf "$tmp/fx/$interpreter" python)
printf 'licence text' > "$tmp/fx/notes/python/licenses/LICENSE.txt"
# shellcheck disable=SC2016
uv run --no-project python -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import pack_licenses; pack_licenses.pack_tree(sys.argv[2], sys.argv[3])' \
    "$here/../" "$tmp/fx/notes" "$tmp/fx/$licenses" || { echo "cannot build the licences fixture with pack_licenses.py (needs uv)"; exit 2; }

publish_world() {
    w=$tmp/$1
    : > "$w/published"
    for f in vitni-verify handsal-check-server handsal-check-server.pyz "$interpreter" "$licenses"; do
        printf '%s  %s\n' "$(sha "$w/artifacts/$f")" "$f" >> "$w/published"
    done
}

make_world() {
    w=$tmp/$1
    rm -rf "$w"
    mkdir -p "$w/artifacts" "$w/dest"
    printf 'vitni' > "$w/artifacts/vitni-verify"
    printf '#!/bin/sh\n' > "$w/artifacts/handsal-check-server"
    printf 'zipapp' > "$w/artifacts/handsal-check-server.pyz"
    cp "$tmp/fx/$interpreter" "$tmp/fx/$licenses" "$w/artifacts/"
    publish_world "$1"
    : > "$w/priv.log"
}

# run_install NAME [SNIPPET]: the installer library with the Linux profile against the world's temporary
# destination. SNIPPET runs after the profile is applied.
run_install() {
    w=$tmp/$1
    # shellcheck disable=SC2030,SC2031
    (
        PRIV_LOG=$w/priv.log
        PRIV_GUARD_DIR=$w/dest
        export PRIV_LOG PRIV_GUARD_DIR
        DEST_ROOT=$w/dest/handsal
        PRIV=$tmp/fakepriv
        OWNER=
        PATH=${RUN_PATH:-$stock_path}
        export PATH
        # shellcheck source=install-lib.sh
        . "$here/install-lib.sh"
        profile_linux_server
        if [ ! -x /usr/bin/sha256sum ]; then HASH_TOOL=/usr/bin/shasum; HASH_ARGS='-a 256'; fi
        if [ -n "${2:-}" ]; then eval "$2"; fi
        install_run "$w/artifacts" "$w/published"
    ) > "$w/out" 2>&1
}

# ---- every artifact verifies: installed at the exact paths, with the right bytes ------------------
make_world ok
run_install ok
status=$?
check "an install of verified artifacts succeeds" test "$status" -eq 0
d=$tmp/ok/dest/handsal
check "vitni-verify is installed in bin" test "$(cat "$d/bin/vitni-verify" 2>/dev/null)" = vitni
check "the server launcher is installed in bin" test -f "$d/bin/handsal-check-server"
check "the server zipapp is installed in lib" test "$(cat "$d/lib/handsal-check-server.pyz" 2>/dev/null)" = zipapp
check "the interpreter is extracted under python" test "$(cat "$d/python/bin/python3.13" 2>/dev/null)" = interpreter
check "the licences land in python/licenses" test "$(cat "$d/python/licenses/LICENSE.txt" 2>/dev/null)" = "licence text"
check "pip is not installed (its vendored setuptools is scanned)" test ! -e "$d/python/lib/python3.13/site-packages/pip" -a ! -e "$d/python/lib/python3.13/site-packages/pip-26.3.dist-info"
check "no pip command is installed" test ! -e "$d/python/bin/pip" -a ! -e "$d/python/bin/pip3" -a ! -e "$d/python/bin/pip3.13"
check "the bundled pip wheel is not installed" test ! -e "$d/python/lib/python3.13/ensurepip/_bundled"
check "the rest of the interpreter stays" test -f "$d/python/lib/python3.13/ensurepip/__init__.py" -a -f "$d/python/lib/python3.13/site-packages/keepme/__init__.py" -a -f "$d/python/bin/pydoc3" -a -f "$d/python/lib/os.py"
check "no staging directory is left" test -z "$(find "$tmp/ok/dest" -name '*staging*' 2>/dev/null)"
check "the executables are 0755" test "$(mode_of "$d/bin/handsal-check-server")" = 755
check "the zipapp is 0644" test "$(mode_of "$d/lib/handsal-check-server.pyz")" = 644
check "no entry is writable by group or others" test -z "$(find "$d" ! -type l -perm -022 2>/dev/null)"
check "no macOS artifact is installed" test ! -e "$d/bin/handsal-pin" -a ! -e "$d/bin/handsal-check" -a ! -e "$d/lib/handsal-check.pyz"
check "no pin directory or lock is made (GP-21)" test ! -e "$d/orgs" -a ! -e "$d/pin.lock"
check "no quarantine removal runs on Linux (SH11 is macOS only)" has_no_line xattr "$tmp/ok/priv.log"

# ---- a hash that differs aborts before any privileged command (SG-15 S1) --------------------------
for victim in vitni-verify handsal-check-server handsal-check-server.pyz "$interpreter" "$licenses"; do
    make_world mismatch
    printf 'tampered' >> "$tmp/mismatch/artifacts/$victim"
    run_install mismatch
    status=$?
    check "a different $victim aborts (nonzero)" test "$status" -ne 0
    check "a different $victim runs no privileged command" test ! -s "$tmp/mismatch/priv.log"
    check "a different $victim copies nothing" test -z "$(ls -A "$tmp/mismatch/dest")"
    check "a different $victim is named" grep -q "$victim" "$tmp/mismatch/out"
done

# ---- not published, missing, a symlink, two values, two archives -------------------------------------
make_world unpublished
grep -v 'handsal-check-server.pyz' "$tmp/unpublished/published" > "$tmp/unpublished/p2" && mv "$tmp/unpublished/p2" "$tmp/unpublished/published"
run_install unpublished
check "an artifact with no published value aborts" test $? -ne 0
check "...before any privileged command" test ! -s "$tmp/unpublished/priv.log"

make_world absent
rm "$tmp/absent/artifacts/handsal-check-server"
run_install absent
check "a missing artifact aborts" test $? -ne 0
check "...before any privileged command (missing)" test ! -s "$tmp/absent/priv.log"

make_world linked
mv "$tmp/linked/artifacts/vitni-verify" "$tmp/linked/elsewhere"
ln -s "$tmp/linked/elsewhere" "$tmp/linked/artifacts/vitni-verify"
run_install linked
check "an artifact that is a symlink aborts" test $? -ne 0
check "...before any privileged command (symlink)" test ! -s "$tmp/linked/priv.log"

make_world twice
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" vitni-verify >> "$tmp/twice/published"
run_install twice
check "two published values for one artifact abort" test $? -ne 0
check "...before any privileged command (two values)" test ! -s "$tmp/twice/priv.log"

make_world twoarchives
cp "$tmp/twoarchives/artifacts/$interpreter" "$tmp/twoarchives/artifacts/cpython-9.9.9+1-$triple-install_only.tar.gz"
run_install twoarchives
check "two interpreter archives abort" test $? -ne 0
check "...before any privileged command (two archives)" test ! -s "$tmp/twoarchives/priv.log"

# the macOS interpreter archive is not this platform's: it is never picked up
make_world otherplatform
mv "$tmp/otherplatform/artifacts/$interpreter" "$tmp/otherplatform/artifacts/cpython-3.13.18+20261110-aarch64-apple-darwin-install_only.tar.gz"
run_install otherplatform
check "an interpreter of another platform is not accepted" test $? -ne 0
check "...before any privileged command (other platform)" test ! -s "$tmp/otherplatform/priv.log"

# ---- the artifacts of the macOS list are never copied, even if they sit among the artifacts --------
make_world foreign
for f in handsal-pin handsal-check handsal-check.pyz handsal-check-conformance; do
    printf 'foreign' > "$tmp/foreign/artifacts/$f"
    printf '%s  %s\n' "$(sha "$tmp/foreign/artifacts/$f")" "$f" >> "$tmp/foreign/published"
done
run_install foreign
check "the install with foreign artifacts around succeeds" test $? -eq 0
check "no foreign artifact is installed" test -z "$(find "$tmp/foreign/dest" \( -name 'handsal-pin' -o -name 'handsal-check' -o -name 'handsal-check.pyz' -o -name '*conformance*' \) 2>/dev/null)"
check "no privileged command names a foreign artifact" has_no_line 'handsal-pin\|handsal-check[. ]\|handsal-check$\|conformance' "$tmp/foreign/priv.log"

# ---- the bytes change after they were verified: the copy is hashed again -----------------------------
cat > "$tmp/swap" <<'SWAP'
#!/bin/sh
case "$*" in
    *install*handsal-check-server.pyz*) printf swapped > "$SWAP_TARGET" ;;
esac
SWAP
chmod +x "$tmp/swap"
# the stand-in that swaps is chained in front of the logging runner
cat > "$tmp/swapruns" <<'CHAIN'
#!/bin/sh
"$SWAP_BIN" "$@"
exec "$REAL_PRIV" "$@"
CHAIN
chmod +x "$tmp/swapruns"
make_world race
SWAP_TARGET=$tmp/race/artifacts/handsal-check-server.pyz SWAP_BIN=$tmp/swap REAL_PRIV=$tmp/fakepriv
export SWAP_TARGET SWAP_BIN REAL_PRIV
run_install race 'PRIV=$tmp/swapruns'
status=$?
unset SWAP_TARGET SWAP_BIN REAL_PRIV
check "bytes swapped after the check abort the install" test "$status" -ne 0
check "the swapped zipapp is not at its path" test ! -e "$tmp/race/dest/handsal/lib/handsal-check-server.pyz"
check "no staging directory is left after the abort" test -z "$(find "$tmp/race/dest" -name '*staging*' 2>/dev/null)"
check "the abort names the artifact that changed" grep -q 'handsal-check-server.pyz' "$tmp/race/out"

# ---- a failure at an unpack leaves the install location as it was -----------------------------------
for fault in '*install_only*' "*handsal-python-licenses*"; do
    make_world atomic
    PRIV_FAIL_ON="*-xf*$(printf '%s' "$fault" | tr -d '*')*"
    export PRIV_FAIL_ON
    run_install atomic
    status=$?
    unset PRIV_FAIL_ON
    check "a failed unpack ($fault) aborts (exit 3)" test "$status" -eq 3
    check "...leaves nothing at all (no handsal, no staging)" test -z "$(ls -A "$tmp/atomic/dest")"
    check "...and the unpack was reached" grep -q -e '-xf' "$tmp/atomic/priv.log"
done

# ---- the profile, not a default: the Linux values are the Linux ones ---------------------------------
lib=$here/install-lib.sh
profile=$(
    . "$lib"
    profile_linux_server
    printf '%s|%s|%s|%s|%s|%s' "$ARTIFACT_BINS" "$ARTIFACT_LIBS" "$TRIPLE" "$HASH_TOOL" "$HASH_ARGS" "$CHOWN_TOOL"
)
check "the profile names the server artifact set and the gnu triple" \
    test "$profile" = "vitni-verify handsal-check-server|handsal-check-server.pyz|x86_64-unknown-linux-gnu|/usr/bin/sha256sum||/usr/bin/chown"
check "the library takes no tool from a variable the caller's environment holds" \
    has_no_line '\${\(HASH_TOOL\|TAR_TOOL\|CHOWN_TOOL\|ARTIFACT_BINS\|ARTIFACT_LIBS\|TRIPLE\):' "$lib"

# ---- the installed script has fixed values and no way in from the environment ------------------------
script=$here/install-linux-server.sh
check "the script is there" test -f "$script"
check "the destination is /opt/handsal, assigned" grep -q "^DEST_ROOT='/opt/handsal'$" "$script"
check "the owner is root:root, assigned" grep -q "^OWNER='root:root'$" "$script"
check "the privileged runner is a fixed absolute path, assigned" grep -q "^PRIV='/usr/bin/env'$" "$script"
check "PATH is fixed to the system directories" grep -q "^PATH='/usr/bin:/bin'$" "$script"
check "the Linux profile is applied" grep -q '^profile_linux_server$' "$script"
check "the script refuses anything but root" grep -q 'id -u' "$script"
check "the script refuses a host that is not Linux amd64" grep -q 'x86_64' "$script"
# shellcheck disable=SC2016
check "no value is read from a variable with a default" has_no_line '\${[A-Z_]*:-' "$script"
check "the script never names sudo" has_no_line 'sudo' "$script"
mkdir -p "$tmp/evil"
make_world script
printf 'tampered' >> "$tmp/script/artifacts/vitni-verify"
env DEST_ROOT="$tmp/evil/handsal" PRIV=/usr/bin/true OWNER= HASH_TOOL=/usr/bin/true sh "$script" "$tmp/script/artifacts" "$tmp/script/published" > "$tmp/script/out" 2>&1
check "the installed script aborts even with variables in the environment" test $? -ne 0
check "...and writes nothing at the path the environment named" test -z "$(ls -A "$tmp/evil")"
sh "$script" > /dev/null 2>&1
check "the installed script without arguments is a usage error" test $? -eq 2

printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
