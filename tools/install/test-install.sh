#!/bin/sh
# Tests of the macOS installer (SG-15, SG-14, T5.23, CF-07 "SG-15 installer"). No root, no sudo:
# the privileged runner is a stand-in that logs the command and runs it as the current user, and
# the destination is a temporary directory. Run:  sh tools/install/test-install.sh
#
# The installer runs with a fixed PATH on a stock macOS. So every installer run below has that same PATH
# (and one run has only the tools the installer names), while the fixtures are built outside it, the way the
# packaging builds them. A test environment richer than the product's hid a missing zstd once.
set -u

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-install-test.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

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

case $(uname -m) in
    arm64) triple=aarch64-apple-darwin ;;
    *) triple=x86_64-apple-darwin ;;
esac
interpreter="cpython-3.13.18+20261110-$triple-install_only.tar.gz"
licenses="handsal-python-licenses-3.13.18+20261110-$triple.tar.gz"
stock_path=/usr/bin:/bin:/usr/sbin:/sbin

sha() { /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; }

# A fake privileged runner: logs its arguments, then runs them as this user. PRIV_FAIL_ON is a case
# pattern for the command line; a command that matches fails without running (a fault injected there).
cat > "$tmp/fakepriv" <<'PRIV'
#!/bin/sh
printf '%s\n' "$*" >> "$PRIV_LOG"
if [ -n "${PRIV_BEFORE:-}" ]; then "$PRIV_BEFORE" "$@"; fi
if [ -n "${PRIV_FAIL_ON:-}" ]; then
    # shellcheck disable=SC2254
    case "$*" in $PRIV_FAIL_ON) exit 1 ;; esac
fi
exec "$@"
PRIV

chmod +x "$tmp/fakepriv"

# The fixtures that do not change are built once, outside the installer's environment: the interpreter archive
# with the system tar, and the licences archive by tools/pack_licenses.py, the code of the real packaging step.
mkdir -p "$tmp/fx/build/python/bin" "$tmp/fx/build/python/lib" "$tmp/fx/notes/python/licenses"
printf 'interpreter' > "$tmp/fx/build/python/bin/python3.13"
ln -s python3.13 "$tmp/fx/build/python/bin/python3"
printf 'stdlib' > "$tmp/fx/build/python/lib/os.py"
(cd "$tmp/fx/build" && tar -czf "$tmp/fx/$interpreter" python)
printf 'licence text' > "$tmp/fx/notes/python/licenses/LICENSE.txt"
# shellcheck disable=SC2016
uv run --no-project python -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import pack_licenses; pack_licenses.pack_tree(sys.argv[2], sys.argv[3])' \
    "$here/../" "$tmp/fx/notes" "$tmp/fx/$licenses" || { echo "cannot build the licences fixture with pack_licenses.py (needs uv)"; exit 2; }

# publish_world NAME: the published values of every artifact in the world, as the tag would list them.
publish_world() {
    w=$tmp/$1
    : > "$w/published"
    for f in vitni-verify handsal-pin handsal-check handsal-check.pyz "$interpreter" "$licenses"; do
        printf '%s  %s\n' "$(sha "$w/artifacts/$f")" "$f" >> "$w/published"
    done
}

# make_world NAME: artifacts/, published, dest/ for one test.
make_world() {
    w=$tmp/$1
    rm -rf "$w"
    mkdir -p "$w/artifacts" "$w/dest"
    printf 'vitni' > "$w/artifacts/vitni-verify"
    printf 'pin helper' > "$w/artifacts/handsal-pin"
    printf '#!/bin/sh\n' > "$w/artifacts/handsal-check"
    printf 'zipapp' > "$w/artifacts/handsal-check.pyz"
    cp "$tmp/fx/$interpreter" "$tmp/fx/$licenses" "$w/artifacts/"
    publish_world "$1"
    : > "$w/priv.log"
}

# snapshot DIR: every path under DIR with its type, link target or content hash, for a before/after comparison.
snapshot() {
    (cd "$1" && find . | sort | while read -r p; do
        if [ -L "$p" ]; then printf '%s -> %s\n' "$p" "$(readlink "$p")"
        elif [ -f "$p" ]; then printf '%s %s\n' "$p" "$(sha "$p")"
        else printf '%s dir\n' "$p"; fi
    done)
}

# run_install NAME [SNIPPET]: the installer library against the world's temporary destination, with the
# installer's fixed PATH (RUN_PATH overrides it for the minimal-tools run). SNIPPET runs after the library is
# sourced, to point a tool variable at a missing file.
run_install() {
    w=$tmp/$1
    # shellcheck disable=SC2030,SC2031
    (
        PRIV_LOG=$w/priv.log
        export PRIV_LOG
        DEST_ROOT=$w/dest/handsal
        PRIV=$tmp/fakepriv
        OWNER=
        PATH=${RUN_PATH:-$stock_path}
        export PATH
        # shellcheck source=install-lib.sh
        . "$here/install-lib.sh"
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
check "vitni-verify is installed" test "$(cat "$d/bin/vitni-verify" 2>/dev/null)" = vitni
check "handsal-pin is installed" test "$(cat "$d/bin/handsal-pin" 2>/dev/null)" = "pin helper"
check "the launcher is installed" test -f "$d/bin/handsal-check"
check "the zipapp is installed in lib" test "$(cat "$d/lib/handsal-check.pyz" 2>/dev/null)" = zipapp
check "the interpreter is extracted under python" test "$(cat "$d/python/bin/python3.13" 2>/dev/null)" = interpreter
check "the interpreter symlink is kept" test -L "$d/python/bin/python3"
check "the licences land in python/licenses" test "$(cat "$d/python/licenses/LICENSE.txt" 2>/dev/null)" = "licence text"
check "only python/licenses comes from the licences archive" test ! -e "$d/python/PYTHON.json"
check "no staging directory is left, inside or beside the install" test -z "$(find "$tmp/ok/dest" -name '*staging*' 2>/dev/null)"
check "the executables are 0755" test "$(stat -f %Lp "$d/bin/handsal-pin")" = 755
check "the zipapp is not executable by itself" test "$(stat -f %Lp "$d/lib/handsal-check.pyz")" = 644
check "no entry is writable by group or others" test -z "$(find "$d" ! -type l -perm -022 2>/dev/null)"
check "the installer makes handsal, bin, lib and python (GP-21, SG-15)" test -d "$d" -a -d "$d/bin" -a -d "$d/lib" -a -d "$d/python"
check "the pin directory and lock are not the installer's" test ! -e "$d/orgs" -a ! -e "$d/pin.lock"

# ---- a hash that differs aborts before any privileged command ------------------------------------
for victim in vitni-verify handsal-pin handsal-check handsal-check.pyz "$interpreter" "$licenses"; do
    make_world mismatch
    printf 'tampered' >> "$tmp/mismatch/artifacts/$victim"
    run_install mismatch
    status=$?
    check "a different $victim aborts (nonzero)" test "$status" -ne 0
    check "a different $victim runs no privileged command" test ! -s "$tmp/mismatch/priv.log"
    check "a different $victim copies nothing" test -z "$(ls -A "$tmp/mismatch/dest")"
    check "a different $victim is named" grep -q "$victim" "$tmp/mismatch/out"
done

# ---- a value that is not published, a missing file, a symlink: abort before any privileged command --
make_world unpublished
grep -v 'handsal-pin' "$tmp/unpublished/published" > "$tmp/unpublished/p2" && mv "$tmp/unpublished/p2" "$tmp/unpublished/published"
run_install unpublished
check "an artifact with no published value aborts" test $? -ne 0
check "…before any privileged command" test ! -s "$tmp/unpublished/priv.log"

make_world absent
rm "$tmp/absent/artifacts/vitni-verify"
run_install absent
check "a missing artifact aborts" test $? -ne 0
check "…before any privileged command (missing)" test ! -s "$tmp/absent/priv.log"

make_world linked
mv "$tmp/linked/artifacts/handsal-pin" "$tmp/linked/elsewhere"
ln -s "$tmp/linked/elsewhere" "$tmp/linked/artifacts/handsal-pin"
run_install linked
check "an artifact that is a symlink aborts" test $? -ne 0
check "…before any privileged command (symlink)" test ! -s "$tmp/linked/priv.log"

make_world twice
printf '%s  %s\n' "$(sha "$tmp/twice/artifacts/handsal-pin")" handsal-pin >> "$tmp/twice/published"
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" handsal-pin >> "$tmp/twice/published"
run_install twice
check "two published values for one artifact abort" test $? -ne 0
check "…before any privileged command (two values)" test ! -s "$tmp/twice/priv.log"

make_world malformed
sed -i '' 's/^\([0-9a-f]\{4\}\)/\1Z/' "$tmp/malformed/published"
run_install malformed
check "a published value that is not 64 hex digits aborts" test $? -ne 0
check "…before any privileged command (malformed)" test ! -s "$tmp/malformed/priv.log"

make_world twoarchives
cp "$tmp/twoarchives/artifacts/$interpreter" "$tmp/twoarchives/artifacts/cpython-9.9.9+1-$triple-install_only.tar.gz"
run_install twoarchives
check "two interpreter archives for this machine abort" test $? -ne 0
check "…before any privileged command (two archives)" test ! -s "$tmp/twoarchives/priv.log"

# ---- the bytes change after they were verified: the copy is hashed again ------------------------
# A stand-in for an agent that changes the zipapp after it was checked, just before its privileged copy.
cat > "$tmp/swap" <<'SWAP'
#!/bin/sh
case "$*" in
    *install*handsal-check.pyz*) printf swapped > "$SWAP_TARGET" ;;
esac
SWAP
chmod +x "$tmp/swap"
make_world race
SWAP_TARGET=$tmp/race/artifacts/handsal-check.pyz
PRIV_BEFORE=$tmp/swap
export PRIV_BEFORE SWAP_TARGET
run_install race
status=$?
unset PRIV_BEFORE SWAP_TARGET
check "bytes swapped after the check abort the install" test "$status" -ne 0
check "the swapped zipapp is not at its path" test ! -e "$tmp/race/dest/handsal/lib/handsal-check.pyz"
check "no staging directory is left after the abort" test -z "$(find "$tmp/race/dest" -name '*staging*' 2>/dev/null)"
check "the abort says which artifact changed" grep -q 'handsal-check.pyz' "$tmp/race/out"

# ---- neither conformance executable is ever copied, even if it sits among the artifacts -----------
make_world conf
for f in handsal-sign-conformance handsal-check-conformance; do
    printf 'conformance' > "$tmp/conf/artifacts/$f"
    printf '%s  %s\n' "$(sha "$tmp/conf/artifacts/$f")" "$f" >> "$tmp/conf/published"
done
run_install conf
check "the install with conformance executables around succeeds" test $? -eq 0
check "handsal-sign-conformance is not installed" test -z "$(find "$tmp/conf/dest" -name 'handsal-sign-conformance*' 2>/dev/null)"
check "handsal-check-conformance is not installed" test -z "$(find "$tmp/conf/dest" -name 'handsal-check-conformance*' 2>/dev/null)"
check "no privileged command names a conformance executable" has_no_line conformance "$tmp/conf/priv.log"

# ---- a reinstall replaces what it installed and leaves the pins alone ---------------------------
make_world again
run_install again
mkdir -p "$tmp/again/dest/handsal/orgs"
printf 'a pin' > "$tmp/again/dest/handsal/orgs/x.pin"
printf 'a lock' > "$tmp/again/dest/handsal/pin.lock"
printf 'stale' > "$tmp/again/dest/handsal/python/stale-file"
printf 'new pin helper' > "$tmp/again/artifacts/handsal-pin"
grep -v ' handsal-pin$' "$tmp/again/published" > "$tmp/again/p2"
printf '%s  %s\n' "$(sha "$tmp/again/artifacts/handsal-pin")" handsal-pin >> "$tmp/again/p2"
mv "$tmp/again/p2" "$tmp/again/published"
run_install again
check "a reinstall succeeds" test $? -eq 0
check "the helper is the new one" test "$(cat "$tmp/again/dest/handsal/bin/handsal-pin")" = "new pin helper"
check "the old interpreter tree is replaced" test ! -e "$tmp/again/dest/handsal/python/stale-file"
check "a pin is untouched" test "$(cat "$tmp/again/dest/handsal/orgs/x.pin")" = "a pin"
check "the lock file is untouched" test "$(cat "$tmp/again/dest/handsal/pin.lock")" = "a lock"

# ---- extraction never takes the owner an archive names (root would keep a builder's uid; a test as a user cannot see it)
# shellcheck disable=SC2016
check "every extraction passes --no-same-owner" sh -c 'n=$(grep -c "TAR_TOOL\" -x" "$1"); m=$(grep "TAR_TOOL\" -x" "$1" | grep -c -e --no-same-owner); [ "$n" -ge 1 ] && [ "$n" -eq "$m" ]' _ "$here/install-lib.sh"

# ---- the installer needs nothing a stock macOS lacks -----------------------------------------------
# The fixed PATH above is the product's. This run is stricter: PATH holds only the tools the library names
# (PATH_TOOLS), so a tool the library started to need from PATH (zstd, gzip, python) fails here even on a
# machine that happens to have it in /usr/bin.
mkdir -p "$tmp/minbin"
# shellcheck source=install-lib.sh
path_tools=$(. "$here/install-lib.sh"; printf '%s' "$PATH_TOOLS")
check "the library names the tools it takes from PATH" test -n "$path_tools"
for t in $path_tools; do ln -s "$(command -v "$t")" "$tmp/minbin/$t"; done
make_world minpath
( RUN_PATH=$tmp/minbin; run_install minpath )
check "an install with only the named PATH tools succeeds" test $? -eq 0
check "…and installed the interpreter" test "$(cat "$tmp/minpath/dest/handsal/python/bin/python3.13" 2>/dev/null)" = interpreter
check "…and the licences" test -f "$tmp/minpath/dest/handsal/python/licenses/LICENSE.txt"
check "the library never assigns PATH" has_no_line '^[[:space:]]*PATH=' "$here/install-lib.sh"

# an upstream notices archive (.tar.zst) among the artifacts is never read or copied
make_world zst
printf 'zst bytes' > "$tmp/zst/artifacts/cpython-3.13.18+20261110-$triple-pgo+lto-full.tar.zst"
printf '%s  %s\n' "$(sha "$tmp/zst/artifacts/cpython-3.13.18+20261110-$triple-pgo+lto-full.tar.zst")" "cpython-3.13.18+20261110-$triple-pgo+lto-full.tar.zst" >> "$tmp/zst/published"
run_install zst
check "an install with the upstream .tar.zst around succeeds" test $? -eq 0
check "no privileged command names a zstd archive" has_no_line 'tar[.]zst' "$tmp/zst/priv.log"

# ---- a missing tool is a refusal before any privileged step ---------------------------------------
make_world notar
run_install notar 'TAR_TOOL=/nonexistent/tar'
status=$?
check "a missing tar refuses (exit 1)" test "$status" -eq 1
check "…names the tool" grep -q '/nonexistent/tar' "$tmp/notar/out"
check "…before any privileged command" test ! -s "$tmp/notar/priv.log"
check "…and touches nothing" test -z "$(ls -A "$tmp/notar/dest")"

make_world noawk
mkdir -p "$tmp/noawkbin"
for t in $path_tools; do [ "$t" = awk ] || ln -sf "$(command -v "$t")" "$tmp/noawkbin/$t"; done
( RUN_PATH=$tmp/noawkbin; run_install noawk )
check "a PATH tool that is missing refuses (nonzero)" test $? -ne 0
check "…names awk" grep -q 'awk' "$tmp/noawk/out"
check "…before any privileged command (PATH tool)" test ! -s "$tmp/noawk/priv.log"

make_world nopriv
run_install nopriv 'PRIV=/nonexistent/sudo'
check "a missing privileged runner refuses" test $? -eq 1
check "…and touches nothing (runner)" test -z "$(ls -A "$tmp/nopriv/dest")"

# ---- a failure at any unpack leaves the install location as it was --------------------------------
# every check and every unpack runs in staging, beside the destination; only then is anything moved in.
for fault in '*install_only*' "*handsal-python-licenses*"; do
    case $fault in *install_only*) which=interpreter ;; *) which=licences ;; esac
    make_world atomic_fresh
    PRIV_FAIL_ON="*-xf*$(printf '%s' "$fault" | tr -d '*')*"
    export PRIV_FAIL_ON
    run_install atomic_fresh
    status=$?
    unset PRIV_FAIL_ON
    check "a failed $which unpack aborts (exit 3)" test "$status" -eq 3
    check "a failed $which unpack on a fresh machine leaves no handsal directory" test ! -e "$tmp/atomic_fresh/dest/handsal"
    check "a failed $which unpack leaves nothing at all in the parent (no staging)" test -z "$(ls -A "$tmp/atomic_fresh/dest")"
    check "the unpack was reached (the fault was injected where meant)" grep -q -e '-xf' "$tmp/atomic_fresh/priv.log"

    make_world atomic_again
    run_install atomic_again
    printf 'a pin' > "$tmp/atomic_again/dest/handsal/pin.lock"
    printf 'new pin helper' > "$tmp/atomic_again/artifacts/handsal-pin"
    publish_world atomic_again
    before=$(snapshot "$tmp/atomic_again/dest")
    PRIV_FAIL_ON="*-xf*$(printf '%s' "$fault" | tr -d '*')*"
    export PRIV_FAIL_ON
    run_install atomic_again
    status=$?
    unset PRIV_FAIL_ON
    check "a failed $which unpack on an existing install aborts" test "$status" -eq 3
    check "…and the existing install is byte for byte as it was" test "$(snapshot "$tmp/atomic_again/dest")" = "$before"
done

# a real unpack failure, no injection: archives whose hash is published and whose bytes are not an archive
for victim in "$interpreter" "$licenses"; do
    make_world corrupt
    printf 'not a gzip tar' > "$tmp/corrupt/artifacts/$victim"
    publish_world corrupt
    run_install corrupt
    status=$?
    check "a published but unreadable $victim fails the install" test "$status" -eq 3
    check "…leaving nothing on a fresh machine" test -z "$(ls -A "$tmp/corrupt/dest")"
done

# archives that unpack but do not hold what the install needs
make_world nolic
mkdir -p "$tmp/nolic/other/python/docs"
printf 'x' > "$tmp/nolic/other/python/docs/README"
(cd "$tmp/nolic/other" && tar -czf "$tmp/nolic/artifacts/$licenses" python)
publish_world nolic
run_install nolic
check "a licences archive without python/licenses fails the install" test $? -eq 3
check "…and leaves nothing" test -z "$(ls -A "$tmp/nolic/dest")"

# ---- the library refuses to run without its parameters ------------------------------------------
( unset DEST_ROOT PRIV OWNER; . "$here/install-lib.sh"; install_run "$tmp/ok/artifacts" "$tmp/ok/published" ) > /dev/null 2>&1
check "no destination, no runner: the library refuses" test $? -ne 0

# ---- the installed script has fixed values and no way in from the environment --------------------
macos=$here/install-macos.sh
check "the script is there" test -f "$macos"
check "the destination is the administrator path, assigned" grep -q "^DEST_ROOT='/Library/Application Support/handsal'$" "$macos"
check "the privileged runner is /usr/bin/sudo, assigned" grep -q "^PRIV='/usr/bin/sudo'$" "$macos"
check "the owner is root:wheel, assigned" grep -q "^OWNER='root:wheel'$" "$macos"
# shellcheck disable=SC2016
check "no value is read from a variable with a default" has_no_line '\${[A-Z_]*:-' "$macos"
check "PATH is fixed to the system directories" grep -q "^PATH='/usr/bin:/bin:/usr/sbin:/sbin'$" "$macos"
check "the credential is dropped at the end" grep -q "/usr/bin/sudo -k" "$macos"
mkdir -p "$tmp/evil"
make_world script
printf 'tampered' >> "$tmp/script/artifacts/handsal-pin"
env DEST_ROOT="$tmp/evil/handsal" PRIV=/usr/bin/true OWNER= sh "$macos" "$tmp/script/artifacts" "$tmp/script/published" > "$tmp/script/out" 2>&1
check "the installed script aborts on a mismatch even with variables in the environment" test $? -ne 0
check "…and writes nothing at the path the environment named" test -z "$(ls -A "$tmp/evil")"
sh "$macos" > /dev/null 2>&1
check "the installed script without arguments is a usage error" test $? -eq 2

printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
