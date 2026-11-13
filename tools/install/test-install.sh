#!/bin/sh
# Tests of the macOS installer (SG-15, SG-14, T5.23, CF-07 "SG-15 installer"). No root, no sudo:
# the privileged runner is a stand-in that logs the command and runs it as the current user, and
# the destination is a temporary directory. Run:  sh tools/install/test-install.sh
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
notices="cpython-3.13.18+20261110-$triple-pgo+lto-full.tar.zst"

sha() { /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; }

# A fake privileged runner: logs its arguments, then runs them as this user.
cat > "$tmp/fakepriv" <<'PRIV'
#!/bin/sh
printf '%s\n' "$*" >> "$PRIV_LOG"
if [ -n "${PRIV_BEFORE:-}" ]; then "$PRIV_BEFORE" "$@"; fi
exec "$@"
PRIV

chmod +x "$tmp/fakepriv"

# make_world NAME: artifacts/, published, dest/ for one test.
make_world() {
    w=$tmp/$1
    rm -rf "$w"
    mkdir -p "$w/artifacts" "$w/build/python/bin" "$w/build/python/lib" "$w/notes/python/licenses" "$w/dest"
    printf 'vitni' > "$w/artifacts/vitni-verify"
    printf 'pin helper' > "$w/artifacts/handsal-pin"
    printf '#!/bin/sh\n' > "$w/artifacts/handsal-check"
    printf 'zipapp' > "$w/artifacts/handsal-check.pyz"
    printf 'interpreter' > "$w/build/python/bin/python3.13"
    ln -s python3.13 "$w/build/python/bin/python3"
    printf 'stdlib' > "$w/build/python/lib/os.py"
    (cd "$w/build" && tar -czf "$w/artifacts/$interpreter" python)
    printf 'licence text' > "$w/notes/python/licenses/LICENSE.txt"
    printf 'other' > "$w/notes/python/PYTHON.json"
    (cd "$w/notes" && tar --zstd -cf "$w/artifacts/$notices" python)
    : > "$w/published"
    for f in vitni-verify handsal-pin handsal-check handsal-check.pyz "$interpreter" "$notices"; do
        printf '%s  %s\n' "$(sha "$w/artifacts/$f")" "$f" >> "$w/published"
    done
    : > "$w/priv.log"
}

# run_install NAME: the installer library against the world's temporary destination.
run_install() {
    w=$tmp/$1
    # shellcheck disable=SC2030,SC2031
    (
        PRIV_LOG=$w/priv.log
        export PRIV_LOG
        DEST_ROOT=$w/dest/handsal
        PRIV=$tmp/fakepriv
        OWNER=
        # shellcheck source=install-lib.sh
        . "$here/install-lib.sh"
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
check "the notices land in python/licenses" test "$(cat "$d/python/licenses/LICENSE.txt" 2>/dev/null)" = "licence text"
check "only the licenses of the notices archive are taken" test ! -e "$d/python/PYTHON.json"
check "no staging directory is left" test -z "$(find "$d" -name '.staging*' 2>/dev/null)"
check "the executables are 0755" test "$(stat -f %Lp "$d/bin/handsal-pin")" = 755
check "the zipapp is not executable by itself" test "$(stat -f %Lp "$d/lib/handsal-check.pyz")" = 644
check "no entry is writable by group or others" test -z "$(find "$d" ! -type l -perm -022 2>/dev/null)"
check "the installer makes handsal, bin, lib and python (GP-21, SG-15)" test -d "$d" -a -d "$d/bin" -a -d "$d/lib" -a -d "$d/python"
check "the pin directory and lock are not the installer's" test ! -e "$d/orgs" -a ! -e "$d/pin.lock"

# ---- a hash that differs aborts before any privileged command ------------------------------------
for victim in vitni-verify handsal-pin handsal-check handsal-check.pyz "$interpreter" "$notices"; do
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
check "no staging directory is left after the abort" test -z "$(find "$tmp/race/dest" -name '.staging*' 2>/dev/null)"
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
check "every extraction passes --no-same-owner" test "$(grep -c 'TAR_TOOL' "$here/install-lib.sh")" -eq "$(( $(grep -c -e '--no-same-owner' "$here/install-lib.sh") + 1 ))"

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
