#!/bin/sh
# Tests of the Linux server release build script (T15.10, SG-15, CF-10). No real build: go and curl are stand-ins
# first on PATH that write a small file where the real tool would, and log what they were asked. The script runs
# from a copy of the files it uses, in a throwaway git repository whose interpreter pin is rewritten to fixture
# archives, so `tools/artifact_hashes.py --release` accepts the result. The refusals it shares with the macOS
# script live in release-lib.sh and are tested in test-build-macos.sh; the ones here prove this script reaches them.
# Run:  sh tools/release/test-build-linux-server.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-linux-release-test.XXXXXX") || exit 2
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
has() { grep -q -- "$1" "$2" 2>/dev/null; }
has_fixed() { grep -qF -- "$1" "$2" 2>/dev/null; }
lacks_fixed() { ! grep -qF -- "$1" "$2" 2>/dev/null; }
is_empty() { [ ! -s "$1" ]; }
same_text() { [ "$1" = "$2" ]; }
is_status() { [ "$status" = "$1" ]; }

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

fix=$tmp/fixtures
stubs=$tmp/stubs
log=$tmp/stub.log
mkdir -p "$fix" "$stubs"
py() { uv run --no-project python -I "$@"; }

# --- the closed list, read from the one place that owns it -------------------------------------------------
cat >"$tmp/list.py" <<'PY'
import importlib.util, json, sys
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("ah", root + "/tools/artifact_hashes.py")
ah = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ah)
pin = json.loads(open(root + "/checker/python/packaging/interpreter.json", encoding="utf-8").read())
row = pin["platforms"]["linux-x86_64"]
kind = ah.ARTIFACTS["linux-x86_64"]
if sys.argv[2] == "closed":
    print("\n".join(sorted(list(kind.fixed) + [row["archive"]["file"], row["packed_licenses"]["file"]])))
else:
    print("\n".join(kind.fixed))
PY
closed=$(py "$tmp/list.py" "$root" closed)
fixed=$(py "$tmp/list.py" "$root" fixed)

# --- fixtures -----------------------------------------------------------------------------------------------
printf 'fixture interpreter archive\n' >"$fix/archive.bin"
mkdir -p "$fix/notices/python/licenses"
printf 'fixture licence text\n' >"$fix/notices/python/licenses/LICENSE.txt"
tar -cf - -C "$fix/notices" python | zstd -q -o "$fix/notices.tar.zst"
printf 'not the pinned archive\n' >"$fix/wrong.bin"

vitni=$tmp/vitni-origin
mkdir -p "$vitni/go/cmd/vitni-verify"
printf 'package main\n' >"$vitni/go/cmd/vitni-verify/main.go"
git -C "$vitni" init -q && git -C "$vitni" add -A && git -C "$vitni" commit -q -m "vitni fixture"
vitni_commit=$(git -C "$vitni" rev-parse HEAD)

repo=$tmp/repo
mkdir -p "$repo/tools/release" "$repo/checker/python" "$repo/signer/apple"
printf '// fixture package\n' >"$repo/signer/apple/Package.swift"
cp "$root/tools/artifact_hashes.py" "$root/tools/pack_licenses.py" "$repo/tools/"
for f in build-linux-server.sh build-vitni.sh release-lib.sh go-version; do cp "$root/tools/release/$f" "$repo/tools/release/" 2>/dev/null; done
cp -R "$root/checker/python/packaging" "$root/checker/python/src" "$repo/checker/python/"
printf '__pycache__/\n*.pyc\n' >"$repo/.gitignore"
printf '%s\n' "$vitni_commit" >"$repo/tools/release/vitni-commit"
cat >"$tmp/pin.py" <<'PY'
import hashlib, json, sys
path, archive, notices = sys.argv[1:4]
pin = json.loads(open(path, encoding="utf-8").read())
row = pin["platforms"]["linux-x86_64"]
row["archive"]["sha256"] = hashlib.sha256(open(archive, "rb").read()).hexdigest()
row["notices"]["sha256"] = hashlib.sha256(open(notices, "rb").read()).hexdigest()
open(path, "w", encoding="utf-8").write(json.dumps(pin, indent=2) + "\n")
PY
py "$tmp/pin.py" "$repo/checker/python/packaging/interpreter.json" "$fix/archive.bin" "$fix/notices.tar.zst"
git -C "$repo" init -q && git -C "$repo" add -A && git -C "$repo" commit -q -m "fixture"
printf 'stray_ignored.txt\n' >>"$repo/.git/info/exclude"
repo_head=$(git -C "$repo" rev-parse HEAD)
script=$repo/tools/release/build-linux-server.sh

# --- stand-ins ----------------------------------------------------------------------------------------------
ctl=$tmp/ctl
mkdir -p "$ctl"
# The stand-in carries its paths in its first lines: the build runs under `env -i`, so it cannot read them from
# the environment, and nothing edits the text afterwards.
{
    printf "#!/bin/sh\nLOG='%s'\nCTL='%s'\nGIT='%s'\n" "$log" "${ctl:-}" "${real_git:-}"
    cat <<'SH'
if [ "${1:-}" = version ]; then
    printf 'go version %s linux/amd64\n' "${GOTOOLCHAIN:-none}"
    exit 0
fi
printf 'go %s\n' "$*" >>"$LOG"
printf 'env GOOS=%s GOARCH=%s CGO_ENABLED=%s\n' "${GOOS-}" "${GOARCH-}" "${CGO_ENABLED-}" >>"$LOG"
out=
while [ $# -gt 0 ]; do
    [ "$1" = -o ] && out=$2
    shift
done
[ -f "$CTL/fail" ] && exit 1
printf 'vitni stub\n' >"$out"
SH
} >"$stubs/go"
cat >"$stubs/swift" <<'SH'
#!/bin/sh
printf 'swift %s\n' "$*" >>"$STUB_LOG"
exit 1
SH
cat >"$stubs/curl" <<'SH'
#!/bin/sh
printf 'curl %s\n' "$*" >>"$STUB_LOG"
out= url=
while [ $# -gt 0 ]; do
    case $1 in
        -o) out=$2; shift ;;
        -*) ;;
        *) url=$1 ;;
    esac
    shift
done
case $url in
    *install_only*) if [ -n "${STUB_BAD_ARCHIVE:-}" ]; then cp "$STUB_FIX/wrong.bin" "$out"; else cp "$STUB_FIX/archive.bin" "$out"; fi ;;
    *) cp "$STUB_FIX/notices.tar.zst" "$out" ;;
esac
SH
cat >"$stubs/uname" <<'SH'
#!/bin/sh
case ${1:-} in
    -s) echo "${STUB_OS:-Linux}" ;;
    -m) echo "${STUB_ARCH:-x86_64}" ;;
    *) echo "${STUB_OS:-Linux}" ;;
esac
SH
chmod +x "$stubs/go" "$stubs/swift" "$stubs/curl" "$stubs/uname"

run() {
    : >"$log"
    (cd "$tmp" && PATH="$stubs:$PATH" STUB_LOG="$log" STUB_FIX="$fix" HANDSAL_VITNI_REPO="$vitni" sh "$script" "$@") >"$tmp/out" 2>"$tmp/err"
    status=$?
}
refused() {
    check "$1: refused with status 2" is_status 2
    check "$1: nothing on stdout" is_empty "$tmp/out"
    check "$1: no tool was run" is_empty "$log"
    check "$1: it says why" test -s "$tmp/err"
}

# --- the script holds no second copy ---------------------------------------------------------------------------
check "the script exists" test -f "$here/build-linux-server.sh"
for n in $closed cpython "$vitni_commit"; do
    check "the script has no copy of $n" lacks_fixed "$n" "$here/build-linux-server.sh"
done
check "the script holds no vitni build flag" lacks_fixed "-buildvcs" "$here/build-linux-server.sh"
check "the script runs no Swift" lacks_fixed "swift" "$here/build-linux-server.sh"
check "the refusals live in the shared library" lacks_fixed 'refuse "the tree has' "$here/build-linux-server.sh"
check "the script sources the shared library" has_fixed "release-lib.sh" "$here/build-linux-server.sh"

# --- a stub run ---------------------------------------------------------------------------------------------
run "$tmp/out1"
check "a stub run exits 0 (err: $(tail -n 4 "$tmp/err" 2>/dev/null))" is_status 0
check "the directory holds exactly the closed list" same_text "$(ls -1 "$tmp/out1" 2>/dev/null | LC_ALL=C sort)" "$(printf '%s\n' "$closed" | LC_ALL=C sort)"
check "stdout is the lines artifact_hashes prints for that directory" same_text "$(cat "$tmp/out")" "$(py "$repo/tools/artifact_hashes.py" --release "$tmp/out1" --platform linux-x86_64 2>/dev/null)"
check "stdout has one line per name of the closed list" same_text "$(wc -l <"$tmp/out" | tr -d ' ')" "$(printf '%s\n' "$closed" | wc -l | tr -d ' ')"
check "it prints the commit it built from, on stderr" has_fixed "$repo_head" "$tmp/err"
check "it prints the vitni commit and where it comes from" has_fixed "vitni commit $vitni_commit from $vitni" "$tmp/err"
check "vitni is built for linux, amd64, without cgo" has_fixed "env GOOS=linux GOARCH=amd64 CGO_ENABLED=0" "$log"
check "vitni is built with -trimpath" has_fixed "-trimpath" "$log"
check "go is run once" same_text "$(grep -c '^go build' "$log")" 1
check "no Swift is run" lacks_fixed "swift" "$log"
check "the interpreter archive is fetched with curl -f" has "^curl -f.*install_only" "$log"
check "the notices archive is fetched with curl -f" has "^curl -f.*pgo" "$log"
check "the launcher is executable" test -x "$tmp/out1/handsal-check-server"
check "the launcher is the server one" has_fixed "/opt/handsal/lib/handsal-check-server.pyz" "$tmp/out1/handsal-check-server"
check "the zipapp has the server entry" test -s "$tmp/out1/handsal-check-server.pyz"

# it does not care what machine builds it: the set is cross built
STUB_OS=Darwin STUB_ARCH=arm64; export STUB_OS STUB_ARCH
run "$tmp/out2"
unset STUB_OS STUB_ARCH
check "it builds on an Apple silicon Mac" is_status 0
check "the two builds print the same lines" same_text "$(cat "$tmp/out")" "$(py "$repo/tools/artifact_hashes.py" --release "$tmp/out1" --platform linux-x86_64 2>/dev/null)"
check "the two builds make the same zipapp" cmp -s "$tmp/out1/handsal-check-server.pyz" "$tmp/out2/handsal-check-server.pyz"
check "the two builds make the same launcher" cmp -s "$tmp/out1/handsal-check-server" "$tmp/out2/handsal-check-server"

# --- refusals reach the shared library ----------------------------------------------------------------------
mkdir "$tmp/full" && : >"$tmp/full/x"
run "$tmp/full"
refused "a directory that is not empty"
run -x
refused "an argument that starts with a dash"
run
refused "no argument"
run "$tmp/a" "$tmp/b"
refused "two arguments"
printf 'x\n' >>"$repo/.gitignore"
run "$tmp/dirty0"
refused "a tracked file changed outside the build inputs (only the tracked-changes guard sees it)"
check "it is the tracked-changes guard that says so" has_fixed "tracked changes" "$tmp/err"
git -C "$repo" checkout -q -- .
printf 'changed\n' >>"$repo/checker/python/packaging/launcher.py"
run "$tmp/dirty1"
refused "a tracked file among the build inputs changed"
git -C "$repo" checkout -q -- .
# S3: the running scripts are read from the working tree; a local edit hidden from git must still be refused
printf '# local edit\n' >>"$repo/tools/release/build-linux-server.sh"
git -C "$repo" update-index --assume-unchanged tools/release/build-linux-server.sh
run "$tmp/hidden1"
refused "an edited entry script hidden with assume-unchanged"
check "it names the script and the commit" has_fixed "build-linux-server.sh differs from commit $repo_head" "$tmp/err"
git -C "$repo" update-index --no-assume-unchanged tools/release/build-linux-server.sh
git -C "$repo" checkout -q -- .
printf '# local edit\n' >>"$repo/tools/release/release-lib.sh"
git -C "$repo" update-index --skip-worktree tools/release/release-lib.sh
run "$tmp/hidden2"
refused "an edited library hidden with skip-worktree"
check "it names the library and the commit" has_fixed "release-lib.sh differs from commit $repo_head" "$tmp/err"
git -C "$repo" update-index --no-skip-worktree tools/release/release-lib.sh
git -C "$repo" checkout -q -- .
check "after the unhide the tree builds again" test -z "$(git -C "$repo" status --porcelain --untracked-files=no)"
printf 'x\n' >"$repo/tools/stray.txt"
run "$tmp/dirty2"
refused "an untracked file among the inputs"
rm -f "$repo/tools/stray.txt"
printf '%s' "main
" >"$repo/tools/release/vitni-commit"
git -C "$repo" commit -q -a -m "bad pin"
run "$tmp/badpin"
refused "a vitni commit that is not a commit"
git -C "$repo" reset -q --hard "$repo_head"
check "a refusal makes no directory" test ! -e "$tmp/badpin"

# --- failures -------------------------------------------------------------------------------------------------
: >"$ctl/fail"
run "$tmp/fail1"
rm -f "$ctl/fail"
check "a failing vitni build fails the script with status 1" is_status 1
check "the failing vitni build did run" has "^go build" "$log"
check "a failing vitni build prints nothing to publish" is_empty "$tmp/out"
check "a failing vitni build says the directory is partial" has "partial build" "$tmp/err"

STUB_BAD_ARCHIVE=1; export STUB_BAD_ARCHIVE
run "$tmp/fail2"
unset STUB_BAD_ARCHIVE
check "an archive that is not the pinned one fails with status 1" is_status 1
check "the refusal names the pinned archive" has "is not the pinned interpreter archive" "$tmp/err"
check "an archive that is not the pinned one prints nothing to publish" is_empty "$tmp/out"

# --- built from git, not from the working tree --------------------------------------------------------------
printf 'ignored\n' >"$repo/checker/python/src/handsal_check/stray_ignored.txt"
run "$tmp/stray"
check "an ignored file in the source tree does not stop the build" is_status 0
check "an ignored file in the source tree is not in the zipapp" cmp -s "$tmp/out1/handsal-check-server.pyz" "$tmp/stray/handsal-check-server.pyz"
rm -f "$repo/checker/python/src/handsal_check/stray_ignored.txt"

printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" = 0 ]
