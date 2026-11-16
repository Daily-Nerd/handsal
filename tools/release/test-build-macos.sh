#!/bin/sh
# Tests of the macOS release build script (T15.8, SG-15, CF-05). No real build: swift, go and curl are
# stand-ins first on PATH that write a small file where the real tool would, and log what they were asked.
# The script runs from a copy of the files it uses, in a throwaway git repository whose interpreter pin
# is rewritten to the fixture archives, so `tools/artifact_hashes.py --release` accepts the result.
# Run:  sh tools/release/test-build-macos.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-release-test.XXXXXX") || exit 2
tmp=$(cd "$tmp" && pwd -P) # the physical path, so a logged working directory compares equal
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
plant() { # FILE OLD NEW: the first occurrence of the fixed text OLD on each line becomes NEW (awk: no sd, no sed -i)
    awk -v old="$2" -v new="$3" '{ i = index($0, old); if (i > 0) $0 = substr($0, 1, i - 1) new substr($0, i + length(old)); print }' "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

fix=$tmp/fixtures
stubs=$tmp/stubs
log=$tmp/stub.log
gitlog=$tmp/git.log
real_git=$(command -v git)
mkdir -p "$fix" "$stubs"

# --- the closed list, read from the one place that owns it -------------------------------------------------
list_py=$tmp/list.py
cat >"$list_py" <<'PY'
import importlib.util, json, sys
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("ah", root + "/tools/artifact_hashes.py")
ah = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ah)
pin = json.loads(open(root + "/checker/python/packaging/interpreter.json", encoding="utf-8").read())
row = pin["platforms"]["macos-arm64"]
kind = ah.ARTIFACTS["macos-arm64"]
what = sys.argv[2]
if what == "closed":
    print("\n".join(sorted(list(kind.fixed) + [row["archive"]["file"], row["packed_licenses"]["file"]])))
elif what == "fixed":
    print("\n".join(kind.fixed))
elif what == "swift":
    print("\n".join(sorted(n for n in kind.fixed if n not in (kind.launcher, kind.zipapp, "vitni-verify"))))
elif what == "archive":
    print(row["archive"]["file"])
PY
py() { uv run --no-project python -I "$@"; }
closed=$(py "$list_py" "$root" closed)
swift_products=$(py "$list_py" "$root" swift)
archive_name=$(py "$list_py" "$root" archive)

# --- fixtures: pinned archives, the vitni source, the repository the script runs in ------------------------
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
printf 'later\n' >"$vitni/later.txt"
git -C "$vitni" add -A && git -C "$vitni" commit -q -m "a later commit"

repo=$tmp/repo
mkdir -p "$repo/tools/release" "$repo/checker/python" "$repo/signer/apple"
printf '// fixture package\n' >"$repo/signer/apple/Package.swift"
cp "$root/tools/artifact_hashes.py" "$root/tools/pack_licenses.py" "$repo/tools/"
for f in build-macos.sh build-vitni.sh release-lib.sh go-version; do cp "$root/tools/release/$f" "$repo/tools/release/" 2>/dev/null; done
cp -R "$root/checker/python/packaging" "$root/checker/python/src" "$repo/checker/python/"
printf '__pycache__/\n*.pyc\n' >"$repo/.gitignore"
printf '%s\n' "$vitni_commit" >"$repo/tools/release/vitni-commit"
cat >"$tmp/pin.py" <<'PY'
import hashlib, json, sys
path, archive, notices = sys.argv[1:4]
pin = json.loads(open(path, encoding="utf-8").read())
row = pin["platforms"]["macos-arm64"]
row["archive"]["sha256"] = hashlib.sha256(open(archive, "rb").read()).hexdigest()
row["notices"]["sha256"] = hashlib.sha256(open(notices, "rb").read()).hexdigest()
open(path, "w", encoding="utf-8").write(json.dumps(pin, indent=2) + "\n")
PY
# The gate is a stand-in here (its own tests are test-vuln-gate.sh): it logs what the build handed it and fails on
# STUB_GATE_FAIL, so the tests see when it runs and that its failure stops the release.
cat >"$repo/tools/release/vuln-gate.sh" <<'SH'
#!/bin/sh
printf 'gate %s %s\n' "$1" "$(basename "$2")" >>"$STUB_LOG"
printf 'gate-lines %s\n' "$(wc -l <"$3" | tr -d ' ')" >>"$STUB_LOG"
printf 'gate-saw %s\n' "$(ls -1 "$2" | wc -l | tr -d ' ')" >>"$STUB_LOG"
[ -z "${STUB_GATE_FAIL:-}" ] || { echo "vuln-gate: stub finding" >&2; exit 1; }
SH
py "$tmp/pin.py" "$repo/checker/python/packaging/interpreter.json" "$fix/archive.bin" "$fix/notices.tar.zst"
git -C "$repo" init -q && git -C "$repo" add -A && git -C "$repo" commit -q -m "fixture"
printf 'stray_ignored.txt\n' >>"$repo/.git/info/exclude"
repo_head=$(git -C "$repo" rev-parse HEAD)
script=$repo/tools/release/build-macos.sh

# --- stand-ins ----------------------------------------------------------------------------------------------
cat >"$stubs/swift" <<'SH'
#!/bin/sh
printf 'swift %s\n' "$*" >>"$STUB_LOG"
printf 'swift-cwd %s\n' "$(pwd)" >>"$STUB_LOG"
product= scratch=
while [ $# -gt 0 ]; do
    case $1 in
        --product) product=$2; shift ;;
        --scratch-path) scratch=$2; shift ;;
    esac
    shift
done
mkdir -p "$scratch/release" && printf 'swift %s\n' "$product" >"$scratch/release/$product"
[ "$product" = "${STUB_FAIL:-}" ] && exit 1
exit 0
SH
# The stand-in carries its paths in its first lines: the build runs under `env -i`, so it cannot read them from
# the environment, and nothing edits the text afterwards.
{
    printf "#!/bin/sh\nLOG='%s'\nCTL='%s'\nGIT='%s'\n" "$log" "${ctl:-}" "${real_git:-}"
    cat <<'SH'
if [ "${1:-}" = version ]; then
    printf 'go version %s darwin/arm64\n' "${GOTOOLCHAIN:-none}"
    exit 0
fi
printf 'go %s\n' "$*" >>"$LOG"
printf 'go-cwd-head %s\n' "$($GIT rev-parse HEAD)" >>"$LOG"
printf 'env GOOS=%s GOARCH=%s CGO_ENABLED=%s\n' "${GOOS-}" "${GOARCH-}" "${CGO_ENABLED-}" >>"$LOG"
out=
while [ $# -gt 0 ]; do
    [ "$1" = -o ] && out=$2
    shift
done
printf 'vitni stub\n' >"$out"
SH
} >"$stubs/go"
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
    -s) echo Darwin ;;
    -m) echo "${STUB_ARCH:-arm64}" ;;
    *) echo Darwin ;;
esac
SH
# git: the real one, except that with STUB_ADVANCE set it moves HEAD one commit just before `archive` runs, and it
# logs the commit its `archive` argument names at that moment.
cat >"$stubs/git" <<'SH'
#!/bin/sh
dir=.
[ "${1:-}" = -C ] && { dir=$2; shift 2; }
if [ "${1:-}" = archive ]; then
    if [ -n "${STUB_ADVANCE:-}" ]; then
        printf 'advanced\n' >"$dir/tools/advanced.txt"
        "$STUB_REAL_GIT" -C "$dir" add tools/advanced.txt
        "$STUB_REAL_GIT" -C "$dir" commit -q -m advanced
    fi
    printf 'archived %s\n' "$("$STUB_REAL_GIT" -C "$dir" rev-parse "$2^{commit}")" >>"$STUB_GIT_LOG"
fi
exec "$STUB_REAL_GIT" -C "$dir" "$@"
SH
chmod +x "$stubs/git" "$stubs/swift" "$stubs/go" "$stubs/curl" "$stubs/uname"

run() { # DIR-argument and extra args; stdout to $tmp/out, stderr to $tmp/err, status to $status
    : >"$log"
    : >"$gitlog"
    (cd "$tmp" && PATH="$stubs:$PATH" STUB_REAL_GIT="$real_git" STUB_GIT_LOG="$gitlog" STUB_LOG="$log" STUB_FIX="$fix" HANDSAL_VITNI_REPO="$vitni" sh "$script" "$@") >"$tmp/out" 2>"$tmp/err"
    status=$?
}
is_status() { [ "$status" = "$1" ]; }
not_status_0() { [ "$status" != 0 ]; }

# --- the script exists and holds no second copy of the names -----------------------------------------------
check "the script exists" test -f "$here/build-macos.sh"
for n in $closed vitni-verify cpython "$vitni_commit"; do
    check "the script has no copy of $n" lacks_fixed "$n" "$here/build-macos.sh"
done

# --- a stub run ---------------------------------------------------------------------------------------------
run "$tmp/out1"
cp "$log" "$tmp/log1"
cp "$tmp/out" "$tmp/lines1"
check "a stub run exits 0 (err: $(tail -n 4 "$tmp/err" 2>/dev/null))" is_status 0
check "the directory holds exactly the closed list" same_text "$(ls -1 "$tmp/out1" 2>/dev/null | LC_ALL=C sort)" "$(printf '%s\n' "$closed" | LC_ALL=C sort)"
check "stdout is the lines artifact_hashes prints for that directory" same_text "$(cat "$tmp/out")" "$(py "$repo/tools/artifact_hashes.py" --release "$tmp/out1" --platform macos-arm64 2>/dev/null)"
check "stdout has one line per name of the closed list" same_text "$(wc -l <"$tmp/out" | tr -d ' ')" "$(printf '%s\n' "$closed" | wc -l | tr -d ' ')"
check "it prints the commit it built from, on stderr" has_fixed "$repo_head" "$tmp/err"
check "it prints the vitni commit and where it comes from" has_fixed "vitni commit $vitni_commit from $vitni" "$tmp/err"
swift_log=$(grep '^swift ' "$log" 2>/dev/null)
check "it builds the Swift products of the list, each once" same_text "$(printf '%s\n' "$swift_log" | sed -e 's/.*--product \([^ ]*\).*/\1/' | LC_ALL=C sort)" "$swift_products"
check "every Swift build is release with -Xswiftc -gnone" same_text "$(printf '%s\n' "$swift_log" | grep -c -e '-c release' | tr -d ' ')" "$(printf '%s\n' "$swift_products" | wc -l | tr -d ' ')"
check "every Swift build has -Xswiftc -gnone" same_text "$(printf '%s\n' "$swift_log" | grep -c -e '-Xswiftc -gnone' | tr -d ' ')" "$(printf '%s\n' "$swift_products" | wc -l | tr -d ' ')"
check "vitni is built from the commit of the one source file" has_fixed "go-cwd-head $vitni_commit" "$log"
check "vitni is built with -trimpath" has_fixed "-trimpath" "$log"
check "vitni is built for darwin and arm64" has_fixed "env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0" "$log"
check "vitni is built by the one build command, not by a go call of this script" lacks_fixed "go build" "$here/build-macos.sh"
check "the script holds no vitni build flag" lacks_fixed "-buildvcs" "$here/build-macos.sh"
check "the script calls the one vitni build command" has_fixed "build-vitni.sh" "$here/build-macos.sh"
check "the refusals live in the shared library, not in the script" lacks_fixed 'refuse "the tree has' "$here/build-macos.sh"
check "the script sources the shared library" has_fixed "release-lib.sh" "$here/build-macos.sh"
check "the interpreter archive is fetched with curl -f" has "^curl -f.*install_only" "$log"
check "the notices archive is fetched with curl -f" has "^curl -f.*pgo" "$log"
check "the launcher is executable" test -x "$tmp/out1/handsal-check"
check "the Swift copies are executable" test -x "$tmp/out1/handsal-sign"

# an existing empty directory is fine
mkdir "$tmp/empty"
run "$tmp/empty"
check "an empty existing directory is accepted" is_status 0

# --- refusals: nothing is built -----------------------------------------------------------------------------
refused() { # name, status check, then the log must have no build
    check "$1: refused with status 2" is_status 2
    check "$1: nothing on stdout" is_empty "$tmp/out"
    check "$1: no tool was run" is_empty "$log"
    check "$1: it says why" test -s "$tmp/err"
}

mkdir "$tmp/full" && : >"$tmp/full/x"
run "$tmp/full"
refused "a directory that is not empty"
check "a directory that is not empty keeps its file" test -f "$tmp/full/x"

run -x
refused "an argument that starts with a dash"
run --help
refused "--help"
run "-$tmp/dashdir"
refused "a path whose first character is a dash"
run
refused "no argument"
run "$tmp/a" "$tmp/b"
refused "two arguments"
check "no directory was made by a refusal" test ! -e "$tmp/a"

printf 'changed\n' >>"$repo/checker/python/packaging/launcher.py"
run "$tmp/dirty1"
refused "a tracked file changed"
check "a dirty tree makes no directory" test ! -e "$tmp/dirty1"
git -C "$repo" checkout -q -- .

printf 'x\n' >>"$repo/.gitignore"
run "$tmp/dirty0"
refused "a tracked file changed outside the build inputs"
git -C "$repo" checkout -q -- .

printf 'x\n' >"$repo/tools/stray.txt"
run "$tmp/dirty2"
refused "an untracked file among the inputs"
rm -f "$repo/tools/stray.txt"

printf 'x\n' >"$repo/.stray"
run "$tmp/dirty3"
check "a stray file outside the build inputs does not block" is_status 0
rm -f "$repo/.stray"

STUB_ARCH=x86_64; export STUB_ARCH
run "$tmp/arch"
unset STUB_ARCH
refused "an Intel machine"
check "an Intel machine makes no directory" test ! -e "$tmp/arch"

# --- the running scripts come from the working tree: a local edit hidden from git is refused ------------------
printf '# local edit\n' >>"$repo/tools/release/release-lib.sh"
git -C "$repo" update-index --assume-unchanged tools/release/release-lib.sh
run "$tmp/hidden1"
refused "an edited library hidden with assume-unchanged"
check "it names the library and the commit" has_fixed "release-lib.sh differs from commit $repo_head" "$tmp/err"
git -C "$repo" update-index --no-assume-unchanged tools/release/release-lib.sh
git -C "$repo" checkout -q -- .
printf '# local edit\n' >>"$repo/tools/release/build-macos.sh"
git -C "$repo" update-index --skip-worktree tools/release/build-macos.sh
run "$tmp/hidden2"
refused "an edited entry script hidden with skip-worktree"
check "it names the script and the commit" has_fixed "build-macos.sh differs from commit $repo_head" "$tmp/err"
git -C "$repo" update-index --no-skip-worktree tools/release/build-macos.sh
git -C "$repo" checkout -q -- .

# --- the commit of the vitni source: one file, read before anything is built --------------------------------
with_commit_file() { # label, content ("@absent" removes the file); commits it in the fixture, runs, puts it back
    if [ "$2" = @absent ]; then
        git -C "$repo" rm -q tools/release/vitni-commit
    else
        printf '%s' "$2" >"$repo/tools/release/vitni-commit"
    fi
    git -C "$repo" commit -q -a -m "vitni-commit: $1"
    run "$tmp/vc"
    git -C "$repo" reset -q --hard HEAD~1
}
with_commit_file "empty" ""
refused "an empty vitni commit file"
with_commit_file "blank line" "
"
refused "a vitni commit file with only a newline"
with_commit_file "short" "aac4c70
"
refused "an abbreviated vitni commit"
with_commit_file "39 digits" "aac4c709500ca0734d7e00db66c6c9edf6a006a
"
refused "a 39-digit vitni commit"
with_commit_file "upper case" "AAC4C709500CA0734D7E00DB66C6C9EDF6A006A6
"
refused "an upper case vitni commit"
with_commit_file "two lines" "$vitni_commit
$vitni_commit
"
refused "a vitni commit file with two lines"
with_commit_file "a branch name" "main
"
refused "a branch name instead of a commit"
with_commit_file "absent" "@absent"
refused "no vitni commit file"
check "a refused vitni commit file makes no directory" test ! -e "$tmp/vc"

with_commit_file "not in vitni" "0123456789abcdef0123456789abcdef01234567
"
check "a commit the vitni repository does not hold fails the script" not_status_0
check "a missing vitni commit prints nothing to publish" is_empty "$tmp/out"
check "a missing vitni commit builds no vitni" lacks_fixed "go " "$log"
rm -rf "$tmp/vc"

# --- one object, one source ---------------------------------------------------------------------------------
# HEAD moves between the moment the script names the commit and the moment it archives: what was archived
# must still be the commit it printed.
STUB_ADVANCE=1; export STUB_ADVANCE
run "$tmp/moved"
unset STUB_ADVANCE
printed=$(sed -n 's/^build-macos: building from handsal commit \([0-9a-f]*\),.*/\1/p' "$tmp/err")
check "HEAD did move during the run" test "$(git -C "$repo" rev-parse HEAD)" != "$repo_head"
check "the run still succeeds" is_status 0
check "the commit it printed is the commit whose tree was archived" same_text "archived $printed" "$(cat "$gitlog")"
check "the printed commit is the one named before HEAD moved" same_text "$printed" "$repo_head"
git -C "$repo" reset -q --hard "$repo_head"
rm -rf "$tmp/moved"

# The vitni commit is read from the archived commit. An edit that is not committed is refused ...
later=$(git -C "$vitni" rev-parse HEAD)
printf '%s\n' "$later" >"$repo/tools/release/vitni-commit"
run "$tmp/edited"
refused "an uncommitted edit of the vitni commit file"
# ... and with that refusal and the status checks planted away, it still cannot change what is built.
lib=$repo/tools/release/release-lib.sh
cp "$lib" "$tmp/release-lib.orig"
plant "$lib" 'rl_refuse "the tree has tracked changes"' ':'
plant "$lib" 'rl_refuse "the tree has untracked files among the build inputs"' ':'
plant "$lib" 'rl_refuse "$1 differs from commit' ': "$1 differs from commit'
check "the planted library differs from the original" test "$(cksum <"$lib")" != "$(cksum <"$tmp/release-lib.orig")"
check "the planted library has no status refusal" lacks_fixed 'refuse "the tree has' "$lib"
run "$tmp/edited2"
cp "$tmp/release-lib.orig" "$lib"
check "with the status refusals planted away the build runs" is_status 0
check "an uncommitted vitni commit edit does not change what is built" has_fixed "go-cwd-head $vitni_commit" "$log"
check "an uncommitted vitni commit edit is not what is built" lacks_fixed "go-cwd-head $later" "$log"
check "it says it built the archived vitni commit" has_fixed "vitni commit $vitni_commit from" "$tmp/err"
git -C "$repo" checkout -q -- .

# --- a failing build says so and prints no line to publish -------------------------------------------------
STUB_FAIL=handsal-link; export STUB_FAIL
run "$tmp/fail1"
unset STUB_FAIL
check "a failing Swift build fails the script with status 1" is_status 1
check "the failing Swift build did run" has "^swift .*--product handsal-link" "$log"
check "a failing Swift build prints nothing to publish" is_empty "$tmp/out"
check "a failing Swift build says the directory is partial" has "partial build" "$tmp/err"

STUB_BAD_ARCHIVE=1; export STUB_BAD_ARCHIVE
run "$tmp/fail2"
unset STUB_BAD_ARCHIVE
check "an archive that is not the pinned one fails with status 1" is_status 1
check "the archive was fetched before it failed" has "^curl -f.*install_only" "$log"
check "the refusal names the pinned archive" has "is not the pinned interpreter archive" "$tmp/err"
check "an archive that is not the pinned one prints nothing to publish" is_empty "$tmp/out"

# --- the build reads what git holds, not what the working tree holds ----------------------------------------
printf 'ignored\n' >"$repo/checker/python/src/handsal_check/stray_ignored.txt"
check "the fixture ignores the stray file" test -z "$(git -C "$repo" status --porcelain --ignored=no)"
run "$tmp/stray"
check "an ignored file in the source tree does not stop the build" is_status 0
check "an ignored file in the source tree is not in the zipapp" cmp -s "$tmp/out1/handsal-check.pyz" "$tmp/stray/handsal-check.pyz"
check "Swift is not built inside the working tree" lacks_fixed "swift-cwd $repo/" "$log"
rm -f "$repo/checker/python/src/handsal_check/stray_ignored.txt"

# --- the gate runs on the finished set, and its failure stops the release ------------------------------------
check "the gate runs for this platform on the set" has_fixed "gate macos-arm64 out1" "$tmp/log1"
check "the gate gets one published line per name of the set" same_text "$(grep '^gate-lines' "$tmp/log1" | cut -d' ' -f2)" "$(wc -l <"$tmp/lines1" | tr -d ' ')"
check "the gate sees the whole set" same_text "$(grep '^gate-saw' "$tmp/log1" | cut -d' ' -f2)" "$(ls -1 "$tmp/out1" | wc -l | tr -d ' ')"
check "the script holds no scan of its own" lacks_fixed "trivy" "$here/build-macos.sh"
STUB_GATE_FAIL=1; export STUB_GATE_FAIL
run "$tmp/gatefail"
unset STUB_GATE_FAIL
check "a failing gate fails the script with status 1" is_status 1
check "the gate did run" has_fixed "gate macos-arm64" "$log"
check "a failing gate prints nothing to publish" is_empty "$tmp/out"
check "a failing gate says why" has_fixed "stub finding" "$tmp/err"


printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" = 0 ]
