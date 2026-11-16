#!/bin/sh
# Tests of the PRODK run scripts (T15.10, T8.6, CF-08): prodk.sh, prodk-undo.sh and final-proof.sh. No key, no
# real build, no real signing: uv, go, git, node, npm and cargo are stand-ins first on PATH that answer the way
# the real tool answers and log what they were asked. The scripts run from a copy in a throwaway git repository.
# Run:  sh tools/release/test-prodk.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-prodk-test.XXXXXX") || exit 2
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
absent() { [ ! -e "$1" ]; }
line_of() { grep -n -m1 -F -- "$1" "$2" | cut -d: -f1; } # first line number of a fixed string in a log
before() { # A B LOG: the first A is logged before the first B, and both are there
    a=$(line_of "$1" "$3")
    b=$(line_of "$2" "$3")
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

real_git=$(command -v git)
real_uv=$(command -v uv)
stubs=$tmp/stubs
log=$tmp/stub.log
state=$tmp/state
mkdir -p "$stubs" "$state"

# --- the fixture repository ---------------------------------------------------------------------------------
repo=$tmp/repo
mkdir -p "$repo/tools/release" "$repo/tools/install" "$repo/conformance/vectors/_gen" "$repo/conformance/vectors/groups" \
    "$repo/spec" "$repo/checker/python" "$repo/signer/apple/scripts" "$repo/signer/windows" "$tmp/vitni-origin/go" "$tmp/vitni-origin/ts"
for f in prodk.sh prodk-undo.sh final-proof.sh proof-lib.sh build-vitni.sh go-version; do cp "$root/tools/release/$f" "$repo/tools/release/" 2>/dev/null; done
cp "$root/conformance/vectors/_gen/prodk_evidence.py" "$repo/conformance/vectors/_gen/" 2>/dev/null
git -C "$tmp/vitni-origin" init -q
printf 'package main\n' >"$tmp/vitni-origin/go/main.go"
printf '{}\n' >"$tmp/vitni-origin/ts/package.json"
git -C "$tmp/vitni-origin" add -A && git -C "$tmp/vitni-origin" commit -q -m fixture
vitni_commit=$(git -C "$tmp/vitni-origin" rev-parse HEAD)
printf '%s\n' "$vitni_commit" >"$repo/tools/release/vitni-commit"
# `pending` holds the owner-signed ids and, while fewer than two editions exist, the prf/ ids that wait by rule (CF-08)
printf '{"pending": ["enr/prodk-a", "fix/prodk-b", "fix/prodk-c", "fix/prodk-d", "fix/prodk-e", "fix/prodk-f", "prf/wait-a", "prf/wait-b"]}\n' >"$repo/conformance/vector-ids.json"
printf '{}\n' >"$repo/spec/MANIFEST.json"
cp "$root/tools/check_catalog.py" "$repo/tools/check_catalog.py"
for f in tools/manifest.py tools/repin.py conformance/run.py conformance/vectors/_gen/make_prodk.py \
    conformance/vectors/_gen/generate.py; do printf '# fixture\n' >"$repo/$f"; done
mkdir -p "$repo/checker/python/.venv/bin" "$repo/signer/apple/.build/debug" "$repo/signer/windows/target/debug"
for p in checker/python/.venv/bin/handsal-check-conformance signer/apple/.build/debug/handsal-sign-conformance signer/windows/target/debug/handsal-sign-conformance; do
    printf "#!/bin/sh\n" >"$repo/$p" && chmod +x "$repo/$p"
done
printf "# fixture\n" >"$repo/tools/artifact_hashes.py"
for f in tools/release/test-prodk.sh tools/install/test-install.sh tools/install/test-install-linux.sh tools/release/test-build-macos.sh \
    tools/release/test-build-linux-server.sh tools/release/test-build-vitni.sh signer/apple/scripts/test.sh; do
    printf '#!/bin/sh\necho "%s ran: 1 checks, 0 failed"\n[ -z "${STUB_FAIL_SCRIPT:-}" ] || [ "${STUB_FAIL_SCRIPT}" != "$0" ] || exit 1\n' "$f" >"$repo/$f"
done
printf '[package]\n' >"$repo/signer/windows/Cargo.toml"
printf '.venv/\n.build/\ntarget/\n' >"$repo/.gitignore"
git -C "$repo" init -q && git -C "$repo" add -A && git -C "$repo" commit -q -m fixture
script=$repo/tools/release/prodk.sh

# --- stand-ins ----------------------------------------------------------------------------------------------
cat >"$stubs/uv" <<'SH'
#!/bin/sh
printf 'uv %s\n' "$*" >>"$STUB_LOG"
args=" $* "
prod=$(ls "$PWD/conformance/vectors/prod" 2>/dev/null | wc -l | tr -d ' ')
case $args in
    *" sync "*) exit 0 ;;
    *check_catalog.py*--owner-signed*) exec "$STUB_REAL_UV" "$@" ;;
    *check_catalog.py*--final*)
        if [ "$prod" != 0 ]; then echo "${STUB_FINAL:-0 holes, 0 pending}"; else echo "${STUB_HOLES:-6} holes, 0 pending"; fi ;;
    *check_catalog.py*)
        if [ "$prod" != 0 ]; then echo "0 holes, 0 pending"; else echo "${STUB_BEFORE:-0 holes, 8 pending}"; fi ;;
    *manifest.py*--check*) echo "bundle manifest: ok" ;;
    *manifest.py*--write*) echo "manifest written" ;;
    *manifest.py*) echo "production  uEiFixtureProfile" ;;
    *repin.py*) echo "pins ok" ;;
    *make_prodk.py*)
        out= evidence=
        while [ $# -gt 0 ]; do
            case $1 in --out) out=$2 ;; --evidence) evidence=$2 ;; esac
            shift
        done
        [ -n "${STUB_SIGN_FAIL:-}" ] && { echo "production vectors not written: stub" >&2; exit 1; }
        mkdir -p "$out"
        for n in enr.prodk-a fix.prodk-b fix.prodk-c fix.prodk-d fix.prodk-e fix.prodk-f; do printf '{"id": "%s"}\n' "$n" >"$out/$n.json"; done
        printf '{"created_utc": "2026-12-01T09:30:00Z", "production_profile": "uEiFixtureProfile", "python": "3.13.7", "pid": 1, "people": {"alice": "kA", "bob": "kB", "carol": "kC"}, "files": {"fix.prodk-b.json": "%064d"}, "files_scanned": 10, "scan_roots": ["r"], "scalars_held": 3}\n' 0 >"$evidence"
        echo "signed 6 vectors into $out" ;;
    *conformance/run.py*)
        vec=
        while [ $# -gt 0 ]; do
            [ "$1" = --vectors ] && vec=$2
            shift
        done
        case $vec in
            */stage) [ -n "${STUB_HARNESS_FAIL:-}" ] && echo "6 vectors, 1 not passing" || echo "6 vectors, 0 not passing" ;;
            */prod) echo "6 vectors, 0 not passing" ;;
            *) [ -n "${STUB_HARNESS_ALL_FAIL:-}" ] && echo "951 vectors, 2 not passing" || echo "951 vectors, 0 not passing" ;;
        esac ;;
    *unittest*) echo "Ran 1 test"; echo OK ;;
    *generate.py*) echo "generate: ok" ;;
    *artifact_hashes.py*) echo "0000  handsal-check" ;;
    *) exec "$STUB_REAL_UV" "$@" ;;
esac
SH
# The stand-in carries its paths in its first lines: the build runs under `env -i`, so it cannot read them from
# the environment, and nothing edits the text afterwards.
{
    printf "#!/bin/sh\nLOG='%s'\nCTL='%s'\nGIT='%s'\n" "$log" "${ctl:-}" "${real_git:-}"
    cat <<'SH'
printf 'go %s\n' "$*" >>"$LOG"
if [ "${1:-}" = env ]; then
    printf '%s\n' "${STUB_GOOS:-darwin}" "${STUB_GOARCH:-arm64}"
elif [ "${1:-}" = version ]; then
    printf 'go version %s darwin/arm64\n' "${GOTOOLCHAIN:-none}"
else
    out=
    while [ $# -gt 0 ]; do
        [ "$1" = -o ] && out=$2
        shift
    done
    printf 'vitni go stub\n' >"$out" && chmod +x "$out"
fi
SH
} >"$stubs/go"
cat >"$stubs/npm" <<'SH'
#!/bin/sh
printf 'npm %s (in %s)\n' "$*" "$(pwd)" >>"$STUB_LOG"
if [ "${1:-}" = run ]; then mkdir -p dist && printf 'cli stub\n' >dist/cli.js; fi
[ -n "${STUB_NPM_FAIL:-}" ] && exit 1
exit 0
SH
cat >"$stubs/node" <<'SH'
#!/bin/sh
exit 0
SH
cat >"$stubs/cargo" <<'SH'
#!/bin/sh
printf 'cargo %s\n' "$*" >>"$STUB_LOG"
echo "test result: ok. 3 passed; 0 failed; 0 ignored"
SH
# git: the real one; it logs the subcommand so a test can prove the scripts only read
cat >"$stubs/git" <<'SH'
#!/bin/sh
dir=.
[ "${1:-}" = -C ] && { dir=$2; shift 2; }
case ${1:-} in -c) shift 2 ;; esac
printf 'git %s\n' "${1:-}" >>"$STUB_GIT_LOG"
exec "$STUB_REAL_GIT" -C "$dir" "$@"
SH
chmod +x "$stubs"/*

gitlog=$tmp/git.log
run() { # STDIN-TEXT then arguments
    stdin=$1
    shift
    : >"$log"
    : >"$gitlog"
    (cd "$tmp" && printf '%s\n' "$stdin" | PATH="$stubs:$PATH" STUB_LOG="$log" STUB_GIT_LOG="$gitlog" STUB_REAL_GIT="$real_git" \
        STUB_REAL_UV="$real_uv" HANDSAL_VITNI_REPO="$tmp/vitni-origin" sh "$script" "$@") >"$tmp/out" 2>"$tmp/err"
    status=$?
}
PHRASE="sign production vectors"
refused() { # name: status 2, no tool run, a reason on stderr
    check "$1: refused with status 2" is_status 2
    check "$1: no tool was run" is_empty "$log"
    check "$1: it says why" test -s "$tmp/err"
}
reset_repo() {
    "$real_git" -C "$repo" reset -q --hard HEAD
    rm -rf "$repo/conformance/vectors/prod" "$repo/stray"
}

# --- the scripts exist; nothing in them commits -------------------------------------------------------------
for f in prodk.sh prodk-undo.sh final-proof.sh proof-lib.sh; do
    check "$f exists" test -f "$here/$f"
    for bad in "git commit" "git add" "git push" "git tag" "git reset" "git checkout" "git clean" "git stash" "sudo"; do
        check "$f does not run $bad" lacks_fixed "$bad" "$here/$f"
    done
    check "$f names no machine path" lacks_fixed "/Users/" "$here/$f"
    check "$f names no /tmp kit" lacks_fixed "/tmp/t72" "$here/$f"
    check "$f has no em-dash" lacks_fixed "$(printf '\342\200\224')" "$here/$f"
done
check "prodk.sh builds the Go verifier through the one build command" has_fixed "build-vitni.sh" "$here/prodk.sh"
check "prodk.sh holds no vitni build flag" lacks_fixed "-buildvcs" "$here/prodk.sh"
check "prodk.sh holds no go build" lacks_fixed "go build" "$here/prodk.sh"

# --- the whole run ------------------------------------------------------------------------------------------
out1=$tmp/run1
run "$PHRASE" --task T8.6 "$out1"; true
check "a run exits 0 (err: $(tail -n 3 "$tmp/err" 2>/dev/null))" is_status 0
check "the six vectors are in the tree" same_text "$(ls "$repo/conformance/vectors/prod" | wc -l | tr -d ' ')" 6
check "the Go verifier was built by the command, for the machine's platform" has_fixed "go env GOOS" "$log"
check "the Go verifier is in the output directory" test -f "$out1/vitni/vitni-verify-go"
check "the TypeScript verifier was installed from the lock file" has_fixed "npm ci" "$log"
check "the TypeScript verifier was built in the pinned source" has "^npm run build (in $out1/vitni/src/ts)" "$log"
check "the pinned source is the vitni commit" same_text "$(git -C "$out1/vitni/src" rev-parse HEAD)" "$vitni_commit"
check "the signer got the Go verifier" has_fixed "--vitni-go $out1/vitni/vitni-verify-go" "$log"
check "the signer got the TypeScript verifier" has "make_prodk.py.*--vitni-ts .*node.* $out1/vitni/src/ts/dist/cli.js" "$log"
check "the staged harness ran the TypeScript verifier" has "run.py --vectors $out1/stage .*--vitni $stubs/node --vitni $out1/vitni/src/ts/dist/cli.js" "$log"
check "the final proof was run, after the proof of the installed files" has "unittest discover -s tools/tests" "$log"
check "the signer scans the conformance and spec trees" has_fixed "--scan-root $repo/conformance --scan-root $repo/spec" "$log"
check "the signer writes to a stage in the output directory" has_fixed "--out $out1/stage" "$log"
check "the report is in the output directory" test -f "$out1/evidence/prodk-evidence.json"
check "the bundle manifest was rewritten" has_fixed "manifest.py --write" "$log"
check "the evidence note is in the output directory" test -f "$out1/evidence/prodk-evidence.md"
check "the note names the task it was given" has "^task: T8.6$" "$out1/evidence/prodk-evidence.md"
check "the note holds the harness line of the run" has_fixed "6 vectors, 0 not passing" "$out1/evidence/prodk-evidence.md"
check "the note holds the final proof line of the run" has "RESULT: final proof passed" "$out1/evidence/prodk-evidence.md"
check "the note names the commit of the tree" has_fixed "$("$real_git" -C "$repo" rev-parse HEAD)" "$out1/evidence/prodk-evidence.md"
check "the note holds no earlier task" lacks_fixed "T7.2" "$out1/evidence/prodk-evidence.md"
check "the last line says the keys are destroyed" has "DONE. The production signing keys have been destroyed" "$tmp/out"
check "the order is: Go verifier, TypeScript verifier, sign, install, proof, final proof" same_text \
    "$(before 'go version' 'npm ci' "$log" && before 'npm run build' 'make_prodk.py' "$log" && before 'make_prodk.py' 'conformance/run.py' "$log" && before 'conformance/run.py' 'manifest.py --write' "$log" && before 'manifest.py --write' 'check_catalog.py --final' "$log" && before 'check_catalog.py --final' 'unittest' "$log" && echo yes)" yes
check "the final proof ran with both verifiers" has_fixed "conformance/run.py --role checker" "$log"
check "it only read git of the repository (the one checkout is the vitni clone)" same_text \
    "$(sort -u "$gitlog" | grep -Ev '^git (rev-parse|status|ls-files|clone|checkout)$' | tr '\n' ' ')" ""
check "git was not asked to change anything" same_text "$(grep -Ec '^git (commit|add|push|tag|reset|clean|stash|rm|mv|merge|rebase|apply)$' "$gitlog")" 0
check "the tree has no tracked change but the manifest the stub rewrote" same_text "$("$real_git" -C "$repo" status --porcelain --untracked-files=no | wc -l | tr -d ' ')" 0

# without --task the note has no task row
reset_repo
out2=$tmp/run2
run "$PHRASE" "$out2"
check "a run without --task exits 0" is_status 0
check "the note has no task row" lacks_fixed "task:" "$out2/evidence/prodk-evidence.md"

# --- refusals: nothing runs ---------------------------------------------------------------------------------
reset_repo
run "$PHRASE"
refused "no argument"
run "$PHRASE" "$tmp/a" "$tmp/b"
refused "two directories"
run "$PHRASE" -x
refused "a directory that starts with a dash"
run "$PHRASE" --help
refused "--help"
run "$PHRASE" --task
refused "--task without a value"
run "$PHRASE" --task "T8.6; x" "$tmp/badtask"
refused "a task id with a shell character"
check "a refusal makes no directory" absent "$tmp/badtask"
run "$PHRASE" "$repo/out"
refused "an output directory inside the repository"
check "it says why" has_fixed "inside the repository" "$tmp/err"
check "nothing was made inside the repository" absent "$repo/out"
run "$PHRASE" "$repo/deeper/out"
refused "an output directory below a new directory inside the repository"
check "no directory was made for it" absent "$repo/deeper"
run "$PHRASE" "$repo"
refused "the repository itself"
run "$PHRASE" "$out1"
refused "an output directory of an earlier run"
check "the earlier run is named as the reason" has_fixed "earlier run" "$tmp/err"
check "the earlier note is untouched" test -f "$out1/evidence/prodk-evidence.md"
printf 'changed\n' >>"$repo/spec/MANIFEST.json"
run "$PHRASE" "$tmp/dirty"
refused "a tracked file changed"
check "a dirty tree makes no directory" absent "$tmp/dirty"
reset_repo
mkdir -p "$repo/conformance/vectors/prod" && printf '{}\n' >"$repo/conformance/vectors/prod/x.json"
run "$PHRASE" "$tmp/signed"
refused "a production directory that already holds vectors"
check "it says the keys sign once" has_fixed "sign once" "$tmp/err"
check "the vectors are untouched" test -f "$repo/conformance/vectors/prod/x.json"
reset_repo
printf 'x\n' >"$repo/tools/stray.txt"
run "$PHRASE" "$tmp/stray"
refused "an untracked file among the inputs"
rm -f "$repo/tools/stray.txt"
printf 'x\n' >"$repo/.stray"
run "$PHRASE" "$tmp/okstray"
check "a stray file outside the inputs does not block" is_status 0
rm -f "$repo/.stray"
reset_repo

# --- stops before the keys exist ----------------------------------------------------------------------------
printf '{"pending": []}\n' >"$repo/conformance/vector-ids.json"
"$real_git" -C "$repo" commit -q -a -m "no pending id"
run "$PHRASE" "$tmp/pre0"
"$real_git" -C "$repo" reset -q --hard HEAD~1
check "with nothing pending the run stops" is_status 1
check "it says there is nothing to sign" has_fixed "nothing to sign" "$tmp/err"
check "and signs nothing" lacks_fixed "make_prodk.py" "$log"

STUB_BEFORE="1 holes, 6 pending"; export STUB_BEFORE
run "$PHRASE" "$tmp/pre1"
unset STUB_BEFORE
check "a catalog that is is not 0 holes stops the run" is_status 1
check "the stop says STOP" has_fixed "STOP" "$tmp/err"
check "nothing was signed" lacks_fixed "make_prodk.py" "$log"
check "no vector was installed" absent "$repo/conformance/vectors/prod"

run "not the phrase" "$tmp/pre2"
check "a wrong phrase stops the run with status 1" is_status 1
check "it says nothing was done" has_fixed "not confirmed; nothing was done" "$tmp/err"
check "a wrong phrase signs nothing" lacks_fixed "make_prodk.py" "$log"
run "" "$tmp/pre3"
check "an empty answer stops the run" is_status 1
check "an empty answer signs nothing" lacks_fixed "make_prodk.py" "$log"

STUB_NPM_FAIL=1; export STUB_NPM_FAIL
run "$PHRASE" "$tmp/pre4"
unset STUB_NPM_FAIL
check "a failing TypeScript build stops the run before the keys" is_status 1
check "a failing TypeScript build signs nothing" lacks_fixed "make_prodk.py" "$log"

# --- stops after the keys exist, before the install ---------------------------------------------------------
STUB_SIGN_FAIL=1; export STUB_SIGN_FAIL
run "$PHRASE" "$tmp/sign1"
unset STUB_SIGN_FAIL
check "a signing failure exits 1" is_status 1
check "a signing failure ran the signer" has_fixed "make_prodk.py" "$log"
check "a signing failure installs nothing" absent "$repo/conformance/vectors/prod"
check "a signing failure says no key exists" has_fixed "no key exists" "$tmp/err"
check "a signing failure writes no note" absent "$tmp/sign1/evidence/prodk-evidence.md"

STUB_HARNESS_FAIL=1; export STUB_HARNESS_FAIL
run "$PHRASE" "$tmp/stage1"
unset STUB_HARNESS_FAIL
check "a staged vector that does not pass exits 1" is_status 1
check "the signer ran" has_fixed "make_prodk.py" "$log"
check "the stage is removed" absent "$tmp/stage1/stage"
check "the report is removed" absent "$tmp/stage1/evidence/prodk-evidence.json"
check "nothing was installed" absent "$repo/conformance/vectors/prod"
check "the manifest was not rewritten" lacks_fixed "manifest.py --write" "$log"
check "it says the vectors were removed and no key exists" has_fixed "No key exists" "$tmp/err"

# --- stops after the install: the files stay, the owner is told to undo ------------------------------------
STUB_FINAL="0 holes, 3 pending"; export STUB_FINAL
run "$PHRASE" "$tmp/post1"
unset STUB_FINAL
check "a failing proof after the install exits 1" is_status 1
check "the six vectors are still in the tree" same_text "$(ls "$repo/conformance/vectors/prod" | wc -l | tr -d ' ')" 6
check "it says not to commit" has_fixed "Do not commit" "$tmp/err"
check "it names the undo script" has_fixed "prodk-undo.sh" "$tmp/err"
check "no note was written" absent "$tmp/post1/evidence/prodk-evidence.md"
check "the final proof did not run" lacks_fixed "unittest" "$log"
reset_repo

STUB_FAIL_SCRIPT=tools/install/test-install.sh; export STUB_FAIL_SCRIPT
run "$PHRASE" "$tmp/post2"
unset STUB_FAIL_SCRIPT
check "a failing final proof exits 1" is_status 1
check "the six vectors are still in the tree after a failing final proof" same_text "$(ls "$repo/conformance/vectors/prod" | wc -l | tr -d ' ')" 6
check "a failing final proof writes no note" absent "$tmp/post2/evidence/prodk-evidence.md"
check "a failing final proof says do not commit" has_fixed "Do not commit" "$tmp/err"
reset_repo

# --- the undo script ----------------------------------------------------------------------------------------
undo=$repo/tools/release/prodk-undo.sh
undo_run() {
    : >"$log"
    (cd "$tmp" && PATH="$stubs:$PATH" STUB_LOG="$log" STUB_GIT_LOG="$gitlog" STUB_REAL_GIT="$real_git" STUB_REAL_UV="$real_uv" sh "$undo" "$@") >"$tmp/out" 2>"$tmp/err"
    status=$?
}
mkdir -p "$repo/conformance/vectors/prod" && printf '{}\n' >"$repo/conformance/vectors/prod/x.json"
undo_run
check "undo exits 0" is_status 0
check "undo removes the production vectors" absent "$repo/conformance/vectors/prod"
check "undo rewrites the manifest" has_fixed "manifest.py --write" "$log"
check "undo prints the catalog line" has_fixed "0 holes, 8 pending" "$tmp/out"
undo_run
check "undo with nothing to undo exits 0 and says so" is_status 0
check "undo with nothing to undo says so" has_fixed "nothing to undo" "$tmp/out"
mkdir -p "$repo/conformance/vectors/prod" && printf '{}\n' >"$repo/conformance/vectors/prod/x.json"
"$real_git" -C "$repo" add conformance/vectors/prod && "$real_git" -C "$repo" commit -q -m "committed vectors"
undo_run
check "undo refuses vectors that are committed" is_status 2
check "undo leaves committed vectors" test -f "$repo/conformance/vectors/prod/x.json"
check "undo runs nothing when it refuses" is_empty "$log"
check "undo says why" has_fixed "committed" "$tmp/err"
undo_run extra
check "undo takes no argument" is_status 2
"$real_git" -C "$repo" reset -q --hard HEAD~1
rm -rf "$repo/conformance/vectors/prod"

# --- the final proof on its own -----------------------------------------------------------------------------
proof_run() { # arguments of final-proof.sh
    : >"$log"
    (cd "$tmp" && PATH="$stubs:$PATH" STUB_LOG="$log" STUB_GIT_LOG="$gitlog" STUB_REAL_GIT="$real_git" STUB_REAL_UV="$real_uv" \
        sh "$repo/tools/release/final-proof.sh" "$@") >"$tmp/out" 2>"$tmp/err"
    status=$?
}
mkproof() { # DIR: an output directory the way prodk.sh leaves it
    mkdir -p "$1/vitni/src/ts/dist" && : >"$1/vitni/vitni-verify-go" && chmod +x "$1/vitni/vitni-verify-go"
    : >"$1/vitni/src/ts/dist/cli.js"
}
mkdir -p "$repo/conformance/vectors/prod" && printf '{}\n' >"$repo/conformance/vectors/prod/x.json"
mkproof "$tmp/fp1"
proof_run "$tmp/fp1"
check "the final proof exits 0 (out: $(tail -n 3 "$tmp/out" 2>/dev/null))" is_status 0
check "the last line says it passed" has "^RESULT: final proof passed (after the PRODK run), commit " "$tmp/out"
for step in tools-tests checker-tests conformance-tests gen-tests generate-check manifest-check repin-check catalog-final \
    catalog harness-checker swift-tests harness-signer-swift rust-core-tests installer-tests installer-linux-tests \
    release-macos-tests release-linux-tests release-vitni-tests prodk-script-tests release-hashes-twice; do
    check "the final proof runs $step" has "^$step " "$tmp/out"
done
check "each step has its own log" test -s "$tmp/fp1/proof/01-tools-tests.log"
check "the harness runs with both verifiers" has_fixed "--vitni $tmp/fp1/vitni/vitni-verify-go" "$log"
check "the harness runs with the TypeScript verifier" has_fixed "$tmp/fp1/vitni/src/ts/dist/cli.js" "$log"
check "the final proof changes nothing in the tree" same_text "$("$real_git" -C "$repo" status --porcelain --untracked-files=no | wc -l | tr -d ' ')" 0

mkproof "$tmp/fp2"
STUB_HARNESS_ALL_FAIL=1; export STUB_HARNESS_ALL_FAIL
proof_run "$tmp/fp2"
unset STUB_HARNESS_ALL_FAIL
check "a harness that does not pass fails the proof" is_status 1
check "the failure is on the harness line" has "^harness-checker .*not ok" "$tmp/out"
check "the last line says a step failed" has "^RESULT: [0-9][0-9]* step(s) failed" "$tmp/out"

mkproof "$tmp/fp3"
STUB_FAIL_SCRIPT=tools/install/test-install-linux.sh; export STUB_FAIL_SCRIPT
proof_run "$tmp/fp3"
unset STUB_FAIL_SCRIPT
check "a failing script fails the proof" is_status 1
check "the failure is on the installer line" has "^installer-linux-tests .*not ok" "$tmp/out"

mkproof "$tmp/fp4"
STUB_FINAL="0 holes, 2 pending"; export STUB_FINAL
proof_run "$tmp/fp4"
unset STUB_FINAL
check "a catalog that is not 0 holes, 0 pending fails the proof after the run" is_status 1
check "the failure is on the catalog line" has "^catalog-final .*not ok" "$tmp/out"

rm -rf "$repo/conformance/vectors/prod"
mkproof "$tmp/fp5"
proof_run --before-prodk "$tmp/fp5"
check "before the run the catalog must show the six holes" is_status 0
check "before the run the last line says so" has "^RESULT: final proof passed (before the PRODK run), commit " "$tmp/out"

# the number of holes before the run is the number of pending ids, read from the catalog source, not a literal
printf '{"pending": ["a", "b", "c"]}\n' >"$repo/conformance/vector-ids.json"
mkproof "$tmp/fp6"
STUB_HOLES=3; export STUB_HOLES
proof_run --before-prodk "$tmp/fp6"
unset STUB_HOLES
check "with three pending ids the tag check before the run expects 3 holes" is_status 0
check "and says so" has_fixed "3 holes, 0 pending" "$tmp/out"
mkproof "$tmp/fp7"
proof_run --before-prodk "$tmp/fp7"
check "with three pending ids and six holes it fails" is_status 1
"$real_git" -C "$repo" checkout -q -- conformance/vector-ids.json
proof_run "$tmp/fp1"
check "an output directory with a proof of an earlier run is refused" is_status 2
check "an earlier proof is named" has_fixed "earlier run" "$tmp/err"
check "an earlier proof ran nothing" is_empty "$log"
proof_run
check "no argument is refused" is_status 2
proof_run "$tmp/nowhere"
check "an output directory without the verifiers is refused" is_status 2
check "a missing output directory ran nothing" is_empty "$log"
proof_run -x
check "a dash argument is refused" is_status 2
proof_run --before-prodk
check "--before-prodk alone is refused" is_status 2
reset_repo

printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" = 0 ]
