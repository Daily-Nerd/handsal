#!/bin/sh
# Tests of the one vitni build command (T15.10, SG-15, CF-05). No real build: `go` is a stand-in first on PATH
# that logs the environment and the arguments it was given and writes a small file where the real one would.
# The script runs from a copy in a throwaway directory next to a fixture `vitni-commit` and `go-version`.
# Run:  sh tools/release/test-build-vitni.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/handsal-vitni-test.XXXXXX") || exit 2
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
not_status_0() { [ "$status" != 0 ]; }

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

# --- fixtures -----------------------------------------------------------------------------------------------
origin=$tmp/vitni-origin
mkdir -p "$origin/go/cmd/vitni-verify"
printf 'package main\n' >"$origin/go/cmd/vitni-verify/main.go"
git -C "$origin" init -q && git -C "$origin" add -A && git -C "$origin" commit -q -m "vitni fixture"
commit=$(git -C "$origin" rev-parse HEAD)
printf 'later\n' >"$origin/later.txt"
git -C "$origin" add -A && git -C "$origin" commit -q -m "a later commit"

dir=$tmp/release
mkdir -p "$dir"
cp "$here/build-vitni.sh" "$dir/" 2>/dev/null
script=$dir/build-vitni.sh
printf '%s\n' "$commit" >"$dir/vitni-commit"
printf '1.25.1\n' >"$dir/go-version"

stubs=$tmp/stubs
log=$tmp/stub.log
mkdir -p "$stubs" "$tmp/tmpdir" "$tmp/out"
# The build runs under `env -i`, so the stand-in cannot read STUB_* variables: its log and control files are
# written into it. Control: $ctl/go_version (what `go version` reports), $ctl/fail (the build fails).
ctl=$tmp/ctl
mkdir -p "$ctl"
# The stand-in carries its paths in its first lines: the build runs under `env -i`, so it cannot read them from
# the environment, and nothing edits the text afterwards.
{
    printf "#!/bin/sh\nLOG='%s'\nCTL='%s'\nGIT='%s'\n" "$log" "${ctl:-}" "${real_git:-}"
    cat <<'SH'
envnames() { env | cut -d= -f1 | while read -r n; do printf 'envname %s\n' "$n"; done >>"$LOG"; }
if [ "${1:-}" = version ]; then
    if [ -f "$CTL/go_version" ]; then v=$(cat "$CTL/go_version"); else v=${GOTOOLCHAIN:-none}; fi
    printf 'go version %s linux/amd64\n' "$v"
    printf 'go-version-toolchain %s\n' "${GOTOOLCHAIN:-}" >>"$LOG"
    envnames
    exit 0
fi
printf 'go %s\n' "$*" >>"$LOG"
printf 'go-cwd-head %s\n' "$(git rev-parse HEAD)" >>"$LOG"
for v in GOOS GOARCH CGO_ENABLED GOTOOLCHAIN GOENV GOFLAGS GOWORK GOAMD64 GOEXPERIMENT GOARM64 GOFIPS140; do
    eval "val=\${$v-UNSET}"
    printf 'env %s=%s\n' "$v" "$val" >>"$LOG"
done
envnames
out=
while [ $# -gt 0 ]; do
    [ "$1" = -o ] && out=$2
    shift
done
[ -f "$CTL/fail" ] && exit 1
printf 'vitni stub\n' >"$out"
SH
} >"$stubs/go"
chmod +x "$stubs/go"

run() { # arguments of the script; stdout to $tmp/out.txt, stderr to $tmp/err.txt, status to $status
    : >"$log"
    (cd "$tmp" && PATH="$stubs:$PATH" STUB_LOG="$log" TMPDIR="$tmp/tmpdir" HANDSAL_VITNI_REPO="$origin" \
        sh "$script" "$@") >"$tmp/out.txt" 2>"$tmp/err.txt"
    status=$?
}
refused() { # name: status 2, nothing on stdout, no tool run, a reason on stderr
    check "$1: refused with status 2" is_status 2
    check "$1: nothing on stdout" is_empty "$tmp/out.txt"
    check "$1: no tool was run" is_empty "$log"
    check "$1: it says why" test -s "$tmp/err.txt"
    check "$1: and does not call a refusal a failure" lacks_fixed "failed" "$tmp/err.txt"
}

# --- the script exists, the flags and the pins live in one place ----------------------------------------------
check "the script exists" test -f "$here/build-vitni.sh"
check "the script has no copy of the vitni commit" lacks_fixed "$commit" "$script"
check "the script has no copy of the go version" lacks_fixed "1.25.1" "$script"
check "the script holds the no-vcs flag" has_fixed "-buildvcs=false" "$script"
check "the script holds the trimpath flag" has_fixed "-trimpath" "$script"
check "the script holds the no-cgo setting" has_fixed "CGO_ENABLED=0" "$script"
check "the repo has a go-version file of one line" test "$(wc -l <"$here/go-version" | tr -d ' ')" = 1
check "the go-version file holds a full version" grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' "$here/go-version"

# --- a stub run -----------------------------------------------------------------------------------------------
run linux amd64 "$tmp/out/v1"
check "a stub run exits 0 (err: $(tail -n 3 "$tmp/err.txt" 2>/dev/null))" is_status 0
check "it wrote the output file" test -f "$tmp/out/v1"
check "nothing on stdout" is_empty "$tmp/out.txt"
check "go build is run once" same_text "$(grep -c '^go build' "$log")" 1
check "-trimpath" has_fixed "-trimpath" "$log"
check "-buildvcs=false" has_fixed "-buildvcs=false" "$log"
check "the output path is the one asked for" has_fixed "-o $tmp/out/v1" "$log"
check "the package is the verifier command" has_fixed "./cmd/vitni-verify" "$log"
check "go runs in the vitni commit of the pin file" has_fixed "go-cwd-head $commit" "$log"
check "CGO_ENABLED=0" has_fixed "env CGO_ENABLED=0" "$log"
check "GOOS is the first argument" has_fixed "env GOOS=linux" "$log"
check "GOARCH is the second argument" has_fixed "env GOARCH=amd64" "$log"
check "the toolchain is the one of go-version" has_fixed "env GOTOOLCHAIN=go1.25.1" "$log"
check "the toolchain is asked for before the build" has_fixed "go-version-toolchain go1.25.1" "$log"
check "the go env file is ignored" has_fixed "env GOENV=off" "$log"
check "it says the commit it built, and where it came from" has_fixed "vitni commit $commit from $origin" "$tmp/err.txt"
check "it says which go it used" has_fixed "go1.25.1" "$tmp/err.txt"
check "the clone is removed" test -z "$(ls -A "$tmp/tmpdir")"

run darwin arm64 "$tmp/out/v2"
check "darwin arm64 runs" is_status 0
check "GOOS darwin" has_fixed "env GOOS=darwin" "$log"
check "GOARCH arm64" has_fixed "env GOARCH=arm64" "$log"

# What the caller's environment holds must not reach the build: one pin gives one binary. The build runs under
# `env -i` with an allow-list, so a knob of a Go release that does not exist yet cannot reach it either.
: >"$log"
(cd "$tmp" && PATH="$stubs:$PATH" STUB_LOG="$log" TMPDIR="$tmp/tmpdir" HANDSAL_VITNI_REPO="$origin" \
    GOFLAGS=-ldflags=-X=x.y=z GOAMD64=v3 GOEXPERIMENT=boringcrypto GOARM64=v8.2 GOFIPS140=latest GODEBUG=fips140=on \
    GOFUTUREKNOB=1 GOSUMDB=off GONOSUMDB=example.invalid GOPRIVATE=example.invalid GOINSECURE=example.invalid GOROOT=/nonexistent GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=plan9 GOWORK=/nonexistent/go.work \
    sh "$script" linux amd64 "$tmp/out/v3") >"$tmp/out.txt" 2>"$tmp/err.txt"
status=$?
check "a poisoned environment still builds" is_status 0
for name in GOSUMDB GONOSUMDB GOPRIVATE GOINSECURE GOFIPS140 GODEBUG GOFUTUREKNOB GOROOT GOAMD64 GOEXPERIMENT GOARM64 STUB_LOG HANDSAL_VITNI_REPO; do
    check "$name does not reach go" lacks_fixed "envname $name" "$log"
done
check "GOFIPS140 is not set for go" has_fixed "env GOFIPS140=UNSET" "$log"
check "GOFLAGS is set, and empty" has "^env GOFLAGS=$" "$log"
check "GOWORK is off" has_fixed "env GOWORK=off" "$log"
check "the caller's GOTOOLCHAIN does not win" has_fixed "env GOTOOLCHAIN=go1.25.1" "$log"
check "the caller's CGO_ENABLED does not win" has_fixed "env CGO_ENABLED=0" "$log"
check "the caller's GOOS does not win" has_fixed "env GOOS=linux" "$log"
for name in PATH HOME TMPDIR; do
    check "$name reaches go (it needs it)" has_fixed "envname $name" "$log"
done
# a variable of the allow-list that the caller did set is passed on, one it did not set is not invented
: >"$log"
(cd "$tmp" && PATH="$stubs:$PATH" TMPDIR="$tmp/tmpdir" HANDSAL_VITNI_REPO="$origin" GOPROXY=https://proxy.example.invalid \
    HTTPS_PROXY=http://p.example.invalid https_proxy=http://p.example.invalid NO_PROXY=x SSL_CERT_FILE=/nonexistent GOCACHE="$tmp/gocache" \
    sh "$script" linux amd64 "$tmp/out/v4") >"$tmp/out.txt" 2>"$tmp/err.txt"
status=$?
for name in GOPROXY HTTPS_PROXY https_proxy NO_PROXY SSL_CERT_FILE GOCACHE; do
    check "the allow-listed $name reaches go" has_fixed "envname $name" "$log"
done
check "an allow-listed variable the caller did not set is not invented" lacks_fixed "envname GOSUMDB" "$log"

# --- the commit and the go version are read, validated, and printed by one mode -------------------------------
run --commit
check "--commit exits 0" is_status 0
check "--commit prints the commit" same_text "$(cat "$tmp/out.txt")" "$commit"
check "--commit runs no tool" is_empty "$log"
run --commit extra
refused "--commit with an argument"

# --source DIR: the pinned source checked out for a caller that builds it another way (the TypeScript verifier)
run --source "$tmp/src1"
check "--source exits 0" is_status 0
check "--source checks out the pinned commit" same_text "$(git -C "$tmp/src1" rev-parse HEAD 2>/dev/null)" "$commit"
check "--source prints nothing on stdout" is_empty "$tmp/out.txt"
check "--source runs no go" is_empty "$log"
check "--source says where the commit came from" has_fixed "vitni commit $commit from $origin" "$tmp/err.txt"
check "--source leaves nothing in the temporary directory" test -z "$(ls -A "$tmp/tmpdir")"
run --source "$tmp/src1"
refused "--source onto a directory that exists"
run --source
refused "--source without a directory"
run --source "$tmp/a" "$tmp/b"
refused "--source with two directories"
run --source "-$tmp/src2"
refused "--source onto a path that starts with a dash"
run --source "$tmp/nodir/src2"
refused "--source onto a directory whose parent is absent"
printf '%s\n' "0123456789abcdef0123456789abcdef01234567" >"$dir/vitni-commit"
run --source "$tmp/src3"
printf '%s\n' "$commit" >"$dir/vitni-commit"
check "--source of a commit the repository does not hold fails" not_status_0
check "--source of a commit the repository does not hold leaves no directory" test ! -e "$tmp/src3"

with_file() { # file label content ("@absent" removes it), then the arguments of the run
    f=$1 content=$2
    shift 2
    keep=$tmp/keep.$f
    cp "$dir/$f" "$keep"
    if [ "$content" = @absent ]; then rm -f "$dir/$f"; else printf '%s' "$content" >"$dir/$f"; fi
    run "$@"
    cp "$keep" "$dir/$f"
}
for args in "--commit" "linux amd64 $tmp/out/bad"; do
    # shellcheck disable=SC2086
    with_file vitni-commit "" $args
    refused "an empty vitni commit ($args)"
    with_file vitni-commit "
" $args
    refused "a vitni commit that is a newline ($args)"
    with_file vitni-commit "aac4c70
" $args
    refused "an abbreviated vitni commit ($args)"
    with_file vitni-commit "AAC4C709500CA0734D7E00DB66C6C9EDF6A006A6
" $args
    refused "an upper case vitni commit ($args)"
    with_file vitni-commit "$commit
$commit
" $args
    refused "two lines in the vitni commit file ($args)"
    with_file vitni-commit "main
" $args
    refused "a branch name instead of a commit ($args)"
    with_file vitni-commit "@absent" $args
    refused "no vitni commit file ($args)"
done
check "a refused commit file makes no output" test ! -e "$tmp/out/bad"

with_file go-version "" linux amd64 "$tmp/out/bad"
refused "an empty go-version"
with_file go-version "latest
" linux amd64 "$tmp/out/bad"
refused "go-version latest"
with_file go-version "go1.25.1
" linux amd64 "$tmp/out/bad"
refused "go-version with the go prefix"
with_file go-version "1.25
" linux amd64 "$tmp/out/bad"
refused "go-version without a patch number"
with_file go-version "1.25.1
1.25.1
" linux amd64 "$tmp/out/bad"
refused "two lines in go-version"
with_file go-version "@absent" linux amd64 "$tmp/out/bad"
refused "no go-version file"
check "a refused go-version makes no output" test ! -e "$tmp/out/bad"

# --- arguments ------------------------------------------------------------------------------------------------
run
refused "no argument"
run linux amd64
refused "two arguments"
run linux amd64 "$tmp/out/x" extra
refused "four arguments"
run -x amd64 "$tmp/out/x"
refused "GOOS that starts with a dash"
run --help
refused "--help"
run linux -amd64 "$tmp/out/x"
refused "GOARCH that starts with a dash"
run Linux amd64 "$tmp/out/x"
refused "an upper case GOOS"
run "linux/x" amd64 "$tmp/out/x"
refused "a GOOS with a slash"
run linux "" "$tmp/out/x"
refused "an empty GOARCH"
run linux amd64 "-$tmp/out/x"
refused "an output path that starts with a dash"
run linux amd64 ""
refused "an empty output path"
run linux amd64 "$tmp/nodir/x"
refused "an output path whose directory is absent"
run linux amd64 "$tmp/out/v1"
refused "an output file that exists"
check "the existing output is untouched" same_text "$(cat "$tmp/out/v1")" "vitni stub"
ln -s "$tmp/nowhere" "$tmp/out/link"
run linux amd64 "$tmp/out/link"
refused "an output path that is a dangling symlink"

# --- failures say so ------------------------------------------------------------------------------------------
printf 'go1.21.13\n' >"$ctl/go_version"
run linux amd64 "$tmp/out/old"
rm -f "$ctl/go_version"
check "a toolchain that is not the pinned one fails with status 1" is_status 1
check "the toolchain was asked for" has_fixed "go-version-toolchain go1.25.1" "$log"
check "no build ran" lacks_fixed "go build" "$log"
check "no output was made" test ! -e "$tmp/out/old"
check "it names both versions" has_fixed "go1.21.13" "$tmp/err.txt"
check "nothing on stdout" is_empty "$tmp/out.txt"

printf '%s\n' "0123456789abcdef0123456789abcdef01234567" >"$dir/vitni-commit"
run linux amd64 "$tmp/out/missing"
printf '%s\n' "$commit" >"$dir/vitni-commit"
check "a commit the repository does not hold fails" not_status_0
check "no build ran for it" lacks_fixed "go build" "$log"
check "no output for it" test ! -e "$tmp/out/missing"
check "the clone is removed after a failed checkout" test -z "$(ls -A "$tmp/tmpdir")"

: >"$ctl/fail"
run linux amd64 "$tmp/out/failed"
rm -f "$ctl/fail"
check "a failing build fails the script" is_status 1
check "the build did run" has_fixed "go build" "$log"
check "a failing build prints nothing on stdout" is_empty "$tmp/out.txt"
check "a failing build says so" has_fixed "failed" "$tmp/err.txt"
check "the clone is removed after a failed build" test -z "$(ls -A "$tmp/tmpdir")"

printf '%s checks, %s failed\n' "$checks" "$failures"
[ "$failures" = 0 ]
