#!/bin/sh
# The one command that builds the vitni verifier (SG-15, CF-05, T15.10). The macOS release script, the Linux server
# release script and the Linux CI job all build vitni-verify through this file and no other, so one pin gives one
# binary per platform.
#
#   sh tools/release/build-vitni.sh GOOS GOARCH OUT       build vitni-verify for that platform into the file OUT
#   sh tools/release/build-vitni.sh --commit              print the pinned vitni commit and do nothing else
#   sh tools/release/build-vitni.sh --source DIR          check the pinned source out into the new directory DIR
#                                                         (for a caller that builds it another way, such as the
#                                                         TypeScript verifier of the PRODK run)
#
# Two files next to this script are the pins:
#
#   vitni-commit   the vitni source commit, one 40-digit line
#   go-version     the Go toolchain, one line, three numbers
#
# The binary holds the Go version, so the Go version is a pin like the commit: the toolchain is requested as
# GOTOOLCHAIN=go<go-version>, which Go downloads when the installed one differs, and the script stops when the
# toolchain it got is not that one. The build is cgo-free, with -trimpath and -buildvcs=false (without it a git
# checkout stamps its commit into the binary). The caller's environment cannot move the bytes: Go runs under
# `env -i` with an allow-list, so a build knob of a Go release that does not exist yet (GOFIPS140 was one) never
# reaches it. The list is below with the reason for each name; a name that changes bytes does not belong on it.
#
# The source is cloned from HANDSAL_VITNI_REPO (default https://github.com/Daily-Nerd/vitni) into a temporary
# directory, checked out at the pinned commit, built, and deleted. Only OUT is left. Needs: git, go.
#
# Refused with status 2 and nothing built: a wrong number of arguments, an argument that starts with a dash, a GOOS
# or GOARCH that is not lower case letters and digits, an OUT that exists (a dangling link counts) or whose directory
# does not exist, a pin file that is missing or malformed. Status 1: the toolchain is not the pinned one, the clone,
# the checkout or the build failed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo_url=${HANDSAL_VITNI_REPO:-https://github.com/Daily-Nerd/vitni}
work=

refused=
say() { printf 'build-vitni: %s\n' "$*" >&2; }
refuse() {
    say "refused: $*"
    refused=1
    exit 2
}
cleanup() {
    status=$?
    [ -n "$work" ] && rm -rf "$work"
    if [ "$status" != 0 ] && [ -z "$refused" ]; then say "failed (status $status)"; fi
}
trap cleanup EXIT
trap 'exit 130' INT HUP TERM

# One line, exactly: a file with a second line is not a pin.
one_line() { # FILE REGEX LABEL: print the line, or refuse
    [ -f "$1" ] || refuse "$1 is missing"
    value=$(cat "$1")
    [ "$(wc -l <"$1" | tr -d ' ')" = 1 ] && [ "$(wc -c <"$1" | tr -d ' ')" = $((${#value} + 1)) ] && printf '%s\n' "$value" | grep -Eq "$2" || refuse "$1 is not $3"
    printf '%s\n' "$value"
}
commit=$(one_line "$here/vitni-commit" '^[0-9a-f]{40}$' "one 40-digit commit") || { refused=1; exit 2; }
gover=$(one_line "$here/go-version" '^[0-9]+\.[0-9]+\.[0-9]+$' "one Go version of three numbers") || { refused=1; exit 2; }

# The pinned source in a new directory: the one place that knows where vitni is cloned from and at which commit.
fetch() { # DIR
    say "vitni commit $commit from $repo_url"
    git clone --quiet --no-hardlinks "$repo_url" "$1" >&2
    git -C "$1" -c advice.detachedHead=false checkout --quiet "$commit" >&2
}

new_dir() { # PATH: refuse a path that starts with a dash, exists (a dangling link counts) or has no directory
    case $1 in
        -*) refuse "an argument starts with a dash: $1" ;;
        "") refuse "the path is empty" ;;
    esac
    { [ -e "$1" ] || [ -L "$1" ]; } && refuse "$1 exists"
    [ -d "$(dirname "$1")" ] || refuse "the directory of $1 does not exist"
    return 0
}

case ${1:-} in
    --commit)
        [ $# -eq 1 ] || refuse "--commit takes no argument"
        printf '%s\n' "$commit"
        exit 0
        ;;
    --source)
        [ $# -eq 2 ] || refuse "usage: build-vitni.sh --source DIR"
        new_dir "$2"
        work=$(mktemp -d "${TMPDIR:-/tmp}/handsal-vitni.XXXXXX")
        fetch "$work/src"
        mv "$work/src" "$2"
        exit 0
        ;;
esac

[ $# -eq 3 ] || refuse "usage: build-vitni.sh GOOS GOARCH OUT"
for arg in "$@"; do
    case $arg in
        -*) refuse "an argument starts with a dash: $arg" ;;
    esac
done
printf '%s\n' "$1" | grep -Eq '^[a-z0-9]+$' || refuse "GOOS is not lower case letters and digits: $1"
printf '%s\n' "$2" | grep -Eq '^[a-z0-9]+$' || refuse "GOARCH is not lower case letters and digits: $2"
new_dir "$3"
goos=$1 goarch=$2
out=$(cd "$(dirname "$3")" && pwd -P)/$(basename "$3")

# One environment for every Go call, built from nothing (`env -i`). Fixed, because they decide the bytes:
#   GOTOOLCHAIN the pinned toolchain      GOOS, GOARCH the target       CGO_ENABLED=0 no libc in the binary
#   GOFLAGS empty (set, so a flag file or shell cannot add one)   GOWORK=off   GOENV=off (the `go env -w` file)
# Passed on only when the caller has them set, and only because Go cannot run or reach the network without them;
# none of them changes the bytes (-trimpath drops the paths, go.sum pins every module):
#   PATH to find go and git       HOME where Go keeps its cache and modules       TMPDIR scratch space
#   GOCACHE GOMODCACHE GOPATH     where the cache and the module download directory are
#   GOPROXY   where modules come from: the checksum database and go.sum pin what any proxy returns
# NOT on the list, on purpose: GOSUMDB, GONOSUMDB, GOPRIVATE, GOINSECURE, GONOSUMCHECK, GOFLAGS=-insecure. They switch the
# checksum check off for the toolchain download and the modules, and a release build always verifies both against the
# default checksum database (GOENV=off keeps a `go env -w` setting from changing it either).
#   HTTP_PROXY HTTPS_PROXY NO_PROXY and their lower case forms, SSL_CERT_FILE SSL_CERT_DIR   reaching them
# Everything else, GOAMD64, GOEXPERIMENT, GOFIPS140, GODEBUG, GOROOT and whatever the next Go release adds, is dropped.
gobuild() {
    for _v in PATH HOME TMPDIR GOCACHE GOMODCACHE GOPATH GOPROXY \
        HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR; do
        eval "_set=\${$_v+set}"
        [ "$_set" = set ] && eval "set -- \"$_v=\$$_v\" \"\$@\""
    done
    env -i GOTOOLCHAIN="go$gover" GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 GOFLAGS= GOWORK=off GOENV=off "$@"
}

got=$(gobuild go version) || { say "go version failed"; exit 1; }
case $got in
    "go version go$gover "*) ;;
    *) say "the Go toolchain is '$got', the pin is go$gover (tools/release/go-version)"; exit 1 ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/handsal-vitni.XXXXXX")
say "go$gover, $goos/$goarch, into $out"
fetch "$work/src"
(cd "$work/src/go" && gobuild go build -trimpath -buildvcs=false -o "$out" ./cmd/vitni-verify) >&2
