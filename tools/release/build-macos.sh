#!/bin/sh
# Build the macOS release set of this checkout into DIR and print the lines to publish (SG-15, CF-05, T15.8).
#
#   sh tools/release/build-macos.sh DIR
#
# DIR must not exist or be empty. It ends up holding exactly the installer's closed list for macos-arm64
# (tools/artifact_hashes.py owns the names; this script keeps no copy of them):
#
#   the Swift executables     swift build -c release --product NAME -Xswiftc -gnone  (signer/apple)
#   the vitni verifier        go build -trimpath -buildvcs=false, from the vitni commit in tools/release/vitni-commit
#   the zipapp and launcher   checker/python/packaging/build_zipapp.py, launcher.py
#   the interpreter archive   downloaded from the pin in checker/python/packaging/interpreter.json, then
#                             tools/pack_licenses.py makes the licence archive from the notices
#
# then `tools/artifact_hashes.py --release DIR --platform macos-arm64` checks DIR and its lines go to stdout,
# the only thing on stdout. Everything else goes to stderr, first the commit this was built from.
#
# Refused with status 2 and nothing built: a missing or extra argument, an argument that starts with a dash,
# a machine that is not an Apple silicon Mac, a tree with tracked changes or with untracked files among the
# build inputs (signer, checker, tools), a DIR that exists and is not empty. A failed build stops the script
# and leaves DIR half full: remove it before the next run.
#
# Everything is built from `git archive HEAD` of signer, checker and tools, not from the working tree, so a file the
# tree ignores cannot reach a binary or the zipapp.
#
# HANDSAL_VITNI_REPO (default https://github.com/Daily-Nerd/vitni) is where the vitni source is cloned from.
# Needs: git, swift, go, uv, curl, tar with zstd.
set -eu

platform=macos-arm64
vitni_repo=${HANDSAL_VITNI_REPO:-https://github.com/Daily-Nerd/vitni}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=
dir=

say() { printf 'build-macos: %s\n' "$*" >&2; }
refuse() {
    say "refused: $*"
    exit 2
}
cleanup() {
    status=$?
    [ -n "$work" ] && rm -rf "$work"
    if [ "$status" != 0 ] && [ -n "$dir" ]; then
        say "failed (status $status); $dir may hold a partial build, remove it before a new run"
    fi
}
py() { uv run --no-project python -I "$@"; }

[ $# -eq 1 ] || refuse "usage: build-macos.sh DIR"
case $1 in
    -*) refuse "the argument starts with a dash: $1" ;;
    "") refuse "the argument is empty" ;;
esac
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || refuse "this builds the $platform set and needs an Apple silicon Mac"

if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
    refuse "the tree has tracked changes"
fi
if [ -n "$(git -C "$root" status --porcelain --untracked-files=all -- signer checker tools)" ]; then
    refuse "the tree has untracked files among the build inputs"
fi
if [ -e "$1" ]; then
    [ -d "$1" ] || refuse "$1 exists and is not a directory"
    [ -z "$(ls -A "$1")" ] || refuse "$1 is not empty"
fi

# One commit, named once. Every build input below comes from the tree of that commit, not from the working
# tree: a file the tree ignores (a stray module under checker/python/src, a leftover under signer/apple) would
# otherwise be packed or compiled, and the status check above cannot see it. The tools run from this copy too,
# and the vitni commit is read from it.
head=$(git -C "$root" rev-parse HEAD)
work=$(mktemp -d "${TMPDIR:-/tmp}/handsal-release.XXXXXX")
trap cleanup EXIT
trap 'exit 130' INT HUP TERM
src=$work/src
mkdir "$src"
git -C "$root" archive "$head" signer checker tools | tar -x -C "$src"

vitni_file=$src/tools/release/vitni-commit
[ -f "$vitni_file" ] || refuse "tools/release/vitni-commit is missing at commit $head"
vitni_commit=$(cat "$vitni_file")
[ "$(wc -c <"$vitni_file" | tr -d ' ')" = 41 ] && printf '%s\n' "$vitni_commit" | grep -Eq '^[0-9a-f]{40}$' || refuse "tools/release/vitni-commit is not one 40-digit commit"

mkdir -p "$1"
dir=$(cd "$1" && pwd)
say "building from handsal commit $head, vitni commit $vitni_commit from $vitni_repo, into $dir"

# One plan from the one place that owns the names and the pin, read once.
py - "$src" "$platform" >"$work/plan" <<'PY'
import importlib.util, json, sys
root, platform = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("artifact_hashes", root + "/tools/artifact_hashes.py")
ah = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ah)
kind = ah.ARTIFACTS[platform]
row = json.loads(open(root + "/checker/python/packaging/interpreter.json", encoding="utf-8").read())["platforms"][platform]
for name in kind.fixed:
    print("fixed", name)
print("launcher", kind.launcher)
print("zipapp", kind.zipapp, kind.entry)
print("archive", row["archive"]["file"], row["archive"]["url"])
print("notices", row["notices"]["file"], row["notices"]["url"])
PY

while read -r what a b; do
    case $what in
        launcher) launcher=$a ;;
        zipapp) zipapp=$a entry=$b ;;
        archive) archive=$a archive_url=$b ;;
        notices) notices=$a notices_url=$b ;;
    esac
done <"$work/plan"

build_swift() { # NAME
    (cd "$src/signer/apple" && swift build -c release --product "$1" --scratch-path "$work/swift" -Xswiftc -gnone) >&2
    cp "$work/swift/release/$1" "$dir/$1"
    chmod 755 "$dir/$1"
}

build_vitni() { # NAME
    if [ ! -d "$work/vitni-src" ]; then
        git clone --quiet --no-hardlinks "$vitni_repo" "$work/vitni-src" >&2
        git -C "$work/vitni-src" -c advice.detachedHead=false checkout --quiet "$vitni_commit" >&2
    fi
    (cd "$work/vitni-src/go" && go build -trimpath -buildvcs=false -o "$dir/$1" "./cmd/$1") >&2
}

while read -r what name; do
    [ "$what" = fixed ] || continue
    if [ "$name" = "$launcher" ]; then
        py "$src/checker/python/packaging/launcher.py" >"$dir/$name"
        chmod 755 "$dir/$name"
    elif [ "$name" = "$zipapp" ]; then
        py "$src/checker/python/packaging/build_zipapp.py" --entry "$entry" "$dir/$name" >&2
    else
        case $name in
            vitni-*) build_vitni "$name" ;;
            *) build_swift "$name" ;;
        esac
    fi
done <"$work/plan"

curl -fsSL -o "$dir/$archive" "$archive_url"
curl -fsSL -o "$work/$notices" "$notices_url"
py "$src/tools/pack_licenses.py" --platform "$platform" "$work/$notices" "$dir" >&2

py "$src/tools/artifact_hashes.py" --release "$dir" --platform "$platform"
