# Sourced by tools/release/build-macos.sh and tools/release/build-linux-server.sh, never run (SG-15, CF-05, T15.10).
# One place for what a release build does whatever the platform: the refusals, the one commit everything is built
# from, the plan read from tools/artifact_hashes.py, the zipapp, the launcher, vitni through its one command, the
# pinned interpreter archive with the packed licences, and the lines to publish. A script adds its machine check and
# one function, `build_other NAME`, for the names of its list that are neither of those (the Swift products).
#
#   rl_start TOOL PLATFORM GOOS GOARCH "$@"    refusals, then the commit, the archive of it, DIR, the plan
#   rl_build_all                               every name of the platform's closed list, the archive, the licences
#   rl_finish                                  tools/artifact_hashes.py --release DIR, then tools/release/vuln-gate.sh on
#                                              the set; the lines on stdout only when the gate passed
#
# Refused with status 2 and nothing built: a missing or extra argument, an argument that starts with a dash, a tree
# with tracked changes or with untracked files among the build inputs (signer, checker, tools), a DIR that exists and
# is not empty, a vitni pin that is not well formed. A failed build stops the script and leaves DIR half full.
#
# Everything is built from `git archive` of one commit of signer, checker and tools, not from the working tree, so a
# file the tree ignores cannot reach a binary or the zipapp. The two files that are read from the working tree, this
# library and the script that sourced it, are compared with that commit byte for byte: the tracked-changes check
# trusts the index, and `git update-index --assume-unchanged` or `--skip-worktree` can hide an edit from it. The
# comparison lives in both files, so an edit hidden in one is caught by the other. (A script cannot vouch for itself:
# an owner who edits both and hides both has chosen to build something that is not a commit.)

rl_work=
rl_dir=

rl_say() { printf '%s: %s\n' "$rl_tool" "$*" >&2; }
rl_refuse() {
    rl_say "refused: $*"
    exit 2
}
rl_cleanup() {
    rl_status=$?
    [ -n "$rl_work" ] && rm -rf "$rl_work"
    if [ "$rl_status" != 0 ] && [ -n "$rl_dir" ]; then
        rl_say "failed (status $rl_status); $rl_dir may hold a partial build, remove it before a new run"
    fi
}
# rl_same_as_commit PATH: a file of the repository is the one the commit holds, whatever the index says
rl_same_as_commit() {
    git -C "$rl_root" show "$rl_head:$1" | cmp -s - "$rl_root/$1" || rl_refuse "$1 differs from commit $rl_head (an edit hidden with assume-unchanged or skip-worktree?)"
}
rl_py() { uv run --no-project python -I "$@"; }

rl_start() { # TOOL PLATFORM GOOS GOARCH ARGS...
    rl_tool=$1 rl_platform=$2 rl_goos=$3 rl_goarch=$4
    shift 4
    rl_root=$(cd "$(dirname "$0")/../.." && pwd)

    [ $# -eq 1 ] || rl_refuse "usage: $rl_tool.sh DIR"
    case $1 in
        -*) rl_refuse "the argument starts with a dash: $1" ;;
        "") rl_refuse "the argument is empty" ;;
    esac
    if [ -n "$(git -C "$rl_root" status --porcelain --untracked-files=no)" ]; then
        rl_refuse "the tree has tracked changes"
    fi
    if [ -n "$(git -C "$rl_root" status --porcelain --untracked-files=all -- signer checker tools)" ]; then
        rl_refuse "the tree has untracked files among the build inputs"
    fi
    if [ -e "$1" ]; then
        [ -d "$1" ] || rl_refuse "$1 exists and is not a directory"
        [ -z "$(ls -A "$1")" ] || rl_refuse "$1 is not empty"
    fi

    # One commit, named once. Every build input comes from the tree of that commit; the tools run from this copy too,
    # and the vitni pins are read from it by the one vitni command.
    rl_head=$(git -C "$rl_root" rev-parse HEAD)
    rl_same_as_commit tools/release/release-lib.sh
    rl_same_as_commit "tools/release/$(basename "$0")"
    rl_work=$(mktemp -d "${TMPDIR:-/tmp}/handsal-release.XXXXXX")
    trap rl_cleanup EXIT
    trap 'exit 130' INT HUP TERM
    rl_src=$rl_work/src
    mkdir "$rl_src"
    git -C "$rl_root" archive "$rl_head" signer checker tools | tar -x -C "$rl_src"
    rl_vitni_sh=$rl_src/tools/release/build-vitni.sh
    [ -f "$rl_vitni_sh" ] || rl_refuse "tools/release/build-vitni.sh is missing at commit $rl_head"
    sh "$rl_vitni_sh" --commit >/dev/null || exit 2 # it says why

    mkdir -p "$1"
    rl_dir=$(cd "$1" && pwd)
    rl_say "building from handsal commit $rl_head, into $rl_dir"

    # One plan from the one place that owns the names and the pin, read once.
    rl_py - "$rl_src" "$rl_platform" >"$rl_work/plan" <<'PY'
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
            launcher) rl_launcher=$a ;;
            zipapp) rl_zipapp=$a rl_entry=$b ;;
            archive) rl_archive=$a rl_archive_url=$b ;;
            notices) rl_notices=$a rl_notices_url=$b ;;
        esac
    done <"$rl_work/plan"
}

rl_build_all() {
    while read -r what name; do
        [ "$what" = fixed ] || continue
        if [ "$name" = "$rl_launcher" ]; then
            rl_py "$rl_src/checker/python/packaging/launcher.py" "$rl_platform" >"$rl_dir/$name"
            chmod 755 "$rl_dir/$name"
        elif [ "$name" = "$rl_zipapp" ]; then
            rl_py "$rl_src/checker/python/packaging/build_zipapp.py" --entry "$rl_entry" "$rl_dir/$name" >&2
        else
            case $name in
                vitni-*) sh "$rl_vitni_sh" "$rl_goos" "$rl_goarch" "$rl_dir/$name" >&2 ;;
                *) build_other "$name" ;;
            esac
        fi
    done <"$rl_work/plan"

    curl -fsSL -o "$rl_dir/$rl_archive" "$rl_archive_url"
    curl -fsSL -o "$rl_work/$rl_notices" "$rl_notices_url"
    rl_py "$rl_src/tools/pack_licenses.py" --platform "$rl_platform" "$rl_work/$rl_notices" "$rl_dir" >&2
}

# The lines go to stdout only after the gate has passed: a set with a CRITICAL or HIGH finding, or one the gate could
# not scan, has nothing to publish. The gate is the copy of the commit being built, like every other tool here.
rl_finish() {
    rl_py "$rl_src/tools/artifact_hashes.py" --release "$rl_dir" --platform "$rl_platform" >"$rl_work/lines" || exit 1
    sh "$rl_src/tools/release/vuln-gate.sh" "$rl_platform" "$rl_dir" "$rl_work/lines" >&2 || exit 1
    cat "$rl_work/lines"
}
