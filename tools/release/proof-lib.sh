# Sourced by tools/release/prodk.sh, tools/release/proof-verifiers.sh and tools/release/final-proof.sh, never run
# (CF-08, T8.6, T15.10). The checks the owner reads line by line, the one build of both vitni verifiers, and the
# conformance harness with them. A script that sources this file sets `here` to its own directory first.
#
# A run's output directory OUT (made by prodk.sh, or by proof-verifiers.sh for a release that signs nothing) holds
# the verifiers pl_build_verifiers built, and its logs:
#   OUT/vitni/vitni-verify-go              the Go verifier
#   OUT/vitni/src/ts/dist/cli.js           the TypeScript verifier, run with node
#   OUT/logs/vitni-*.log                   the output of each build step

pl_uv="env -u VIRTUAL_ENV uv"
pl_fails=0

pl_say() { printf '%s\n' "$*"; }
pl_hdr() { printf '\n== %s\n' "$*"; }
pl_die() {
    printf 'STOP: %s\n' "$*" >&2
    exit 1
}
pl_refuse() {
    printf '%s: refused: %s\n' "$pl_tool" "$*" >&2
    exit 2
}

# pl_expect LABEL EXPECTED OBSERVED
pl_expect() {
    if [ "$2" = "$3" ]; then
        printf 'PASS  %s\n        expected: %s\n        observed: %s\n' "$1" "$2" "$3"
    else
        pl_fails=$((pl_fails + 1))
        printf 'FAIL  %s\n        expected: %s\n        observed: %s\n' "$1" "$2" "$3"
    fi
}
pl_finish() {
    if [ "$pl_fails" -eq 0 ]; then
        pl_say
        pl_say "RESULT: all checks passed"
    else
        pl_say
        pl_say "RESULT: $pl_fails check(s) FAILED"
        return 1
    fi
}

# pl_owner_signed_count REPO: how many ids the owner run signs. Asked of tools/check_catalog.py, which reads them from
# `pending`: the owner-signed ids are exactly the pending ones (CF-08). Also the number of holes
# `check_catalog.py --final` shows before the PRODK run. Stops when the check fails or no id is left to sign.
pl_owner_signed_count() {
    _line=$(cd "$1" && $pl_uv run python -I tools/check_catalog.py --owner-signed | tail -n 1) || pl_die "cannot read the owner-signed ids"
    _n=${_line% owner-signed}
    [ "$_n" -gt 0 ] 2>/dev/null || pl_die "no owner-signed vector is pending: there is nothing to sign"
    printf '%s\n' "$_n"
}

# pl_new_out OUT REPO: refuse an output directory that holds anything, a tree with tracked changes or untracked
# inputs, an OUT inside the repository; then make OUT and set pl_out to its resolved path. Nothing is made when it
# refuses.
pl_new_out() {
    if [ -e "$1" ]; then
        [ -d "$1" ] || pl_refuse "$1 exists and is not a directory"
        [ -z "$(ls -A "$1")" ] || pl_refuse "$1 is not empty: it holds the output of an earlier run, or something else. Use a new directory."
    fi
    if [ -n "$(git -C "$2" status --porcelain --untracked-files=no)" ]; then
        pl_refuse "the tree has tracked changes"
    fi
    if [ -n "$(git -C "$2" status --porcelain --untracked-files=all -- conformance spec tools checker signer)" ]; then
        pl_refuse "the tree has untracked files among the inputs"
    fi
    # The output is not part of the tree: the nearest directory that exists, resolved, must not be the repository or
    # below it (the stage, the vitni source and the logs would show up in `git status`, and the scan roots would meet them).
    _d=$1
    while [ ! -e "$_d" ]; do _d=$(dirname "$_d"); done
    _real=$(cd "$_d" && pwd -P)
    case $_real in
        "$2" | "$2"/*) pl_refuse "$1 is inside the repository: use a directory outside it" ;;
    esac
    mkdir -p "$1"
    pl_out=$(cd "$1" && pwd -P)
}

# pl_build_verifiers OUT: build the two verifiers into OUT/vitni from the pinned vitni source, the Go one through
# tools/release/build-vitni.sh for this machine and the TypeScript one from the same source (npm ci, npm run build),
# each step logged in OUT/logs. Stops at the first step that fails. The one place that makes what pl_use_verifiers reads.
pl_build_verifiers() {
    _logs=$1/logs
    mkdir -p "$1/vitni" "$_logs"
    _goos=$(go env GOOS) || pl_die "go env GOOS failed (is go installed?)"
    _goarch=$(go env GOARCH) || pl_die "go env GOARCH failed (is go installed?)"
    sh "$here/build-vitni.sh" "$_goos" "$_goarch" "$1/vitni/vitni-verify-go" >"$_logs/vitni-go.log" 2>&1 || pl_die "the Go verifier did not build; see $_logs/vitni-go.log"
    sh "$here/build-vitni.sh" --source "$1/vitni/src" >"$_logs/vitni-source.log" 2>&1 || pl_die "the vitni source did not check out; see $_logs/vitni-source.log"
    (cd "$1/vitni/src/ts" && npm ci --ignore-scripts --no-audit --no-fund && npm run build) >"$_logs/vitni-ts.log" 2>&1 || pl_die "the TypeScript verifier did not build; see $_logs/vitni-ts.log"
    pl_use_verifiers "$1" || pl_die "the verifiers are not where they should be: $pl_go, $pl_node $pl_cli"
    pl_say "Go          $pl_go"
    pl_say "TypeScript  $pl_node $pl_cli"
}

# pl_use_verifiers OUT: name the two verifiers of a run, or stop
pl_use_verifiers() {
    pl_go=$1/vitni/vitni-verify-go
    pl_cli=$1/vitni/src/ts/dist/cli.js
    pl_node=$(command -v node) || pl_node=
    [ -x "$pl_go" ] && [ -f "$pl_cli" ] && [ -n "$pl_node" ]
}

# pl_harness REPO VECTORS_DIR LOG: the checker harness over a vector directory, both verifiers, full output in
# LOG. Sets pl_harness_line (the last line, "N vectors, M not passing").
pl_harness() {
    _c=$1/checker/python/.venv/bin/handsal-check-conformance
    [ -x "$_c" ] || pl_die "$_c is missing (run: env -u VIRTUAL_ENV uv sync --project $1/checker/python)"
    (cd "$1" && $pl_uv run --no-project python -I conformance/run.py --vectors "$2" --role checker \
        --impl "$_c --vitni $pl_go" --impl "$_c --vitni $pl_node --vitni $pl_cli") >"$3" 2>&1 || :
    pl_harness_line=$(tail -n 1 "$3")
}
