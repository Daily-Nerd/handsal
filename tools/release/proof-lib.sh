# Sourced by tools/release/prodk.sh and tools/release/final-proof.sh, never run (CF-08, T8.6, T15.10).
# The checks the owner reads line by line, and the conformance harness with both vitni verifiers.
#
# A run's output directory OUT (made by prodk.sh) holds the verifiers it built:
#   OUT/vitni/vitni-verify-go              the Go verifier
#   OUT/vitni/src/ts/dist/cli.js           the TypeScript verifier, run with node

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

# pl_owner_signed_count REPO: how many ids the owner run signs. Asked of tools/check_catalog.py, the one place that
# tells an owner-signed id from an id that waits for a second edition (both sit in `pending`). Also the number of holes
# `check_catalog.py --final` shows before the PRODK run. Stops when the check fails or no id is left to sign.
pl_owner_signed_count() {
    _line=$(cd "$1" && $pl_uv run python -I tools/check_catalog.py --owner-signed | tail -n 1) || pl_die "cannot read the owner-signed ids"
    _n=${_line% owner-signed}
    [ "$_n" -gt 0 ] 2>/dev/null || pl_die "no owner-signed vector is pending: there is nothing to sign"
    printf '%s\n' "$_n"
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
