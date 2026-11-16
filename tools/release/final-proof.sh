#!/bin/sh
# The final local proof of a PRODK run (CF-08, T8.6, T15.10): every suite, the conformance harness for the checker
# and both signers with both vitni verifiers, the closed-list checks, and the tests of the release scripts. One line per
# step with its status, then RESULT. Full output of every step: OUT/proof/NN-name.log.
#
#   sh tools/release/final-proof.sh OUT                  after the PRODK run: the tag check must show 0 holes
#   sh tools/release/final-proof.sh --before-prodk OUT   before it: the tag check must show exactly one hole per
#                                                        pending owner-signed id (conformance/vector-ids.json)
#
# OUT is the output directory of tools/release/prodk.sh, where its verifiers were built (OUT/vitni). It must not hold a
# proof already (status 2): a proof of an earlier run is never mixed with this one. Runs in the repo working tree and
# changes nothing in it (build outputs stay in ignored build directories). No elevated rights, no password. About 15 to 25
# minutes: two harness runs and the Swift and Rust suites take most of it.
set -u

pl_tool=final-proof
here=$(cd "$(dirname "$0")" && pwd)
. "$here/proof-lib.sh"
repo=$(cd "$here/../.." && pwd)

mode=after
[ "${1:-}" = --before-prodk ] && { mode=before; shift; }
[ $# -eq 1 ] || pl_refuse "usage: final-proof.sh [--before-prodk] OUT"
case $1 in
    -*) pl_refuse "the argument starts with a dash: $1" ;;
esac
[ -d "$1" ] || pl_refuse "$1 is not a directory (it is the output directory of prodk.sh)"
out=$(cd "$1" && pwd -P)
pl_use_verifiers "$out" || pl_refuse "$out holds no verifiers (vitni/vitni-verify-go, vitni/src/ts/dist/cli.js, and node on PATH)"
[ ! -e "$out/proof" ] || pl_refuse "$out/proof exists from an earlier run: use a new output directory"
proof=$out/proof
mkdir "$proof"
summary=$proof/summary.txt
: >"$summary"
cd "$repo" || pl_die "no repo at $repo"
pending=$(pl_owner_signed_count "$repo")

n=0
bad=0
# step NAME CMD...: run CMD, log it; ok when the status is 0
step() {
    name=$1
    shift
    n=$((n + 1))
    log=$proof/$(printf '%02d' "$n")-$name.log
    "$@" >"$log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then ok=ok; else ok="not ok"; bad=$((bad + 1)); fi
    printf '%-26s rc=%s  %s  [%s]\n' "$name" "$rc" "$(tail -n 1 "$log")" "$ok" | tee -a "$summary"
}
# step_last NAME EXPECTED CMD...: ok when the last line of the output is exactly EXPECTED (the status may be 1)
step_last() {
    name=$1
    want=$2
    shift 2
    n=$((n + 1))
    log=$proof/$(printf '%02d' "$n")-$name.log
    "$@" >"$log" 2>&1
    rc=$?
    got=$(tail -n 1 "$log")
    if [ "$got" = "$want" ]; then ok=ok; else ok="not ok"; bad=$((bad + 1)); fi
    printf '%-26s rc=%s  %s  [%s, expected: %s]\n' "$name" "$rc" "$got" "$ok" "$want" | tee -a "$summary"
}
# step_harness NAME CMD...: ok when the last line says no vector failed
step_harness() {
    name=$1
    shift
    n=$((n + 1))
    log=$proof/$(printf '%02d' "$n")-$name.log
    "$@" >"$log" 2>&1
    rc=$?
    got=$(tail -n 1 "$log")
    if printf '%s\n' "$got" | grep -Eq '^[0-9]+ vectors, 0 not passing$'; then ok=ok; else ok="not ok"; bad=$((bad + 1)); fi
    printf '%-26s rc=%s  %s  [%s]\n' "$name" "$rc" "$got" "$ok" | tee -a "$summary"
}
say() { printf '%s\n' "$*" | tee -a "$summary"; }

c=$repo/checker/python/.venv/bin/handsal-check-conformance
head=$(git rev-parse HEAD)
say "commit  $head  branch $(git rev-parse --abbrev-ref HEAD)"
say "status  $(git status --porcelain | wc -l | tr -d ' ') changed or untracked paths (uncommitted tree if not 0)"
say "mode    $mode the PRODK run"
say "date    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say ""
$pl_uv sync --project checker/python >/dev/null 2>&1 || pl_die "uv sync of the checker failed"

step tools-tests $pl_uv run python -I -m unittest discover -s tools/tests -t tools
step checker-tests $pl_uv run --project checker/python python -I -m unittest discover -s checker/python/tests -t checker/python
step conformance-tests $pl_uv run --no-project python -I -m unittest discover -s conformance/tests -t conformance
step gen-tests $pl_uv run --project conformance/vectors/_gen python -I -m unittest discover -s conformance/vectors/_gen/tests -t conformance/vectors/_gen
step generate-check $pl_uv run --project conformance/vectors/_gen python -I conformance/vectors/_gen/generate.py --check --vitni-go "$pl_go" --vitni-ts "$pl_node $pl_cli"
step_last manifest-check "bundle manifest: ok" $pl_uv run python -I tools/manifest.py --check
step_last repin-check "pins ok" $pl_uv run python -I tools/repin.py --check
if [ "$mode" = after ]; then
    step_last catalog-final "0 holes, 0 pending" $pl_uv run python -I tools/check_catalog.py --final
else
    step_last catalog-final "$pending holes, 0 pending" $pl_uv run python -I tools/check_catalog.py --final
fi
step catalog $pl_uv run python -I tools/check_catalog.py
step_harness harness-checker $pl_uv run --no-project python -I conformance/run.py --role checker --impl "$c --vitni $pl_go" --impl "$c --vitni $pl_node --vitni $pl_cli"

# the signers need their own builds; the Swift one is a debug build of the signer package
step swift-tests sh signer/apple/scripts/test.sh
sign_swift=$repo/signer/apple/.build/debug/handsal-sign-conformance
if [ -x "$sign_swift" ]; then
    step_harness harness-signer-swift $pl_uv run --no-project python -I conformance/run.py --role signer --impl "$sign_swift"
else
    n=$((n + 1)); bad=$((bad + 1)); say "harness-signer-swift       MISSING $sign_swift  [not ok]"
fi
step rust-core-tests cargo test --manifest-path signer/windows/Cargo.toml
sign_rust=$repo/signer/windows/target/debug/handsal-sign-conformance
if [ -x "$sign_rust" ]; then
    step_harness harness-signer-rust $pl_uv run --no-project python -I conformance/run.py --role signer --impl "$sign_rust"
else
    n=$((n + 1)); bad=$((bad + 1)); say "harness-signer-rust        MISSING $sign_rust  [not ok]"
fi
step installer-tests sh tools/install/test-install.sh
step installer-linux-tests sh tools/install/test-install-linux.sh
step release-macos-tests sh tools/release/test-build-macos.sh
step release-linux-tests sh tools/release/test-build-linux-server.sh
step release-vitni-tests sh tools/release/test-build-vitni.sh
step prodk-script-tests sh tools/release/test-prodk.sh
step release-hashes-twice sh -c "$pl_uv run python -I tools/artifact_hashes.py > $proof/h1.txt && $pl_uv run python -I tools/artifact_hashes.py > $proof/h2.txt && cmp $proof/h1.txt $proof/h2.txt && echo 'two builds print the same text'"

say ""
say "steps $n, not ok $bad"
if [ "$bad" -eq 0 ]; then
    say "RESULT: final proof passed ($mode the PRODK run), commit $(git rev-parse --short HEAD)"
    exit 0
fi
say "RESULT: $bad step(s) failed; read the logs in $proof"
exit 1
