#!/bin/sh
# Sign the pending owner-signed vectors with production keys that live only in the memory of one process (PRODK,
# CF-08, T8.6, T15.10). One command from a clean checkout of the commit to be tagged:
#
#   sh tools/release/prodk.sh [--task ID] OUT
#
# OUT must not exist or be empty, and must be outside the repository. It receives, and keeps for the vault, everything the run makes outside the
# repository: the two vitni verifiers (OUT/vitni), the staged vectors (OUT/stage, until they are installed), the logs
# (OUT/logs), the proof (OUT/proof) and the public report and evidence note (OUT/evidence). ID is the task row the note
# names (for example T8.6); without it the note names none. This script never commits, tags or pushes: the signed files
# and the rewritten spec/MANIFEST.json are left in the working tree for the owner to review and commit.
#
# What it does, in order. Nothing here needs elevated rights, a password or Touch ID.
#   1 refusals            no argument but OUT, an OUT inside the repository, a tree with tracked changes or untracked build inputs, an OUT that holds
#                         anything (the output of an earlier run is never overwritten), production vectors already there
#   2 verifiers           the Go verifier through tools/release/build-vitni.sh for this machine, the TypeScript verifier
#                         from the same pinned source (npm ci, npm run build): both judge every signed act
#   3 preflight           the catalog shows no hole and every owner-signed id pending, the manifest and the pins hold
#   4 confirmation        you type one phrase
#   5 sign                ONE python process draws the production signing keys from the operating system's random
#                         source, in memory only, has both verifiers judge every act, signs the vectors into OUT/stage,
#                         scans for the scalars, and ends. THE KEYS EXIST ONLY INSIDE THAT PROCESS.
#   6 harness             the staged vectors, the checker, both verifiers: all must pass or the stage is removed
#   7 install             the files into conformance/vectors/prod, then spec/MANIFEST.json
#   8 proof               check_catalog --final, the manifest and the pins, the harness over the installed files
#   9 final proof         tools/release/final-proof.sh OUT (15 to 25 minutes)
#  10 evidence            OUT/evidence/prodk-evidence.md (public values only), for the vault
#
# After a failure past step 7 the files are in the tree: do not commit, run tools/release/prodk-undo.sh, then run this
# script again with a new OUT (new keys). Allowed until the files are committed.
# Needs: git, go, node, npm, uv, and what final-proof.sh needs.
set -eu
umask 077
ulimit -c 0

pl_tool=prodk
here=$(cd "$(dirname "$0")" && pwd)
. "$here/proof-lib.sh"
repo=$(cd "$here/../.." && pwd -P)

task=
out=
while [ $# -gt 0 ]; do
    case $1 in
        --task)
            [ $# -ge 2 ] || pl_refuse "--task needs an id"
            task=$2
            shift 2
            ;;
        -*) pl_refuse "unknown option: $1" ;;
        *)
            [ -z "$out" ] || pl_refuse "one output directory only"
            out=$1
            shift
            ;;
    esac
done
[ -n "$out" ] || pl_refuse "usage: prodk.sh [--task ID] OUT"
if [ -n "$task" ]; then
    printf '%s\n' "$task" | grep -Eq '^[A-Za-z0-9.]+$' || pl_refuse "the task id is not letters, digits and dots: $task"
fi
if [ -e "$out" ]; then
    [ -d "$out" ] || pl_refuse "$out exists and is not a directory"
    [ -z "$(ls -A "$out")" ] || pl_refuse "$out is not empty: it holds the output of an earlier run, or something else. Use a new directory."
fi
prod=$repo/conformance/vectors/prod
if [ -d "$prod" ] && [ -n "$(ls -A "$prod")" ]; then
    pl_refuse "$prod already holds files: the production keys sign once. Remove them only if you mean to sign again (sh tools/release/prodk-undo.sh)."
fi

if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ]; then
    pl_refuse "the tree has tracked changes"
fi
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=all -- conformance spec tools checker signer)" ]; then
    pl_refuse "the tree has untracked files among the inputs"
fi
# The output is not part of the tree: the nearest directory that exists, resolved, must not be the repository or below it
# (the stage and the logs would show up in `git status`, and the scan roots would meet them).
_d=$out
while [ ! -e "$_d" ]; do _d=$(dirname "$_d"); done
_real=$(cd "$_d" && pwd -P)
case $_real in
    "$repo" | "$repo"/*) pl_refuse "$out is inside the repository: use a directory outside it" ;;
esac
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
stage=$out/stage
evid=$out/evidence
logs=$out/logs
mkdir -p "$evid" "$logs"
cd "$repo"
head=$(git rev-parse HEAD)
branch=$(git rev-parse --abbrev-ref HEAD)
pl_say "repo     $repo"
pl_say "branch   $branch   commit $head"
pl_say "output   $out"

pl_hdr "1 the two vitni verifiers, built from the pinned source"
pl_goos=$(go env GOOS)
pl_goarch=$(go env GOARCH)
mkdir -p "$out/vitni"
sh "$here/build-vitni.sh" "$pl_goos" "$pl_goarch" "$out/vitni/vitni-verify-go" >"$logs/vitni-go.log" 2>&1 || pl_die "the Go verifier did not build; see $logs/vitni-go.log"
sh "$here/build-vitni.sh" --source "$out/vitni/src" >"$logs/vitni-source.log" 2>&1 || pl_die "the vitni source did not check out; see $logs/vitni-source.log"
(cd "$out/vitni/src/ts" && npm ci --ignore-scripts --no-audit --no-fund && npm run build) >"$logs/vitni-ts.log" 2>&1 || pl_die "the TypeScript verifier did not build; see $logs/vitni-ts.log"
pl_use_verifiers "$out" || pl_die "the verifiers are not where they should be: $pl_go, $pl_node $pl_cli"
pl_say "Go          $pl_go"
pl_say "TypeScript  $pl_node $pl_cli"

pl_hdr "2 preflight"
$pl_uv sync --project checker/python >/dev/null 2>&1 || pl_die "uv sync of the checker failed"
count=$(pl_owner_signed_count "$repo")
# only the holes are compared (the catalog's pending ids are listed apart);
# that no owner-signed id has a file yet is the empty production directory
catalog_line=$($pl_uv run python -I tools/check_catalog.py | tail -n 1)
pl_expect "catalog before: no hole" "0 holes" "${catalog_line%%,*}"
pl_expect "no owner-signed vector exists yet" "0" "$(ls "$repo/conformance/vectors/prod" 2>/dev/null | wc -l | tr -d ' ')"
pl_expect "bundle manifest matches the tree" "bundle manifest: ok" "$($pl_uv run python -I tools/manifest.py --check | tail -n 1)"
pl_expect "pins match the core files" "pins ok" "$($pl_uv run python -I tools/repin.py --check | tail -n 1)"
pl_say "production profile the vectors will name: $($pl_uv run python -I tools/manifest.py | sed -n 's/^production  *//p')"
pl_finish || pl_die "preflight failed; nothing was signed"

pl_hdr "3 confirmation"
cat <<MSG
You are about to draw the production keys and sign the $count vectors.

  - The private scalars will exist only in memory of one process and vanish when it ends. They are
    written nowhere: no file, no log, no argument.
  - The vector files and a public report are the only results.
  - The keys can never sign again. Running this again draws NEW keys and needs the files removed
    first (prodk-undo.sh). Doing that is allowed until you commit or tag; after a tag it would change the
    published bundle.
  - Run it in this Terminal, not under a recorder, screen share or session logger.

MSG
printf 'Type exactly   sign production vectors   and press Return: '
answer=
read -r answer || :
[ "$answer" = "sign production vectors" ] || pl_die "not confirmed; nothing was done"

pl_hdr "4 sign (one process, keys in memory only)"
(cd "$repo" && $pl_uv run --project conformance/vectors/_gen python -I conformance/vectors/_gen/make_prodk.py \
    --out "$stage" --evidence "$evid/prodk-evidence.json" \
    --scan-root "$repo/conformance" --scan-root "$repo/spec" --scan-root "$logs" \
    --vitni-go "$pl_go" --vitni-ts "$pl_node $pl_cli") || pl_die "signing failed; no vector was written and no key exists"
pl_say "the signing process has ended: the production signing keys no longer exist anywhere"

pl_hdr "5 harness over the staged vectors"
pl_expect "files staged" "$count" "$(ls "$stage" | wc -l | tr -d ' ')"
pl_harness "$repo" "$stage" "$logs/harness-stage.log"
pl_expect "checker, both vitni verifiers, staged vectors" "$count vectors, 0 not passing" "$pl_harness_line"
if [ "$pl_fails" -ne 0 ]; then
    rm -rf "$stage" "$evid/prodk-evidence.json"
    pl_die "the staged vectors did not pass. They were removed. No key exists; run prodk.sh again (new keys, a new output directory)."
fi

pl_hdr "6 install into the working tree"
mkdir -p "$prod"
chmod 755 "$prod"
cp "$stage"/*.json "$prod"/
chmod 644 "$prod"/*.json
$pl_uv run python -I tools/manifest.py --write
pl_say "installed: $(ls "$prod" | wc -l | tr -d ' ') files in $prod; spec/MANIFEST.json rewritten"

pl_hdr "7 proof"
pl_expect "catalog at the tag: no hole, nothing pending" "0 holes, 0 pending" "$($pl_uv run python -I tools/check_catalog.py --final | tail -n 1)"
pl_expect "bundle manifest covers the new files" "bundle manifest: ok" "$($pl_uv run python -I tools/manifest.py --check | tail -n 1)"
pl_expect "pins unchanged" "pins ok" "$($pl_uv run python -I tools/repin.py --check | tail -n 1)"
pl_harness "$repo" "$prod" "$logs/harness-installed.log"
pl_expect "the installed files, from their place in the tree, both verifiers" "$count vectors, 0 not passing" "$pl_harness_line"
installed_line=$pl_harness_line
pl_finish || pl_die "The vectors are in the tree but a proof failed. Do not commit. Show the output above, then run sh tools/release/prodk-undo.sh and run this script again with a new output directory."

pl_hdr "8 final proof (15 to 25 minutes)"
proof_rc=0
sh "$here/final-proof.sh" "$out" || proof_rc=$?
proof_line=$(tail -n 1 "$out/proof/summary.txt" 2>/dev/null || :)
[ "$proof_rc" -eq 0 ] || pl_die "The final proof failed (read $out/proof). The vectors are in the tree. Do not commit. If the cause is the signed vectors, run sh tools/release/prodk-undo.sh and run this script again with a new output directory; if it is not, fix that first."

pl_hdr "9 evidence"
set -- "$evid/prodk-evidence.json" "$evid/prodk-evidence.md" --commit "$head" --branch "$branch" --harness "$installed_line" --proof "$proof_line"
[ -z "$task" ] || set -- "$@" --task "$task"
$pl_uv run --no-project python -I "$repo/conformance/vectors/_gen/prodk_evidence.py" "$@"
pl_say "public report   $evid/prodk-evidence.json"
pl_say "note for vault  $evid/prodk-evidence.md"
pl_say
pl_say "DONE. The production signing keys have been destroyed (see the note for how, and what cannot be promised)."
pl_say "Next: review 'git status' (the vector files and spec/MANIFEST.json), file the note in the vault, then commit and open the PR."
