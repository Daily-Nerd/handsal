#!/bin/sh
# Build the two vitni verifiers the final proof judges with, and nothing else: no key, no signing, no change to the
# tree (CF-08, T15.10). For a release that runs no PRODK run. One command from a clean checkout of the commit to be
# tagged:
#
#   sh tools/release/proof-verifiers.sh OUT
#   sh tools/release/final-proof.sh OUT
#
# OUT must not exist or be empty, and must be outside the repository. It receives OUT/vitni (the Go verifier for this
# machine and the TypeScript verifier, from the vitni commit pinned in tools/release/vitni-commit) and OUT/logs. The
# build is pl_build_verifiers of proof-lib.sh, the same one prodk.sh runs, so both lay OUT out the same way.
#
# Refused with status 2 and nothing made: a missing or extra argument, an argument that starts with a dash, an OUT
# that holds anything, an OUT inside the repository, a tree with tracked changes or untracked inputs. Status 1 and a
# STOP line naming the log: a build step failed.
# Needs: git, go, node, npm.
set -eu

pl_tool=proof-verifiers
here=$(cd "$(dirname "$0")" && pwd)
. "$here/proof-lib.sh"
repo=$(cd "$here/../.." && pwd -P)

[ $# -eq 1 ] || pl_refuse "usage: proof-verifiers.sh OUT"
case $1 in
    -*) pl_refuse "the argument starts with a dash: $1" ;;
    "") pl_refuse "the argument is empty" ;;
esac
pl_new_out "$1" "$repo"
pl_say "output   $pl_out"
pl_build_verifiers "$pl_out"
pl_say "Next: sh tools/release/final-proof.sh $pl_out"
