#!/bin/sh
# Take the production vectors of an uncommitted PRODK run out of the tree again (CF-08, T8.6, T15.10).
#
#   sh tools/release/prodk-undo.sh
#
# Removes conformance/vectors/prod and rewrites spec/MANIFEST.json, so tools/release/prodk.sh can run again with new
# keys. It revives no key: the signing keys of the first run are gone. Allowed until the vectors are committed:
# after that a replacement changes a published bundle, and this script refuses (status 2, nothing touched).
set -eu

pl_tool=prodk-undo
here=$(cd "$(dirname "$0")" && pwd)
. "$here/proof-lib.sh"
repo=$(cd "$here/../.." && pwd)
prod=$repo/conformance/vectors/prod

[ $# -eq 0 ] || pl_refuse "usage: prodk-undo.sh (no argument)"
if [ ! -d "$prod" ] || [ -z "$(ls -A "$prod")" ]; then
    pl_say "nothing to undo: $prod is absent or empty"
    exit 0
fi
if [ -n "$(git -C "$repo" ls-files conformance/vectors/prod)" ]; then
    pl_refuse "the production vectors are committed; a replacement would change a published bundle"
fi
rm -rf "$prod"
(cd "$repo" && $pl_uv run python -I tools/manifest.py --write)
pl_say "removed. check_catalog now: $(cd "$repo" && $pl_uv run python -I tools/check_catalog.py | tail -n 1)"
