#!/bin/sh
# Install the handsal binaries at the administrator paths of macOS (SG-15, SG-14).
#
#   sh tools/install/install-macos.sh ARTIFACT_DIR PUBLISHED_HASHES
#
# ARTIFACT_DIR holds the files of the tag; PUBLISHED_HASHES holds the SHA-256 values published for
# that tag in `sha256sum` form (`<64 hex>  <file name>`), read by you on a second device, not
# downloaded to this machine. Every artifact is hashed and compared before anything privileged
# runs; any mismatch aborts. Then each file is copied once into a root-owned staging directory,
# hashed again there, and only then moved into place. The destination, the privileged runner and
# the owner are fixed below, assigned after the environment is cleared of them; no variable or
# argument changes them. The two conformance executables are not on the list of what is copied.
set -eu

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset DEST_ROOT PRIV OWNER

DEST_ROOT='/Library/Application Support/handsal'
PRIV='/usr/bin/sudo'
OWNER='root:wheel'

here=$(cd "$(dirname "$0")" && pwd)
if [ "$#" -ne 2 ]; then
    echo 'usage: install-macos.sh ARTIFACT_DIR PUBLISHED_HASHES' >&2
    exit 2
fi

# shellcheck source=install-lib.sh
. "$here/install-lib.sh"
status=0
install_run "$1" "$2" || status=$?
/usr/bin/sudo -k
exit "$status"
