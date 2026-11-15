#!/bin/sh
# Install the handsal server build under /opt/handsal on Linux amd64 (SG-15, SG-14, RS4, CF-10).
#
#   sh tools/install/install-linux-server.sh ARTIFACT_DIR PUBLISHED_HASHES
#
# ARTIFACT_DIR holds the Linux files of the tag (vitni-verify, handsal-check-server,
# handsal-check-server.pyz, the pinned interpreter archive and the packed licences);
# PUBLISHED_HASHES holds the SHA-256 values published for that tag in `sha256sum` form
# (`<64 hex>  <file name>`), the values an image build pins from the published list. Every artifact is
# hashed and compared before anything privileged runs; any mismatch aborts before the first copy. Then
# each file is copied once into a root-owned staging directory, hashed again there, and only then moved
# into place. It is the step an image build runs, as root. The destination, the owner and the runner are
# fixed below, assigned after the environment is cleared of them; no variable or argument changes them.
# Needs only sh, sha256sum, tar and the coreutils at /usr/bin and /bin.
set -eu

PATH='/usr/bin:/bin'
export PATH
unset DEST_ROOT PRIV OWNER

DEST_ROOT='/opt/handsal'
PRIV='/usr/bin/env'
OWNER='root:root'

here=$(cd "$(dirname "$0")" && pwd)
if [ "$#" -ne 2 ]; then
    echo 'usage: install-linux-server.sh ARTIFACT_DIR PUBLISHED_HASHES' >&2
    exit 2
fi

# shellcheck source=install-lib.sh
. "$here/install-lib.sh"
profile_linux_server

# The server build is Linux on amd64 only (RS4); arm64 is a later, additive artifact. Root is required: the
# runner above only runs the command it is given, so a person's user would fail at the first privileged step.
if [ "$(uname -s)" != 'Linux' ] || [ "$(uname -m)" != 'x86_64' ]; then
    fail "the server build installs on Linux x86_64 only (this host: $(uname -s) $(uname -m)); nothing was done"
    exit 1
fi
if [ "$(/usr/bin/id -u)" != '0' ]; then
    fail 'run as root, as the image build does; nothing was done'
    exit 1
fi

status=0
install_run "$1" "$2" || status=$?
exit "$status"
