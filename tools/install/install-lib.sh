#!/bin/sh
# The installation procedure of SG-15, as functions. Sourced by install-macos.sh, which fixes the
# destination, the privileged runner and the owner; the tests source it with a temporary
# destination and a stand-in runner. Nothing here has a default for those three, so a caller that
# forgets one gets a refusal, not the administrator path.
#
# The rule (SG-15): before the privileged copy, the SHA-256 of each artifact is computed and
# compared with the value published for the tag, read on a second device. Any mismatch aborts.
# What this adds, and why:
#   - nothing privileged happens before every artifact verifies;
#   - the privileged copy goes into a root-owned staging directory, and the copy is hashed again
#     before it is moved into place, because the first check read a file the person's user can
#     still change (an agent between the check and the copy would win otherwise);
#   - the closed list of artifacts below is the whole of what is ever copied: the conformance
#     executables are not on it, so they cannot be installed however they got into the directory;
#   - an interpreter archive is extracted without the owner its members name, then owned by root;
#   - every check and every unpack happens in the staging directory, which sits beside the destination
#     (same file system, so each move is a rename). Nothing is created at the destination until all of
#     them passed, so a failure before that leaves the install location as it was;
#   - the installer reads only what a stock macOS reads at its fixed PATH: gzip tar archives (the licence
#     texts are repacked from the upstream notices archive at packaging time, tools/pack_licenses.py), and
#     the tools of PATH_TOOLS and the absolute tools below, all checked present before any privileged step.
# The installer never creates, reads or writes `orgs` or `pin.lock` (GP-21): the pin helper owns
# them. It creates `handsal` and the directories of its own artifacts (see the note at `prepare`).
#
# Variables the caller sets (no defaults):
#   DEST_ROOT  the installation root, `/Library/Application Support/handsal` on macOS
#   PRIV       the privileged runner, `/usr/bin/sudo`
#   OWNER      `root:wheel`, or empty for a test that cannot be root
# Exit codes: 0 installed; 1 an artifact missing, not published, malformed, or its hash differs, or a
# required tool is missing (nothing was done); 3 a privileged step failed, a staged copy differs or an
# archive does not unpack to what is needed (staging removed; the destination untouched unless the
# failing step was one of the final moves).

log() { printf 'install: %s\n' "$*"; }
fail() { printf 'install: %s\n' "$*" >&2; }

HASH_TOOL=/usr/bin/shasum
TAR_TOOL=/usr/bin/tar
# The tools taken from PATH (the installer's PATH is fixed to the system directories). The tests build a
# PATH holding only these, so a tool added to the code and not here fails there.
PATH_TOOLS="awk cut wc uname"

hash_of() { "$HASH_TOOL" -a 256 "$1" | cut -d' ' -f1; }

# priv COMMAND...: the privileged runner, then the command by absolute path.
priv() { "$PRIV" "$@"; }

# preflight: every tool the install runs exists, before anything privileged. Absolute paths are checked as
# files, the PATH_TOOLS by lookup in the PATH the caller fixed. A refusal names the tool.
preflight() {
    _absent=
    for _tool in "$HASH_TOOL" "$TAR_TOOL" /usr/bin/install /bin/mkdir /bin/mv /bin/rm /bin/chmod "$PRIV"; do
        [ -x "$_tool" ] || _absent="$_absent $_tool"
    done
    if [ -n "$OWNER" ]; then [ -x /usr/sbin/chown ] || _absent="$_absent /usr/sbin/chown"; fi
    for _tool in $PATH_TOOLS; do
        command -v "$_tool" > /dev/null 2>&1 || _absent="$_absent $_tool"
    done
    if [ -n "$_absent" ]; then
        fail "a required tool is missing:$_absent (nothing was done)"
        return 1
    fi
}

# published_for NAME FILE: the one published hash of NAME. Two lines for a name, none, or a value
# that is not 64 lowercase hex digits are refusals.
published_for() {
    _count=$(awk -v n="$1" '$2 == n { c++ } END { print c + 0 }' "$2")
    if [ "$_count" -ne 1 ]; then
        fail "$1: $_count published values, expected exactly one"
        return 1
    fi
    _value=$(awk -v n="$1" '$2 == n { print $1 }' "$2")
    case $_value in
        *[!0-9a-f]*) fail "$1: the published value is not lowercase hex"; return 1 ;;
    esac
    if [ "${#_value}" -ne 64 ]; then
        fail "$1: the published value is not 64 hex digits"
        return 1
    fi
    printf '%s\n' "$_value"
}

# find_one DIR PATTERN: the one file name in DIR matching PATTERN.
find_one() {
    _hits=$(cd "$1" && for f in $2; do [ -e "$f" ] && printf '%s\n' "$f"; done)
    if [ -z "$_hits" ] || [ "$(printf '%s\n' "$_hits" | wc -l)" -ne 1 ]; then
        fail "expected exactly one file matching $2 in $1"
        return 1
    fi
    printf '%s\n' "$_hits"
}

# verify_one DIR NAME PUBLISHED: a regular file, not a symlink, whose hash is the published one.
verify_one() {
    if [ -L "$1/$2" ] || [ ! -f "$1/$2" ]; then
        fail "$2: not a regular file in $1"
        return 1
    fi
    _want=$(published_for "$2" "$3") || return 1
    _got=$(hash_of "$1/$2")
    if [ "$_got" != "$_want" ]; then
        fail "$2: MISMATCH (computed $_got, published $_want): aborting before any copy"
        return 1
    fi
    log "$2 matches the published value"
}

owned_args() { if [ -n "$OWNER" ]; then printf -- '-o %s -g %s' "${OWNER%%:*}" "${OWNER##*:}"; fi; }

# install_dir PATH: a root-owned directory, 0755, by the same tool whatever the umask.
install_dir() {
    if [ -n "$OWNER" ]; then
        priv /usr/bin/install -d -o "${OWNER%%:*}" -g "${OWNER##*:}" -m 0755 "$1"
    else
        priv /usr/bin/install -d -m 0755 "$1"
    fi
}

# install_file MODE SRC DEST: one privileged copy with the owner and mode.
install_file() {
    if [ -n "$OWNER" ]; then
        priv /usr/bin/install -o "${OWNER%%:*}" -g "${OWNER##*:}" -m "$1" "$2" "$3"
    else
        priv /usr/bin/install -m "$1" "$2" "$3"
    fi
}

# stage NAME SRC MODE PUBLISHED: copy into staging, hash the copy, and keep it only if it still
# matches. The copy is root-owned, so nothing the person's user does can change it after this.
stage() {
    install_file "$3" "$2" "$STAGING/$1" || return 3
    _want=$(published_for "$1" "$4") || return 1
    _got=$(priv "$HASH_TOOL" -a 256 "$STAGING/$1" | cut -d' ' -f1)
    if [ "$_got" != "$_want" ]; then
        fail "$1: the copy differs from the published value (computed $_got): the file changed after it was checked"
        return 3
    fi
}

# unpack ARCHIVE INTO: extract without the owners the archive names, then own and restrict the result.
unpack() {
    priv /bin/mkdir -p "$2" || return 3
    priv "$TAR_TOOL" -xf "$1" -C "$2" --no-same-owner || return 3
    if [ -n "$OWNER" ]; then priv /usr/sbin/chown -R "$OWNER" "$2" || return 3; fi
    priv /bin/chmod -R go-w "$2" || return 3
}

cleanup_staging() {
    if [ -n "${STAGING:-}" ]; then priv /bin/rm -rf "$STAGING" || true; fi
}

# prepare: the staging directory, root-owned 0700, beside the destination. It is the only thing created
# before every check and unpack has passed; the destination and its directories wait for `place`.
prepare() {
    STAGING="$DEST_ROOT.staging.$$"
    priv /bin/rm -rf "$STAGING" || return 3
    priv /usr/bin/install -d -m 0700 "$STAGING" || return 3
    if [ -n "$OWNER" ]; then priv /usr/sbin/chown "$OWNER" "$STAGING" || return 3; fi
}

# assemble: the final python/ tree, inside staging. The licence texts replace whatever python/licenses the
# interpreter archive carried (the notices of the same platform are the complete set).
assemble() {
    if [ ! -d "$STAGING/tree/python" ] || [ ! -d "$STAGING/notices/python/licenses" ]; then
        fail "the archives do not hold python/ and python/licenses/"
        return 3
    fi
    priv /bin/rm -rf "$STAGING/tree/python/licenses" || return 3
    priv /bin/mv "$STAGING/notices/python/licenses" "$STAGING/tree/python/licenses" || return 3
}

# place: `handsal` and the directories of the installed artifacts, root-owned 0755 (GP-21, SG-15: the helper
# lives in `handsal/bin`, so the installer creates `handsal`, `bin` and `lib`, and `python` by the move, with
# the attributes the reader checks, GP-10; the helper alone creates `orgs` and `pin.lock`), then the staged,
# re-verified pieces moved to their exact paths. Every move is a rename within one file system. A previous
# python/ is set aside first and put back if the move of the new one fails.
place() {
    install_dir "$DEST_ROOT" || return 3
    install_dir "$DEST_ROOT/bin" || return 3
    install_dir "$DEST_ROOT/lib" || return 3
    for _pair in vitni-verify:bin/vitni-verify handsal-pin:bin/handsal-pin handsal-check:bin/handsal-check \
        handsal-check.pyz:lib/handsal-check.pyz; do
        priv /bin/mv -f "$STAGING/${_pair%%:*}" "$DEST_ROOT/${_pair##*:}" || return 3
    done
    priv /bin/rm -rf "$DEST_ROOT/python.old" || return 3
    if [ -e "$DEST_ROOT/python" ]; then priv /bin/mv "$DEST_ROOT/python" "$DEST_ROOT/python.old" || return 3; fi
    if ! priv /bin/mv "$STAGING/tree/python" "$DEST_ROOT/python"; then
        if [ -e "$DEST_ROOT/python.old" ]; then priv /bin/mv "$DEST_ROOT/python.old" "$DEST_ROOT/python" || true; fi
        return 3
    fi
    priv /bin/rm -rf "$DEST_ROOT/python.old" || return 3
}

# install_run ARTIFACT_DIR PUBLISHED_FILE
install_run() {
    : "${DEST_ROOT:?DEST_ROOT is not set}" "${PRIV:?PRIV is not set}"
    [ -n "${OWNER+set}" ] || { fail "OWNER is not set"; return 2; }
    [ -d "$1" ] && [ -f "$2" ] || { fail "usage: install ARTIFACT_DIR PUBLISHED_HASHES"; return 2; }
    [ -d "${DEST_ROOT%/*}" ] || { fail "${DEST_ROOT%/*} is not a directory (nothing was done)"; return 1; }
    preflight || return 1
    case $(uname -m) in
        arm64) _triple=aarch64-apple-darwin ;;
        x86_64) _triple=x86_64-apple-darwin ;;
        *) fail "no pinned interpreter for $(uname -m)"; return 1 ;;
    esac
    _interpreter=$(find_one "$1" "cpython-*-$_triple-install_only.tar.gz") || return 1
    _licenses=$(find_one "$1" "handsal-python-licenses-*-$_triple.tar.gz") || return 1

    # 1. every artifact, before anything privileged
    for _name in vitni-verify handsal-pin handsal-check handsal-check.pyz "$_interpreter" "$_licenses"; do
        verify_one "$1" "$_name" "$2" || return 1
    done

    # 2. one privileged copy of each into root-owned staging beside the destination, hashed again, unpacked
    #    and checked there; only then is anything created at the destination
    STAGING=
    prepare || { fail "could not prepare the staging directory"; cleanup_staging; return 3; }
    _fail=0
    stage vitni-verify "$1/vitni-verify" 0755 "$2" || _fail=$?
    [ "$_fail" -eq 0 ] && { stage handsal-pin "$1/handsal-pin" 0755 "$2" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { stage handsal-check "$1/handsal-check" 0755 "$2" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { stage handsal-check.pyz "$1/handsal-check.pyz" 0644 "$2" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { stage "$_interpreter" "$1/$_interpreter" 0644 "$2" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { stage "$_licenses" "$1/$_licenses" 0644 "$2" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { unpack "$STAGING/$_interpreter" "$STAGING/tree" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { unpack "$STAGING/$_licenses" "$STAGING/notices" || _fail=$?; }
    [ "$_fail" -eq 0 ] && { assemble || _fail=$?; }
    [ "$_fail" -eq 0 ] && { place || _fail=$?; }
    cleanup_staging
    if [ "$_fail" -ne 0 ]; then
        fail "installation failed; nothing was moved into place after the failing step"
        return 3
    fi
    log "installed under $DEST_ROOT"
}
