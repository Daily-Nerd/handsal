"""The administrator-owned launchers of the checker builds (T4.5, T13.5, SG-14, GP-17).

`render(root, zipapp)` returns the text of a POSIX shell script that replaces itself
with the pinned interpreter, isolated, running the zipapp, both named by
absolute path under `root`. It reads nothing from the environment and does no
PATH lookup: the paths are baked in when the text is rendered. `-I -E -s` is
the GP-17 form (`python -I -E -s`: no user site, no environment, no script
directory on the path).

Layout under the root (the installer, SG-15, copies each piece there):

    <root>/bin/handsal-check              this launcher        (SG-14 path)
    <root>/lib/handsal-check.pyz          the zipapp
    <root>/python/bin/python3             the pinned CPython
    <root>/python/licenses/               the notices that travel with it

The Linux server build (CF-10, RS4) has the same layout under /opt/handsal with the names
`bin/handsal-check-server` and `lib/handsal-check-server.pyz`; its vitni is `<root>/bin/vitni-verify`.

Standard library only.
"""
import sys

MACOS_ROOT = "/Library/Application Support/handsal"
LAUNCHER_PATH = MACOS_ROOT + "/bin/handsal-check"
LINUX_ROOT = "/opt/handsal"
LINUX_LAUNCHER_NAME = "handsal-check-server"
LINUX_ZIPAPP_NAME = "handsal-check-server.pyz"


class LauncherError(Exception):
    pass


def render(root, zipapp="handsal-check.pyz"):
    """The launcher text for an installation at the absolute `root`, running `lib/<zipapp>`."""
    if not isinstance(root, str) or not root.startswith("/") or "'" in root or any(
            ch == "\x00" or ch == "\n" or ch == "\r" for ch in root):
        raise LauncherError("root must be an absolute path without a quote or a control line break: %r" % (root,))
    interpreter = "%s/python/bin/python3" % root.rstrip("/")
    path = "%s/lib/%s" % (root.rstrip("/"), zipapp)
    return "#!/bin/sh\nexec '%s' -I -E -s '%s' \"$@\"\n" % (interpreter, path)


def render_macos():
    return render(MACOS_ROOT)


def render_linux_server():
    return render(LINUX_ROOT, LINUX_ZIPAPP_NAME)


# One entry per platform of tools/artifact_hashes.py; tools/tests/test_artifact_hashes.py compares the two.
RENDERERS = {"macos-arm64": render_macos, "macos-x86_64": render_macos, "linux-x86_64": render_linux_server}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in RENDERERS:
        print("usage: launcher.py (%s)   (writes the launcher text of that platform to stdout)"
              % "|".join(sorted(RENDERERS)), file=sys.stderr)
        return 2
    sys.stdout.write(RENDERERS[argv[0]]())
    return 0


if __name__ == "__main__":
    sys.exit(main())
