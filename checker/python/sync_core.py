"""Refresh the core data the checker ships from the repo's core files.

    uv run --project checker/python python -I checker/python/sync_core.py

Copies the registry and the fixture kid list of the current edition into `src/handsal_check/data/` and
writes `core-manifest.json` (the hash of every core file, CF-01). It then mirrors the repo's `profiles/` (the
catalog and the frozen edition directories, GP-22) into `src/handsal_check/data/profiles/`, because the zipapp
reads its data through `importlib.resources`. The repo's `profiles/` is only read: a frozen edition is never
written here, and a second run changes nothing. Run it after any edit to a core file; `test_registry.py` fails
until you do.
"""
import json
import shutil
import sys
from pathlib import Path

from handsal_check import coredata, encoding

ROOT = Path(__file__).resolve().parents[2]
COPIED = (coredata.REGISTRY, coredata.FIXTURE_KIDS)
PROFILES = "profiles"


def sync(root, dest):
    root, dest = Path(root), Path(dest)
    manifest = {}
    for rel in coredata.CORE_FILES:
        try:
            manifest[rel] = encoding.hashstr((root / rel).read_bytes())
        except OSError as err:
            raise SystemExit("core file unreadable: %s (%s)" % (rel, err))
    for rel in COPIED:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / rel, target)
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (dest / coredata.MANIFEST).write_text(text, encoding="utf-8")
    _mirror_profiles(root / PROFILES, dest / PROFILES)


def _mirror_profiles(source, target):
    """`target` is a byte copy of `source`, or absent when `source` is: the packaged set is the repo's set."""
    if target.exists():
        shutil.rmtree(target)
    if source.is_dir():
        shutil.copytree(source, target)


if __name__ == "__main__":
    sync(ROOT, coredata.DATA_DIR)
