"""Refresh the core data the checker ships from the repo's core files.

    uv run --project checker/python python -I checker/python/sync_core.py

Copies the registry and the fixture kid list into `src/handsal_check/data/` and
writes `core-manifest.json` (the hash of every core file, CF-01). Run it
after any edit to a core file; `test_registry.py` fails until you do.
"""
import json
import shutil
import sys
from pathlib import Path

from handsal_check import coredata, encoding

ROOT = Path(__file__).resolve().parents[2]
COPIED = (coredata.REGISTRY, coredata.FIXTURE_KIDS)


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


if __name__ == "__main__":
    sync(ROOT, coredata.DATA_DIR)
