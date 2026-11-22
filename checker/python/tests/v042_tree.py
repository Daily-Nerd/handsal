"""A released version of the checker package, read from the git history of the checkout.

`sources(tag)` is the text of every module of the package at a tag, for the tests that compare files. `load(tag)` is
that package imported next to the current one under a name of its own (`handsal_check_v042` for `v0.4.2`), for the
tests that compare answers: the two share a process, a module is the module of its own package, and the packaged data
is read from the copy that belongs to the tag, because the package reads it by its own name. The tag is read with
`git archive`, as the older-edition tests read theirs; a tag that is not fetched is an error (`TagMissing`), never a
reason to skip.
"""
import atexit
import importlib
import importlib.util
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = "checker/python/src/handsal_check"

_extracted = {}
_loaded = {}


class TagMissing(RuntimeError):
    """The tag cannot be read: the checkout does not hold it."""


def name_of(tag):
    """The name the package of `tag` is imported under: `v0.4.2` is `handsal_check_v042`."""
    return "handsal_check_" + tag.replace(".", "")


def checkout(tag):
    """The directory holding the package at `tag`, extracted once per process and removed at exit."""
    if tag in _extracted:
        return _extracted[tag]
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", tag, PACKAGE], capture_output=True)
    if archive.returncode != 0:
        raise TagMissing("the tag %s is not fetched: %s (CF-15: fetch the whole history and every tag)"
                         % (tag, archive.stderr.decode().strip()))
    tmp = Path(tempfile.mkdtemp())
    atexit.register(shutil.rmtree, tmp, True)
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(tmp, filter="data")
    target = tmp / name_of(tag)
    shutil.move(str(tmp / PACKAGE), str(target))
    _extracted[tag] = target
    return target


def sources(tag):
    """`{module name: bytes}` of the `.py` files of the package at `tag`."""
    return {path.stem: path.read_bytes() for path in sorted(checkout(tag).glob("*.py"))}


def load(tag):
    """The package at `tag`, imported as `name_of(tag)`; its modules are `importlib.import_module(name + ".x")`."""
    if tag in _loaded:
        return _loaded[tag]
    where, name = checkout(tag), name_of(tag)
    spec = importlib.util.spec_from_file_location(name, where / "__init__.py", submodule_search_locations=[str(where)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[name] = package
    spec.loader.exec_module(package)
    _loaded[tag] = package
    return package


def module(tag, name):
    """The module `name` of the package at `tag`."""
    return importlib.import_module("%s.%s" % (load(tag).__name__, name))
