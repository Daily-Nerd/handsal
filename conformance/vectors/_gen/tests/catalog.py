"""Shared helpers for the group tests: load a group's vectors and read the catalog.

The catalog (conformance/effective-rows.json) is the independent statement of
what each row must produce. A group table that disagrees with it fails here.
"""
import json
import re
import tempfile
from pathlib import Path

import generate

ROWS = json.loads((Path(generate.CONFORMANCE) / "effective-rows.json")
                  .read_text(encoding="utf-8"))["rows"]


def generate_group(module_name, prefixes):
    """{name: vector} for the vectors one group module writes."""
    return generate_modules([module_name], prefixes)


def generate_modules(module_names, prefixes):
    """{name: vector} for the vectors of several group modules, run in the given order."""
    import importlib
    modules = [importlib.import_module("groups." + name) for name in module_names]
    with tempfile.TemporaryDirectory() as d:
        out = Path(d)
        generate.run(out, registry=modules, known_ids=generate.shipping_ids())
        found = {}
        for prefix in prefixes:
            for path in sorted(out.glob(prefix + ".*.json")):
                doc = json.loads(path.read_text(encoding="utf-8"))
                found[doc["name"]] = doc
        return found


def catalog_code(name):
    """The reason or error code the catalog expects for row `name`.

    `valid` is `ok`. The first backticked token is the code; a token that is an
    `{"error":...}` object gives its error code.
    """
    expected = ROWS[name]["expected"]
    token = re.search(r"`([^`]+)`", expected)
    if token is None:
        return "ok" if expected.strip().startswith("valid") else None
    text = token.group(1)
    if text.startswith("{"):
        return json.loads(text)["error"]
    return text


def anchor_code(vector):
    """The code in a vector's anchor: `reason` of a result, or the `error` code."""
    obj = json.loads(vector["anchor"])
    return obj.get("error", obj.get("reason"))
