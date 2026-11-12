"""The registry: key classes, the method table and the section 2 constants (KC-01, ACT-09).

Single owner of every table the registry carries. `load` reads the packaged
registry through `coredata.read_checked`, so a registry that is not the one the
profile hash covers is refused before any rule reads it. The shape is closed:
an unexpected member, algorithm or enum value is a `RegistryError`, because the
rules below index into it without further checks.

Nothing here names a class or a method in code: the rules read these tables.
Values of constants are decimal strings in the file (no JSON number appears in
a profile value); `number` turns one into an int.
"""
from collections import namedtuple

from . import coredata, ijson

TOP_KEYS = ("act_extra_key_types", "binding", "constants", "enums", "fixture_only",
            "key_classes", "methods", "registry_version")
CLASS_KEYS = ("alg", "hardware_bound", "id", "per_signature_user_verification", "status",
              "user_verification")
METHOD_KEYS = ("act_extra_keys", "body", "head", "inputs_hash", "method", "outputs_hash")
HEADS = ("always", "conditional", "never")

Class = namedtuple("Class", "id alg hardware_bound per_signature_user_verification "
                            "user_verification status")
Method = namedtuple("Method", "method act_extra_keys head body inputs_hash outputs_hash")


class RegistryError(Exception):
    pass


def _require(ok, message):
    if not ok:
        raise RegistryError(message)


def _class(entry, enums):
    _require(type(entry) is dict and tuple(sorted(entry)) == CLASS_KEYS, "class entry shape")
    _require(entry["alg"] in enums["alg"], "class algorithm: %r" % (entry["alg"],))
    _require(entry["status"] in enums["status"], "class status")
    uv = entry["user_verification"]
    _require(uv is None or uv in enums["user_verification"], "class user_verification")
    _require(type(entry["id"]) is str and entry["id"], "class id")
    _require(type(entry["hardware_bound"]) is bool
             and type(entry["per_signature_user_verification"]) is bool, "class flags")
    return Class(**entry)


def _method(entry):
    _require(type(entry) is dict and tuple(sorted(entry)) == METHOD_KEYS, "method entry shape")
    _require(entry["head"] in HEADS, "method head")
    _require(type(entry["body"]) is dict and tuple(entry["body"]) == ("keys",), "method body")
    keys = entry["act_extra_keys"]
    _require(type(keys) is list and keys == sorted(set(keys)), "method act_extra_keys")
    return Method(entry["method"], tuple(keys), entry["head"], entry["body"],
                  entry["inputs_hash"], entry["outputs_hash"])


class Registry:
    def __init__(self, doc):
        _require(type(doc) is dict and tuple(sorted(doc)) == TOP_KEYS, "registry shape")
        enums = doc["enums"]
        _require(enums["alg"] == ["ES256"], "only ES256 exists in version 1 (KC-05)")
        self.version = doc["registry_version"]
        self.binding = doc["binding"]
        self._classes = {}
        for entry in doc["key_classes"]:
            cls = _class(entry, enums)
            _require(cls.id not in self._classes, "duplicate class id")
            self._classes[cls.id] = cls
        self._fixture_only = {}
        for entry in doc["fixture_only"]:
            cls = _class(entry, enums)
            _require(cls.id not in self._classes and cls.id not in self._fixture_only,
                     "duplicate class id")
            self._fixture_only[cls.id] = cls
        self.methods = {}
        for entry in doc["methods"]:
            method = _method(entry)
            _require(method.method not in self.methods, "duplicate method")
            self.methods[method.method] = method
        self.act_extra_key_types = dict(doc["act_extra_key_types"])
        self._constants = doc["constants"]

    def classes(self, fixture):
        """`{id: Class}`; the fixture-only classes are part of it only under the fixture profile."""
        out = dict(self._classes)
        if fixture:
            out.update(self._fixture_only)
        return out

    def lookup_class(self, class_id, fixture):
        """The Class for `class_id` under the profile kind, or None (`class_unknown`)."""
        return self.classes(fixture).get(class_id)

    def method(self, name):
        """The Method for `name`, matched byte-exact, or None (`method_unknown`)."""
        return self.methods.get(name)

    def number(self, *path):
        """The int at `path` in the constants, e.g. `number("persons", "min")`.

        A missing name raises KeyError: a rule that reads a bound which does not
        exist is a bug, never a default.
        """
        node = self._constants
        for step in path:
            node = node[step]
        if type(node) is dict:
            node = node["value"]
        return int(node)


def load(data_dir=coredata.DATA_DIR):
    """The registry packaged under `data_dir`, verified against its manifest."""
    raw = coredata.read_checked(coredata.REGISTRY, data_dir)
    try:
        doc = ijson.loads(raw)
    except ijson.Unparseable as err:
        raise RegistryError("registry is not I-JSON: %s" % err) from err
    return Registry(doc)
