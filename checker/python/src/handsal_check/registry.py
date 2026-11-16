"""The registry: key classes, the method table and the section 2 constants (KC-01, ACT-09).

Single owner of every table the registry carries. `load` reads the packaged
registry through `coredata.read_checked`, so a registry that is not the one the
profile hash covers is refused before any rule reads it. The shape is closed:
an unexpected member, algorithm or enum value is a `RegistryError`, because the
rules below index into it without further checks.

Nothing here names a class or a method in code: the rules read these tables.
Values of constants are decimal strings in the file (no JSON number appears in
a profile value); `number` turns one into an int.

The registry has two parts (GP-23, I3). The **wire** part is what a parser may read before any profile is known:
the method table, `act_extra_key_types`, `binding`, `enums` and every constant that is not a policy bound. It is
the same in every edition, and `Registry.wire` is a `Wire`, a value of its own with no class and no policy
bound on it, so a parser handed one cannot read them. The **evaluation** part (the key classes, the
fixture-only classes, the policy-bound constants) and the registry's own version label are listed once, here;
everything else is wire by default, so a key nobody classified is frozen across editions and fails closed.
"""
import json
from collections import namedtuple

from . import coredata, ijson

TOP_KEYS = ("act_extra_key_types", "binding", "constants", "enums", "fixture_only",
            "key_classes", "methods", "registry_version")
CLASS_KEYS = ("alg", "hardware_bound", "id", "per_signature_user_verification", "status",
              "user_verification")
METHOD_KEYS = ("act_extra_keys", "body", "head", "inputs_hash", "method", "outputs_hash")
HEADS = ("always", "conditional", "never")
NOT_WIRE_KEYS = ("fixture_only", "key_classes", "registry_version")   # the evaluation part and the label
EVALUATION_CONSTANTS = ("clock_skew_s", "max_tip_age_s", "max_validity_s", "max_view_age_s", "persons", "relays")

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


def _number(constants, path):
    node = constants
    for step in path:
        node = node[step]
    if type(node) is dict:
        node = node["value"]
    return int(node)


class Wire:
    """What a parser may read of a registry (I3): the same value in every edition. It has no class and no policy
    bound: a class, `persons` or any other evaluation name is an AttributeError, never a silent read."""

    def __init__(self, doc, methods):
        self.methods = methods
        self.act_extra_key_types = dict(doc["act_extra_key_types"])
        self.binding = doc["binding"]
        self.enums = doc["enums"]
        part = {key: value for key, value in doc.items() if key not in NOT_WIRE_KEYS}
        part["constants"] = {name: value for name, value in doc["constants"].items()
                             if name not in EVALUATION_CONSTANTS}
        self._part = part

    def method(self, name):
        """The Method for `name`, matched byte-exact, or None (`method_unknown`)."""
        return self.methods.get(name)

    def number(self, *path):
        """The int at `path` in the wire constants. A policy bound is not here: AttributeError. A missing name
        is a KeyError: a rule that reads a bound which does not exist is a bug, never a default."""
        if path[0] in EVALUATION_CONSTANTS:
            raise AttributeError("%s is a policy bound, not part of the wire" % path[0])
        return _number(self._part["constants"], path)

    def canonical(self):
        """The bytes two editions must share: the wire part as JSON with sorted keys and no spaces."""
        return json.dumps(self._part, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Registry:
    def __init__(self, doc):
        _require(type(doc) is dict and tuple(sorted(doc)) == TOP_KEYS, "registry shape")
        enums = doc["enums"]
        _require(enums["alg"] == ["ES256"], "only ES256 exists in version 1 (KC-05)")
        self.version = doc["registry_version"]
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
        methods = {}
        for entry in doc["methods"]:
            method = _method(entry)
            _require(method.method not in methods, "duplicate method")
            methods[method.method] = method
        self.wire = Wire(doc, methods)
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

    def number(self, *path):
        """The int at `path` in the constants, e.g. `number("persons", "min")`.

        A missing name raises KeyError: a rule that reads a bound which does not
        exist is a bug, never a default.
        """
        return _number(self._constants, path)


def parse(raw):
    """The registry in the bytes `raw`, whatever edition they belong to."""
    try:
        doc = ijson.loads(raw)
    except ijson.Unparseable as err:
        raise RegistryError("registry is not I-JSON: %s" % err) from err
    return Registry(doc)


def load(data_dir=None):
    """The registry packaged under `data_dir`, verified against its manifest."""
    return parse(coredata.read_checked(coredata.REGISTRY, data_dir))
