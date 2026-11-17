"""Vector writer (CF-02, CF-07).

One JSON file per vector, `{name, command, input | input_raw | input_hex,
anchor, pad?, exit?}`. The contract lives in conformance/vector_schema.py and
every document is checked against it before it is written. `anchor` is a
required string, the exact output line (CF-02). Keys are sorted and the text
is plain ASCII with a single trailing LF, so a rerun is byte-identical (CF-06).

Names are `group/case`. The group must be one of GROUPS (the prefixes of the
catalog). When a set of shipping ids is given (`vector-ids.json`, built in a
later task) an unlisted name is refused too. The file is named
`<group>.<case>.json` inside the target directory.
"""
import json
import re
import sys
from pathlib import Path

# The vector schema is owned by the harness (conformance/vector_schema.py) and
# shared here, so this writer cannot emit a file the harness rejects. This is
# the conformance harness, not a checker: the generator still imports no checker code.
_CONFORMANCE = str(Path(__file__).resolve().parents[3])
if _CONFORMANCE not in sys.path:
    sys.path.insert(0, _CONFORMANCE)
from vector_schema import VectorError, validate  # noqa: E402

GROUPS = frozenset(
    "add bod cas cf chg chk cli cln cls dec end enr fix fld frk frs gen idn ing inp jcs "
    "jws key lnk mem mth ok ord org pin pol prf quo rck rem rep rev rly rnd rsv sch sgn sig "
    "tim vrd vtn wit adm kpl cmp hed aid".split()
)

# lowercase hyphenated words; one catalog id (rnd/hash12-skips-uEi) has a capital
_NAME = re.compile(r"^([a-z0-9]+)/([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)$")


class VectorWriter:
    def __init__(self, directory, known_ids=None):
        self.directory = Path(directory)
        self.known_ids = None if known_ids is None else frozenset(known_ids)
        self._seen = set()
        self.names = []  # names written, in order

    def _check_name(self, name):
        match = _NAME.match(name) if isinstance(name, str) else None
        if not match:
            raise VectorError("bad vector name: %r" % (name,))
        if match.group(1) not in GROUPS:
            raise VectorError("unknown group %r in %r" % (match.group(1), name))
        if self.known_ids is not None and name not in self.known_ids:
            raise VectorError("name not in the shipping id list: %r" % name)
        if name in self._seen:
            raise VectorError("duplicate vector name: %r" % name)
        return match.group(1), match.group(2)

    def add(self, name, command, anchor, *, input=None, input_raw=None, input_hex=None,
            pad=None, exit=None):
        group, case = self._check_name(name)
        doc = {"name": name, "command": command, "anchor": anchor}
        for key, value in (("input", input), ("input_raw", input_raw), ("input_hex", input_hex),
                           ("pad", pad), ("exit", exit)):
            if value is not None:
                doc[key] = value
        validate(doc, name)
        try:
            text = json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise VectorError("%s: not serializable: %s" % (name, exc)) from exc
        path = self.directory / ("%s.%s.json" % (group, case))
        path.write_bytes((text + "\n").encode("ascii"))
        self._seen.add(name)
        self.names.append(name)
        return path
