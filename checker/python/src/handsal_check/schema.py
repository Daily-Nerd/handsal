"""Field formats and the closed-object engine (ACT-07, ACT-09, ACT-10, section 2.2).

Single owner of every field form. The hashstr primitive lives in `encoding`;
this module is where a field *type name* (the names the registry uses) becomes
a yes or no. The registry's body schemas are interpreted here, so a method's
body has one definition (the registry) and one reader (`check`).

Which reason code a defect gets follows ACT-07 and ACT-09:
- the forms ACT-07 names (`hashstr`, `time`, `member_id`, `decimal`) are always
  `schema`, wherever the field sits, a `chain.resolve` body included;
- any other defect (structure, list length, order, another form) gets the code
  of the container being checked: `schema` for the act object, `body_schema`
  for a body (a node can say so with `"code"`).
`check` walks the whole value and reports `schema` first, so one value with
both kinds of defect yields the code VR-02 step 5 orders first.

Node vocabulary (what the registry files use):
  {"type": T}                          a leaf of form T (a key of FORMS)
  {"const": text}                      exactly that string
  {"keys": {name: node}}               a closed object: exactly these keys
  {"type": "list", "of": T | node,     a list; `cap` names a registry bound
   "cap": name, "sorted": bool,        (`min`/`max`), `sorted`/`distinct` apply
   "distinct": bool,                   to string elements, `sorted_by`/
   "sorted_by": key, "distinct_by": key}  `distinct_by` to a member of each
                                        object element
An unknown type name is a KeyError: the table and the registry disagree, and
that is a bug, not input.
"""
import calendar
import re

from . import encoding, errors

_ASCII = re.ASCII
_MEMBER = re.compile(r"[a-z0-9][a-z0-9-]{1,31}", _ASCII)
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}", _ASCII)
_REQUEST = re.compile(r"[a-z0-9][a-z0-9-]{7,35}", _ASCII)
_RECORD = re.compile(r"[a-z0-9][a-z0-9-]{1,31}", _ASCII)
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,8}", _ASCII)
_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z", _ASCII)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", _ASCII)


def _match(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def is_hashstr(value):
    return encoding.is_hashstr(value)


def is_b64u32(value):
    """Canonical base64url of exactly 32 bytes (43 characters)."""
    if type(value) is not str or len(value) != 43:
        return False
    try:
        return len(encoding.b64u_decode(value)) == 32
    except ValueError:
        return False


is_kid = is_b64u32   # a kid is the 43-character thumbprint of a key (ACT-11)


def is_member_id(value):
    return _match(_MEMBER, value)


def is_role_id(value):
    return _match(_ROLE, value)


def is_class_id(value):
    """Registry class ids use the role id alphabet (section 2.2 names no class alphabet)."""
    return _match(_ROLE, value)


def is_request_id(value):
    return _match(_REQUEST, value)


def is_record_id(value):
    return _match(_RECORD, value)


def is_text(value, maximum):
    return encoding.is_plain_text(value) and 1 <= len(value) <= maximum


def is_label(value):
    return is_text(value, 64)


def is_org_name(value):
    return is_text(value, 24)


def is_anchor(value):
    return is_text(value, 128)


def is_decimal(value):
    return _match(_DECIMAL, value)


def _days_in(year, month):
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def is_time(value):
    """`YYYY-MM-DDTHH:MM:SSZ`, a real calendar date, seconds 00 to 59."""
    m = _TIME.fullmatch(value) if type(value) is str else None
    if m is None:
        return False
    year, month, day, hour, minute, second = (int(g) for g in m.groups())
    return (1 <= month <= 12 and 1 <= day <= _days_in(year, month)
            and hour <= 23 and minute <= 59 and second <= 59)


def seconds(value):
    """Seconds since 1970-01-01T00:00:00Z of the `time` value `value` (UTC, no leap seconds). A value that
    is no `time` is a caller bug (the command checked it), not an input: ValueError."""
    if not is_time(value):
        raise ValueError("not a time: %r" % (value,))
    year, month, day, hour, minute, second = (int(g) for g in _TIME.fullmatch(value).groups())
    return calendar.timegm((year, month, day, hour, minute, second))


def _is_ldh_label(label):
    if _HOST_LABEL.fullmatch(label) is None:
        return False
    if label.startswith("xn--"):
        try:
            return bool(label[4:]) and bool(label[4:].encode("ascii").decode("punycode"))
        except (UnicodeError, ValueError):
            return False
    return True


def is_hostname(value):
    """Lowercase ASCII LDH labels, punycode for IDN, no trailing dot or port, at most 253."""
    if type(value) is not str or not 1 <= len(value) <= 253:
        return False
    return all(_is_ldh_label(label) for label in value.split("."))


FORMS = {
    "hashstr": is_hashstr,
    "b64u32": is_b64u32,
    "kid": is_kid,
    "member_id": is_member_id,
    "role_id": is_role_id,
    "class_id": is_class_id,
    "request_id": is_request_id,
    "record_id": is_record_id,
    "label": is_label,
    "org_name": is_org_name,
    "anchor": is_anchor,
    "hostname": is_hostname,
    "time": is_time,
    "decimal": is_decimal,
}

ACT07_FORMS = frozenset(("hashstr", "time", "member_id", "decimal"))


def _cap(reg, name, bound):
    return reg.number(*name.split("."), bound)


def _order_defect(node, items):
    """True if `items` break the node's sorted/distinct rule.

    The compared values are the elements themselves (strings) or, with
    `sorted_by`/`distinct_by`, the named member of each object element.
    Elements that cannot be compared are skipped: their own form defect is
    reported by the walk.
    """
    by = node.get("sorted_by", node.get("distinct_by"))
    if by is None:
        keys = items
        orderable = all(type(it) is str for it in items)
    else:
        orderable = all(type(it) is dict and type(it.get(by)) is str for it in items)
        keys = [it[by] for it in items] if orderable else []
    if not orderable:
        return False
    if (node.get("sorted") or node.get("sorted_by")) and any(a > b for a, b in zip(keys, keys[1:])):
        return True
    return bool(node.get("distinct") or node.get("distinct_by")) and len(set(keys)) != len(keys)


def _walk(node, value, reg, code, found):
    code = node.get("code", code)
    if "const" in node:
        if type(value) is not str or value != node["const"]:
            found.append(code)
    elif "keys" in node:
        if type(value) is not dict:
            found.append(code)
            return
        expected = node["keys"]
        if set(value) != set(expected):
            found.append(code)
        for name, child in expected.items():
            if name in value:
                _walk(child, value[name], reg, code, found)
    elif node["type"] == "list":
        if type(value) is not list:
            found.append(code)
            return
        if "cap" in node and not _cap(reg, node["cap"], "min") <= len(value) <= _cap(reg, node["cap"], "max"):
            found.append(code)
        of = node["of"]
        child = {"type": of} if type(of) is str else of
        for item in value:
            _walk(child, item, reg, code, found)
        if _order_defect(node, value):
            found.append(code)
    else:
        name = node["type"]
        if not FORMS[name](value):
            found.append("schema" if name in ACT07_FORMS else code)


def defects(node, value, reg, code):
    """Every defect of `value` against `node`, as a list of reason codes in walk order."""
    found = []
    _walk(node, value, reg, code, found)
    return found


def refuse(found):
    """Raise Refused with the code ordered first in `found` (`schema` before the rest), or return."""
    if "schema" in found:
        raise errors.Refused("schema")
    if found:
        raise errors.Refused(found[0])


def check(node, value, reg, code):
    """Raise Refused with the code ordered first among the defects of `value`, or return."""
    refuse(defects(node, value, reg, code))
