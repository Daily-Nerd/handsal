"""The command table and the modes of each build, read from the spec sentences that state them (CF-03, CF-08, CF-10).

A build is exactly what its sentence says. `table(text, build)` is the set of commands of the one sentence
`Its table is exactly `a`, `b` and `c`;` that the spec holds for that build, and `modes(text, build)` the set of the one
sentence `Its modes are exactly `serve`;` (or `It has no modes;`). Every other reading raises `SpecTextError`: a
sentence that is missing, that appears twice, that holds a word which is no command name, or that names a command the
CF-03 table lacks, never holds a build to an empty set. The CF-03 rows that name a build in their input cell must agree
with the sentences, so the table of commands and the sentences are one fact written in two places and checked as one.

No test keeps a list of commands or a count of them: the lists live in the spec.
"""
import re

BUILDS = ("production", "conformance", "server")

# Where each build states itself: the requirement, and the start of the paragraph that holds its sentences.
HOME = {"production": ("CF-08", "- **production**"),
        "conformance": ("CF-08", "- **conformance**"),
        "server": ("CF-10", None)}

NAMES = re.compile(r"`([a-z-]+)`")
BUILD_WORDS = r"(?:production|conformance|server)"
MARK = re.compile(r"(%s(?:,? and %s)*) builds?\b" % (BUILD_WORDS, BUILD_WORDS))


class SpecTextError(Exception):
    """The spec text does not say what a build's table or modes are in the one form these tests read."""


def section(text, rid):
    """The text of requirement `rid` (`### <rid> ...` up to the next `### `), or `SpecTextError`."""
    found = re.search(r"^### %s .*?(?=^### )" % re.escape(rid), text, re.M | re.S)
    if found is None:
        raise SpecTextError("no section %s" % rid)
    return found[0]


def command_rows(text):
    """`{command: input cell}` of the CF-03 command table."""
    rows = dict(re.findall(r"^\| `([a-z-]+)` \| ([^|]*) \|", section(text, "CF-03"), re.M))
    if not rows:
        raise SpecTextError("CF-03 has no command table")
    return rows


def _owner(text, build):
    """The text that holds the sentences of `build`: its paragraph of CF-08, or CF-10 for the server."""
    if build not in HOME:
        raise SpecTextError("no build %r" % build)
    rid, opening = HOME[build]
    owner = section(text, rid)
    if opening is None:
        return owner
    start = owner.find("\n" + opening)
    if start < 0:
        raise SpecTextError("%s has no paragraph %r" % (rid, opening))
    end = re.search(r"\n\n|\n- \*\*", owner[start + 1:])
    return owner[start:start + 1 + end.start()] if end else owner[start:]


def _sentence(owner, lead, build):
    found = re.findall(r"(?i:%s) ([^;]*);" % re.escape(lead), owner)
    if len(found) != 1:
        raise SpecTextError("the %s build has %d sentences `%s ...;`, not one" % (build, len(found), lead))
    return found[0]


def _list(sentence):
    """The names of a sentence that holds names, requirement ids, commas and `and`, and nothing else."""
    names = frozenset(NAMES.findall(sentence))
    rest = re.sub(r"`[a-z-]+`|\([A-Z]{2}-\d+\)|,|\band\b", "", sentence).strip()
    if not names or rest:
        raise SpecTextError("not a list of names: %r" % sentence)
    return names


def table(text, build):
    """The commands the spec names as the whole table of `build`."""
    names = _list(_sentence(_owner(text, build), "Its table is exactly", build))
    rows = command_rows(text)
    if names - set(rows):
        raise SpecTextError("the %s sentence names commands CF-03 does not: %s" % (build, sorted(names - set(rows))))
    return names


def modes(text, build):
    """The modes the spec names for `build`: the names of `Its modes are exactly ...;`, or none for `It has no modes;`."""
    owner = _owner(text, build)
    if re.search(r"(?i:it has no modes);", owner):
        if re.search(r"(?i:its modes are exactly)", owner):
            raise SpecTextError("the %s build says it has modes and that it has none" % build)
        return frozenset()
    return _list(_sentence(owner, "Its modes are exactly", build))


def marked(cell):
    """The builds an input cell of CF-03 names (`production build only`, `conformance and server builds`), or `None`
    for a command that is no build's alone."""
    found = MARK.search(cell)
    return frozenset(re.findall(BUILD_WORDS, found[1])) if found else None


def check_rows(text):
    """Every CF-03 row that names builds is in exactly those tables; every other row is in the production and the
    conformance table and not in the server's. Raises `SpecTextError` where the rows and the sentences disagree."""
    tables = {build: table(text, build) for build in BUILDS}
    for name, cell in command_rows(text).items():
        want = marked(cell)
        if want is None:
            want = frozenset({"production", "conformance"})
        have = frozenset(build for build in BUILDS if name in tables[build])
        if have != want:
            raise SpecTextError("CF-03 puts `%s` in %s, the table sentences in %s" % (name, sorted(want), sorted(have)))
    return tables
