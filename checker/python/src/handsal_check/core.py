"""Command dispatch shared by both builds.

A build passes its own command table. The core holds no build switch: which
commands exist is decided by the module that calls it. Input framing is done
here once, before any command logic (CF-03): the size first, then, unless the
command takes raw bytes, I-JSON parsing. The size is judged on at most one byte more than the limit (`stdin.read(n)`
gives `n` bytes unless the stream ends first), so an input of any length is refused without being read to its end.
Handlers return a result object and raise `Malformed` for a missing or mistyped input. They never see stdin that
failed framing, and the one place that turns a refusal into an `{"error"}`
line is `run`.
"""
import sys
from collections import namedtuple

from . import emit, ijson
from .errors import Malformed

Command = namedtuple("Command", "handler raw")   # raw: the handler takes the stdin bytes


def _line(obj):
    return emit.emit_result(obj) + b"\n"


def run(commands, argv, stdin, stdout, serving=None):
    """Answer one call. `serving` is the function of a build that can serve (`serve.run`): the argument list
    `["serve"]` and nothing else hands it the streams. `serve` is no command of any table, so anywhere else it is
    unsupported, inside a stream too."""
    if serving is not None and argv == ["serve"]:
        return serving(stdin, stdout)
    command = argv[0] if argv else None
    spec = commands.get(command)
    if spec is None:
        stdout.write(_line({"error": "unsupported_command"}))
        return 0
    try:
        raw = stdin.read(ijson.MAX_INPUT + 1)   # one byte past the limit is enough to refuse, and all that is held
        ijson.check_size(raw)
        value = raw if spec.raw else ijson.loads(raw)
        result = spec.handler(value)
    except ijson.Unparseable:
        result = {"error": "unparseable_input"}
    except Malformed:
        result = {"error": "malformed_input"}
    stdout.write(_line(result))
    return 0


def entry(commands, serving=None):
    return run(commands, sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, serving)
