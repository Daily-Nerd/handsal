"""Commands that need no chain state: `subset` and `kid` (CF-03).

The table is shared by both builds; builds add the commands that differ.
"""
from . import core, encoding, profiles, registry, render_attach, subset


def kid(value):
    """`{x, y}` to `{kid}` (ACT-11): the thumbprint of the key.

    Exactly the two members, each a string of base64url characters. The point is
    not checked here: whether a key is valid is the introducing act's concern.
    """
    if type(value) is not dict or set(value) != {"x", "y"}:
        raise core.Malformed()
    for member in ("x", "y"):
        if not encoding.is_b64u_text(value[member]):
            raise core.Malformed()
    return {"kid": encoding.thumbprint(value["x"], value["y"])}


def subset_command(raw):
    """Raw bytes to `{canonical, reason}`: the grammar of ACT-04 and nothing else."""
    canonical, reason = subset.recognize(raw)
    return {"canonical": canonical, "reason": reason}


def render_command(value):
    """`{attachments, kid, method, payload}` to `{first_line, text}` or `{error}` (CF-03, RN-09)."""
    return render_attach.command(value, registry.load(), profiles.load())


PURE = {
    "render": core.Command(render_command, False),
    "kid": core.Command(kid, False),
    "subset": core.Command(subset_command, True),
}
