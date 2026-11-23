"""`version` (CF-03): what a build is, from the data packed in it and nothing else.

Input `{}` exactly: any other object, and any value that is no object, is `malformed_input`, after the framing every
command gets (CF-03). Output `{impl, profiles, spec}`: `impl` is the literal `handsal-check-python`, `profiles` the
production profile hash of every edition of the packed catalog in catalog order, oldest first, and `spec` the last of
them, the hash of the build's own edition (GP-22). It reads no pin, no store, no clock and no build stamp, so it can
never disagree with the editions the build implements: it is the checker's counterpart of the signer's `version`
(SG-02), without `class`. The production build and the server build have it; the conformance build does not, and no
vector runs it (CF-15 makes that command surface append-only).
"""
from . import core, errors

IMPL = "handsal-check-python"


def command(load_profiles):
    """The `core.Command` of `version` over the profile set `load_profiles()` gives. The builds that have `version`
    hand over the loader they hand every other command, so this module does not import the owner of the edition set
    (GP-23)."""

    def run(value):
        if type(value) is not dict or value:
            raise errors.Malformed()
        hashes = load_profiles().production_hashes()
        return {"impl": IMPL, "profiles": hashes, "spec": hashes[-1]}

    return core.Command(run, False)
