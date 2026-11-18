"""Build the draft of a genesis document and assemble the receipts that sign it.

Usage: genesis_build.py draft OUT          (input JSON on stdin)
       genesis_build.py assemble DRAFT RECEIPT... [--out DIR]

The tool constructs a document from public data and asks the checker of this checkout about every rule, byte
and hash. It decides nothing itself: a refusal is the checker's own code.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER_SRC = ROOT / "checker" / "python" / "src"

# The checker of this checkout, never an installed copy: a module already imported from elsewhere would win over
# the path inserted here, so the identity of what was imported is checked.
sys.path.insert(0, str(CHECKER_SRC))
import handsal_check  # noqa: E402

_IMPORTED = Path(handsal_check.__file__).resolve().parent.parent
if _IMPORTED != CHECKER_SRC.resolve():
    raise ImportError("handsal_check was imported from %s, this checkout's checker is at %s" % (_IMPORTED, CHECKER_SRC))


def production_profile(profile_set):
    """The production hash of the current edition: the one a new document names."""
    return profile_set.production_hashes()[-1]
