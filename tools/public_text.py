"""Wording that must never reach public text.

One definition, shared by the spec tests and the vector extractor.
"""

import re

# Words that belong to how the text was produced, not to the text itself.
PROCESS_WORDS = re.compile(
    r"\biteration\b|\bround[\s-]+\d+|\bjudge[sd]?\b|\bjudging\b|\bOT-\d+|"
    r"\bowner\s+decisions?\b",
    re.IGNORECASE,
)
