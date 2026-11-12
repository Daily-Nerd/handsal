"""The ways a command stops, kept apart on purpose.

`Malformed` is a missing or mistyped command input (`malformed_input`): the
command line contract, decided at the boundary. `Refused` is a rule of the
profile saying no, carrying the reason code of section 11. A validator raises
`Refused` at the first failure and never returns a default.
"""


class Malformed(Exception):
    """A required input is missing or mistyped (`malformed_input`)."""


class Refused(Exception):
    """A profile rule refused the value; `code` is the section 11 reason code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code
