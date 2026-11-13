# handsal-check command contract

This file tells an implementer what a checker must do at the command line. It restates CF-03 and CF-08 of the profile (section 9, in `spec/profile-interfaces.md`; the profile is that file and `spec/profile.md`). The spec is the authority. If this file and the spec disagree, the spec wins and this file is the bug. `checker/python/tests/test_contract.py` compares the two.

The vector file format that the harness loads is defined in `conformance/vector_schema.py`. Read it there. It is not repeated here.

## Invocation

`handsal-check <command> < input.json`

- Exit 0 always. A nonzero exit means a crash, and consumers MUST treat it as failure.
- Write exactly one line to stdout: one JCS JSON object followed by one LF. Nothing else goes to stdout.
- Output is deterministic. Equal input gives equal bytes.
- An unknown command is an error result, not a nonzero exit.
- There is no `build` or `emit` command. Signers produce emitted bytes.

## Input framing

- stdin MUST be I-JSON (RFC 7493): UTF-8, no duplicate member names at any depth, no lone surrogates.
- MAX_INPUT is 16777216 bytes (2^24). The size is checked first, before parsing.
- MAX_NESTING is 64: arrays and objects nested deeper than that, the root value counting as 1, are refused. Input of exactly 64 levels passes the reader.
- A duplicate member name, invalid UTF-8, more than MAX_INPUT bytes, or nesting deeper than MAX_NESTING is `{"error":"unparseable_input"}`, before any command logic.
- `subset` is the exception. It reads stdin as raw bytes and passes them to the recognizer unparsed. More than MAX_INPUT bytes is still `unparseable_input`.
- JSON that is missing a required key, or gives it the wrong type, is `{"error":"malformed_input"}`.

## Commands

| Command | Input | Output |
|---|---|---|
| `check-act` | VR-01 | `{class, reason, receipt_id, valid}` |
| `fold` | `{acts, at?, lineage, org, pin}` | FO-01 |
| `render` | `{attachments, kid, method, payload}` | `{first_line, text}` or `{"error":code}` (RN-06, RN-09) |
| `subset` | raw bytes | `{canonical, reason}` (ACT-04, grammar only) |
| `kid` | `{x, y}` | `{kid}` (ACT-11) |
| `genesis-check` | `{acts, lineage}`; the last lineage entry is the candidate document with its signatures | `{pin, reason, valid}`; `pin` is the exact pin line (GP-05) when valid, else null |
| `enrolled` | GP-13 | `{enrolled, reason}` |

`genesis-check` validates every link of `lineage` in order from the original. It returns the first failure, so `valid:true` means every link is authorized (GP-21).

## Error codes

These are the codes the checker command line itself produces. Each is returned as `{"error":"<code>"}`, with exit 0.

| Code | When |
|---|---|
| `unsupported_command` | the command is not one of the table above |
| `unparseable_input` | stdin is not I-JSON, or is over MAX_INPUT bytes |
| `malformed_input` | a required input is missing or mistyped, or a production build was given `pin` or `now` |

Every other reason code (section 11 of the spec) comes from a command's own logic and is returned inside that command's output shape.

## Production and conformance builds (CF-08)

One pure core, two builds.

- `handsal-check` is the production build and the only one installed at the administrator path. `check-act`, `enrolled` and `fold` call the platform probe in-process at the fixed pin path and read the time from the system clock. An input carrying `pin` or `now` is `malformed_input`. A lineage under the fixture profile is refused.
- `handsal-check-conformance` runs the same commands with `pin` and `now` as input data. It accepts both profiles and is never installed at an administrator path. Every vector runs against it.

The build split enforces this, not a flag. Do not add a switch to the production build that turns the conformance behavior on.
