# handsal-check command contract

This file tells an implementer what a checker must do at the command line. It restates CF-03 and CF-08 of the profile (section 9, in `spec/profile-interfaces.md`; the profile is that file, `spec/profile.md`, `spec/profile-checks.md`, `spec/profile-display.md` and `spec/profile-part3.md`). The spec is the authority. If this file and the spec disagree, the spec wins and this file is the bug. `checker/python/tests/test_contract.py` compares the two.

The vector file format that the harness loads is defined in `conformance/vector_schema.py`. Read it there. It is not repeated here.

This command interface is append-only across supported editions (CF-15): a command, an input key or a reason code may be added (an added input key is optional, and its absence gives the answer the earlier edition gave), and none is removed or changes its meaning, because the vectors of every earlier tag run against the current build.

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
| `recheck-act` | VR-17 | `{class, not_proven, reason, receipt_id, rechecked}` |
| `fold` | `{acts, at?, lineage, org, pin}` | FO-01 |
| `render` | `{attachments, kid, method, payload}` | `{first_line, text}` or `{"error":code}` (RN-06, RN-09) |
| `subset` | raw bytes | `{canonical, reason}` (ACT-04, grammar only) |
| `kid` | `{x, y}` | `{kid}` (ACT-11) |
| `genesis-check` | `{acts, lineage}`; the last lineage entry is the candidate document with its signatures | `{pin, reason, valid}`; `pin` is the exact pin line (GP-05) when valid, else null |
| `genesis-aids` | `{acts, lineage}`, the input of `genesis-check` | `{aids, reason}`; `aids` is null, or `{head, removed}` for a change (SG-12 steps 6 and 7) |
| `enrolled` | GP-13 | `{enrolled, reason}` |
| `head` | VR-19 | `{head, reason}` |
| `sync` | `{acts, docs, org}` (CF-09), production build only | `{reason, synced_at}` |
| `admit` | CF-11, conformance and server builds | `{reason, store}` |
| `pool` | CF-12, conformance and server builds | `{in_pool, reason}` |
| `compact` | CF-14, conformance and server builds | `{drop, reason}` |
| `agree-points` | CF-16, conformance and server builds | `{active, pool, reason}` |
| `version` | `{}`, production and server builds | `{impl, profiles, spec}` |

`genesis-check` validates every link of `lineage` in order from the original. It returns the first failure, so `valid:true` means every link is authorized (GP-21).

`genesis-aids` folds the same lineage and answers the facts the ceremony shows about the previous epoch of the candidate: where H lies against the accepted chain (a tip, or a fork) and which kids that the candidate lists, or whose key signed it, a valid `device.remove` removed anywhere in that epoch. It reads no pin, no clock and no store, in every build.

## Error codes

These are the codes the checker command line itself produces. Each is returned as `{"error":"<code>"}`, with exit 0.

| Code | When |
|---|---|
| `unsupported_command` | the command is not one of the table above |
| `unparseable_input` | stdin is not I-JSON, or is over MAX_INPUT bytes |
| `malformed_input` | a required input is missing or mistyped, or a production build was given `pin` or `now` (and, for `check-act`, `recheck-act`, `enrolled` and `head`, `acts`, `lineage`, `next`, `synced_at` or `tip_statement`) |

Every other reason code (section 11 of the spec) comes from a command's own logic and is returned inside that command's output shape.

## Checker builds (CF-08)

One pure core, three builds.

- `handsal-check` is the production build and the only one installed at the administrator path. `check-act`, `recheck-act`, `enrolled`, `head` and `fold` call the platform probe in-process at the fixed pin path; all but `recheck-act` and `fold` also read the time from the system clock (`recheck-act` reads no clock and takes no `now`). The four commands other than `fold` also read the per-machine store (CF-09) in process, once per call, and every command that reads chain state gets it from that one read and one pinned fold. `head` takes `{org}` and nothing else in this build. An input carrying `pin`, `now`, `acts`, `lineage`, `next`, `synced_at` or `tip_statement` is `malformed_input` (`fold` takes its bag as input and reads no store; `genesis-check` and `genesis-aids` read no pin, no clock and no store). A lineage under the fixture profile is refused. `sync` (CF-09) writes the store and exists in this build only, and `version` (CF-03) answers `{impl, profiles, spec}` from the packed catalog in this build and the server build. Its table is the sentence of CF-08.
- `handsal-check-conformance` runs the same commands with `pin`, `now` and the store's content (`next` included) as input data (`head` takes `{acts, lineage, next, now, org, pin, synced_at, tip_statement}`), plus `admit`, `pool`, `compact` and `agree-points`, and has no `sync` and no `version` (`unsupported_command`). It has the mode `serve`. It accepts both profiles and is never installed at an administrator path. Every vector runs against it.
- `handsal-check-server` (CF-10) has the table and the modes that its sentence in CF-10 names (`admit`, `pool`, `compact`, `agree-points` and `version`; the mode `serve`), and answers every other command `unsupported_command`. It reads no pin, no clock and no store, refuses the fixture profile and proves nothing about any person. It runs on Linux automation hosts, never at a macOS or Windows administrator path. A checker role that runs the vectors runs `admit`, `pool`, `compact` and `agree-points` like every other command.

The build split enforces this, not a flag. Do not add a switch to the production build that turns the conformance behavior on.
