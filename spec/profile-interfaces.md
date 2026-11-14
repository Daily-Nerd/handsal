# handsal profile, version 1, part 2

This file is the second part of the normative profile. `spec/profile.md` holds sections 0 to 7 (reading guide, scope, definitions, act profile, key classes, genesis and pin, fold, verifier rules). This file holds sections 8 to 14 (rendering, conformance and checker CLI, signer CLI, reason codes, vector groups, freshness witness, known limitations) and the appendices. Section numbers and requirement ids are global to the profile: a reference such as "section 9" or `KC-02` names one place whichever file it is read in. The two files are one text, hashed as two core files (CF-01).

## 8. Rendering

### RN-01 Pure function

The render, `render({attachments, kid, method, payload}) -> {first_line, text}`, is a pure function: byte-for-byte deterministic, ASCII only, with no locale, no clock and no I/O. Lines end with LF, with no trailing blank line and one final LF. The signer's `render` command is that function composed with the signer's own fill (SG-04): it takes `{attachments, draft}`, fills `performer_id` and `kid` from its key and `ts` from its clock as `sign` does, and so needs a key (`key_unavailable`, exit 3, without one) and shows no prompt. Given a `payload` and a `kid` instead of a draft, the function is the CF-03 `render`, which a signer runs only as `handsal-sign-conformance render` (CF-04). Attachments are listed in RN-09.

Why: the render is a pure function of signed bytes plus bound attachments, in ASCII, so independent implementations need no Unicode tables.

- S1: GIVEN the same input twice WHEN rendered THEN equal bytes. V: rnd/determinism

### RN-02 Layout

Line 1 is the first line (RN-03). Then, in order: `Method: <method>`, `Org: <hash12(org)>`, `Signer: <performer_id> key <kid12>`, the method lines (RN-04), `Signed at: <ts>`, `Expires: <expires>` when present, `Parent: <hash12(parent_receipt_hash)>` when non-null, and `Head: <hash12(head.id)>` when present. Verdicts add `Sender: not proven` (RN-07). The org name is shown only for `genesis.sign`, from the signed document: for other acts the signer does not fold, so a name could only come from the caller, and the caller never chooses the words.

Every line after line 1 is at most 100 bytes. A longer line is written as its first 98 bytes, with no prefix, and then continuation lines, each `+ ` followed by the next at most 98 bytes, so no signed byte is hidden; a 253-character relay hostname stays fully visible. A render longer than 72 lines is refused (`render_refused`).

- S1: GIVEN an approve payload WHEN rendered THEN the text matches the anchor. V: rnd/approve, rnd/reject, rnd/no-org-name-non-genesis, rnd/long-line-wrapped, rnd/render-73-lines-refused

### RN-03 First line

Line 1 is at most 80 bytes, is the OS prompt text (RN-11), and MUST carry the decision summary. A free field longer than 12 characters appears as its first 11 characters plus `~`. The free fields are `<class>`, `<person>`, `<member>`, `<role>`, `<request_id>`, `<record_id>`, the decision `<consumer>` and `<subject>`, and the genesis `<name>` (`org_name`, up to 24 characters, so it is cut like the others). `kid12`, `hash12` and decimal counts appear as is. Templates:
- `device.add`: `Add device <kid12> (<class>) to <person>`
- `device.remove`: `Remove device <kid12> of <person>`
- `member.add`: `Add device <kid12> as member <member> (<role>)`
- `chain.resolve`: `Resolve fork, keep: ` followed by line 1 of the chosen candidate cut to 59 bytes, plus `~` when cut
- `request.approve`: `APPROVE request <request_id> (<hash12(inputs_hash)>, <N> bytes)`; `request.reject`: `REJECT request ...`; `request.needs-info`: `NEEDS-INFO on request ...`, with the same tail
- `record.promote`: `Promote record <record_id> (<hash12>, <N> bytes)`
- `decision`: `<consumer>: <action> <subject> (<hash12(inputs_hash)>, <N> bytes)`. `<action>` is shown whole, never cut: its grammar bounds it at 24 characters (section 2.2), so a consumer and a subject cut to 12 characters each, the hash12 and a size of four digits (the content block bound is 2048 bytes, RN-05) give a line 1 of at most 80 bytes
- `genesis.sign` over an original: `Sign genesis of <name> (<hash12(doc)>): <M> members, <D> devices`
- `genesis.sign` over a change: `Change <name> (<hash12(doc)>): +<A>/-<R> dev, <C> mem, policy same|NEW`, where A and R are the devices added and removed, C counts member entries added, removed or with a changed role, and `NEW` means some policy byte differs
- `act.endorse`: `Endorse: ` followed by line 1 of the endorsed act cut to 70 bytes, plus `~` when cut

There is one vector per method at maximum field lengths proving the 80-byte bound.

- S1: GIVEN maximum-length fields WHEN rendered THEN line 1 is at most 80 bytes. V: rnd/prompt-line-max-length, rnd/prompt-line-max-device-remove, rnd/prompt-line-max-member-add, rnd/prompt-line-max-resolve, rnd/prompt-line-max-approve, rnd/prompt-line-max-reject, rnd/prompt-line-max-needs-info, rnd/prompt-line-max-promote, rnd/prompt-line-max-decision, rnd/prompt-line-max-genesis-original, rnd/prompt-line-max-genesis-change, rnd/first-line-tilde, rnd/line1-endorse-bounded
- S2: GIVEN each method WHEN rendered THEN line 1 follows its template. V: rnd/decision, rnd/line1-approve-size, rnd/line1-device-add-class, rnd/line1-member-add-kid-first, rnd/line1-resolve-keeps-kid12, rnd/line1-genesis-change-summary
- S3: GIVEN a kid or a hashstr whose twelve shown characters hold `-`, at the edge of a group or inside one, WHEN rendered THEN the short form is three groups of four joined by one space and each `-` stays in its group (`pbubEyWn-20K` shows as `pbub EyWn -20K`). V: rnd/record-promote, rnd/resolve-max-caps-fits. T: checker/python/tests/test_render.py::test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four, conformance/vectors/_gen/tests/test_render.py::test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four, signer/apple/Tests/HandsalCoreTests/RenderCoreTests.swift::aDashOfTheAlphabetIsNeverTakenForTheSeparator, signer/windows/tests/draft.rs::a_dash_of_the_alphabet_is_never_taken_for_the_group_separator

### RN-04 Method lines

Every signed value a person decides on is rendered: one line per field, in ACT-09 order, values verbatim. A field line is the field name, a colon, one space and the value (`Person: alice`). A list is a header line, the name and a colon with nothing after it, followed by one indented line per entry. `hash12` and the thumbprint of a key are defined in section 2.1. The lines, in order:
- `device.add`: `Person: <person>`, `New device: <full kid>`, `Agree key: <thumbprint of agree>`, `Class: <class>` (on its own line, so endorsers vouch for it), `Label: <label>`, `Link code: <hash12(link_code_hash)>`.
- `device.remove`: `Person: <person>`, `Remove device: <full kid>`.
- `member.add`: `Member: <member>`, `Role: <role>`, `New device: <full kid>`, `Agree key: <thumbprint of agree>`, `Class: <class>`, `Label: <label>`.
- `chain.resolve`: `Fork parent: <full id>`, `Choose: <full id>`; `Candidates:` and one line per candidate in `candidates` order, `  > <hash12> <line 1>` for the chosen one and `    <hash12> <line 1>` for the others; `Heads:` and one line per head in `heads` order, `  - <hash12> <line 1 of the attached head act>`; then `Overrides: none`, or `Overrides:` and one line per entry in entry order, `  - <hash12 of resolve> (endorsements: <E>)`, E the decimal count.
- `request.*`: `Request: <request_id>`, `Recipient: <recipient>`, `Relay: <relay>`, `Request hash: <hash12(inputs_hash)>`, then the request block (RN-05).
- `record.promote`: `Record: <record_id>`, `Anchors:` and one line `  - <anchor>` per anchor, `Body hash: <hash12(inputs_hash)>`, then the record body block (RN-12).
- `decision`: `Consumer: <consumer>`, `Action: <action>`, `Subject: <subject>`, `Decision hash: <hash12(inputs_hash)>`, then the decision block (RN-12). A decision has no `Sender` line: it names no sender and no recipient.
- `genesis.sign` over an original: `Org name: <name>`, `Profile: <full profile hash>`, `Members:` and per member `  - <id> <role>`, `Devices:` and per device four lines, `  - <full kid> of <person>`, `    Class: <class>`, `    Label: <label>`, `    Agree: <thumbprint of agree>`, then the policy lines (below), then `Document hash: <hash12 of the document hash>`. Members and devices are in document order, which is sorted (GP-01). A change renders as a difference (RN-10).
- `act.endorse`: `Endorsed act: <full receipt id>`, then the endorsed act's method lines. For an endorsed resolve these run from its first method line through its last `Overrides` line, never the resolve's line 1, `Method`, `Org`, `Signer`, `Signed at` or `Parent`, so the endorser sees the same method lines as the resolve's signer.

The policy lines are the same in an original and in a change: `Policy:`, `  Roles: <roles joined by ",">` in document order, one line per rule in ascending order of rule name, `  Rule <name>: <persons> of <roles joined by ",">`, one line per entry of `classes` in document order, `  Class <class>: <user_verification>`, `  Clock skew: <clock_skew_s> s`, `  Max validity: <max_validity_s> s`, `  Max view age: <max_view_age_s> s`, and the witness: `  Witness: none`, or `  Witness: relay`, `  Relay key: <full relay_kid>`, `  Max tip age: <max_tip_age_s> s` (WT-08).

Entries inside a change section keep document order (RN-10): the added members, the changed roles and the added devices in the order of the new document, the removed members and devices in the order of the previous one. Both documents are sorted (GP-01), so members run by `id` and devices by `kid`.

Not rendered: the envelope constants (fixed by ACT-01) and `nonce` (signer-chosen randomness with no decision value).

At the ACT-09 caps a resolve renders at most 60 lines (line 1, 3 header lines, 54 method lines, `Signed at`, `Parent`), each under 100 bytes, inside the 72-line limit. Its endorsement is exactly 62 lines (line 1, `Method`, `Org`, `Signer`, `Endorsed act`, the 54 method lines, `Signed at`, `Parent`, `Head`). The longest `Overrides` entry line is 37 bytes.

- S1: GIVEN a genesis change WHEN rendered THEN policy changes are visible as lines. V: rnd/genesis-policy-lines, rnd/genesis-class-own-line, wit/render-genesis-witness-relay
- S2: GIVEN a resolve and its endorsement at the caps WHEN rendered by the checker and by each signer THEN the exact anchored text. V: rnd/resolve-max-caps-fits, rnd/endorse-resolve-max-caps-fits
- S3: GIVEN a resolve with one override entry of one endorsement WHEN rendered THEN the line `  - <hash12> (endorsements: 1)`. V: rnd/resolve-override-entry-line, rnd/resolve-override-entry-line-one
- S4: GIVEN a `device.add` and a genesis document WHEN rendered THEN the agree key and the full profile hash appear. V: rnd/device-add-agree-key-id, rnd/genesis-agree-key-id, rnd/genesis-profile-full, rnd/endorse-shows-endorsed-id, rnd/resolve-candidates-listed, rnd/resolve-heads-attached

### RN-05 Request block

Request bytes are untrusted and are not decoded as UTF-8. The block starts with `----- request (<N> bytes, sha256 <hash12(inputs_hash)>) -----` and ends with `----- end -----`. Each source line (bytes up to an LF) is rendered as `| ` plus its escaped bytes: 0x20 to 0x7E as is, and every other byte (CR, TAB, NUL, DEL, every byte of a multi-byte UTF-8 sequence, bidirectional controls) as `\xHH` in lowercase. Escaped content longer than 96 bytes continues on lines that are `|+` (no space) followed by the next at most 96 bytes, never splitting an escape. An empty source line is `| ` (a pipe and a space). A final LF ends the last line and does not start another, so an empty request has no content line.

There is no truncation. A request whose block would exceed 2048 source bytes or 32 block lines is refused (`render_refused`) by every renderer, so a signer never signs bytes the person could not see. The 32 lines are the content lines, continuations included, without the two delimiter lines.

Why: no Unicode tables (they differ across implementation languages and versions); every content line starts with `|`, so request text cannot spoof the end delimiter; bidirectional and control bytes are visible. The cost is that non-ASCII text shows as escapes, for example `\xc3\xa1` for an accented letter.

- S1: GIVEN request text containing a line `----- end -----` WHEN rendered THEN it appears as `| ----- end -----` and does not end the block. V: rnd/hostile-delimiter, rnd/hostile-bidi
- S2: GIVEN a request over 2048 bytes, or of 33 or 40 block lines WHEN rendered THEN `render_refused`; GIVEN exactly 2048 bytes THEN rendered. V: rnd/request-over-2048-refused, rnd/request-33-lines-refused, rnd/oversize-truncated, rnd/request-32-lines-cap. C: rnd/request-exactly-2048-ok
- S3: GIVEN a request of zero bytes, or one line of 300 bytes WHEN rendered THEN the block has no content line, or a `| ` line followed by `|+` lines. V: rnd/empty-request, rnd/request-long-line-continuation

### RN-06 Refusal

`render` MUST refuse any payload that is not schema-valid for its method, any method not in the registry, any value outside the alphabets, and any render over 72 lines. A signer MUST NOT sign what its own renderer refuses.

- S1: GIVEN a payload with an extra key WHEN rendered THEN `schema`. V: rnd/refuse-extra-key
- S2: GIVEN a method that is not in the registry WHEN rendered THEN `method_unknown`. V: rnd/refuse-unknown-method

### RN-07 Sender not proven

Verdict renders MUST show `Sender: not proven` and MUST NOT display any sender name sourced from outside the signed bytes.

- S1: GIVEN an attachment carrying a sender WHEN rendered THEN the line still reads `not proven`. V: rnd/sender-not-proven

### RN-08 Genesis rendering is complete

The render of an original genesis document MUST list every member, role, device (full kid), class and the full policy, with nothing summarized by the caller. A change shows every difference plus the full policy (RN-10). A document whose render exceeds 72 lines is `genesis_render_too_large` in the fold.

- S1: GIVEN an original genesis WHEN rendered THEN every member and device appears. V: rnd/genesis-sign-original, rnd/genesis-policy-lines

### RN-09 Attachments are bound to the payload

Every renderer (checker `render`, signer `render` and `sign`) MUST verify every attachment against the payload before rendering:

| Method | Attachment | Binding |
|---|---|---|
| verdicts | `request_b64` | hashstr(bytes) = `inputs_hash` |
| `record.promote` | `record_body_b64` | hashstr(bytes) = `inputs_hash` |
| `decision` | `decision_b64` | hashstr(bytes) = `inputs_hash` |
| `genesis.sign` | `document` | hashstr(JCS(document)) = `inputs_hash` |
| `genesis.sign` over a change | `previous` | hashstr(JCS(previous)) = `document.prev` |
| `genesis.sign` over a change | `document` | `head.id` of the payload = `document.head` |
| `act.endorse` | `act` (JWS) | its receipt id = `body.act` = `parent_receipt_hash`; its `performer_id` = `parent_performer_id`; its `parent_receipt_hash` = `head.id`; it is a chain primary or a resolve |
| `act.endorse` of a resolve | `candidates`, `heads` (JWS lists) | bound against the attached resolve exactly as for the resolve itself (next rows) |
| `chain.resolve` | `candidates` (JWS list) | one JWS per id of `body.candidates`; each has `parent_receipt_hash` = the resolve's parent |
| `chain.resolve` | `heads` (JWS list) | one JWS per id of `body.heads`; each is a chain primary |

Every attachment that is an act MUST pass ACT-01 to ACT-14. An attachment that is a genesis document (`document`, `previous`) MUST be valid by itself: GP-15 steps 1 and 3 over the document alone (structure, then policy and devices; the profile and lineage steps belong to the fold). `fixture_key` follows the profile the document itself names: a document naming the production profile that lists a fixture kid is not valid alone, and one naming the fixture profile, or a profile the checker does not implement (step 2 belongs to the fold), is not refused for it. One that binds by hash but is not a valid document is `attachment_mismatch`, the same code as an act attachment that fails ACT-01 to ACT-14. A JWS list bound to a body list holds exactly one JWS per receipt id of that list and nothing else, in any order: a duplicate copy, an extra JWS or a missing id is `attachment_mismatch`. An `act.endorse` of a chain primary that carries `candidates` or `heads` is `attachment_mismatch`. A name that is absent from `attachments` is `attachment_missing`. Every other defect of an attachment is `attachment_mismatch`: a list that is present but is not an array, a value of the wrong type (`request_b64`, `record_body_b64` and `decision_b64` excepted, CF-03), a list that lacks an id, or an attachment that does not bind. Whether a head lies in a losing subtree is decided by the fold (FO-25), not by the renderer. A signer MUST NOT sign what its renderer refuses.

Order of checks. A renderer decides in this order and the first defect wins: the envelope and the method; for `genesis.sign` the `document` (absent, not bound, or not valid alone), because it fixes whether a head is due; the form of the act object and body, including the presence of the `head`; then the other attachments in the order of the table above, each read and bound completely (present, of the right type, bound) before the next is looked at. An `act.endorse` is decided on `act` first, and only an attached resolve then asks for `candidates` and then `heads`: an endorse whose attached act does not bind is `attachment_mismatch` whether or not `heads` is there, and so is a `chain.resolve` whose `candidates` do not bind, whether or not `heads` is there. For `genesis.sign`, `previous` is read after the head presence is checked, then `head.id` against `document.head`. The signer's own comparisons of a draft with an attachment (SG-08, SG-13) take their places in this order and add none of their own.

Why: the words a person sees are a function of signed bytes only; an attachment is never a second, unbound source.

- S1: GIVEN an endorse draft whose attachment is another act WHEN signed THEN exit 2, `attachment_mismatch`, no prompt (a signer implementation test, CF-07). V: rnd/endorse-attachment-mismatch
- S2: GIVEN an endorsement draft of a resolve without `heads`, or with a candidate act outside the resolve's candidates, or a head act whose act `kid` differs from its header kid WHEN rendered THEN `attachment_missing`, `attachment_mismatch`, `attachment_mismatch`. V: rnd/endorse-attachment-missing, rnd/endorse-resolve-heads-missing, rnd/endorse-resolve-candidate-mismatch, rnd/attachment-act-kid-differs, rnd/endorse-primary-extra-attachment. C: rnd/endorse-resolve-nested-attached
- S4: GIVEN an endorsement of a resolve whose attached act does not bind to `body.act` and that carries no `heads`, or a resolve whose `candidates` do not bind and that carries no `heads` WHEN rendered THEN `attachment_mismatch`; GIVEN a change `genesis.sign` with no `head` and no `previous` attachment THEN `schema`. V: rnd/endorse-resolve-act-mismatch-before-heads-missing, rnd/resolve-candidates-mismatch-before-heads-missing, rnd/genesis-head-missing-before-previous-missing
- S3: GIVEN a request, record, decision, document or candidate attachment that does not bind WHEN rendered THEN `attachment_mismatch` or `attachment_missing`. V: rnd/request-attachment-mismatch, rnd/record-attachment-mismatch, rnd/decision-attachment-mismatch, rnd/decision-attachment-missing, rnd/genesis-attachment-hash-mismatch, rnd/genesis-change-previous-mismatch, rnd/resolve-candidate-wrong-parent, rnd/resolve-candidate-missing, rnd/resolve-head-attachment-missing
- S4: GIVEN a change whose `head.id` differs from `document.head` WHEN rendered THEN `attachment_mismatch`. V: rnd/genesis-head-mismatch
- S5: GIVEN a `document` or a `previous` that binds by hash and is not a valid document WHEN rendered THEN `attachment_mismatch`. V: rnd/genesis-document-invalid-bound, rnd/genesis-previous-invalid-bound
- S6: GIVEN an `act.endorse` whose `act` attachment is a number WHEN rendered THEN `attachment_mismatch`. V: rnd/attachment-wrong-type-mismatch

### RN-10 Genesis change rendering and the size bound

A change renders as a difference from the previous document (attachment `previous`, RN-09). Its method lines, in order: `Org name: <name>`, `Profile: <full profile hash>` (the two lines an original opens with, so a rename or a profile change is never hidden), `Previous: <hash12(prev)>`, `Head: <full H>`, then these sections, each written only when it has an entry: `Members added:` and `Members removed:` (per member `  - <id> <role>`), `Role changed:` (`  - <id> <old role> -> <new role>`), `Devices added:` (the four device lines of RN-04 per device), `Devices removed:` (per device `  - <full kid> of <person>`); then the policy lines of RN-04 in full, and last `Unchanged: <D> devices, <M> members`, D the devices in both documents and M the members in both documents with the same role. A change has no `Document hash` line: hash12 of the document is in line 1 (RN-03). `Head` also appears as hash12 in the RN-02 frame; both come from `head.id`, which equals `document.head` (RN-09). Carried devices are byte-identical (GP-20), so there is no "devices changed" section. An original renders in full (RN-08).

Fold bound: a genesis document whose `genesis.sign` render exceeds 72 lines is `genesis_render_too_large` (GP-15 step 5). The fold computes it with the same render function, which is the single owner of "fits". The count does not depend on the signer: `Org`, `Signer`, `Signed at` and `Head` are one line each whoever signs, so the fold counts the render with any performer id, kid and time.

Why: every valid genesis document is signable by every listed device. An organization grows through chain acts, and each change shows only what changes, so the 72-line cap does not block growth. A difference with a fold bound is preferred over paging, which would split one decision across screens of an untrusted channel.

- S1: GIVEN a change WHEN rendered THEN the difference, the head line and the full policy appear. V: rnd/genesis-change-diff, rnd/genesis-change-head-line, rnd/genesis-sign-change
- S2: GIVEN a change that renames the organization WHEN rendered THEN `Org name` and `Profile` open the method lines. V: rnd/genesis-change-org-name-profile-lines

### RN-11 The display is not a trust boundary

The signer's display channel (`/dev/tty`, `CONOUT$`) and the OS prompt text are both reachable by same-user processes (section 1.2). The full render and line 1 are aids. The signer MUST still put line 1 into the OS prompt; where a platform prompt cannot carry it, that is stated for that class. Chain security comes from FO-22. A tricked touch on a verdict, a record promotion or a decision signs one decision whose request, record or consumer, action and subject, hash12 and size are in line 1; a consumer that needs more requires decisions from more than one recipient, which is consumer policy outside this profile. The ceremony's hash12 comparison is an aid (SG-12).

- S1: GIVEN a verdict draft WHEN the signer asks the platform to confirm THEN the prompt text is line 1 of the render, the `first_line` that `render` returns for the same draft. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::theDisplayShowsTheRenderBeforeThePrompt

### RN-12 Record body and decision blocks

`record.promote` renders the record body exactly like a request block (RN-05 escaping, prefixes and limits), delimited by `----- record body (<N> bytes, sha256 <hash12>) -----` and `----- end -----`, from the bound attachment `record_body_b64` (RN-09). Over the limits it is `render_refused`.

`decision` renders its attached content exactly like a request block (RN-05 escaping, prefixes and limits), delimited by `----- decision (<N> bytes, sha256 <hash12>) -----` and `----- end -----`, from the bound attachment `decision_b64` (RN-09). Over the limits it is `render_refused`, so a signer never signs content the person could not see. A content of zero bytes has no content line and line 1 says `0 bytes`: the decision is then about its `subject` alone, and the person sees that.

- S1: GIVEN a record promotion WHEN rendered THEN the body block appears; GIVEN a body over the limits THEN `render_refused`. V: rnd/record-body-over-limit-refused. C: rnd/record-body-block
- S2: GIVEN a decision WHEN rendered THEN the decision block appears, line 1 carries the consumer, the action whole, the subject, the hash12 and the size, and nothing is truncated. V: rnd/decision, rnd/decision-block-hostile, rnd/decision-empty
- S3: GIVEN a decision content over 2048 bytes or over 32 block lines WHEN rendered THEN `render_refused`; GIVEN exactly 2048 bytes in 32 lines THEN rendered. V: rnd/decision-over-2048-refused, rnd/decision-33-lines-refused. C: rnd/decision-exactly-2048-ok
- S4: GIVEN a decision payload whose `action` is outside its grammar WHEN rendered THEN `body_schema`. V: rnd/decision-action-grammar-refused

## 9. Conformance and checker CLI

### CF-01 Profile hashes and bundle

- **Core manifest**: `{path: hashstr}` over `spec/profile.md`, `spec/profile-interfaces.md`, `spec/registry.json`, `conformance/CONTRACT.md`, `conformance/fixtures/keys.json` and `conformance/fixtures/fixture-kids.json`.
- **Production profile** = hashstr(JCS({"core": <core manifest>, "kind": "production"})). **Fixture profile** = hashstr(JCS({"core": <core manifest>, "kind": "fixture"})) (GP-18).
- **Bundle hash** = hashstr(JCS(full manifest: the core plus every vector file)), published with each tag for the integrity of the vector set.

Genesis `profile`, pin `spec` and consumer pins hold a profile hash, never the bundle hash. A verifier implements a fixed set of profile hashes; any other is `profile_mismatch`.

Why the split: vectors embed a profile hash in their genesis `profile`. If the profile hash covered the vectors it would have to be its own input, a SHA-256 fixed point that cannot exist. Profile hashes therefore never cover vectors, and vectors may embed them.

- S1: GIVEN a `profile` naming an unimplemented profile hash WHEN folded THEN `profile_mismatch`. V: gen/profile-mismatch
- S2: GIVEN the core manifest WHEN listed THEN it holds no vector file, so a profile hash is never its own input. T: tools/tests/test_manifest.py::test_lists_no_vector_file
- S3: GIVEN the core files WHEN any tool, table or text lists them THEN the list is the one in `tools/manifest.py`: the re-pin tool, the checker's copy and its manifest, the Swift table, the Rust table, the bundle manifest and this requirement name the same set, and every part of the profile is on it. T: tools/tests/test_core_files.py::test_repin_reads_the_same_list, tools/tests/test_core_files.py::test_the_checker_ships_the_same_list, tools/tests/test_core_files.py::test_the_swift_table_has_one_row_per_file, tools/tests/test_core_files.py::test_the_rust_table_embeds_each_file_once, tools/tests/test_core_files.py::test_the_spec_names_the_same_list, tools/tests/test_core_files.py::test_every_profile_part_is_a_core_file_and_no_core_spec_file_is_missing

### CF-02 Vector format

Vector files follow the vitni format: one JSON file per vector, `{name, command, input | input_raw, anchor}`. Unlike vitni, `anchor` is REQUIRED on every handsal vector: vitni can run without anchors because two independent verifiers cross-check each other, while handsal starts with one reference. `input_raw` MAY carry bytes that JSON would normalize. Names are `group/case`. Vectors over MAX_INPUT are built by the harness at run time from their row, a valid input padded inside one string to MAX_INPUT + 1 bytes; no 16 MiB file is stored.

- S1: GIVEN a vector without `anchor` WHEN the harness loads it THEN it fails. T: conformance/tests/test_run.py::test_vector_without_anchor_is_rejected

### CF-03 Commands

`handsal-check <command> < input.json` writes exactly one line of JCS JSON and exits 0.

| Command | Input | Output |
|---|---|---|
| `check-act` | VR-01 | `{class, reason, receipt_id, valid}` |
| `recheck-act` | VR-17 | `{class, not_proven, reason, receipt_id, rechecked}` |
| `fold` | `{acts, at?, lineage, org, pin}` | FO-01 |
| `render` | `{attachments, kid, method, payload}` | `{first_line, text}` or `{"error":code}` (RN-06, RN-09) |
| `subset` | raw bytes | `{canonical, reason}` (ACT-04, grammar only) |
| `kid` | `{x, y}` | `{kid}` (ACT-11) |
| `genesis-check` | `{acts, lineage}`; the last lineage entry is the candidate document with its signatures | `{pin, reason, valid}`; `pin` is the exact content of the pin file (GP-05), the JCS line and its closing LF, when valid, else null |
| `enrolled` | GP-13 | `{enrolled, reason}` |

`pin` and `now` are inputs of the conformance build only. The production build (CF-08) takes neither: it reads the pin through the platform probe and `now` from the system clock, and an input carrying `pin` or `now` is `malformed_input`. `recheck-act` takes no `now` in either build and reads no clock; the production build reads only the pin (VR-17).

`render` takes exactly the keys `attachments`, `kid`, `method` and `payload`, else `malformed_input`. `payload` is the signed payload as a JSON object (not its bytes and not its base64url text), `kid` is the `kid` of the JWS header and `method` the method string to render, both strings, and `attachments` is an object. The names RN-09 binds are the only ones read: `request_b64`, `record_body_b64` and `decision_b64` (strings, standard base64 with padding, section 2.2), `document` and `previous` (genesis documents as JSON objects), `act` (a compact JWS string), and `candidates` and `heads` (arrays of compact JWS strings). A `request_b64`, `record_body_b64` or `decision_b64` that is not a string or not canonical base64 is `malformed_input`; any other attachment of the wrong JSON type is `attachment_mismatch`. Any other name is ignored.

`genesis-check` validates every link of `lineage` in order from the original: GP-03 for the original, GP-19 for each change against the path to its H in the epoch before it, and the GP-15 order per document. It returns the first failure, so `valid:true` means every link is authorized (GP-21). The ceremony and the pin helper use it.

Command inputs follow CF-08: the production build takes no `pin` and no `now`.

`kid` takes exactly `{x, y}`, two strings of base64url characters, and returns the thumbprint of those strings as given. It checks neither length nor curve: whether the key is valid is the concern of the act that introduces it (ACT-11). Any other shape is `malformed_input`.

Input framing: stdin MUST be I-JSON (RFC 7493: UTF-8, no duplicate member names, no lone surrogates) of at most MAX_INPUT bytes. Size is checked first, before parsing. A duplicate member name at any depth, invalid UTF-8, or more than MAX_INPUT bytes is `{"error":"unparseable_input"}`, before any command logic. Nesting deeper than MAX_NESTING is `unparseable_input` too: arrays and objects count together, the root value counts as 1, and input of exactly MAX_NESTING levels passes the reader and meets the command's own checks. The bound is one number for every implementation, because a reader with a bound of its own answers differently at the edge, and a recursive reader with none lets hostile input exhaust the stack. Exception: `subset` reads its stdin as raw bytes (the value under test; more than MAX_INPUT is `unparseable_input`) and hands them to the recognizer unparsed.

Errors, all with exit 0: an unknown command is `{"error":"unsupported_command"}`; input that is not I-JSON within the bound is `{"error":"unparseable_input"}`; JSON missing or mistyping a required input is `{"error":"malformed_input"}`. A nonzero exit happens only for a crash, which consumers MUST treat as failure. Nothing but the result line goes to stdout. Output is deterministic. There is no checker `build` or `emit` command: emitted bytes are produced by signers (`handsal-sign emit`, SG-01) and anchored by the vector generator.

- S1: GIVEN `{}` and command `x` WHEN run THEN `{"error":"unsupported_command"}`. V: cli/unsupported-command
- S2: GIVEN a duplicate key, or more than MAX_INPUT bytes, on stdin WHEN read THEN `{"error":"unparseable_input"}`. V: cli/stdin-duplicate-key-unparseable, cli/stdin-over-max-input-unparseable
- S3: GIVEN a lineage whose original is valid, or whose middle link is forged WHEN `genesis-check` runs THEN `valid:true` with the pin line, or the first failing link's code. V: cli/genesis-check-original-ok, cli/genesis-check-forged-middle-link, cli/genesis-check-change-revoked-signer
- S5: GIVEN stdin that is not JSON WHEN read THEN `{"error":"unparseable_input"}`; GIVEN `fold` without `lineage` THEN `{"error":"malformed_input"}`. V: cli/unparseable-stdin, cli/malformed-input
- S6: GIVEN the members of a value out of order WHEN `subset` reads them THEN `{"canonical":false}` with `payload_not_canonical_subset`: an output is its own JCS, never the unsorted form. V: cli/output-is-jcs
- S4: GIVEN `render` input nested MAX_NESTING + 1 levels WHEN read THEN `{"error":"unparseable_input"}`; GIVEN MAX_NESTING levels THEN the reader accepts it and the command answers `malformed_input`. V: cli/stdin-nesting-over-max-unparseable, cli/stdin-nesting-at-max-malformed

### CF-04 Implementations

Every checker implementation MUST produce byte-identical stdout for every vector. The harness (`conformance/run.py`, standard library only, `--impl "<argv>"` given one or more times) reports PASS, DIVERGE or ANCHOR-FAIL per vector, in the manner of vitni's `compare.mjs`. The checker role runs every command but `emit`, `recheck-act` included, and it is read from the vectors, not from a list in the harness.

A signer implementation runs the `render` and `emit` vectors, and only those, through its own conformance executable, `handsal-sign-conformance`. It is built from the same core as the shipped `handsal-sign` (SG-01), is never installed at an administrator path (SG-14, SG-15) and is not part of the signer's distribution. It takes one argument. `render` takes the CF-03 `render` input, read as CF-03 reads it, MAX_NESTING included, and writes the CF-03 output, with exit 0 for every result, so the `render` vectors are the ones the checker runs. `emit` is the shipped `emit` (SG-01, SG-04), with the same input, output and exit codes; a vector whose expected exit code is not 0 names it in its `exit` member. Any other argument is `{"error":"unsupported_command"}`, exit 2 (SG-08). The executable holds no key, shows no prompt and reads neither the clock nor a random source: every value its output depends on is in its input.

Why: the shipped `render` takes a draft and fills `performer_id`, `kid` and `ts` from its own key and clock (SG-04, RN-01), so it can never take a `payload` and a `kid` from its caller, and a flag in it would be a way to make the signer show words for bytes it did not derive. As in CF-08, the split is a build, not a flag.

- S1: GIVEN a divergent implementation WHEN the harness runs THEN it reports DIVERGE. T: conformance/tests/test_run.py::test_diverge
- S2: GIVEN a `render` vector WHEN run through `handsal-sign-conformance` THEN the output the checker gives. V: rnd/approve, rnd/render-73-lines-refused
- S3: GIVEN an approve draft with fixed values WHEN run through `handsal-sign-conformance emit` THEN `{payload_hex}`; GIVEN a draft with a JSON number THEN exit 2, `schema_refused`. V: jcs/emit-value-with-number-refused. C: cli/build-approve

### CF-05 Reference checker

The reference checker is Python (standard library logic) delegating ES256 to vitni behind a `Verifier` interface. The vitni binary is located only by an absolute administrator-owned path fixed per platform (SG-14): on macOS `/Library/Application Support/handsal/bin/vitni-verify`, checked like the pin (GP-10 `lstat` chain, root-owned, not group or other writable) before each spawn; on Windows `C:\Program Files\handsal\vitni-verify.exe`. There is no PATH lookup and no environment override; tests inject a path through a constructor argument only (the GP-14 pattern). A spawn error, an ownership failure, a timeout, non-JSON output or an `{"error"}` result is `verifier_unavailable`, never a skip, from `check-act`, `fold`, `enrolled` and `genesis-check`, which verify signatures through the same interface: each returns it in its own output form (the reason beside `valid:false`, `{"error"}`, or the `reason` of `enrolled` and `genesis-check`).

- S1: GIVEN the vitni binary absent WHEN `check-act` runs THEN `valid:false`, `verifier_unavailable`. T: checker/python/tests/test_rules.py::test_a_verifier_that_cannot_answer_is_verifier_unavailable_with_the_class, checker/python/tests/test_verifier.py::test_a_missing_binary_is_unavailable

### CF-06 Vector generation

ES256 vectors use the fixed P-256 scalars of `conformance/fixtures/keys.json` (KC-07), RFC 6979 nonces and then low-S normalization, so every run is byte-identical. A rerun followed by `git diff --exit-code` over the vector directory is the regeneration check. The generator calls both vitni implementations (Go and TypeScript) on every positive JWS and aborts unless both say `ok`; negative signature vectors record vitni's verdict. Vectors cover the low-S and high-S forms of one payload; they are the ES256 coverage vitni lacks. Vector anchors are authored by the generator from the expected behaviour, never by running the checker under test. PRODK vectors are not regenerated (CF-08).

- S1: GIVEN the generator run twice WHEN outputs are compared THEN identical. T: conformance/vectors/_gen/tests/test_generate.py::test_deterministic_stub_is_reproducible

### CF-07 Coverage rule

Every reason code defined here, except `verifier_unavailable` and `verifier_unexpected` (checker), and `pin_invalid`, `pin_rollback`, `internal`, `user_cancel`, `key_unavailable`, `key_exists`, `no_display`, `prompt_refused` and `biometric_unavailable` (pin helper and signer), and `class_pending` (no tagged registry holds a pending class, KC-02), MUST have at least one vector in which it is the only defect. Every adjacent pair of VR-02 steps MUST have an ordering vector, and so must the GP-15 genesis order. Every expectation is a concrete output: a case whose expectation is not observable at a command line is not a vector. A reason code with no vector, other than those excepted, fails the coverage check. The excepted codes need a missing verifier, a held lock, a pin file at a rollback, a biometric prompt, a key backend, a display or a registry class that is pending, and a vector input provides none of them: each is proven by the implementation tests listed below.

Rules whose case no vector input can set up are proven by implementation tests, and each test suite of a checker MUST hold one test per item. The harness gives a vector no way to stub vitni, remove it, set an environment variable or choose a signature:
- VR-03: a vitni reason that is not passed through, a listed one (`alg_not_allowed`) and a string vitni never defined, is `verifier_unexpected`; the test injects a verifier that answers it.
- CF-05: a missing vitni binary, a binary or ancestor that is not administrator-owned or is writable by the user, a spawn error, a timeout and a bad output are `verifier_unavailable` from `check-act`, `fold`, `enrolled` and `genesis-check`; an environment variable naming another binary is ignored; the tests inject a path, an owner and a root through the constructor.
- KC-02: a policy that lists a class with status `pending-spike` is `class_pending`; the shipped registry has no such class, so the test builds a registry with one (a policy that lists `win-hello-hw` under the shipped registry is `class_unknown`).
- VR-04: `S` equal to (n-1)/2 is low and `S` equal to (n+1)/2 is `high_s`; no signer can produce a valid signature with a chosen `S`, so the test calls the predicate with both values.
- FO-04 item 3: a chain act whose receipt id equals that of an ancestor is ignored as a cycle; no honest bytes produce it (it needs a SHA-256 fixed point), so the test builds the tree with the id function replaced.

The same holds for components other than the checker: a case that no command input can set up is an implementation test of that component, one test per item.
- Production-only behaviour, `test_builds.py` of the checker: the production build refuses an input carrying `pin` or `now` (`malformed_input`), refuses the fixture profile in every command (`fixture_profile`), reads the pin and the clock in process once per call (`recheck-act` the pin only, never the clock), and gives the answer the conformance build gives for the same data. The ancestor symlink case of the pin probe (GP-10) is in `test_probe_posix.py`, the WSL2 probe (GP-17) in `test_probe_wsl.py`. Whether the administrator path holds the production build only (SG-15), and whether the Windows-side gate runs isolated Python (GP-17 item 2), are installer tests outside the checker.
- GP-21 pin helper, in the library build of GP-21 Tests: rollback refused (`pin_rollback`, file unchanged), a pin on a sibling change included; an invalid lineage (`pin_invalid`); a first pin and an extension written; the path taken from the org of the returned line only, another org's file untouched; an argument, a third input key or a mistyped `lineage` (`malformed_input`); a malformed file at the derived path (`pin_malformed`); a duplicate input key or more than MAX_INPUT bytes (`unparseable_input`, exit 2); an existing `orgs` the reader would reject (`pin_owner`); the lock held (`internal`); the written file accepted by the platform probe, on macOS and on Windows. The cases `genesis-check` alone decides are vectors: `cli/genesis-check-missing-head-acts-invalid`, `cli/genesis-check-extra-acts-same-result`, `cli/genesis-check-forged-middle-link`.
- SG signer, tests of the signer with a software key backend (KC-07), one per item: an unknown command, none or two arguments are `unsupported_command`, and two trailing LF on stdin are `schema_refused`; `keygen` returns a `kid` that is the thumbprint of `sign` with `agree` different, refuses an existing key (`key_exists`) and an equal pair (`internal`); `keygen` and `pubkey` write the `Key <kid12> for <person>, class <class>` line to the display channel and not to stdout; `pubkey` and `version` show no prompt; `render` and `sign` without a key are `key_unavailable`, and so are a key of another class and one invalidated by a biometric change; a cancelled prompt is `user_cancel`, a missing display channel is `no_display` and a sensor that cannot verify now is `biometric_unavailable`; a refusal that needs no key is decided before `key_unavailable` (a malformed draft without a key is `schema_refused`; a missing attachment without a key is `key_unavailable`), and every exit 2 refusal is decided before `no_display` (a refused render with no display channel is exit 2, no key and no display channel is `key_unavailable`); two `sign` calls in one process show two prompts, and a second `sign` while a prompt is open is `prompt_refused` and shows nothing; a platform signature with high S comes back low; a failed self-verification and a prehash computed twice are `internal`, with no output; `render` of a payload the renderer refuses, or of a 2049-byte request, is `render_refused` with no prompt; the SG-13 checks of a draft against its attachments (the `act` id, `head`, `parent` id and performer, an attachment that is not a chain act, a missing attachment, a resolve without candidates); the success output is `{jws, receipt_id}` and passes `check-act`; on Windows `pin-read` answers `{bytes_b64, owner_ok, reason}` for a fixture file and a fake `handsal-sign.exe` first on PATH is not used.
- SG-12 ceremony, tests of the ceremony: a production policy whose `relay_kid` is the fixture relay key, a fixture kid, a fixture profile and a two-person organization (`policy_unreachable`) are refused before any write; the head line of a change at a forked previous epoch, the removed-key line and the pin's hash12 are shown; a failed `enrolled` after the write fails the ceremony and leaves the pin unchanged; the macOS write is one `/usr/bin/sudo -k` invocation of the helper and a fake `sudo` first on PATH is not used; on Windows a busy `\\.\pipe\handsal-pin` fails the ceremony before the helper starts, with nothing written.
- SG-15 installer, tests of the installation procedure: an artifact whose hash differs from the published value aborts it before the privileged copy, a failed unpack leaves the install path as it was, and neither conformance executable is ever copied to an administrator path.
- Named tests. A scenario cites an implementation test in a `T:` tail by its file path, two colons and the test name, and every test it cites is listed here:
  - `checker/python/tests/test_policy.py::test_pending_class_cannot_be_listed`: a registry with a `pending-spike` class gives `class_pending` for a policy that lists it (KC-02).
  - `checker/python/tests/test_policy.py::test_the_windows_class_is_not_in_the_first_tag`: under the shipped registry a policy that lists `win-hello-hw` is `class_unknown` (KC-02).
  - `signer/apple/Tests/HandsalCoreTests/GenesisTests.swift::aPendingClassIsRefusedOnARegistryThatHasOne`: the same rule in the Swift signer (KC-02).
  - `signer/windows/tests/forms_keys.rs::a_pending_class_is_refused_on_a_registry_that_has_one`: the same rule in the Rust core (KC-02).
  - `checker/python/tests/test_render.py::test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four`: a `-` of the alphabet at any of the twelve places never merges or splits the groups of a short form (section 2.1, RN-03).
  - `conformance/vectors/_gen/tests/test_render.py::test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four`: the generator's model of the short forms, checked the same way (CF-06).
  - `signer/apple/Tests/HandsalCoreTests/RenderCoreTests.swift::aDashOfTheAlphabetIsNeverTakenForTheSeparator`: the same in the Swift signer (RN-03).
  - `signer/windows/tests/draft.rs::a_dash_of_the_alphabet_is_never_taken_for_the_group_separator`: the same in the Rust core (RN-03).
  - `conformance/tests/test_run.py::test_vector_without_anchor_is_rejected`: the harness refuses a vector without `anchor` (CF-02).
  - `conformance/tests/test_run.py::test_diverge`: two implementations that differ are reported `DIVERGE` (CF-04).
  - `conformance/vectors/_gen/tests/test_generate.py::test_deterministic_stub_is_reproducible`: the generator run twice gives identical files (CF-06); `generate.py --check` runs the same check over the real vectors.
  - `tools/tests/test_manifest.py::test_lists_no_vector_file`: the core manifest lists no vector file, so a profile hash is never its own input (CF-01).
  - `tools/tests/test_core_files.py::test_repin_reads_the_same_list`: the re-pin tool reads the core list from the one owner (CF-01).
  - `tools/tests/test_core_files.py::test_the_checker_ships_the_same_list`: the checker's list and its shipped manifest are the owner's list (CF-01).
  - `tools/tests/test_core_files.py::test_the_swift_table_has_one_row_per_file`: the Swift table has a row for every core file and no other (CF-01).
  - `tools/tests/test_core_files.py::test_the_rust_table_embeds_each_file_once`: the Rust table embeds every core file and no other (CF-01).
  - `tools/tests/test_core_files.py::test_the_spec_names_the_same_list`: the core manifest sentence of CF-01 names the owner's list.
  - `tools/tests/test_core_files.py::test_every_profile_part_is_a_core_file_and_no_core_spec_file_is_missing`: every part of the profile is a core file, so none can change without moving the hash (CF-01).
  - `tools/tests/test_catalog.py::test_the_final_check_refuses_a_registry_class_that_is_pending_the_spike`: a tagged registry has no class that is `pending-spike` (KC-02).
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::theDisplayShowsTheRenderBeforeThePrompt`: the platform prompt carries line 1 (RN-11).
  - `signer/apple/Tests/HandsalCoreTests/KeyMaterialTests.swift::noOutputCarriesKeyMaterial`: no output of the signer carries the private scalar (SG-03).
  - `checker/python/tests/test_probe_posix.py::test_an_ancestor_that_is_a_symlink_is_pin_owner`.
  - `checker/python/tests/test_builds.py::test_an_input_carrying_pin_or_now_is_malformed_input`.
  - `checker/python/tests/test_builds.py::test_check_act`.
  - `checker/python/tests/test_builds.py::test_recheck_act_refuses_pin_and_every_key_that_names_a_moment`: the production `recheck-act` refuses `pin`, `now`, `synced_at`, `seen` and `tip_statement` and reads nothing first (VR-17).
  - `checker/python/tests/test_builds.py::test_recheck_act_reads_the_pin_in_process_and_never_the_clock`: the production `recheck-act` reads the pin once and the clock never (VR-17).
  - `checker/python/tests/test_recheck.py::test_both_commands_give_the_same_reason_for_every_time_free_defect`: `check-act` and `recheck-act` give one reason for each defect of steps 7 to 12 (VR-17).
  - `checker/python/tests/test_recheck.py::test_the_steps_are_one_list_cut_in_two`: the time-free steps are one list that both commands run (VR-17).
  - `checker/python/tests/test_builds.py::test_a_decision_is_decided_by_the_production_build_like_any_non_chain_act`: the production `check-act` and `recheck-act` of a decision read the pin in process and give the answer of the conformance build (VR-18).
  - `tools/tests/test_catalog.py::test_an_owner_signed_vector_names_one_profile_and_a_changed_profile_makes_it_stale`: an owner-signed vector that names another production profile than the current one is a hole of the catalog check (CF-08).
  - `checker/python/tests/test_builds.py::test_genesis_check`.
  - `checker/python/tests/test_verifier.py::test_four_reasons_pass_through_and_the_rest_is_unexpected`.
  - `checker/python/tests/test_verifier.py::test_a_missing_binary_is_unavailable`.
  - `checker/python/tests/test_rules.py::test_a_verifier_that_cannot_answer_is_verifier_unavailable_with_the_class`.
  - `signer/apple/Tests/HandsalCoreTests/CLITests.swift::unknownCommandsAreRefused`.
  - `signer/apple/Tests/HandsalCoreTests/CLITests.swift::missingOrExtraArgumentsAreRefused`.
  - `signer/apple/Tests/HandsalCoreTests/CLITests.swift::versionAnswersWithoutReadingStdinOrAKey`.
  - `signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::versionShowsNoPrompt`.
  - `signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::keygenReturnsTheThumbprintAndADistinctAgreementKey`.
  - `signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::aSecondKeygenNeverOverwrites`.
  - `signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::keygenShowsTheKidLineOnTheDisplayOnly`.
  - `signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::pubkeyReturnsTheKeygenObjectWithoutAPrompt`.
  - `signer/apple/Tests/HandsalLinkTests/LinkTests.swift::noOutputCarriesKeyMaterial`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::noOutputCarriesKeyMaterial`.
  - `signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::noOutputCarriesKeyMaterial`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::twoSignsInOneProcessShowTwoPrompts`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aHighSSignatureIsReturnedLow`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aFailedSelfVerificationIsInternal`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aPrehashComputedTwiceIsInternal`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::theSuccessOutputPassesCheckAct`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aRefusedRenderShowsNoPrompt`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aMissingDisplayIsNoDisplay`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aCancelledPromptIsUserCancel`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aKeyOfAnotherClassIsKeyUnavailable`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aSecondSignWhileAPromptIsOpenIsRefused`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aKeyTheBiometricsInvalidatedIsKeyUnavailable`.
  - `signer/apple/Tests/HandsalCoreTests/SignTests.swift::aSensorThatCannotVerifyNowIsBiometricUnavailable`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theActIdMustBeTheAttachedActs`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theHeadMustBeTheAttachedActsParent`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theParentIdMustBeTheAttachedAct`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theParentPerformerMustBeTheAttachedActsPerformer`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::anEndorsementNeedsItsAct`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theAttachedActMustBeAChainAct`.
  - `signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::aResolveNeedsItsCandidatesAndHeads`.
  - `signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::anArgumentIsRefused`.
  - `signer/apple/Tests/HandsalPinTests/PinProcessTests.swift::aThirdKeyIsMalformed`.
  - `signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::aMalformedFileAtThePathIsRefused`.
  - `signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::theOrgIsTheCheckersAndNobodyElses`.
  - `signer/apple/Tests/HandsalPinTests/PinProcessTests.swift::badFramingIsUnparseable`.
  - `signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::anExistingDirectoryTheReaderRejectsIsRefused`.
  - `signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::aHeldLockIsRefused`.
  - `signer/apple/Tests/HandsalPinTests/PinProbeTests.swift::theWrittenFilePassesTheProbe`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::theChannelIsSudoMinusKAtTheFixedPaths`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFakeSudoOnPathIsNotUsed`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFailedEnrolledLeavesThePin`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFixtureKidIsRefused`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFixtureProfileIsRefused`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aTwoPersonOrganizationIsRefused`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::theHeadLineAtAFork`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::aRemovedKeyThatTheDocumentCarriesIsShown`.
  - `signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::thePinHash12IsShown`.
  - `tools/install/test-install.sh::mismatch`.

`enrolled:true` can be shown by a vector only under production keys (PRODK, CF-08), because GP-13 step 7 answers `fixture_profile` under the fixture profile. Until a PRODK vector is committed, `enrolled:true` is proven by implementation tests (`Positive` in `test_enrolled.py` of the checker); every vector of `enrolled` shows a `false` result.

Ordering vectors for VR-02: 1/2 `ord/jws-before-canonical`; 2/3 `ord/canonical-before-schema`; 3/4 `ord/schema-before-method`; 4/5 `ord/method-before-act-object`, `ord/chain-method-before-body`; inside 5 `ord/act-object-before-body`; 5/6 `ord/body-before-fold`; inside 6 `ord/probe-org-before-owner`, `ord/owner-before-pin-parse`, `ord/pin-parse-before-pin-org`, `ord/pin-org-before-fold`; 6/7 `ord/fold-before-org`; 7/8 `ord/org-before-relay`; 8/9 `ord/relay-before-signature`; 9/10 `ord/signature-before-high-s`; 10/11 `ord/high-s-before-identity`; 11/12 `ord/identity-before-inputs`; inside 12 `ord/request-before-inputs`; 12/13 `ord/inputs-before-time`; 13/14 `ord/time-before-view`, `wit/ord-time-before-witness`; inside 14 `wit/ord-view-before-witness`; 14/15 `ord/view-before-dup`, `wit/ord-witness-before-duplicate`; 15/16 `ord/dup-before-class`.

Ordering vectors for GP-15: `gen/order-schema-before-lineage`, `gen/order-profile-before-class`, `gen/order-policy-before-device-class`, `gen/order-lineage-before-render`, `gen/order-lineage-before-unsigned`, `gen/order-unsigned-before-head`, `gen/order-unauthorized-before-carry`.

One adjacent pair of GP-15 has no vector: `role_key_class` before `fixture_key` (step 3). `role_key_class` needs a role holder whose class is not `biometric_only` and is not refused earlier in step 3, and registry version 1 has no such class under a production profile (KC-08 vectors use the fixture-only class, and `fixture_key` is not checked under the fixture profile). The order is fixed by GP-15 and no vector checks it until a registry lists such a class.

The same registry limit leaves the acceptance half of clean(k, H) (FO-26) without an only-defect vector: a role holder's device class must be `biometric_only` (KC-08), registry version 1 has one such class, and a policy that lists a role holder's device lists it (GP-20), so a role holder's key is always accepted. A member with no role can hold an unaccepted class, but then the role test refuses the change anyway, so such a vector could not fail for its stated reason and none exists. The acceptance half is proven by `checker/python/tests/test_tree.py::test_an_unaccepted_key_is_not_clean` (FO-26) and `checker/python/tests/test_epoch.py::test_a_role_holder_whose_class_the_policy_does_not_accept_does_not_count` (GP-19), which builds the epoch directly. A vector becomes possible when a registry lists a second `biometric_only` class.

- S1: GIVEN the vector set WHEN the coverage check runs THEN every reason code in section 11 that this requirement does not except has an only-defect vector. V: ord/jws-before-canonical, ord/dup-before-class

### CF-08 Production and conformance checker builds

The checker ships as two builds of one pure core:
- **production** `handsal-check`, the only build installed at the administrator path (SG-14): `check-act`, `enrolled` and `fold` call the platform probe in-process at the fixed pin path and read `now` from the system clock. An input carrying `pin` or `now` is `malformed_input`. A lineage under the fixture profile is `fixture_profile`.
- **conformance** `handsal-check-conformance`: the same commands with `pin` and `now` as input data. It implements both profiles and is never installed at an administrator path. Every vector runs against it (CF-04). No vector runs against the production build: it takes no `pin` and no `now`, so a vector input cannot set it up. Production-only behaviour is proven by implementation tests (CF-07).

Production-profile vectors use PRODK: production keys generated once per tag, used to sign the committed production vectors, with their private scalars destroyed afterwards and not listed in `fixture-kids.json`. Their bytes are committed and covered by the bundle hash; they are not regenerated. Continuous integration injects the vitni path through the conformance build's constructor.

An owner-signed vector names one production profile. Every genesis document of its lineage carries the production profile hash, and an edit to any core file moves that hash (CF-01), so a signed set belongs to the core it names and to no later one. After such an edit the committed set is stale: it is removed from the tree in the same change (it stays in the tag that shipped it), its ids are pending again, and the next tag needs a new signing run with new keys. The catalog check reads the current production profile from `conformance/pins.json` and lists every owner-signed file that names another as `owner-stale`, so a stale set cannot sit in the tree unnoticed; at the tag, `--final` lists each pending id that has no file.

Why: a consumer at the administrator path can never be handed a forged probe, a forged clock or a fixture profile, and every rule stays testable under both profiles. The build split enforces this, not a flag.

- S1: GIVEN the production build and an input with `pin`, or with `now`, or a lineage under the fixture profile WHEN run THEN `{"error":"malformed_input"}` for the first two and `fixture_profile` for the third. These are implementation tests of the production build (CF-07), not vectors. T: checker/python/tests/test_builds.py::test_an_input_carrying_pin_or_now_is_malformed_input, checker/python/tests/test_builds.py::test_check_act, checker/python/tests/test_builds.py::test_genesis_check
- S2: GIVEN ORG_PRODK under the production profile WHEN folded, and an approve by alice's production key WHEN checked THEN the state, and valid. P: fix/prodk-fold-ok, fix/prodk-check-act-ok
- S3: GIVEN an owner-signed vector whose lineage names another production profile than the current one WHEN the catalog check runs THEN it is a hole of kind `owner-stale`. T: tools/tests/test_catalog.py::test_an_owner_signed_vector_names_one_profile_and_a_changed_profile_makes_it_stale

## 10. Signer CLI

One contract, two implementations: Swift on macOS and Rust on Windows, run against the same vectors. On Windows the signer is a native `.exe` called from WSL2 through interop, with stdin and stdout as byte streams, UTF-8 without BOM, LF only and no newline translation; the authentication prompt appears on the Windows desktop. The signer does not fold: it checks bindings between bytes it holds, never chain state.

### SG-01 Command surface

`handsal-sign <command>`: `version`, `keygen`, `pubkey`, `emit`, `render`, `sign`, and `pin-read` (Windows only, GP-11). Each reads at most one JSON object from stdin through the canonical subset recognizer (ACT-04), with MAX_INPUT in place of MAX_PAYLOAD as the bound on the stdin bytes; MAX_PAYLOAD still bounds the signed values inside, and MAX_DEPTH is unchanged. Every recognizer failure, a duplicate key and an oversize input included, is exit 2 `schema_refused`. One trailing LF of stdin is framing, not part of the object; the MAX_INPUT bound counts it. Each command writes exactly one JCS line to stdout: the JCS bytes then one LF. There is no `info`, `key-create`, `key-list`, `build`, `link-code` or `enroll` command. Any other command, no command, or more than one argument is `{"error":"unsupported_command"}`, exit 2 (SG-08). `emit` writes `{payload_hex}`, the lowercase hex of the emitted payload bytes (ACT-05). These commands are the whole surface of the shipped signer; the executable that runs the vectors is `handsal-sign-conformance` (CF-04).

The largest signer input, the `act.endorse` draft of a resolve at the ACT-09 caps with its 34 act attachments, is at most 766,326 bytes, so MAX_INPUT leaves a wide margin.

- S1: GIVEN a draft padded to MAX_INPUT + 1 bytes WHEN read THEN exit 2, `schema_refused`. V: sgn/signer-stdin-over-max-input-refused
- S2: GIVEN a command that is not listed WHEN run THEN exit 2, `unsupported_command`. T: signer/apple/Tests/HandsalCoreTests/CLITests.swift::unknownCommandsAreRefused, signer/apple/Tests/HandsalCoreTests/CLITests.swift::missingOrExtraArgumentsAreRefused

### SG-02 version

`version` returns `{class, impl, spec}`. `class` is the registry id of the key class the build produces (`apple-se-bio` on macOS), `impl` is `handsal-sign-swift` on macOS and `handsal-sign-rust` on Windows, and `spec` is the production profile hash (CF-01): the shipped signer implements the production profile only (GP-18). It reads no stdin, needs no key and shows no prompt.

- S1: GIVEN `version` WHEN run THEN no authentication prompt. T: signer/apple/Tests/HandsalCoreTests/CLITests.swift::versionAnswersWithoutReadingStdinOrAKey, signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::versionShowsNoPrompt

### SG-03 keygen and pubkey

`keygen` input `{label, person}` creates a non-exportable hardware key of the build's class plus a separate key-agreement key, binds `person` as the performer for every later signature, and returns `{agree:{x,y}, class, kid, sign:{x,y}}`. It refuses if `agree` equals `sign` (exit 5, `internal`) or if a key already exists for this configuration (exit 2, `key_exists`); it never overwrites. The private key never leaves the hardware. `pubkey` returns the same object with no prompt. Both also write `Key <kid12> for <person>, class <class>` to the display channel, never to stdout, as an aid for linking (SG-09).

Repositories hold key ids, never key material. The only file that holds private key material is the signer's key file, in the signer's own configuration directory and readable by its owner only (the key blob, never the private scalar in clear). Nothing else a handsal tool writes or prints carries it: `keygen`, `pubkey`, `render`, `sign` and `emit`, the linking tool, the ceremony and the pin helper produce kids, public coordinates, hashes, signatures and one-time codes. A repository that holds handsal files holds kids, and in a genesis document the public coordinates of a device (GP-01), nothing more. The pin has no member for a key (GP-05), so a pin cannot carry one. Each tool that writes or shows something has its own scan for the private scalar (S3, S5), and a signer for another platform carries the same scan in its own suite.

- S1: GIVEN a successful keygen WHEN the result is read THEN `kid` is the thumbprint of `sign`; a second keygen is `key_exists`. T: signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::keygenReturnsTheThumbprintAndADistinctAgreementKey, signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::aSecondKeygenNeverOverwrites
- S2: GIVEN keygen or pubkey WHEN run THEN the kid12 line appears on the display channel, and `pubkey` shows no prompt. T: signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::keygenShowsTheKidLineOnTheDisplayOnly, signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::pubkeyReturnsTheKeygenObjectWithoutAPrompt
- S3: GIVEN a signer with a known private scalar WHEN `keygen`, `pubkey`, `emit`, `render` and `sign` run THEN neither stdout, the display channel nor a prompt carries the scalar, raw, in hex, in base64 or in base64url. T: signer/apple/Tests/HandsalCoreTests/KeyMaterialTests.swift::noOutputCarriesKeyMaterial
- S4: GIVEN a pin file with a member other than `genesis`, `org` and `spec` WHEN parsed THEN `pin_malformed`, so a pin has no place for a key. V: pin/unknown-key
- S5: GIVEN the linking tool, the ceremony and the pin helper WHEN each runs where a private scalar is known THEN nothing it prints, shows, hands to another tool or writes carries the scalar, in any form of S3. T: signer/apple/Tests/HandsalLinkTests/LinkTests.swift::noOutputCarriesKeyMaterial, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::noOutputCarriesKeyMaterial, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::noOutputCarriesKeyMaterial

### SG-04 Draft input and caller powers

`sign`, `render` and `emit` take `draft` plus `attachments`. The draft is a closed object `{body, expires_in_s?, head?, method, org, parent?}`, and a verdict draft also carries `recipient`, `relay` and `request_id` (ACT-09 gives them to the act object of a verdict and to no other method). A decision draft carries its `consumer` inside `body` with `action` and `subject` (VR-18) and none of the three keys of a verdict. Each of `expires_in_s`, `head`, `parent`, `recipient`, `relay` and `request_id` is present exactly where its method has it and absent elsewhere; a key outside the set, a missing key or a malformed value is `schema_refused`, and a method outside the registry is `unsupported_method`.
- `parent = {id, performer}` is given for chain acts and endorsements and fills `parent_receipt_hash` and `parent_performer_id`.
- `expires_in_s` is a decimal string from "1" to MAX_EXPIRES_IN_S, present iff the method carries `expires` (verdicts, `record.promote`, `decision`). "0" is refused, and so are a leading zero, a sign, a fraction and a JSON number: `expires` equal to `ts` is `bad_expiry` at every verifier (VR-11), and a signer MUST NOT sign what every verifier refuses. The policy maximum is checked by verifiers.
- `head` is exactly the ACT-08 object `{id, kind:"chain"}`, present exactly where ACT-08 gives the method one (for `genesis.sign`, iff `prev` of the attached document is non-null, SG-13).
- `recipient`, `relay` and `request_id` go into the act object of the verdict. A verdict draft whose `recipient` is not the person bound to the signer's key at keygen is `identity_mismatch`, exit 2, the code VR-05 gives the same fact, and nothing is signed.

The signer fills `performer_id` (bound at keygen), `kid` in the header and in the act object (ACT-14), `ts` from its own clock, `nonce` from 32 random bytes, `expires = ts + expires_in_s`, every pinned constant, and `inputs_hash` and `outputs_hash` from the attachments. A draft carrying `inputs_hash`, `outputs_hash`, `ts`, `nonce`, display text, prompt text or any authentication handle is refused (`schema_refused`). `emit` alone accepts `fixed = {kid, nonce, performer, ts}` and never signs. `emit` checks the forms of the four `fixed` values as `sign` fills them (ACT-07: `kid` a thumbprint of 43 base64url characters, `nonce` a canonical hashstr, `performer` a `member_id`, `ts` a `time`): a malformed value, a missing key or an extra key is `schema_refused`. The values are otherwise the caller's and harmless, since nothing is signed, and `emit` applies every rule above with `fixed.performer` as the person bound to the key, so it refuses what `sign` would refuse.

Why: the signer is the single owner of nonce and time, and `render` is the single owner of display text. The caller supplies facts, never derived values or words. `emit` is where vectors take the bytes of an act, so it must not write bytes for a value that no signer could produce, such as a nonce that is not a hashstr: a vector of such bytes would be an act that every verifier refuses (ACT-07). Identity has one owner, the key (SG-03): a verdict is addressed to one person (ACT-13), so a key answers only requests addressed to its own person, and the signer says so before the prompt instead of signing what VR-05 rejects.

- S1: GIVEN a draft with `ts` WHEN signed THEN exit 2, `schema_refused`. V: sgn/refuse-ts-input, sgn/refuse-nonce-input, sgn/refuse-display-text, sgn/refuse-auth-handle, sgn/refuse-schema-violation, sgn/parent-performer-required
- S2: GIVEN `expires_in_s` on a chain method, "0", or above 30 days WHEN signed THEN `schema_refused`. V: sgn/expires-in-s-refused-for-chain-method, sgn/expires-in-s-zero-refused, sgn/expires-over-30d
- S3: GIVEN an `emit` draft WHEN emitted THEN the act object carries the header kid. V: sgn/emit-act-kid-filled
- S5: GIVEN a draft whose method is not in the registry WHEN signed THEN exit 2, `unsupported_method`. V: sgn/refuse-unknown-method
- S4: GIVEN a verdict draft whose `recipient` is not the key's person WHEN signed or emitted THEN exit 2, `identity_mismatch`; GIVEN a verdict draft without `relay`, or a chain draft carrying `recipient`, THEN `schema_refused`. V: sgn/verdict-recipient-not-performer-refused, sgn/verdict-draft-missing-relay-refused, sgn/chain-draft-recipient-refused
- S5: GIVEN an `emit` input whose `fixed.nonce` is not a canonical hashstr WHEN emitted THEN exit 2, `schema_refused`. V: cli/build-bad-nonce
- S6: GIVEN a decision draft whose `action` is outside its grammar, or that carries `recipient` WHEN signed or emitted THEN exit 2, `schema_refused`. V: sgn/decision-action-grammar-refused, sgn/decision-draft-recipient-refused

### SG-05 Fresh authentication per signature

Every signature MUST require a fresh user verification from the key's class. A signer MUST NOT accept, cache or reuse an authentication context from a caller or from a previous signature; on macOS this means a new `LAContext` per call. Endorsements and resolves each prompt.

- S1: GIVEN two sign calls in one process WHEN run THEN two prompts. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::twoSignsInOneProcessShowTwoPrompts

### SG-06 Signature form

The signature is ES256 over the ASCII bytes `b64url(header).b64url(payload)`. CryptoKit hashes internally; on Windows, CNG `NCryptSignHash` signs a digest, so the signer computes SHA-256 once itself. The signer returns raw 64-byte R||S, normalizes S to the low half, verifies its own signature with the public key before output, and re-runs the recognizer and schema checks on the emitted payload. Output `{jws, receipt_id}`.

- S1: GIVEN a platform signature with high S WHEN returned THEN S is replaced by n minus S; a failed self-verification, or a prehash computed twice, is exit 5, `internal`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aHighSSignatureIsReturnedLow, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aFailedSelfVerificationIsInternal, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aPrehashComputedTwiceIsInternal
- S2: GIVEN a successful `sign` by a key of a lineage WHEN its `jws` is given to `check-act` of the reference checker THEN `valid:true`, the `receipt_id` the signer returned, and the class of the signing key. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::theSuccessOutputPassesCheckAct

### SG-07 Display

Once it holds the prompt guard (SG-10), the signer writes the full render to its own display channel (`/dev/tty` on macOS, `CONOUT$` on Windows), then `Signing as <performer> with <kid12>`, and puts line 1 into the OS prompt (macOS `localizedReason`; on Windows where the API allows it). The render never goes to stdout. With no display channel the signer exits 4. A refused render (`render_refused`, `attachment_missing`, `attachment_mismatch`) exits 2 with no prompt. The render and line 1 are aids (RN-11).

- S1: GIVEN a payload the renderer refuses WHEN signed THEN `render_refused`, no prompt; with no display channel, exit 4, `no_display`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aRefusedRenderShowsNoPrompt, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aMissingDisplayIsNoDisplay

### SG-08 Exit codes

Success is exit 0 with the result. Every failure writes `{"error":code}` and exits:
- 1 `user_cancel` (cancelled, or biometric verification failed);
- 2 input rejected: `schema_refused`, `render_refused`, `attachment_missing`, `attachment_mismatch`, `unsupported_method`, `unsupported_command`, `identity_mismatch`, `key_exists` (keygen only);
- 3 `key_unavailable` (missing, invalidated by a biometric set change, or of the wrong class; missing means that no key is bound (`render` or `sign` before `keygen`));
- 4 `no_display`, `prompt_refused`, `biometric_unavailable` (the person cannot be asked: there is no display, the signer will not open a prompt now (SG-10), or the biometric sensor cannot verify now);
- 5 `internal`, including a failed self-verification.

There is no partial output and no signature without a fresh prompt.

When a command has more than one defect, the first of these decides and no later check runs:
1. the framing and the form of the draft, in this order: the closed top-level object of the command (for `emit`, `fixed` with exactly its four string members); the draft as a closed object whose `method`, `body` and `org` are present with their types (`schema_refused`); the method against the registry (`unsupported_method`); every form that depends on the method (`org`, `expires_in_s`, `head`, `parent`, `recipient`, `relay`, `request_id`, `body`: `schema_refused`); and, for `emit`, last, the forms of the four `fixed` values (`schema_refused`), so a draft with an unsupported method and a malformed `fixed` value is `unsupported_method`;
2. the person: a verdict whose `recipient` is not the key's person is `identity_mismatch`, decided before any attachment is read;
3. the attachments, in the order RN-09 gives (Order of checks), the first defect deciding: a missing one is `attachment_missing`; one the method cannot read (for `genesis.sign`, a document without `prev`, or a change whose `org` is not a string) is `attachment_mismatch`. Where the signer compares a value of the draft with an attachment, the comparison sits where that attachment is read. For `genesis.sign`: the `document`, then the `head` of the draft against `prev` of the document (`schema_refused`, a form defect), then the `org` of the draft against the document's (`attachment_mismatch`, SG-13), then `previous`, then `head.id`. An absent `document` is `attachment_missing` whatever the draft's `head` says, because whether a head is due is known only from the document. For `act.endorse`, the values derived from the attached act (`body.act`, `parent`, `head.id`) are compared when that act is read, before `candidates` and `heads` are asked for;
4. the render (`render_refused`).

The key sits between steps 1 and 2. `render` and `sign` need the person and the kid the key holds (step 2 reads the person), so after step 1 a missing key, or one of the wrong class, is `key_unavailable` (exit 3) and no later check runs; `emit` takes the person from `fixed` and reads no key. After step 4 come, in this order, the display (`no_display`), the sensor (`biometric_unavailable`), the prompt guard (`prompt_refused`) and the prompt (`user_cancel`). Every other exit 2 refusal therefore comes before the display and the prompt (SG-07): a refused render is never shown, and a missing display channel never hides a refused draft.

Why: a draft that is wrong in its own form is refused before the signer weighs it against anything else, and the key's person, which the signer holds, is weighed before the caller's attachments. Where a rule reads an attachment to decide the shape of the draft (the `head` of a `genesis.sign`), it is still shape: it comes before the checks that bind a draft value to the attachment. Two implementations that chose differently answered the same input with different codes.

`biometric_unavailable` is a sensor that cannot verify a person now (a closed lid, a disabled, locked-out or interrupted sensor). The signer asks the platform before it shows anything, and a platform that interrupts a prompt it opened gives the same code. A condition of the machine is never `user_cancel`, which is a person's decision; a key the platform will never use is `key_unavailable`. Nothing is signed, and the call can be repeated when the sensor is back.

- S1: GIVEN the user cancels WHEN run THEN exit 1, `user_cancel`; a key of another class is exit 3, `key_unavailable`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aCancelledPromptIsUserCancel, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aKeyOfAnotherClassIsKeyUnavailable
- S3: GIVEN a `genesis.sign` draft that carries a `head` and has no `document` attachment WHEN emitted THEN exit 2, `attachment_missing`. V: sgn/genesis-document-missing-before-head-refused
- S4: GIVEN a draft whose method is outside the registry and a `fixed.nonce` that is not a canonical hashstr WHEN emitted THEN exit 2, `unsupported_method`. V: sgn/unsupported-method-before-bad-fixed-refused
- S5: GIVEN a sensor that cannot verify now WHEN signing THEN exit 4, `biometric_unavailable`, nothing shown and no prompt. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aSensorThatCannotVerifyNowIsBiometricUnavailable
- S2: GIVEN a verdict draft whose `recipient` is not the key's person and whose request attachment is missing WHEN emitted THEN `identity_mismatch`; GIVEN a `genesis.sign` draft of an original that carries a `head` and whose `org` is not the hash of its document THEN `schema_refused`. V: sgn/identity-before-attachment-refused, sgn/genesis-head-before-org-refused

### SG-09 Device linking

The linking tool, outside the signer, generates a one-time code of 32 random bytes and shows it as a QR code. `device.add` and `member.add` bind `link_code_hash`, its hashstr. The new key endorses (FO-07, FO-23). The fold MUST ignore a `device.add` or `member.add` whose `link_code_hash` equals that of an applied primary on the path from the epoch's root to the act's parent (`link_code_reused`, an internal ignore reason). The scope is the past cone (FO-05): a primary on another branch, or below the parent, never makes a code reused. The QR carries the code itself as the 43-character base64url text of the 32 bytes (RFC 4648 section 5, no padding), and nothing else: no prefix, no URL, no hash. The new device decodes the text to the 32 bytes, and `link_code_hash` is the hashstr of those bytes. `link_code_hash` is a one-time uniqueness value; it proves nothing about the QR flow.

The person compares the kid12 shown for the new device (SG-03) with line 1 of the `device.add` OS prompt on each signing device. That comparison is an aid. Linking security is FO-22.

- S1: GIVEN two `device.add` acts with the same code hash WHEN folded THEN only the first applies. V: lnk/reused-code, lnk/code-hash-format, lnk/ok

### SG-10 Rate and surprise

The signer SHOULD limit prompt frequency per process and MUST NOT run while another of its prompts is open. An unexpected prompt is a signal, never routine.

A prompt the signer refuses to open, because another of its prompts is open or because its rate limit is reached, is exit 4, `prompt_refused`: nothing is shown and nothing is signed. It is not `internal`, which says the signer itself is faulty, and not `user_cancel`, which says a person declined. A caller that gets `prompt_refused` can tell a signer that is busy or limited from a broken one.

- S1: GIVEN a prompt that is open WHEN a second `sign` is called THEN exit 4, `prompt_refused`, no second prompt and nothing shown. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aSecondSignWhileAPromptIsOpenIsRefused

### SG-11 Biometric set change

A key invalidated by a change of the enrolled biometrics is exit 3 `key_unavailable`. Recovery is a `device.add` signed from other devices. The ceremony MUST flag persons holding a single device.

- S1: GIVEN a key invalidated by a biometric change WHEN signing THEN exit 3, `key_unavailable`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aKeyTheBiometricsInvalidatedIsKeyUnavailable

### SG-12 Enrollment ceremony

The ceremony is a procedure, not a signer command. It MUST:
1. collect the document and every listed device's `genesis.sign`, as one input line (GP-21 grammar: the canonical subset recognizer, MAX_INPUT, one LF, no argument) holding one object with exactly the keys `acts` (the bag of every epoch), `device_kid`, `lineage` (the `genesis-check` lineage, the candidate document last, each entry with the `genesis.sign` receipts of every listed device), `synced_at` and `tip_statement` (the `enrolled` inputs, GP-13); `org` is not an input, it is the hash of the first lineage document (GP-04);
2. refuse a document whose `profile` is a fixture profile, and any kid listed in `fixture-kids.json` (a device or the `relay_kid`);
3. run `genesis-check` and stop unless it returns `valid:true`;
4. refuse a policy without a spare person (GP-02 `policy_unreachable`) and a role holder's device whose class is not biometric-only (KC-08);
5. show the render (RN-08 for an original, RN-10 for a change), including the witness lines, and flag persons holding a single device (SG-11);
6. for a change, show from the previous epoch's accepted chain in the ceremony's bag one line about H: when the chain ends at tip T, `H is the tip` or `H is not the tip (tip <full T>)`; when it ends at fork parent P, `Previous epoch forked at <full P>;` followed by `H is P`, `H is below candidate <full c>` or `H is not below P`, where H counts as below a candidate when it is that candidate (the top of its branch), so `H is below candidate <full c>` also when H is c itself;
7. for a change, show one line `Key removed in the previous epoch: <full kid>` per kid that the document carries, or whose key signed it, and that a valid `device.remove` in the ceremony's bag removes anywhere in the previous epoch; when the previous epoch forked, the ceremony folds each branch alone, its own acts and the acts above the fork, and takes the union of the removed kids, because the checker's `fold` of a forked epoch answers the fork and no state; a previous epoch that cannot be folded at all stops the ceremony with the fold's code, since an aid that cannot be shown is not skipped;
8. show hash12 of the `genesis` in the exact pin line and ask the person to compare it with line 1 of the `genesis.sign` prompt they saw;
9. hand `{acts, lineage}` to the pin helper through GP-12 and GP-21;
10. run `enrolled`.

The pin write is the ceremony's last write and is never undone. On a failure after the write the ceremony reports the failure and leaves the pin. The lines of steps 6 to 8 are aids against the cases in section 14 (L4, L5), not boundaries. The ceremony SHOULD run in a terminal with no agent session, because its comparisons happen on a shared channel (RN-11).

- S1: GIVEN `enrolled` false after the pin write WHEN the ceremony finishes THEN it fails and the pin file is unchanged. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFailedEnrolledLeavesThePin
- S2: GIVEN a fixture kid, a fixture relay kid, a fixture profile, or a two-person organization WHEN the ceremony runs THEN it refuses before any write. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFixtureKidIsRefused, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFixtureProfileIsRefused, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aTwoPersonOrganizationIsRefused
- S3: GIVEN a change at a forked previous epoch, or one carrying a removed key WHEN the ceremony runs THEN it shows the head line and the removed-key line; and it shows the pin's hash12. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::theHeadLineAtAFork, signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::aRemovedKeyThatTheDocumentCarriesIsShown, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::thePinHash12IsShown

### SG-13 Signer derives and checks attachments

For `genesis.sign` the signer derives `org` from the attached `document`: hashstr(JCS(document)) for an original (`prev` null, GP-03), `document.org` for a change; a draft whose `org` differs is `attachment_mismatch` (SG-08 gives the order of the refusals). For `act.endorse` the signer MUST derive the expected `body.act`, `parent = {id, performer}` and `head.id` from the attached act (RN-09) and refuse a draft whose values differ (exit 2, `attachment_mismatch`); a missing attachment is `attachment_missing`. For `chain.resolve` the candidate and head acts are required attachments, checked per RN-09. For an endorsement of a resolve the signer requires and checks the nested `candidates` and `heads` attachments. Every refusal is exit 2 with no prompt.

Why: the caller supplies the attachment, never a second copy of facts derivable from it.

- S1: GIVEN an endorse draft whose head, parent id or parent performer differs from the attached act WHEN signed THEN exit 2, `attachment_mismatch`. T: signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theActIdMustBeTheAttachedActs, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theHeadMustBeTheAttachedActsParent, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theParentIdMustBeTheAttachedAct, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theParentPerformerMustBeTheAttachedActsPerformer
- S2: GIVEN an endorse draft without its attachment, or whose attachment is an approve, or a resolve draft without candidate attachments WHEN signed THEN exit 2, `attachment_missing` (`attachment_mismatch` for the approve). T: signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::anEndorsementNeedsItsAct, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theAttachedActMustBeAChainAct, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::aResolveNeedsItsCandidatesAndHeads
- S3: GIVEN a `genesis.sign` draft of an original whose `org` is not the hash of its attached document WHEN signed or emitted THEN exit 2, `attachment_mismatch`. V: sgn/genesis-org-not-document-hash-refused
- S4: GIVEN a decision draft without its `decision_b64` attachment WHEN signed or emitted THEN exit 2, `attachment_missing`: the signer derives `inputs_hash` from the attached bytes and signs nothing it cannot show. V: sgn/decision-attachment-missing-refused

### SG-14 Helpers by absolute path

Signer, checker, probe and ceremony locate every helper they execute only by an absolute administrator-owned path fixed per platform. There is no PATH lookup and no environment override outside a test constructor.
- macOS: `/Library/Application Support/handsal/bin/vitni-verify`, `/Library/Application Support/handsal/bin/handsal-pin` (the pin helper, a native binary), `/Library/Application Support/handsal/bin/handsal-check` (the launcher of the production checker, CF-08, in the form GP-17 allows), `/Library/Application Support/handsal/lib/handsal-check.pyz` (its zipapp), `/Library/Application Support/handsal/python/bin/python3` (the pinned interpreter, with its notices in `python/licenses/` beside it), and `/usr/bin/sudo`. The launcher runs the interpreter and the zipapp only by those two paths.
- Windows: `C:\Program Files\handsal\` holding `handsal-sign.exe`, `handsal-check` (in the form GP-17 allows: a native binary, or `lib\handsal-check.pyz` run by the interpreter under `python\` with its notices in `python\licenses\`), `vitni-verify.exe` and `handsal-pin.exe` (native).
- WSL2: the Windows binaries through the drvfs path `/mnt/c/Program Files/handsal/...`, never PATH and never `\\wsl$`. On WSL2 this is not a boundary (GP-17).

The ceremony runs the helper, and the helper runs the checker, only by these paths.

Why: an agent that can set environment variables or prepend to PATH cannot substitute the verifier, the pin reader, the pin helper or sudo.

- S1: GIVEN a fake `sudo` first on PATH WHEN the ceremony runs THEN `/usr/bin/sudo` is used. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFakeSudoOnPathIsNotUsed

### SG-15 Binary installation

Files at administrator paths (`vitni-verify`, both pin helpers, the checker launcher `bin/handsal-check`, `lib/handsal-check.pyz`, the interpreter under `python/` with its `python/licenses/`, `handsal-sign.exe`) are installed only by a person-run procedure that, before the privileged copy, computes the SHA-256 of each artifact (the interpreter as the one pinned archive, its licence texts as a gzip tar packed from the pinned notices) and compares it with the value published for the tag, read on a second device. Any mismatch aborts. It needs only stock tools at its fixed PATH (checked before any privileged step) and unpacks in staging before creating anything at an administrator path, so a failure leaves them as they were. The installer creates `handsal`, `bin`, `lib` and `python` owned by root, mode 0755 on macOS (GP-10), and never `orgs` or `pin.lock`, which belong to the pin helper (GP-21). Artifacts built in a user-writable tree are never copied to an administrator path, and neither conformance executable is ever installed.

Why: an administrator path is only as trustworthy as the bytes copied into it.

- S1: GIVEN an artifact whose hash differs from the published value WHEN installing THEN the procedure aborts before the privileged copy. T: tools/install/test-install.sh::mismatch

## 11. Reason codes

Every code is lowercase snake_case and appears verbatim in outputs and vectors. Each has a vector in which it is the only defect (CF-07).

| Code | Where |
|---|---|
| `unsupported_command`, `unparseable_input`, `malformed_input` | checker command line (CF-03); `unparseable_input` and `malformed_input` also from the pin helper (GP-21) |
| `jws_shape` | `check-act` step 1 (ACT-02, ACT-03) |
| `payload_not_canonical_subset`, `payload_too_large` | step 2 (ACT-04, VR-16); `subset` |
| `schema` | steps 3 and 5 (ACT-01, ACT-06 to ACT-08, ACT-13, ACT-14); `render` |
| `method_unknown`, `chain_method` | step 4 (ACT-09, VR-02) |
| `body_schema` | step 5 (ACT-09, ACT-10) |
| `pin_org_mismatch`, `pin_missing`, `pin_owner`, `pin_probe_unavailable`, `pin_probe_unprotected`, `pin_malformed`, `profile_mismatch`, `fixture_profile`, `genesis_pin_mismatch`, `pin_spec_mismatch`, `lineage_broken` | step 6, `enrolled` steps 1 to 3 and 7, fold (GP-05, GP-10, GP-11, GP-13, GP-17, GP-18) |
| fold error codes (below) | step 6 (i), `enrolled` step 4, `fold`, `genesis-check` |
| `org_mismatch` | step 7 (GP-04) |
| `relay_mismatch` | step 8 (VR-08) |
| `unknown_key`, `revoked_key`, `bad_signature`, `context_mismatch`, `verifier_unavailable`, `verifier_unexpected` | step 9 (VR-03, CF-05) |
| `high_s` | step 10 (VR-04) |
| `identity_mismatch` | step 11 (VR-05) |
| `request_mismatch`, `consumer_mismatch`, `inputs_mismatch`, `outputs_mismatch` | step 12 (VR-02, VR-06, VR-07, VR-18) |
| `ts_in_future`, `bad_expiry`, `validity_too_long`, `expired` | step 13 (VR-11) |
| `view_in_future`, `stale_view` | step 14 (VR-12), `enrolled` step 6; `stale_view` also from `recheck-act` for a head that is no position of a chain the lineage proves (VR-17) |
| `witness_unexpected`, `witness_missing`, `witness_malformed`, `witness_key_mismatch`, `witness_bad_signature`, `witness_org_mismatch`, `witness_epoch_mismatch`, `witness_superseded`, `witness_in_future`, `stale_witness`, `behind_witness` | step 14 (WT-04, WT-05, WT-10), `enrolled` step 6 |
| `duplicate_receipt` | step 15 (VR-09, VR-15) |
| `unproven_class` | step 16 (KC-04) |
| `ok` | success of `check-act`, `recheck-act` (`rechecked:true`), `enrolled`, `genesis-check`, `subset` and the pin helper |
| `local_key_unknown`, `local_key_not_active`, `local_class_not_accepted` | `enrolled` step 5 (GP-13) |
| `attachment_missing`, `attachment_mismatch`, `render_refused` | `render`, signer exit 2 (RN-02, RN-05, RN-09, RN-12) |
| `pin_invalid`, `pin_rollback`, `internal` | pin helper (GP-21) |
| `user_cancel` (1), `schema_refused`, `unsupported_method`, `unsupported_command`, `identity_mismatch`, `key_exists` (2), `key_unavailable` (3), `no_display`, `prompt_refused`, `biometric_unavailable` (4), `internal` (5) | signer exit codes (SG-08) |

Fold error codes, in GP-15 order where they apply: `genesis_schema`, `doc_not_sorted`, `genesis_key_invalid`, `duplicate_key`, `profile_mismatch`, `fixture_profile`, `policy_invalid`, `policy_out_of_bounds`, `policy_unreachable`, `class_unknown`, `class_pending`, `class_test_only`, `class_policy_mismatch`, `role_key_class`, `fixture_key`, `lineage_broken`, `genesis_render_too_large`, `genesis_unsigned`, `genesis_head_unknown`, `genesis_change_unauthorized`, `genesis_device_revoked`, `genesis_device_changed`; then `genesis_pin_mismatch`, `fork`, `at_beyond_tip`, `verifier_unavailable`.

Internal ignore reasons inside the fold (never output; the act is not on the chain): every FO rejection, `link_code_reused`.

Retired codes, never reused: `genesis_signer_unknown` and `genesis_sig_mismatch` (signatures that do not count are ignored, GP-15), and `genesis_head_mismatch` (one H per document, GP-19).

## 12. Vector groups

| Group | Requirements |
|---|---|
| `ok`, `jws`, `jcs`, `sch`, `mth`, `bod`, `vrd`, `key` | ACT |
| `cls` | KC |
| `gen`, `pol`, `pin`, `chg`, `org`, `enr`, `fix` | GP, KC-07 |
| `fld`, `add`, `mem`, `rem`, `cas`, `rev`, `quo`, `end`, `frk`, `rsv`, `cln`, `lnk` | FO, SG-09 |
| `chk`, `ord`, `vtn`, `sig`, `idn`, `inp`, `rly`, `rep`, `tim`, `frs`, `ing`, `rck`, `dec` | VR |
| `rnd` | RN |
| `cli`, `cf` | CF |
| `sgn` | SG, GP-12, GP-21 |
| `wit` | WT |

Groups name where a vector lives, not a limit on what it proves: many vectors cite requirements of several families.

## 13. Freshness witness

VR-12 freshness rests on `synced_at`, which is a claim by the consumer. An actor controlling the consumer's act file and sync timestamp can withhold a removal indefinitely (section 14, L10). The witness adds an independent signed claim: "at time T, the latest position of epoch E of org O that the relay held was X". The consumer's view counts as fresh only if its own fold reaches X and T is recent. The relay attests freshness, never validity.

- The pinned genesis policy decides whether freshness is witnessed and by which key (WT-01); only a genesis change changes it (WT-08).
- The relay produces statement bytes; WT-02 fixes their format. The relay server itself is out of scope.
- The checker verifies statements once, at `check-act` step 14 and `enrolled` step 6 (WT-05).
- The fold and the VR rules decide act validity, never the statement (WT-06).
- A statement arrives through the consumer, a path an agent can reach. It is untrusted until authenticated by the pinned relay key, and even then it can only refuse.

### WT-01 Policy field witness

`policy` (GP-02) MUST carry the key `witness`, whose value is exactly one of:
- `{"mode":"none"}`
- `{"max_tip_age_s":D,"mode":"relay","relay_kid":K,"relay_pub_jwk":{"crv":"P-256","kty":"EC","x":X,"y":Y}}`

Rules:
- Keys exactly as shown for the mode, with `mode` matched byte-exact. Another mode value, or a missing or extra key, is `policy_invalid`. A policy without `witness` is `policy_invalid`: absence never means `none`.
- `D` is a decimal string with `60 <= D <= 86400`, else `policy_out_of_bounds`. Below a minute a relay refresh plus clock skew cannot be met; a witness older than a day no longer narrows the gap it exists to close.
- `X` and `Y` are canonical base64url of 32 bytes each, and the point is on P-256 (ACT-11 rules), else `policy_invalid`. `relay_pub_jwk` is exactly the RFC 7638 thumbprint input, and `K` MUST equal its thumbprint, else `policy_invalid`.
- The relay key is disjoint from every device key: `K` equals no device `kid` of the document, and the relay point equals no device `sign` or `agree` point, else `policy_invalid`. In the fold the epoch's relay key counts as an already-present key for FO-07: a `device.add` or `member.add` that introduces it as `kid`, `sign` or `agree` is not on the chain.
- Fixture: `conformance/fixtures/keys.json` carries one relay key, labelled `relay-fixture`, whose kid is listed in `fixture-kids.json` (KC-07). Only vectors use it. Under a production profile a policy whose `relay_kid` is a fixture kid is `fixture_key` in the fold (GP-18), and the ceremony refuses it (SG-12).

Why: one rule owns the freshness regime, the pinned policy. Relay key and member keys are disjoint by construction, so a relay signature never counts as a human act, and no member key can sign a statement under the relay's name.

- S1: GIVEN ORG without `witness` WHEN folded THEN `policy_invalid`. V: wit/pol-missing-witness, wit/pol-mode-unknown, wit/pol-none-extra-key, wit/pol-relay-missing-jwk, wit/pol-kid-not-thumbprint, wit/pol-jwk-not-on-curve, wit/pol-jwk-extra-member
- S2: GIVEN a relay policy whose `relay_pub_jwk` equals alice's `sign` key WHEN folded THEN `policy_invalid`. V: wit/pol-relay-key-is-device-key, wit/pol-relay-key-is-agree-key
- S3: GIVEN `max_tip_age_s` `"59"` or `"86401"` THEN `policy_out_of_bounds`; GIVEN `"60"` or `"86400"` THEN the state. V: wit/pol-tip-age-59, wit/pol-tip-age-86401. C: wit/pol-tip-age-bounds-ok, wit/pol-tip-age-upper-bound-ok
- S4: GIVEN WIT_ORG WHEN folded and checked by `genesis-check` THEN the state with witness mode `relay`, and `valid:true`. V: wit/relay-ok-original, wit/genesis-check-relay-ok

### WT-02 Tip statement

A tip statement is a JWS compact serialization over the act envelope. Reusing the envelope means the same recognizer, the same schema code and vitni `verify` (the single ES256 owner, CF-05) handle it: there is no second parser and no ES256 inside the checker. It MUST be exactly:
- header `{"alg":"ES256","kid":<relay_kid>}` (ACT-02); segments per ACT-03; payload in the canonical subset (ACT-04), at most MAX_PAYLOAD; signature with low S (the VR-04 rule);
- envelope constants per ACT-01; `method` = `local:handsal.relay.tip`; `performer_id` = `"relay"`; `parent_receipt_hash` = null; `parent_performer_id` = null; `inputs_hash` = `outputs_hash` = EMPTY_HASH; `nonce` per ACT-07; `ts` = the statement time, from the relay's clock;
- `ext` = `{"dev.handsal/act":{"body":{"epoch":E,"next":N,"tip":X},"org":O}}`, closed, with no `head` and no act-object `kid` (ACT-14 does not apply), where E = hashstr(JCS(the epoch's genesis document)), X = a position id of epoch E's chain (the root id E at position 0), O = the org id, and N = `"yes"` or `"no"` (WT-10).

The statement time is the envelope `ts`; a body `time` would be a second source for one value. There is no `n` (it is derivable, as in ACT-08). `epoch` is not a duplicate of `tip`: it is checked against the pin's `genesis`, an independent source, so a relay on a newer epoch tells the consumer to re-pin instead of reporting the consumer as merely behind.

`local:handsal.relay.tip` is a statement, not an act. It is not in the ACT-09 registry: given as the `check-act` `jws` it is `method_unknown`, and inside `acts` the fold ignores it (FO-06). `performer_id` `"relay"` exists only to address the one-entry vitni keys map of WT-05. A member whose id is `relay` gains nothing, because member keys never enter that map and the relay key never enters the fold `keys` (WT-01).

Relay obligations (a contract for the relay server, not checked by verifiers): the relay MUST serve a statement for every epoch it holds, the latest and every superseded one, each naming that epoch and the last position of that epoch in the relay's own successful fold, with `next` set per WT-10 (`"yes"` for every superseded epoch). It takes `ts` from its own clock and never signs a tip it has not folded.

Any violation of this format is `witness_malformed` (WT-05 step 2).

- S1: GIVEN a statement whose body also carries `time` WHEN verified THEN `witness_malformed`. V: wit/malformed-body-extra-key, wit/malformed-head-present, wit/malformed-method, wit/malformed-performer, wit/malformed-jws
- S2: GIVEN TIP_OK passed as the `check-act` `jws` WHEN checked THEN `method_unknown`. V: wit/statement-as-act
- S3: GIVEN a bag with no primaries and a statement whose tip is the epoch root WHEN checked THEN valid. V: wit/tip-root-position-ok

### WT-03 Transport

`check-act` (VR-01) and `enrolled` (GP-13) take the required input key `tip_statement`: either `null` or a JWS compact string. A missing key, or a value of any other JSON type, is `{"error":"malformed_input"}`, checked with the other required inputs before folding. The consumer requests the statement for its pinned epoch, the pin's `genesis`, so a consumer not yet re-pinned after a change still gets a statement it can verify. How the consumer obtains the statement from the relay is out of scope. `fold` and `genesis-check` take no statement: they decide history, not freshness.

- S1: GIVEN a `check-act` input without the key `tip_statement` WHEN run THEN `{"error":"malformed_input"}`. V: wit/statement-key-absent, wit/statement-wrong-type

### WT-04 Mode none

When the current epoch's `witness.mode` is `none`, freshness is exactly VR-12 (`synced_at`). `tip_statement` MUST be `null`; any non-null value is `witness_unexpected`, whatever its content, and it is not parsed.

Why reject instead of ignore: an ignored statement is a silent path. A consumer that supplies a statement believes its view is witnessed while the pinned policy says it is not. Rejecting makes the disagreement between consumer configuration and pin loud, at the cost of one configuration fix. With mode `none`, behaviour equals the profile without a witness for every input that carries `tip_statement: null`.

- S1: GIVEN ORG (mode `none`) and TIP_OK supplied WHEN checked THEN `valid:false`, `witness_unexpected`. V: wit/mode-none-statement-supplied, wit/mode-none-garbage-statement, wit/enr-mode-none-supplied
- S2: GIVEN ORG and `tip_statement` null WHEN checked THEN valid, with bytes equal to `ok/approve`. V: wit/mode-none-null-ok

### WT-05 Mode relay: ordered verification

When `witness.mode` is `relay`, `check-act` step 14 and `enrolled` step 6 run these checks after the VR-12 checks, in this order, first failure wins:
1. `tip_statement` is null: `witness_missing`.
2. Structure: ACT-01, ACT-02, ACT-03, ACT-04, ACT-06 (with the closed act object of WT-02) and ACT-07 applied to the statement, plus the WT-02 method, performer, closed body, `next` value, absence of `head`, and size. Any failure: `witness_malformed`.
3. The header `kid` differs from the policy's `relay_kid`: `witness_key_mismatch`.
4. vitni `verify` with `keys = {"relay":{<relay_kid>:{"alg":"ES256","crv":"P-256","kty":"EC","status":"active","x":X,"y":Y}}}`, `policy.expected_binding = "local"` and `policy.expected_method = "local:handsal.relay.tip"`. Any non-ok vitni reason, or S above n/2, is `witness_bad_signature`. vitni unreachable or failing is `verifier_unavailable` (CF-05).
5. The act object's `org` differs from the pin's `org`: `witness_org_mismatch`.
6. `body.epoch` differs from the pin's `genesis` (the current document hash): `witness_epoch_mismatch`.
6a. `body.next` is `"yes"`: `witness_superseded` (WT-10).
7. `ts` later than `now + clock_skew_s`: `witness_in_future`; exactly equal is valid.
8. `now - ts` greater than `max_tip_age_s`: `stale_witness`; exactly equal is valid.
9. `body.tip` is not a position of the current epoch's chain as folded from the consumer's own bag: `behind_witness`. A tip older than the consumer's tip is valid: a consumer ahead of the relay holds everything the relay held.

Signature before content: apart from the header kid used to select the key, no field of an unauthenticated statement decides anything.

Why: in mode `relay` a non-chain act authorizes something now only if an independent pinned key attests that the consumer's view contains every position the relay held at most `max_tip_age_s` ago.

- S1: GIVEN WIT_ORG, a bag ending at T4 and TIP_OK (tip T4, `ts` NOW minus 60) WHEN checked THEN `valid:true`. V: wit/valid-tip-ok, wit/tip-older-than-consumer-tip-ok
- S2: GIVEN a statement with tip T5 and a consumer bag ending at T4 WHEN checked THEN `behind_witness`. V: wit/behind-tip, wit/tip-junk, wit/tip-other-branch
- S3: GIVEN `now - ts == max_tip_age_s` THEN valid; one second more THEN `stale_witness`; GIVEN `ts == now + clock_skew_s + 1` THEN `witness_in_future`. V: wit/stale-tip, wit/future-tip. C: wit/tip-age-exactly-max-ok, wit/future-within-skew-ok
- S4: GIVEN a statement signed by bob's key with the relay kid in its header WHEN checked THEN `witness_bad_signature`. V: wit/wrong-key-signature, wit/statement-high-s
- S8: GIVEN a statement whose header kid is alice's, signed by alice WHEN checked THEN `witness_key_mismatch`. V: wit/wrong-key-kid
- S5: GIVEN a statement for another org, or for an epoch the consumer has not pinned WHEN checked THEN `witness_org_mismatch`, `witness_epoch_mismatch`. V: wit/wrong-org, wit/wrong-epoch-newer
- S6: GIVEN two witness defects WHEN checked THEN the earlier step's code. V: wit/ord-key-before-signature, wit/ord-signature-before-content, wit/ord-stale-before-behind, wit/ord-view-before-witness, wit/ord-time-before-witness, wit/ord-witness-before-duplicate
- S7: GIVEN WIT_ORG and TIP_OK WHEN `enrolled` runs THEN false, `fixture_profile` (steps 1 to 6 passed). V: wit/enr-relay-ok

### WT-06 Freshness, never validity

A tip statement can only add a refusal. No rule reads a statement to accept an act, to extend or choose the chain, to supply a key, to lift a fork, or to override any other step: VR-02 steps 1 to 13 and the fold run identically with and without it. A relay tip the consumer lacks is `behind_witness`, never a reason to adopt the relay's chain. Statements inside `acts` are ignored by the fold.

Why: a compromised relay key yields at most forged freshness, the same exposure as mode `none`, never a forged human act.

- S1: GIVEN TIP_OK valid and an approve signed by a key removed at T3 WHEN checked THEN `revoked_key`. V: wit/never-validates-revoked
- S3: GIVEN TIP_OK valid and an approve with a bad signature, or one by a key that is not accepted WHEN checked THEN `bad_signature`, `unproven_class`: the statement validates nothing. V: wit/never-validates-bad-sig, wit/never-validates-unproven
- S2: GIVEN the witness bag plus TIP_OK in `acts` WHEN folded THEN the output equals the output without it. V: wit/statement-in-bag-ignored

### WT-07 Fail closed, no fallback

In mode `relay` every WT-05 failure is a refusal. No code path evaluates mode `relay` with VR-12 alone. VR-12 still runs in mode `relay`: `synced_at` alone never suffices, and the witness never replaces the `head` rule. An unknown or missing mode is a fold error (WT-01), never read as `none`.

Why conjunctive: removing a check per mode would create a mode-dependent hole and a second rule set. Keeping VR-12 makes mode `relay` a strict superset of mode `none`, so turning the witness on can never weaken a consumer. The cost is that a consumer in mode `relay` still supplies a fresh `synced_at`.

- S1: GIVEN WIT_ORG, `tip_statement` null and a fresh `synced_at` WHEN checked THEN `witness_missing`. V: wit/mode-relay-no-statement
- S2: GIVEN WIT_ORG, TIP_OK and a `synced_at` older than `max_view_age_s` WHEN checked THEN `stale_view`: the witness does not replace the view check. V: wit/synced-at-still-checked

### WT-08 Changing the witness is a policy change

The `witness` value changes only through a genesis change (GP-19): a new document, authority by the previous policy's `rules["genesis.change"]` counting only keys clean at H, proof of possession by every listed device, and a re-pin (GP-12). This covers `none` to `relay`, `relay` to `none`, relay key rotation and any `max_tip_age_s` change. Until the re-pin, the old mode applies on that machine. No act, no flag and no consumer configuration switches the mode. Turning the witness on is a re-pin of one org, not a new profile hash.

The genesis render (RN-04) shows the witness as policy lines: `Witness: none`, or `Witness: relay`, `Relay key: <full kid>`, `Max tip age: <D> s`, so every signer of a change sees a relay key rotation or a downgrade.

Why: a downgrade to `none` needs the same quorum and clean keys as any other authority change; a removed key cannot help install or remove a witness.

- S1: GIVEN ORG (mode `none`) and a change to a relay policy signed by alice and bob at the epoch-0 tip WHEN folded with the new pin THEN the new epoch state has `witness.mode` `relay`. V: wit/change-none-to-relay-quorum, wit/change-relay-key-rotation-ok
- S2: GIVEN a none-to-relay or relay-to-none change signed by alice only, or by alice whose key was removed on the path to H WHEN folded THEN `genesis_change_unauthorized`. V: wit/change-none-to-relay-one-signer, wit/change-relay-to-none-one-signer, wit/change-none-to-relay-revoked-signer
- S3: GIVEN a signed none-to-relay change that is not yet pinned WHEN checked with `tip_statement` null THEN valid; GIVEN the pin at the change THEN `witness_missing`. V: wit/change-after-repin-needs-statement. C: wit/change-before-repin-old-mode
- S4: GIVEN `genesis.sign` over ORG and over the change WHEN rendered THEN `Witness: none`, and the relay lines. V: wit/render-genesis-witness-none, wit/render-genesis-witness-relay

### WT-09 No relay head kind

`head.kind` stays closed to `"chain"` (ACT-08). Relay freshness is verifier input (WT-03), not an act field, for four reasons:
1. Freshness is a property of the verifier's view at check time. A signer's `head` records what the signer saw when signing; it cannot attest that no removal arrived later.
2. If an act could carry either a chain or a relay head, the signer, or an agent writing the draft (the caller supplies `head`), would pick the freshness regime per act. The policy must be the only switch.
3. Acts stay byte-identical in every mode. Turning the witness on needs no re-signing, no signer change (signers stay fold-free and relay-free) and no act-body version.
4. Nothing is lost: the relay's `tip` is a chain position id, and `kind:"chain"` already references any position.

A future signed log head, whose inclusion proof travels inside the act, remains possible as a new kind under a new profile hash; that is a different mechanism from this witness.

- S1: GIVEN an approve with `head.kind` `"relay"` WHEN checked THEN `schema`. V: sch/head-kind-unknown, wit/head-kind-relay-schema

### WT-10 Superseded epochs

A tip statement attests freshness only for an epoch with no known successor.
- Body: `{"epoch":E,"next":N,"tip":X}`, keys sorted, closed. N is the string `"yes"` iff the relay's successor set of E is non-empty, else `"no"`. The successor set of E is every change document whose `prev` is hashstr(JCS(E's document)) and that is a valid link (GP-15, GP-19) against the acts the relay holds; sibling successors are all members. The statement names no successor, and nothing in it guides which one a person re-pins (GP-12 and RN-10 render the candidate's difference). The relay MUST serve superseded epochs with `"yes"`, so a consumer not yet re-pinned gets a precise refusal, not a timeout. A change's validity never changes (GP-19), so once `"yes"`, `next` stays `"yes"`. Every other value of `next` (absent, `null`, another string, or a JSON boolean, which already fails ACT-04) is `witness_malformed` (WT-05 step 2).
- Check, WT-05 step 6a, after step 6 and before the time checks, in mode `relay`, for `check-act` and `enrolled`: `witness_superseded` iff `body.next` is `"yes"`. The checker reads no other source; in particular it does not look for a successor in the consumer's bag.
- Window: a statement issued before the relay held the successor carries `"no"` and passes until its own `max_tip_age_s` expires. That is the statement's freshness bound, not an added grace period.
- Exit: a person re-pins (GP-12). From the moment the relay knows a successor, every non-chain act of the old epoch is refused until the re-pin. A consumer that refuses to re-pin stays refused (fail closed).
- Step 6 stays: a statement for a newer or foreign epoch is `witness_epoch_mismatch`. Mode `none` is unaffected.

Why: one grammar for every signed value; `next` is a string inside the canonical subset. No freshness is attested for an epoch whose relay holds a valid successor.

- S1: GIVEN a statement for epoch 0 with `next` `"yes"` WHEN checked THEN `witness_superseded`. V: wit/superseded-epoch-refused
- S2: GIVEN a fresh statement for epoch 0 with `next` `"no"` WHEN checked THEN valid, whatever the consumer's bag holds: the checker reads no other source (a change is a lineage document, never a member of the act bag). V: wit/next-no-latest-epoch-ok
- S3: GIVEN a superseded and stale statement WHEN checked THEN `witness_superseded` (step 6a precedes the age checks). V: wit/order-superseded-before-stale
- S4: GIVEN a statement body without `next`, or with JSON `false` or the string `"true"` as `next` WHEN checked THEN `witness_malformed`. V: wit/next-missing-malformed, wit/next-boolean-not-canonical-malformed, wit/next-other-string-malformed, wit/next-hashstr-malformed

## 14. Known limitations

These are the properties version 1 does not provide. Each is bounded as stated. Integrity, meaning which keys an organization trusts, holds under section 1.4; most items below concern availability or depend on a person's care.

Several of the availability items (L1, L2, L3) share one root: chain acts have no global order, so no tree rule can stop a rival branch from growing. A future ordering service for chain acts would remove that root; version 1 does not have one.

- **L1. A removed key still works at old nodes.** A key K whose removal is at node r stays valid at every node outside r's subtree (FO-05). An attacker who still holds K's key blob, for example from a lost or stolen device, can sign there.
  - With Q-1 tricked touches, K signs a valid chain primary at such a node. Each one forks a parent or stops a current resolve from being current (FO-24).
  - K plus Q-1 tricked touches can also sign an applicable resolve at an ancestor P of r whose examined paths stop above r. It is never current, but FO-25 condition (c) requires every resolve at P that chooses otherwise to name it with its evidence. Each such resolve freezes P until one resolve names it, and uses one of the 16 `overrides` entries; 17 or more of them at one P make that fork impossible to lift by a resolve, leaving a genesis change as the exit.
  - Such acts can add keys. K plus tricked touches can add, at such a node, a key the attacker holds for a second person: a `member.add` of a new role holder (its class is declared, L7), or a `device.add` for an existing person carrying that person's own consent touch. Each person the attacker controls on the branch lowers the touches needed for the next add by one. Once it controls Q_m persons there, Q_m being the smaller `persons` of the `device.remove` and `member.add` rules, it signs every further act on the branch with no touch. The total cost is Q_m(Q_m-1)/2 tricked touches per removed key held: one touch when Q_m = 2.
  - The branch can then remove every honest key on it and grow. No resolve at the branch point can be current, because the honest signers are removed on its examined paths and the branch can exceed 16 leaves. The fork freezes every consumer.
  - The branch also yields a valid genesis change at any H on it, signed only by persons the attacker controls (L4). It makes the relay set `next` to `"yes"` (L10). It applies only through a re-pin (L5).
  - Exit, which K cannot block: an honest genesis change with H at or below r on the honest branch, so that K is removed in `S_H` and neither counts nor can be carried (GP-19, GP-20), applied by a re-pin on every machine. A change with H above r has K active in `S_H`: K's signature counts toward it and the document can carry K, so it MUST NOT list K (the ceremony shows `Key removed in the previous epoch`, SG-12). The attack repeats only with a key removed in the new epoch.
  - Still true: K never counts in a current resolve that discards r's branch, or in a change whose H is at or below r, and K never adds, removes or revives a key on the branch it was removed on. The honest chain's keys stay untouched; what is lost is availability.
  - A verdict signed by K that names a head before r also passes `recheck-act`, because that command examines the key at the act's own head (VR-17, L9 (a)). `check-act` at a later tip refuses it as `revoked_key`.
- **L2. Stale artifacts completed by one touch.** One tricked touch can complete a stale artifact that holds Q-1 persons' counted signatures:
  - a stale chain primary whose parent is the tip with no other child applies. It adds or removes exactly the key those Q-1 persons signed for, however old their signatures are; chain primaries carry no expiry;
  - any other stale primary causes exactly one freeze (a fork at its parent, or a current resolve that stops being current), lifted by one new resolve that examines it;
  - a pending resolve that does not name, by an effective entry, every applicable resolve it must name is not current, and neither is any resolve it disagrees with that does not name it; the parent is a fork until one new resolve names it with evidence. Otherwise, if current, it takes effect (L3).
  - Bound: one freeze per completed stale proposal or pending resolve that cannot name what it must, each lifted by one resolve while Q persons can sign one and the `overrides` caps allow it; when none can (L1, FO-27), the exit is a genesis change. The count is bounded by the stale artifacts in existence, not by one per parent. Mitigations are human: the render, and review before endorsing.
- **L3. With Q = 2, one proposal plus one tricked touch is a quorum.** Under section 1.2, one person's signed proposal plus one tricked touch is a quorum for any chain act. That includes a resolve that overrides an applied choice, made by a person who saw the applied one and disagrees. With three role holders Q cannot be 3 (GP-02). Mitigations are human: the render, review before endorsing, and not endorsing resolves one did not request. No rule of this profile stops it.
- **L4. Backdated genesis changes.** Q persons whose keys are active and accepted at any node H of the previous epoch can sign a valid change at H, including persons whose keys were removed after H outside the path to H. The change can carry devices active in `S_H`, keys removed after H included. It still needs a `genesis.sign` from every listed device and applies only through a re-pin that renders `Head:` and the full difference (RN-10); the ceremony shows whether H is the current tip (SG-12). These renders are aids, not a guard (L5).
- **L5. A re-pin with an agent present can pin any valid successor.** The display is not a trust boundary (section 1.2). Whenever a person authorizes a re-pin while an agent is present in that session, the agent can replace the helper's input after the person approved what the ceremony showed, and the helper accepts every authorized lineage that contains the pinned document. Any valid successor of the pinned document can then be pinned, an attacker's sibling change included. Once that happened, the honest lineage is `pin_rollback` on that machine, irreversibly: only an administrator deleting the pin by hand recovers it (GP-21). Run the ceremony with no agent session (SG-12).
- **L6. Q persons can replace a person's keys.** Q persons can remove every key of a person (removal needs no consent, because a compromised key must be removable without its holder) and then add a device for the now device-less person (no consent exists). FO-22 forces the removal first and makes it visible on the chain; it does not prevent the replacement.
- **L7. Classes are declared, not attested.** A key's class is a label vouched by the genesis signers or by the Q persons who add the device, not attested by hardware. Signers who label a PIN-capable key `apple-se-bio` get it accepted, and KC-08 enforces declared classes only. A `biometric_or_pin` key lets a process that captures the PIN sign with no person present; KC-08 keeps such classes off role holders, so they never count toward Q. What remains: a member who is not a role holder and uses such a class signs verdicts and record promotions without a person present (bounded by L9), and that member's consent on a `device.add` is only as strong as the class. An organization avoids this by not listing the class.
- **L8. A resolve can make a key active again.** Q persons whose keys were active and accepted at an old parent P, and are removed on none of the branches they discard, can choose any child of P by a current resolve. A key removed only on a discarded branch is then active again, although FO-07 forbids re-adding a removed kid at the tip. Keys removed on the chosen branch stay removed. Forbidding this would require the chosen branch to repeat every removal of the discarded ones, which would let an attacker branch force honest keys out.
- **L9. Verdicts are one touch, and consumer storage is editable.** Verdicts, record promotions and decisions stay single-touch: one decision per touch. `seen` and ingestion records live in consumer storage that an agent running as the same user may edit (VR-09, VR-14). That is inside the profile's threat scope: the pin turns "rewrite one data file" into "modify code" (GP-10), and an ingestion record that says valid would be the one data file left. VR-14 therefore has the consumer keep the full JWS and run `recheck-act` (VR-17) on it at read time, so that "this stored act is a human decision" is recomputed from the signed bytes and the pinned fold, not read from the record. What that bounds, and what it does not:
  - (a) Bound by L1: a holder of a removed key can sign a verdict that names a head before the removal, and `recheck-act` accepts it, because the key is active at that head (FO-05). Producing it takes the device that holds the key blob and a touch with that device's enrolled biometrics, the same cost as any single verdict. The re-check stops an agent that edits storage; it does not remove L1.
  - (b) Without a trusted clock, stored data cannot show when an act arrived. An agent that can edit the consumer's storage can insert an act that is genuine, signed for exactly the request it binds, and expired or never ingested: an old verdict, or one that `check-act` would have refused at ingestion. `recheck-act` accepts it, because it reads no moment. Witness mode (section 13) helps only at ingestion: it lets `check-act` refuse an act made against a view the relay no longer vouches for, and it does nothing for a stored act that skipped ingestion. A consumer that records what ingestion saw (receipt id, tip id and the relay's statement) in root-owned append-only storage, outside the agent's user, can compare a stored act with that record, and an inserted act shows as one with no ingestion entry. That detects the insertion and does not prevent it, and it holds only as far as that storage is out of the agent's reach (L13).
  - (c) Epochs: a head is a position in its own epoch, and the lineage proves which, so a stored act of an earlier epoch re-checks after a genesis change and a re-pin, and L1 applies per epoch. A key removed by a later epoch does not change the answer for an act of an earlier epoch: that is the intended historic semantics, the same as a removal after the head within one epoch. The cost is that a removal in a later epoch never invalidates an earlier act, so an agent holding such a key can still sign for the earlier epoch's heads (L1, L4). Only the positions on the path to the change's head are proven: an act whose head lies on a branch the change did not continue from is `stale_view`, and so is an act whose consumer no longer holds the earlier epoch's acts.
  - A `rechecked:true` does not prove that the act was ever ingested, that it was fresh or unexpired, that it is the only verdict for its request (VR-09 is the consumer's), or that its key is not revoked at the tip. The answer lists these in `not_proven`.
- **L10. Freshness gaps.** In mode `none`, an actor controlling the act file and the consumer's sync timestamp can withhold a removal from that machine indefinitely (exploiting it also needs a compromised key); `synced_at` proves only that the consumer looked recently. Turn the witness on by a genesis change before a member who is not a maintainer joins, or before a second org exists. In mode `relay` the gap narrows to collusion between relay and agent, or a removal that never reached the relay; for an honest relay a withheld removal is visible after at most `max_tip_age_s`. A compromised relay key yields forged freshness only (WT-06); the recovery is a key rotation by genesis change (WT-08). Every valid successor of an epoch makes the relay set `next` to `"yes"`, so consumers in mode `relay` refuse every non-chain act of that epoch until a person re-pins; this includes backdated changes (L4) and changes from a rival branch (L1). That costs availability only: the pin moves only by a person (GP-12, GP-21). A consumer that already holds a successor in its bag accepts statements issued before the successor until their `max_tip_age_s` expires.
- **L11. The clock.** `now` is the verifier's clock. An agent that controls the clock defeats expiry and freshness. That requires administrator rights on the machine; the profile cannot detect it. `recheck-act` reads no clock, so L11 does not touch it, and what it cannot show about time is in L9 (b).
- **L12. Unreachable rules.** Every rule has one spare person (GP-02), so one person losing every device never makes a rule unreachable. Two persons doing so with Q = 2 of 3 does, and the exit is a new organization (FO-27). Recovery is out of scope.
- **L13. The pin's threat scope.** The pin defends against an agent writing files as the person's user. It does not defend against an agent that changes verifier code or its runtime: consumer repositories owned by the user on macOS, and on WSL2 distribution root and `/mnt/c` remounts. A WSL2 consumer receives the Windows-side gate's answer through a path WSL2 root can redirect (GP-17).
- **L14. Installation relies on a person.** SG-15 relies on the person comparing hashes on a second device.
- **L15. Capacity.** MAX_INPUT (16 MiB) bounds the checker's and the pin helper's input. Signer inputs need under 0.8 MB at the caps, but `fold` and `genesis-check` inputs grow with the bag: past about 761 acts of the largest size, or over 7,000 typical chain acts of about 2 KB, an organization can no longer fold or re-pin with these binaries.
- **L16. Windows.** The first release has no Windows class, so `win-hello-hw` cannot be listed (KC-02, KC-08). When the Windows release adds it and the evaluation reports `biometric_or_pin`, a Windows user cannot be a role holder through that class. Where the Windows prompt cannot carry line 1, that class shows no signer text in the OS prompt (RN-11).

## Appendix A. Retired requirement ids

Retired ids are never reused and never appear as live requirements.

| Retired id | Disposition | Replaced by | What went |
|---|---|---|---|
| KC-06 | retired | none | an `evidence` field on device entries; any class or schema change is a new profile hash anyway |
| GP-06 | superseded | GP-19 | a genesis change rule weighting revocations over the whole previous tree, with several heads per change |
| GP-08 | retired | none | a freshness basis registry; freshness is `synced_at` plus the witness (VR-12, section 13) |
| GP-16 | superseded | GP-20 | carry rules for `added_by`, introduction position and self-removal |
| FO-09 | superseded | FO-22 | a two-signer `device.add` with a same-person path |
| FO-10 | superseded | FO-22 | separate `member.add` counting |
| FO-11 | superseded | FO-22 | single-signature self-removal, target exclusion, seniority |
| FO-12 | deleted | none | cascade, taint, `added_by`, re-confirmation |
| FO-14 | superseded | FO-24 | merge, alias groups, built-upon, withdrawal, retroactive drops |
| FO-17 | superseded | FO-25 | a resolve condition tied to built-upon candidates |
| FO-18 | superseded | FO-26 | grade-weighted cleanliness over the whole tree, branch views |
| FO-19 | deleted | none | authority grades, path A and B, seniority |
| FO-20 | superseded | FO-24, FO-27 | grade-based finality and a liftability bound |
| VR-13 | retired | none | a `local_sync` basis; its meaning is the definition of `synced_at` in VR-12 |

## Appendix B. Example policy (not normative)

The conformance fixture ORG uses the policy below: three maintainers, two of whom must sign every trust change, so each rule keeps one spare person. Shown with whitespace for reading; the signed form is canonical (ACT-04).

```json
{
  "classes": [{"class": "apple-se-bio", "user_verification": "biometric_only"}],
  "freshness": {"clock_skew_s": "300", "max_validity_s": "604800", "max_view_age_s": "86400"},
  "roles": ["maintainer", "member"],
  "rules": {
    "chain.resolve": {"persons": "2", "roles": ["maintainer"]},
    "device.remove": {"persons": "2", "roles": ["maintainer"]},
    "genesis.change": {"persons": "2", "roles": ["maintainer"]},
    "member.add": {"persons": "2", "roles": ["maintainer"]}
  },
  "v": "handsal-policy/1",
  "witness": {"mode": "none"}
}
```

With these values, one removed key plus one tricked touch can freeze the organization until an honest genesis change and a re-pin on every machine (section 14, L1). Mode `none` is acceptable while every member is a maintainer and there is one organization; switch the witness on by a genesis change before that changes (L10).
