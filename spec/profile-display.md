# handsal profile, version 1, rendering

This file is one of the parts of the normative profile. It holds section 8 (rendering). `spec/profile.md` holds sections 0 to 6 (reading guide, scope, definitions, act profile, key classes, genesis and pin, fold), `spec/profile-checks.md` holds section 7 (verifier rules), `spec/profile-interfaces.md` holds section 9 (conformance and checker CLI) and `spec/profile-part3.md` holds sections 10 to 14 (signer CLI, reason codes, vector groups, freshness witness, known limitations) and the appendices. Section numbers and requirement ids are global to the profile: a reference such as "section 8" or `RN-01` names one place whichever file it is read in. The files are one text, hashed as core files (CF-01).

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

Line 1 is at most 80 bytes, is the OS prompt text (RN-11), and MUST carry the decision summary. A free field longer than 12 characters appears as its first 11 characters plus `~`. The free fields are `<class>`, `<person>`, `<member>`, `<role>`, `<request_id>`, the decision `<consumer>` and `<subject>`, and the genesis `<name>` (`org_name`, up to 24 characters, so it is cut like the others). `kid12`, `hash12` and decimal counts appear as is. Templates:
- `device.add`: `Add device <kid12> (<class>) to <person>`
- `device.remove`: `Remove device <kid12> of <person>`
- `member.add`: `Add device <kid12> as member <member> (<role>)`
- `chain.resolve`: `Resolve fork, keep: ` followed by line 1 of the chosen candidate cut to 59 bytes, plus `~` when cut
- `request.approve`: `APPROVE request <request_id> (<hash12(inputs_hash)>, <N> bytes)`; `request.reject`: `REJECT request ...`; `request.needs-info`: `NEEDS-INFO on request ...`, with the same tail
- `decision`: `<consumer>: <action> <subject> (<hash12(inputs_hash)>, <N> bytes)`. `<action>` is shown whole, never cut: its grammar bounds it at 24 characters (section 2.2), so a consumer and a subject cut to 12 characters each, the hash12 and a size of four digits (the content block bound is 2048 bytes, RN-05) give a line 1 of at most 80 bytes
- `genesis.sign` over an original: `Sign genesis of <name> (<hash12(doc)>): <M> members, <D> devices`
- `genesis.sign` over a change: `Change <name> (<hash12(doc)>): +<A>/-<R> dev, <C> mem, policy same|NEW`, where A and R are the devices added and removed, C counts member entries added, removed or with a changed role, and `NEW` means some policy byte differs
- `act.endorse`: `Endorse: ` followed by line 1 of the endorsed act cut to 70 bytes, plus `~` when cut

There is one vector per method at maximum field lengths proving the 80-byte bound.

- S1: GIVEN maximum-length fields WHEN rendered THEN line 1 is at most 80 bytes. V: rnd/prompt-line-max-length, rnd/prompt-line-max-device-remove, rnd/prompt-line-max-member-add, rnd/prompt-line-max-resolve, rnd/prompt-line-max-approve, rnd/prompt-line-max-reject, rnd/prompt-line-max-needs-info, rnd/prompt-line-max-decision, rnd/prompt-line-max-genesis-original, rnd/prompt-line-max-genesis-change, rnd/first-line-tilde, rnd/line1-endorse-bounded
- S2: GIVEN each method WHEN rendered THEN line 1 follows its template. V: rnd/decision, rnd/line1-approve-size, rnd/line1-device-add-class, rnd/line1-member-add-kid-first, rnd/line1-resolve-keeps-kid12, rnd/line1-genesis-change-summary
- S3: GIVEN a kid or a hashstr whose twelve shown characters hold `-`, at the edge of a group or inside one, WHEN rendered THEN the short form is three groups of four joined by one space and each `-` stays in its group (`pbubEyWn-20K` shows as `pbub EyWn -20K`). V: rnd/decision-hash12-dash, rnd/resolve-max-caps-fits. T: checker/python/tests/test_render.py::test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four, conformance/vectors/_gen/tests/test_render.py::test_a_dash_at_any_place_of_the_twelve_leaves_three_groups_of_four, signer/apple/Tests/HandsalCoreTests/RenderCoreTests.swift::aDashOfTheAlphabetIsNeverTakenForTheSeparator, signer/windows/tests/draft.rs::a_dash_of_the_alphabet_is_never_taken_for_the_group_separator

### RN-04 Method lines

Every signed value a person decides on is rendered: one line per field, in ACT-09 order, values verbatim. A field line is the field name, a colon, one space and the value (`Person: alice`). A list is a header line, the name and a colon with nothing after it, followed by one indented line per entry. `hash12` and the thumbprint of a key are defined in section 2.1. The lines, in order:
- `device.add`: `Person: <person>`, `New device: <full kid>`, `Agree key: <thumbprint of agree>`, `Class: <class>` (on its own line, so endorsers vouch for it), `Label: <label>`, `Link code: <hash12(link_code_hash)>`.
- `device.remove`: `Person: <person>`, `Remove device: <full kid>`.
- `member.add`: `Member: <member>`, `Role: <role>`, `New device: <full kid>`, `Agree key: <thumbprint of agree>`, `Class: <class>`, `Label: <label>`.
- `chain.resolve`: `Fork parent: <full id>`, `Choose: <full id>`; `Candidates:` and one line per candidate in `candidates` order, `  > <hash12> <line 1>` for the chosen one and `    <hash12> <line 1>` for the others; `Heads:` and one line per head in `heads` order, `  - <hash12> <line 1 of the attached head act>`; then `Overrides: none`, or `Overrides:` and one line per entry in entry order, `  - <hash12 of resolve> (endorsements: <E>)`, E the decimal count.
- `request.*`: `Request: <request_id>`, `Recipient: <recipient>`, `Relay: <relay>`, `Request hash: <hash12(inputs_hash)>`, then the request block (RN-05).
- `decision`: `Consumer: <consumer>`, `Action: <action>`, `Subject: <subject>`, `Decision hash: <hash12(inputs_hash)>`, then the decision block (RN-12). A decision has no `Sender` line: it names no sender and no recipient.
- `genesis.sign` over an original: `Org name: <name>`, `Profile: <full profile hash>`, `Members:` and per member `  - <id> <role>`, `Devices:` and per device four lines, `  - <full kid> of <person>`, `    Class: <class>`, `    Label: <label>`, `    Agree: <thumbprint of agree>`, then the policy lines (below), then `Document hash: <hash12 of the document hash>`. Members and devices are in document order, which is sorted (GP-01). A change renders as a difference (RN-10).
- `act.endorse`: `Endorsed act: <full receipt id>`, then the endorsed act's method lines. For an endorsed resolve these run from its first method line through its last `Overrides` line, never the resolve's line 1, `Method`, `Org`, `Signer`, `Signed at` or `Parent`, so the endorser sees the same method lines as the resolve's signer.

The policy lines are the same in an original and in a change: `Policy:`, `  Roles: <roles joined by ",">` in document order, one line per rule in ascending order of rule name, `  Rule <name>: <persons> of <roles joined by ",">`, one line per entry of `classes` in document order, `  Class <class>: <user_verification>`, `  Clock skew: <clock_skew_s> s`, `  Max validity: <max_validity_s> s`, `  Max view age: <max_view_age_s> s`, `  Relays: none` or `  Relays: <hosts joined by ",">` in document order, and the witness: `  Witness: none`, or `  Witness: relay`, `  Relay key: <full relay_kid>`, `  Max tip age: <max_tip_age_s> s` (WT-08).

Entries inside a change section keep document order (RN-10): the added members, the changed roles and the added devices in the order of the new document, the removed members and devices in the order of the previous one. Both documents are sorted (GP-01), so members run by `id` and devices by `kid`.

Not rendered: the envelope constants (fixed by ACT-01) and `nonce` (signer-chosen randomness with no decision value).

At the ACT-09 caps a resolve renders at most 60 lines (line 1, 3 header lines, 54 method lines, `Signed at`, `Parent`), each under 100 bytes, inside the 72-line limit. Its endorsement is exactly 62 lines (line 1, `Method`, `Org`, `Signer`, `Endorsed act`, the 54 method lines, `Signed at`, `Parent`, `Head`). The longest `Overrides` entry line is 37 bytes.

- S1: GIVEN a genesis change WHEN rendered THEN policy changes are visible as lines. V: rnd/genesis-policy-lines, rnd/genesis-class-own-line, wit/render-genesis-witness-relay
- S2: GIVEN a resolve and its endorsement at the caps WHEN rendered by the checker and by each signer THEN the exact anchored text. V: rnd/resolve-max-caps-fits, rnd/endorse-resolve-max-caps-fits
- S3: GIVEN a resolve with one override entry of one endorsement WHEN rendered THEN the line `  - <hash12> (endorsements: 1)`. V: rnd/resolve-override-entry-line, rnd/resolve-override-entry-line-one
- S4: GIVEN a `device.add` and a genesis document WHEN rendered THEN the agree key and the full profile hash appear. V: rnd/device-add-agree-key-id, rnd/genesis-agree-key-id, rnd/genesis-profile-full, rnd/endorse-shows-endorsed-id, rnd/resolve-candidates-listed, rnd/resolve-heads-attached
- S5: GIVEN a policy whose `relays` is `["r.example"]` WHEN an original is rendered THEN the line `  Relays: r.example` follows `  Max view age`. V: rnd/genesis-relays-line

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
| `decision` | `decision_b64` | hashstr(bytes) = `inputs_hash` |
| `genesis.sign` | `document` | hashstr(JCS(document)) = `inputs_hash` |
| `genesis.sign` over a change | `previous` | hashstr(JCS(previous)) = `document.prev` |
| `genesis.sign` over a change | `document` | `head.id` of the payload = `document.head` |
| `act.endorse` | `act` (JWS) | its receipt id = `body.act` = `parent_receipt_hash`; its `performer_id` = `parent_performer_id`; its `parent_receipt_hash` = `head.id`; it is a chain primary or a resolve |
| `act.endorse` of a resolve | `candidates`, `heads` (JWS lists) | bound against the attached resolve exactly as for the resolve itself (next rows) |
| `chain.resolve` | `candidates` (JWS list) | one JWS per id of `body.candidates`; each has `parent_receipt_hash` = the resolve's parent |
| `chain.resolve` | `heads` (JWS list) | one JWS per id of `body.heads`; each is a chain primary |

Every attachment that is an act MUST pass ACT-01 to ACT-14. An attachment that is a genesis document (`document`, `previous`) MUST be valid by itself: GP-15 steps 1 and 3 over the document alone, under the registry and bounds of the profile the document names (structure, then policy and devices; the profile and lineage steps belong to the fold). A document that names a profile outside the catalog has no registry of its own: for this check only it is read under the current edition's, as when there was one edition, and it is not refused for its profile (step 2 belongs to the fold). `fixture_key` follows the profile the document itself names: a document naming the production profile that lists a fixture kid is not valid alone, and one naming the fixture profile is not refused for it. One that binds by hash but is not a valid document is `attachment_mismatch`, the same code as an act attachment that fails ACT-01 to ACT-14. A JWS list bound to a body list holds exactly one JWS per receipt id of that list and nothing else, in any order: a duplicate copy, an extra JWS or a missing id is `attachment_mismatch`. An `act.endorse` of a chain primary that carries `candidates` or `heads` is `attachment_mismatch`. A name that is absent from `attachments` is `attachment_missing`. Every other defect of an attachment is `attachment_mismatch`: a list that is present but is not an array, a value of the wrong type (`request_b64` and `decision_b64` excepted, CF-03), a list that lacks an id, or an attachment that does not bind. Whether a head lies in a losing subtree is decided by the fold (FO-25), not by the renderer. A signer MUST NOT sign what its renderer refuses.

Order of checks. A renderer decides in this order and the first defect wins: the envelope and the method; for `genesis.sign` the `document` (absent, not bound, or not valid alone), because it fixes whether a head is due; the form of the act object and body, including the presence of the `head`; then the other attachments in the order of the table above, each read and bound completely (present, of the right type, bound) before the next is looked at. An `act.endorse` is decided on `act` first, and only an attached resolve then asks for `candidates` and then `heads`: an endorse whose attached act does not bind is `attachment_mismatch` whether or not `heads` is there, and so is a `chain.resolve` whose `candidates` do not bind, whether or not `heads` is there. For `genesis.sign`, `previous` is read after the head presence is checked, then `head.id` against `document.head`. The signer's own comparisons of a draft with an attachment (SG-08, SG-13) take their places in this order and add none of their own.

Why: the words a person sees are a function of signed bytes only; an attachment is never a second, unbound source.

- S1: GIVEN an endorse draft whose attachment is another act WHEN signed THEN exit 2, `attachment_mismatch`, no prompt (a signer implementation test, CF-07). V: rnd/endorse-attachment-mismatch
- S2: GIVEN an endorsement draft of a resolve without `heads`, or with a candidate act outside the resolve's candidates, or a head act whose act `kid` differs from its header kid WHEN rendered THEN `attachment_missing`, `attachment_mismatch`, `attachment_mismatch`. V: rnd/endorse-attachment-missing, rnd/endorse-resolve-heads-missing, rnd/endorse-resolve-candidate-mismatch, rnd/attachment-act-kid-differs, rnd/endorse-primary-extra-attachment. C: rnd/endorse-resolve-nested-attached
- S7: GIVEN an endorsement of a resolve whose attached act does not bind to `body.act` and that carries no `heads`, or a resolve whose `candidates` do not bind and that carries no `heads` WHEN rendered THEN `attachment_mismatch`; GIVEN a change `genesis.sign` with no `head` and no `previous` attachment THEN `schema`. V: rnd/endorse-resolve-act-mismatch-before-heads-missing, rnd/resolve-candidates-mismatch-before-heads-missing, rnd/genesis-head-missing-before-previous-missing
- S3: GIVEN a request, decision, document or candidate attachment that does not bind WHEN rendered THEN `attachment_mismatch` or `attachment_missing`. V: rnd/request-attachment-mismatch, rnd/decision-attachment-mismatch, rnd/decision-attachment-missing, rnd/genesis-attachment-hash-mismatch, rnd/genesis-change-previous-mismatch, rnd/resolve-candidate-wrong-parent, rnd/resolve-candidate-missing, rnd/resolve-head-attachment-missing
- S4: GIVEN a change whose `head.id` differs from `document.head` WHEN rendered THEN `attachment_mismatch`. V: rnd/genesis-head-mismatch
- S5: GIVEN a `document` or a `previous` that binds by hash and is not a valid document WHEN rendered THEN `attachment_mismatch`. V: rnd/genesis-document-invalid-bound, rnd/genesis-previous-invalid-bound
- S6: GIVEN an `act.endorse` whose `act` attachment is a number WHEN rendered THEN `attachment_mismatch`. V: rnd/attachment-wrong-type-mismatch
- S8: GIVEN a change `genesis.sign` whose `previous` names P1 and whose `document` names P2 WHEN rendered THEN each is valid alone under its own edition's registry, and the render is the text of RN-10. V: prf/render-change-across-editions

### RN-10 Genesis change rendering and the size bound

A change renders as a difference from the previous document (attachment `previous`, RN-09). Its method lines, in order: `Org name: <name>`, `Profile: <full profile hash>` (the two lines an original opens with, so a rename or a profile change is never hidden), `Previous: <hash12(prev)>`, `Head: <full H>`, then these sections, each written only when it has an entry: `Members added:` and `Members removed:` (per member `  - <id> <role>`), `Role changed:` (`  - <id> <old role> -> <new role>`), `Devices added:` (the four device lines of RN-04 per device), `Devices removed:` (per device `  - <full kid> of <person>`); then the policy lines of RN-04 in full, and last `Unchanged: <D> devices, <M> members`, D the devices in both documents and M the members in both documents with the same role. A change has no `Document hash` line: hash12 of the document is in line 1 (RN-03). `Head` also appears as hash12 in the RN-02 frame; both come from `head.id`, which equals `document.head` (RN-09). Carried devices are byte-identical (GP-20), so there is no "devices changed" section. An original renders in full (RN-08).

Fold bound: a genesis document whose `genesis.sign` render exceeds 72 lines is `genesis_render_too_large` (GP-15 step 5). The fold computes it with the same render function, which is the single owner of "fits". The count does not depend on the signer: `Org`, `Signer`, `Signed at` and `Head` are one line each whoever signs, so the fold counts the render with any performer id, kid and time.

Why: every valid genesis document is signable by every listed device. An organization grows through chain acts, and each change shows only what changes, so the 72-line cap does not block growth. A difference with a fold bound is preferred over paging, which would split one decision across screens of an untrusted channel.

- S1: GIVEN a change WHEN rendered THEN the difference, the head line and the full policy appear. V: rnd/genesis-change-diff, rnd/genesis-change-head-line, rnd/genesis-sign-change
- S2: GIVEN a change that renames the organization WHEN rendered THEN `Org name` and `Profile` open the method lines. V: rnd/genesis-change-org-name-profile-lines
- S3: GIVEN a change that adds a relay host WHEN rendered THEN the full policy shows the new `Relays` line. V: rnd/genesis-change-relays-diff

### RN-11 The display is not a trust boundary

The signer's display channel (`/dev/tty`, `CONOUT$`) and the OS prompt text are both reachable by same-user processes (section 1.2). The full render and line 1 are aids. The signer MUST still put line 1 into the OS prompt; where a platform prompt cannot carry it, that is stated for that class. Chain security comes from FO-22. A tricked touch on a non-chain act signs one decision whose request, or consumer, action and subject, hash12 and size are in line 1; a consumer that needs more requires decisions from more than one recipient, which is consumer policy outside this profile. The ceremony's hash12 comparison is an aid (SG-12).

- S1: GIVEN a verdict draft WHEN the signer asks the platform to confirm THEN the prompt text is line 1 of the render, the `first_line` that `render` returns for the same draft. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::theDisplayShowsTheRenderBeforeThePrompt

### RN-12 Decision block

`decision` renders its attached content exactly like a request block (RN-05 escaping, prefixes and limits), delimited by `----- decision (<N> bytes, sha256 <hash12>) -----` and `----- end -----`, from the bound attachment `decision_b64` (RN-09). Over the limits it is `render_refused`, so a signer never signs content the person could not see. A content of zero bytes has no content line and line 1 says `0 bytes`: the decision is then about its `subject` alone, and the person sees that.

- S1: GIVEN a decision WHEN rendered THEN the decision block appears, line 1 carries the consumer, the action whole, the subject, the hash12 and the size, and nothing is truncated. V: rnd/decision, rnd/decision-block-hostile, rnd/decision-empty
- S2: GIVEN a decision content over 2048 bytes or over 32 block lines WHEN rendered THEN `render_refused`; GIVEN exactly 2048 bytes in 32 lines THEN rendered. V: rnd/decision-over-2048-refused, rnd/decision-33-lines-refused. C: rnd/decision-exactly-2048-ok
- S3: GIVEN a decision payload whose `action` is outside its grammar WHEN rendered THEN `body_schema`. V: rnd/decision-action-grammar-refused
