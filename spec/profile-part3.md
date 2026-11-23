# handsal profile, version 1, signer, reason codes and witness

## 10. Signer CLI

One contract, two implementations: Swift on macOS and Rust on Windows, run against the same vectors. On Windows the signer is a native `.exe` called from WSL2 through interop, with stdin and stdout as byte streams, UTF-8 without BOM, LF only and no newline translation; the authentication prompt appears on the Windows desktop. The signer does not fold: it checks bindings between bytes it holds, never chain state.

### SG-01 Command surface

`handsal-sign <command>`: `version`, `keygen`, `pubkey`, `emit`, `render`, `sign`, `agree`, and `pin-read` (Windows only, GP-11). Each reads at most one JSON object from stdin through the canonical subset recognizer (ACT-04), with MAX_INPUT in place of MAX_PAYLOAD as the bound on the stdin bytes; MAX_PAYLOAD still bounds the signed values inside, and MAX_DEPTH is unchanged. Every recognizer failure, a duplicate key and an oversize input included, is exit 2 `schema_refused`. One trailing LF of stdin is framing, not part of the object; the MAX_INPUT bound counts it. Each command writes exactly one JCS line to stdout: the JCS bytes then one LF. There is no `info`, `key-create`, `key-list`, `build`, `link-code` or `enroll` command. Any other command, no command, or more than one argument is `{"error":"unsupported_command"}`, exit 2 (SG-08). `emit` writes `{payload_hex}`, the lowercase hex of the emitted payload bytes (ACT-05). `agree` reads `{context, peer}` and writes `{key}` (SG-16). These commands are the whole surface of the shipped signer; the executable that runs the vectors is `handsal-sign-conformance` (CF-04).

The largest signer input, the `act.endorse` draft of a resolve at the ACT-09 caps with its 34 act attachments, is at most 766,326 bytes, so MAX_INPUT leaves a wide margin.

What an edition governs. A command that reads no document (`version`, `keygen`, `pubkey`, `agree`) behaves as the release that ships it says, whatever the edition of any organization on the machine: it has no document, no pin and so no edition to consult (GP-23). Where an earlier edition's text of such a command differs from this release's, the release's text rules for that command. The commands that read a document (`render`, `emit`, `sign`) apply the edition of the document they read (SG-17).

- S1: GIVEN a draft padded to MAX_INPUT + 1 bytes WHEN read THEN exit 2, `schema_refused`. V: sgn/signer-stdin-over-max-input-refused
- S2: GIVEN a command that is not listed WHEN run THEN exit 2, `unsupported_command`. T: signer/apple/Tests/HandsalCoreTests/CLITests.swift::unknownCommandsAreRefused, signer/apple/Tests/HandsalCoreTests/CLITests.swift::missingOrExtraArgumentsAreRefused

### SG-02 version

`version` returns `{class, impl, profiles, spec}`. `class` is the registry id of the key class the build produces (`apple-se-bio` on macOS), `impl` is `handsal-sign-swift` on macOS and `handsal-sign-rust` on Windows, `profiles` is the list of every production profile hash the signer implements, an array of hashstr in catalog order (oldest first), and `spec` is the current production profile hash (CF-01), the last member of `profiles` (GP-22). The shipped signer implements the production profiles only (GP-18). It reads no stdin, needs no key and shows no prompt. Key order is the canonical one: `class`, `impl`, `profiles`, `spec`. The signer recognizes every supported edition in the lineage (SG-12) and signs an original only under the current one (SG-17).

- S1: GIVEN `version` WHEN run THEN no authentication prompt. T: signer/apple/Tests/HandsalCoreTests/CLITests.swift::versionAnswersWithoutReadingStdinOrAKey, signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::versionShowsNoPrompt
- S2: GIVEN `version` WHEN run THEN `profiles` is a non-empty array of production hashes in catalog order and `spec` equals its last member. T: signer/apple/Tests/HandsalCoreTests/CLITests.swift::versionListsEverySupportedProductionProfileAndSpecIsTheLast, signer/windows/tests/cli.rs::version_lists_every_supported_production_profile_and_spec_is_the_last
- S3: GIVEN the signer and the checker built from one tree WHEN `profiles` is compared THEN it is the checker's production hashes. T: tools/tests/test_core_files.py::test_the_signer_version_lists_the_checker_production_hashes

### SG-03 keygen and pubkey

`keygen` input `{label, person}` creates a non-exportable hardware key of the build's class plus a separate key-agreement key, created without per-use presence (KC-09), binds `person` as the performer for every later signature, and returns `{agree:{x,y}, class, kid, sign:{x,y}}`. It refuses if `agree` equals `sign` (exit 5, `internal`) or if a key already exists for this configuration (exit 2, `key_exists`); it never overwrites. The private key never leaves the hardware. `pubkey` returns the same object with no prompt and shows nothing: it needs no display channel, so it answers from a process that has no terminal. `keygen` alone also writes `Key <kid12> for <person>, class <class>` to the display channel, never to stdout, as an aid for linking (SG-09); that line belongs to the moment a key is made and is not repeated by `pubkey`. Why: `pubkey` reads a public value, so it has no human decision to inform. A program that needs a device's public points, such as an agreement partner reading the `agree` point (SG-16), must get them without a person at a terminal.

Repositories hold key ids, never key material. The only file that holds private key material is the signer's key file, in the signer's own configuration directory and readable by its owner only (the key blob, never the private scalar in clear). Nothing else a handsal tool writes or prints carries it: `keygen`, `pubkey`, `render`, `sign` and `emit`, the linking tool, the ceremony and the pin helper produce kids, public coordinates, hashes, signatures and one-time codes. A repository that holds handsal files holds kids, and in a genesis document the public coordinates of a device (GP-01), nothing more. The pin has no member for a key (GP-05), so a pin cannot carry one. Each tool that writes or shows something has its own scan for the private scalar (S3, S5), and a signer for another platform carries the same scan in its own suite.

- S1: GIVEN a successful keygen WHEN the result is read THEN `kid` is the thumbprint of `sign`; a second keygen is `key_exists`. T: signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::keygenReturnsTheThumbprintAndADistinctAgreementKey, signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::aSecondKeygenNeverOverwrites
- S2: GIVEN `keygen` WHEN run THEN the kid12 line appears on the display channel and not on stdout. T: signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::keygenShowsTheKidLineOnTheDisplayOnly
- S3: GIVEN a signer with a known private scalar WHEN `keygen`, `pubkey`, `emit`, `render`, `sign` and `agree` run THEN neither stdout, the display channel nor a prompt carries the signing scalar, the agreement scalar or the shared secret `agree` computes, raw, in hex, in base64 or in base64url. T: signer/apple/Tests/HandsalCoreTests/KeyMaterialTests.swift::noOutputCarriesKeyMaterial, signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theAgreementScalarAndTheSecretAreInNoOutput, signer/windows/tests/agree.rs::the_answer_is_the_key_and_nothing_else_and_never_the_shared_secret
- S4: GIVEN a pin file with a member other than `genesis`, `org` and `spec` WHEN parsed THEN `pin_malformed`, so a pin has no place for a key. V: pin/unknown-key
- S5: GIVEN the linking tool, the ceremony and the pin helper WHEN each runs where a private scalar is known THEN nothing it prints, shows, hands to another tool or writes carries the scalar, in any form of S3. T: signer/apple/Tests/HandsalLinkTests/LinkTests.swift::noOutputCarriesKeyMaterial, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::noOutputCarriesKeyMaterial, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::noOutputCarriesKeyMaterial
- S6: GIVEN a bound key and `pubkey` WHEN run THEN the output is the object `keygen` returned (`{agree, class, kid, sign}`), no prompt is shown and nothing is written to the display channel. T: signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::pubkeyReturnsTheKeygenObjectWithoutAPrompt
- S7: GIVEN a bound key and no display channel (no controlling terminal) WHEN `pubkey` runs THEN exit 0 with the same object and nothing shown. T: signer/apple/Tests/HandsalCoreTests/KeygenTests.swift::pubkeyWithoutADisplayChannelGivesTheObjectAndShowsNothing. O: the owner, on hardware, from a process with no controlling terminal; and `keygen` still shows the line.

### SG-04 Draft input and caller powers

`sign`, `render` and `emit` take `draft` plus `attachments`. The draft is a closed object `{body, expires_in_s?, head?, method, org, parent?}`, and a verdict draft also carries `recipient`, `relay` and `request_id` (ACT-09 gives them to the act object of a verdict and to no other method). A decision draft carries its `consumer` inside `body` with `action` and `subject` (VR-18) and none of the three keys of a verdict. Each of `expires_in_s`, `head`, `parent`, `recipient`, `relay` and `request_id` is present exactly where its method has it and absent elsewhere; a key outside the set, a missing key or a malformed value is `schema_refused`, and a method outside the registry is `unsupported_method`.
- `parent = {id, performer}` is given for chain acts and endorsements and fills `parent_receipt_hash` and `parent_performer_id`.
- `expires_in_s` is a decimal string from "1" to MAX_EXPIRES_IN_S, present iff the method carries `expires` (verdicts and `decision`). "0" is refused, and so are a leading zero, a sign, a fraction and a JSON number: `expires` equal to `ts` is `bad_expiry` at every verifier (VR-11), and a signer MUST NOT sign what every verifier refuses. The policy maximum is checked by verifiers.
- `head` is exactly the ACT-08 object `{id, kind:"chain"}`, present exactly where ACT-08 gives the method one (for `genesis.sign`, iff `prev` of the attached document is non-null, SG-13). For a verdict or a `decision`, on a machine with a store the caller gets it from `handsal-check head` (VR-19) and copies it into the draft unchanged.
- `recipient`, `relay` and `request_id` go into the act object of the verdict. A verdict draft whose `recipient` is not the person bound to the signer's key at keygen is `identity_mismatch`, exit 2, the code VR-05 gives the same fact, and nothing is signed.

The signer builds the act, and the text it shows for it, itself: the caller supplies facts, never derived values and never words. The signer fills `performer_id` (bound at keygen), `kid` in the header and in the act object (ACT-14), `ts` from its own clock, `nonce` from 32 random bytes, `expires = ts + expires_in_s`, every pinned constant, and `inputs_hash` and `outputs_hash` from the attachments. A draft carrying `inputs_hash`, `outputs_hash`, `ts`, `nonce`, display text, prompt text or any authentication handle is refused (`schema_refused`). `emit` alone accepts `fixed = {kid, nonce, performer, ts}` and never signs. `emit` checks the forms of the four `fixed` values as `sign` fills them (ACT-07: `kid` a thumbprint of 43 base64url characters, `nonce` a canonical hashstr, `performer` a `member_id`, `ts` a `time`): a malformed value, a missing key or an extra key is `schema_refused`. The values are otherwise the caller's and harmless, since nothing is signed, and `emit` applies every rule above with `fixed.performer` as the person bound to the key, so it refuses what `sign` would refuse.

Why: the signer is the single owner of nonce and time, and `render` is the single owner of display text. The caller supplies facts, never derived values or words. `emit` is where vectors take the bytes of an act, so it must not write bytes for a value that no signer could produce, such as a nonce that is not a hashstr: a vector of such bytes would be an act that every verifier refuses (ACT-07). Identity has one owner, the key (SG-03): a verdict is addressed to one person (ACT-13), so a key answers only requests addressed to its own person, and the signer says so before the prompt instead of signing what VR-05 rejects.

- S1: GIVEN a draft with `ts` WHEN signed THEN exit 2, `schema_refused`. V: sgn/refuse-ts-input, sgn/refuse-nonce-input, sgn/refuse-display-text, sgn/refuse-auth-handle, sgn/refuse-schema-violation, sgn/parent-performer-required
- S2: GIVEN `expires_in_s` on a chain method, "0", or above 30 days WHEN signed THEN `schema_refused`. V: sgn/expires-in-s-refused-for-chain-method, sgn/expires-in-s-zero-refused, sgn/expires-over-30d
- S3: GIVEN an `emit` draft WHEN emitted THEN the act object carries the header kid. V: sgn/emit-act-kid-filled
- S7: GIVEN a draft whose method is not in the registry WHEN signed THEN exit 2, `unsupported_method`. V: sgn/refuse-unknown-method
- S4: GIVEN a verdict draft whose `recipient` is not the key's person WHEN signed or emitted THEN exit 2, `identity_mismatch`; GIVEN a verdict draft without `relay`, or a chain draft carrying `recipient`, THEN `schema_refused`. V: sgn/verdict-recipient-not-performer-refused, sgn/verdict-draft-missing-relay-refused, sgn/chain-draft-recipient-refused
- S5: GIVEN an `emit` input whose `fixed.nonce` is not a canonical hashstr WHEN emitted THEN exit 2, `schema_refused`. V: cli/build-bad-nonce
- S6: GIVEN a decision draft whose `action` is outside its grammar, or that carries `recipient` WHEN signed or emitted THEN exit 2, `schema_refused`. V: sgn/decision-action-grammar-refused, sgn/decision-draft-recipient-refused

### SG-05 Fresh authentication per signature

Every signature MUST require a fresh user verification from the key's class. A signer MUST NOT accept, cache or reuse an authentication context from a caller or from a previous signature; on macOS this means a new `LAContext` per call. Endorsements and resolves each prompt. The agreement key is not a signing key and has no such rule (KC-09).

- S1: GIVEN two sign calls in one process WHEN run THEN two prompts. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::twoSignsInOneProcessShowTwoPrompts

### SG-06 Signature form

The signature is ES256 over the ASCII bytes `b64url(header).b64url(payload)`. CryptoKit hashes internally; on Windows, CNG `NCryptSignHash` signs a digest, so the signer computes SHA-256 once itself. The signer returns raw 64-byte R||S, normalizes S to the low half, verifies its own signature with the public key before output, and re-runs the recognizer and schema checks on the emitted payload. Output `{jws, receipt_id}`.

- S1: GIVEN a platform signature with high S WHEN returned THEN S is replaced by n minus S; a failed self-verification, or a prehash computed twice, is exit 5, `internal`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aHighSSignatureIsReturnedLow, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aFailedSelfVerificationIsInternal, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aPrehashComputedTwiceIsInternal
- S2: GIVEN a successful `sign` by a key of a lineage WHEN its `jws` is given to `check-act` of the reference checker THEN `valid:true`, the `receipt_id` the signer returned, and the class of the signing key. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::theSuccessOutputPassesCheckAct

### SG-07 Display

Once it holds the prompt guard (SG-10), the signer writes the full render to its own display channel (`/dev/tty` on macOS, `CONOUT$` on Windows), then `Signing as <performer> with <kid12>`, and puts line 1 into the OS prompt (macOS `localizedReason`; on Windows where the API allows it). The render never goes to stdout. With no display channel the signer exits 4. No signer implements the Windows channel `CONOUT$` in this release; it is named here so that the first one that does has one meaning to meet. `pubkey` never uses the display channel, and neither does `agree` (SG-16). A refused render (`render_refused`, `attachment_missing`, `attachment_mismatch`) exits 2 with no prompt. The render and line 1 are aids (RN-11).

- S1: GIVEN a payload the renderer refuses WHEN signed THEN `render_refused`, no prompt; with no display channel, exit 4, `no_display`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aRefusedRenderShowsNoPrompt, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aMissingDisplayIsNoDisplay

### SG-08 Exit codes

Success is exit 0 with the result. Every failure writes `{"error":code}` and exits:
- 1 `user_cancel` (cancelled, or biometric verification failed);
- 2 input rejected: `schema_refused`, `render_refused`, `attachment_missing`, `attachment_mismatch`, `profile_not_current`, `unsupported_method`, `unsupported_command`, `identity_mismatch`, `key_exists` (keygen only);
- 3 `key_unavailable` (missing, invalidated by a biometric set change, or of the wrong class; missing means that no key is bound (`render` or `sign` before `keygen`));
- 4 `no_display`, `prompt_refused`, `biometric_unavailable` (the person cannot be asked: there is no display, the signer will not open a prompt now (SG-10), or the biometric sensor cannot verify now);
- 5 `internal`, including a failed self-verification.

There is no partial output and no signature without a fresh prompt.

When a command has more than one defect, the first of these decides and no later check runs:
1. the framing and the form of the draft, in this order: the closed top-level object of the command (for `emit`, `fixed` with exactly its four string members); the draft as a closed object whose `method`, `body` and `org` are present with their types (`schema_refused`); the method against the registry (`unsupported_method`); every form that depends on the method (`org`, `expires_in_s`, `head`, `parent`, `recipient`, `relay`, `request_id`, `body`: `schema_refused`); and, for `emit`, last, the forms of the four `fixed` values (`schema_refused`), so a draft with an unsupported method and a malformed `fixed` value is `unsupported_method`;
2. the person: a verdict whose `recipient` is not the key's person is `identity_mismatch`, decided before any attachment is read;
3. the attachments, in the order RN-09 gives (Order of checks), the first defect deciding: a missing one is `attachment_missing`; one the method cannot read (for `genesis.sign`, a document without `prev`, or a change whose `org` is not a string) is `attachment_mismatch`. Where the signer compares a value of the draft with an attachment, the comparison sits where that attachment is read. For `genesis.sign`: the `document`, then the `head` of the draft against `prev` of the document (`schema_refused`, a form defect), then the `org` of the draft against the document's (`attachment_mismatch`, SG-13), then `previous`, then `head.id`. An absent `document` is `attachment_missing` whatever the draft's `head` says, because whether a head is due is known only from the document. For `act.endorse`, the values derived from the attached act (`body.act`, `parent`, `head.id`) are compared when that act is read, before `candidates` and `heads` are asked for;
3a. for `sign` of a `genesis.sign` only: the attached document is an original whose `profile` is not the current production profile hash (`profile_not_current`, SG-17). `emit` and `render` read the same document and do not apply 3a: they sign nothing, and a renderer reads documents of every edition (RN-09). Only `sign` refuses;
4. the render (`render_refused`).

`agree` (SG-16) takes only the form of its input (step 1, `schema_refused`) and then the key (`key_unavailable`): it has no person, no attachment, no render, no display, no sensor check, no prompt guard and no prompt, so none of `identity_mismatch`, `attachment_missing`, `attachment_mismatch`, `render_refused`, `no_display`, `biometric_unavailable`, `prompt_refused` and `user_cancel` is one of its results. `pubkey` (SG-03) reads no input and no display: its only refusal is `key_unavailable`, and `no_display` is never its result.

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

The person compares the kid12 that `keygen` shows for the new device (SG-03) with line 1 of the `device.add` OS prompt on each signing device. That comparison is an aid. Linking security is FO-22.

- S1: GIVEN two `device.add` acts with the same code hash WHEN folded THEN only the first applies. V: lnk/reused-code, lnk/code-hash-format, lnk/ok

### SG-10 Rate and surprise

The signer SHOULD limit prompt frequency per process and MUST NOT run while another of its prompts is open. An unexpected prompt is a signal, never routine.

A prompt the signer refuses to open, because another of its prompts is open or because its rate limit is reached, is exit 4, `prompt_refused`: nothing is shown and nothing is signed. It is not `internal`, which says the signer itself is faulty, and not `user_cancel`, which says a person declined. A caller that gets `prompt_refused` can tell a signer that is busy or limited from a broken one.

- S1: GIVEN a prompt that is open WHEN a second `sign` is called THEN exit 4, `prompt_refused`, no second prompt and nothing shown. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aSecondSignWhileAPromptIsOpenIsRefused

### SG-11 Biometric set change

A key invalidated by a change of the enrolled biometrics is exit 3 `key_unavailable`. Recovery is a `device.add` signed from other devices. The ceremony MUST flag persons holding a single device. Only the signing key is invalidated: the agreement key needs no presence (KC-09), so `agree` keeps working after the change (SG-16).

- S1: GIVEN a key invalidated by a biometric change WHEN signing THEN exit 3, `key_unavailable`. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aKeyTheBiometricsInvalidatedIsKeyUnavailable

### SG-12 Enrollment ceremony

The ceremony is a procedure, not a signer command. It MUST:
1. collect the document and every listed device's `genesis.sign`, as one input line (GP-21 grammar: the canonical subset recognizer, MAX_INPUT, one LF, no argument) holding one object with exactly the keys `acts` (the bag of every epoch), `device_kid`, `lineage` (the `genesis-check` lineage, the candidate document last, each entry with the `genesis.sign` receipts of every listed device); `org` is not an input, it is the hash of the first lineage document (GP-04), and any other key is `malformed_input`;
2. refuse a document whose `profile` is a fixture profile, and any kid listed in the `fixture-kids.json` of the edition that document names (a device or the `relay_kid`); and refuse, with `profile_mismatch`, a lineage in which any document, last or earlier, names a hash that is not a production profile of the supported set. A lineage whose documents name different supported production editions, the last included, is accepted: the ceremony re-pins a migrated organization and an organization that never migrated alike;
3. run `genesis-check` and stop unless it returns `valid:true`;
4. refuse a policy without a spare person (GP-02 `policy_unreachable`), a role holder's device whose class is not biometric-only (KC-08), and a policy whose witness `mode` is `relay`, with `witness_missing`: this version has no path that gives the production `enrolled` a statement (WT-03), so a machine pinned under it would never be enrolled, and the pin is permanent;
5. show the render (RN-08 for an original, RN-10 for a change), including the witness lines, and flag persons holding a single device (SG-11);
6. for a change, run `genesis-aids` (CF-03) on the same `{acts, lineage}` and show from its answer one line about H in the previous epoch's accepted chain in the ceremony's bag: when the chain ends at tip T, `H is the tip` or `H is not the tip (tip <full T>)`; when it ends at fork parent P, `Previous epoch forked at <full P>;` followed by `H is P`, `H is below candidate <full c>` or `H is not below P`, where H counts as below a candidate when it is that candidate (the top of its branch), so `H is below candidate <full c>` also when H is c itself;
7. for a change, show from the same answer one line `Key removed in the previous epoch: <full kid>` per kid that the document carries, or whose key signed it, and that a valid `device.remove` in the ceremony's bag removes at any node of the previous epoch's act tree: the accepted chain, each branch of a fork and a branch that a `chain.resolve` discarded alike, and a fork inside a branch shows its lines too instead of stopping the ceremony; an answer that is a refusal, a reason code or `verifier_unavailable`, stops the ceremony with that code, since an aid that cannot be shown is not skipped;
8. show hash12 of the `genesis` in the exact pin line and ask the person to compare it with line 1 of the `genesis.sign` prompt they saw;
9. hand `{acts, lineage}` to the pin helper through GP-12 and GP-21;
10. run `sync` with `{acts, docs, org}` (CF-09), `docs` being the lineage of step 1, then run `enrolled` with `{device_kid, org}` (GP-13).

Steps 2 to 8 depend on the ceremony's input alone: everything the ceremony shows or checks before the pin write is a function of `{acts, lineage}`, and of the editions of the release for steps 2 and 4. The only checker commands it runs there are `genesis-check` and `genesis-aids`, which read no pin, no clock and no store (CF-08). It never runs a command that reads this machine (`fold`, `check-act`, `enrolled`, `head`, `sync`) before the write, so a machine with no pin for the organization sees the same lines as one that has it, and `sync` and `enrolled` run only after the write (step 10).

The pin write is the ceremony's last write to an administrator path and is never undone; `sync` writes only the user's store. On a failure after the write the ceremony reports the failure and leaves the pin, and so a failed `sync` after the write fails the ceremony and leaves the pin. Only a `sync` answer of `ok` lets the ceremony continue to `enrolled`; any other answer, `fork` and `epoch_superseded` included, fails the ceremony with that reason after the pin write, and the pin stays (the store holds the fork, and `enrolled` would refuse a forked view, so the ceremony fails one step earlier with the same outcome; `epoch_superseded` means the person pinned a document that already has a successor, and the remedy is a re-pin to it). The aids of steps 6 and 7 read the ceremony's bag, which is short after an early compaction of the closed epoch (CF-14). The lines of steps 6 to 8 are aids against the cases in section 14 (L4, L5), not boundaries. The ceremony SHOULD run in a terminal with no agent session, because its comparisons happen on a shared channel (RN-11).

The ceremony does not decide an edition's age: `profile_downgrade` comes from `genesis-check` (step 3). The ceremony never creates a document: it pins one that exists. The rule "an original names the current edition" is the signer's (SG-17), because a lineage of one document is the same input for a founding and for a second machine of an organization founded earlier, and the ceremony cannot tell them apart. A Rust ceremony does not exist yet; when one does, it MUST resolve profiles through the Rust edition table, and the guard test of GP-23 S3 records that.

- S1: GIVEN `enrolled` false after the pin write WHEN the ceremony finishes THEN it fails and the pin file is unchanged. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFailedEnrolledLeavesThePin
- S2: GIVEN a fixture kid, a fixture relay kid, a fixture profile, or a two-person organization WHEN the ceremony runs THEN it refuses before any write. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFixtureKidIsRefused, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFixtureProfileIsRefused, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aTwoPersonOrganizationIsRefused
- S3: GIVEN a change at a forked previous epoch, or one carrying a removed key WHEN the ceremony runs THEN it shows the head line and the removed-key line; and it shows the pin's hash12. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::theHeadLineAtAFork, signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::aRemovedKeyThatTheDocumentCarriesIsShown, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::thePinHash12IsShown
- S4: GIVEN `sync` refusing after the pin write WHEN the ceremony finishes THEN it fails with that reason and the pin file is unchanged. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFailedSyncAfterTheWriteLeavesThePin
- S5: GIVEN an input with `synced_at` or `tip_statement` WHEN the ceremony reads it THEN `malformed_input`; GIVEN a ceremony that wrote the pin THEN the checker is called `sync` and then `enrolled`. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::theInputIsAClosedObjectOfActsDeviceKidAndLineage, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::theCheckerIsCalledSyncThenEnrolledAfterThePinWrite
- S6: GIVEN `sync` answering `fork` after the pin write WHEN the ceremony finishes THEN it fails with `fork`, `enrolled` does not run and the pin file is unchanged. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aForkedSyncAfterTheWriteFailsWithForkAndLeavesThePin
- S7: GIVEN `sync` answering `epoch_superseded` after the pin write WHEN the ceremony finishes THEN it fails with `epoch_superseded` and the pin file is unchanged. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aSupersededSyncAfterTheWriteFailsWithThatReasonAndLeavesThePin
- S8: GIVEN a lineage of one P1 document and a lineage P1 then P2, both with every device's `genesis.sign` WHEN the ceremony runs on a release whose current edition is P2 THEN each is pinned. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aLineageOfTwoSupportedProductionEditionsIsPinned, signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aLineageStillOnAnOlderEditionIsPinned
- S9: GIVEN a lineage whose middle document names a hash of no catalog entry WHEN the ceremony runs THEN it refuses with `profile_mismatch` before any write. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aLineageNamingAnUnsupportedProfileInTheMiddleIsRefused
- S10: GIVEN a change that names an older edition than its previous document WHEN the ceremony runs THEN it refuses with `profile_downgrade` (from `genesis-check`) before any write. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aDowngradeIsRefusedBeforeAnyWrite
- S11: GIVEN a machine with no pin and no store for the organization, and a lineage of one document or a change WHEN the ceremony runs against the production checker THEN it shows the head line of the change and reaches step 8, and nothing before the write reads this machine. T: signer/apple/Tests/HandsalCeremonyTests/ProductionCheckerCeremonyTests.swift::anOriginalWithNoPinReachesTheQuestion, signer/apple/Tests/HandsalCeremonyTests/ProductionCheckerCeremonyTests.swift::aChangeWithNoPinShowsTheHeadLineAndReachesTheQuestion, checker/python/tests/test_builds.py::test_genesis_aids_reads_no_pin_no_store_and_no_clock
- S12: GIVEN a policy whose witness mode is `relay` WHEN the ceremony runs THEN `witness_missing` before any write. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aRelayWitnessPolicyIsRefusedBeforeAnyWrite
- S13: GIVEN a removal on a branch that a `chain.resolve` discarded, or a fork inside a branch of the previous epoch WHEN the ceremony runs THEN the removed-key line shows the removed kid and the head line shows the nested fork, and the ceremony goes on to step 8. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::aRemovalOnADiscardedBranchAndANestedForkAreShown
- S14: GIVEN a `genesis-aids` answer that is a refusal WHEN the ceremony reaches step 6 THEN it stops with that code before any write. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyChangeTests.swift::aRefusedAidStopsTheCeremonyWithItsReason

### SG-13 Signer derives and checks attachments

For `genesis.sign` the signer derives `org` from the attached `document`: hashstr(JCS(document)) for an original (`prev` null, GP-03), `document.org` for a change; a draft whose `org` differs is `attachment_mismatch` (SG-08 gives the order of the refusals). For `act.endorse` the signer MUST derive the expected `body.act`, `parent = {id, performer}` and `head.id` from the attached act (RN-09) and refuse a draft whose values differ (exit 2, `attachment_mismatch`); a missing attachment is `attachment_missing`. For `chain.resolve` the candidate and head acts are required attachments, checked per RN-09. For an endorsement of a resolve the signer requires and checks the nested `candidates` and `heads` attachments. Every refusal is exit 2 with no prompt.

Why: the caller supplies the attachment, never a second copy of facts derivable from it.

- S1: GIVEN an endorse draft whose head, parent id or parent performer differs from the attached act WHEN signed THEN exit 2, `attachment_mismatch`. T: signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theActIdMustBeTheAttachedActs, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theHeadMustBeTheAttachedActsParent, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theParentIdMustBeTheAttachedAct, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theParentPerformerMustBeTheAttachedActsPerformer
- S2: GIVEN an endorse draft without its attachment, or whose attachment is an approve, or a resolve draft without candidate attachments WHEN signed THEN exit 2, `attachment_missing` (`attachment_mismatch` for the approve). T: signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::anEndorsementNeedsItsAct, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::theAttachedActMustBeAChainAct, signer/apple/Tests/HandsalCoreTests/AttachmentSignTests.swift::aResolveNeedsItsCandidatesAndHeads
- S3: GIVEN a `genesis.sign` draft of an original whose `org` is not the hash of its attached document WHEN signed or emitted THEN exit 2, `attachment_mismatch`. V: sgn/genesis-org-not-document-hash-refused
- S4: GIVEN a decision draft without its `decision_b64` attachment WHEN signed or emitted THEN exit 2, `attachment_missing`: the signer derives `inputs_hash` from the attached bytes and signs nothing it cannot show. V: sgn/decision-attachment-missing-refused

### SG-14 Helpers by absolute path

Signer, checker, probe and ceremony locate every helper they execute only by an absolute administrator-owned path fixed per platform. There is no PATH lookup and no environment override outside a test constructor.
- macOS: `/Library/Application Support/handsal/bin/vitni-verify`, `/Library/Application Support/handsal/bin/handsal-pin` (the pin helper, a native binary), `/Library/Application Support/handsal/bin/handsal-sign` (the signer), `/Library/Application Support/handsal/bin/handsal-ceremony` and `/Library/Application Support/handsal/bin/handsal-link` (the ceremony and the linking tool, both native binaries), `/Library/Application Support/handsal/bin/handsal-check` (the launcher of the production checker, CF-08, in the form GP-17 allows), `/Library/Application Support/handsal/lib/handsal-check.pyz` (its zipapp), `/Library/Application Support/handsal/python/bin/python3` (the pinned interpreter, with its notices in `python/licenses/` beside it), and `/usr/bin/sudo`. The launcher runs the interpreter and the zipapp only by those two paths.
- Windows: `C:\Program Files\handsal\` holding `handsal-sign.exe`, `handsal-check` (in the form GP-17 allows: a native binary, or `lib\handsal-check.pyz` run by the interpreter under `python\` with its notices in `python\licenses\`), `vitni-verify.exe` and `handsal-pin.exe` (native).
- Linux (the server build, CF-10): `/opt/handsal/bin/vitni-verify`, `/opt/handsal/bin/handsal-check-server` (its launcher, in the form GP-17 allows), `/opt/handsal/lib/handsal-check-server.pyz` (its zipapp) and `/opt/handsal/python/bin/python3` (the pinned interpreter, its notices in `python/licenses/`). `/opt/handsal` and everything in it is root-owned, mode 0755, never writable by the service user, and the launcher runs the interpreter and the zipapp only by those two paths.
- WSL2: the Windows binaries through the drvfs path `/mnt/c/Program Files/handsal/...`, never PATH and never `\\wsl$`. On WSL2 this is not a boundary (GP-17).

A program that runs the signer runs it only by its fixed path: on macOS the path above, on Windows `C:\Program Files\handsal\handsal-sign.exe`, on WSL2 `/mnt/c/Program Files/handsal/handsal-sign.exe`. It never finds it through PATH and never runs a copy in a user-writable directory. The same holds for the ceremony and the linking tool, which a person runs and whose bytes the person trusts.

The ceremony runs the helper, and the helper runs the checker, only by these paths.

Why: an agent that can set environment variables or prepend to PATH cannot substitute the verifier, the pin reader, the pin helper or sudo.

- S1: GIVEN a fake `sudo` first on PATH WHEN the ceremony runs THEN `/usr/bin/sudo` is used. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::aFakeSudoOnPathIsNotUsed

### SG-15 Binary installation

Files at administrator paths (`vitni-verify`, both pin helpers, the checker launcher `bin/handsal-check`, `lib/handsal-check.pyz`, the interpreter under `python/` with its `python/licenses/`, `handsal-sign.exe`, and on macOS `handsal-sign`, `handsal-ceremony` and `handsal-link`) are installed only by a person-run procedure that, before the privileged copy, computes the SHA-256 of each artifact (the interpreter as the one pinned archive, its licence texts as a gzip tar packed from the pinned notices) and compares it with the value published for the tag, read on a second device. Any mismatch aborts. It needs only stock tools at its fixed PATH (checked before any privileged step) and unpacks in staging before creating anything at an administrator path, so a failure leaves them as they were. On macOS it removes `com.apple.quarantine` from every file and directory of the staged tree after the second hash check and before the move, never from the person's downloaded files, and an absent attribute is not an error: the published hash, read on a second device, is the control, and a binary that carries the attribute is refused at start by macOS though its bytes are the published ones. The installer creates `handsal`, `bin`, `lib` and `python` owned by root, mode 0755 on macOS (GP-10), and never `orgs` or `pin.lock`, which belong to the pin helper (GP-21). It never creates a store, which is the user's and is made by `sync` (CF-09). Artifacts built in a user-writable tree are never copied to an administrator path, and neither conformance executable is ever installed. The Linux server artifact set (`vitni-verify`, `bin/handsal-check-server`, `lib/handsal-check-server.pyz`, the interpreter and its `python/licenses/`) is published as a closed list per platform; an image build installs it as root under `/opt/handsal` by the same procedure, with each hash checked against values pinned from the published list, and any mismatch aborts before the first copy.

Why: an administrator path is only as trustworthy as the bytes copied into it.

- S1: GIVEN an artifact whose hash differs from the published value WHEN installing THEN the procedure aborts before the privileged copy. T: tools/install/test-install.sh::mismatch

### SG-16 agree

`agree` is the signer command for key agreement with the device's own agreement key, the key `keygen` created without per-use presence (KC-09). Its input is one closed object `{context, peer}`: `peer` is a public point `{x, y}` in the form of ACT-11 (two canonical base64url coordinates of 32 bytes, on P-256) and `context` is an `agree_context` (section 2.2). Anything else is `schema_refused`, exit 2. Its output is `{key}`, one member: `key` is the base64url of 32 bytes, 43 characters with no padding.

Derivation. The signer performs ECDH between its agreement key and `peer` and does not return the result. It returns the HKDF (RFC 5869) with SHA-256 whose input keying material is the 32-byte x coordinate of the shared point, with an empty salt (HashLen zero bytes, as RFC 5869 says), length 32 and

`info = "handsal-agree/1" || 0x00 || lo || hi || context`

where the label is those 15 ASCII bytes, `lo` and `hi` are the two public points of the agreement, the device's own `agree` point and `peer`, each as 65 bytes (`0x04 || x || y`) with the smaller in byte order first, and `context` is the input's bytes. Everything before `context` has a fixed length, so two different inputs never share an `info`. A peer equal to the device's own point is not special: the same rule gives its answer.

Why each part. The raw shared secret is a value a caller could use for anything, another protocol's key included, so it is never returned: the label and the two points confine the output to handsal's agreement domain, and a key another program derives from the same secret differs from this one unless it builds this `info`. The `context` is the caller's name for what the key is for, so two uses of one pair of keys never share a key (the idea of `consumer` in a decision, VR-18). The two points are put in order, not in the roles "own" and "peer", so that both parties of one agreement build the same `info`: a message sealed from one device's agreement key to another's is derived by either end with this command, and a party that is not a handsal signer (a sender with an ephemeral key) derives the same bytes with the same `info`. The known answers, from public fixture keys, are in `conformance/fixtures/agree-kat.json`; a pure Python derivation wrote them and the `cryptography` package recomputed them.

What the command does not do. The command needs no prompt, no display, no sensor check and no prompt guard (SG-07, SG-10): the agreement key needs no presence (KC-09), the command shows nothing and asks nothing, and a closed lid, a missing display channel or an open prompt elsewhere never stops it. The command never uses the signing key: it reads nothing of `sign`, and a change of the enrolled biometrics, which invalidates the signing key (SG-11), leaves the agreement key usable. The command never returns the raw shared secret, the agreement private key or a signature, and no function of a key backend returns the shared secret: the backend takes the peer and the `info`, does the agreement and the HKDF inside, and returns the 32 derived bytes.

Refusals, in the order of SG-08: the form of the input first (the closed object, then `context`, then `peer`: `schema_refused`, exit 2), then the key: no key bound, or a key of another class than the build's, is `key_unavailable`, exit 3. A failure of the platform's agreement that SG-08 does not name is `internal`, exit 5. No other code is a result of `agree`.

- S1: GIVEN the fixture agreement keys of X1 and X2 and the context `mail/v1` WHEN `agree` runs on either key with the other's point THEN `{"key":"B15Cebpl8FrRVUZq56kbnE4rihbIZepGsGbIA0BX-ak"}` from both sides; GIVEN the other vectors of the known-answer file THEN the key it lists. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theKnownAnswersAreDerivedFromFixtureKeys, signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theInfoLayoutIsTheOneTheSpecStates, signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theTwoSidesOfOnePairDeriveTheSameKey, signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::aDifferentContextOrPeerGivesAnotherKey, signer/windows/tests/agree.rs::the_known_answers_are_derived_from_fixture_keys, signer/windows/tests/agree.rs::the_info_layout_is_the_one_the_spec_states, signer/windows/tests/agree.rs::both_parties_of_one_pair_derive_the_same_key, conformance/vectors/_gen/tests/test_agree_kat.py::test_every_answer_is_the_one_cryptography_derives, conformance/vectors/_gen/tests/test_agree_kat.py::test_the_committed_file_equals_a_fresh_derivation
- S2: GIVEN an input that is not a closed `{context, peer}`, a `context` outside its form or a `peer` that is not a point on P-256 WHEN run THEN `schema_refused`, exit 2, and no agreement ran. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theInputIsAClosedObjectOfContextAndPeer, signer/windows/tests/agree.rs::the_input_is_a_closed_context_and_peer_and_anything_else_is_schema_refused, signer/windows/tests/agree.rs::the_context_form_is_the_signed_alphabet_without_space_1_to_128
- S3: GIVEN a bound key, a sensor that cannot verify now, no display channel and a prompt open elsewhere WHEN `agree` runs THEN `{key}` with no prompt and nothing shown. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::agreeShowsNoPromptAndNeedsNoDisplayOrSensor, signer/apple/Tests/HandsalCoreTests/SecureEnclaveTests.swift::theSecureEnclaveAgreementKeyWorksWithNoPresence
- S4: GIVEN no key bound, or a key of another class, and a well-formed input WHEN run THEN `key_unavailable`, exit 3; GIVEN no key and a malformed input THEN `schema_refused`. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::withoutAKeyItIsKeyUnavailableAfterTheForm, signer/windows/tests/agree.rs::the_form_is_decided_before_the_key_and_no_key_is_key_unavailable
- S5: GIVEN a signing key the platform will no longer use WHEN `agree` runs THEN the same key as before. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::aBiometricChangeLeavesTheAgreementKeyUsable
- S6: GIVEN any run of `agree` WHEN its output is scanned THEN it is `{key}` and holds neither scalar nor the shared secret, and no function of the backend port returns a shared secret and each key blob has one use. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theOutputIsOnlyTheDerivedKey, signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::noApiReturnsTheSharedSecret, signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::eachKeyBlobHasOneUse, signer/windows/tests/agree.rs::no_api_returns_the_shared_secret_only_derived_bytes_cross_the_port

### SG-17 An original is signed only under the current edition

The shipped signer's `sign` MUST refuse to sign a `genesis.sign` whose attached `document` is an original (`prev` null) whose `profile` is not the current production profile hash (the `spec` of `version`, SG-02): exit 2, `profile_not_current`, before any prompt. It reads the document it is given (SG-13) and nothing else, and applies the refusal after the attachments and before the render (SG-08, step 3a).

A change is not refused for its edition. A change may name its previous document's edition or any newer supported one. The signer does not compare the editions of a change: `profile_downgrade` is the fold's (GP-24), and a signed downgrade never reaches a pin, because `genesis-check` refuses it before the ceremony or the pin helper writes anything (SG-12, GP-21). A change that names a hash the signer does not implement is not refused by `sign` either (the renderer reads documents of every edition, RN-09); the ceremony and the fold refuse it. If a quorum signs such a change anyway, its own organization is locked out on every machine: each machine answers `epoch_superseded` (CF-09, foreign successor), which fails closed. That gives the quorum no power it lacks, since it can already sign a change that removes every device. `render` and `emit` do not refuse any document (SG-08). The conformance executable keeps the profile of the vector's document (CF-04), so vectors are not tied to the signer's current edition. The Rust core has no `sign` yet; when one exists it MUST apply this rule, and a future Rust `sign` MUST resolve profiles through the Rust edition table, as SG-12 says for the ceremony.

Why: founding is a moment, and only the signing release knows what "current" is, so the rule lives in the signer and never in the fold (GP-24). Refusing an original under an older edition steers every new organization onto the current rules, so a fix in a newer edition reaches new organizations by default and the set stops growing for no reason. A change must stay possible under the organization's own edition: an incident (a lost device, a key removed) is answered by a genesis change today, and forcing a migration into the same change would tie incident response to a fleet upgrade, which contradicts "migration is optional".

- S1: GIVEN a `genesis.sign` draft over an original whose `profile` is not the current production hash WHEN signed THEN exit 2, `profile_not_current`, no prompt. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aGenesisSignOverAnOriginalOfAnOlderEditionIsRefused
- S2: GIVEN a `genesis.sign` over an original that names the current edition WHEN signed THEN it is signed. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aGenesisSignOverAnOriginalOfTheCurrentEditionIsSigned
- S3: GIVEN a `genesis.sign` over a change that names the previous document's edition, older than the current one, WHEN signed THEN it is signed; GIVEN one that names a newer supported edition THEN it is signed. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aGenesisSignOverAChangeUnderThePreviousEditionIsSigned, signer/apple/Tests/HandsalCoreTests/SignTests.swift::aGenesisSignOverAChangeToANewerSupportedEditionIsSigned
- S4: GIVEN a `render` or an `emit` of a `genesis.sign` that names an older edition WHEN run THEN it is rendered or emitted, as before. T: signer/apple/Tests/HandsalCoreTests/RenderCoreTests.swift::aDocumentOfAnOlderEditionStillRenders
- S5: GIVEN a draft with a defect of step 1 and an original of an older edition WHEN signed THEN the step 1 code. T: signer/apple/Tests/HandsalCoreTests/SignTests.swift::aFormDefectIsDecidedBeforeTheProfile

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
| `pin_org_mismatch`, `pin_missing`, `pin_owner`, `pin_probe_unavailable`, `pin_probe_unprotected`, `pin_malformed`, `profile_mismatch`, `fixture_profile`, `genesis_pin_mismatch`, `pin_spec_mismatch`, `lineage_broken` | step 6, `enrolled` steps 1 to 3 and 7, `head` (VR-19), fold (GP-05, GP-10, GP-11, GP-13, GP-17, GP-18) |
| fold error codes (below) | step 6 (i), `enrolled` step 4, `head` (VR-19), `fold`, `genesis-check` |
| `org_mismatch` | step 7 (GP-04) |
| `relay_mismatch` | step 8 (VR-08) |
| `unknown_key`, `revoked_key`, `bad_signature`, `context_mismatch`, `verifier_unavailable`, `verifier_unexpected` | step 9 (VR-03, CF-05) |
| `high_s` | step 10 (VR-04); `admit` (CF-11) |
| `identity_mismatch` | step 11 (VR-05) |
| `request_mismatch`, `consumer_mismatch`, `inputs_mismatch`, `outputs_mismatch` | step 12 (VR-02, VR-06, VR-07, VR-18) |
| `ts_in_future`, `bad_expiry`, `validity_too_long`, `expired` | step 13 (VR-11) |
| `view_in_future`, `stale_view` | step 14 (VR-12), `enrolled` step 6, `head` (VR-19); `stale_view` also from `recheck-act` for a head that is no position of a chain the lineage proves (VR-17) |
| `epoch_superseded` | step 14 (VR-12), `enrolled` step 6, `head` (VR-19), `sync` (CF-09) |
| `witness_unexpected`, `witness_missing`, `witness_malformed`, `witness_key_mismatch`, `witness_bad_signature`, `witness_org_mismatch`, `witness_epoch_mismatch`, `witness_superseded`, `witness_in_future`, `stale_witness`, `behind_witness` | step 14 (WT-04, WT-05, WT-10), `enrolled` step 6, `head` (VR-19) |
| `duplicate_receipt` | step 15 (VR-09, VR-15) |
| `unproven_class` | step 16 (KC-04) |
| `store_missing`, `store_owner`, `store_malformed`, `store_unavailable` | step 6 (f), `enrolled` steps 1 to 3, `head` (VR-19), `sync` (CF-09) |
| `store_full` | `sync` (CF-09), `admit` (CF-11) |
| `parent_unknown`, `already_stored`, `act_not_valid`, `not_chain_act` | `admit` (CF-11) |
| `epoch_closed` | `admit` (CF-11) |
| `evidence_missing` | `admit` (CF-11) |
| `snapshot_incomplete` | `sync` (CF-09) |
| `kid_repeated` | `admit` (CF-11) |
| `not_in_pool` | `pool` (CF-12) |
| `ok` | success of `check-act`, `recheck-act` (`rechecked:true`), `enrolled`, `head`, `genesis-check`, `subset` and the pin helper |
| `local_key_unknown`, `local_key_not_active`, `local_class_not_accepted` | `enrolled` step 5 (GP-13) |
| `attachment_missing`, `attachment_mismatch`, `render_refused` | `render`, signer exit 2 (RN-02, RN-05, RN-09, RN-12) |
| `pin_invalid`, `pin_rollback`, `internal` | pin helper (GP-21) |
| `user_cancel` (1), `schema_refused`, `unsupported_method`, `unsupported_command`, `identity_mismatch`, `profile_not_current`, `key_exists` (2), `key_unavailable` (3), `no_display`, `prompt_refused`, `biometric_unavailable` (4), `internal` (5) | signer exit codes (SG-08) |

Fold error codes, in GP-15 order where they apply: `genesis_schema`, `doc_not_sorted`, `genesis_key_invalid`, `duplicate_key`, `profile_mismatch`, `fixture_profile`, `profile_downgrade`, `policy_invalid`, `policy_out_of_bounds`, `policy_unreachable`, `class_unknown`, `class_pending`, `class_test_only`, `class_policy_mismatch`, `role_key_class`, `fixture_key`, `lineage_broken`, `genesis_render_too_large`, `genesis_unsigned`, `genesis_head_unknown`, `genesis_change_unauthorized`, `genesis_device_revoked`, `genesis_device_changed`; then `genesis_pin_mismatch`, `fork`, `at_beyond_tip`, `verifier_unavailable`.

`profile_downgrade` is a fold error (GP-15 step 2, GP-24): it comes out of `fold`, `genesis-check` and `admit`, and is the `inner_reason` of the pin helper's `pin_invalid`. It is not a pin code, so VR-02 step 6 gains no letter: it comes out of the fold at (i). `profile_not_current` is a signer code of exit 2 (SG-17, SG-08), decided after the attachments (step 3) and before the render (step 4). The foreign-successor rule adds no code and moves no ordering vector: `sync` answers `epoch_superseded` (CF-09, VR-12).

Why two codes and not a reuse: `profile_mismatch` says "a well-formed profile hash the implementation does not implement" (GP-01, GP-15); a downgrade names a profile that is implemented, so reusing it would give one code two meanings, which VR-18 and the coverage rule (CF-07) refuse. `genesis_change_unauthorized` says the quorum was not met; a downgrade can have full quorum. The signer's refusal is a decision about what the signer creates, not about a form, a render or an attachment, so no existing exit 2 code is true.

Internal ignore reasons inside the fold (never output; the act is not on the chain): every FO rejection, `link_code_reused`.

Classes. Each code the checker returns has a class in one table outside the profile, `conformance/reason-classes.json`, and the one reader of that table is `classify(command, code)` (`tools/reason_classes.py`). The classes are `membership`, `freshness`, `validity`, `time`, `environment`, `input`, `admission`, `capacity` and `ok`. A row gives a code its class for every command, or for one command where the same code means another thing there; `evidence_missing` and `snapshot_incomplete` are `admission` for every command. The table is not a core file and moves neither hash. It is append-only across tags: a code that was published keeps its class, and a new code gets its row in the change that gives it its row here.

Retired codes, never reused: `genesis_signer_unknown` and `genesis_sig_mismatch` (signatures that do not count are ignored, GP-15), and `genesis_head_mismatch` (one H per document, GP-19).

## 12. Vector groups

| Group | Requirements |
|---|---|
| `ok`, `jws`, `jcs`, `sch`, `mth`, `bod`, `vrd`, `key` | ACT |
| `cls` | KC |
| `gen`, `pol`, `pin`, `chg`, `org`, `enr`, `fix` | GP, KC-07 |
| `fld`, `add`, `mem`, `rem`, `cas`, `rev`, `quo`, `end`, `frk`, `rsv`, `cln`, `lnk` | FO, SG-09 |
| `chk`, `ord`, `vtn`, `sig`, `idn`, `inp`, `rly`, `rep`, `tim`, `frs`, `ing`, `rck`, `dec`, `hed` | VR |
| `rnd` | RN |
| `cli`, `cf`, `adm`, `kpl`, `cmp` | CF |
| `sgn` | SG, GP-12, GP-21 |
| `wit` | WT |
| `prf` | GP-22 to GP-24, and the cross-edition cases of GP-05, GP-19, GP-20, VR-17, RN-09, CF-08 |

Groups name where a vector lives, not a limit on what it proves: many vectors cite requirements of several families.

## 13. Freshness witness

VR-12 freshness rests on `synced_at`, which is a claim of the user's own `sync` (CF-09). An actor controlling the user's store can withhold a removal indefinitely (section 14, L10). The witness adds an independent signed claim: "at time T, the latest position of epoch E of org O that the relay held was X". The consumer's view counts as fresh only if its own fold reaches X and T is recent. The relay attests freshness, never validity.

- The pinned genesis policy decides whether freshness is witnessed and by which key (WT-01); only a genesis change changes it (WT-08).
- The relay produces statement bytes; WT-02 fixes their format. The relay server itself is out of scope.
- The checker verifies statements once, at `check-act` step 14 and `enrolled` step 6 (WT-05).
- The fold and the VR rules decide act validity, never the statement (WT-06).
- A statement arrives through the store slot that `sync` writes (CF-09), a file an agent running as the user can reach. It is untrusted until authenticated by the pinned relay key, and even then it can only refuse.

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

In the conformance build `check-act` (VR-01) and `enrolled` (GP-13) take the required input key `tip_statement`: either `null` or a JWS compact string. A missing key, or a value of any other JSON type, is `{"error":"malformed_input"}`, checked with the other required inputs before folding. The statement is for the pinned epoch, the pin's `genesis`, so a machine not yet re-pinned after a change still gets a statement it can verify. The production build takes no `tip_statement` (an input carrying it is `malformed_input`): it reads the `witness` slot of the store (CF-09), which is `null` in this version. Mode `none` needs nothing from the consumer, and mode `relay` answers `witness_missing` for every non-chain act until the relay path is specified, and the ceremony refuses such a policy before the pin write (SG-12 step 4); how a statement reaches `sync` is part of that path. `fold` and `genesis-check` take no statement: they decide history, not freshness.

- S1: GIVEN a `check-act` input without the key `tip_statement` WHEN run THEN `{"error":"malformed_input"}`. V: wit/statement-key-absent, wit/statement-wrong-type
- S2: GIVEN the production build and a relay witness policy WHEN a non-chain act is checked THEN `witness_missing`, because the slot is null. T: checker/python/tests/test_builds.py::test_relay_mode_with_the_reserved_null_slot_is_witness_missing

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
  - Exit, which K cannot block: an honest genesis change with H at or below r on the honest branch, so that K is removed in `S_H` and neither counts nor can be carried (GP-19, GP-20), applied by a re-pin on every machine. A change with H above r has K active in `S_H`: K's signature counts toward it and the document can carry K, so it MUST NOT list K (the ceremony shows `Key removed in the previous epoch`, SG-12). The attack repeats only with a key removed in the new epoch. After a store compacts the epoch (CF-14), only the heads on the retained paths are publishable there, and the fork point is one: K is active there, so the document does not list it.
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
- **L7. Classes are declared, not attested.** A key's class is a label vouched by the genesis signers or by the Q persons who add the device, not attested by hardware. Signers who label a PIN-capable key `apple-se-bio` get it accepted, and KC-08 enforces declared classes only. A `biometric_or_pin` key lets a process that captures the PIN sign with no person present; KC-08 keeps such classes off role holders, so they never count toward Q. What remains: a member who is not a role holder and uses such a class signs non-chain acts without a person present (bounded by L9), and that member's consent on a `device.add` is only as strong as the class. An organization avoids this by not listing the class.
- **L8. A resolve can make a key active again.** Q persons whose keys were active and accepted at an old parent P, and are removed on none of the branches they discard, can choose any child of P by a current resolve. A key removed only on a discarded branch is then active again, although FO-07 forbids re-adding a removed kid at the tip. Keys removed on the chosen branch stay removed. Forbidding this would require the chosen branch to repeat every removal of the discarded ones, which would let an attacker branch force honest keys out.
- **L9. Verdicts are one touch, and consumer storage is editable.** Non-chain acts stay single-touch: one decision per touch. `seen` and ingestion records live in consumer storage that an agent running as the same user may edit (VR-09, VR-14). That is inside the profile's threat scope: the pin turns "rewrite one data file" into "modify code" (GP-10), and an ingestion record that says valid would be the one data file left. VR-14 therefore has the consumer keep the full JWS and run `recheck-act` (VR-17) on it at read time, so that "this stored act is a human decision" is recomputed from the signed bytes and the pinned fold, not read from the record. What that bounds, and what it does not:
  - (a) Bound by L1: a holder of a removed key can sign a verdict that names a head before the removal, and `recheck-act` accepts it, because the key is active at that head (FO-05). Producing it takes the device that holds the key blob and a touch with that device's enrolled biometrics, the same cost as any single verdict. The re-check stops an agent that edits storage; it does not remove L1.
  - (b) Without a trusted clock, stored data cannot show when an act arrived. An agent that can edit the consumer's storage can insert an act that is genuine, signed for exactly the request it binds, and expired or never ingested: an old verdict, or one that `check-act` would have refused at ingestion. `recheck-act` accepts it, because it reads no moment. Witness mode (section 13) helps only at ingestion: it lets `check-act` refuse an act made against a view the relay no longer vouches for, and it does nothing for a stored act that skipped ingestion. A consumer that records what ingestion saw (the receipt id and the `check-act` answer) in root-owned append-only storage, outside the agent's user, can compare a stored act with that record, and an inserted act shows as one with no ingestion entry. That detects the insertion and does not prevent it, and it holds only as far as that storage is out of the agent's reach (L13).
  - (c) Epochs: a head is a position in its own epoch, and the lineage proves which, so a stored act of an earlier epoch re-checks after a genesis change and a re-pin, and L1 applies per epoch. A key removed by a later epoch does not change the answer for an act of an earlier epoch: that is the intended historic semantics, the same as a removal after the head within one epoch. The cost is that a removal in a later epoch never invalidates an earlier act, so an agent holding such a key can still sign for the earlier epoch's heads (L1, L4). Only the positions on the path to the change's head are proven: an act whose head lies on a branch the change did not continue from is `stale_view`, and so is an act of an epoch whose acts the machine never synced. The store keeps the path of every earlier epoch (CF-14), so a stored act whose head is on it keeps its evidence on the machine that synced it. T: checker/python/tests/test_sync.py::test_a_closed_epoch_keeps_the_path_to_its_successor_and_drops_the_rest
  - A `rechecked:true` does not prove that the act was ever ingested, that it was fresh or unexpired, that it is the only verdict for its request (VR-09 is the consumer's), or that its key is not revoked at the tip. The answer lists these in `not_proven`.
- **L10. Freshness gaps.** The store is the user's (CF-09), so an agent running as the user can withhold acts from `sync`, delete the store, hold its lock or edit `synced_at`. `sync` itself cannot roll the store back past what its readers need (CF-14). In mode `none` that lets the agent withhold a removal from that machine indefinitely (exploiting it also needs a compromised key); `synced_at` proves only that something ran `sync` recently, with the acts it chose. Production mode `relay` refuses every non-chain act (`witness_missing`) until the relay path is specified, so do not switch an organization to relay mode before then (the ceremony refuses a relay-mode policy before the pin write, SG-12); once it exists, turn the witness on by a genesis change before a member who is not a maintainer joins, or before a second org exists. In mode `relay` the gap narrows to collusion between relay and agent, or a removal that never reached the relay; for an honest relay a withheld removal is visible after at most `max_tip_age_s`. A compromised relay key yields forged freshness only (WT-06); the recovery is a key rotation by genesis change (WT-08). Every valid successor of an epoch makes the relay set `next` to `"yes"`, so consumers in mode `relay` refuse every non-chain act of that epoch until a person re-pins; this includes backdated changes (L4) and changes from a rival branch (L1). That costs availability only: the pin moves only by a person (GP-12, GP-21). In mode `none` a machine whose store holds a valid successor of its pin refuses the same way (`epoch_superseded`, VR-12), until a person re-pins; a source that withholds a successor document withholds that refusal too (CF-13). With several sources (CF-13) a withholding source still advances `synced_at`, which says some source was consulted and not which: the union narrows withholding to the case where every source a machine reaches withholds.
- **L11. The clock.** `now` is the verifier's clock. An agent that controls the clock defeats expiry and freshness. That requires administrator rights on the machine; the profile cannot detect it. Editing `synced_at` in the store defeats freshness the same way and needs only the user's rights, not administrator rights (L10). `recheck-act` reads no clock, so L11 does not touch it, and what it cannot show about time is in L9 (b).
- **L12. Unreachable rules.** Every rule has one spare person (GP-02), so one person losing every device never makes a rule unreachable. Two persons doing so with Q = 2 of 3 does, at that node. A rule unreachable at a node becomes reachable again below it only through a `device.add` (governed by the rule `device.remove`) or a `member.add` that gives role holders active accepted keys, and stays unreachable on every path below once both the rule `device.remove` and the rule `member.add` are unreachable (FO-27). When `genesis.change` is unreachable at every node, the epoch cannot be changed and the exit is a new organization (FO-27). Recovery is out of scope.
- **L13. The pin's threat scope.** The pin defends against an agent writing files as the person's user. It does not defend against an agent that changes verifier code or its runtime: consumer repositories owned by the user on macOS, and on WSL2 distribution root and `/mnt/c` remounts. A WSL2 consumer receives the Windows-side gate's answer through a path WSL2 root can redirect (GP-17).
- **L14. Installation relies on a person.** SG-15 relies on the person comparing hashes on a second device.
- **L15. Capacity.** MAX_INPUT (16 MiB) bounds the checker's and the pin helper's input and the store (CF-09). Signer inputs need under 0.8 MB at the caps, but `fold` and `genesis-check` inputs grow with the bag: past about 761 acts of the largest size, or over 7,000 typical chain acts of about 2 KB, an organization can no longer fold or re-pin with these binaries, and a retained store over that bound is `store_full`: `sync` writes nothing. The server store is bounded below MAX_INPUT by ADMIT_RESERVE (CF-11), so acts stop being admitted 2 MiB before the bound and a genesis change always fits. Room comes back by dropping (CF-14): once a change closes an epoch, `compact` lists everything of it off the paths to the heads of its changes, and a machine drops the same in its own `sync`. Two limits remain.
  - The path floor: the paths from each epoch's root to the head of the change after it are never droppable, so the sum of those paths, about 7,000 typical acts in all, is what one lineage can hold before a new original genesis (GP-03).
  - A hostile sibling lineage: a successor document published by an attacker (L1, L4) opens an epoch that the shared store keeps whole, and its acts can fill the store. Compaction cannot drop them, because which successor counts is a person's re-pin (GP-12). The exit is a new original genesis; capacity per lineage is not part of this version.
- **L16. Windows.** The first release has no Windows class, so `win-hello-hw` cannot be listed (KC-02, KC-08). When the Windows release adds it and the evaluation reports `biometric_or_pin`, a Windows user cannot be a role holder through that class. Where the Windows prompt cannot carry line 1, that class shows no signer text in the OS prompt (RN-11). Every device carries an agreement key and `keygen` always makes both keys (KC-09), so a Windows class ships only together with agreement. The Windows evaluation also measures an agreement key made without Windows Hello gating (the spike's step on key agreement); if it reports that such a key cannot be made, the class stays out of the registry, as KC-02 keeps out a class whose evaluation is pending.
- **L17. The agreement key needs no touch.** Reading what was sealed to a device is not a human decision, so a device's `agree` key is created without per-use presence (KC-09, SG-16). Any process running as the user on that device can use the agreement key: it can run `agree` with any peer and context, so it can read that device's mail and send as the device. It can never act as the person: signing still needs a fresh presence on the signing key (SG-05), and `agree` signs nothing and returns no secret and no signature. What such a process gains is the device's confidentiality and its voice as a sender, not a verdict, an endorsement, a resolve or a key change. Bounds: the key is hardware bound and non-exportable, so a copied key file is of no use without the device; the output is a key under the handsal label, so it opens only what was sealed under it; removing the device by a chain act stops others from sealing to it and does not unread what it already received. Not bounded: with no prompt, no rate limit applies (SG-10 limits prompts, and `agree` has none), so such a process can ask for as many agreements as it likes. Windows: whether a TPM key without Hello gating can agree is unverified, and a Windows class is not listed until it can (L16).
- **L18. An automation host proves no human act.** A host with no administrator-written pin (a CI runner, a server, any Linux host other than WSL2) cannot prove that a person decided anything. There the production `check-act` and `recheck-act` answer a pin reason (`pin_missing` where the platform has a probe and no pin was written, GP-10; `pin_probe_unavailable` where it has none, GP-11, GP-17), and the conformance build answers from data its caller supplies (FO-02). A consumer that runs on such a host MUST report a human act as not proven, never as passed, and checks the proof on a machine that holds the pin. This profile defines no trust anchor for an automation host. The server build (CF-10) runs on automation hosts and answers admission and pool membership; it proves nothing about any person.

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
  "relays": ["r.example"],
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
