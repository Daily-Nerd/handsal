# handsal profile, version 1, verifier rules

This file holds section 7 of the normative profile (verifier rules). `spec/profile.md` holds sections 0 to 6 (reading guide, scope, definitions, act profile, key classes, genesis and pin, fold), `spec/profile-display.md` holds section 8, `spec/profile-interfaces.md` holds section 9 and `spec/profile-part3.md` holds sections 10 to 14 and the appendices. Section numbers and requirement ids are global to the profile: a reference such as "section 7" or `VR-02` names one place whichever file it is read in. The files are one text, hashed as core files (CF-01).

## 7. Verifier rules

`check-act` evaluates one non-chain act (section 2.1) for a consumer. It folds the evidence it is given and never accepts a state from the caller. `recheck-act` (VR-17) answers the time-free half of the same question for an act the consumer stored.

### VR-01 check-act input and output

Input (conformance build): `{acts, action, consumer, decision_b64, expect_method, jws, lineage, next, now, org, pin, recipient, request_b64, request_id, seen, subject, synced_at, tip_statement}`, where:
- `pin` is the probe object (GP-14); `lineage` and `acts` are as in GP-07; `org` is the org id the consumer expects (hashstr);
- `now` and `synced_at` are `time`; `seen` is a list of receipt ids (VR-15);
- `tip_statement` is null or a relay tip statement JWS (WT-03);
- `next` is `"yes"` or `"no"`: whether the store holds a valid successor of the pinned document (VR-12). It is store content, like `synced_at`;
- for verdicts, `request_b64`, `request_id` and `recipient` are required: the request bytes and the values the consumer expects. A verdict's `relay` is read against the policy, not an input: an input carrying `relay` is `malformed_input` in both builds (VR-08);
- for `decision`, `action`, `consumer`, `decision_b64` and `subject` are required: the words the consumer asked for (an `action` and a `subject_id`), the consumer the verifier is (a `consumer_id`) and the bytes of the content the decision is about (VR-18);
- `expect_method` is a string. A verdict method or `decision` makes the inputs of its kind required, and any other string requires nothing more. Its value is read at step 9 (VR-03) only: an act whose own method is a chain method is `chain_method` at step 4 whatever `expect_method` says.

The production build reads the pin, the clock and the store in process (CF-08, CF-09); an input carrying `pin`, `now`, `acts`, `lineage`, `next`, `synced_at` or `tip_statement` is `malformed_input`, before the probe and the store are read; the build reads `next` from the store.

Required inputs are checked before anything else. Any of these is `{"error":"malformed_input"}`: a missing `expect_method`, `jws`, `seen` or `org` (or a non-hashstr `org`), or, in the conformance build, a missing `acts`, `lineage`, `next`, `now`, `pin`, `synced_at`, a `next` that is neither `"yes"` nor `"no"`, or a `tip_statement` key that is missing or neither null nor a string; `request_b64`, `request_id` or `recipient` absent when `expect_method` is a verdict; `action`, `consumer`, `decision_b64` or `subject` absent when it is `decision`, or an `action`, `consumer` or `subject` that is not of its form.

Output, always these four keys: `{"class","reason","receipt_id","valid"}`. Each of `class` and `receipt_id` is filled as soon as it is known, on a failure as on success. `receipt_id` is null for steps 1 and 2 and the hashstr of the payload bytes from step 3 on. `class` is null for steps 1 to 6 and from step 7 on is the class of the device in the pinned state whose kid is the header kid, or null when the state has no such device. `valid:true` only with `reason:"ok"`, and only for an accepted key (KC-04). There are no partial-success flags: every check runs on every act. `check-act` is pure: no clock, no I/O, no hidden state (the production build's probe, clock and store reads happen before the pure core runs).

Why: `valid:true` means a fully checked human decision; there is no partial-success shape a consumer could misread.

- S1: GIVEN a probe reporting `pin_missing` WHEN checked THEN `valid:false`, `pin_missing`. V: chk/state-is-error. C: ok/approve
- S2: GIVEN a `check-act` input without `org`, or a verdict input without `request_id` WHEN run THEN `{"error":"malformed_input"}`. V: org/check-act-org-input-missing, chk/request-id-input-missing
- S3: GIVEN the production build and an input with `pin` WHEN run THEN `{"error":"malformed_input"}`; the production build refuses `pin` in a test of the build (CF-07, CF-08), because no vector runs against it. T: checker/python/tests/test_builds.py::test_an_input_carrying_pin_or_now_is_malformed_input
- S4: GIVEN the production build and an input with `acts`, `lineage`, `synced_at` or `tip_statement` WHEN run THEN `{"error":"malformed_input"}` and nothing is read first. T: checker/python/tests/test_builds.py::test_production_refuses_acts_lineage_synced_at_and_tip_statement
- S5: GIVEN a conformance `check-act` input without `next`, or with `next` `"maybe"` WHEN run THEN `{"error":"malformed_input"}`. V: chk/next-input-missing

### VR-02 Ordered pipeline, first failure wins

`check-act` runs these steps in order and returns the first failure:
1. `jws_shape` (ACT-02, ACT-03);
2. `payload_not_canonical_subset`, `payload_too_large` (ACT-04);
3. `schema`, envelope only: ACT-01 constants and key set, ACT-07 forms of envelope fields, and `ext` has exactly the key `dev.handsal/act` with an object value;
4. `method_unknown`, then `chain_method` for every method other than verdicts and `decision` (chain primaries, `chain.resolve`, `act.endorse`, `genesis.sign`), so no human act is ever treated as permanent;
5. method-dependent: `schema` for the act object (ACT-06 keys, ACT-08 head presence and shape, ACT-09 extra keys, ACT-13 parent fields, ACT-14 `kid`, ACT-07 forms of act-object and body fields), then `body_schema` (ACT-09, ACT-10);
6. pin and fold, in this order: (a) the probe's `org` or `filename` differs from the input `org`: `pin_org_mismatch`; (b) `owner_ok` false: the probe's reason; (c) `pin_malformed`; (d) the pin's `org` differs from the input `org`: `pin_org_mismatch`; (e) `profile_mismatch`; (f) production build only: `fixture_profile`, then the store reason (CF-09); (g) `lineage_broken` for an empty lineage, then `lineage_broken` for a first document whose hash differs from the pin's `org`, then `genesis_pin_mismatch` for a last document whose hash differs from the pin's `genesis` (GP-07); (h) `pin_spec_mismatch`; (i) the fold error code, `fork` included, but a `fork` where `next` is `"yes"` is `epoch_superseded` (VR-12);
7. `org_mismatch` (the act's `org` against the pin's `org`);
8. `relay_mismatch` (verdicts, VR-08);
9. vitni `verify` (VR-03): `unknown_key`, `revoked_key`, `bad_signature`, `context_mismatch`, `verifier_unavailable`, `verifier_unexpected`;
10. `high_s` (VR-04);
11. `identity_mismatch` (VR-05);
12. `request_mismatch` (verdicts: the act's `request_id` or `recipient` differs from the inputs) or `consumer_mismatch` (decisions: the act's `consumer` differs from the input `consumer`, VR-18), then `inputs_mismatch`, `outputs_mismatch` (VR-06, VR-07);
13. time (VR-11);
14. view (VR-12), then witness (WT-04, WT-05, WT-10);
15. `duplicate_receipt` (VR-15);
16. `unproven_class`, else `ok`.

Why steps 3 and 5 are split: the act object's closed key set depends on the method, so it cannot be checked before the method is known; the envelope can. Profile rules have one owner (the checker) and ES256 has one owner (vitni). Two defects in one act return the earlier reason, so `unproven_class` appears only for an act that is otherwise perfect.

Steps 7 to 12 and 16 read no moment and no view age: they read the act, the request the consumer holds and the state at one node. Steps 13 to 15 read the verifier's clock, its view of the bag, the witness statement or its `seen` list. `recheck-act` (VR-17) runs steps 1 to 12 and 16 and no other, over the state at the act's own head.

- S1: GIVEN an act with both a bad signature and a stale view WHEN checked THEN `bad_signature`. V: ord/sig-before-time
- S2: GIVEN adjacent defects of steps 4 and 5, inside step 5, and inside step 6 WHEN checked THEN the earlier code. V: ord/method-before-act-object, ord/chain-method-before-body, ord/act-object-before-body, ord/probe-org-before-owner, ord/owner-before-pin-parse, ord/pin-parse-before-pin-org
- S3: GIVEN a wrong `request_id` input and another request's bytes WHEN checked THEN `request_mismatch`. V: ord/request-before-inputs, rep/request-id-input-mismatch, rep/recipient-input-mismatch
- S4: GIVEN a frozen bag WHEN `check-act` runs THEN `valid:false`, `fork`. V: frk/check-act-refuses, ord/fork-before-vitni
- S5: GIVEN an act with an extra key and an unknown method WHEN checked THEN `schema`, the earlier step. V: ord/schema-before-method
- S6: GIVEN a decision for another consumer and other content bytes WHEN checked THEN `consumer_mismatch`, the earlier of the two. V: ord/consumer-before-inputs

### VR-03 vitni verify, always pinned

The checker MUST have each question answered by vitni `verify`, singly or in a batch with a per-element verdict, with `policy.expected_binding = "local"` and `policy.expected_method = expect_method`, always set and never null. `keys` is the fold `keys`, except when the signer kid is a device with `accepted:false`: then it is a one-entry map keyed by that device's person in the state, `{person(kid): {kid: {that device's sign key, status: "active" if the device is active, else "revoked"}}}`. The signature of a key that is not accepted is therefore still verified before step 16 can say `unproven_class`. A `performer_id` that differs from the device's person yields vitni `unknown_key`. A batch element's verdict is the verdict `verify` gives that question alone.

The vitni reasons `unknown_key`, `revoked_key`, `bad_signature` and `context_mismatch` pass through unchanged. Every other vitni reason (`malformed`, `header_key_material`, `alg_not_allowed`, `non_canonical_payload`, or any string not listed) is `verifier_unexpected`: steps 1 to 5 should have made it unreachable, so vitni and the profile disagree, and the checker fails closed with one defined code. The checker MUST NOT implement ES256 itself. The vitni binary is located per CF-05.

- S1: GIVEN `expect_method` approve and a signed reject WHEN checked THEN `context_mismatch`. V: vtn/context-mismatch
- S2: GIVEN vitni returning a reason outside the four pass-through codes WHEN checked THEN `verifier_unexpected`. T: checker/python/tests/test_verifier.py::test_four_reasons_pass_through_and_the_rest_is_unexpected
- S3: GIVEN a key that is not accepted and a bad signature WHEN checked THEN `bad_signature`, never `unproven_class`. V: vtn/unaccepted-bad-sig
- S4: GIVEN a decision whose `performer_id` is not the signing device's person WHEN checked THEN `unknown_key`. V: idn/decision-performer-not-signer
- S5: GIVEN a signature by a kid that is not in the state, or by a key of bob that is not accepted under a `performer_id` of alice WHEN checked THEN `unknown_key`: keys are found by kid, never by person. V: vtn/unknown-key, vtn/unaccepted-map-keyed-by-person

### VR-04 Low S

After a valid signature, the checker MUST reject S above n/2 (`high_s`). The signer normalizes before returning (SG-06). Deduplication stays on receipt id.

Why: vitni accepts high S on both implementations; the profile wants one signature string per payload at the producer and checks it at the verifier.

- S1: GIVEN a payload signed with S replaced by n minus S WHEN checked THEN `high_s`, while vitni alone says ok. V: sig/high-s. C: sig/low-s-ok

### VR-05 Identity

For verdicts, `performer_id` MUST equal the act's `recipient`, else `identity_mismatch`. The recipient the consumer expects is compared at step 12 (`request_mismatch`). The sender of a request is not signed by anyone and MUST be shown as "not proven" wherever it is displayed (RN-07).

- S1: GIVEN `recipient` bob and `performer_id` alice WHEN checked THEN `identity_mismatch`. V: idn/recipient-not-performer

### VR-06 inputs_hash

For verdicts `request_b64` and for `decision` `decision_b64`, are required inputs (VR-01). The checker MUST recompute the hashstr over the raw decoded bytes, without re-canonicalizing, and compare it to `inputs_hash`; a mismatch is `inputs_mismatch`.

Why required: a `valid:true` without the bytes would approve whatever request the consumer later pairs with it.

- S1: GIVEN another request's bytes WHEN checked THEN `inputs_mismatch`. V: inp/other-request, dec/inputs-mismatch
- S2: GIVEN a verdict input without `request_b64` WHEN run THEN `{"error":"malformed_input"}`. V: inp/not-supplied-flag

### VR-07 outputs_hash

VR-07 is the single owner of `outputs_hash` for every method that `check-act` decides. `outputs_hash` MUST equal the value ACT-09 derives: for a verdict, hashstr(JCS({"request_id":R,"verdict":V})) from the act's `request_id` and the verdict of its method; for a decision, hashstr(JCS({"action":A,"subject":S})) of the `action` and `subject` the caller expects (VR-01), and the act's body MUST say the same two values. A mismatch of either is `outputs_mismatch`: the outputs of the act are not the outputs the caller asked for, whether the hash or the words differ, and the caller refuses in both cases. A new code would split one refusal in two. No other method is decided by `check-act` (`chain_method`, VR-02 step 4); ACT-09 says what the fold does with their hashes.

- S1: GIVEN an approve whose `outputs_hash` was computed for verdict `reject` WHEN checked THEN `outputs_mismatch`. V: vrd/outputs-verdict-swapped
- S2: GIVEN a decision whose `outputs_hash` is of another `action` and `subject`, or whose words are not the ones the caller expects, WHEN checked THEN `outputs_mismatch`. V: dec/outputs-mismatch, dec/other-action, dec/other-subject

### VR-08 Relay

A verdict's `relay` MUST be listed in `relays` of the policy of the state the step reads (GP-02), else `relay_mismatch`: the tip's epoch for `check-act`, the head epoch of the act for `recheck-act` (VR-17). `relay` is not an input of either command, and an input that carries it is `malformed_input` in both builds, so a consumer that still passes one fails loudly. An empty `relays` makes every verdict `relay_mismatch` until a genesis change names a host. A rename from A to B is two genesis changes: `relays [A, B]` and a re-pin on every machine, then `relays [B]`. The policy holds no time (`recheck-act` reads no clock, VR-17); when to make the second change is operational.

- S1: GIVEN `relays` `["r.example"]` and an act for relay `a.example` WHEN checked THEN `relay_mismatch`. V: rly/other-relay
- S2: GIVEN an input with `relay` WHEN run THEN `{"error":"malformed_input"}`. V: rly/relay-input-refused
- S3: GIVEN `relays` of two names WHEN a verdict naming the old one, or the new one, is checked THEN step 8 passes. C: rly/two-names-old-ok, rly/two-names-new-ok
- S4: GIVEN an empty `relays` WHEN a verdict is checked THEN `relay_mismatch`. V: rly/empty-relays-mismatch

### VR-09 One verdict per request and recipient

Consumers MUST keep at most one verdict per `(request_id, recipient)`: `seen` carries accepted receipt ids, and the consumer's own store carries the pair. A second distinct verdict for the pair is the consumer's conflict to surface. The checker's duty is only `duplicate_receipt` on equal receipt ids.

- S1: GIVEN the same receipt presented twice WHEN checked with `seen` containing its id THEN `duplicate_receipt`. V: rep/same-receipt-twice. C: rep/different-receipt-same-request-ok

### VR-10 Replay across contexts

A different org, a different relay, a swapped `request_id` or another request's `inputs_hash` MUST each fail with its own reason: `org_mismatch`, `relay_mismatch`, vitni `bad_signature` (an edited payload no longer verifies) and `inputs_mismatch`.

- S1: GIVEN `request_id` edited in the payload WHEN checked THEN `bad_signature`. V: rep/request-id-swapped, rep/org-swapped, rep/inputs-hash-swapped

### VR-11 Time rules

`ts` MUST be at most `now + clock_skew_s`, else `ts_in_future`; exactly `now + clock_skew_s` is valid. Non-chain acts carry `expires`: `expires` MUST be after `ts` (else `bad_expiry`), and `expires - ts` MUST be at most `max_validity_s` (else `validity_too_long`). The act is `expired` when `now >= expires`. No act is permanent. The values come from the epoch policy's `freshness`.

`now` is the verifier's clock. An agent that controls the clock defeats expiry and freshness (section 14, L11).

- S1: GIVEN `now == expires` WHEN checked THEN `expired`; GIVEN `now == expires - 1` THEN valid. V: tim/expired-at-now. C: tim/one-second-left-ok
- S2: GIVEN `ts` exactly `clock_skew_s` ahead of `now` THEN valid; one second more THEN `ts_in_future`. V: tim/ts-future-by-skew-plus-1. C: tim/ts-future-by-skew-ok
- S3: GIVEN `expires` equal to `ts`, or validity one second over the maximum WHEN checked THEN `bad_expiry`, `validity_too_long`. V: tim/expires-equal-ts, tim/validity-max-plus-1

### VR-12 View rules and fail-closed freshness

`synced_at` is input data in the conformance build. `next` is the store's fact that a valid successor of the pinned document is known, or that an authorized foreign successor is (CF-09): input data in the conformance build, read from the store in the production build. In the production build `synced_at` is the time `sync` last wrote the store after a fold that reached a verdict, a state or `fork` (CF-09), and only `sync` sets it. In order:
- `next` is `"yes"`: `epoch_superseded`;
- `synced_at` more than `clock_skew_s` after `now` is `view_in_future`;
- `now - synced_at` greater than `max_view_age_s` is `stale_view`;
- the act's `head.id` not being a position of the current epoch's accepted chain is `stale_view`. One rule covers a verifier that is behind, another branch, another epoch, and junk.

A head older than the tip is valid; the signing key must be active at the tip regardless of when the act was signed.

These rules run in every witness mode. In mode `relay` the witness rules (WT-05) run after them, and both must pass (WT-07). In mode `none` they are the whole freshness check and the tip statement (the store's `witness` slot in the production build) must be null (WT-04). Mode `none` leaves a known gap (section 14, L10).

A `fork` of the pinned epoch is a verdict about an open tip. Where `next` is `"yes"` the epoch has a successor, takes no further act (`epoch_closed`, CF-11) and so no resolve could lift the fork: `check-act` (VR-02 step 6 (i)), `enrolled` (GP-13 step 4) and `sync` (CF-09) all answer `epoch_superseded` there, one order for one fact. `check-act` stops at step 6 there, so its `class` is null, as for `fork`. Every other fold error keeps its place and comes first.

Why: a non-chain act authorizes something now only if the verifier's view could have seen any revocation. `epoch_superseded` comes first because a machine whose store holds a valid successor of its pin cannot see what the new epoch removed, whatever the age of its view, and a store may have dropped acts of the old epoch after H (CF-14). It holds in every witness mode, and a person's re-pin (GP-12) is the remedy.

- S1: GIVEN `now - synced_at == max_view_age_s` THEN valid; one second more THEN `stale_view`. V: frs/age-max-plus-1. C: frs/age-exactly-max-ok
- S2: GIVEN a head that is a losing candidate of a current resolve, or an unknown id WHEN checked THEN `stale_view`. V: frs/head-other-branch, frs/head-unknown-id
- S3: GIVEN a head older than the tip and a key still active WHEN checked THEN valid; GIVEN the key revoked at the tip THEN `revoked_key`. V: frs/head-older-key-revoked-at-tip. C: frs/head-older-than-tip-ok
- S4: GIVEN the production build and a store whose `synced_at` is older than `max_view_age_s` WHEN checked THEN `stale_view`. T: checker/python/tests/test_builds.py::test_synced_at_comes_from_the_store_and_its_age_is_judged
- S5: GIVEN `next` `"yes"` and a fresh view WHEN checked THEN `epoch_superseded`; GIVEN `next` `"yes"` and a stale view THEN `epoch_superseded` too. V: frs/epoch-superseded, ord/superseded-before-stale-view
- S6: GIVEN the production build WHEN `check-act` runs THEN `next` comes from the store, and an input carrying `next` is `malformed_input`. T: checker/python/tests/test_builds.py::test_next_is_read_from_the_store_and_refused_as_input
- S9: GIVEN the same questions asked one at a time and in one batch WHEN vitni answers THEN each question has the same verdict in both. T: checker/python/tests/test_verifier.py::test_a_batch_element_is_what_verify_gives_that_question_alone
- S7: GIVEN a frozen bag at the pin and `next` `"yes"` WHEN `check-act` or `enrolled` runs THEN `epoch_superseded`, and `fork` with `next` `"no"`. V: ord/superseded-before-fork, enr/epoch-superseded-before-fork. T: checker/python/tests/test_rules.py::test_a_fork_at_a_superseded_pin_is_epoch_superseded_and_every_other_fold_error_keeps_its_place, checker/python/tests/test_enrolled.py::test_a_fork_at_a_superseded_pin_is_epoch_superseded_and_the_other_fold_errors_come_first, checker/python/tests/test_sync.py::test_a_fork_at_a_superseded_pin_is_epoch_superseded_as_in_the_readers
- S8: GIVEN the production build and a store whose `next` is `"yes"` because of a foreign successor WHEN `check-act`, `enrolled` and `head` run THEN `epoch_superseded`, as for a valid successor. T: checker/python/tests/test_builds.py::test_a_foreign_successor_makes_the_commands_epoch_superseded

### VR-14 Ingestion contract

A consumer MUST run `check-act` once, when an act first arrives, and record `{receipt_id, valid, reason}` for a valid act, the values its output carries (VR-01). An invalid result is recorded keyed by the hashstr of the full JWS bytes, or not at all; it is never recorded against a receipt id, so a garbage-signature twin cannot make the consumer refuse the valid act later. The consumer MUST NOT re-run `check-act` on stored acts to decide historic validity, and MUST run it for every new act. Consumers verifying chain acts use the fold, not `check-act`.

A consumer MUST keep the full JWS of every act it accepts, and the request or content bytes it was accepted for, and MUST run `recheck-act` (VR-17) on the stored JWS at read time, before it treats the act as a human decision. `recheck-act` can answer `stale_view` for an act that `check-act` found valid when it arrived: after a resolve, a fork or a genesis change the act's head can lie on a branch a resolve discarded, beyond a fork parent, or past the head H of a change (VR-17). A consumer reads that answer as "this stored act is no longer provable against the pinned chain", never as "the act was never valid", and it does not repair the answer by re-running `check-act` on the stored act. The recorded `valid` is the consumer's own data, which an agent running as the same user can rewrite (section 14, L9); `rechecked:true` is recomputed from the act's signature and the pinned fold. Freshness and expiry are ingestion-only: `recheck-act` reads no clock, so a consumer that wants an expiry or a freshness decision at read time keeps the times it recorded at ingestion and decides them itself, knowing that record is editable too.

Why: an approval must not flip after an unrelated later revocation, so the decision made at ingestion stands and `check-act` is not run again. The record holds no tip: no command returns the tip `check-act` decided against, and `recheck-act` examines a stored act at its own head (VR-17). A decision that stands must still rest on something an agent cannot mint: the signed bytes. Vectors assert the pure-function side: a revocation after ingestion changes `check-act` at the new tip, which is why the consumer must not re-run it, and `recheck-act` of the same act is unchanged. The ingestion store is the consumer's and this repository ships none (CF-09 is another store), so the tests of the rest of this requirement (S2 to S4) belong to each consumer's own suite.

- S1: GIVEN an approve ingested at tip 7 and its signing key removed at 8 WHEN `check-act` is run at tip 8 THEN `revoked_key`; the consumer's recorded decision stands. V: ing/revoked-after-ingestion-recheck-fails
- S2: GIVEN an invalid twin of a valid act WHEN ingested THEN it is not recorded against the receipt id. O: the consumer's own test suite; this repository ships no store
- S3: GIVEN a valid act WHEN ingested THEN the record carries `receipt_id`, `valid` and `reason` as `check-act` returned them, and no value its output does not carry. O: the consumer's own test suite; this repository ships no store
- S4: GIVEN an ingestion record rewritten to say valid WHEN the act is read THEN the consumer runs `recheck-act` on the stored JWS and does not trust the record. O: the consumer's own test suite; this repository ships no store
- S5: GIVEN a stored act whose head a later resolve discarded WHEN `recheck-act` runs at read time THEN `stale_view`, and the consumer does not read it as an invalid act and does not re-run `check-act` on it. O: the consumer's own test suite; this repository ships no store

### VR-15 Duplicate receipt

`seen` holds only receipt ids of acts the consumer previously found valid. A presented act whose receipt id is in `seen` is `duplicate_receipt`.

- S1: GIVEN an invalid twin that was never found valid WHEN the valid act is checked THEN it is not a duplicate. V: rep/invalid-twin-not-in-seen

### VR-16 Verifier-side limits

`check-act` MUST reject a payload segment larger than MAX_PAYLOAD before any other work on it.

- S1: GIVEN a 16385-byte payload WHEN checked THEN `payload_too_large`. V: jcs/oversize

### VR-17 Re-check of a stored act

`recheck-act` re-verifies the time-free part of one non-chain act that a consumer stored. `check-act` answers "may this act be acted on now?": it joins a time-free question (is this a genuine act by a key the fold gave a person, active at the act's own head, naming this request) to the verifier's moment (fresh, unexpired, not revoked at the tip, not seen before). A consumer that kept only that joined answer kept an editable record. `recheck-act` answers the first question alone, from the stored JWS, and shares the code of the steps it runs with `check-act`: `check-act` is the steps of `recheck-act` and then the steps that read the verifier's moment, and the two cannot disagree about a signature, a key or a request.

Input (conformance build): `{acts, action, consumer, decision_b64, expect_method, jws, lineage, org, pin, recipient, request_b64, request_id, subject}`, the inputs of `check-act` (VR-01) read the same way, without four of them. For a decision `action`, `consumer`, `decision_b64` and `subject` are read as `check-act` reads them and are required. `now`, `synced_at`, `seen`, `tip_statement` and `next` are `malformed_input` in both builds, so a caller cannot believe a clock, a view, a witness or a store was used. `seen` in particular would make every stored act `duplicate_receipt`, because the consumer recorded it as found valid. `relay` is `malformed_input` in both builds too (VR-08). The production build reads the pin in process, as `check-act` does, and the store (CF-09); it takes no `pin`, `acts` or `lineage` (`malformed_input`) and reads no clock (CF-08). The pin is the trust anchor, so the re-check runs the same pin checks as `check-act` and a lineage that is not pinned proves nothing.

Output, always these five keys: `{"class","not_proven","reason","receipt_id","rechecked"}`. `rechecked:true` only with `reason:"ok"`. There is no `valid` key: a consumer that swaps `check-act` for this command reads no `valid` and fails closed, and a `rechecked:true` is never mistaken for permission to act now. `class` and `receipt_id` are filled as in VR-01, with the class of the device in the state at the act's own head. `not_proven` is always the list `["expiry","freshness","order_of_arrival","replay","revocation_after_head"]`, in this order: the five things a `rechecked:true` leaves open (section 14, L9).

Steps, in order. `recheck-act` runs steps 1 to 6 of VR-02 as `check-act` does. Then one step of its own: the act's `head.id` MUST be a position of a chain the lineage proves, else `stale_view`, and the class is null. A head is a position in its own epoch, and the lineage proves which epoch that is. In the last epoch the positions are those of the accepted chain. In an earlier epoch they are the nodes on the path to the head H of the change that follows, the only part of that epoch the lineage continues from (GP-19). `stale_view` here means only that the head is no position of a chain the lineage proves: unknown, on a branch a resolve discarded, beyond a fork parent, or past H. The state examined is the state at the act's own head in that epoch, the node `fold` reads with `at` (FO-16), not the tip. A fork or later acts beyond that node do not change it, so `fork` is not a reason of this command. The lineage is accepted from the pinned genesis exactly as `check-act` accepts it (step 6), so the same answer holds after a genesis change and a re-pin. Then steps 7 to 12 and 16 of VR-02, unchanged, over that state: `org_mismatch`, `relay_mismatch` (against `relays` of that head's epoch, VR-08), vitni `verify` with the keys of that state, `high_s`, `identity_mismatch`, `request_mismatch`, `inputs_mismatch`, `outputs_mismatch`, then `unproven_class`, else `ok`. A chain act is `chain_method` (step 4): only non-chain acts are re-checkable, and a chain act is decided by the fold. `recheck-act` does not run step 13, step 14 or step 15: no `now`, no freshness, no expiry (`ts_in_future`, `bad_expiry`, `validity_too_long`, `expired`), no view and no witness, no revocation read at the tip, no `seen`.

Fold scope: the key is examined at the act's own signed head, with the chain acts of the bag. A key that was added after that head is `unknown_key`. A key removed after that head is still valid there (FO-05): `rechecked:true`, where `check-act` at a later tip says `revoked_key`. That is the intended meaning for an act accepted before the removal, and it is also the bound of section 14, L9. A key removed by a later epoch does not change the answer for an act of an earlier epoch: each epoch's act is examined in its own epoch's state, under the profile of that epoch's document (GP-23), so a re-pin to a newer edition does not change the rules by which an older epoch's act is read. The act form read at steps 1 to 6 is the same in every edition (I3). The bag and the lineage are the caller's in the conformance build; in the production build they are the store's, which keeps the path of every earlier epoch (CF-09, CF-14), so a head on such a path stays checkable. A head that they do not contain is `stale_view`, never a pass.

After `valid:true` of `check-act` or `rechecked:true` of `recheck-act` a consumer may read `performer_id` and `ts` from the payload of the same JWS string, and the checker returns neither (CF-15: an output key added to an issued command would make the vectors of every earlier edition fail). `performer_id` is then proven to be the person that owns the header `kid` in the state the answer was read from: a payload whose `performer_id` differs from that person is `unknown_key` at VR-03. `ts` is the signer's clock: `check-act` bounds it against the verifier's clock (VR-11), and `recheck-act` bounds nothing, because it reads no clock. A consumer MUST NOT cache `recheck-act` answers. The cost of an answer is one pinned fold per call, and a cache would be the editable record that this command exists to remove (VR-14); no digest of the store is ever offered for that purpose either.

Why a command and not a flag on `check-act`: a flag is a second meaning under the same output key, and the consumer that forgets it gets an answer that reads as permission to act. Two commands with different output keys cannot be swapped by accident. Why `rechecked` and not `valid`: the same reason, the name is the contract.

`rechecked:true` proves that the stored bytes are a genuine act by a key the pinned fold gave a person, active at the act's own head, naming this request and these bytes. It does not prove that the act was ever ingested, when it was made, that it was fresh or unexpired, that it is the only verdict for the request, or that its key is not revoked at the tip (section 14, L9).

- S1: GIVEN a valid stored approve WHEN rechecked THEN `rechecked:true` with `reason` ok, the `not_proven` list and no `valid` key. V: rck/ok
- S2: GIVEN an approve whose `expires` is long past WHEN rechecked THEN `rechecked:true`, although `check-act` at that time says `expired`. V: tim/expired-at-now. C: rck/ok-expired-act
- S3: GIVEN a stored decision WHEN rechecked with its content and the expected words THEN `rechecked:true`. V: rck/ok-decision
- S4: GIVEN a bag that forks at the act's head WHEN rechecked THEN `rechecked:true`, although `check-act` says `fork`. V: frk/check-act-refuses. C: rck/ok-fork-after-head
- S5: GIVEN an approve by alice whose head is before the removal of alice's key WHEN rechecked THEN `rechecked:true`, although `check-act` at the tip says `revoked_key`. This is the bound L9 (a). V: frs/head-older-key-revoked-at-tip. C: rck/removed-key-names-old-head-accepted
- S6: GIVEN an approve signed by alice2 whose head is before alice2 was added WHEN rechecked THEN `unknown_key` and class null, although `check-act` at the tip says valid. V: rck/key-not-active-at-head. C: rck/key-added-after-head-check-act-ok
- S7: GIVEN an approve whose `request_id` was edited after signing WHEN rechecked THEN `bad_signature`. V: rck/bad-signature
- S8: GIVEN another request's bytes WHEN rechecked THEN `inputs_mismatch`. V: rck/inputs-mismatch
- S9: GIVEN a chain act WHEN rechecked THEN `chain_method`. V: rck/chain-method-refused
- S10: GIVEN a head that names no node WHEN rechecked THEN `stale_view`. V: rck/head-unknown
- S11: GIVEN an input that carries `now`, `synced_at`, `seen` or `tip_statement` WHEN run THEN `{"error":"malformed_input"}`. V: rck/now-input-malformed, rck/synced-at-input-malformed, rck/seen-input-malformed, rck/tip-statement-input-malformed
- S13: GIVEN a payload whose `performer_id` is not the person of the device that owns the header `kid` WHEN checked THEN `unknown_key`, so after `valid:true` the `performer_id` of the payload is that person. V: idn/decision-performer-not-signer
- S14: GIVEN a consumer that has stored a `recheck-act` answer WHEN the act is read again THEN it asks `recheck-act` again and does not use the stored answer. O: the consumer's own test suite; this repository ships no store
- S12: GIVEN the same data WHEN `check-act` and `recheck-act` run THEN they give one reason for every defect of steps 7 to 12 and 16: the steps are one list. T: checker/python/tests/test_recheck.py::test_both_commands_give_the_same_reason_for_every_time_free_defect, checker/python/tests/test_recheck.py::test_the_steps_are_one_list_cut_in_two
- S13: GIVEN the production build and an input carrying `acts` or `lineage` WHEN run THEN `{"error":"malformed_input"}`. T: checker/python/tests/test_builds.py::test_production_refuses_acts_lineage_synced_at_and_tip_statement
- S18: GIVEN a lineage that continues with a change at the root, pinned at the change, and an approve whose head is the root of the first epoch WHEN rechecked THEN `rechecked:true`: a stored act of an earlier epoch is not lost by a re-pin, while `check-act` still wants the head in the current epoch. V: rck/ok-act-of-earlier-epoch
- S14: GIVEN the same lineage and an approve whose head is a node beside the change, off the path to its head WHEN rechecked THEN `stale_view`. V: rck/head-past-change-stale-view
- S15: GIVEN the production build and an input with `pin`, `now` or any other key that names a moment WHEN run THEN `{"error":"malformed_input"}`, and the build reads the pin in process and never the clock. T: checker/python/tests/test_builds.py::test_recheck_act_refuses_pin_and_every_key_that_names_a_moment, checker/python/tests/test_builds.py::test_recheck_act_reads_the_pin_in_process_and_never_the_clock
- S16: GIVEN a verdict that names a host a later genesis change dropped from `relays` WHEN rechecked at its own head THEN `rechecked:true`, while `check-act` at the tip says `relay_mismatch`. V: rly/relay-dropped-at-tip-mismatch. C: rck/relay-from-head-epoch
- S17: GIVEN a `recheck-act` input carrying `next`, in either build WHEN run THEN `{"error":"malformed_input"}`. V: rck/next-input-malformed
- S19: GIVEN a P1 original, a P2 change, a pin at the P2 document, and an approve whose head is in the P1 epoch WHEN rechecked THEN `rechecked:true`; and the same approve under `check-act` WHEN checked THEN it wants a head in the P2 epoch (`stale_view`). V: chg/old-epoch-head-stale. C: prf/recheck-p1-epoch-act-after-repin-to-p2. P: prf/prodk-recheck-p1-epoch-after-repin
- S20: GIVEN the same lineage and an act of the P1 epoch signed by a key that a rule of P2 would reject WHEN rechecked THEN the answer is the P1 rule's. T: checker/python/tests/test_profile_set.py::test_an_act_of_the_first_epoch_is_rechecked_by_the_first_editions_rule_after_a_re_pin

### VR-18 Decision acts

`local:handsal.decision` records one decision of a person about content, on the machine where the person signs. It is the one generic method for a local human decision (ratify a ruling, forget an item), so a consumer does not need a method for each of its verbs. A verdict that travels between machines through a relay stays `request.*` (VR-08): it is addressed to a recipient and a relay, and a decision is for an act that stays on one machine, so it carries no `recipient`, no `relay` and no `request_id`.

The act (ACT-09): the act object has `expires` and `head` (always) besides the common keys; `performer_id` is the person of the signing device (ACT-13). The body is closed and all three keys are required:
- `action`: a short label of what is decided, an `action` (section 2.2): lowercase ASCII words separated by single spaces, 1 to 24 characters;
- `consumer`: the consumer the decision is for, a `consumer_id`;
- `subject`: the id of what the decision is about, a `subject_id`.

What binds what. `inputs_hash` is hashstr(raw bytes of the content decided), carried as the attachment `decision_b64` (RN-09): the person sees those bytes in the render (RN-12, at most 2048 bytes and 32 block lines, no truncation) and the signature covers exactly them, so an opaque id alone is never what a person decides. `outputs_hash` is hashstr(JCS({"action":A,"subject":S})) from the act's own body. `consumer` is signed and rendered (RN-03, RN-04): it is the domain separation that `recipient` and `relay` give a verdict, so a decision signed for one consumer cannot be accepted by another that expects the same words and bytes.

Who owns what. The profile owns the grammar and the rendering; a consumer owns its vocabulary. `action` is not data in the genesis policy: the checker accepts every `action` of the grammar and no list of labels exists in any profile file. `check-act` binds the key, the consumer, the content and the words: the caller gives the `action` and `subject` it asked for, as a verdict's caller gives the `request_id` and `recipient`, and no consumer compares them again. What stays with the consumer is its vocabulary: a consumer MUST accept only its own exact labels, and decide which `action` and `subject` to ask for.

Why `consumer` should be a stable product identifier: it is signed domain separation. A consumer that renames its `consumer_id` makes every decision it stored `consumer_mismatch` on `recheck-act`, and no checker can tell a product id from a display name. Use an identifier that never changes, not a brand name. The `consumer_id` grammar is wire (GP-23), so no edition narrows it.

`check-act` and `recheck-act` require the expected `action`, `consumer`, `subject` and the content bytes (VR-01). A different `consumer` in the act is `consumer_mismatch` at step 12 (VR-02), before `inputs_mismatch` and `outputs_mismatch`. Other words in the act than the caller expects are `outputs_mismatch` (VR-07): the signed `outputs_hash` is the commitment to `{action, subject}`, so a mismatch of the words is the outputs differing, and no code is added. The code is its own: `request_mismatch` says the request or recipient of a verdict differs, which is another fact, and one code keeps one meaning. An `action`, `consumer` or `subject` input that is not of its form is `malformed_input` (a `consumer` input that is not a `consumer_id` is `malformed_input`): a consumer that configured a value no act can carry is told at once and not by a mismatch on every act. A grammar violation of `action`, `subject` or `consumer` inside the act is `body_schema` (ACT-10). A decision names no sender: whichever process asks for the signature chooses the words and the bytes, and the person sees both (RN-11), so who asked is as unproven as the sender of a request (RN-07). `recheck-act` (VR-17) runs the same steps, through the one implementation of the time-free steps, so no rule exists twice.

- S1: GIVEN a valid decision for consumer `notes` WHEN checked by `notes` with the content THEN `valid:true`. V: ok/decision. C: ok/decision-action-24
- S2: GIVEN the same act WHEN checked by another consumer THEN `consumer_mismatch`. V: dec/other-consumer, rck/decision-other-consumer
- S3: GIVEN a decision signed for `archive` with the `action`, `subject` and content of a decision signed for `notes` WHEN checked by `notes` THEN `consumer_mismatch`, and by `archive` `valid:true`. V: dec/replay-same-decision-other-consumer. C: ok/decision-other-consumer
- S4: GIVEN a decision whose `consumer` was edited after signing WHEN checked THEN `bad_signature`. V: dec/consumer-swapped
- S5: GIVEN an `action` with an uppercase letter, a digit, a doubled, leading or trailing space, 25 characters or none WHEN checked THEN `body_schema`. V: dec/action-uppercase-body-schema, dec/action-digit-body-schema, dec/action-double-space-body-schema, dec/action-leading-space-body-schema, dec/action-trailing-space-body-schema, dec/action-25-bytes-body-schema, dec/action-empty-body-schema
- S6: GIVEN a `subject` or a `consumer` with an uppercase letter WHEN checked THEN `body_schema`. V: dec/subject-uppercase-body-schema, dec/consumer-uppercase-body-schema
- S7: GIVEN other content bytes WHEN checked THEN `inputs_mismatch`. V: dec/inputs-mismatch
- S8: GIVEN a decision whose `expires` has passed WHEN checked THEN `expired`: a decision is not permanent (VR-11). V: dec/expired
- S9: GIVEN a decision input without `consumer`, `action`, `subject` or `decision_b64`, or with a `consumer`, `action` or `subject` that is not of its form WHEN run THEN `{"error":"malformed_input"}`. V: dec/consumer-input-missing, dec/decision-input-missing, dec/consumer-input-form-malformed, dec/action-input-missing, dec/subject-input-missing, dec/action-input-form-malformed, dec/subject-input-form-malformed
- S10: GIVEN a bag with one valid chain act and one valid decision WHEN folded THEN the decision is not on the chain. V: fld/decision-ignored
- S11: GIVEN a stored decision WHEN rechecked with its content and its consumer THEN `rechecked:true`; with another consumer THEN `consumer_mismatch`; with other bytes THEN `inputs_mismatch`; with another action or subject THEN `outputs_mismatch`; without `consumer` or `action` THEN `{"error":"malformed_input"}`. V: rck/decision-other-consumer, rck/decision-inputs-mismatch, rck/decision-consumer-input-missing, rck/decision-action-input-missing. C: rck/ok-decision
- S12: GIVEN the production build and a decision WHEN checked THEN the same steps run as for any non-chain act and the build reads the pin in process. T: checker/python/tests/test_builds.py::test_a_decision_is_decided_by_the_production_build_like_any_non_chain_act
- S13: GIVEN the right consumer and another `action`, or another `subject`, than the act says WHEN checked THEN `outputs_mismatch`. V: dec/other-action, dec/other-subject, rck/decision-other-action, rck/decision-other-subject


### VR-19 Head for a signer

`head` answers the one question a producer of an act cannot answer without the chain: which `head` (ACT-08) to name. `handsal-check head < input.json` (conformance and production builds, framed as CF-03; the server build answers `unsupported_command`, CF-10). Input (conformance build) `{acts, lineage, next, now, org, pin, synced_at, tip_statement}`: the inputs of `enrolled` (GP-13) without `device_kid`, with `pin` the probe object of GP-14 and `next` as in VR-01. Input (production build) `{org}`: it reads the pin, `now` and the store in process (CF-08, CF-09), and an input carrying `acts`, `lineage`, `next`, `now`, `pin`, `synced_at` or `tip_statement` is `malformed_input`. A missing or non-hashstr `org`, and in the conformance build a missing key, is `malformed_input`.

Output `{"head":{"id":T,"kind":"chain"},"reason":"ok"}` or `{"head":null,"reason":R}`. The object is the exact ACT-08 value, so the caller copies it into the draft unchanged (SG-04): there is no `n` to strip and no `kind` to add. Steps, first failure wins:
1. to 3. the pin checks of VR-02 step 6, (a) to (h), in that order and with those codes, the store reason at (f) included in the production build;
4. the fold succeeds (else its error code, `fork` included, but a `fork` where `next` is `"yes"` is `epoch_superseded`, VR-12);
5. the view: the act-free rules of VR-12 (`epoch_superseded`, `view_in_future`, `stale_view` by age), then the witness rules of the policy's mode (WT-04, WT-05, WT-10).

Else `ok`, and T is the id of the tip of the pinned epoch's accepted chain: the receipt id of its last primary, or the current genesis document hash where the chain is empty (ACT-08, position 0). Where the lineage has several epochs, T is a position of the last one, never of the path of an earlier one. There is no fixture step and no new reason code. The conformance build answers under the fixture profile and the production build refuses it at step 6 (f); `head` proves nothing about a person, so the reason of GP-13 step 7 does not apply. Every code is one `check-act` already gives for the same fact, with the remedy consumers already handle.

Equality (I12). For the same pin, store and clock, `head` answers `ok` with T exactly when `check-act` of an otherwise perfect non-chain act that names T as its head passes steps 6 and 14, and answers a code R exactly when `check-act` of such an act answers R at one of those steps. The two commands run the same steps with the act removed, and a change to VR-12 or to the witness rules that reaches one must reach the other.

Which head. The tip, because ACT-08 defines the head as the position the signer saw, and VR-12 accepts every position of the accepted chain up to the tip. When no head is acceptable there is none. A fork has none: `check-act` refuses every non-chain act on this store, and a head at the fork parent would be accepted only by a machine that has not seen the fork. A refused view has none (`epoch_superseded`, `view_in_future`, `stale_view`, the witness codes): `check-act` on this machine refuses every act now, and the remedy is `sync` or a re-pin and then to ask again, not a touch spent on an act this machine refuses. Every pin, store and verifier failure answers the code `check-act` gives.

Meaning. A verifier on this machine, now, would accept an act that names this head at steps 6 and 14. It is not human proof, not an enrolment check (the key may be removed or its class not accepted, which `enrolled` answers) and not a promise about later: the tip may move after the answer, a head older than the tip stays valid (VR-12), and a resolve that moves the chain away from it makes it `stale_view`. A caller asks again for every signature, because a cached answer can name a head that a resolve has since stranded. Consumers MUST NOT treat `ok` as human proof (SG-10).

Scope. Heads of verdicts and `decision` only. `head.id` is also the right `parent.id` for a new chain primary, but `head` returns no `parent.performer`, and chain drafts are built in ceremonies from a bag the people hold. The head of an endorsement comes from the endorsed act (FO-08) and the head of a `genesis.sign` over a change from the document (GP-19); the signer derives and checks both from attachments (SG-13). VR-14 is unchanged: an ingestion record still holds no tip, and `head` returns the head a producer names, not the tip a verdict was decided against.

Why: ACT-08 gives `head` to the caller of the signer and keeps the signer free of the fold (WT-09), and since CF-09 the view of the chain is the store's, behind the checker. Without this command every caller would rebuild the chain from its own bag to find the tip that `check-act` will accept, which is the duplication the store removed, and would have to agree with VR-12 forever with nothing showing it. One command over the one store read and the one pinned fold (CF-08) gives that fact one owner, and the equality is locked by a property test over the `check-act` worlds and by a guard over every vector of the group, so a rule changed in one command and not the other turns a test red. Why the tip and not an older position: an older position misstates what the signer saw, a verifier that is behind refuses the tip with `stale_view` until it syncs (which it must do within `max_view_age_s` anyway), and a resolve can strand an old head as easily as the tip. Why no code of its own for "no head": one name for a dozen facts with a dozen remedies would send the caller to `check-act` to learn which.

- S1: GIVEN a fresh view of a chain of three primaries WHEN `head` runs THEN `ok` and the head is the tip; GIVEN an empty chain THEN `ok` and the head is the genesis document hash; GIVEN a fork lifted by a resolve THEN the head is the tip of the chosen branch. V: hed/ok-tip, hed/ok-root, hed/ok-after-resolve
- S2: GIVEN a store that forks WHEN `head` runs THEN `fork` and a null head; GIVEN `next` `"yes"` THEN `epoch_superseded`, with a fork or a stale view beside it. V: hed/fork, hed/epoch-superseded, hed/superseded-before-fork, hed/superseded-before-stale-view
- S3: GIVEN `now - synced_at` greater than `max_view_age_s` WHEN `head` runs THEN `stale_view`; GIVEN `synced_at` more than `clock_skew_s` after `now` THEN `view_in_future`; GIVEN exactly `max_view_age_s` THEN `ok`. V: hed/stale-view, hed/view-in-future. C: hed/age-exactly-max-ok
- S4: GIVEN a relay witness policy and no statement WHEN `head` runs THEN `witness_missing`; GIVEN mode `none` and a statement THEN `witness_unexpected`; GIVEN a relay policy and a good statement THEN `ok`. V: hed/relay-witness-missing, hed/mode-none-statement-supplied. C: hed/relay-ok
- S5: GIVEN a probe that reports no pin, a probe of another organization, or a lineage that is not the pin's WHEN `head` runs THEN `pin_missing`, `pin_org_mismatch`, `lineage_broken`, each before any fold or view code; GIVEN an input without `org` or without `next` THEN `{"error":"malformed_input"}`. V: hed/pin-missing, hed/pin-org-mismatch, hed/lineage-broken, hed/next-input-missing, hed/org-input-missing
- S6: GIVEN a lineage of two epochs and a pin at the last WHEN `head` runs THEN the head is in the last epoch and never a position of the path of the earlier one. V: hed/ok-two-epochs
- S7: GIVEN the production build and an input with any state key WHEN `head` runs THEN `{"error":"malformed_input"}` and nothing is read first; GIVEN a call THEN the store is read once; GIVEN no store THEN `store_missing`, after the pin reasons. T: checker/python/tests/test_builds.py::test_head_refuses_every_state_key_and_reads_nothing_first, checker/python/tests/test_builds.py::test_head_reads_the_store_once_per_call, checker/python/tests/test_builds.py::test_head_answers_store_missing_after_the_pin_reasons
- S8: GIVEN any world of the `check-act` tests, and every vector of the group WHEN `head` runs and `check-act` runs on an otherwise perfect decision that names its head THEN they agree on `ok` or on the code (the equality above). T: checker/python/tests/test_head.py::test_head_and_check_act_agree_over_every_check_act_world, conformance/vectors/_gen/tests/test_group_hed.py::test_every_hed_vector_agrees_with_the_check_act_model
