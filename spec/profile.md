# handsal profile, version 1

This is the normative text of the handsal profile. handsal turns a vitni signed receipt into proof that a person decided something with a hardware-bound key: an approval of a request, a decision about content, or a change to who may sign for an organization. The profile fixes the bytes of every signed act, the trust anchor a machine pins, the pure function that folds an organization's acts into its current keys, the rules a verifier applies to a single act, the text a signer shows before a signature, and the command line contracts that let independent implementations be compared byte for byte.

vitni is used unchanged. This profile narrows what vitni accepts and adds the rules vitni does not own.

## 0. Reading guide

- The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
- Requirement ids have the form `FAMILY-NN`. Families: `ACT` act profile (section 3), `KC` key classes (4), `GP` genesis and pin (5), `FO` fold (6), `VR` verifier rules (7), `RN` rendering (8), `CF` conformance and checker CLI (9), `SG` signer CLI (10), `WT` freshness witness (13). Ids are stable. An id is never renumbered and never reused. Gaps in a family are retired ids, listed in Appendix A with what replaced them.
- Each requirement states its rule, the reason codes it produces, and scenarios. A scenario is one line, `GIVEN ... WHEN ... THEN ...`, ending in its proof, in one or more tails. `V:` lists shipped conformance vectors, ids of the form `group/case`. `C:` lists shipped vectors that end in no reason code, the positive controls of a scenario whose THEN part names one. `P:` lists vectors that ship at the tag and wait for an owner step (the production-key vectors, CF-08). `T:` lists implementation tests, each a file path, two colons and a test name, which CF-07 lists. `O:` names a proof outside this repository's suites and whose it is (a consumer's tests, a platform check the owner runs by hand). When the THEN part names reason codes, a `V:` vector ends in one of them, and a tail other than `C:` proves the code. The ids listed are representative; the vector set holds further cases for most requirements.
- The profile is several files, one text: `spec/profile.md` holds sections 0 to 6, `spec/profile-checks.md` holds section 7, `spec/profile-display.md` holds section 8, `spec/profile-interfaces.md` holds section 9 and `spec/profile-part3.md` holds sections 10 to 14 and the appendices. Section numbers and requirement ids are global, so a reference names one place whichever file holds it. Every one of them is a core file (CF-01), and a tool that reads the profile reads them all.
- A line starting with "Why:" explains a rule for implementers. It is not normative.
- Reason codes are lowercase snake_case. They are part of the contract and appear verbatim in outputs and vectors. Section 11 indexes them.
- "Fail closed" means: refuse, return a reason code, and never map an unknown or missing thing to a skip or a default.
- "Not on the chain" means the fold ignores the act: the fold output equals the output for the same bag without that act.
- Normative references: vitni 0.5.3 or later, `conformance/CONTRACT.md` section 7 (`verify` input and algorithm) and section 8 (chain link checks), cited as "vitni CONTRACT.md". What the profile relies on is that contract, not a release: 0.5.3 is the release it was written against and ES256 `verify` is unchanged since. A vitni build that disagrees with a vector fails `generate.py --check`, which is the guard that this reference stays true; RFC 4648 (base64url), RFC 6979 (deterministic ECDSA nonces), RFC 7493 (I-JSON), RFC 7638 (JWK thumbprint), RFC 7515 (JWS compact serialization).

Names used in scenarios (the conformance fixtures define them exactly):
- `alice`, `bob`, `carol`: members with role `maintainer`, one `apple-se-bio` device each. `alice2`, `alice3`, `bob2`, `X1`, `X2`: further devices added by two-person acts. `dave`: a member whose role is listed in no rule. `frank`, `grace`, `heidi`: new maintainers introduced by a genesis change. `K`: a key a scenario names as stolen or removed.
- ORG: the base genesis document. Members alice, bob, carol; roles `maintainer` and `member`; every rule `{persons:"2", roles:["maintainer"]}`; freshness `clock_skew_s "300"`, `max_validity_s "604800"`, `max_view_age_s "86400"`; witness `{"mode":"none"}`. LINEAGE and PIN_OK are its lineage and a passing probe. ORG4 adds a fourth maintainer `erin`. PINORG adds `dave` with a device of the fixture-only class `fixture-pin`. ORG_PRODK is ORG under the production profile, its maintainers alice, bob and carol holding PRODK keys.
- NOW: the fixed verifier time. SYNCED: `synced_at` equal to NOW. APPROVE: a valid `request.approve` by alice.
- WIT_ORG: ORG with a relay witness whose key is RELAY_FX. TIP_OK: a valid tip statement for WIT_ORG at tip T4, 60 seconds old.
- CHG-NEW: a change document that keeps the named role holders' devices and adds new maintainers `frank` and `grace`. CHG-VALID: a change document built from the devices active at its head.
- Fixture profile and production profile: section 9 (CF-01) and GP-18. PRODK: production-profile vectors signed by keys whose private scalars were destroyed after signing.

## 1. Scope and threat model

### 1.1 What this profile covers

The profile defines: the act format (section 3), the key class registry (4), the genesis document, its policy and the pinned trust anchor (5), the fold that computes an organization's state from its acts (6), the checks a verifier runs on one act (7), the text shown to a signer (8), the checker command line and the conformance vectors (9), the signer command line (10), and an optional freshness witness (13).

Out of scope: how acts are transported (their storage on the verifying machine is CF-09), the relay server that produces witness statements (section 13 states only what a verifier checks and what a relay must do), the user interface of device linking, and recovery of an organization whose rules can no longer be met.

### 1.2 Threat principle

Any single biometric touch may sign attacker-chosen bytes. The full render is written to a terminal or console that every process of the same user can also write to. The key blob is usable by any process of the same user that obtains a touch, and such a process can call the platform API with prompt text of its own choosing. Neither the display nor the OS prompt text is a trust boundary: line 1 of the render, which the signer puts into the OS prompt, is an aid. No security property of this profile depends on what a person read.

The fold and the verifier MUST stay safe under one arbitrary signature per tricked touch.

### 1.3 Two persons for every trust change

Changing an organization's trust state always requires at least two distinct persons. Every chain act (`device.add`, `device.remove`, `member.add`, `chain.resolve`) and every genesis change needs counted signatures from Q distinct persons, where Q is the policy's `persons` value for that rule. The profile fixes `persons >= 2` (GP-02). A genesis document may set Q at or above that floor, never below it. A genesis change may lower Q, down to the floor, only with the previous quorum (GP-19).

Costs of this rule: adding your own new phone needs another person's touch; single-person and two-person organizations cannot exist in version 1; recovery stays out of scope.

### 1.4 What one tricked touch can do

This list is complete. One tricked touch can:
- sign one non-chain act. Line 1 names the request or the decision, its hash12 and its size;
- be one person's signature inside a Q-person chain act or genesis change. Together with a removed key an attacker still holds, used at a node outside that key's removal subtree, this is the route described in section 14, L1: with Q = 2 one touch mints a key for a second person on a new branch, which then grows with no further touch and freezes the organization until an honest genesis change and a re-pin on every machine;
- complete a stale chain primary that already carries Q-1 persons' counted signatures. If its parent is the tip and has no other child, it applies: it adds or removes exactly the key those Q-1 persons signed for, however old their signatures are (chain primaries carry no expiry). Otherwise it causes one freeze: a fork at its parent, or a current resolve that stops being current. One new resolve that examines it lifts that freeze, if Q persons can still sign one;
- complete a pending `chain.resolve` that already carries Q-1 persons' counted signatures. If it is then current (FO-25), it takes effect: it lifts the fork it names (which can make active again a key removed only on a branch it discards, section 14, L8), or, if its primary names an applied resolve together with that resolve's completion evidence, it replaces the applied choice. If an applicable resolve it must name is not named by an effective entry (in particular any resolve that completed after its primary was signed), it is not current, every resolve it disagrees with that does not name it is not current either, and the parent is a fork until one resolve names it with evidence;
- complete a stale genesis change that already carries every other signature. The result is a valid successor document. Nothing moves until a person re-pins, and consumers whose relay knows the successor refuse non-chain acts of the old epoch until then;
- nothing else. It cannot invalidate a genesis change or move a pin. It adds, removes or revives a key, or changes an applied choice, only in the ways listed.

An applied choice at a fork changes only through an act that Q persons signed, tricked touches counted, never by fewer, and never by a resolve whose primary was signed before the overridden resolve completed. The one exception to the last clause: if the attacker fixed in advance the bytes of any signature in the overridden resolve's completing set (its primary included; a same-user process can sign bytes of its own choosing, nonce and `ts` included), the attacker can precompute every receipt id an overriding resolve must name, so that resolve's primary can precede the completion. That still costs a tricked touch inside the completing set, and the overriding resolve still needs Q persons' signatures. With Q = 2, one person's proposal made after seeing the applied choice plus one tricked touch is such an act; nothing in the fold distinguishes it from an honest decision.

## 2. Definitions and constants

### 2.1 Terms

- **person**: a member id. **device**: one signing key of a person, identified by its `kid`. **act**: a vitni signed receipt (JWS compact serialization) whose payload follows section 3.
- **hashstr**: `"u" + base64url_nopad(0x12 0x20 || sha256(bytes))`, 47 characters. The canonical encoding is enforced by decode, re-encode, compare (vitni CONTRACT.md hash-string rules). Every hashstr starts with the constant `uEi`. `receipt_id(payload)` is the hashstr of the JCS bytes of the payload.
- **EMPTY_HASH**: the hashstr of zero bytes.
- **thumbprint(key)**: the RFC 7638 thumbprint of `{"crv":"P-256","kty":"EC","x":..,"y":..}`, SHA-256, base64url without padding, 43 characters. A device's `kid` is the thumbprint of its signing key.
- **chain primary**: an act of method `device.add`, `device.remove` or `member.add`. **chain act**: a chain primary or a `chain.resolve`. **endorsement**: an `act.endorse` receipt. **bag**: the unordered set of acts a verifier holds.
- **non-chain act**: a verdict (`request.approve`, `request.reject`, `request.needs-info`) or a `decision`: the acts `check-act` and `recheck-act` decide (VR-02 step 4). A non-chain act is never on the chain (FO-15).
- **epoch**: one genesis document and the chain rooted at it. The **root** of an epoch has id hashstr(JCS(document)) and is position 0.
- **position id**: the root id at position 0, otherwise the receipt id of the chain primary at that position.
- **children(n)**: the valid chain primaries whose parent is node n (FO-24). Resolves, endorsements and invalid acts are never children.
- **act tree**, **past cone**, **state at node n** (`S_n`), **accepted chain** and **clean(k, H)**: defined once in FO-26.
- **tip**: the last node of the accepted chain. The fold reports it as `{genesis, id, n}`, where `n` is derived and never signed.
- **counted signature** and **persons(A)**: defined once in FO-23.
- **role holder**: a member whose role is listed in `roles` of any rule of the epoch policy (KC-08, GP-20). Where a requirement counts persons toward one rule `r` it says "holds a role listed in `rules[r].roles`" (GP-02, FO-23 item 3, FO-25, FO-27) and means that rule alone: a member can be a role holder in the first sense and hold no role of `r`. The code takes the first meaning for the device class of KC-08 and the second wherever it meets a quorum.
- **decimal string**: `0` or `[1-9][0-9]{0,8}`.
- **Short forms** (render only): `kid12` is the first 12 characters of a kid; `hash12` is characters 3 to 14 (0-indexed) of a hashstr, that is the 12 characters after the constant `uEi`. Each is written as three groups of four characters joined by one space, `xxxx xxxx xxxx`, 14 characters in all. The separator is never a character of the grouped alphabet: base64url contains `-`, so a hyphen separator would show `pbubEyWn-20K` as `pbub-EyWn--20K`, which two people comparing it aloud cannot tell from another grouping. The groups are cut by position, so a group may begin or end with `-`.

### 2.2 Alphabets

- `member_id`: `[a-z0-9][a-z0-9-]{1,31}`
- `role_id`: `[a-z][a-z0-9-]{0,31}`
- `request_id`: `[a-z0-9][a-z0-9-]{7,35}`
- `class_id`: `[a-z][a-z0-9-]{0,31}`, the form of the `class` of a device in a `device.add` or `member.add` body (ACT-09). A class in a genesis document or a policy is looked up in the registry (KC-01) instead: a string the registry does not list is `class_unknown` in a policy entry and `genesis_schema` in a device entry (GP-15 step 3).
- `text(max)`: 1 to max characters from 0x20 to 0x7E, excluding `"` and `\`. `label` is text(64), `org_name` is text(24).
- `consumer_id`: `[a-z][a-z0-9-]{1,31}`, the name of the consumer a decision is for (VR-18)
- `subject_id`: `[a-z0-9][a-z0-9-]{1,63}`, the id of what a decision is about (VR-18)
- `action`: lowercase ASCII words separated by single spaces, `[a-z]+( [a-z]+)*`, 1 to 24 characters in all: no digit, no hyphen, no leading, trailing or doubled space (VR-18). The bound is the room line 1 of the render leaves for it (RN-03)
- `agree_context`: 1 to 128 bytes, each a printable ASCII character from 0x21 to 0x7E other than `"` and `\` (the signed alphabet of ACT-04 without the space: no space, no control character, nothing outside ASCII), the caller's name for what a derived key is for (SG-16). The form is what a string of the canonical subset can carry, so every context a signer accepts can be written in its input
- `hostname`: lowercase ASCII LDH labels (letters, digits and hyphens) separated by dots, each label 1 to 63 characters long and neither starting nor ending with a hyphen, punycode for internationalized names, no trailing dot, no port, at most 253 characters in all. A 253-character name therefore has at least four labels.
- `time`: `YYYY-MM-DDTHH:MM:SSZ`, a valid calendar date, seconds 00 to 59.
- `_b64` inputs: `bytes_b64`, `request_b64` and `decision_b64` carry raw bytes and are never signed. Each is standard base64 (RFC 4648 section 4) with padding, and canonical: decoding and then encoding gives the input string. A violation is `malformed_input`.

### 2.3 Constants

| Name | Value | Bounds |
|---|---|---|
| MAX_PAYLOAD | 16384 bytes | every signed or hashed value: payload, header, genesis document, `outputs_hash` object (ACT-04) |
| MAX_DEPTH | 8 | nesting of every signed or hashed value (ACT-04) |
| MAX_INPUT | 16777216 bytes (2^24) | the bytes any signer, checker or pin helper reads from its input channel (CF-03, SG-01, GP-21) |
| MAX_NESTING | 64 | nesting of the JSON a checker command or a conformance executable reads from stdin, the root value counting as 1 (CF-03) |
| MAX_EXPIRES_IN_S | 2592000 (30 days) | the signer's bound on `expires_in_s` (SG-04) |
| ADMIT_RESERVE | 1048576 bytes (2^20) | the room `admit` keeps free below MAX_INPUT (CF-11) |
| Pin file size | at most 512 bytes | GP-05 |
| `persons` | 2 to 15, and smaller than the role holders of its rule | GP-02 |
| `clock_skew_s` | 0 to 3600 | GP-02 |
| `max_validity_s`, `max_view_age_s` | 60 to 2592000 | GP-02 |
| `max_tip_age_s` | 60 to 86400 | WT-01 |
| `relays` | 0 to 2 | GP-02 |
| `chain.resolve` caps | `candidates` 2 to 17; `heads` 1 to 16; `overrides` 0 to 16 entries of 1 to 15 endorsements | ACT-09 |
| Render line 1 | at most 80 bytes | RN-03 |
| Render line | at most 100 bytes; longer lines wrap into segments of at most 98 bytes | RN-02 |
| Render length | at most 72 lines | RN-02 |
| Content block | at most 2048 source bytes and 32 block lines; at most 96 escaped bytes per line | RN-05, RN-12 |

No JSON number appears anywhere in any signed or hashed value of this profile. Counts, durations and thresholds are decimal strings.

## 3. Act profile

### ACT-01 Envelope fill and constants

Every act MUST be a vitni receipt with these exact constants: `v="vitni/0.2"`, `binding="local"`, `status="OK"`, `reason=null`, `action_ref=null`, `requester_id=null`, `cost={"rail_ref":null,"tokens":"0","usd_micros":"0","wall_ms":"0"}`, `log_policy="best_effort"`. The payload key set MUST be exactly: `action_ref binding cost ext inputs_hash log_policy method nonce outputs_hash parent_performer_id parent_receipt_hash performer_id reason requester_id status ts v`. No other key is allowed. `parent_performer_id` is always present, as null or a string.

Any deviation is `schema`.

Why: vitni `verify` reads only `performer_id`, `binding`, `method`, `kid` and `alg`, so the profile owns every other envelope field.

- S1: GIVEN a valid approve act WHEN `status` is `"FAILED"` THEN `check-act` returns `schema`. V: sch/status-not-ok, sch/binding-mcp
- S2: GIVEN all constants correct WHEN checked THEN no schema failure is raised on them. V: ok/approve

### ACT-02 Header

The JWS header bytes MUST equal `{"alg":"ES256","kid":"<kid>"}` exactly, with `kid` a 43-character thumbprint. Any other member, member order, whitespace or algorithm is `jws_shape`.

Why: vitni accepts extra header members such as `typ`, `crit` and `b64`; the profile closes the header.

- S1: GIVEN header `{"alg":"ES256","kid":K,"typ":"JWT"}` WHEN checked THEN `jws_shape`. V: jws/header-extra-member, jws/header-key-order

### ACT-03 JWS segments and encodings

An act MUST be three base64url segments without padding. Each segment MUST re-encode canonically: decoding and then encoding gives the input string. The signature MUST decode to exactly 64 bytes (raw R||S). Violations are `jws_shape`.

Why: spare bits in the last base64url character allow several strings per value, so the string alone is not an identity.

- S1: GIVEN a payload segment whose final character carries nonzero spare bits WHEN checked THEN `jws_shape`. V: jws/b64-trailing-bits-header, jws/b64-trailing-bits-payload

### ACT-04 Canonical subset

Every signed or hashed JSON value (payload, header, genesis document, `outputs_hash` object) MUST be in the canonical subset. The subset is two rules.

Grammar. A canonical value is UTF-8 bytes of one JSON value of any root kind, built only from objects, arrays, strings and the literal `null`, where:
- no numbers, no `true` or `false` appear;
- no whitespace appears outside strings;
- object keys are unique, ASCII, sorted by byte order;
- strings contain only bytes 0x20 to 0x7E except `"` and `\`, and no backslash escape of any kind;
- nesting is at most MAX_DEPTH, total size at most MAX_PAYLOAD, and nothing follows the root value.

Root. Every signed payload, JWS header and genesis document MUST additionally be a JSON object. A `null`, array or string root there is `payload_not_canonical_subset`.

The checker `subset` command (CF-03) checks the grammar only. The recognizer MUST run before vitni `verify`. A violation is `payload_not_canonical_subset`; a size violation is `payload_too_large`. MAX_PAYLOAD bounds signed and hashed values only; input framing is bounded by MAX_INPUT (CF-03, SG-01, GP-21).

Why: one grammar removes number formatting, Unicode escaping, surrogates and the `null` header or payload as sources of verifier divergence. The two vitni implementations differ on some of these; none is reachable inside the subset.

- S1: GIVEN a payload with a JSON number WHEN recognized THEN `payload_not_canonical_subset`. V: jcs/number-anywhere, jcs/true-literal
- S2: GIVEN a value using only allowed constructs, nested at depth 8 WHEN recognized THEN valid. V: jcs/depth-8-ok, jcs/null-where-allowed
- S3: GIVEN the string root `"a/b"` WHEN `subset` runs THEN canonical (grammar only). V: jcs/raw-slash-ok
- S4: GIVEN a payload whose root is `null` or an array WHEN checked as a payload THEN `payload_not_canonical_subset`. V: jcs/payload-null, jcs/payload-array

### ACT-05 Canonical emitter

An emitter for the subset MUST output keys sorted by byte order, no whitespace, strings verbatim (`/` unescaped) and arrays in the given order. Emitting, then recognizing, then comparing MUST be the identity for every schema-valid value. A general-purpose JSON serializer whose output is not byte-checked MUST NOT be used.

- S1: GIVEN the draft input for each method WHEN emitted by two implementations THEN the bytes are equal. V: jcs/emit-sorted, jcs/emit-slash-raw, jcs/emit-device-remove, jcs/emit-member-add, jcs/emit-chain-resolve, jcs/emit-endorse, jcs/emit-reject, jcs/emit-needs-info, jcs/emit-decision, jcs/emit-genesis-sign-original, jcs/emit-genesis-sign-change (the approve draft is `cli/build-approve`, CF-03)
- S2: GIVEN the payload of a real signed act of a method WHEN recognized THEN it is canonical and the bytes are the same. V: jcs/emit-roundtrip-approve, jcs/emit-roundtrip-device-add, jcs/emit-roundtrip-device-remove, jcs/emit-roundtrip-member-add, jcs/emit-roundtrip-chain-resolve, jcs/emit-roundtrip-endorse, jcs/emit-roundtrip-reject, jcs/emit-roundtrip-needs-info, jcs/emit-roundtrip-decision, jcs/emit-roundtrip-genesis-sign

### ACT-06 Extension object

`ext` MUST have exactly one key, `dev.handsal/act`, whose value (the act object) is a closed object. Common act-object keys for every method: `body`, `kid` (ACT-14), `org`. `head` is present exactly where the ACT-09 `head` column says so and MUST be absent everywhere else. Further keys per method are listed in ACT-09. Unknown keys anywhere are `schema`. Absent keys are errors: no key is optional except `head` as ACT-09 defines it.

- S1: GIVEN `ext` with a second key `x.other` WHEN checked THEN `schema`. V: sch/ext-extra-key, sch/ext-missing
- S2: GIVEN a `device.add` act object carrying `head` WHEN folded THEN it is not on the chain (closed schema). V: sch/chain-primary-with-head

### ACT-07 Field formats

These fields MUST be canonical hashstr: `inputs_hash`, `outputs_hash`, `nonce`, `parent_receipt_hash` when non-null, `org`, `head.id`, `link_code_hash`, the endorsement `body.act`, and in a `chain.resolve` body `choose`, every `candidates[]` and `heads[]` entry, every `overrides[].resolve` and every `overrides[].endorsements[]` entry. `nonce` MUST be the hashstr of 32 bytes from a cryptographically secure random source. `ts` and `expires` MUST be `time`. `performer_id` and every person id MUST be `member_id`. Decimal-string fields MUST match the decimal-string grammar. Any violation is `schema`.

ACT-07 owns the form of every hashstr field, so a non-canonical hashstr anywhere, a `chain.resolve` body included, is `schema`. ACT-09 owns structure only (closed objects, array lengths, sort order, distinctness), which is `body_schema`. One defect yields one code.

The one exception is the fixture profile: its fixtures and the vector generator derive every `nonce` from the other inputs of the act, so that every vector is the same bytes on every run, and `emit` takes the nonce from `fixed` (SG-04). A verifier checks the form and cannot tell the two sources apart. Production acts never meet the exception: a production checker refuses the fixture profile (GP-18, CF-08), and a production signer fills the nonce from a random source itself (SG-04).

- S1: GIVEN `inputs_hash` with nonzero trailing bits WHEN checked THEN `schema`. V: sch/hashstr-trailing-bits, sch/hashstr-wrong-code
- S2: GIVEN a resolve in which `overrides[0].endorsements[0]`, `overrides[0].resolve`, `candidates[0]`, `heads[0]` or `choose` has nonzero trailing bits, and which would otherwise lift a fork, WHEN folded THEN the resolve is ignored (it fails ACT-07, ACT-09) and the output is the fork at its parent. `check-act` never reads a resolve (VR-02 step 4), so this case is observable through `fold` only. V: rsv/override-entry-non-canonical-hashstr, rsv/override-resolve-non-canonical-hashstr, rsv/candidate-non-canonical-hashstr, rsv/head-non-canonical-hashstr, rsv/choose-non-canonical-hashstr

### ACT-08 Head

`head` MUST be exactly `{"id":hashstr,"kind":"chain"}`. `id` is the position id of the chain position the signer saw: the receipt id of that position's primary, or the current genesis document hash at position 0. There is no `n`: the position number is derivable from `id` and the chain, so signing it would create a second source for one value. The fold output `tip` carries `n` as a derived value. `kind` is closed for this profile: any other value, or any extra member such as `n`, is `schema`. A future signed log head would be a new kind under a new profile hash. Relay freshness is not a head kind (WT-09): a relay tip statement is verifier input, so act bodies are identical in every witness mode.

`head` appears in verdicts, `decision`, `act.endorse`, and `genesis.sign` over a genesis change, where `head.id` equals the change document's `head` (GP-19). Chain primaries and `chain.resolve` never carry it: their `parent_receipt_hash` is the head, and the closed schema forbids the duplicate. `genesis.sign` over an original document carries none.

The caller of a signer supplies `head`; the signer does not fold. A caller on a machine with a store gets it from `head` (VR-19). The checker validates it (VR-12, FO-08, GP-19).

- S1: GIVEN `head.kind` `"merkle"` WHEN checked THEN `schema`. V: sch/head-kind-unknown, sch/head-has-n

### ACT-09 Method registry and closed schemas

Exactly these methods exist, all with `binding="local"`. Any other string is `method_unknown`. Methods are matched byte-exact, with no case folding.

| Method | Act-object extra keys | `head` | `body` (closed) | `inputs_hash` | `outputs_hash` |
|---|---|---|---|---|---|
| `local:handsal.genesis.sign` | none | present iff the document's `prev` is non-null | `{}` | hashstr(JCS(genesis document)) | EMPTY_HASH |
| `local:handsal.device.add` | none | never | `{agree:{x,y}, class, kid, label, link_code_hash, person, sign:{x,y}}` | EMPTY_HASH | EMPTY_HASH |
| `local:handsal.device.remove` | none | never | `{kid, person}` | EMPTY_HASH | EMPTY_HASH |
| `local:handsal.member.add` | none | never | `{device:{agree:{x,y}, class, kid, label, sign:{x,y}}, link_code_hash, member, role}` | EMPTY_HASH | EMPTY_HASH |
| `local:handsal.chain.resolve` | none | never | `{candidates, choose, heads, overrides}` | EMPTY_HASH | EMPTY_HASH |
| `local:handsal.act.endorse` | none | always | `{act}` (receipt id of the endorsed chain act) | EMPTY_HASH | EMPTY_HASH |
| `local:handsal.request.approve` | `expires`, `recipient`, `relay`, `request_id` | always | `{}` | hashstr(raw request bytes) | hashstr(JCS({"request_id":R,"verdict":"approve"})) |
| `local:handsal.request.reject` | same | always | `{}` | same | verdict `reject` |
| `local:handsal.request.needs-info` | same | always | `{}` | same | verdict `needs-info` |
| `local:handsal.decision` | `expires` | always | `{action, consumer, subject}` | hashstr(raw decision bytes) | hashstr(JCS({"action":A,"subject":S})) |

Field types: `x` and `y` are base64url of 32 bytes (43 characters, canonical); `class` is a registry id (KC-01); `kid` is a 43-character thumbprint; `person`, `member` and `recipient` are `member_id`; `role` is one `role_id` listed in the epoch policy `roles` (each member holds one role); `relay` is a `hostname`; `request_id` is `request_id`; `label` is `label`; `consumer` is a `consumer_id`; `subject` is a `subject_id`; `action` is an `action`.

`chain.resolve` body, all keys required:
- `candidates`: 2 to 17 distinct hashstr, sorted ascending; `choose` is one of them;
- `heads`: 1 to 16 distinct hashstr, sorted ascending;
- `overrides`: 0 to 16 entries, sorted ascending by `resolve` (byte order), `resolve` values distinct. Each entry is exactly the closed object `{"endorsements":[...],"resolve":R}`, with `endorsements` 1 to 15 distinct hashstr sorted ascending.

The relations of these ids to the act tree are FO-25, not schema.

There is no `request.send` method and no sequence number. `inputs_hash` and `outputs_hash` are derived from the method and its inputs; checker and signer recompute them and never trust a supplied value. For a non-chain act, `inputs_hash` is checked by VR-06 and `outputs_hash` by VR-07. For a chain act and for `genesis.sign`, a hash that is not its fixed value in the table (EMPTY_HASH, or the document hash for the `inputs_hash` of `genesis.sign`) makes the act invalid for its method: the fold ignores a chain act (FO-06), and a `genesis.sign` does not count (GP-15), so its device is `genesis_unsigned` unless another signature of that device counts. No reason code is output for the hash itself: `check-act` never decides these methods (`chain_method`, VR-02 step 4), and the fold outputs no code for an ignored act.

A shape violation of a body is `body_schema`; in the fold the act is ignored.

`local:handsal.relay.tip` is the relay tip statement method (WT-02). It is not in this registry, so as an act it is `method_unknown`, and the fold ignores it.

`local:handsal.record.promote` is retired and never reused. It signed a `record_id` and `anchors` that no verifier compared and named no consumer. A record promotion is a `local:handsal.decision` whose `consumer`, `action` and `subject` the consumer chooses, with the record as its content (VR-18). The retired method is not in this registry: as an act it is `method_unknown`, as a draft `unsupported_method` (SG-04), and the fold ignores it.

- S1: GIVEN `local:handsal.request.send` WHEN checked THEN `method_unknown`. V: mth/request-send, mth/case-variant
- S2: GIVEN an approve whose `outputs_hash` was computed for verdict `reject` WHEN checked THEN `outputs_mismatch`. V: vrd/outputs-verdict-swapped
- S3: GIVEN a `device.add` body missing `link_code_hash` WHEN folded THEN the act is not on the chain. V: bod/device-add-missing-link-code, bod/device-add-extra-key
- S4: GIVEN a `member.add` whose `role` is not listed in policy `roles` WHEN folded THEN it is not on the chain. V: bod/member-add-role-unlisted
- S5: GIVEN a resolve whose `overrides` entry is not the closed `{endorsements, resolve}` object WHEN folded THEN the resolve is ignored and the fork stays (`fork`); the same resolve checked is `body_schema`. V: rsv/override-entry-shape-schema, rsv/override-entry-bare-hashstr-schema, rsv/override-entry-sixteen-endorsements-schema
- S6: GIVEN a relay tip statement passed as an act WHEN checked THEN `method_unknown`. V: wit/statement-as-act
- S7: GIVEN a resolve whose body has a key besides `choose` WHEN folded THEN the resolve is ignored. V: bod/resolve-extra-key
- S8: GIVEN a `decision` whose body has a key besides `action`, `consumer` and `subject`, or whose act object carries `recipient` WHEN checked THEN `body_schema`, and `schema` for the act object. V: dec/body-extra-key-body-schema, dec/recipient-key-schema
- S9: GIVEN an act or a payload of the retired `local:handsal.record.promote` WHEN checked or rendered THEN `method_unknown`; GIVEN its draft WHEN emitted THEN exit 2, `unsupported_method`. V: mth/record-promote-retired, rnd/record-promote-retired-refused, sgn/record-promote-retired-refused

### ACT-10 Signed strings are ASCII

No signed string may contain a byte outside the alphabets of section 2. Request text and decided content are only hashed, never embedded.

A byte outside 0x20 to 0x7E, a `"` or a `\` never reaches an alphabet check: the recognizer refuses the payload first (`payload_not_canonical_subset`, ACT-04), and a genesis document holding one is `genesis_schema` (GP-01). A string of allowed bytes that is outside the alphabet of its field is `schema` when the field is an ACT-07 form or a key of the act object (`kid`, `recipient`, `relay`, `request_id`, `expires`, `head`), and `body_schema` when it is a field of `body` (VR-02 step 5), the three fields of a `decision` body included (VR-18). `relay` is no ACT-07 form: it takes the code of its container, the act object. The label alphabet of a `device.add` or `member.add` body is seen only as state: `check-act` stops at `chain_method` (step 4) and the fold ignores the act without giving a reason, so no reason code of that case is a vector (CF-07).

Why: this removes Unicode normalization, confusable characters, bidirectional controls and escape divergence from signed bytes. The cost is that labels are ASCII in version 1; widening the alphabet changes the profile hash.

- S1: GIVEN a payload with a string containing U+00E9 WHEN recognized THEN `payload_not_canonical_subset`. V: jcs/raw-non-ascii-e9, jcs/key-non-ascii
- S2: GIVEN a verdict whose `relay` is `R.example` WHEN checked THEN `schema`. V: rly/uppercase-relay-schema

### ACT-11 kid and key encoding

`kid` MUST equal the thumbprint of the key it names. `x` and `y` MUST decode to exactly 32 bytes, including a leading zero byte when a coordinate is small. The point MUST be on P-256. A violation makes the introducing act invalid (the fold ignores it) or the genesis document invalid (`genesis_key_invalid`; `duplicate_key` for a repeated `kid` or `agree` key).

- S1: GIVEN a `kid` that is not the thumbprint of `sign` WHEN folded THEN the act is not on the chain. V: key/kid-not-thumbprint, key/x-31-bytes
- S2: GIVEN `{x,y}` WHEN the checker `kid` command runs THEN it returns the thumbprint (CF-03). V: cli/kid-ok, cli/kid-leading-zero

### ACT-12 Replay identity

The identity of an act is its receipt id, never its signature string. Two signatures over one payload are one act. Because the act object names the signing kid (ACT-14), one receipt id has exactly one signer.

- S1: GIVEN the same payload with low-S and high-S signatures WHEN deduplicated THEN one receipt id. V: rep/same-payload-two-sigs, rep/same-payload-low-s-same-receipt-id

### ACT-13 Envelope fields per method

| Method | `parent_receipt_hash` | `parent_performer_id` | `performer_id` |
|---|---|---|---|
| verdicts (`request.*`) | null | null | `recipient` of the act object (VR-05) |
| `decision` | null | null | the person of the signing device (enforced through the vitni keys map, VR-03) |
| `genesis.sign` | null | null | the person of the signing device: from the document for possession, from `S_H` for authority (below) |
| `device.add`, `device.remove`, `member.add` | the parent position id, never null (FO-04) | the parent's performer, null iff the parent is the root | the primary signer's person |
| `chain.resolve` | the fork parent P | the performer at P, null iff P is the root | the signer's person |
| `act.endorse`, counted | receipt id of the endorsed act | that act's `performer_id` | the endorser's person |
| `act.endorse`, proof of possession | same | same | the new device's person (`body.person`; for `member.add`, `body.member`) |

A parent field that differs from the table is `schema` at `check-act` step 5 (VR-02). A `performer_id` that is a `member_id` but not the person the table names is not `schema`: for verdicts it is `identity_mismatch` at step 11 (VR-05), and for `decision` it is `unknown_key` at step 9 (VR-03). In the fold the act is ignored or the signature does not count.

A `genesis.sign` over a change document D with head H is read by two independent tests:
- **Possession** (GP-15 step 6): it counts iff it passes ACT-01 to ACT-14 for `genesis.sign`, its kid is listed in D, its `performer_id` is the `person` of that listed device, and the rest of the GP-15 counting rule holds.
- **Authority** (GP-19, GP-15 step 8): it counts iff it passes ACT-01 to ACT-14 for `genesis.sign`; its `head.id` is H; `inputs_hash` is hashstr(JCS(D)); `org` is the original org id; its kid is a device of `S_H`, listed in D or not; `performer_id` is that device's `person` in `S_H`; vitni `verify` is ok with the one-entry keys map of that `S_H` device; S is low; and the key meets clean(k, H) and the role condition of GP-19.

A signature passing neither test is ignored. Original documents have no authority test. When D lists a kid of `S_H` under another person, one signature passes at most one test, and the GP-15 order decides the code: step 6 `genesis_unsigned` if possession fails, else step 8 `genesis_change_unauthorized` if authority fails, else step 9 `genesis_device_changed` (GP-20).

Every test of whether an act or a signature passes the act rules (possession, authority, every act attachment of RN-09, nested ones included) applies ACT-01 to ACT-14 in full, never a subset. ACT-09 (the closed `{}` body of `genesis.sign`) and ACT-14 therefore decide both genesis tests.

Why: every signed envelope field has exactly one allowed value or source per method, so no field is free for a caller to fill.

- S1: GIVEN an approve whose `parent_receipt_hash` is the tip WHEN checked THEN `schema`. V: sch/verdict-parent-nonnull, sch/verdict-parent-performer-nonnull
- S2: GIVEN a change listing alice's carried kid under bob, signed by that kid with `performer_id` bob WHEN folded THEN `genesis_device_changed`. V: chg/carried-kid-other-person-device-changed
- S3: GIVEN a `genesis.sign` whose body is not `{}`, or whose act-object `kid` differs from its header kid WHEN folded THEN that device is unsigned (`genesis_unsigned`). V: gen/sign-body-not-empty-unsigned, gen/sign-act-kid-differs-unsigned

### ACT-14 Signer kid inside the signed object

The act object carries the common key `kid` for every method. It MUST equal the JWS header `kid` (ACT-02). A mismatch or absence is `schema` at `check-act` step 5; in the fold the act is ignored or the signature does not count. The signer fills it (SG-04). The relay tip statement keeps its closed act object `{body, org}` (WT-02): it is not an act.

Why: the receipt id then binds the signing key, so another key cannot re-sign the same payload under the same receipt id.

- S1: GIVEN alice2 re-signs alice's payload WHEN checked THEN `schema` (the act object names alice's kid). V: sch/act-kid-differs-from-header, sch/act-kid-missing

## 4. Key classes

### KC-01 Registry

The profile owns a closed registry, `spec/registry.json`, covered by the profile hash (CF-01). Each class has `id`, `alg` (only `ES256` in version 1), `hardware_bound`, `per_signature_user_verification`, `user_verification` (`biometric_only`, `biometric_or_pin` or `none`) and `status` (`active`, `pending-spike` or `test-only`). Adding a class is a new registry entry and a new profile hash, never a schema change. An id not in the registry is `class_unknown`. The first release is macOS only, so the registry lists `apple-se-bio` and the test class; the Windows class returns with the Windows release and a registry version bump (KC-02).

| id | alg | hardware_bound | per_signature_user_verification | user_verification | status |
|---|---|---|---|---|---|
| `apple-se-bio` | ES256 | true | true | `biometric_only` | `active` |
| `test-sw-p256` | ES256 | false | false | `none` | `test-only` (KC-07) |

Both properties describe the signing key of a device. The agreement key has no class property and no per-use verification (KC-09).

The registry also carries a `fixture_only` list, recognized only under the fixture profile (GP-18). Under a production profile its ids are `class_unknown`. Version 1 lists one entry: `fixture-pin` (ES256, `hardware_bound` false, `per_signature_user_verification` true, `user_verification` `biometric_or_pin`, `status` `active`). It exists so KC-08 vectors never depend on a platform evaluation.

- S1: GIVEN a `device.add` with class `yubikey-piv` WHEN folded THEN it is not on the chain. V: cls/unknown-class-device-add, cls/unknown-class-genesis

### KC-02 Classes pending evaluation

A class with status `pending-spike` MUST NOT appear in any genesis policy `classes` (`class_pending`). A tagged registry never contains `pending-spike`, so no vector can show `class_pending` and CF-07 proves it with implementation tests on a registry that has such a class.

The first release is macOS only. The Windows Hello evaluation has not reported, so `win-hello-hw` is not in the registry of that release, and a genesis that lists it is `class_unknown`. The class is added back in the Windows release, once the evaluation has decided it, with exactly one of two outcomes (KC-08): it is `active` with `user_verification` `biometric_only`, or it is `active` with `user_verification` `biometric_or_pin`; either is a new registry entry and a registry version bump (KC-01). If the evaluation finds no usable key, the class stays out.

- S1: GIVEN a registry that holds a class with status `pending-spike` and a genesis accepting it WHEN folded THEN `class_pending`; GIVEN the registry of the first release and a genesis accepting `win-hello-hw` THEN `class_unknown`. T: checker/python/tests/test_policy.py::test_pending_class_cannot_be_listed, checker/python/tests/test_policy.py::test_the_windows_class_is_not_in_the_first_tag, signer/apple/Tests/HandsalCoreTests/GenesisTests.swift::aPendingClassIsRefusedOnARegistryThatHasOne, signer/windows/tests/forms_keys.rs::a_pending_class_is_refused_on_a_registry_that_has_one
- S2: GIVEN the registry at the tag WHEN the tag check runs (`check_catalog.py --final`) THEN no class is `pending-spike`. T: tools/tests/test_catalog.py::test_the_final_check_refuses_a_registry_class_that_is_pending_the_spike

### KC-03 user_verification is data

A class's `user_verification` MUST be a property of its registry entry, never inferred from the platform. A genesis policy accepts a class only by listing the pair `{class, user_verification}`, with `user_verification` equal to the registry value at the document's `profile`. A mismatch is `class_policy_mismatch`.

Why: the people signing a genesis decide on an exact property set, so a registry change that alters a class's verification makes an old policy entry fail closed instead of silently weakening it.

With a `biometric_or_pin` class, a same-user process that captures or injects the PIN signs with no person present. KC-08 keeps such classes off role holders; section 14 states what remains.

- S1: GIVEN policy entry `{class:"apple-se-bio", user_verification:"biometric_or_pin"}` WHEN folded THEN `class_policy_mismatch`. V: cls/uv-mismatch. C: cls/nonrole-pin-device-ok

### KC-04 Accepted and unproven keys

A key is **accepted** iff its class is listed in the epoch policy `classes` (KC-03) and GP-18 does not exclude it. A key that is not accepted:
- is absent from the fold `keys` map (FO-02) and present in `devices` with `accepted:false`;
- counts toward no authority: no quorum signature, no endorsement, no consent, no resolve, no genesis change;
- yields `check-act` `{valid:false, reason:"unproven_class"}` when its signature verifies (VR-02 step 16), never human proof.

`valid:true` from `check-act` is the only signal that an act may be acted on now, and `rechecked:true` from `recheck-act` (VR-17) is the same proof of a human decision for an act the consumer stored, without the moment. Neither is returned for a key that is not accepted, so a consumer that tests `valid` or `rechecked` cannot treat an unproven key as a person by accident. The decision is data in the genesis document; no code names a class.

- S1: GIVEN a verdict signed by a key whose class is not in the policy WHEN checked THEN `valid:false`, `unproven_class`. V: cls/verdict-unproven
- S2: GIVEN the same acts and a policy that lists the class WHEN checked THEN `valid:true`, with no code change. V: cls/policy-swap-human
- S3: GIVEN an endorsement by a key that is not accepted WHEN folded THEN it does not count. V: cls/unproven-endorsement-ignored, cls/unproven-self-remove-ignored

### KC-05 Single algorithm

Only ES256 keys on P-256 exist. Device entries have no `alg` member. A device entry carrying one, or a key that is not a P-256 point, is invalid.

- S1: GIVEN a genesis device entry with an `alg` member WHEN folded THEN `genesis_schema`. V: cls/ed25519-device

### KC-07 Test class and fixture keys

`test-sw-p256` exists only for signer plumbing tests (a separate software test binary) and for exercising `unproven_class` in consumers. A policy listing it is `class_test_only`; its keys are never accepted. No mode, flag or policy changes that.

Fixture keys (`conformance/fixtures/keys.json`, listed in `conformance/fixtures/fixture-kids.json`, the relay fixture key included) are governed by GP-18: never accepted under a production profile, and treated as their labelled class under the fixture profile. The enrollment ceremony also refuses any listed kid (SG-12).

- S1: GIVEN a policy listing `test-sw-p256` WHEN folded THEN `class_test_only`. V: cls/test-class-listed
- S2: GIVEN a fixture device kid under a production profile WHEN `enrolled` runs THEN false, `fixture_key` from the fold. V: enr/fixture-kid
- S3: GIVEN a production policy whose `relay_kid` is the fixture relay key WHEN folded THEN `fixture_key`; WHEN the ceremony runs THEN it refuses before any write (an SG-12 ceremony implementation test, CF-07). P: fix/prodk-relay-fixture-kid
- S4: GIVEN a `device.add` of a `test-sw-p256` key and then a verdict signed by it WHEN `check-act` runs THEN `valid:false`, `unproven_class`. V: cls/test-class-key-unproven

### KC-08 Role-holder key class

Every device of a role holder MUST have a class whose registry `user_verification` (KC-01, at the document's profile) is `biometric_only`. The value is read from the registry whether or not the policy accepts the class; for an accepted class it equals the policy entry (KC-03). Devices of other members have no restriction beyond KC-04.

The predicate is evaluated where a device enters state, and nowhere else:
- (a) each genesis document, original or change, over all its devices including carried ones: a violating device is `role_key_class` (GP-15 step 3);
- (b) `device.add` and `member.add` (FO-22): a new key whose class violates the predicate for the person's role is not on the chain.

Roles are fixed at `member.add` (there is no role-change act), and every change document re-evaluates the predicate, so a later role listing cannot leave a PIN-capable key on a role holder.

Consequence: every key whose touch can count toward Q, or give consent for a role holder, has a biometric-only declared class. A key of a PIN-capable class is allowed only for members who are not role holders; it never counts toward a quorum (FO-23 requires a listed role) and is never a role holder's consent.

Windows: the first release has no Windows class (KC-02). When the Windows release adds `win-hello-hw`, and if the evaluation finds no hardware key, no prompt, or no use from WSL2, the class stays out. Otherwise it is added as `active` with exactly one `user_verification`: `biometric_only` if Windows Hello can be required to be biometric-only per key (fingerprint reader or infrared face camera, PIN excluded), else `biometric_or_pin`. In the second case a genesis listing it for a role holder is `role_key_class`, so a Windows user cannot be a role holder through that class. Nothing is accepted silently.

KC-08 vectors use the fixture-only class `fixture-pin` under the fixture profile.

- S1: GIVEN a PINORG genesis whose maintainer alice also holds a `fixture-pin` device WHEN folded THEN `role_key_class`; GIVEN only dave (role `member`) holds one THEN the state. V: cls/role-holder-pin-genesis-refused. C: cls/nonrole-pin-device-ok
- S2: GIVEN alice and bob add a `fixture-pin` device for alice, or a `member.add` of maintainer frank with one, WHEN folded THEN it is not on the chain; with `apple-se-bio` THEN applied; GIVEN a policy that does not accept `fixture-pin` THEN still not on the chain (registry value). V: cls/role-holder-pin-device-add-not-on-chain, cls/role-holder-pin-member-add-not-on-chain, cls/role-holder-biometric-member-add-ok, cls/role-holder-unaccepted-pin-class-not-on-chain
- S3: GIVEN dave's `fixture-pin` key endorses an act of alice WHEN folded THEN it is not counted. V: cls/pin-key-never-counts

### KC-09 The agreement key

A device has two keys with two jobs and two access rules. The signing key, `sign`, is the person's authority: its class carries the properties of KC-01 and every signature needs a fresh presence (SG-05). The agreement key, `agree`, is the device's: it exists so that the device can take part in a key agreement (SG-16), it is created without per-use presence, and no class property describes it. On the Apple class its access control is private key use only, never biometry. The rule is fixed at creation: device entries are immutable (GP-20) and a removed kid never returns (FO-07), so a device's agreement key cannot later be changed to require presence without replacing the device.

An agreement key never signs. The verifier takes keys from the fold `keys` map only (FO-02), `agree` is never in it, and a `kid` is the thumbprint of `sign` alone, so no signature made with an `agree` key verifies as an act. The signer never uses `agree` for a signature and never uses `sign` for an agreement (SG-16).

Why: reading what was sealed to a device is not a human decision, so it needs no touch, and a touch for every read would train the blind touching that SG-10 exists to prevent. Human authority stays on the presence-gated signing key. What a process running as the user can do with the agreement key, and what it still cannot do, is stated in section 14, L17.

- S1: GIVEN a fold of an organization WHEN read THEN `agree` appears in `devices` and in no `keys` entry. V: fld/agree-not-in-keys
- S2: GIVEN a signer with a bound key WHEN it signs THEN the signature verifies under `sign` and under no other key of the device, and what `agree` returns is a derived key, never a signature. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::aSignatureNeverVerifiesUnderTheAgreementKey
- S3: GIVEN `keygen` on the Secure Enclave WHEN the two keys are made THEN `sign` carries the biometry flag and `agree` carries private key use only, and an agreement runs with no finger. T: signer/apple/Tests/HandsalCoreTests/AgreeTests.swift::theAgreementKeyIsCreatedWithoutPresence, signer/apple/Tests/HandsalCoreTests/SecureEnclaveTests.swift::theSecureEnclaveAgreementKeyWorksWithNoPresence

## 5. Genesis and pin

### GP-01 Genesis document

A genesis document is a canonical-subset object (ACT-04) with exactly these keys: `devices`, `members`, `name` (`org_name`), `org` (null in the original, else the original org id), `policy` (GP-02), `prev` (null in the original, else hashstr(JCS(previous document))), `profile` (a profile hash, CF-01), `v` = `"handsal-genesis/1"`, and `head`. `head` is the canonical hashstr of the node H a change is made at (GP-19); it is required iff `prev` is non-null and forbidden otherwise. The presence of `policy` belongs to GP-02: a document without `policy` is `policy_invalid` (GP-15 step 3), and any other missing or extra key is `genesis_schema`.
- `devices`: a list sorted by `kid`, entries `{agree:{x,y}, class, kid, label, person, sign:{x,y}}`.
- `members`: a list sorted by `id`, entries `{id, role}`, with `role` a `role_id` listed in `policy.roles` (GP-02).

Sorted means ascending in byte order, equal neighbours allowed, so a repeated entry is never `doc_not_sorted` and its own rule decides. Unsorted lists are `doc_not_sorted`: one document has one byte form and one hash. The lists are `devices`, `members` and, in `policy`, `classes`, `relays`, `roles` and the `roles` of each rule; a policy list whose entries are too malformed to order is `policy_invalid` (GP-02). Every device's `person` is a listed member, every member has at least one device, `kid` equals the thumbprint of `sign`, `agree` differs from `sign`, and no kid or agree key repeats. The org id is hashstr(JCS(original document)). It is stored in every later document's `org`, and in no document's own bytes before it exists.

"Every member has at least one device" is a rule on a document, which is a snapshot of one epoch. A state inside an epoch may hold a member with no device (FO-27), and a change made at a node of such a state either lists a device for that member, with its possession signature (else `genesis_unsigned`), or leaves that member out (and GP-02 still binds: `policy_unreachable` where no spare person is left); a change that lists the member with no device is `genesis_schema`. No other rule caps the devices of an organization: a document whose `genesis.sign` render exceeds 72 lines is `genesis_render_too_large` (GP-15 step 5), which bounds the devices one document can list or add, and MAX_INPUT bounds a store; an organization grows through chain acts (RN-10).

Structure violations, `head` included and a repeated member `id` too, are `genesis_schema`: so are a document that is not an object, a value outside the canonical subset (ACT-04), and a `profile` that is not a canonical hashstr. `profile_mismatch` is only for a well-formed profile hash the implementation does not implement (GP-15 step 2). Key problems are `genesis_key_invalid` or `duplicate_key`.

- S1: GIVEN members listed out of order WHEN folded THEN `doc_not_sorted`. V: gen/unsorted-members, gen/unsorted-devices
- S2: GIVEN a change without `head`, or an original with `head`, WHEN folded THEN `genesis_schema`. V: chg/document-head-missing-schema, chg/original-with-head-schema

### GP-02 Policy

`policy` MUST be exactly:
- `classes`: a non-empty list of `{class, user_verification}`, sorted by `class`, unique (KC-02, KC-03, KC-07).
- `freshness`: `{clock_skew_s, max_validity_s, max_view_age_s}`, decimal strings, with `0 <= clock_skew_s <= 3600`, `60 <= max_validity_s <= 2592000` and `60 <= max_view_age_s <= 2592000`.
- `relays`: a sorted, unique list of 0 to 2 `hostname` values (section 2.2): the relay hostnames a verdict may name (VR-08). It is required: a policy without it is `policy_invalid`, never read as an empty list. A repeat or a non-hostname entry is `policy_invalid`, an unsorted list `doc_not_sorted` (GP-01), three or more entries `policy_out_of_bounds`. An empty list is valid: every verdict is `relay_mismatch` until a genesis change names a host.
- `roles`: a non-empty, sorted, unique list of `role_id`. Every role used in `members` or `rules` is listed.
- `rules`: exactly the keys `chain.resolve`, `device.remove`, `genesis.change`, `member.add`, each `{persons, roles}`, with `persons` a decimal string and `roles` a non-empty, sorted, unique list of role ids. `rules["device.remove"]` governs every `device.add` and every `device.remove` (FO-22).
- `v` = `"handsal-policy/1"`.
- `witness`: `{"mode":"none"}` or `{"max_tip_age_s","mode":"relay","relay_kid","relay_pub_jwk"}`, with the schema, bounds and key rules of WT-01. It is required: a policy without it is `policy_invalid`, never read as `none`.

Bounds on `persons`: `2 <= persons <= 15`, else `policy_out_of_bounds`. Each rule's `persons` MUST also be smaller than the number of members holding a role listed in that rule's `roles`, else `policy_unreachable`. Every rule therefore has at least one spare person: single-person and two-person organizations are refused, as is any organization where a rule's `persons` equals its role holders. The check runs for the original and for every change document (GP-15 step 3). Q is bounded in this one place: floor 2, ceiling the smaller of 15 and the rule's role holders minus 1.

Validation codes: a missing, extra or malformed field, a repeated entry in a list that must be unique, and a role used in `members` or `rules` that `roles` does not list are `policy_invalid`; a violated bound is `policy_out_of_bounds`; the spare rule is `policy_unreachable`; class problems are `class_unknown`, `class_pending`, `class_test_only` and `class_policy_mismatch`.

Endorsement mechanics are fixed by the profile, not by policy (FO-08, FO-23). The fold reads the policy and never names a role, a threshold, a duration or a class. Appendix B shows an example policy.

Why the ceiling: every applicable resolve must be nameable within the 15-endorsement cap of an `overrides` entry (ACT-09, FO-27), so the cap never decides whether a fork can be lifted. Why the spare: every rule stays reachable after one person loses every device.

- S1: GIVEN a document without `freshness` WHEN folded THEN `policy_invalid`. V: pol/missing-freshness
- S2: GIVEN identical acts and a document with `persons "3"` instead of `"2"` (ORG4) WHEN folded THEN a different result with no code change. V: quo/policy-swap-2-vs-3
- S3: GIVEN ORG4 with `device.remove` persons `"3"` and alice and bob remove carol's device WHEN folded THEN it is not on the chain; GIVEN carol's endorsement too THEN applied. V: quo/raised-floor-3-two-rejected, quo/raised-floor-3-three-applied
- S8: GIVEN `rules["device.remove"].persons` `"1"` WHEN folded THEN `policy_out_of_bounds`; GIVEN `"16"` THEN `policy_out_of_bounds`. V: pol/persons-one-refused, pol/persons-16-out-of-bounds
- S4: GIVEN three maintainers and `persons "2"` THEN the state; GIVEN `persons "3"` THEN `policy_unreachable`; GIVEN two maintainers and `persons "2"` THEN `policy_unreachable`; GIVEN a change dropping one of three maintainers with `persons "2"` THEN `policy_unreachable`. V: pol/persons-equals-role-holders-refused, pol/two-person-org-refused, pol/change-removing-spare-refused, pol/single-person-org-unreachable. C: pol/org3-2-of-3-ok
- S5: GIVEN a document without `policy` WHEN folded THEN `policy_invalid`, not `genesis_schema`. V: pol/missing-policy
- S6: GIVEN a `relays` that is missing, unsorted, repeated, three long or not hostnames WHEN folded THEN `policy_invalid`, `doc_not_sorted`, `policy_invalid`, `policy_out_of_bounds`, `policy_invalid`. V: pol/relays-missing, pol/relays-unsorted, pol/relays-duplicate, pol/relays-three, pol/relays-not-hostname
- S7: GIVEN a `relays` that holds a JSON number WHEN a genesis document is checked THEN `genesis_schema`: a number is outside the canonical subset, so the document is no genesis document before its policy is read, and the same answer is given by the checker and by each signer's check of a document alone. V: pol/relays-number

### GP-03 Original genesis and proof of possession

An original document has `org=null`, `prev=null`, no `head`, at least one member, at least one device per member, and every device of a class its own policy accepts.

Proof of possession: every device listed in a genesis document MUST have at least one counting `local:handsal.genesis.sign` act over that document, signed under its own key (GP-15). Several counting signatures by one kid are one. For an original, that act has `inputs_hash` = hashstr(JCS(document)), `org` = that same hash, and no `head` (ACT-08). For a change, `org` is the original org id and `head` names the document's H (GP-19). A listed device without a counting signature is `genesis_unsigned`. Signatures that do not count (junk, unlisted keys, another document, duplicates) are ignored.

Why: every key in the state has signed at least once under its class's prompt.

- S1: GIVEN three maintainers and only two counting `genesis.sign` receipts WHEN folded THEN `genesis_unsigned`. V: gen/missing-maintainer-sig. C: gen/ok-3-maintainers
- S2: GIVEN a signature by an unlisted key next to every listed device's signature WHEN folded THEN the state; GIVEN a device whose only signature covers another document THEN `genesis_unsigned`. V: gen/sig-over-other-doc. C: gen/sig-by-unlisted-key

### GP-04 org id

The `org` of every act MUST equal hashstr(JCS(original document)). An act for another org is `org_mismatch`. Cross-org replay is impossible by construction.

- S1: GIVEN a valid approve for org A WHEN checked against org B's state THEN `org_mismatch`. V: org/other-org, org/sig-valid-wrong-org

### GP-05 Pin file

The pin file is named `<hex64>.pin`, where `hex64` is the lowercase hex of the SHA-256 digest inside the org id. Hex is used instead of base64url so that NTFS case folding cannot merge two names. Content: exactly one line of canonical-subset JSON, `{"genesis":<hashstr of the current document>,"org":<org id>,"spec":<profile hash>,"v":"handsal-pin/1"}`, followed by one LF, at most 512 bytes in total.

Checks, in the order of VR-02 step 6:
- a file name that does not match the org is `pin_org_mismatch`;
- anything else wrong with the bytes (CRLF, a second line, a missing LF, an extra or missing member, a member name that repeats, whatever its values, unsorted keys, non-ASCII, a wrong `v`, more than 512 bytes, an empty file) is `pin_malformed`;
- the pin's `org` MUST equal the consumer's input `org`, else `pin_org_mismatch`;
- `spec` MUST be a profile hash the running implementation implements, else `profile_mismatch`;
- the hash of the first lineage document MUST equal the pin's `org`, else `lineage_broken` (GP-07);
- `genesis` MUST equal hashstr(JCS(last lineage document)), else `genesis_pin_mismatch`;
- `spec` MUST equal the `profile` of the last lineage document, else `pin_spec_mismatch`.

A document served by a relay or found in a repository that differs from the pin does not matter: the pin decides.

- S1: GIVEN a pin file ending in CRLF WHEN parsed THEN `pin_malformed`. V: pin/crlf
- S2: GIVEN a file name whose hex differs from the org digest WHEN checked THEN `pin_org_mismatch`. V: pin/filename-mismatch, pin/org-not-original
- S3: GIVEN a probe for another org, or a pin whose `spec` is not the last document's `profile` WHEN checked THEN `pin_org_mismatch`, `pin_spec_mismatch`. V: org/probe-other-org, pin/spec-not-last-profile
- S4: GIVEN a pin file with the `org` member twice, with the same value or with two values WHEN parsed THEN `pin_malformed`. V: pin/duplicate-key, pin/duplicate-key-differing-values
- S5: GIVEN a valid pin file WHEN parsed THEN the pin; GIVEN a probe that reports `pin_missing` THEN `pin_missing`. V: pin/missing. C: pin/ok
- S6: GIVEN a pin whose `spec` is a supported older edition and a last lineage document that names a newer one WHEN checked THEN `pin_spec_mismatch`; GIVEN a pin whose `spec` is in no catalog entry THEN `profile_mismatch`. V: pin/spec-not-last-profile, prf/pin-spec-older-edition-not-last-doc

### GP-07 Lineage input

`fold`, `check-act`, `enrolled` and `genesis-check` take `lineage`: the ordered list `[{doc, sigs}]` from the original document to the pinned one, where `sigs` are that document's `genesis.sign` receipts. They also take one `acts` bag holding the chain acts of every epoch; each epoch's chain roots at its own document hash, so acts sort themselves into epochs. In the production build `check-act`, `recheck-act` and `enrolled` read `acts` and `lineage` from the store (CF-09) and an input carrying either is `malformed_input`. Every item of `acts` and of every `sigs` is a string: a string that is no valid act is ignored by the fold (FO-06), and an item of any other type is `malformed_input`.

The fold MUST validate every link: GP-03 for the original, and for each change GP-19 against the path to its H in the epoch before it, never the full fold of that epoch, so a fork there never fails a later epoch. Every command that reads a pin (`fold`, `check-act`, `enrolled`) makes three comparisons, in this order, at VR-02 step 6 (g). An empty lineage is `lineage_broken`. The pin's `org` MUST equal the hash of the first lineage document, which is the org id (GP-04), else `lineage_broken`. The pin's `genesis` MUST equal the hash of the last lineage document, else `genesis_pin_mismatch`. A document outside the canonical subset has no hash and never equals either: as the first document it is `lineage_broken`, as the last it is `genesis_pin_mismatch`. `genesis-check` and the pin helper read no pin and take the org id from the first document (CF-03, GP-21), so they cannot disagree with it. A lineage is also `lineage_broken` when its first document has a non-null `prev`, or when a later document's `prev` is not the hash of the document before it, or its `org` is not the hash of the first document (GP-15 step 4).

Every lineage document's `profile` MUST be implemented, that is, a hash of a supported edition (GP-22), else `profile_mismatch`. Each epoch is evaluated under its own document's profile, and a change's authority under the previous document's profile (GP-23). A change MUST NOT name an older edition than the previous document's (`profile_downgrade`, GP-24). A lineage that mixes a production and a fixture profile is `fixture_profile` (GP-18). A release implements every production profile any live lineage names (GP-22). `fold`, `check-act` and `enrolled` take the required input `org` (GP-14).

- S1: GIVEN a lineage whose last document does not hash to the pin WHEN folded THEN `genesis_pin_mismatch`. V: chg/lineage-last-not-pinned
- S2: GIVEN a fixture-profile original and a production-profile change WHEN folded THEN `fixture_profile`. V: fix/mixed-profile-lineage
- S3: GIVEN a pin and an input `org` that agree, and a lineage whose first document hashes to another org WHEN folded THEN `lineage_broken`. V: pin/lineage-original-not-org
- S4: GIVEN a lineage whose middle document is absent WHEN folded THEN `lineage_broken`. V: chg/lineage-missing-doc
- S5: GIVEN a lineage whose documents name P1 then P2, both supported, WHEN folded under a release whose current edition is P2 THEN the fold gives the state of the last document and no document is refused for its edition. V: prf/p1-org-folds-on-p2-release, prf/change-p1-to-p2-ok
- S6: GIVEN a lineage P1, an unsupported hash, P2 WHEN folded THEN `profile_mismatch`, the first failing document winning (GP-15). V: chg/profile-unimplemented-in-middle

### GP-09 Epoch scope

The fold result is the state of the pinned (last) epoch. Earlier epochs are read only along the path to each change's H, to validate that change (GP-19). A non-chain act whose `head.id` is not a position of the current epoch's chain is `stale_view` (VR-12); this covers heads from other epochs.

- S1: GIVEN an approve with a head from epoch 0 and a verifier on epoch 1 WHEN checked THEN `stale_view`. V: chg/old-epoch-head-stale

### GP-10 Pin location

The pin MUST live where only an administrator principal can write it and the agent's user can only read it.
- macOS: `/Library/Application Support/handsal/orgs/<hex64>.pin`. The directories `handsal` and `orgs` are `root:wheel 0755`. Check (in-process, standard library only): open with `O_NOFOLLOW`; `fstat` the descriptor: a regular file, `st_uid == 0`, `mode & 0o022 == 0`, `st_nlink == 1`; `lstat` every ancestor up to `/`: not a symlink, `st_uid == 0`, `mode & 0o022 == 0`.
- Windows: `C:\ProgramData\handsal\orgs\<hex64>.pin`. The directories carry a protected DACL: owner Administrators (S-1-5-32-544); SYSTEM and Administrators full control; Users (S-1-5-32-545) read and execute only. Ownership is checked only on the Windows side, by `handsal-sign.exe pin-read` (GP-11) or the Windows-side checker (GP-17). A WSL2 checker MUST NOT decide ownership from drvfs mode bits, from a copy inside the WSL filesystem, or through the `\\wsl$` share.

Any failed check is `pin_owner`; an absent file is `pin_missing`.

Scope: the pin defends against an agent writing files as the person's user principal. It does not defend against an agent that changes verifier code or its runtime (section 14, L13). Within that scope, it turns "rewrite one data file" into "modify code or remount a filesystem".

- S1: GIVEN a pin file writable by group WHEN probed THEN `owner_ok:false`, `pin_owner`, and `enrolled` is false. V: enr/pin-owner
- S2: GIVEN a pin whose ancestor directory is a symlink WHEN probed THEN `owner_ok:false`, `pin_owner`. A vector cannot build a symlinked ancestor of the fixed pin path, so the ancestor symlink case is a probe test (CF-07). T: checker/python/tests/test_probe_posix.py::test_an_ancestor_that_is_a_symlink_is_pin_owner

### GP-11 Windows ownership check

`handsal-sign.exe pin-read` is installed under `C:\Program Files\handsal\`, which is administrator-only by default ACL. Input `{"org"}`. It opens the pin with `FILE_FLAG_OPEN_REPARSE_POINT` and refuses reparse points. It reads the security descriptor of the open handle and of `orgs` and `handsal`, and requires: owner SID in {Administrators, SYSTEM}; a protected DACL; every ACE for any other SID grants at most `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` (no WRITE, DELETE, WRITE_DAC, WRITE_OWNER or FILE_DELETE_CHILD); and no non-administrator ACE on `C:\ProgramData` grants `FILE_DELETE_CHILD`. Output is one JCS line `{"bytes_b64","filename","org","owner_ok","reason"}` (GP-14). A caller on a host where it cannot be run gets `pin_probe_unavailable`; a WSL2 host gets `pin_probe_unprotected` (GP-17).

The reference checker has no Windows path for this check. It never calls `pin-read`; its ownership test of the vitni binary (CF-05) reads POSIX owner and mode bits only, and it fixes a vitni path on macOS alone, so on Windows its verifier is always unavailable. Until a Windows implementation of these checks exists in the checker, the checker is not the Windows-side gate of GP-17 step 2.

Why: each platform has one owner for the ownership rule, native code for NTFS, never a parse of PowerShell output.

- S1: GIVEN `pin-read` absent WHEN the probe runs THEN `owner_ok:false`, `pin_probe_unavailable`. V: enr/pin-probe-unavailable

### GP-12 Pin write

The pin MUST be written only during the enrollment ceremony (SG-12), after `genesis-check` returns `valid:true` and the person has seen the full genesis render (RN-08, RN-10). Before the write the ceremony shows hash12 of the `genesis` in the exact pin line, for comparison with line 1 of the `genesis.sign` prompt each signer saw.
- macOS: only by `/usr/bin/sudo -k "/Library/Application Support/handsal/bin/handsal-pin"`, with no argument and the GP-21 input line on stdin. With a command, `-k` neither uses a cached credential nor leaves one.
- Windows: only by `C:\Program Files\handsal\handsal-pin.exe`, started elevated (UAC) by the ceremony over the GP-21 pipe channel. The agent cannot pass the secure-desktop consent.

On both platforms the pin helper owns monotonicity, directory creation and the pin's attributes (GP-21). No other component writes the pin.

- S1: GIVEN an agent process without elevation WHEN it writes the pin location THEN the OS denies it (platform test, outside the vector set). O: a platform check the owner runs on a real macOS, as root, because no test in this repository can hold a root-owned directory
- S2: GIVEN the macOS ceremony WHEN it writes the pin THEN it uses one `/usr/bin/sudo -k` invocation of the helper and leaves no cached credential. T: signer/apple/Tests/HandsalCeremonyTests/CeremonyTests.swift::theChannelIsSudoMinusKAtTheFixedPaths

### GP-13 enrolled predicate

`enrolled` is pure. Input (conformance build) `{acts, device_kid, lineage, next, now, org, pin, synced_at, tip_statement}`, with `pin` the probe object of GP-14 and `next` as in VR-01. Input (production build) `{device_kid, org}`: it reads the pin, `now` and the store in process (CF-08, CF-09), and an input carrying `acts`, `lineage`, `next`, `now`, `pin`, `synced_at` or `tip_statement` is `malformed_input`. Output `{enrolled, reason}`. It is true iff all of these hold, in order, first failure wins:
1. to 3. the pin checks of VR-02 step 6, (a) to (h), in that order and with those codes, the store reason at (f) included in the production build;
4. the fold succeeds (else its error code, `fork` included, but a `fork` where `next` is `"yes"` is `epoch_superseded`, VR-12);
5. `device_kid` is a device in the state (`local_key_unknown`), active (`local_key_not_active`) and accepted (`local_class_not_accepted`);
6. the view is fresh: VR-12 (`epoch_superseded` included), then the witness rules of the policy's mode (WT-04, WT-05, WT-10);
7. the pin's `spec` is not a fixture profile (`fixture_profile`, GP-18).

Under the production profile a fixture kid never enters `devices` (GP-18), so step 5 reports it as `local_key_unknown`, or the fold fails at step 4 when the genesis lists one.

Meaning: `enrolled:true` says "this machine holds a valid administrator-written pin for `org`, its evidence folds, and `device_kid` names an active accepted device of that org, freshly viewed". It does NOT prove that the key is on this machine or that a person is present: `device_kid` is caller-supplied, and a prompt per `enrolled` call would train blind touching (SG-10). Presence is proven per act, by `check-act`. Consumers MUST NOT treat `enrolled:true` as human proof.

- S1: GIVEN a valid pin and an active accepted local key but a stale view WHEN evaluated THEN `enrolled:false`, `stale_view`. V: enr/stale-view
- S2: GIVEN a probe reporting `pin_missing`, a removed local key, or a frozen bag WHEN evaluated THEN false with `pin_missing`, `local_key_not_active`, `fork`. V: enr/pin-missing, enr/local-key-revoked, enr/fork
- S3: GIVEN a fixture kid under ORG_PRODK WHEN evaluated THEN false, `local_key_unknown`. P: enr/prodk-fixture-kid-unknown
- S4: GIVEN everything valid under the fixture profile WHEN evaluated THEN false, `fixture_profile` (steps 1 to 6 passed). V: enr/ok, fix/fix-profile-enrolled
- S5: GIVEN a probe of another org, or bob's kid on alice's machine WHEN evaluated THEN false, `pin_org_mismatch`; false, `fixture_profile` (enrolled does not prove presence). V: org/enrolled-org-mismatch, enr/device-kid-not-presence
- S6: GIVEN a relay witness policy and no statement WHEN evaluated THEN false, `witness_missing`. V: wit/enr-relay-missing
- S7: GIVEN a `synced_at` more than `clock_skew_s` in the future WHEN evaluated THEN false, `view_in_future`. V: enr/view-in-future
- S8: GIVEN a relay witness policy and a statement older than `max_tip_age_s` WHEN evaluated THEN false, `stale_witness`. V: wit/enr-relay-stale
- S9: GIVEN `next` `"yes"` and everything else valid WHEN evaluated THEN false, `epoch_superseded`. V: enr/epoch-superseded

### GP-14 Pin probe is data

Reading the pin and checking its ownership is one impure probe per platform (GP-10 on macOS, GP-11 on Windows). The probe is called with an org id and returns `{bytes_b64, filename, org, owner_ok, reason}`, echoing the org it was asked for and the file name it opened. No pure command reads a file.

The conformance checker takes this object as the input key `pin` of `fold`, `check-act` and `enrolled`. The production checker calls the platform probe in-process at the fixed pin path and takes no `pin` key (CF-08). The pure core is the same in both builds. `fold`, `check-act` and `enrolled` take the required input `org`; a missing or non-hashstr `org` is `malformed_input`. The checker compares probe, pin, input and lineage (GP-13 steps 1 to 3, VR-02 step 6). The macOS probe takes two test-only constructor arguments, a root path and the uid it treats as administrator (0 by default); neither is a command line flag, an environment variable or an input key, and the production build constructs the probe with the defaults.

Why: the org a consumer expects is explicit input, so another org's valid pin can never stand in for it, and every rule stays testable by vectors while platform code stays one small function per operating system.

- S1: GIVEN `owner_ok:false` with reason `pin_owner` WHEN `check-act` runs THEN `valid:false`, `pin_owner`. V: chk/pin-owner-false
- S2: GIVEN a `check-act` input without `org` WHEN run THEN `{"error":"malformed_input"}`. V: org/check-act-org-input-missing

### GP-15 Genesis signatures and genesis error order

A `genesis.sign` over a lineage document D counts for possession iff: it passes ACT-01 to ACT-14 for `genesis.sign` (`head` present iff D's `prev` is non-null, with `head.id` equal to D's `head`; parent fields null; `performer_id` the `person` of the listed device whose kid is the header kid); its kid is listed in D; `inputs_hash` is hashstr(JCS(D)); `org` follows GP-03; vitni `verify` is ok with the one-entry keys map of that device; and S is low. For a change, the authority test of ACT-13 and GP-19 reads the same signatures independently. Every other signature is ignored (FO-06, FO-21). Several counting signatures by one kid are one.

Order, per document from the original, first failure of the first failing document wins:
1. structure: `genesis_schema` (including GP-01 `head`), `doc_not_sorted`, `genesis_key_invalid`, `duplicate_key`;
2. profile: `profile_mismatch`, `fixture_profile`, then, for a change only, `profile_downgrade` (GP-24);
3. policy and devices: `policy_invalid`, `policy_out_of_bounds`, `policy_unreachable`, `class_unknown`, `class_pending`, `class_test_only`, `class_policy_mismatch`, then a listed device of a class the policy does not accept (`genesis_schema`, GP-20), then `role_key_class` (KC-08), then `fixture_key` (GP-18);
4. links: `lineage_broken` (GP-07);
5. render size: `genesis_render_too_large` (RN-10; the difference render needs a valid `previous`);
6. possession: `genesis_unsigned`;
7. change only: `genesis_head_unknown`;
8. change only: `genesis_change_unauthorized`;
9. change only: `genesis_device_revoked`, then `genesis_device_changed`.

Inside one step the codes are tried in the order listed, each over the whole document before the next. A document with two defects of one step returns the code listed first, wherever the defects sit: a `class_unknown` anywhere in `classes` wins over a `class_pending` that comes earlier in the list.

Registry-dependent and policy-dependent checks run only after the profile and the policy are known. Steps 1 to 5 read the profile of the document under test. Steps 7 and 8 read the previous document's profile. Step 9 reads the new document's profile, and the previous epoch only through `S_H` (GP-20, GP-23). Step 6 reads the act form, which is the same in every edition (I3). Junk or duplicate signatures cannot fail the fold; only a listed device without a counting signature can. A `genesis.sign` over a change without `head`, or over an original with `head`, does not count, so its device is unsigned (step 6).

- S1: GIVEN ORG's signatures plus a non-verifying one and a second valid one by alice WHEN folded THEN the state. V: gen/junk-sig-ignored, gen/duplicate-sig-same-kid-ok
- S2: GIVEN a `genesis.sign` over a change without `head` WHEN folded THEN `genesis_unsigned`. V: sch/genesis-sign-change-without-head, sch/genesis-sign-original-with-head
- S3: GIVEN two defects in one document WHEN folded THEN the earlier step's code. V: gen/order-schema-before-lineage, gen/order-lineage-before-unsigned, gen/order-unsigned-before-head, gen/order-unauthorized-before-carry, gen/order-profile-before-class, gen/order-lineage-before-render, gen/order-policy-before-device-class
- S4: GIVEN a downgrade that also has a class defect, and a downgrade with a fixture mix WHEN folded THEN `profile_downgrade`, `fixture_profile`. V: prf/order-downgrade-before-class, prf/order-fixture-before-downgrade

### GP-17 WSL2 is unprotected until a Windows-side gate exists

A WSL2 host is a Linux host whose kernel release contains `microsoft` (compared without regard to case). Any other host has no pin location the checker can read (it is neither macOS nor WSL2), so its probe returns `{owner_ok:false, reason:"pin_probe_unavailable"}`: a checker on native Windows or on another Linux host never reports a machine enrolled.

On WSL2 an agent running as the user can usually obtain distribution root (`wsl.exe -u root`) and with it redirect every path a WSL2 process uses (bind mounts over `/mnt/c`, replaced binaries). Then no WSL2-side check is protected, the interop call to `pin-read` included.
1. The WSL2-side probe MUST return `{owner_ok:false, reason:"pin_probe_unprotected"}`, so no WSL2-side code ever reports a machine enrolled.
2. Before any Windows machine counts as enrolled, a Windows-side gate MUST exist: the production checker (CF-08) installed by an administrator under `C:\Program Files\handsal\`, reading the pin in the same process with the GP-11 checks and reading the clock itself, so pin read, fold and decision run in one administrator-installed Windows process that takes neither `pin` nor `now`. It is a native binary, or Python started as `python -I -E -s` from the administrator path with no user site. WSL2 consumers call it through interop at its absolute path (SG-14).
3. A WSL2 consumer receives the gate's answer through a path WSL2 root can redirect (section 14, L13).

- S1: GIVEN the WSL2-side probe WHEN `enrolled` runs THEN false, `pin_probe_unprotected`. The WSL2 probe itself is `test_probe_wsl.py` (CF-07). V: enr/wsl-unprotected

### GP-18 Fixture keys and profiles

- Each edition defines two profile hashes from one core manifest (CF-01): a **production** profile and a **fixture** profile. The rules below hold in every edition (GP-22).
- Production profile: a kid listed in `fixture-kids.json` is never accepted, whatever its class label. It is absent from `keys` and from `devices` and counts for nothing. A genesis document listing one, or a policy whose `relay_kid` is one, is `fixture_key` (fold error). A `device.add` or `member.add` introducing one is not on the chain. `check-act` of an act signed by one returns `unknown_key`.
- Fixture profile: identical rules, except that fixture kids are treated as their labelled class. It exists for vectors only; positive vectors use it.
- Production never pins it. Three owners enforce this: the fold refuses fixture kids under the production profile; the production checker refuses the fixture profile (CF-08); the ceremony refuses it (SG-12). `enrolled` returns `fixture_profile` (GP-13 step 7), and a lineage mixing the two profiles is `fixture_profile` (GP-07). The conformance `fold`, `check-act` and `genesis-check` accept the fixture profile so vectors can prove positive paths. Production paths are proven by PRODK vectors (CF-08).

Why: a key whose private scalar is published is never human proof in production, by a fold rule and not only by a ceremony check.

- S1: GIVEN ORG under the production profile WHEN folded THEN `fixture_key`. V: fix/prod-genesis-fixture-kid, fix/prod-check-act-fixture-pin-refused. P: fix/prodk-relay-fixture-kid
- S2: GIVEN ORG_PRODK and a `device.add` of a fixture kid WHEN folded THEN not on the chain; an approve by that kid WHEN checked THEN `unknown_key`. P: fix/prodk-fixture-kid-add-not-on-chain, fix/prodk-check-act-fixture-kid-unknown
- S3: GIVEN APPROVE under the fixture profile WHEN checked by the conformance build THEN valid. V: fix/fix-profile-check-act-ok

### GP-19 Genesis change

A change is a new document with `prev` = hashstr(JCS(previous document)), `org` = the original org id, a full snapshot of the new epoch, and `head` = H (GP-01). Proof of possession: GP-03 and GP-15.

Head: H MUST be a node of the previous epoch's act tree (FO-26): its root or a valid chain primary, never a resolve, an endorsement or an invalid act; else `genesis_head_unknown`. Every `genesis.sign` over a change carries `head = {id: H, kind: "chain"}` with `id` equal to the document's `head`. A signature naming another head is not a signature over this change and is ignored for possession and authority alike. One document has one H.

Path: the previous epoch is read along the path from its root to H, each primary validated against its prefix state; FO-24 is not applied on the path, because by naming H the change's quorum selects the branch. H may lie on any branch, a losing or unresolved one included: authority and carried devices then come from that branch's state.

Authority: the previous epoch, its path to H, its state `S_H`, its policy and every rule applied to them are those of the previous document's profile, whatever profile the new document names (GP-23). A signature counts iff it passes the authority test of ACT-13 (its key is a device of `S_H`, listed in the document or not), its key satisfies clean(k, H) (FO-26: active and accepted in `S_H`), and its person holds a role in the previous policy's `rules["genesis.change"].roles`. Counted persons MUST meet the previous policy's `persons` for that rule, else `genesis_change_unauthorized`. Several counting signatures by one kid are one. A carried device's possession signature naming H is also an authority signature when it meets these conditions, so a change carrying the devices of Q previous role holders is authorized by their possession signatures alone.

Why unlisted keys count: authority is a property of the previous epoch at H, not of the new document. Any role holder's key that is clean at H could also be listed and sign, so counting it unlisted grants nothing new. Requiring listing would make a full key rotation (a document listing only new keys) impossible. The difference render shows every dropped key under `Devices removed` (RN-10).

Close: the previous epoch's state ends at H. No act outside the path to H is ever read for this change. Later acts of the old epoch, forks and resolves cannot invalidate it, so a pinned change never becomes invalid. A change takes effect on a machine only after a person re-pins it (GP-12). The acts this paragraph says are never read are the acts a store may drop once the change is stored (CF-14).

A key removed after H, outside the path to H, still counts at H (section 14, L4).

- S1: GIVEN alice removed by bob and carol at position 2 and a change with H = 4 listing bob plus new maintainers frank and grace, signed by every listed device and by alice's removed key WHEN folded THEN `genesis_change_unauthorized` (only bob counts). V: chg/signer-revoked-before-head, wit/change-none-to-relay-revoked-signer, cli/genesis-check-change-revoked-signer
- S2: GIVEN alice removed at position 3 and a change with H = 2 signed by alice and bob WHEN folded THEN the new epoch. V: chg/signer-revoked-after-head, chg/backdate-through-fork-residual
- S3: GIVEN H on a branch whose path does not contain alice's removal WHEN folded THEN the new epoch. V: chg/head-on-side-branch-clean-rule, chg/signer-revoked-on-branch
- S4: GIVEN a listed device whose only `genesis.sign` names another head WHEN folded THEN `genesis_unsigned`; GIVEN an unlisted previous role holder whose only signature names another head THEN it does not count (`genesis_change_unauthorized` under CHG-NEW). V: chg/possession-sig-other-head-ignored, chg/heads-differ
- S5: GIVEN a change listing alice plus new maintainers and signed also by carol, clean at H and not listed WHEN folded THEN the new epoch (alice and carol count). V: chg/unlisted-clean-signer-counts, chg/unlisted-signer-wrong-performer-ignored
- S6: GIVEN a document listing only new keys for alice, bob and carol, signed for authority by alice's and bob's old keys WHEN folded THEN the new epoch. V: chg/full-key-rotation-ok
- S7: GIVEN 2 of 3 maintainers sign a change at the previous tip WHEN folded with the new pin THEN the new epoch is the state; GIVEN only one counts THEN `genesis_change_unauthorized`. V: chg/quorum-unmet-1-of-3. C: chg/ok-2-of-3
- S8: GIVEN a change whose document `head` is no node of the previous act tree WHEN folded THEN `genesis_head_unknown`. V: chg/head-unknown
- S9: GIVEN a change signed by a role holder whose device class the epoch's policy does not accept, and by one role holder whose class it accepts, WHEN folded THEN only the accepted one counts, so a rule that needs two persons is `genesis_change_unauthorized`. T: checker/python/tests/test_epoch.py::test_a_role_holder_whose_class_the_policy_does_not_accept_does_not_count
- S10: GIVEN a change under P2 whose signatures meet the P2 quorum rule and not the P1 quorum rule WHEN folded THEN `genesis_change_unauthorized`; GIVEN them meeting P1 and not P2 THEN the epoch under P2. T: checker/python/tests/test_profile_set.py::test_a_change_is_authorized_by_the_previous_documents_rule_not_the_new_ones
- S11: GIVEN a P1 epoch with a fork and a change under P2 whose H is on the path WHEN folded THEN the path is validated under P1 and the new epoch is the state. V: prf/change-p1-to-p2-fork-path-under-p1

### GP-20 Carried devices across a change

- Every device listed in any document is of a class accepted by that document's policy, else `genesis_schema`, checked at GP-15 step 3 after the policy checks.
- A device whose kid occurs in an earlier lineage epoch (in its document, or in the state at the H that closed it) is **carried**. It MUST be active in `S_H` of the previous epoch, and it MUST NOT be `removed` in the state at the closing H of any earlier epoch, else `genesis_device_revoked`. Acceptance is decided by the new document's policy only, under the registry of the new document's profile, so a device whose class the old policy did not accept may be carried once the new policy accepts it. The whole carry (acceptance, byte-identity, `genesis_device_revoked`, `genesis_device_changed`) is evaluated under the new document's profile; the previous epoch is read only through `S_H` and the earlier keys, whose shape is the same in every edition (GP-23).
- A carried entry MUST be byte-identical to its entry in `S_H` (`person`, `class`, `label`, `sign`, `agree`), else `genesis_device_changed`. Changing a label or class means removing the key and adding a new one.

Why: a re-pin never revives a key removed on the path to H or in an earlier epoch, and never changes a vouched device value outside the rendered difference.

- S1: GIVEN bob2 removed by bob and carol before H and a change carrying bob2 WHEN folded THEN `genesis_device_revoked`; GIVEN the removal after H THEN bob2 is carried. V: chg/carry-removed-kid-returns. C: chg/carry-revoked-after-head
- S2: GIVEN a listed device of a class the document's policy does not accept WHEN folded THEN `genesis_schema`. V: chg/device-unaccepted-class
- S3: GIVEN a change carrying bob2 with a new label WHEN folded THEN `genesis_device_changed`: a carried entry is compared whole, the class with the rest. V: chg/carry-entry-changed
- S4: GIVEN a change P1 to P2 that carries every active device of the P1 epoch WHEN folded THEN the new epoch lists them byte-identical. V: prf/change-p1-to-p2-ok

### GP-21 Pin monotonicity and the pin helper

The pin helper is one binary per platform at an exact administrator path (SG-14): `/Library/Application Support/handsal/bin/handsal-pin` on macOS, run as `/usr/bin/sudo -k "/Library/Application Support/handsal/bin/handsal-pin"`, and `C:\Program Files\handsal\handsal-pin.exe` on Windows, started elevated (UAC). Both implement this rule identically: the same input bytes, checks, output line and exit codes. Only the channel differs.

Input. The helper takes no argument; any argument is `malformed_input` and nothing is written. The input is exactly one line: one JSON object with exactly the keys `acts` and `lineage` (the `genesis-check` input, CF-03), followed by one LF. Its grammar is the canonical subset recognizer (ACT-04) with MAX_INPUT in place of MAX_PAYLOAD. Any recognizer failure (a duplicate key, more than MAX_INPUT bytes, a missing LF, bytes after the LF) is `unparseable_input`. A missing, extra or mistyped key is `malformed_input`.

Steps, first failure wins. No pin is written on any failure; directories created at step 0 stay.
0. Check or create the directories (below), then take the lock (below), held through the write.
1. Run the production checker at its SG-14 path with `genesis-check` on `{acts, lineage}`. Unless it returns `valid:true`, `pin_invalid`. The returned `pin` (one JCS line plus LF, GP-05) is the only content the helper writes.
2. Derive the path from that `pin`'s `org` only (`<hex64>.pin` under `orgs`, GP-05).
3. If a file exists at that path, whatever it contains, it MUST be a well-formed pin line for that same org (GP-05), else `pin_malformed`; and the new lineage MUST contain the document whose hash is that file's `genesis`, else `pin_rollback`. If no file exists there, step 3 passes.

Directories. The installer (SG-15) creates `handsal` and the directories of its own artifacts (`bin`, `lib`, `python`) with the GP-10 attributes, because the helper lives under `handsal` and cannot run before it exists. The helper is the only creator of `orgs` and of `pin.lock` on both platforms, and it creates `handsal` itself only when it finds it absent (a test root, or an installation that was cut short); the ceremony creates none of them. What the helper creates has the GP-10 attributes: on macOS `root:wheel 0755`, set by `fchown` and `fchmod` independent of umask; on Windows owner Administrators with a protected DACL, SYSTEM and Administrators full control, Users read and execute. When present, it checks them with the reader's own checks (GP-10 `lstat` chain on macOS; GP-11 owner, protected DACL, ACE limits and the `C:\ProgramData` `FILE_DELETE_CHILD` rule on Windows) and refuses any mismatch with `pin_owner`, writing nothing. It never repairs, because a repair would be a privileged change to an object the agent may have prepared.

Write. The content is exactly the `pin` returned at step 1. A temporary file is created exclusively in `orgs` (macOS `O_CREAT|O_EXCL|O_NOFOLLOW`; Windows `CREATE_NEW` with an explicit security descriptor) and given the reader's attributes before the rename: on macOS owner `root:wheel`, mode `0644` by `fchown` and `fchmod`, one link; on Windows owner Administrators and the protected GP-10 DACL, set at creation and never inherited. It is flushed, then renamed over the path (macOS `rename` plus `fsync` of `orgs`; Windows `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH`). The path therefore holds the old pin or the new one, never a partial one, and the new one always passes GP-10 or GP-11.

Lock. After the directory check and before step 1 the helper opens `handsal/pin.lock`, created like a pin file when absent, and takes an exclusive lock held until after the rename (macOS `flock(LOCK_EX|LOCK_NB)` on a descriptor opened with `O_NOFOLLOW`; Windows a handle opened with share mode 0). A lock held by another run is `internal`, and nothing is written. Check-then-rename is therefore atomic per machine, and two concurrent runs never move the pin off one lineage.

Output. Exactly one JCS line plus LF: `{"inner_reason":I,"reason":R,"written":W}`. R is `ok` or one of `malformed_input`, `unparseable_input`, `pin_invalid`, `pin_owner`, `pin_malformed`, `pin_rollback`, `internal`. I is the `reason` that `genesis-check` returned when step 1 ran (`ok` when valid), else `null`. W is `"yes"` iff the rename completed, else `"no"`. `internal` covers every I/O failure: read, lock, create, write, flush, rename, checker launch, or checker output that is not one JCS line. A failure before the rename writes nothing, and nothing can fail after it. Exit codes: 0 `ok`; 2 `malformed_input`, `unparseable_input`; 3 `pin_invalid`, `pin_owner`, `pin_malformed`, `pin_rollback`; 5 `internal`. Exit 1 with no line means the helper never ran (sudo authentication failed, or UAC was declined). The ceremony accepts only a line whose R matches the exit code; anything else is a failed write report, and the next `enrolled`, which reads the real pin, decides what is pinned.

Channel. On macOS `sudo` passes the ceremony's standard input and output through: the helper reads the input line from stdin and writes the output line to stdout. On Windows a process started with `ShellExecuteEx` `runas` inherits no handles, so the ceremony first creates the named pipe `\\.\pipe\handsal-pin` as a byte-mode server with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL for the current user, SYSTEM and Administrators only. If that fails because the name exists, the ceremony fails before starting the helper. It then starts `handsal-pin.exe` with `ShellExecuteEx` (`runas`, no parameters, `SEE_MASK_NOCLOSEPROCESS`), writes the input line to the pipe, reads the output line from it, and takes the exit code from the process handle. The helper connects to that fixed name as a client with `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`, so the pipe server can never impersonate the elevated token, reads up to the first LF and writes its output line. No privileged write goes to a user-writable location. On both platforms a same-user agent can replace the input on the channel (section 14, L5); the channel adds no property beyond that.

Tests. Helper tests are implementation tests (CF-07), not vectors. The installed helper runs the production checker, which refuses every fixture-profile lineage (CF-08), and its effects are the contents, owner and attributes of files under a root directory, a lock and a rename, none of which a harness vector can set up (CF-04: signers run the `render` and `emit` vectors only). The tests run against a library build of the helper core, built by a test constructor that injects the conformance checker and a temporary root directory in place of the SG-14 checker path and the GP-10 root. The installed binary has no such constructor and is never the subject of a test. Platform tests run the same injected core on the target operating system with privileges, so the owner, DACL, lock and rename code paths are exercised for real. What `genesis-check` alone decides (the acts on the path to H, extra acts, a forged link) is a checker vector (CF-03).

The helper never deletes, truncates or restores a pin, and no component of this profile does. A downgrade, or recovery of a machine pinned to a lineage it must leave, needs an administrator to delete the pin by hand outside any ceremony.

Why the caller may supply `acts`: by GP-19 a link's validity reads only its documents, their signatures and the acts on the path to its H. Omitting any of them makes the link invalid (`genesis_head_unknown` or `genesis_change_unauthorized`), and adding acts changes nothing. A caller can withhold evidence, which fails closed, but cannot select it, so `valid:true` proves authority. This holds for every link because `genesis-check` validates each link of `lineage` from the original (CF-03): a lineage that contains the pinned document but has a forged link after it is `pin_invalid`.

Why no argument: a caller-supplied file name would be a second source for the org. Deriving the path from the checker's returned line leaves one source, so an agent cannot point org A's lineage at org B's pin.

Per org, the pin only moves forward along one lineage, only to a lineage whose every link is authorized, only at the path of the org it names, only with bytes and attributes the reader accepts, and one run at a time.

- S1: GIVEN a pin on epoch 1 and a ceremony submitting epoch 0 WHEN the helper runs THEN `pin_rollback`, the file unchanged; GIVEN a bag missing the acts on the path to H THEN `pin_invalid`, whose cause `genesis-check` gives as `genesis_head_unknown`, and a forged middle link as `genesis_change_unauthorized`. Tests: CF-07. V: cli/genesis-check-missing-head-acts-invalid, cli/genesis-check-forged-middle-link. C: cli/genesis-check-extra-acts-same-result
- S2: GIVEN any argument, a third input key, a malformed file at the derived path, or another org's pin present WHEN the helper runs THEN `malformed_input`, `malformed_input`, `pin_malformed`, and the other org's file untouched. T: signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::anArgumentIsRefused, signer/apple/Tests/HandsalPinTests/PinProcessTests.swift::aThirdKeyIsMalformed, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::aMalformedFileAtThePathIsRefused, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::theOrgIsTheCheckersAndNobodyElses
- S3: GIVEN input with a duplicate key, or more than MAX_INPUT bytes THEN `unparseable_input`, exit 2; GIVEN an existing `orgs` the reader would reject THEN `pin_owner`, nothing written; GIVEN the lock held THEN `internal`; GIVEN a successful write THEN the platform probe returns `owner_ok:true` for the new file. T: signer/apple/Tests/HandsalPinTests/PinProcessTests.swift::badFramingIsUnparseable, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::anExistingDirectoryTheReaderRejectsIsRefused, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::aHeldLockIsRefused, signer/apple/Tests/HandsalPinTests/PinProbeTests.swift::theWrittenFilePassesTheProbe
- S4: GIVEN a pin at a P1 document and a lineage that continues with a P2 change WHEN the helper runs THEN the new pin is written, with `inner_reason` `ok`; GIVEN a lineage that names a hash of no catalog entry THEN `pin_invalid` with `inner_reason` `profile_mismatch` and nothing written. T: signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::aMigrationToTheNextEditionIsWritten, signer/apple/Tests/HandsalPinTests/PinHelperTests.swift::aLineageNamingNoSupportedProfileIsPinInvalid

### GP-22 Supported set of editions

A release implements a **supported set** of editions, the catalog. The catalog is ordered, oldest first, and its order is the order in which the editions were published. An edition enters the catalog at the tag that ships it. From that tag its core files, registry, fixture kids and therefore its rules never change: a profile hash names its rules for good (CF-01). A change to any of them is a new edition with a new hash. The last entry is the current edition. New organizations are founded under the current edition only (SG-17); every other edition is implemented so that documents already made under it keep working.

The catalog is append-only and is not a core file: it is on no core manifest, because a catalog inside the core would make every edition's hash depend on the editions after it, a fixed point of the kind CF-01 avoids for vectors. A tool writes the current edition and appends to the catalog; none edits an earlier entry or an earlier edition's data. A catalog entry is `{label, production, fixture, bundle, tag}`: a display label, the two profile hashes, the CF-01 bundle hash of the tag that shipped the edition, and that tag's name (CF-15).

I1. Every release MUST implement every production profile that any document of any live lineage names. The lineage always starts at the original document (GP-07), so this means every production profile any document of that organization has ever named. A release MUST NOT remove an edition from the catalog. There is no end of support in this profile: nothing leaves the set, and no date, promise or rule in this profile makes any edition stop being implemented.

The production and server builds implement the production hash of every edition and refuse every fixture hash (`fixture_profile`); the conformance build implements both kinds of every edition (CF-08). A hash that belongs to no catalog entry, in either kind, is `profile_mismatch` (GP-15 step 2). A signer's `version` lists the production hashes it implements (SG-02).

Fixture kids are append-only across editions: a kid listed in `fixture-kids.json` of any edition stays refused under the production profile of every newer edition (GP-18).

Deferred, and not decided here: an end-of-support date or per-edition support promise; any retirement model, a settled-checkpoint rule included (it weakens what the org id proves and needs its own threat review, before any contract promises an end of support); automated fleet re-pin (GP-12 is unchanged). A catalog entry MAY carry an end-of-support field; it has no effect, and a date in it does not allow a release to drop the entry.

Why: the org id is the hash of the original document, so a lineage never forgets the profile it was founded under. A build with only the newest edition strands every older organization (`profile_mismatch` everywhere), and it cannot migrate, because the change that would move it is evaluated under the edition the build dropped (GP-19, GP-23).

- S1: GIVEN an organization founded under P1 and a release whose current edition is P2 WHEN `fold`, `check-act`, `recheck-act` and `enrolled` run on its lineage and pin THEN they answer as a P1-only release answers. V: prf/p1-org-folds-on-p2-release. T: conformance/tests/test_run.py::test_every_catalog_tag_vector_set_runs_against_the_current_build
- S2: GIVEN a document whose `profile` is a well-formed hash that is in no catalog entry WHEN folded THEN `profile_mismatch`, wherever it sits in the lineage. V: gen/profile-mismatch, chg/profile-unimplemented-in-middle
- S3: GIVEN the catalog of the previous tag and the catalog of this release WHEN compared THEN every entry of the previous one is present, in the same place, with the same hashes. T: checker/python/tests/test_profile_set.py::test_a_release_keeps_every_edition_the_previous_tag_listed
- S4: GIVEN a catalog entry WHEN its frozen core manifest is hashed as CF-01 says, in both kinds, and its registry and fixture-kid bytes are hashed THEN the results are the entry's two hashes and the manifest's entries. T: checker/python/tests/test_profile_set.py::test_every_edition_has_a_frozen_manifest_that_hashes_to_its_two_profiles
- S5: GIVEN the Python, Swift and Rust profile tables and the catalog WHEN compared THEN they list the same editions in the same order with the same hashes. T: tools/tests/test_core_files.py::test_the_three_tables_list_the_same_editions_in_the_same_order
- S6: GIVEN a kid in the fixture-kid list of an edition WHEN a newer edition's list is read THEN the kid is in it. T: checker/python/tests/test_profile_set.py::test_fixture_kids_are_append_only_across_editions
- S7: GIVEN the current core files WHEN hashed THEN the result is the newest edition's hash or a new edition's, never an older edition's. T: checker/python/tests/test_profile_set.py::test_the_current_core_is_never_an_older_edition
- S8: GIVEN the catalog file WHEN the core manifest is listed THEN it is not on it. T: tools/tests/test_core_files.py::test_the_catalog_is_not_a_core_file

### GP-23 One evaluator per epoch, and a frozen wire

I5. The rules of an epoch come only from the profile of that epoch's document. The rules of a change's authority come only from the profile of the previous document. No rule asks which edition it is running under: the profile of a document is resolved once, where the document is read (GP-15 step 2) and where the pin is read (GP-05), and every later rule of that epoch reads that one answer. In detail:
- the structure, policy, class and device checks of a document (GP-15 steps 1 to 5) read the registry and the policy bounds of that document's profile;
- the fold of an epoch (FO rules, quorum, policy evaluation) reads that epoch's document's profile, along the path to H for an epoch before the last, and the whole bag for the last epoch (GP-09);
- a change's head validity, the validation of the previous epoch along the path to H, the authority test of ACT-13, clean(k, H) and the previous policy's quorum (GP-19) read the previous document's profile;
- the carry of devices (GP-20: acceptance of a carried device, byte-identity, `genesis_device_revoked`, `genesis_device_changed`) reads the new document's profile, because the new document declares the carry and only its profile knows its classes; it reads the previous epoch only through the state `S_H` and the pool of earlier keys, whose shapes are frozen (below);
- `check-act`, `enrolled`, `head` and `sync` read the profile of the pinned (last) document; `sync` evaluates a successor of the pin as GP-19 does, under the pinned document's profile; `recheck-act` reads the profile of the document of the epoch the act's head is in (VR-17).

The order of GP-15 across documents and the pool of earlier keys (FO-07, FO-22) are lineage-wide: they are one rule for every edition, not a choice of any edition.

I3. The wire is the same in every edition. An edition MUST NOT change any of: the act form (ACT-01 to ACT-14, including the closed key sets, the envelope, the JWS form, the canonical subset and the encodings); the set of methods and their body schemas (ACT-09, ACT-10); the genesis document key set, its `v` constant and its hashing (GP-01, GP-04); the `genesis.sign` form (GP-15); the pin line `handsal-pin/1` and the pin file name (GP-05); the `consumer_id`, `action` and `subject` grammars (VR-18); the render grammar (RN-02 to RN-12), which the one signer applies to documents of every edition; the shape of a device entry of `S_H` and of the pool of earlier keys (GP-20, FO-07). A change to any of these is not an edition of this profile family: it is a new family, it means a new organization (re-founding), and it is outside this profile. What an edition MAY change: the registry's classes and their entries, the fixture kids, and the evaluation of an epoch (fold rules, policy bounds, quorum, freshness, cleanliness), subject to I2 (GP-24).

Whatever the registry holds that is not a class or a policy bound is wire by default: an unclassified registry key is frozen across editions, so a forgotten key fails closed.

Why: the same `genesis.sign` counts for possession under the new document's profile and for authority under the previous one (GP-15), and one signer, one act parser and one render serve a lineage whose documents name different editions. If any of those differed, a signature or a bag could mean two things in one lineage. Acts are parsed once for the whole lineage (GP-07), which is safe only because parsing reads nothing an edition can change. Obligation on a later edition: an edition that changes an evaluation rule adds, in its own change, one vector id for each rule it changes, one each for the cases of GP-23 S5 and S6 and VR-17 S20, and each is active from that edition on. The checker cannot tell by itself that a prose rule changed, so the edition that changes it states it. A third edition adds the vector for GP-24 S11 (a change that names an edition newer than the next).

- S1: GIVEN a lineage P1 original, P2 change, with the change's `genesis.sign` signatures WHEN each signature is read for possession under P2 and for authority under P1 THEN both read the same bytes and the same form. V: prf/change-p1-to-p2-ok
- S2: GIVEN the acts of the epoch of P1 and of the epoch of P2 of one lineage WHEN folded THEN each epoch's chain is built from the same parsed bag, and act parsing reads no value that depends on a profile. T: checker/python/tests/test_profile_set.py::test_act_parsing_reads_nothing_that_depends_on_a_profile
- S3: GIVEN any comparison of a profile hash or an edition position WHEN the source is scanned THEN it occurs only in the owner of the edition set of each implementation (checker, Rust core, Swift core). T: checker/python/tests/test_profile_guard.py::test_no_profile_comparison_outside_the_edition_set, tools/tests/test_core_files.py::test_no_profile_hash_comparison_outside_the_swift_and_rust_profile_files
- S4: GIVEN two editions WHEN their wire parts of the registry and their ACT, GP-01, GP-05, VR-18 and RN grammars are compared THEN they are identical, and the catalog check fails an edition that differs. T: tools/tests/test_catalog.py::test_an_edition_does_not_change_the_wire, checker/python/tests/test_profile_set.py::test_the_wire_view_is_identical_in_every_edition
- S5: GIVEN a rule that differs between P1 and P2 (an edition that adds a difference names each such rule) WHEN a change P1 to P2 is evaluated THEN the authority and head are decided by the P1 rule and the new document's structure by the P2 rule. T: checker/python/tests/test_profile_set.py::test_a_change_is_authorized_by_the_previous_documents_rule_not_the_new_ones
- S6: GIVEN a change that carries devices WHEN evaluated THEN the carry reads the new document's registry and `S_H` of the previous epoch. T: checker/python/tests/test_profile_set.py::test_a_carry_is_byte_identical_and_the_new_documents_edition_decides_acceptance

### GP-24 Migration and no downgrade

A migration is a GP-19 genesis change whose document names a newer edition than the previous document's. It has no act of its own: the signatures are the `genesis.sign` receipts of GP-15, the authority is the previous document's (I5), and the pin moves by the re-pin of GP-12 and GP-21, unchanged. Migration is optional: an organization that never migrates keeps working on its founding edition (I1). A change that does not migrate names the previous document's edition.

I2. Migrability. For every pair of adjacent editions Pn and Pn+1, and for every document D valid under Pn: the document D', equal to D in every member except `profile` (the hash of Pn+1, same kind), `prev`, `org` and `head`, MUST pass GP-15 steps 1 to 5 under Pn+1. Therefore, from any valid state under Pn, a change to Pn+1 exists that carries every active device and keeps every policy. In particular: every class that is `active` in the registry of Pn is `active` in the registry of Pn+1 with an identical entry (`alg`, `hardware_bound`, `per_signature_user_verification`, `user_verification`); the bounds of GP-02 do not narrow; and KC-03, KC-08 and the carry rules of GP-20 accept every device and policy that Pn accepted. A release that would break this does not publish the edition. There is no emergency withdrawal of a class: a compromised class is handled by removing the affected devices and publishing an advisory.

I4. No downgrade. A change whose document names an edition older than the previous document's, of the same kind, is `profile_downgrade`. Naming the same edition is allowed (a change that does not migrate, and every lineage made before a newer edition existed). Naming any newer supported edition is allowed, not only the current one: an organization may move to the newest edition its whole fleet runs. A bad edition is fixed forward by a newer one, and organizations do not migrate to it meanwhile. The comparison is by catalog order and needs both profiles implemented, which GP-15 step 2 has already established for the previous document. With a production and a fixture profile mixed, `fixture_profile` is decided first (GP-15 step 2). The fold alone enforces I4: the signer does not (SG-17).

"Current" never enters a fold rule: it depends on the release that reads the lineage, and a change made when P2 was current must stay valid on the release where P3 is current. The fold uses the catalog order only.

Why: a change names the profile that evaluates every later epoch. A quorum has no reason to move an organization to replaced rules, and an attacker who completes a stale change (section 14, L2) would use exactly this to return it to rules that have been fixed. Forbidding it costs nothing: an organization already has its older rules in its own earlier epochs.

- S1: GIVEN an original under P1 and a change under P2 whose authority is met by the P1 policy and signatures WHEN folded THEN the epoch under P2 is the state. V: prf/change-p1-to-p2-ok
- S2: GIVEN the same change with the P1 quorum unmet WHEN folded THEN `genesis_change_unauthorized`. V: prf/change-p1-to-p2-quorum-unmet-under-p1
- S3: GIVEN a lineage P2 original and a P1 change, with every other check passing, WHEN folded THEN `profile_downgrade`. V: prf/downgrade-refused. T: checker/python/tests/test_profile_set.py::test_a_downgrade_is_refused_over_a_synthetic_two_edition_set
- S4: GIVEN a lineage P1 original, P2 change and a P1 change WHEN folded THEN `profile_downgrade` for the third document. V: prf/downgrade-after-migration
- S5: GIVEN a lineage P1 original, P2 change and a P2 change WHEN folded THEN the epoch under P2. V: prf/second-change-same-edition-ok
- S6: GIVEN a document D valid under P1 and D' as I2 says WHEN D' is checked under P2 THEN it passes GP-15 steps 1 to 5. V: prf/migration-reprofiled-document-valid. T: checker/python/tests/test_profile_set.py::test_every_active_class_of_an_edition_is_identical_in_the_next, checker/python/tests/test_profile_set.py::test_a_valid_document_reprofiled_to_the_next_edition_passes_steps_1_to_5
- S7: GIVEN a downgrade document that also lists a class the previous profile does not know WHEN folded THEN `profile_downgrade` (step 2 before step 3). V: prf/order-downgrade-before-class
- S8: GIVEN a lineage whose original is a fixture profile and whose change is a production profile of an older edition WHEN folded THEN `fixture_profile`, not `profile_downgrade`. V: prf/order-fixture-before-downgrade
- S9: GIVEN a fixture-profile original of P1 and a production-profile change of P2 (or the reverse) WHEN folded THEN `fixture_profile`. V: fix/mixed-profile-lineage, prf/mixed-kind-across-editions
- S10: GIVEN a P1 pin and a valid P2 successor of the pinned document WHEN a non-chain act is checked THEN `epoch_superseded`, as for any successor (VR-12). V: prf/p2-successor-supersedes-p1-pin
- S11: GIVEN a catalog of three editions, a lineage P1 original and a change to P3 WHEN folded THEN the P3 epoch: a change may name any newer supported edition and need not name the current one or the next. V: prf/change-p1-to-p3-ok. T: checker/python/tests/test_profile_set.py::test_a_change_may_name_any_newer_edition_not_only_the_next_or_the_current
- S12: GIVEN two adjacent editions WHEN their GP-02 policy bounds are compared THEN no bound of the newer one is narrower than the older one's. T: checker/python/tests/test_profile_set.py::test_policy_bounds_never_narrow_between_adjacent_editions
- S13: GIVEN a device or a policy that the older edition accepts under KC-03, KC-08 or the carry rules of GP-20 WHEN the newer edition evaluates it THEN it accepts it. T: checker/python/tests/test_profile_set.py::test_kc03_kc08_and_the_carry_rules_accept_in_the_next_edition_what_the_previous_accepted

## 6. Fold

The fold computes an organization's state from its genesis lineage and an unordered bag of acts. It is the only place chain acts are examined.

Past-cone validity. The validity and effect of a chain primary, a `chain.resolve` and a genesis change depend only on the act's own bytes (signatures over them included) and its past cone (FO-26): the path from the act's parent back to the root, plus the paths to the nodes the act names (a resolve's candidates and heads, a change's head H). No rule reads descendants or later acts to decide whether such an act is valid or what it changes. Non-chain acts and tip statements are outside this rule: their checks read the state at the tip by design (VR-02, VR-12, WT-10).

One rule reads beyond a past cone: fork detection (FO-24), which compares the valid children of one parent and decides whether a resolve is current (FO-25).

Consequences:
1. Validity is permanent: an act valid in a bag is valid in every larger bag.
2. Which child of a parent is accepted is not permanent. A new valid primary can turn a resolved parent back into a fork. A different child wins only through a current resolve choosing it, and that resolve names, by effective entries (FO-25 condition (c)), every applicable resolve it overturns at its parent or discards below it.
3. A key valid at an old node stays valid there forever (FO-05). A removed key can still sign at nodes outside its removal's subtree (section 14, L1 and L4).

### FO-01 Signature

`fold` is a pure function: no clock, no I/O, no randomness. Input `{acts, at?, lineage, org, pin}`, with `pin` the probe object (GP-14); the production build takes no `pin` (CF-08). `acts` is an unordered bag: array order MUST NOT affect the result. The output is either `{"error":code}` or `{devices, keys, org, org_name, policy, spec, tip:{genesis, id, n}}`. `tip.n` is a decimal string: the position of the tip node in the accepted chain, root = 0, the count `at` takes (FO-16). A fork is `{"error":"fork","fork":{"candidates":[sorted ids],"parent":id}}`. On any error no `keys` are emitted, so a consumer cannot verify against a frozen or invalid state by forgetting a flag. `keys` is exactly the `keys` value of vitni CONTRACT.md section 7.

- S1: GIVEN the same acts shuffled WHEN folded THEN identical output bytes. V: fld/shuffle-same-output, fld/duplicate-act-twice
- S2: GIVEN a bag that forks WHEN folded THEN the fork error and no `keys`. V: fld/fork-error-no-keys

### FO-02 keys output

`keys` is `{<member id>: {<kid>: {alg:"ES256", crv:"P-256", kty:"EC", status:"active"|"revoked", x, y}}}` and nothing else inside the entries (the vitni CONTRACT.md section 7 shape). It contains exactly the accepted devices (KC-04, GP-18): `active` when active, `revoked` when removed. Devices that are not accepted are absent (vitni answers `unknown_key`) and appear only in `devices`, with `accepted:false`. A person none of whose devices is accepted has no entry in `keys`, not even an empty object. `keys` is a projection of `devices` computed by one function in the fold.

Meaning: a vitni `ok` against fold `keys` means only "signed by a key that is active and accepted in that state". It is NOT proof of a human decision and NOT an approval: it skips identity, inputs, relay, time, freshness, witness, replay and profile checks (VR-02). A non-chain act MUST be decided by `check-act`, or for a stored act by `recheck-act` (VR-17), whose `valid:true` and `rechecked:true` are the only human-proof signals (KC-04), and only when the production build (CF-08) returns them. The conformance build answers from a pin, evidence and a clock its caller supplies, and accepts the fixture profile, whose private keys are public: a consumer MUST NOT use its output to decide whether an act is a human decision, tests excepted. Chain acts are decided by the fold. A consumer that hands fold `keys` to vitni for a non-chain act and treats `ok` as an approval violates this requirement. `keys` keeps only accepted keys as defense in depth: a skipped `check-act` still cannot get `ok` for an unproven key.

- S1: GIVEN a removed device WHEN folded THEN its key stays in `keys` as revoked, so a valid signature by it checked at a later tip is `revoked_key`. V: vtn/revoked-key. C: fld/removed-stays-revoked
- S2: GIVEN a device of a class absent from the policy WHEN folded THEN its kid is absent from `keys` and present in `devices` with `accepted:false`. V: fld/unaccepted-not-in-keys
- S3: GIVEN an approve by an active accepted key whose `synced_at` is stale WHEN checked THEN `stale_view`, although vitni alone says ok against the fold keys. V: cls/vitni-ok-not-approval
- S4: GIVEN a valid act under the fixture profile WHEN the production build checks or re-checks it THEN `fixture_profile`: no human-proof signal rests on trust the caller supplied. T: checker/python/tests/test_builds.py::test_check_act, checker/python/tests/test_builds.py::test_recheck_act

### FO-03 devices output

`devices` MUST be `{<member id>: {<kid>: {accepted, agree:{x,y}, class, label, sign:{x,y}, status:"active"|"removed"}}}`. CLI output is not signed, so JSON booleans are allowed there, as in `check-act` `valid`. The key-agreement key appears only here, never in `keys`. A removed device keeps its entry with status `removed`.

- S1: GIVEN a device with `agree` equal to its `sign` WHEN introduced THEN it is rejected. V: fld/agree-equals-sign, fld/agree-not-in-keys

### FO-04 Chain recovery and link rules

Order is recovered from parent links, never from array position. The link rules are stated here in full. vitni CONTRACT.md section 8 is cited for intent only, because handsal differs from it in three places:
1. Every chain primary and every `chain.resolve` has a non-null `parent_receipt_hash`: the root id (the hash of the epoch's genesis document) at position 0, otherwise the position id of its parent. The handsal root is a document, not a receipt, so no chain act has a null parent. (vitni CONTRACT.md step 4 instead requires a null parent on the root hop.)
2. `parent_performer_id` MUST be null when the parent is the root, and MUST equal the `performer_id` of the parent primary otherwise. The check always runs; a null at a non-root parent is a mismatch. (vitni CONTRACT.md step 6 skips the check when the field is null.)
3. A chain act whose receipt id equals the receipt id of any ancestor is ignored as a cycle. Content addressing makes this unreachable for honest bytes; the rule fixes behaviour on hostile input. (vitni CONTRACT.md step 7 is a path check after the link checks; here it is a fold rule.)

A violation means the act is not on the chain. The fold never calls vitni `verify-chain`. Endorsements link to the act they endorse (FO-08).

- S1: GIVEN a primary whose `parent_performer_id` differs from its parent's performer WHEN folded THEN it is not on the chain. V: fld/parent-performer-mismatch, fld/dangling-parent
- S2: GIVEN a child of the root with `parent_performer_id` set, or a null `parent_performer_id` at a non-root parent WHEN folded THEN it is not on the chain. V: fld/root-child-parent-performer-set, fld/parent-performer-null-non-root

### FO-05 Prefix-state evaluation

Each chain act MUST be verified (vitni `verify` with binding and method pinned, plus the VR-03 and VR-04 checks) against the state at its parent, `S_P`. A removal therefore affects only later positions: a removed key cannot authorize a later primary, and its earlier primaries stay applied. Authority is evaluated on `S_P` only. This is the parent binding: validity against `S_P` depends only on the path to P, which is the act's past cone.

Why: vitni's `revoked` flag has no time; the fold supplies time by always evaluating against a prefix.

- S1: GIVEN K removed at position 5 and a primary signed by K at parent 5 WHEN folded THEN it is not on the chain; a primary by K at position 4 stays. V: rev/act-after-revocation-ignored, rev/act-before-revocation-kept

### FO-06 Failing acts are ignored, not errors

A chain act or endorsement that fails verification or authority MUST be ignored (not on the chain) and MUST NOT change the fold result. Only genesis and input problems are fold errors. A chain act whose signed `org` is not the organization's is ignored the same way, whatever its parent: the fold of an organization counts only the chain acts that name it (GP-04), so a device shared with another organization never lets that organization's act into this one's chain, and `admit`, `sync`, `compact`, `check-act`, `recheck-act` and `enrolled`, which all read the fold, agree on it.

- S1: GIVEN 100 forged acts appended WHEN folded THEN identical output. V: fld/junk-appended, fld/forged-sig-ignored
- S2: GIVEN a primary that names another organization in its `org` and whose parent is a node of this chain, with every signature valid WHEN folded THEN it is not on the chain. V: fld/other-org-primary-at-our-node

### FO-07 Proof of possession and uniqueness

A `device.add` or `member.add` is valid only with a proof-of-possession endorsement signed by the new key, with its `performer_id` per ACT-13, verified under `S_P` plus the new key as active. The proof-of-possession endorsement is never a counted signature. The receipts that make up a signed `device.add` or `member.add` are listed in FO-23.

The new `kid`, `sign` point and `agree` point MUST NOT equal the kid, sign or agree key of any device of `S_P` (removed devices included), of any device of an earlier lineage epoch (its document and the state at the H that closed it, GP-19), or the epoch's relay key (WT-01). The comparison runs over one pool of kids and one pool of points, and the points of `sign` and of `agree` share the points pool: a new `sign` point equal to any `agree` point of the pool is refused, and so is a new `agree` point equal to any `sign` point. A kid removed there never returns. Acts of an earlier epoch outside the path to its closing H are not read.

- S1: GIVEN a `device.add` without the new key's endorsement WHEN folded THEN it is not on the chain. V: add/ok, add/no-pop, add/pop-performer-mismatch
- S2: GIVEN a `device.add` that re-introduces a removed kid WHEN folded THEN it is not on the chain. V: cas/removed-never-returns
- S3: GIVEN a `device.add` introducing the relay key as `sign` WHEN folded THEN it is not on the chain. V: wit/device-add-relay-key-ignored

### FO-08 Endorsement rules

An `act.endorse` receipt MUST have `parent_receipt_hash` = the receipt id of the endorsed chain act, `parent_performer_id` = its `performer_id`, `body.act` = that id, and `head = {id: the endorsed act's parent_receipt_hash, kind: "chain"}`, so the endorser saw the same state. Endorsements of endorsements, of non-chain acts or of unknown ids, and endorsements with another head, are ignored. Which endorsements count, and how persons are counted, is FO-23.

The `ts` of an endorsement is the time its signer signed it, from the signer's clock (SG-04), a `time` under ACT-07 like every `ts`. The fold reads no `ts`: an endorsement counts by this requirement and FO-23 whatever its `ts` is next to the `ts` of the endorsed act or of other endorsements, so neither the order nor the spacing of signatures is evidence, and the fold never depends on a clock.

Why: a late endorsement from a signer who saw a newer state cannot revive a primary made at an older parent.

- S1: GIVEN an endorsement whose head is a later position WHEN folded THEN it does not count for a primary at an older parent. V: end/head-binding, end/endorse-endorsement

### FO-13 Quorum is policy

The fold MUST contain no role name, threshold, class id or duration. Roles and counts come only from the epoch's policy and the persons in `S_P`. Persons are counted once however many of their devices signed. A person with no active accepted key contributes no signature. The floor of 2 lives in GP-02, not in the fold.

- S1: GIVEN a maintainer removed so that two of three maintainers remain WHEN a `member.add` with Q = 2 is signed by both THEN valid; with one maintainer remaining THEN never valid. V: quo/two-left-reachable, quo/one-left-unreachable

### FO-15 Non-chain acts

Non-chain acts are never on the chain. They are verified at ingestion (VR-14) against the fold at the verifier's tip.

- S1: GIVEN a bag holding one chain act, a valid `request.approve` and a valid decision WHEN folded THEN the output equals the output for the bag without the verdict and the decision. V: fld/non-chain-acts-ignored

### FO-16 at

`at = n` (a decimal string) counts nodes of the accepted chain from the root (root = 0). An `n` at or before the last accepted node returns that prefix state, also when the chain ends at a fork parent. An `n` beyond the tip is `at_beyond_tip`. An `n` beyond a fork parent is `fork`.

- S1: GIVEN a chain of 4 WHEN `at` is `"2"` THEN the state after two positions; likewise for `"0"`, `"1"`, `"3"` and `"4"`, and an `n` of `"9"` is `at_beyond_tip`. V: fld/at-beyond-tip. C: fld/at-0-state, fld/at-1-state, fld/at-prefix-states, fld/at-3-state, fld/at-4-state
- S2: GIVEN a fork at accepted node 2 WHEN `at` is `"2"` THEN the state at 2; WHEN `at` is `"3"` THEN `fork`. V: fld/at-beyond-fork-parent. C: fld/at-fork-parent-state

### FO-21 Verify before deduplication

The fold verifies every JWS in `acts` (recognizer, schema, vitni, low S) before grouping by receipt id. Among JWS sharing a receipt id only valid ones count, and one valid copy suffices. An invalid copy never shadows, replaces or blocks a valid one, whatever its place in `acts`. The same holds for genesis signatures (GP-15) and endorsements.

Why: identity is the receipt id (ACT-12) but evidence is a valid signature. Whoever can append bytes must not be able to hide an act by appending a twin with a garbage signature.

- S1: GIVEN a valid primary and a twin with its payload and a garbage signature listed first WHEN folded THEN the primary applies. V: fld/garbage-twin-does-not-shadow, fld/garbage-twin-only

### FO-22 Quorum authority

Every chain act is valid only if its counted signatures (FO-23) come from at least `Q_r` distinct persons, where `Q_r` is `policy.rules[r].persons` of the epoch (for a genesis change, of the previous epoch), and its body conditions hold against `S_P`:

| Act | Rule `r` | Body conditions against `S_P` |
|---|---|---|
| `device.add` | `device.remove` | proof of possession by the new key (FO-07); `body.person` is a member; the new key's class is allowed for that person (KC-08); consent (below) |
| `device.remove` | `device.remove` | `body.kid` is a device of `body.person`, active in `S_P`; a member may end with zero devices (FO-27) |
| `member.add` | `member.add` | proof of possession (FO-07); the member id is unused in `S_P` and in every earlier lineage epoch (its document and the state at the H that closed it, GP-19); `role` is listed in policy `roles`; the new key's class is allowed for `role` (KC-08) |
| `chain.resolve` | `chain.resolve` | FO-25 |
| genesis change | `genesis.change` of the previous policy | GP-19 |

Two devices of one person are one person. There is no other authority path: no single-signature act and no same-person path. The holder of a removal's target counts like anyone, which is the target's consent. The new key of an add never counts, because it is not in `S_P`.

Consent on `device.add`. If `body.person` has at least one device active and accepted in `S_P`, the act MUST also carry a signature, primary or an endorsement passing FO-08 and FO-21, by a key of `body.person` that is active and accepted in `S_P`. That signature is one of the act's signatures and counts toward Q like any other when the person holds a listed role (FO-23), so adding your own new phone takes your own key plus one other person. If `body.person` has no such device (zero devices, or only devices of classes the policy does not accept), no consent exists and none is required: Q other persons add the device. Consent applies to `device.add` only: `member.add` creates a person with no device, and in `device.remove` the target already counts. The receipts that carry the signatures are listed in FO-23.

Removal needs no consent, because a compromised key must be removable without its holder. So Q persons can replace the keys of a person who has n devices in n + 1 visible acts: n `device.remove` acts, one for each key, then one `device.add` for the now device-less person (section 14, L6).

Why: no set of signatures from fewer than two persons changes trust state (section 1.3). A device is never added beside a person's working key unless one of that person's keys signed.

- S1: GIVEN alice and alice2 sign a `device.add` of alice3 WHEN folded THEN it is not on the chain; GIVEN alice and bob THEN applied. V: add/ok-two-devices-same-person, quo/single-person-act-rejected
- S2: GIVEN alice2 alone signs its own removal WHEN folded THEN it is not on the chain; GIVEN alice2 and bob THEN applied. V: rem/self-removal-ok, frk/two-self-removals-no-fork, quo/self-removal-needs-second-person
- S3: GIVEN alice signs the removal of bob2 and bob2 endorses WHEN folded THEN applied (the target counts). V: rem/target-is-endorser
- S4: GIVEN alice holds an active key and bob and carol sign a `device.add` of X1 for alice WHEN folded THEN it is not on the chain; GIVEN bob signs and alice's own key endorses THEN applied. V: quo/device-add-needs-own-key, quo/device-add-own-key-as-endorser-ok
- S5: GIVEN alice's old key was removed, alice holds another active key, and the consent is signed by the removed key WHEN folded THEN it is not on the chain. V: quo/device-add-consent-from-removed-key-invalid
- S6: GIVEN bob and carol remove alice's only key, then add X1 for alice WHEN folded THEN both apply. V: quo/remove-then-add-replaces-keys
- S7: GIVEN a `member.add` whose member id belonged to a member of epoch 0 dropped by the change WHEN folded THEN it is not on the chain. V: mem/id-reused-across-epochs
- S8: GIVEN a `member.add` signed by one maintainer, or by two devices of one maintainer, WHEN folded THEN it is not on the chain; GIVEN two of three maintainers THEN applied. V: mem/ok-2-of-3, mem/one-of-3, mem/two-devices-one-person

### FO-23 Counted signatures

The signatures of a chain act A with parent P are its primary signature and every endorsement of A that passes FO-08 (`body.act` = A, `head.id` = P). A signature is **counted** iff all hold:
1. it verifies per FO-21 (recognizer, schema, ACT-13, ACT-14, vitni with binding and method pinned, low S);
2. its key is active and accepted in `S_P`;
3. the key's person holds a role listed in `rules[r].roles`;
4. for `chain.resolve` only: the key is clean on the resolve's examined paths (FO-25).

The proof-of-possession endorsement belongs to the new key and is never counted. `persons(A)` is the set of distinct persons of A's counted signatures. A is valid iff its primary verifies under a key active and accepted in `S_P` (the primary signer need not hold a role) and `persons(A)` has at least `Q_r` members.

Surplus. The effect of a valid act is a function of its method and body only. No output field, no other act's validity, no fork decision and no cleanliness evaluation reads which signatures an act carries beyond the test above. One exception: an effective `overrides` entry (FO-25) reads the endorsements it names; an endorsement named by an entry is evidence for that entry, not surplus. So two bags that differ only in endorsements that no `overrides` entry names, and whose removal leaves every act valid, fold to identical bytes. Validity is monotone: adding a valid signature never makes an act invalid. The consent condition of FO-22 is part of validity and reads the same passes, so it breaks neither rule.

**Shape of a signed chain act.** A chain act A with parent P is carried by these receipts and no others that count: the primary (the act itself, `parent_receipt_hash` P), zero or more `act.endorse` receipts naming A (`body.act` = A, `head.id` = P, FO-08), and for a `device.add` or `member.add` the proof-of-possession endorsement of the new key (FO-07). With Q = 2, a `device.add` of a new device for a person with no accepted device is therefore three receipts: the primary by one person, one endorsement by a second person, and the proof of possession by the new key, which is never counted. For a person with an accepted device, one of the two signing keys, primary or endorser, belongs to that person (FO-22).

This requirement is the only place that reads the signatures of a chain act.

- S1: GIVEN alice and bob add alice2 and carol also endorses WHEN folded THEN the output is identical to the bag without carol's endorsement. V: quo/surplus-endorsement-same-output, quo/surplus-no-role-ignored
- S2: GIVEN a sequence where one person's keys sign a removal and a competing act at one parent WHEN folded THEN only the two-person removal applies. V: frk/bc1-sequence-rejected
- S3: GIVEN a `member.add` endorsed by a member whose role is in no rule WHEN folded THEN that endorsement is not counted. V: mem/endorser-no-role, add/pop-not-counted

### FO-24 Children, fork and refreeze

Each chain primary names its parent (FO-04) and is valid or not against `S_P` alone (FO-05, FO-22, FO-23). A pure fold has no "current tip": a primary at an old parent is evaluated exactly like one at the tip. `children(n)` is the set of valid primaries whose parent is n. Resolves, endorsements and invalid acts are never children.

Walk: the accepted chain is walked from the root. At each accepted node n:
1. no child: n is the tip;
2. exactly one child: it is the next node;
3. two or more children: let CR be the resolves current at n (FO-25). If CR is empty, n is a fork with candidates `children(n)`. Otherwise every resolve in CR chooses the same child, and that child is the next node: two current resolves that chose different children would each have to name the other by an effective entry (FO-25, Current (c)), and a receipt id covers the bytes of the act that carries it, so the two ids would depend on each other, a hash cycle that no signed bytes make. A fold that meets two chosen children at one node has met a state this profile cannot produce and raises an internal error.

The fork output is FO-01's: `{"error":"fork","fork":{"candidates","parent"}}`, candidates sorted ascending, no `keys`. Every consumer fails closed.

A fork means two valid children of one parent, each carrying counted signatures of Q persons whose keys were valid at the parent. Causes include a quorum that signed two conflicting acts, an honest race, a stale proposal completed later, and a removed key used at an old parent together with Q-1 touches (section 14). The response is to freeze; the exits are in FO-27.

Refreeze: the walk is recomputed from the whole bag on every call. A new valid primary below n that a current resolve did not examine (a new child of n, or an extension of a branch the resolve discards) makes that resolve not current, and n is a fork until a resolve that examined it exists. Acts in the chosen child's subtree never affect a resolve at n.

Finality: for bags B and B' with B a subset of B', and a node n reached by the same path in both: if `fold(B)` takes child c at n, then `fold(B')` takes c, or reports a fork at n, or takes another child c' only through a resolve current in B' that chooses c'. Validity is monotone, and nothing but this walk and current resolves ranks children.

No takeover: a resolve current at n that chooses c' over c examined every valid primary in c's subtree, so no key removed anywhere in c's subtree counts for it (FO-25). A key removed on a branch never helps discard that branch.

The accepted child of a parent changes only through a current resolve signed by Q persons whose keys are removed on none of the branches it discards, and which names, by effective entries, every applicable resolve FO-25 condition (c) requires. No act signed by fewer than Q persons has any effect. This walk is the only rule that reads siblings.

- S1: GIVEN honest c at P and one tricked signature by bob on any act at P WHEN folded THEN the output is unchanged. A self-removal signed by its key alone is not a valid chain primary (FO-22), so it is no child of P and cannot fork it. V: frk/single-touch-cannot-fork, frk/two-self-removals-no-fork
- S2: GIVEN c1 by alice and bob and c2 by bob and carol at P WHEN folded THEN `fork`. V: frk/quorum-equivocation-freeze, frk/two-identical-bodies-fork
- S3: GIVEN alice's stale proposal at P completed by bob's late endorsement while c sits at P WHEN folded THEN `fork`; plus a resolve by bob and carol choosing c THEN c; plus a second stale proposal at P completed by one touch THEN `fork` again; plus a resolve examining it THEN c. V: frk/late-endorsement-stale-head-fork, frk/stale-proposal-second-stale-refreezes. C: frk/stale-proposal-first-resolve-lifts, frk/stale-proposal-refreeze-lifted-again
- S4: GIVEN a current resolve choosing c1 and then a new valid primary under c2, or a new child c3 of P, WHEN folded THEN `fork`; plus a resolve whose heads examine it THEN c1. V: frk/losing-branch-extension-refreezes, frk/resolve-new-child-refreezes. C: frk/losing-branch-extension-lifted, frk/resolve-new-child-lifted
- S5: GIVEN two valid two-person removals of different devices at one parent WHEN folded THEN `fork`. V: frk/two-valid-removals, frk/mutual-disqualification
- S6: GIVEN bag B where c is built upon at P, and B plus one two-signer leaf, or one two-act branch, at P WHEN folded THEN c in B and `fork` in the larger bag, never another winner. V: frk/finality-added-leaf-only-forks, frk/finality-added-branch-only-forks. C: frk/finality-base-bag-applies

### FO-25 chain.resolve

A resolve has body `{candidates, choose, heads, overrides}` (ACT-09), parent P, endorsements per FO-08, and the candidate and head acts attached for its render (RN-09). The candidates other than `choose` are the **losing candidates**. `heads` names the nodes up to which the resolve examined them: each head is a losing candidate or a valid primary in a losing candidate's subtree; each losing candidate has at least one head in its subtree; no head is an ancestor of another. The **examined paths** are the paths from P (exclusive) to each head (inclusive).

**Applicable** (validity; reads only the past cone):
1. every candidate is a child of P, and `choose` is one of them;
2. `heads` meets the conditions above;
3. the counted signatures (FO-23) meet `rules["chain.resolve"]`, where a key counts only if, besides FO-23 items 1 to 3, it is **clean on the examined paths**: it is not the `body.kid` of any `device.remove` on an examined path.

Once applicable, a resolve stays applicable in every larger bag.

**Effective override entry.** An `overrides` entry `{endorsements, resolve}` of a resolve X at parent P is effective iff all hold:
1. `resolve` is the receipt id of an applicable resolve R whose parent is P or a node on X's examined paths;
2. every id in `endorsements` is the receipt id of an endorsement of R in the bag that passes FO-21 and FO-08 (`body.act` = R, `head.id` = R's parent); one valid copy suffices and an invalid copy never counts;
3. the counted signatures (FO-23 items 1 to 4, evaluated with the state at R's parent, R's policy rules, and item 4 on R's own examined paths) of R's primary and of exactly the endorsements named, and no other, meet R's `rules["chain.resolve"]`. X's parent P plays no part in this condition.

An entry that is not effective has no effect: it neither helps X nor makes it invalid. R stays applicable and its endorsements stay valid in every larger bag, so an effective entry stays effective.

**Current** (fork detection, FO-24): an applicable resolve X is current iff
- (a) `candidates` equals `children(P)` as a set;
- (b) every valid primary in a losing candidate's subtree lies on an examined path;
- (c) every applicable resolve R with (i) parent P and a `choose` different from X's, or (ii) parent a node on X's examined paths (any `choose`), is named by an effective entry of X.

The chosen candidate's subtree is never read.

Effect: FO-24 step 3. The resolve takes no position, has no children, and is never a head or an H.

Conflicting resolves: two applicable resolves that each fall under (c) of the other and do not name each other by effective entries are both not current, so P is a fork until one resolve names the disagreeing ones with evidence. A completed resolve that cannot name an applied one, because it was signed before that one completed, freezes P. It never replaces the applied choice, except as stated in section 1.4.

Equivocators: a person who signed two children of P counts like anyone. An honest person can sign two children in a race, and an attacker holding Q persons' signatures already holds authority.

Why heads, and why the losing side only: the resolve discards the losing branches whole. It must not count a key those branches removed, which would erase the removal, and it must not discard acts it did not see. Naming the heads fixes both in the resolve's bytes. The chosen branch is kept whole, so nothing on it is erased and nothing on it is read: later acts there, honest removals of the resolve's own signers included, never affect the resolve.

Why keys from `S_P` only (FO-23 item 2): a key added on a branch after P never counts. Otherwise one removed key plus one tricked touch could add a fresh key for a second person on its own branch and choose that branch. The cost: a person whose every `S_P` key is unusable, or removed on a losing branch, cannot sign the resolve; the exit is FO-27.

Why condition (c)(ii): a resolve at P discards its losing subtrees whole, including choices applied there by resolves at lower parents. Naming them with evidence makes "discarded" as strict as "overturned": a resolve signed before a lower resolve completed cannot name it, so once that lower resolve is applicable, the resolve at P is not current. That is a freeze, never a silent discard.

Why evidence: an endorsement's receipt id hashes a payload carrying 32 bytes of signer randomness (`nonce`, SG-04), so a resolve can name that evidence only after it exists. A receipt id alone would not do: it exists as soon as a primary is signed, before the resolve completes.

A current resolve that overturns or discards an applied resolve's choice names it together with evidence that existed only after that resolve completed. FO-25 condition (c) is the only reader of `overrides`.

- S1: GIVEN K removed by bob and carol on branch c1 and a resolve by K and bob choosing c2 whose heads cover c1 WHEN folded THEN ignored, `fork`; GIVEN its heads stop before the removal THEN not current, `fork`. V: rsv/revoked-on-branch-not-counted, rsv/stale-head-not-current, rsv/stale-head-covers-removal-ignored
- S2: GIVEN an applied resolve signed by alice's key a1 and bob choosing c2 and, later, alice and carol remove a1 on c2's branch WHEN folded THEN c2 stays. V: frk/resolve-not-voided-by-later-acts, rsv/chosen-branch-removal-not-read
- S3: GIVEN alice's key X1, added on c1 after P, signs a resolve choosing c1 WHEN folded THEN X1 is not counted. V: rsv/fresh-key-on-chosen-branch-not-counted
- S4: GIVEN a current resolve by bob and carol choosing c1 (heads [c2]) and a stale resolve choosing c2 (heads [c1]) completed by one touch WHEN folded THEN `fork`, also after a later primary under c1; plus a resolve by bob and carol choosing c1, heads [c2], overriding the stale one with its evidence THEN c1. V: frk/stale-resolve-completed-forks, frk/stale-resolve-late-endorsement-still-forks, rsv/override-wrong-id-not-current. C: frk/stale-resolve-lifted-by-override, rsv/overriding-resolve-lifts-conflict
- S5: GIVEN heads in the chosen subtree, or one head an ancestor of another WHEN folded THEN ignored. V: rsv/head-outside-losing-subtree-ignored, rsv/heads-ancestor-pair-ignored
- S6: GIVEN an applied resolve choosing c1, then a stale primary under c2 and a stale resolve choosing c2, each completed by one touch WHEN folded THEN `fork`, never c2. V: frk/two-stale-artifacts-cannot-replace-winner, frk/two-stale-artifacts-stale-primary-forks. C: frk/two-stale-artifacts-winner-applied, frk/two-stale-artifacts-override-lifts
- S7: GIVEN a losing candidate c2 with children d1 and d2 and a resolve choosing c1 with heads [d1, d2] WHEN folded THEN c1. V: rsv/two-heads-one-losing-candidate-current
- S8: GIVEN bob's pending R1 (c1) at P with bob2's endorsement e_b2 (same person, so it does not complete R1), alice's S (c2) naming R1 with [e_b2], then carol completes R1, then bob's tricked touch completes S WHEN folded THEN `fork`, never c2; plus R3 by bob and carol naming S with its evidence THEN c1. V: frk/pending-name-override-cannot-replace. C: frk/pending-name-override-first-resolve-applies, frk/pending-name-override-lifted
- S9: GIVEN R1 applied (c1) and, after it, alice's S (c2) naming R1 with its completing endorsement, completed by bob WHEN folded THEN c2 (one proposal plus one touch, section 1.4). V: rsv/override-with-completion-evidence-current, rsv/override-completion-evidence-first-resolve-applies, rsv/override-evidence-insufficient-not-current, rsv/override-evidence-bad-signature-not-effective
- S10: GIVEN R_P at a node d below P whose evidence key was added between P and d, named by X at P WHEN folded THEN the entry is effective. V: rsv/override-evidence-key-added-below-p-counts
- S11: GIVEN R_G applied at G (c1), alice's pending R_x at G (c2) naming R_G with evidence, then R_P applied at a node of c1's branch, then bob completes R_x WHEN folded THEN `fork` at G; GIVEN R_x signed after R_P and naming both with evidence THEN c2. V: frk/ancestor-override-cannot-discard-unseen-resolve. C: frk/ancestor-override-before-completion-applies, frk/ancestor-override-lifted, rsv/override-names-discarded-subtree-resolve-current
- S12: GIVEN two applicable resolves choosing different candidates that do not name each other WHEN folded THEN `fork`. V: rsv/conflicting-resolves-freeze
- S13: GIVEN a fork at P (c1, c2) and one resolve, or two resolves, choosing c1 with heads [c2] WHEN folded THEN c1 is the next node. V: rsv/lifts-fork, rsv/same-choice-two-resolves-ok
- S14: GIVEN an honest chain below node 3 whose last act removes K, a rival child c2 of 3 signed by K, and a resolve by bob and carol choosing the honest child WHEN folded THEN the honest child; GIVEN then a resolve by K and carol choosing c2 THEN `fork` at 3 (applicable, never current); GIVEN then a resolve by bob and carol naming it with its evidence THEN the honest child. V: frk/r11-resolve-above-removal-costs-override. C: frk/r11-honest-resolve-applies, frk/r11-override-lifts
- S15: GIVEN a person minted at node 3 by K and one tricked touch, with a branch that removes bob and carol, and a resolve by bob and carol whose examined path holds those removals WHEN folded THEN the resolve is ignored and `fork` at 3; GIVEN an honest change with H on the honest branch THEN the state of the new epoch. V: frk/r11-minted-person-branch-freezes. C: frk/r11-minted-person-change-recovers

### FO-26 Act tree, past cone, accepted chain, cleanliness

These definitions are stated once:
- **act tree** of an epoch: the root plus every chain primary valid (FO-22, FO-23, body rules) against the state at its parent. Resolves and endorsements are never nodes. Each primary is verified once per call (memoized).
- **past cone** of an act: the nodes on the path from its parent to the root; for a resolve, also its candidates (applicability condition 1 reads them, `choose` included) and the paths to its heads; for a genesis change, the path to H.
- **state at node n** (`S_n`): the result of applying the primaries on the path from the root to n, in order. A removed device keeps its entry with status `removed`.
- **accepted chain**: the nodes FO-24 reaches from the root, ending at the tip or at a fork parent.
- **clean on the examined paths**: FO-25 only, defined there.
- **clean(k, H)** (GP-19, GP-20): k is active and accepted in `S_H`. Nothing after or beside H is read.

A removal counts against its key in every act whose past cone contains it and in every resolve that discards its branch, and nowhere else. No later act changes whether an act is valid.

- S1: GIVEN a resolve at P chose c1, losing c2 removed bob, and a later fork at a node of c1's branch WHEN a resolve there or a change with H on c1's branch counts bob THEN bob counts. V: cln/losing-branch-no-effect, chg/removal-in-losing-branch-no-effect
- S2: GIVEN a single-person removal of bob, which is not an act, WHEN bob signs a resolve THEN bob counts. V: cln/invalid-act-removal-no-effect
- S3: GIVEN a key whose device class the epoch's policy does not accept WHEN clean(k, H) is asked THEN false, whatever the person's role. T: checker/python/tests/test_tree.py::test_an_unaccepted_key_is_not_clean

### FO-27 Liveness: last device, unreachable rules, exits

- A member may end with zero devices through a Q-person removal. That member has no signature until Q other persons add a device for them; their new key never counts for its own add.
- A rule is reachable at node n iff the role-holding persons with an active accepted key in `S_n` number at least `Q_r`. Genesis requires one spare person per rule (GP-02), so one person losing every device never makes a rule unreachable; two persons doing so with Q = 2 of 3 does. A role holder's key enters the state only through `device.add` (rule `device.remove`) or `member.add`. A rule unreachable at n therefore becomes reachable again below n only through such acts, under whichever of those two rules is reachable there, giving its role holders active accepted keys. Once both `device.remove` and `member.add` are unreachable at n, every rule unreachable at n stays unreachable on every path below n. When `genesis.change` is unreachable at every node, the epoch cannot be changed, and the only exit is a new original genesis (a new org id; every consumer re-pins). Recovery is out of scope.
- Fork exits, in order: (1) a current resolve (FO-25). It is possible iff Q role-holding persons can sign with keys active and accepted in `S_P` that no examined path removes, P has at most 17 children, the losing candidates hold at most 16 leaves in total, the resolves condition (c) requires number at most 16, and each can be named within 15 endorsements. A minimal evidence set has at most Q endorsements (Q-1 when R's primary is counted; the primary signer need not hold a role), and GP-02 bounds every `persons` at 15, so naming always fits. (2) A genesis change with H on the branch to keep (GP-19): its validity reads only the path to H, so no act anywhere can block or later invalidate it, and it applies through a re-pin. (3) A new original genesis.
- Single-person and two-person organizations cannot exist in version 1: GP-02 requires `Q_r` to be smaller than the number of role holders for every rule. The ceremony refuses them (SG-12).

The fold never invents authority to leave a deadlock. Every stop state is a loud error or an unreachable rule, never a silent default.

- S1: GIVEN the three maintainers and the only devices of bob and carol removed by two Q-person removals WHEN alice alone signs any chain act THEN it is not on the chain. V: quo/one-left-unreachable, quo/last-device-removed-no-vote
- S1b: GIVEN the same state WHEN a change lists alice plus new maintainers frank and grace and every listed device signs THEN `genesis_change_unauthorized` (only alice counts, GP-19). V: quo/two-lost-persons-unreachable
- S2: GIVEN alice and bob remove carol's only device WHEN folded THEN applied, and carol has zero devices. V: rem/remove-last-device
- S3: GIVEN a frozen fork WHEN a genesis change with H on the branch to keep is pinned THEN the new epoch is the state. V: frk/genesis-change-recovers
