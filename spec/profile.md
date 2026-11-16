# handsal profile, version 1

This is the normative text of the handsal profile. handsal turns a vitni signed receipt into proof that a person decided something with a hardware-bound key: an approval of a request, a decision about content, or a change to who may sign for an organization. The profile fixes the bytes of every signed act, the trust anchor a machine pins, the pure function that folds an organization's acts into its current keys, the rules a verifier applies to a single act, the text a signer shows before a signature, and the command line contracts that let independent implementations be compared byte for byte.

vitni is used unchanged. This profile narrows what vitni accepts and adds the rules vitni does not own.

## 0. Reading guide

- The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
- Requirement ids have the form `FAMILY-NN`. Families: `ACT` act profile (section 3), `KC` key classes (4), `GP` genesis and pin (5), `FO` fold (6), `VR` verifier rules (7), `RN` rendering (8), `CF` conformance and checker CLI (9), `SG` signer CLI (10), `WT` freshness witness (13). Ids are stable. An id is never renumbered and never reused. Gaps in a family are retired ids, listed in Appendix A with what replaced them.
- Each requirement states its rule, the reason codes it produces, and scenarios. A scenario is one line, `GIVEN ... WHEN ... THEN ...`, ending in its proof, in one or more tails. `V:` lists shipped conformance vectors, ids of the form `group/case`. `C:` lists shipped vectors that end in no reason code, the positive controls of a scenario whose THEN part names one. `P:` lists vectors that ship at the tag and wait for an owner step (the production-key vectors, CF-08). `T:` lists implementation tests, each a file path, two colons and a test name, which CF-07 lists. `O:` names a proof outside this repository's suites and whose it is (a consumer's tests, a platform check the owner runs by hand). When the THEN part names reason codes, a `V:` vector ends in one of them, and a tail other than `C:` proves the code. The ids listed are representative; the vector set holds further cases for most requirements.
- The profile is three files, one text: `spec/profile.md` holds sections 0 to 7, `spec/profile-interfaces.md` holds sections 8 and 9 and `spec/profile-part3.md` holds sections 10 to 14 and the appendices. Section numbers and requirement ids are global, so a reference names one place whichever file holds it. All three files are core files (CF-01), and a tool that reads the profile reads all three.
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
- **role holder**: a member whose role is listed in `roles` of any rule of the epoch policy (KC-08).
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

### GP-07 Lineage input

`fold`, `check-act`, `enrolled` and `genesis-check` take `lineage`: the ordered list `[{doc, sigs}]` from the original document to the pinned one, where `sigs` are that document's `genesis.sign` receipts. They also take one `acts` bag holding the chain acts of every epoch; each epoch's chain roots at its own document hash, so acts sort themselves into epochs. In the production build `check-act`, `recheck-act` and `enrolled` read `acts` and `lineage` from the store (CF-09) and an input carrying either is `malformed_input`. Every item of `acts` and of every `sigs` is a string: a string that is no valid act is ignored by the fold (FO-06), and an item of any other type is `malformed_input`.

The fold MUST validate every link: GP-03 for the original, and for each change GP-19 against the path to its H in the epoch before it, never the full fold of that epoch, so a fork there never fails a later epoch. Every command that reads a pin (`fold`, `check-act`, `enrolled`) makes three comparisons, in this order, at VR-02 step 6 (g). An empty lineage is `lineage_broken`. The pin's `org` MUST equal the hash of the first lineage document, which is the org id (GP-04), else `lineage_broken`. The pin's `genesis` MUST equal the hash of the last lineage document, else `genesis_pin_mismatch`. A document outside the canonical subset has no hash and never equals either: as the first document it is `lineage_broken`, as the last it is `genesis_pin_mismatch`. `genesis-check` and the pin helper read no pin and take the org id from the first document (CF-03, GP-21), so they cannot disagree with it. A lineage is also `lineage_broken` when its first document has a non-null `prev`, or when a later document's `prev` is not the hash of the document before it, or its `org` is not the hash of the first document (GP-15 step 4).

Every lineage document's `profile` MUST be implemented (`profile_mismatch`). Each epoch is evaluated under its own document's profile, and a change's authority under the previous document's profile. A lineage that mixes a production and a fixture profile is `fixture_profile` (GP-18). Version 1 implements one production profile. `fold`, `check-act` and `enrolled` take the required input `org` (GP-14).

- S1: GIVEN a lineage whose last document does not hash to the pin WHEN folded THEN `genesis_pin_mismatch`. V: chg/lineage-last-not-pinned
- S2: GIVEN a fixture-profile original and a production-profile change WHEN folded THEN `fixture_profile`. V: fix/mixed-profile-lineage
- S3: GIVEN a pin and an input `org` that agree, and a lineage whose first document hashes to another org WHEN folded THEN `lineage_broken`. V: pin/lineage-original-not-org
- S4: GIVEN a lineage whose middle document is absent WHEN folded THEN `lineage_broken`. V: chg/lineage-missing-doc

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
2. profile: `profile_mismatch`, `fixture_profile`;
3. policy and devices: `policy_invalid`, `policy_out_of_bounds`, `policy_unreachable`, `class_unknown`, `class_pending`, `class_test_only`, `class_policy_mismatch`, then a listed device of a class the policy does not accept (`genesis_schema`, GP-20), then `role_key_class` (KC-08), then `fixture_key` (GP-18);
4. links: `lineage_broken` (GP-07);
5. render size: `genesis_render_too_large` (RN-10; the difference render needs a valid `previous`);
6. possession: `genesis_unsigned`;
7. change only: `genesis_head_unknown`;
8. change only: `genesis_change_unauthorized`;
9. change only: `genesis_device_revoked`, then `genesis_device_changed`.

Inside one step the codes are tried in the order listed, each over the whole document before the next. A document with two defects of one step returns the code listed first, wherever the defects sit: a `class_unknown` anywhere in `classes` wins over a `class_pending` that comes earlier in the list.

Registry-dependent and policy-dependent checks run only after the profile and the policy are known. Junk or duplicate signatures cannot fail the fold; only a listed device without a counting signature can. A `genesis.sign` over a change without `head`, or over an original with `head`, does not count, so its device is unsigned (step 6).

- S1: GIVEN ORG's signatures plus a non-verifying one and a second valid one by alice WHEN folded THEN the state. V: gen/junk-sig-ignored, gen/duplicate-sig-same-kid-ok
- S2: GIVEN a `genesis.sign` over a change without `head` WHEN folded THEN `genesis_unsigned`. V: sch/genesis-sign-change-without-head, sch/genesis-sign-original-with-head
- S3: GIVEN two defects in one document WHEN folded THEN the earlier step's code. V: gen/order-schema-before-lineage, gen/order-lineage-before-unsigned, gen/order-unsigned-before-head, gen/order-unauthorized-before-carry, gen/order-profile-before-class, gen/order-lineage-before-render, gen/order-policy-before-device-class

### GP-17 WSL2 is unprotected until a Windows-side gate exists

A WSL2 host is a Linux host whose kernel release contains `microsoft` (compared without regard to case). Any other host has no pin location the checker can read (it is neither macOS nor WSL2), so its probe returns `{owner_ok:false, reason:"pin_probe_unavailable"}`: a checker on native Windows or on another Linux host never reports a machine enrolled.

On WSL2 an agent running as the user can usually obtain distribution root (`wsl.exe -u root`) and with it redirect every path a WSL2 process uses (bind mounts over `/mnt/c`, replaced binaries). Then no WSL2-side check is protected, the interop call to `pin-read` included.
1. The WSL2-side probe MUST return `{owner_ok:false, reason:"pin_probe_unprotected"}`, so no WSL2-side code ever reports a machine enrolled.
2. Before any Windows machine counts as enrolled, a Windows-side gate MUST exist: the production checker (CF-08) installed by an administrator under `C:\Program Files\handsal\`, reading the pin in the same process with the GP-11 checks and reading the clock itself, so pin read, fold and decision run in one administrator-installed Windows process that takes neither `pin` nor `now`. It is a native binary, or Python started as `python -I -E -s` from the administrator path with no user site. WSL2 consumers call it through interop at its absolute path (SG-14).
3. A WSL2 consumer receives the gate's answer through a path WSL2 root can redirect (section 14, L13).

- S1: GIVEN the WSL2-side probe WHEN `enrolled` runs THEN false, `pin_probe_unprotected`. The WSL2 probe itself is `test_probe_wsl.py` (CF-07). V: enr/wsl-unprotected

### GP-18 Fixture keys and profiles

- Each profile version defines two profile hashes from one core manifest (CF-01): a **production** profile and a **fixture** profile.
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

Authority: a signature counts iff it passes the authority test of ACT-13 (its key is a device of `S_H`, listed in the document or not), its key satisfies clean(k, H) (FO-26: active and accepted in `S_H`), and its person holds a role in the previous policy's `rules["genesis.change"].roles`. Counted persons MUST meet the previous policy's `persons` for that rule, else `genesis_change_unauthorized`. Several counting signatures by one kid are one. A carried device's possession signature naming H is also an authority signature when it meets these conditions, so a change carrying the devices of Q previous role holders is authorized by their possession signatures alone.

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

### GP-20 Carried devices across a change

- Every device listed in any document is of a class accepted by that document's policy, else `genesis_schema`, checked at GP-15 step 3 after the policy checks.
- A device whose kid occurs in an earlier lineage epoch (in its document, or in the state at the H that closed it) is **carried**. It MUST be active in `S_H` of the previous epoch, and it MUST NOT be `removed` in the state at the closing H of any earlier epoch, else `genesis_device_revoked`. Acceptance is decided by the new document's policy only, so a device whose class the old policy did not accept may be carried once the new policy accepts it.
- A carried entry MUST be byte-identical to its entry in `S_H` (`person`, `class`, `label`, `sign`, `agree`), else `genesis_device_changed`. Changing a label or class means removing the key and adding a new one.

Why: a re-pin never revives a key removed on the path to H or in an earlier epoch, and never changes a vouched device value outside the rendered difference.

- S1: GIVEN bob2 removed by bob and carol before H and a change carrying bob2 WHEN folded THEN `genesis_device_revoked`; GIVEN the removal after H THEN bob2 is carried. V: chg/carry-removed-kid-returns. C: chg/carry-revoked-after-head
- S2: GIVEN a listed device of a class the document's policy does not accept WHEN folded THEN `genesis_schema`. V: chg/device-unaccepted-class
- S3: GIVEN a change carrying bob2 with a new label WHEN folded THEN `genesis_device_changed`: a carried entry is compared whole, the class with the rest. V: chg/carry-entry-changed

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

Removal needs no consent, because a compromised key must be removable without its holder. So Q persons can replace a person's keys in two visible acts: remove every key, then add one for the now device-less person (section 14, L6).

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
3. two or more children: let CR be the resolves current at n (FO-25). If CR is empty, n is a fork with candidates `children(n)`. If every resolve in CR chooses the same child, that child is the next node. Otherwise n is a fork with candidates the distinct chosen ids.

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

The checker MUST call vitni `verify` with `policy.expected_binding = "local"` and `policy.expected_method = expect_method`, always set and never null. `keys` is the fold `keys`, except when the signer kid is a device with `accepted:false`: then it is a one-entry map keyed by that device's person in the state, `{person(kid): {kid: {that device's sign key, status: "active" if the device is active, else "revoked"}}}`. The signature of a key that is not accepted is therefore still verified before step 16 can say `unproven_class`. A `performer_id` that differs from the device's person yields vitni `unknown_key`.

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

`synced_at` is input data in the conformance build. `next` is the store's fact that a valid successor of the pinned document is known (CF-09): input data in the conformance build, read from the store in the production build. In the production build `synced_at` is the time `sync` last wrote the store after a fold that reached a verdict, a state or `fork` (CF-09), and only `sync` sets it. In order:
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
- S7: GIVEN a frozen bag at the pin and `next` `"yes"` WHEN `check-act` or `enrolled` runs THEN `epoch_superseded`, and `fork` with `next` `"no"`. V: ord/superseded-before-fork, enr/epoch-superseded-before-fork. T: checker/python/tests/test_rules.py::test_a_fork_at_a_superseded_pin_is_epoch_superseded_and_every_other_fold_error_keeps_its_place, checker/python/tests/test_enrolled.py::test_a_fork_at_a_superseded_pin_is_epoch_superseded_and_the_other_fold_errors_come_first, checker/python/tests/test_sync.py::test_a_fork_at_a_superseded_pin_is_epoch_superseded_as_in_the_readers

### VR-14 Ingestion contract

A consumer MUST run `check-act` once, when an act first arrives, and record `{receipt_id, valid, reason}` for a valid act, the values its output carries (VR-01). An invalid result is recorded keyed by the hashstr of the full JWS bytes, or not at all; it is never recorded against a receipt id, so a garbage-signature twin cannot make the consumer refuse the valid act later. The consumer MUST NOT re-run `check-act` on stored acts to decide historic validity, and MUST run it for every new act. Consumers verifying chain acts use the fold, not `check-act`.

A consumer MUST keep the full JWS of every act it accepts, and the request or content bytes it was accepted for, and MUST run `recheck-act` (VR-17) on the stored JWS at read time, before it treats the act as a human decision. The recorded `valid` is the consumer's own data, which an agent running as the same user can rewrite (section 14, L9); `rechecked:true` is recomputed from the act's signature and the pinned fold. Freshness and expiry are ingestion-only: `recheck-act` reads no clock, so a consumer that wants an expiry or a freshness decision at read time keeps the times it recorded at ingestion and decides them itself, knowing that record is editable too.

Why: an approval must not flip after an unrelated later revocation, so the decision made at ingestion stands and `check-act` is not run again. The record holds no tip: no command returns the tip `check-act` decided against, and `recheck-act` examines a stored act at its own head (VR-17). A decision that stands must still rest on something an agent cannot mint: the signed bytes. Vectors assert the pure-function side: a revocation after ingestion changes `check-act` at the new tip, which is why the consumer must not re-run it, and `recheck-act` of the same act is unchanged. The ingestion store is the consumer's and this repository ships none (CF-09 is another store), so the tests of the rest of this requirement (S2 to S4) belong to each consumer's own suite.

- S1: GIVEN an approve ingested at tip 7 and its signing key removed at 8 WHEN `check-act` is run at tip 8 THEN `revoked_key`; the consumer's recorded decision stands. V: ing/revoked-after-ingestion-recheck-fails
- S2: GIVEN an invalid twin of a valid act WHEN ingested THEN it is not recorded against the receipt id. O: the consumer's own test suite; this repository ships no store
- S3: GIVEN a valid act WHEN ingested THEN the record carries `receipt_id`, `valid` and `reason` as `check-act` returned them, and no value its output does not carry. O: the consumer's own test suite; this repository ships no store
- S4: GIVEN an ingestion record rewritten to say valid WHEN the act is read THEN the consumer runs `recheck-act` on the stored JWS and does not trust the record. O: the consumer's own test suite; this repository ships no store

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

Fold scope: the key is examined at the act's own signed head, with the chain acts of the bag. A key that was added after that head is `unknown_key`. A key removed after that head is still valid there (FO-05): `rechecked:true`, where `check-act` at a later tip says `revoked_key`. That is the intended meaning for an act accepted before the removal, and it is also the bound of section 14, L9. A key removed by a later epoch does not change the answer for an act of an earlier epoch: each epoch's act is examined in its own epoch's state. The bag and the lineage are the caller's in the conformance build; in the production build they are the store's, which keeps the path of every earlier epoch (CF-09, CF-14), so a head on such a path stays checkable. A head that they do not contain is `stale_view`, never a pass.

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
- S12: GIVEN the same data WHEN `check-act` and `recheck-act` run THEN they give one reason for every defect of steps 7 to 12 and 16: the steps are one list. T: checker/python/tests/test_recheck.py::test_both_commands_give_the_same_reason_for_every_time_free_defect, checker/python/tests/test_recheck.py::test_the_steps_are_one_list_cut_in_two
- S13: GIVEN the production build and an input carrying `acts` or `lineage` WHEN run THEN `{"error":"malformed_input"}`. T: checker/python/tests/test_builds.py::test_production_refuses_acts_lineage_synced_at_and_tip_statement
- S18: GIVEN a lineage that continues with a change at the root, pinned at the change, and an approve whose head is the root of the first epoch WHEN rechecked THEN `rechecked:true`: a stored act of an earlier epoch is not lost by a re-pin, while `check-act` still wants the head in the current epoch. V: rck/ok-act-of-earlier-epoch
- S14: GIVEN the same lineage and an approve whose head is a node beside the change, off the path to its head WHEN rechecked THEN `stale_view`. V: rck/head-past-change-stale-view
- S15: GIVEN the production build and an input with `pin`, `now` or any other key that names a moment WHEN run THEN `{"error":"malformed_input"}`, and the build reads the pin in process and never the clock. T: checker/python/tests/test_builds.py::test_recheck_act_refuses_pin_and_every_key_that_names_a_moment, checker/python/tests/test_builds.py::test_recheck_act_reads_the_pin_in_process_and_never_the_clock
- S16: GIVEN a verdict that names a host a later genesis change dropped from `relays` WHEN rechecked at its own head THEN `rechecked:true`, while `check-act` at the tip says `relay_mismatch`. V: rly/relay-dropped-at-tip-mismatch. C: rck/relay-from-head-epoch
- S17: GIVEN a `recheck-act` input carrying `next`, in either build WHEN run THEN `{"error":"malformed_input"}`. V: rck/next-input-malformed

### VR-18 Decision acts

`local:handsal.decision` records one decision of a person about content, on the machine where the person signs. It is the one generic method for a local human decision (ratify a ruling, forget an item), so a consumer does not need a method for each of its verbs. A verdict that travels between machines through a relay stays `request.*` (VR-08): it is addressed to a recipient and a relay, and a decision is for an act that stays on one machine, so it carries no `recipient`, no `relay` and no `request_id`.

The act (ACT-09): the act object has `expires` and `head` (always) besides the common keys; `performer_id` is the person of the signing device (ACT-13). The body is closed and all three keys are required:
- `action`: a short label of what is decided, an `action` (section 2.2): lowercase ASCII words separated by single spaces, 1 to 24 characters;
- `consumer`: the consumer the decision is for, a `consumer_id`;
- `subject`: the id of what the decision is about, a `subject_id`.

What binds what. `inputs_hash` is hashstr(raw bytes of the content decided), carried as the attachment `decision_b64` (RN-09): the person sees those bytes in the render (RN-12, at most 2048 bytes and 32 block lines, no truncation) and the signature covers exactly them, so an opaque id alone is never what a person decides. `outputs_hash` is hashstr(JCS({"action":A,"subject":S})) from the act's own body. `consumer` is signed and rendered (RN-03, RN-04): it is the domain separation that `recipient` and `relay` give a verdict, so a decision signed for one consumer cannot be accepted by another that expects the same words and bytes.

Who owns what. The profile owns the grammar and the rendering; a consumer owns its vocabulary. `action` is not data in the genesis policy: the checker accepts every `action` of the grammar and no list of labels exists in any profile file. `check-act` binds the key, the consumer, the content and the words: the caller gives the `action` and `subject` it asked for, as a verdict's caller gives the `request_id` and `recipient`, and no consumer compares them again. What stays with the consumer is its vocabulary: a consumer MUST accept only its own exact labels, and decide which `action` and `subject` to ask for.

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
