# handsal profile, version 1

This is the normative text of the handsal profile. handsal turns a vitni signed receipt into proof that a person decided something with a hardware-bound key: an approval of a request, the promotion of a record, or a change to who may sign for an organization. The profile fixes the bytes of every signed act, the trust anchor a machine pins, the pure function that folds an organization's acts into its current keys, the rules a verifier applies to a single act, the text a signer shows before a signature, and the command line contracts that let independent implementations be compared byte for byte.

vitni is used unchanged. This profile narrows what vitni accepts and adds the rules vitni does not own.

## 0. Reading guide

- The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
- Requirement ids have the form `FAMILY-NN`. Families: `ACT` act profile (section 3), `KC` key classes (4), `GP` genesis and pin (5), `FO` fold (6), `VR` verifier rules (7), `RN` rendering (8), `CF` conformance and checker CLI (9), `SG` signer CLI (10), `WT` freshness witness (13). Ids are stable. An id is never renumbered and never reused. Gaps in a family are retired ids, listed in Appendix A with what replaced them.
- Each requirement states its rule, the reason codes it produces, and scenarios. A scenario is one line, `GIVEN ... WHEN ... THEN ...`, followed by `V:` and the ids of conformance vectors that prove it. Vector ids have the form `group/case` and name files in the conformance vector set. The ids listed are representative; the vector set holds further cases for most requirements.
- A line starting with "Why:" explains a rule for implementers. It is not normative.
- Reason codes are lowercase snake_case. They are part of the contract and appear verbatim in outputs and vectors. Section 11 indexes them.
- "Fail closed" means: refuse, return a reason code, and never map an unknown or missing thing to a skip or a default.
- "Not on the chain" means the fold ignores the act: the fold output equals the output for the same bag without that act.
- Normative references: vitni 0.5.3, `conformance/CONTRACT.md` section 7 (`verify` input and algorithm) and section 8 (chain link checks), cited as "vitni CONTRACT.md"; RFC 4648 (base64url), RFC 6979 (deterministic ECDSA nonces), RFC 7493 (I-JSON), RFC 7638 (JWK thumbprint), RFC 7515 (JWS compact serialization).

Names used in scenarios (the conformance fixtures define them exactly):
- `alice`, `bob`, `carol`: members with role `maintainer`, one `apple-se-bio` device each. `alice2`, `alice3`, `bob2`, `X1`, `X2`: further devices added by two-person acts. `dave`: a member whose role is listed in no rule. `frank`, `grace`, `heidi`: new maintainers introduced by a genesis change. `K`: a key a scenario names as stolen or removed.
- ORG: the base genesis document. Members alice, bob, carol; roles `maintainer` and `member`; every rule `{persons:"2", roles:["maintainer"]}`; freshness `clock_skew_s "300"`, `max_validity_s "604800"`, `max_view_age_s "86400"`; witness `{"mode":"none"}`. LINEAGE and PIN_OK are its lineage and a passing probe. ORG4 adds a fourth maintainer `erin`. PINORG adds `dave` with a device of the fixture-only class `fixture-pin`.
- NOW: the fixed verifier time. SYNCED: `synced_at` equal to NOW. APPROVE: a valid `request.approve` by alice.
- WIT_ORG: ORG with a relay witness whose key is RELAY_FX. TIP_OK: a valid tip statement for WIT_ORG at tip T4, 60 seconds old.
- CHG-NEW: a change document that keeps the named role holders' devices and adds new maintainers `frank` and `grace`. CHG-VALID: a change document built from the devices active at its head.
- Fixture profile and production profile: section 9 (CF-01) and GP-18. PRODK: production-profile vectors signed by keys whose private scalars were destroyed after signing.

## 1. Scope and threat model

### 1.1 What this profile covers

The profile defines: the act format (section 3), the key class registry (4), the genesis document, its policy and the pinned trust anchor (5), the fold that computes an organization's state from its acts (6), the checks a verifier runs on one act (7), the text shown to a signer (8), the checker command line and the conformance vectors (9), the signer command line (10), and an optional freshness witness (13).

Out of scope: how acts are transported or stored, the relay server that produces witness statements (section 13 states only what a verifier checks and what a relay must do), the user interface of device linking, and recovery of an organization whose rules can no longer be met.

### 1.2 Threat principle

Any single biometric touch may sign attacker-chosen bytes. The full render is written to a terminal or console that every process of the same user can also write to. The key blob is usable by any process of the same user that obtains a touch, and such a process can call the platform API with prompt text of its own choosing. Neither the display nor the OS prompt text is a trust boundary: line 1 of the render, which the signer puts into the OS prompt, is an aid. No security property of this profile depends on what a person read.

The fold and the verifier MUST stay safe under one arbitrary signature per tricked touch.

### 1.3 Two persons for every trust change

Changing an organization's trust state always requires at least two distinct persons. Every chain act (`device.add`, `device.remove`, `member.add`, `chain.resolve`) and every genesis change needs counted signatures from Q distinct persons, where Q is the policy's `persons` value for that rule. The profile fixes `persons >= 2` (GP-02). A genesis document may set Q at or above that floor, never below it. A genesis change may lower Q, down to the floor, only with the previous quorum (GP-19).

Costs of this rule: adding your own new phone needs another person's touch; single-person and two-person organizations cannot exist in version 1; recovery stays out of scope.

### 1.4 What one tricked touch can do

This list is complete. One tricked touch can:
- sign one verdict or one record promotion. Line 1 names the request or record, its hash12 and its size;
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
- **epoch**: one genesis document and the chain rooted at it. The **root** of an epoch has id hashstr(JCS(document)) and is position 0.
- **position id**: the root id at position 0, otherwise the receipt id of the chain primary at that position.
- **children(n)**: the valid chain primaries whose parent is node n (FO-24). Resolves, endorsements and invalid acts are never children.
- **act tree**, **past cone**, **state at node n** (`S_n`), **accepted chain** and **clean(k, H)**: defined once in FO-26.
- **tip**: the last node of the accepted chain. The fold reports it as `{genesis, id, n}`, where `n` is derived and never signed.
- **counted signature** and **persons(A)**: defined once in FO-23.
- **role holder**: a member whose role is listed in `roles` of any rule of the epoch policy (KC-08).
- **decimal string**: `0` or `[1-9][0-9]{0,8}`.
- **Short forms** (render only): `kid12` is the first 12 characters of a kid, grouped `xxxx-xxxx-xxxx`; `hash12` is characters 3 to 14 (0-indexed) of a hashstr, that is the 12 characters after the constant `uEi`, grouped the same way.

### 2.2 Alphabets

- `member_id`: `[a-z0-9][a-z0-9-]{1,31}`
- `role_id`: `[a-z][a-z0-9-]{0,31}`
- `request_id`: `[a-z0-9][a-z0-9-]{7,35}`
- `record_id`: `[a-z0-9][a-z0-9-]{1,31}`
- `class_id`: `[a-z][a-z0-9-]{0,31}`, the form of the `class` of a device in a `device.add` or `member.add` body (ACT-09). A class in a genesis document or a policy is looked up in the registry (KC-01) instead: a string the registry does not list is `class_unknown` in a policy entry and `genesis_schema` in a device entry (GP-15 step 3).
- `text(max)`: 1 to max characters from 0x20 to 0x7E, excluding `"` and `\`. `label` is text(64), `org_name` is text(24), `anchor` is text(128).
- `hostname`: lowercase ASCII LDH labels (letters, digits and hyphens) separated by dots, each label 1 to 63 characters long and neither starting nor ending with a hyphen, punycode for internationalized names, no trailing dot, no port, at most 253 characters in all. A 253-character name therefore has at least four labels.
- `time`: `YYYY-MM-DDTHH:MM:SSZ`, a valid calendar date, seconds 00 to 59.
- `_b64` inputs: `bytes_b64`, `request_b64` and `record_body_b64` carry raw bytes and are never signed. Each is standard base64 (RFC 4648 section 4) with padding, and canonical: decoding and then encoding gives the input string. A violation is `malformed_input`.

### 2.3 Constants

| Name | Value | Bounds |
|---|---|---|
| MAX_PAYLOAD | 16384 bytes | every signed or hashed value: payload, header, genesis document, `outputs_hash` object (ACT-04) |
| MAX_DEPTH | 8 | nesting of every signed or hashed value (ACT-04) |
| MAX_INPUT | 16777216 bytes (2^24) | the bytes any signer, checker or pin helper reads from its input channel (CF-03, SG-01, GP-21) |
| MAX_EXPIRES_IN_S | 2592000 (30 days) | the signer's bound on `expires_in_s` (SG-04) |
| Pin file size | at most 512 bytes | GP-05 |
| `persons` | 2 to 15, and smaller than the role holders of its rule | GP-02 |
| `clock_skew_s` | 0 to 3600 | GP-02 |
| `max_validity_s`, `max_view_age_s` | 60 to 2592000 | GP-02 |
| `max_tip_age_s` | 60 to 86400 | WT-01 |
| `record.promote` anchors | 1 to 16 | ACT-09 |
| `chain.resolve` caps | `candidates` 2 to 17; `heads` 1 to 16; `overrides` 0 to 16 entries of 1 to 15 endorsements | ACT-09 |
| Render line 1 | at most 80 bytes | RN-03 |
| Render line | at most 100 bytes; longer lines wrap into segments of at most 98 bytes | RN-02 |
| Render length | at most 72 lines | RN-02 |
| Request and record block | at most 2048 source bytes and 32 block lines; at most 96 escaped bytes per line | RN-05, RN-12 |

No JSON number appears anywhere in any signed or hashed value of this profile. Counts, durations and thresholds are decimal strings.

## 3. Act profile

### ACT-01 Envelope fill and constants

Every act MUST be a vitni receipt with these exact constants: `v="vitni/0.2"`, `binding="local"`, `status="OK"`, `reason=null`, `action_ref=null`, `requester_id=null`, `cost={"rail_ref":null,"tokens":"0","usd_micros":"0","wall_ms":"0"}`, `log_policy="best_effort"`. The payload key set MUST be exactly: `action_ref binding cost ext inputs_hash log_policy method nonce outputs_hash parent_performer_id parent_receipt_hash performer_id reason requester_id status ts v`. No other key is allowed. `parent_performer_id` is always present, as null or a string.

Any deviation is `schema`.

Why: vitni `verify` reads only `performer_id`, `binding`, `method`, `kid` and `alg`, so the profile owns every other envelope field.

- S1: GIVEN a valid approve act WHEN `status` is `"FAILED"` THEN `check-act` returns `schema`. V: sch/status-not-ok, sch/binding-mcp
- S2: GIVEN all constants correct WHEN checked THEN no `schema` is raised on them. V: ok/approve

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

- S1: GIVEN the draft input for each method WHEN emitted by two implementations THEN the bytes are equal. V: jcs/emit-sorted, jcs/emit-slash-raw

### ACT-06 Extension object

`ext` MUST have exactly one key, `dev.handsal/act`, whose value (the act object) is a closed object. Common act-object keys for every method: `body`, `kid` (ACT-14), `org`. `head` is present exactly where the ACT-09 `head` column says so and MUST be absent everywhere else. Further keys per method are listed in ACT-09. Unknown keys anywhere are `schema`. Absent keys are errors: no key is optional except `head` as ACT-09 defines it.

- S1: GIVEN `ext` with a second key `x.other` WHEN checked THEN `schema`. V: sch/ext-extra-key, sch/ext-missing
- S2: GIVEN a `device.add` act object carrying `head` WHEN folded THEN it is not on the chain (closed schema). V: sch/chain-primary-with-head

### ACT-07 Field formats

These fields MUST be canonical hashstr: `inputs_hash`, `outputs_hash`, `nonce`, `parent_receipt_hash` when non-null, `org`, `head.id`, `link_code_hash`, the endorsement `body.act`, and in a `chain.resolve` body `choose`, every `candidates[]` and `heads[]` entry, every `overrides[].resolve` and every `overrides[].endorsements[]` entry. `nonce` MUST be the hashstr of 32 bytes from a cryptographically secure random source. `ts` and `expires` MUST be `time`. `performer_id` and every person id MUST be `member_id`. Decimal-string fields MUST match the decimal-string grammar. Any violation is `schema`.

ACT-07 owns the form of every hashstr field, so a non-canonical hashstr anywhere, a `chain.resolve` body included, is `schema`. ACT-09 owns structure only (closed objects, array lengths, sort order, distinctness), which is `body_schema`. One defect yields one code.

- S1: GIVEN `inputs_hash` with nonzero trailing bits WHEN checked THEN `schema`. V: sch/hashstr-trailing-bits, sch/hashstr-wrong-code
- S2: GIVEN a resolve in which `overrides[0].endorsements[0]`, `overrides[0].resolve`, `candidates[0]`, `heads[0]` or `choose` has nonzero trailing bits, and which would otherwise lift a fork, WHEN folded THEN the resolve is ignored (it fails ACT-07, ACT-09) and the output is the fork at its parent. `check-act` never reads a resolve (VR-02 step 4), so this case is observable through `fold` only. V: rsv/override-entry-non-canonical-hashstr, rsv/override-resolve-non-canonical-hashstr, rsv/candidate-non-canonical-hashstr, rsv/head-non-canonical-hashstr, rsv/choose-non-canonical-hashstr

### ACT-08 Head

`head` MUST be exactly `{"id":hashstr,"kind":"chain"}`. `id` is the position id of the chain position the signer saw: the receipt id of that position's primary, or the current genesis document hash at position 0. There is no `n`: the position number is derivable from `id` and the chain, so signing it would create a second source for one value. The fold output `tip` carries `n` as a derived value. `kind` is closed for this profile: any other value, or any extra member such as `n`, is `schema`. A future signed log head would be a new kind under a new profile hash. Relay freshness is not a head kind (WT-09): a relay tip statement is verifier input, so act bodies are identical in every witness mode.

`head` appears in verdicts, `record.promote`, `act.endorse`, and `genesis.sign` over a genesis change, where `head.id` equals the change document's `head` (GP-19). Chain primaries and `chain.resolve` never carry it: their `parent_receipt_hash` is the head, and the closed schema forbids the duplicate. `genesis.sign` over an original document carries none.

The caller of a signer supplies `head`; the signer does not fold. The checker validates it (VR-12, FO-08, GP-19).

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
| `local:handsal.record.promote` | `expires` | always | `{anchors, record_id}` | hashstr(raw record body bytes) | EMPTY_HASH |

Field types: `x` and `y` are base64url of 32 bytes (43 characters, canonical); `class` is a registry id (KC-01); `kid` is a 43-character thumbprint; `person`, `member` and `recipient` are `member_id`; `role` is one `role_id` listed in the epoch policy `roles` (each member holds one role); `relay` is a `hostname`; `request_id` is `request_id`; `record_id` is `record_id`; `anchors` is a list of 1 to 16 `anchor` values; `label` is `label`.

`chain.resolve` body, all keys required:
- `candidates`: 2 to 17 distinct hashstr, sorted ascending; `choose` is one of them;
- `heads`: 1 to 16 distinct hashstr, sorted ascending;
- `overrides`: 0 to 16 entries, sorted ascending by `resolve` (byte order), `resolve` values distinct. Each entry is exactly the closed object `{"endorsements":[...],"resolve":R}`, with `endorsements` 1 to 15 distinct hashstr sorted ascending.

The relations of these ids to the act tree are FO-25, not schema.

There is no `request.send` method and no sequence number. `inputs_hash` and `outputs_hash` are derived from the method and its inputs; checker and signer recompute them and never trust a supplied value. For a verdict and for `record.promote`, `inputs_hash` is checked by VR-06 and `outputs_hash` by VR-07. For a chain act and for `genesis.sign`, a hash that is not its fixed value in the table (EMPTY_HASH, or the document hash for the `inputs_hash` of `genesis.sign`) makes the act invalid for its method: the fold ignores a chain act (FO-06), and a `genesis.sign` does not count (GP-15), so its device is `genesis_unsigned` unless another signature of that device counts. No reason code is output for the hash itself: `check-act` never decides these methods (`chain_method`, VR-02 step 4), and the fold outputs no code for an ignored act.

A shape violation of a body is `body_schema`; in the fold the act is ignored.

`local:handsal.relay.tip` is the relay tip statement method (WT-02). It is not in this registry, so as an act it is `method_unknown`, and the fold ignores it.

- S1: GIVEN `local:handsal.request.send` WHEN checked THEN `method_unknown`. V: mth/request-send, mth/case-variant
- S2: GIVEN an approve whose `outputs_hash` was computed for verdict `reject` WHEN checked THEN `outputs_mismatch`. V: vrd/outputs-verdict-swapped
- S3: GIVEN a `device.add` body missing `link_code_hash` WHEN folded THEN the act is not on the chain. V: bod/device-add-missing-link-code, bod/device-add-extra-key
- S4: GIVEN a `member.add` whose `role` is not listed in policy `roles` WHEN folded THEN it is not on the chain. V: bod/member-add-role-unlisted, bod/resolve-extra-key
- S5: GIVEN a resolve whose `overrides` entry is not the closed `{endorsements, resolve}` object WHEN folded THEN ignored (`body_schema`). V: rsv/override-entry-shape-schema, rsv/override-entry-bare-hashstr-schema, rsv/override-entry-sixteen-endorsements-schema
- S6: GIVEN a relay tip statement passed as an act WHEN checked THEN `method_unknown`. V: wit/statement-as-act

### ACT-10 Signed strings are ASCII

No signed string may contain a byte outside the alphabets of section 2. Request text and record bodies are only hashed, never embedded.

A byte outside 0x20 to 0x7E, a `"` or a `\` never reaches an alphabet check: the recognizer refuses the payload first (`payload_not_canonical_subset`, ACT-04), and a genesis document holding one is `genesis_schema` (GP-01). A string of allowed bytes that is outside the alphabet of its field is `schema` when the field is an ACT-07 form or a key of the act object (`kid`, `recipient`, `relay`, `request_id`, `expires`, `head`), and `body_schema` when it is a field of `body` (VR-02 step 5). `relay` is no ACT-07 form: it takes the code of its container, the act object. The label alphabet of a `device.add` or `member.add` body is seen only as state: `check-act` stops at `chain_method` (step 4) and the fold ignores the act without giving a reason, so no reason code of that case is a vector (CF-07).

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
| `record.promote` | null | null | the person of the signing device (enforced through the vitni keys map, VR-03) |
| `genesis.sign` | null | null | the person of the signing device: from the document for possession, from `S_H` for authority (below) |
| `device.add`, `device.remove`, `member.add` | the parent position id, never null (FO-04) | the parent's performer, null iff the parent is the root | the primary signer's person |
| `chain.resolve` | the fork parent P | the performer at P, null iff P is the root | the signer's person |
| `act.endorse`, counted | receipt id of the endorsed act | that act's `performer_id` | the endorser's person |
| `act.endorse`, proof of possession | same | same | the new device's person (`body.person`; for `member.add`, `body.member`) |

A parent field that differs from the table is `schema` at `check-act` step 5 (VR-02). A `performer_id` that is a `member_id` but not the person the table names is not `schema`: for verdicts it is `identity_mismatch` at step 11 (VR-05), and for `record.promote` it is `unknown_key` at step 9 (VR-03). In the fold the act is ignored or the signature does not count.

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

The profile owns a closed registry, `spec/registry.json`, covered by the profile hash (CF-01). Each class has `id`, `alg` (only `ES256` in version 1), `hardware_bound`, `per_signature_user_verification`, `user_verification` (`biometric_only`, `biometric_or_pin` or `none`) and `status` (`active`, `pending-spike` or `test-only`). Adding a class is a new registry entry and a new profile hash, never a schema change. An id not in the registry is `class_unknown`.

| id | alg | hardware_bound | per_signature_user_verification | user_verification | status |
|---|---|---|---|---|---|
| `apple-se-bio` | ES256 | true | true | `biometric_only` | `active` |
| `win-hello-hw` | ES256 | true | true | set by the Windows Hello evaluation (KC-02) | `pending-spike` until that evaluation reports |
| `test-sw-p256` | ES256 | false | false | `none` | `test-only` (KC-07) |

The registry also carries a `fixture_only` list, recognized only under the fixture profile (GP-18). Under a production profile its ids are `class_unknown`. Version 1 lists one entry: `fixture-pin` (ES256, `hardware_bound` false, `per_signature_user_verification` true, `user_verification` `biometric_or_pin`, `status` `active`). It exists so KC-08 vectors never depend on a platform evaluation.

- S1: GIVEN a `device.add` with class `yubikey-piv` WHEN folded THEN it is not on the chain. V: cls/unknown-class-device-add, cls/unknown-class-genesis

### KC-02 Classes pending evaluation

A class with status `pending-spike` MUST NOT appear in any genesis policy `classes` (`class_pending`). A tagged registry never contains `pending-spike`. Before the first tag the Windows Hello evaluation decides `win-hello-hw`, with exactly one of three outcomes (KC-08): the class is removed from the registry; it becomes `active` with `user_verification` `biometric_only`; or it becomes `active` with `user_verification` `biometric_or_pin`.

- S1: GIVEN a pre-tag registry and a genesis accepting `win-hello-hw` WHEN folded THEN `class_pending`. V: cls/pending-class-accepted, cls/tagged-registry-no-pending

### KC-03 user_verification is data

A class's `user_verification` MUST be a property of its registry entry, never inferred from the platform. A genesis policy accepts a class only by listing the pair `{class, user_verification}`, with `user_verification` equal to the registry value at the document's `profile`. A mismatch is `class_policy_mismatch`.

Why: the people signing a genesis decide on an exact property set, so a registry change that alters a class's verification makes an old policy entry fail closed instead of silently weakening it.

With a `biometric_or_pin` class, a same-user process that captures or injects the PIN signs with no person present. KC-08 keeps such classes off role holders; section 14 states what remains.

- S1: GIVEN policy entry `{class:"apple-se-bio", user_verification:"biometric_or_pin"}` WHEN folded THEN `class_policy_mismatch`. V: cls/uv-mismatch, cls/biometric-or-pin-listed-ok

### KC-04 Accepted and unproven keys

A key is **accepted** iff its class is listed in the epoch policy `classes` (KC-03) and GP-18 does not exclude it. A key that is not accepted:
- is absent from the fold `keys` map (FO-02) and present in `devices` with `accepted:false`;
- counts toward no authority: no quorum signature, no endorsement, no consent, no resolve, no genesis change;
- yields `check-act` `{valid:false, reason:"unproven_class"}` when its signature verifies (VR-02 step 16), never human proof.

`valid:true` from `check-act` is the only human-proof signal, and it is never returned for a key that is not accepted, so a consumer that tests `valid` cannot treat an unproven key as a person by accident. The decision is data in the genesis document; no code names a class.

- S1: GIVEN a verdict signed by a key whose class is not in the policy WHEN checked THEN `valid:false`, `unproven_class`. V: cls/verdict-unproven, cls/biometric-or-pin-not-listed-unproven
- S2: GIVEN the same acts and a policy that lists the class WHEN checked THEN `valid:true`, with no code change. V: cls/policy-swap-human
- S3: GIVEN an endorsement by a key that is not accepted WHEN folded THEN it does not count. V: cls/unproven-endorsement-ignored, cls/unproven-self-remove-ignored

### KC-05 Single algorithm

Only ES256 keys on P-256 exist. Device entries have no `alg` member. A device entry carrying one, or a key that is not a P-256 point, is invalid.

- S1: GIVEN a genesis device entry with an `alg` member WHEN folded THEN `genesis_schema`. V: cls/ed25519-device

### KC-07 Test class and fixture keys

`test-sw-p256` exists only for signer plumbing tests (a separate software test binary) and for exercising `unproven_class` in consumers. A policy listing it is `class_test_only`; its keys are never accepted. No mode, flag or policy changes that.

Fixture keys (`conformance/fixtures/keys.json`, listed in `conformance/fixtures/fixture-kids.json`, the relay fixture key included) are governed by GP-18: never accepted under a production profile, and treated as their labelled class under the fixture profile. The enrollment ceremony also refuses any listed kid (SG-12).

- S1: GIVEN a policy listing `test-sw-p256` WHEN folded THEN `class_test_only`. V: cls/test-class-listed, cls/test-class-key-unproven
- S2: GIVEN a fixture device kid under a production profile WHEN `enrolled` runs THEN false, `fixture_key` from the fold. V: enr/fixture-kid
- S3: GIVEN a production policy whose `relay_kid` is the fixture relay key WHEN folded THEN `fixture_key`; WHEN the ceremony runs THEN it refuses before any write (an SG-12 ceremony implementation test, CF-07). V: fix/prodk-relay-fixture-kid

### KC-08 Role-holder key class

Every device of a role holder MUST have a class whose registry `user_verification` (KC-01, at the document's profile) is `biometric_only`. The value is read from the registry whether or not the policy accepts the class; for an accepted class it equals the policy entry (KC-03). Devices of other members have no restriction beyond KC-04.

The predicate is evaluated where a device enters state, and nowhere else:
- (a) each genesis document, original or change, over all its devices including carried ones: a violating device is `role_key_class` (GP-15 step 3);
- (b) `device.add` and `member.add` (FO-22): a new key whose class violates the predicate for the person's role is not on the chain.

Roles are fixed at `member.add` (there is no role-change act), and every change document re-evaluates the predicate, so a later role listing cannot leave a PIN-capable key on a role holder.

Consequence: every key whose touch can count toward Q, or give consent for a role holder, has a biometric-only declared class. A key of a PIN-capable class is allowed only for members who are not role holders; it never counts toward a quorum (FO-23 requires a listed role) and is never a role holder's consent.

Windows: until the Windows Hello evaluation reports, `win-hello-hw` stays `pending-spike` (KC-02) and cannot be listed. If the evaluation finds no hardware key, no prompt, or no use from WSL2, the class is removed from the registry. Otherwise it becomes `active` with exactly one `user_verification`: `biometric_only` if Windows Hello can be required to be biometric-only per key (fingerprint reader or infrared face camera, PIN excluded), else `biometric_or_pin`. In the second case a genesis listing it for a role holder is `role_key_class`, so a Windows user cannot be a role holder through that class. Nothing is accepted silently.

KC-08 vectors use the fixture-only class `fixture-pin` under the fixture profile.

- S1: GIVEN a PINORG genesis whose maintainer alice also holds a `fixture-pin` device WHEN folded THEN `role_key_class`; GIVEN only dave (role `member`) holds one THEN the state. V: cls/role-holder-pin-genesis-refused, cls/nonrole-pin-device-ok
- S2: GIVEN alice and bob add a `fixture-pin` device for alice, or a `member.add` of maintainer frank with one, WHEN folded THEN it is not on the chain; with `apple-se-bio` THEN applied; GIVEN a policy that does not accept `fixture-pin` THEN still not on the chain (registry value). V: cls/role-holder-pin-device-add-not-on-chain, cls/role-holder-pin-member-add-not-on-chain, cls/role-holder-biometric-member-add-ok, cls/role-holder-unaccepted-pin-class-not-on-chain
- S3: GIVEN dave's `fixture-pin` key endorses an act of alice WHEN folded THEN it is not counted. V: cls/pin-key-never-counts

## 5. Genesis and pin

### GP-01 Genesis document

A genesis document is a canonical-subset object (ACT-04) with exactly these keys: `devices`, `members`, `name` (`org_name`), `org` (null in the original, else the original org id), `policy` (GP-02), `prev` (null in the original, else hashstr(JCS(previous document))), `profile` (a profile hash, CF-01), `v` = `"handsal-genesis/1"`, and `head`. `head` is the canonical hashstr of the node H a change is made at (GP-19); it is required iff `prev` is non-null and forbidden otherwise. The presence of `policy` belongs to GP-02: a document without `policy` is `policy_invalid` (GP-15 step 3), and any other missing or extra key is `genesis_schema`.
- `devices`: a list sorted by `kid`, entries `{agree:{x,y}, class, kid, label, person, sign:{x,y}}`.
- `members`: a list sorted by `id`, entries `{id, role}`, with `role` a `role_id` listed in `policy.roles` (GP-02).

Sorted means ascending in byte order, equal neighbours allowed, so a repeated entry is never `doc_not_sorted` and its own rule decides. Unsorted lists are `doc_not_sorted`: one document has one byte form and one hash. The lists are `devices`, `members` and, in `policy`, `classes`, `roles` and the `roles` of each rule; a policy list whose entries are too malformed to order is `policy_invalid` (GP-02). Every device's `person` is a listed member, every member has at least one device, `kid` equals the thumbprint of `sign`, `agree` differs from `sign`, and no kid or agree key repeats. The org id is hashstr(JCS(original document)). It is stored in every later document's `org`, and in no document's own bytes before it exists.

Structure violations, `head` included and a repeated member `id` too, are `genesis_schema`: so are a document that is not an object, a value outside the canonical subset (ACT-04), and a `profile` that is not a canonical hashstr. `profile_mismatch` is only for a well-formed profile hash the implementation does not implement (GP-15 step 2). Key problems are `genesis_key_invalid` or `duplicate_key`.

- S1: GIVEN members listed out of order WHEN folded THEN `doc_not_sorted`. V: gen/unsorted-members, gen/unsorted-devices
- S2: GIVEN a change without `head`, or an original with `head`, WHEN folded THEN `genesis_schema`. V: chg/document-head-missing-schema, chg/original-with-head-schema

### GP-02 Policy

`policy` MUST be exactly:
- `classes`: a non-empty list of `{class, user_verification}`, sorted by `class`, unique (KC-02, KC-03, KC-07).
- `freshness`: `{clock_skew_s, max_validity_s, max_view_age_s}`, decimal strings, with `0 <= clock_skew_s <= 3600`, `60 <= max_validity_s <= 2592000` and `60 <= max_view_age_s <= 2592000`.
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
- S3: GIVEN `rules["device.remove"].persons` `"1"` WHEN folded THEN `policy_out_of_bounds`; GIVEN `"16"` THEN `policy_out_of_bounds`. V: pol/persons-one-refused, pol/persons-16-out-of-bounds
- S4: GIVEN three maintainers and `persons "2"` THEN the state; GIVEN `persons "3"` THEN `policy_unreachable`; GIVEN two maintainers and `persons "2"` THEN `policy_unreachable`; GIVEN a change dropping one of three maintainers with `persons "2"` THEN `policy_unreachable`. V: pol/org3-2-of-3-ok, pol/persons-equals-role-holders-refused, pol/two-person-org-refused, pol/change-removing-spare-refused, pol/single-person-org-unreachable
- S5: GIVEN a document without `policy` WHEN folded THEN `policy_invalid`, not `genesis_schema`. V: pol/missing-policy

### GP-03 Original genesis and proof of possession

An original document has `org=null`, `prev=null`, no `head`, at least one member, at least one device per member, and every device of a class its own policy accepts.

Proof of possession: every device listed in a genesis document MUST have at least one counting `local:handsal.genesis.sign` act over that document, signed under its own key (GP-15). Several counting signatures by one kid are one. For an original, that act has `inputs_hash` = hashstr(JCS(document)), `org` = that same hash, and no `head` (ACT-08). For a change, `org` is the original org id and `head` names the document's H (GP-19). A listed device without a counting signature is `genesis_unsigned`. Signatures that do not count (junk, unlisted keys, another document, duplicates) are ignored.

Why: every key in the state has signed at least once under its class's prompt.

- S1: GIVEN three maintainers and only two counting `genesis.sign` receipts WHEN folded THEN `genesis_unsigned`. V: gen/ok-3-maintainers, gen/missing-maintainer-sig
- S2: GIVEN a signature by an unlisted key next to every listed device's signature WHEN folded THEN the state; GIVEN a device whose only signature covers another document THEN `genesis_unsigned`. V: gen/sig-by-unlisted-key, gen/sig-over-other-doc

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

- S1: GIVEN a pin file ending in CRLF WHEN parsed THEN `pin_malformed`. V: pin/ok, pin/missing
- S2: GIVEN a file name whose hex differs from the org digest WHEN checked THEN `pin_org_mismatch`. V: pin/filename-mismatch, pin/org-not-original
- S3: GIVEN a probe for another org, or a pin whose `spec` is not the last document's `profile` WHEN checked THEN `pin_org_mismatch`, `pin_spec_mismatch`. V: org/probe-other-org, pin/spec-not-last-profile
- S4: GIVEN a pin file with the `org` member twice, with the same value or with two values WHEN parsed THEN `pin_malformed`. V: pin/duplicate-key, pin/duplicate-key-differing-values

### GP-07 Lineage input

`fold`, `check-act`, `enrolled` and `genesis-check` take `lineage`: the ordered list `[{doc, sigs}]` from the original document to the pinned one, where `sigs` are that document's `genesis.sign` receipts. They also take one `acts` bag holding the chain acts of every epoch; each epoch's chain roots at its own document hash, so acts sort themselves into epochs. Every item of `acts` and of every `sigs` is a string: a string that is no valid act is ignored by the fold (FO-06), and an item of any other type is `malformed_input`.

The fold MUST validate every link: GP-03 for the original, and for each change GP-19 against the path to its H in the epoch before it, never the full fold of that epoch, so a fork there never fails a later epoch. Every command that reads a pin (`fold`, `check-act`, `enrolled`) makes three comparisons, in this order, at VR-02 step 6 (g). An empty lineage is `lineage_broken`. The pin's `org` MUST equal the hash of the first lineage document, which is the org id (GP-04), else `lineage_broken`. The pin's `genesis` MUST equal the hash of the last lineage document, else `genesis_pin_mismatch`. A document outside the canonical subset has no hash and never equals either: as the first document it is `lineage_broken`, as the last it is `genesis_pin_mismatch`. `genesis-check` and the pin helper read no pin and take the org id from the first document (CF-03, GP-21), so they cannot disagree with it. A lineage is also `lineage_broken` when its first document has a non-null `prev`, or when a later document's `prev` is not the hash of the document before it, or its `org` is not the hash of the first document (GP-15 step 4).

Every lineage document's `profile` MUST be implemented (`profile_mismatch`). Each epoch is evaluated under its own document's profile, and a change's authority under the previous document's profile. A lineage that mixes a production and a fixture profile is `fixture_profile` (GP-18). Version 1 implements one production profile. `fold`, `check-act` and `enrolled` take the required input `org` (GP-14).

- S1: GIVEN a lineage whose last document does not hash to the pin WHEN folded THEN `genesis_pin_mismatch`. V: chg/lineage-last-not-pinned, chg/lineage-missing-doc
- S2: GIVEN a fixture-profile original and a production-profile change WHEN folded THEN `fixture_profile`. V: fix/mixed-profile-lineage
- S3: GIVEN a pin and an input `org` that agree, and a lineage whose first document hashes to another org WHEN folded THEN `lineage_broken`. V: pin/lineage-original-not-org

### GP-09 Epoch scope

The fold result is the state of the pinned (last) epoch. Earlier epochs are read only along the path to each change's H, to validate that change (GP-19). A non-chain act whose `head.id` is not a position of the current epoch's chain is `stale_view` (VR-12); this covers heads from other epochs.

- S1: GIVEN an approve with a head from epoch 0 and a verifier on epoch 1 WHEN checked THEN `stale_view`. V: chg/old-epoch-head-stale

### GP-10 Pin location

The pin MUST live where only an administrator principal can write it and the agent's user can only read it.
- macOS: `/Library/Application Support/handsal/orgs/<hex64>.pin`. The directories `handsal` and `orgs` are `root:wheel 0755`. Check (in-process, standard library only): open with `O_NOFOLLOW`; `fstat` the descriptor: a regular file, `st_uid == 0`, `mode & 0o022 == 0`, `st_nlink == 1`; `lstat` every ancestor up to `/`: not a symlink, `st_uid == 0`, `mode & 0o022 == 0`.
- Windows: `C:\ProgramData\handsal\orgs\<hex64>.pin`. The directories carry a protected DACL: owner Administrators (S-1-5-32-544); SYSTEM and Administrators full control; Users (S-1-5-32-545) read and execute only. Ownership is checked only on the Windows side, by `handsal-sign.exe pin-read` (GP-11) or the Windows-side checker (GP-17). A WSL2 checker MUST NOT decide ownership from drvfs mode bits, from a copy inside the WSL filesystem, or through the `\\wsl$` share.

Any failed check is `pin_owner`; an absent file is `pin_missing`.

Scope: the pin defends against an agent writing files as the person's user principal. It does not defend against an agent that changes verifier code or its runtime (section 14, L13). Within that scope, it turns "rewrite one data file" into "modify code or remount a file system".

- S1: GIVEN a pin file writable by group WHEN probed THEN `owner_ok:false`, `pin_owner`, and `enrolled` is false. V: enr/pin-owner
- S2: GIVEN a pin whose ancestor directory is a symlink WHEN probed THEN `owner_ok:false`, `pin_owner`. A vector cannot build a symlinked ancestor of the fixed pin path, so the ancestor symlink case is a probe test (CF-07).

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

- S1: GIVEN an agent process without elevation WHEN it writes the pin location THEN the OS denies it (platform test, outside the vector set).
- S2: GIVEN the macOS ceremony WHEN it writes the pin THEN it uses one `/usr/bin/sudo -k` invocation of the helper and leaves no cached credential (a ceremony implementation test, CF-07).

### GP-13 enrolled predicate

`enrolled` is pure. Input (conformance build) `{acts, device_kid, lineage, now, org, pin, synced_at, tip_statement}`, with `pin` the probe object of GP-14. The production build reads the pin and `now` in-process and takes neither key (CF-08). Output `{enrolled, reason}`. It is true iff all of these hold, in order, first failure wins:
1. to 3. the pin checks of VR-02 step 6, (a) to (h), in that order and with those codes;
4. the fold succeeds (else its error code, `fork` included);
5. `device_kid` is a device in the state (`local_key_unknown`), active (`local_key_not_active`) and accepted (`local_class_not_accepted`);
6. the view is fresh: VR-12, then the witness rules of the policy's mode (WT-04, WT-05, WT-10);
7. the pin's `spec` is not a fixture profile (`fixture_profile`, GP-18).

Under the production profile a fixture kid never enters `devices` (GP-18), so step 5 reports it as `local_key_unknown`, or the fold fails at step 4 when the genesis lists one.

Meaning: `enrolled:true` says "this machine holds a valid administrator-written pin for `org`, its evidence folds, and `device_kid` names an active accepted device of that org, freshly viewed". It does NOT prove that the key is on this machine or that a person is present: `device_kid` is caller-supplied, and a prompt per `enrolled` call would train blind touching (SG-10). Presence is proven per act, by `check-act`. Consumers MUST NOT treat `enrolled:true` as human proof.

- S1: GIVEN a valid pin and an active accepted local key but a stale view WHEN evaluated THEN `enrolled:false`, `stale_view`. V: enr/stale-view, enr/view-in-future
- S2: GIVEN a probe reporting `pin_missing`, a removed local key, or a frozen bag WHEN evaluated THEN false with `pin_missing`, `local_key_not_active`, `fork`. V: enr/pin-missing, enr/local-key-revoked, enr/fork
- S3: GIVEN a fixture kid under ORG_PRODK WHEN evaluated THEN false, `local_key_unknown`. V: enr/prodk-fixture-kid-unknown
- S4: GIVEN everything valid under the fixture profile WHEN evaluated THEN false, `fixture_profile` (steps 1 to 6 passed). V: enr/ok, fix/fix-profile-enrolled
- S5: GIVEN a probe of another org, or bob's kid on alice's machine WHEN evaluated THEN false, `pin_org_mismatch`; false, `fixture_profile` (enrolled does not prove presence). V: org/enrolled-org-mismatch, enr/device-kid-not-presence
- S6: GIVEN a relay witness policy and no statement WHEN evaluated THEN false, `witness_missing`. V: wit/enr-relay-missing, wit/enr-relay-stale

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

- S1: GIVEN ORG under the production profile WHEN folded THEN `fixture_key`. V: fix/prod-genesis-fixture-kid, fix/prod-check-act-fixture-pin-refused, fix/prodk-relay-fixture-kid
- S2: GIVEN ORG_PRODK and a `device.add` of a fixture kid WHEN folded THEN not on the chain; an approve by that kid WHEN checked THEN `unknown_key`. V: fix/prodk-fixture-kid-add-not-on-chain, fix/prodk-check-act-fixture-kid-unknown
- S3: GIVEN APPROVE under the fixture profile WHEN checked by the conformance build THEN valid. V: fix/fix-profile-check-act-ok

### GP-19 Genesis change

A change is a new document with `prev` = hashstr(JCS(previous document)), `org` = the original org id, a full snapshot of the new epoch, and `head` = H (GP-01). Proof of possession: GP-03 and GP-15.

Head: H MUST be a node of the previous epoch's act tree (FO-26): its root or a valid chain primary, never a resolve, an endorsement or an invalid act; else `genesis_head_unknown`. Every `genesis.sign` over a change carries `head = {id: H, kind: "chain"}` with `id` equal to the document's `head`. A signature naming another head is not a signature over this change and is ignored for possession and authority alike. One document has one H.

Path: the previous epoch is read along the path from its root to H, each primary validated against its prefix state; FO-24 is not applied on the path, because by naming H the change's quorum selects the branch. H may lie on any branch, a losing or unresolved one included: authority and carried devices then come from that branch's state.

Authority: a signature counts iff it passes the authority test of ACT-13 (its key is a device of `S_H`, listed in the document or not), its key satisfies clean(k, H) (FO-26: active and accepted in `S_H`), and its person holds a role in the previous policy's `rules["genesis.change"].roles`. Counted persons MUST meet the previous policy's `persons` for that rule, else `genesis_change_unauthorized`. Several counting signatures by one kid are one. A carried device's possession signature naming H is also an authority signature when it meets these conditions, so a change carrying the devices of Q previous role holders is authorized by their possession signatures alone.

Why unlisted keys count: authority is a property of the previous epoch at H, not of the new document. Any role holder's key that is clean at H could also be listed and sign, so counting it unlisted grants nothing new. Requiring listing would make a full key rotation (a document listing only new keys) impossible. The difference render shows every dropped key under `Devices removed` (RN-10).

Close: the previous epoch's state ends at H. No act outside the path to H is ever read for this change. Later acts of the old epoch, forks and resolves cannot invalidate it, so a pinned change never becomes invalid. A change takes effect on a machine only after a person re-pins it (GP-12).

A key removed after H, outside the path to H, still counts at H (section 14, L4).

- S1: GIVEN alice removed by bob and carol at position 2 and a change with H = 4 listing bob plus new maintainers frank and grace, signed by every listed device and by alice's removed key WHEN folded THEN `genesis_change_unauthorized` (only bob counts). V: chg/signer-revoked-before-head, wit/change-none-to-relay-revoked-signer, cli/genesis-check-change-revoked-signer
- S2: GIVEN alice removed at position 3 and a change with H = 2 signed by alice and bob WHEN folded THEN the new epoch. V: chg/signer-revoked-after-head, chg/backdate-through-fork-residual
- S3: GIVEN H on a branch whose path does not contain alice's removal WHEN folded THEN the new epoch. V: chg/head-on-side-branch-clean-rule, chg/signer-revoked-on-branch
- S4: GIVEN a listed device whose only `genesis.sign` names another head WHEN folded THEN `genesis_unsigned`; GIVEN an unlisted previous role holder whose only signature names another head THEN it does not count (`genesis_change_unauthorized` under CHG-NEW). V: chg/possession-sig-other-head-ignored, chg/heads-differ
- S5: GIVEN a change listing alice plus new maintainers and signed also by carol, clean at H and not listed WHEN folded THEN the new epoch (alice and carol count). V: chg/unlisted-clean-signer-counts, chg/unlisted-signer-wrong-performer-ignored
- S6: GIVEN a document listing only new keys for alice, bob and carol, signed for authority by alice's and bob's old keys WHEN folded THEN the new epoch. V: chg/full-key-rotation-ok
- S7: GIVEN 2 of 3 maintainers sign a change at the previous tip WHEN folded with the new pin THEN the new epoch is the state; GIVEN only one counts THEN `genesis_change_unauthorized`. V: chg/ok-2-of-3, chg/quorum-unmet-1-of-3
- S8: GIVEN a change whose document `head` is no node of the previous act tree WHEN folded THEN `genesis_head_unknown`. V: chg/head-unknown

### GP-20 Carried devices across a change

- Every device listed in any document is of a class accepted by that document's policy, else `genesis_schema`, checked at GP-15 step 3 after the policy checks.
- A device whose kid occurs in an earlier lineage epoch (in its document, or in the state at the H that closed it) is **carried**. It MUST be active in `S_H` of the previous epoch, and it MUST NOT be `removed` in the state at the closing H of any earlier epoch, else `genesis_device_revoked`. Acceptance is decided by the new document's policy only, so a device whose class the old policy did not accept may be carried once the new policy accepts it.
- A carried entry MUST be byte-identical to its entry in `S_H` (`person`, `class`, `label`, `sign`, `agree`), else `genesis_device_changed`. Changing a label or class means removing the key and adding a new one.

Why: a re-pin never revives a key removed on the path to H or in an earlier epoch, and never changes a vouched device value outside the rendered difference.

- S1: GIVEN bob2 removed by bob and carol before H and a change carrying bob2 WHEN folded THEN `genesis_device_revoked`; GIVEN the removal after H THEN bob2 is carried. V: chg/carry-removed-kid-returns, chg/carry-revoked-after-head, chg/carry-entry-changed
- S2: GIVEN a listed device of a class the document's policy does not accept WHEN folded THEN `genesis_schema`. V: chg/device-unaccepted-class

### GP-21 Pin monotonicity and the pin helper

The pin helper is one binary per platform at an exact administrator path (SG-14): `/Library/Application Support/handsal/bin/handsal-pin` on macOS, run as `/usr/bin/sudo -k "/Library/Application Support/handsal/bin/handsal-pin"`, and `C:\Program Files\handsal\handsal-pin.exe` on Windows, started elevated (UAC). Both implement this rule identically: the same input bytes, checks, output line and exit codes. Only the channel differs.

Input. The helper takes no argument; any argument is `malformed_input` and nothing is written. The input is exactly one line: one JSON object with exactly the keys `acts` and `lineage` (the `genesis-check` input, CF-03), followed by one LF. Its grammar is the canonical subset recognizer (ACT-04) with MAX_INPUT in place of MAX_PAYLOAD. Any recognizer failure (a duplicate key, more than MAX_INPUT bytes, a missing LF, bytes after the LF) is `unparseable_input`. A missing, extra or mistyped key is `malformed_input`.

Steps, first failure wins. No pin is written on any failure; directories created at step 0 stay.
0. Check or create the directories (below), then take the lock (below), held through the write.
1. Run the production checker at its SG-14 path with `genesis-check` on `{acts, lineage}`. Unless it returns `valid:true`, `pin_invalid`. The returned `pin` (one JCS line plus LF, GP-05) is the only content the helper writes.
2. Derive the path from that `pin`'s `org` only (`<hex64>.pin` under `orgs`, GP-05).
3. If a file exists at that path, whatever it contains, it MUST be a well-formed pin line for that same org (GP-05), else `pin_malformed`; and the new lineage MUST contain the document whose hash is that file's `genesis`, else `pin_rollback`. If no file exists there, step 3 passes.

Directories. The helper is the only creator of `handsal` and `orgs` on both platforms; neither the ceremony nor the installer creates them. When absent, the helper creates them with the GP-10 attributes: on macOS `root:wheel 0755`, set by `fchown` and `fchmod` independent of umask; on Windows owner Administrators with a protected DACL, SYSTEM and Administrators full control, Users read and execute. When present, it checks them with the reader's own checks (GP-10 `lstat` chain on macOS; GP-11 owner, protected DACL, ACE limits and the `C:\ProgramData` `FILE_DELETE_CHILD` rule on Windows) and refuses any mismatch with `pin_owner`, writing nothing. It never repairs, because a repair would be a privileged change to an object the agent may have prepared.

Write. The content is exactly the `pin` returned at step 1. A temporary file is created exclusively in `orgs` (macOS `O_CREAT|O_EXCL|O_NOFOLLOW`; Windows `CREATE_NEW` with an explicit security descriptor) and given the reader's attributes before the rename: on macOS owner `root:wheel`, mode `0644` by `fchown` and `fchmod`, one link; on Windows owner Administrators and the protected GP-10 DACL, set at creation and never inherited. It is flushed, then renamed over the path (macOS `rename` plus `fsync` of `orgs`; Windows `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH`). The path therefore holds the old pin or the new one, never a partial one, and the new one always passes GP-10 or GP-11.

Lock. After the directory check and before step 1 the helper opens `handsal/pin.lock`, created like a pin file when absent, and takes an exclusive lock held until after the rename (macOS `flock(LOCK_EX|LOCK_NB)` on a descriptor opened with `O_NOFOLLOW`; Windows a handle opened with share mode 0). A lock held by another run is `internal`, and nothing is written. Check-then-rename is therefore atomic per machine, and two concurrent runs never move the pin off one lineage.

Output. Exactly one JCS line plus LF: `{"inner_reason":I,"reason":R,"written":W}`. R is `ok` or one of `malformed_input`, `unparseable_input`, `pin_invalid`, `pin_owner`, `pin_malformed`, `pin_rollback`, `internal`. I is the `reason` that `genesis-check` returned when step 1 ran (`ok` when valid), else `null`. W is `"yes"` iff the rename completed, else `"no"`. `internal` covers every I/O failure: read, lock, create, write, flush, rename, checker launch, or checker output that is not one JCS line. A failure before the rename writes nothing, and nothing can fail after it. Exit codes: 0 `ok`; 2 `malformed_input`, `unparseable_input`; 3 `pin_invalid`, `pin_owner`, `pin_malformed`, `pin_rollback`; 5 `internal`. Exit 1 with no line means the helper never ran (sudo authentication failed, or UAC was declined). The ceremony accepts only a line whose R matches the exit code; anything else is a failed write report, and the next `enrolled`, which reads the real pin, decides what is pinned.

Channel. On macOS `sudo` passes the ceremony's standard input and output through: the helper reads the input line from stdin and writes the output line to stdout. On Windows a process started with `ShellExecuteEx` `runas` inherits no handles, so the ceremony first creates the named pipe `\\.\pipe\handsal-pin` as a byte-mode server with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL for the current user, SYSTEM and Administrators only. If that fails because the name exists, the ceremony fails before starting the helper. It then starts `handsal-pin.exe` with `ShellExecuteEx` (`runas`, no parameters, `SEE_MASK_NOCLOSEPROCESS`), writes the input line to the pipe, reads the output line from it, and takes the exit code from the process handle. The helper connects to that fixed name as a client with `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`, so the pipe server can never impersonate the elevated token, reads up to the first LF and writes its output line. No privileged write goes to a user-writable location. On both platforms a same-user agent can replace the input on the channel (section 14, L5); the channel adds no property beyond that.

Tests. Helper tests are implementation tests (CF-07), not vectors. The installed helper runs the production checker, which refuses every fixture-profile lineage (CF-08), and its effects are the contents, owner and attributes of files under a root directory, a lock and a rename, none of which a harness vector can set up (CF-04: signers run the `render` and `emit` vectors only). The tests run against a library build of the helper core, built by a test constructor that injects the conformance checker and a temporary root directory in place of the SG-14 checker path and the GP-10 root. The installed binary has no such constructor and is never the subject of a test. Platform tests run the same injected core on the target operating system with privileges, so the owner, DACL, lock and rename code paths are exercised for real. What `genesis-check` alone decides (the acts on the path to H, extra acts, a forged link) is a checker vector (CF-03).

The helper never deletes, truncates or restores a pin, and no component of this profile does. A downgrade, or recovery of a machine pinned to a lineage it must leave, needs an administrator to delete the pin by hand outside any ceremony.

Why the caller may supply `acts`: by GP-19 a link's validity reads only its documents, their signatures and the acts on the path to its H. Omitting any of them makes the link invalid (`genesis_head_unknown` or `genesis_change_unauthorized`), and adding acts changes nothing. A caller can withhold evidence, which fails closed, but cannot select it, so `valid:true` proves authority. This holds for every link because `genesis-check` validates each link of `lineage` from the original (CF-03): a lineage that contains the pinned document but has a forged link after it is `pin_invalid`.

Why no argument: a caller-supplied file name would be a second source for the org. Deriving the path from the checker's returned line leaves one source, so an agent cannot point org A's lineage at org B's pin.

Per org, the pin only moves forward along one lineage, only to a lineage whose every link is authorized, only at the path of the org it names, only with bytes and attributes the reader accepts, and one run at a time.

- S1: GIVEN a pin on epoch 1 and a ceremony submitting epoch 0 WHEN the helper runs THEN `pin_rollback`, the file unchanged; GIVEN a bag missing the acts on the path to H THEN `pin_invalid`. Tests: CF-07. V: cli/genesis-check-missing-head-acts-invalid, cli/genesis-check-extra-acts-same-result, cli/genesis-check-forged-middle-link
- S2: GIVEN any argument, a third input key, a malformed file at the derived path, or another org's pin present WHEN the helper runs THEN `malformed_input`, `malformed_input`, `pin_malformed`, and the other org's file untouched. Tests: CF-07.
- S3: GIVEN input with a duplicate key, or more than MAX_INPUT bytes THEN `unparseable_input`, exit 2; GIVEN an existing `orgs` the reader would reject THEN `pin_owner`, nothing written; GIVEN the lock held THEN `internal`; GIVEN a successful write THEN the platform probe returns `owner_ok:true` for the new file. Tests: CF-07.

## 6. Fold

The fold computes an organization's state from its genesis lineage and an unordered bag of acts. It is the only place chain acts are examined.

Past-cone validity. The validity and effect of a chain primary, a `chain.resolve` and a genesis change depend only on the act's own bytes (signatures over them included) and its past cone (FO-26): the path from the act's parent back to the root, plus the paths to the nodes the act names (a resolve's candidates and heads, a change's head H). No rule reads descendants or later acts to decide whether such an act is valid or what it changes. Verdicts, record promotions and tip statements are outside this rule: their checks read the state at the tip by design (VR-02, VR-12, WT-10).

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

Meaning: a vitni `ok` against fold `keys` means only "signed by a key that is active and accepted in that state". It is NOT proof of a human decision and NOT an approval: it skips identity, inputs, relay, time, freshness, witness, replay and profile checks (VR-02). A non-chain act (verdict, record promotion) MUST be decided by `check-act`, whose `valid:true` is the only human-proof signal (KC-04); chain acts are decided by the fold. A consumer that hands fold `keys` to vitni for a non-chain act and treats `ok` as an approval violates this requirement. `keys` keeps only accepted keys as defense in depth: a skipped `check-act` still cannot get `ok` for an unproven key.

- S1: GIVEN a removed device WHEN a valid-signature act by it is checked at a later tip THEN `revoked_key`. V: fld/removed-stays-revoked
- S2: GIVEN a device of a class absent from the policy WHEN folded THEN its kid is absent from `keys` and present in `devices` with `accepted:false`. V: fld/unaccepted-not-in-keys, cls/vitni-direct-unknown-key, cls/vitni-ok-not-approval

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

A chain act or endorsement that fails verification or authority MUST be ignored (not on the chain) and MUST NOT change the fold result. Only genesis and input problems are fold errors.

- S1: GIVEN 100 forged acts appended WHEN folded THEN identical output. V: fld/junk-appended, fld/forged-sig-ignored

### FO-07 Proof of possession and uniqueness

A `device.add` or `member.add` is valid only with a proof-of-possession endorsement signed by the new key, with its `performer_id` per ACT-13, verified under `S_P` plus the new key as active. The proof-of-possession endorsement is never a counted signature.

The new `kid`, `sign` point and `agree` point MUST NOT equal the kid, sign or agree key of any device of `S_P` (removed devices included), of any device of an earlier lineage epoch (its document and the state at the H that closed it, GP-19), or the epoch's relay key (WT-01). The comparison runs over one pool of kids and one pool of points, and the points of `sign` and of `agree` share the points pool: a new `sign` point equal to any `agree` point of the pool is refused, and so is a new `agree` point equal to any `sign` point. A kid removed there never returns. Acts of an earlier epoch outside the path to its closing H are not read.

- S1: GIVEN a `device.add` without the new key's endorsement WHEN folded THEN it is not on the chain. V: add/ok, add/no-pop, add/pop-performer-mismatch
- S2: GIVEN a `device.add` that re-introduces a removed kid WHEN folded THEN it is not on the chain. V: cas/removed-never-returns
- S3: GIVEN a `device.add` introducing the relay key as `sign` WHEN folded THEN it is not on the chain. V: wit/device-add-relay-key-ignored

### FO-08 Endorsement rules

An `act.endorse` receipt MUST have `parent_receipt_hash` = the receipt id of the endorsed chain act, `parent_performer_id` = its `performer_id`, `body.act` = that id, and `head = {id: the endorsed act's parent_receipt_hash, kind: "chain"}`, so the endorser saw the same state. Endorsements of endorsements, of non-chain acts or of unknown ids, and endorsements with another head, are ignored. Which endorsements count, and how persons are counted, is FO-23.

Why: a late endorsement from a signer who saw a newer state cannot revive a primary made at an older parent.

- S1: GIVEN an endorsement whose head is a later position WHEN folded THEN it does not count for a primary at an older parent. V: end/head-binding, end/endorse-endorsement

### FO-13 Quorum is policy

The fold MUST contain no role name, threshold, class id or duration. Roles and counts come only from the epoch's policy and the persons in `S_P`. Persons are counted once however many of their devices signed. A person with no active accepted key contributes no signature. The floor of 2 lives in GP-02, not in the fold.

- S1: GIVEN a maintainer removed so that two of three maintainers remain WHEN a `member.add` with Q = 2 is signed by both THEN valid; with one maintainer remaining THEN never valid. V: quo/two-left-reachable, quo/one-left-unreachable

### FO-15 Non-chain acts

Verdicts and record promotions are never on the chain. They are verified at ingestion (VR-14) against the fold at the verifier's tip.

### FO-16 at

`at = n` (a decimal string) counts nodes of the accepted chain from the root (root = 0). An `n` at or before the last accepted node returns that prefix state, also when the chain ends at a fork parent. An `n` beyond the tip is `at_beyond_tip`. An `n` beyond a fork parent is `fork`.

- S1: GIVEN a chain of 4 WHEN `at` is `"2"` THEN the state after two positions; likewise for `"0"`, `"1"`, `"3"` and `"4"`, and an `n` of `"9"` is `at_beyond_tip`. V: fld/at-0-state, fld/at-1-state, fld/at-prefix-states, fld/at-3-state, fld/at-4-state, fld/at-beyond-tip
- S2: GIVEN a fork at accepted node 2 WHEN `at` is `"2"` THEN the state at 2; WHEN `at` is `"3"` THEN `fork`. V: fld/at-fork-parent-state, fld/at-beyond-fork-parent

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

Consent on `device.add`. If `body.person` has at least one device active and accepted in `S_P`, the act MUST also carry a signature, primary or an endorsement passing FO-08 and FO-21, by a key of `body.person` that is active and accepted in `S_P`. That signature is one of the act's signatures and counts toward Q like any other when the person holds a listed role (FO-23), so adding your own new phone takes your own key plus one other person. If `body.person` has no such device (zero devices, or only devices of classes the policy does not accept), no consent exists and none is required: Q other persons add the device. Consent applies to `device.add` only: `member.add` creates a person with no device, and in `device.remove` the target already counts.

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

- S1: GIVEN honest c at P and one tricked signature by bob on any act at P WHEN folded THEN the output is unchanged. V: frk/single-touch-cannot-fork, frk/a-c1-self-removal-variant-rejected
- S2: GIVEN c1 by alice and bob and c2 by bob and carol at P WHEN folded THEN `fork`. V: frk/quorum-equivocation-freeze, frk/two-identical-bodies-fork
- S3: GIVEN alice's stale proposal at P completed by bob's late endorsement while c sits at P WHEN folded THEN `fork`; plus a resolve by bob and carol choosing c THEN c; plus a second stale proposal at P completed by one touch THEN `fork` again; plus a resolve examining it THEN c. V: frk/late-endorsement-stale-head-fork, frk/stale-proposal-first-resolve-lifts, frk/stale-proposal-second-stale-refreezes, frk/stale-proposal-refreeze-lifted-again
- S4: GIVEN a current resolve choosing c1 and then a new valid primary under c2, or a new child c3 of P, WHEN folded THEN `fork`; plus a resolve whose heads examine it THEN c1. V: frk/losing-branch-extension-refreezes, frk/losing-branch-extension-lifted, frk/resolve-new-child-refreezes, frk/resolve-new-child-lifted
- S5: GIVEN two valid two-person removals of different devices at one parent WHEN folded THEN `fork`. V: frk/two-valid-removals, frk/mutual-disqualification
- S6: GIVEN bag B where c is built upon at P, and B plus one two-signer leaf, or one two-act branch, at P WHEN folded THEN c in B and `fork` in the larger bag, never another winner. V: frk/finality-base-bag-applies, frk/finality-added-leaf-only-forks, frk/finality-added-branch-only-forks

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
- S4: GIVEN a current resolve by bob and carol choosing c1 (heads [c2]) and a stale resolve choosing c2 (heads [c1]) completed by one touch WHEN folded THEN `fork`, also after a later primary under c1; plus a resolve by bob and carol choosing c1, heads [c2], overriding the stale one with its evidence THEN c1. V: frk/stale-resolve-lifted-by-override, frk/stale-resolve-completed-forks, frk/stale-resolve-late-endorsement-still-forks, rsv/overriding-resolve-lifts-conflict, rsv/override-wrong-id-not-current
- S5: GIVEN heads in the chosen subtree, or one head an ancestor of another WHEN folded THEN ignored. V: rsv/head-outside-losing-subtree-ignored, rsv/heads-ancestor-pair-ignored
- S6: GIVEN an applied resolve choosing c1, then a stale primary under c2 and a stale resolve choosing c2, each completed by one touch WHEN folded THEN `fork`, never c2. V: frk/two-stale-artifacts-cannot-replace-winner, frk/two-stale-artifacts-winner-applied, frk/two-stale-artifacts-stale-primary-forks, frk/two-stale-artifacts-override-lifts
- S7: GIVEN a losing candidate c2 with children d1 and d2 and a resolve choosing c1 with heads [d1, d2] WHEN folded THEN c1. V: rsv/two-heads-one-losing-candidate-current
- S8: GIVEN bob's pending R1 (c1) at P with bob2's endorsement e_b2 (same person, so it does not complete R1), alice's S (c2) naming R1 with [e_b2], then carol completes R1, then bob's tricked touch completes S WHEN folded THEN `fork`, never c2; plus R3 by bob and carol naming S with its evidence THEN c1. V: frk/pending-name-override-cannot-replace, frk/pending-name-override-first-resolve-applies, frk/pending-name-override-lifted
- S9: GIVEN R1 applied (c1) and, after it, alice's S (c2) naming R1 with its completing endorsement, completed by bob WHEN folded THEN c2 (one proposal plus one touch, section 1.4). V: rsv/override-with-completion-evidence-current, rsv/override-completion-evidence-first-resolve-applies, rsv/override-evidence-insufficient-not-current, rsv/override-evidence-bad-signature-not-effective
- S10: GIVEN R_P at a node d below P whose evidence key was added between P and d, named by X at P WHEN folded THEN the entry is effective. V: rsv/override-evidence-key-added-below-p-counts
- S11: GIVEN R_G applied at G (c1), alice's pending R_x at G (c2) naming R_G with evidence, then R_P applied at a node of c1's branch, then bob completes R_x WHEN folded THEN `fork` at G; GIVEN R_x signed after R_P and naming both with evidence THEN c2. V: frk/ancestor-override-cannot-discard-unseen-resolve, frk/ancestor-override-before-completion-applies, frk/ancestor-override-lifted, rsv/override-names-discarded-subtree-resolve-current
- S12: GIVEN two applicable resolves choosing different candidates that do not name each other WHEN folded THEN `fork`. V: rsv/conflicting-resolves-freeze
- S13: GIVEN a fork at P (c1, c2) and one resolve, or two resolves, choosing c1 with heads [c2] WHEN folded THEN c1 is the next node. V: rsv/lifts-fork, rsv/same-choice-two-resolves-ok
- S14: GIVEN an honest chain below node 3 whose last act removes K, a rival child c2 of 3 signed by K, and a resolve by bob and carol choosing the honest child WHEN folded THEN the honest child; GIVEN then a resolve by K and carol choosing c2 THEN `fork` at 3 (applicable, never current); GIVEN then a resolve by bob and carol naming it with its evidence THEN the honest child. V: frk/r11-honest-resolve-applies, frk/r11-resolve-above-removal-costs-override, frk/r11-override-lifts
- S15: GIVEN a person minted at node 3 by K and one tricked touch, with a branch that removes bob and carol, and a resolve by bob and carol whose examined path holds those removals WHEN folded THEN the resolve is ignored and `fork` at 3; GIVEN an honest change with H on the honest branch THEN the state of the new epoch. V: frk/r11-minted-person-branch-freezes, frk/r11-minted-person-change-recovers

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

`check-act` evaluates one non-chain act (a verdict or a record promotion) for a consumer. It folds the evidence it is given and never accepts a state from the caller.

### VR-01 check-act input and output

Input (conformance build): `{acts, expect_method, jws, lineage, now, org, pin, recipient, record_body_b64, relay, request_b64, request_id, seen, synced_at, tip_statement}`, where:
- `pin` is the probe object (GP-14); `lineage` and `acts` are as in GP-07; `org` is the org id the consumer expects (hashstr);
- `now` and `synced_at` are `time`; `seen` is a list of receipt ids (VR-15);
- `tip_statement` is null or a relay tip statement JWS (WT-03);
- for verdicts, `request_b64`, `request_id`, `recipient` and a non-null `relay` are required: the request bytes and the values the consumer expects;
- for `record.promote`, `record_body_b64` is required;
- `expect_method` is a string. A verdict method or `record.promote` makes the inputs of its kind required, and any other string requires nothing more. Its value is read at step 9 (VR-03) only: an act whose own method is a chain method is `chain_method` at step 4 whatever `expect_method` says.

The production build reads the pin and the clock itself and takes no `pin` and no `now`; an input carrying either is `malformed_input` (CF-08).

Required inputs are checked before anything else. Any of these is `{"error":"malformed_input"}`: a missing `expect_method`, `jws`, `acts`, `seen`, `synced_at`, `lineage`, `org` (or a non-hashstr `org`), or, in the conformance build, `now` or `pin`; a missing `tip_statement` key or a value that is neither null nor a string; `request_b64`, `request_id` or `recipient` absent when `expect_method` is a verdict; `record_body_b64` absent when it is `record.promote`; `relay` null when it is a verdict.

Output, always these four keys: `{"class","reason","receipt_id","valid"}`. Each of `class` and `receipt_id` is filled as soon as it is known, on a failure as on success. `receipt_id` is null for steps 1 and 2 and the hashstr of the payload bytes from step 3 on. `class` is null for steps 1 to 6 and from step 7 on is the class of the device in the pinned state whose kid is the header kid, or null when the state has no such device. `valid:true` only with `reason:"ok"`, and only for an accepted key (KC-04). There are no partial-success flags: every check runs on every act. `check-act` is pure: no clock, no I/O, no hidden state (the production build's probe and clock read happen before the pure core runs).

Why: `valid:true` means a fully checked human decision; there is no partial-success shape a consumer could misread.

- S1: GIVEN a probe reporting `pin_missing` WHEN checked THEN `valid:false`, `pin_missing`. V: chk/state-is-error, ok/approve
- S2: GIVEN a `check-act` input without `org`, or a verdict input without `request_id` WHEN run THEN `{"error":"malformed_input"}`. V: org/check-act-org-input-missing, chk/request-id-input-missing
- S3: GIVEN the production build and an input with `pin` WHEN run THEN `{"error":"malformed_input"}`; the production build refuses `pin` in a test of the build (CF-07, CF-08), because no vector runs against it.

### VR-02 Ordered pipeline, first failure wins

`check-act` runs these steps in order and returns the first failure:
1. `jws_shape` (ACT-02, ACT-03);
2. `payload_not_canonical_subset`, `payload_too_large` (ACT-04);
3. `schema`, envelope only: ACT-01 constants and key set, ACT-07 forms of envelope fields, and `ext` has exactly the key `dev.handsal/act` with an object value;
4. `method_unknown`, then `chain_method` for every method other than verdicts and `record.promote` (chain primaries, `chain.resolve`, `act.endorse`, `genesis.sign`), so no human act is ever treated as permanent;
5. method-dependent: `schema` for the act object (ACT-06 keys, ACT-08 head presence and shape, ACT-09 extra keys, ACT-13 parent fields, ACT-14 `kid`, ACT-07 forms of act-object and body fields), then `body_schema` (ACT-09, ACT-10);
6. pin and fold, in this order: (a) the probe's `org` or `filename` differs from the input `org`: `pin_org_mismatch`; (b) `owner_ok` false: the probe's reason; (c) `pin_malformed`; (d) the pin's `org` differs from the input `org`: `pin_org_mismatch`; (e) `profile_mismatch`; (f) production build only: `fixture_profile`; (g) `lineage_broken` for an empty lineage, then `lineage_broken` for a first document whose hash differs from the pin's `org`, then `genesis_pin_mismatch` for a last document whose hash differs from the pin's `genesis` (GP-07); (h) `pin_spec_mismatch`; (i) the fold error code;
7. `org_mismatch` (the act's `org` against the pin's `org`);
8. `relay_mismatch` (verdicts, VR-08);
9. vitni `verify` (VR-03): `unknown_key`, `revoked_key`, `bad_signature`, `context_mismatch`, `verifier_unavailable`, `verifier_unexpected`;
10. `high_s` (VR-04);
11. `identity_mismatch` (VR-05);
12. `request_mismatch` (the act's `request_id` or `recipient` differs from the inputs), then `inputs_mismatch`, `outputs_mismatch` (VR-06, VR-07);
13. time (VR-11);
14. view (VR-12), then witness (WT-04, WT-05, WT-10);
15. `duplicate_receipt` (VR-15);
16. `unproven_class`, else `ok`.

Why steps 3 and 5 are split: the act object's closed key set depends on the method, so it cannot be checked before the method is known; the envelope can. Profile rules have one owner (the checker) and ES256 has one owner (vitni). Two defects in one act return the earlier reason, so `unproven_class` appears only for an act that is otherwise perfect.

- S1: GIVEN an act with both a bad signature and a stale view WHEN checked THEN `bad_signature`. V: ord/sig-before-time, ord/schema-before-method
- S2: GIVEN adjacent defects of steps 4 and 5, inside step 5, and inside step 6 WHEN checked THEN the earlier code. V: ord/method-before-act-object, ord/chain-method-before-body, ord/act-object-before-body, ord/probe-org-before-owner, ord/owner-before-pin-parse, ord/pin-parse-before-pin-org
- S3: GIVEN a wrong `request_id` input and another request's bytes WHEN checked THEN `request_mismatch`. V: ord/request-before-inputs, rep/request-id-input-mismatch, rep/recipient-input-mismatch
- S4: GIVEN a frozen bag WHEN `check-act` runs THEN `valid:false`, `fork`. V: frk/check-act-refuses, ord/fork-before-vitni

### VR-03 vitni verify, always pinned

The checker MUST call vitni `verify` with `policy.expected_binding = "local"` and `policy.expected_method = expect_method`, always set and never null. `keys` is the fold `keys`, except when the signer kid is a device with `accepted:false`: then it is a one-entry map keyed by that device's person in the state, `{person(kid): {kid: {that device's sign key, status: "active" if the device is active, else "revoked"}}}`. The signature of a key that is not accepted is therefore still verified before step 16 can say `unproven_class`. A `performer_id` that differs from the device's person yields vitni `unknown_key`.

The vitni reasons `unknown_key`, `revoked_key`, `bad_signature` and `context_mismatch` pass through unchanged. Every other vitni reason (`malformed`, `header_key_material`, `alg_not_allowed`, `non_canonical_payload`, or any string not listed) is `verifier_unexpected`: steps 1 to 5 should have made it unreachable, so vitni and the profile disagree, and the checker fails closed with one defined code. The checker MUST NOT implement ES256 itself. The vitni binary is located per CF-05.

- S1: GIVEN `expect_method` approve and a signed reject WHEN checked THEN `context_mismatch`. V: vtn/context-mismatch, vtn/unknown-key
- S2: GIVEN vitni returning a reason outside the four pass-through codes WHEN checked THEN `verifier_unexpected` (an implementation test, CF-07).
- S3: GIVEN a key that is not accepted and a bad signature WHEN checked THEN `bad_signature`, never `unproven_class`. V: vtn/unaccepted-bad-sig, vtn/unaccepted-map-keyed-by-person
- S4: GIVEN a record promotion whose `performer_id` is not the signing device's person WHEN checked THEN `unknown_key`. V: idn/record-performer-unknown-member

### VR-04 Low S

After a valid signature, the checker MUST reject S above n/2 (`high_s`). The signer normalizes before returning (SG-06). Deduplication stays on receipt id.

Why: vitni accepts high S on both implementations; the profile wants one signature string per payload at the producer and checks it at the verifier.

- S1: GIVEN a payload signed with S replaced by n minus S WHEN checked THEN `high_s`, while vitni alone says ok. V: sig/high-s, sig/low-s-ok

### VR-05 Identity

For verdicts, `performer_id` MUST equal the act's `recipient`, else `identity_mismatch`. The recipient the consumer expects is compared at step 12 (`request_mismatch`). The sender of a request is not signed by anyone and MUST be shown as "not proven" wherever it is displayed (RN-07).

- S1: GIVEN `recipient` bob and `performer_id` alice WHEN checked THEN `identity_mismatch`. V: idn/recipient-not-performer

### VR-06 inputs_hash

For verdicts `request_b64`, and for `record.promote` `record_body_b64`, are required inputs (VR-01). The checker MUST recompute the hashstr over the raw decoded bytes, without re-canonicalizing, and compare it to `inputs_hash`; a mismatch is `inputs_mismatch`.

Why required: a `valid:true` without the bytes would approve whatever request the consumer later pairs with it.

- S1: GIVEN another request's bytes WHEN checked THEN `inputs_mismatch`. V: inp/other-request, inp/record-body-mismatch
- S2: GIVEN a verdict input without `request_b64` WHEN run THEN `{"error":"malformed_input"}`. V: inp/not-supplied-flag

### VR-07 outputs_hash

VR-07 is the single owner of `outputs_hash` for every method that `check-act` decides. `outputs_hash` MUST equal the value ACT-09 derives: for a verdict, hashstr(JCS({"request_id":R,"verdict":V})) from the act's `request_id` and the verdict of its method; for `record.promote`, EMPTY_HASH. A mismatch is `outputs_mismatch`. No other method is decided by `check-act` (`chain_method`, VR-02 step 4); ACT-09 says what the fold does with their hashes.

- S1: GIVEN an approve whose `outputs_hash` was computed for verdict `reject` WHEN checked THEN `outputs_mismatch`. V: vrd/outputs-verdict-swapped
- S2: GIVEN a `record.promote` whose `outputs_hash` is not EMPTY_HASH WHEN checked THEN `outputs_mismatch`. V: vrd/record-outputs-not-empty

### VR-08 Relay

Verdicts carry `relay`. The verifier MUST supply its configured relay hostname for verdicts (VR-01). An act naming a different relay is `relay_mismatch`.

- S1: GIVEN an act for relay `a.example` WHEN verified at `b.example` THEN `relay_mismatch`. V: rly/other-relay
- S2: GIVEN a verdict input whose `relay` is null WHEN run THEN `{"error":"malformed_input"}`. V: rly/not-configured-flag

### VR-09 One verdict per request and recipient

Consumers MUST keep at most one verdict per `(request_id, recipient)`: `seen` carries accepted receipt ids, and the consumer's own store carries the pair. A second distinct verdict for the pair is the consumer's conflict to surface. The checker's duty is only `duplicate_receipt` on equal receipt ids.

- S1: GIVEN the same receipt presented twice WHEN checked with `seen` containing its id THEN `duplicate_receipt`. V: rep/same-receipt-twice, rep/different-receipt-same-request-ok

### VR-10 Replay across contexts

A different org, a different relay, a swapped `request_id` or another request's `inputs_hash` MUST each fail with its own reason: `org_mismatch`, `relay_mismatch`, vitni `bad_signature` (an edited payload no longer verifies) and `inputs_mismatch`.

- S1: GIVEN `request_id` edited in the payload WHEN checked THEN `bad_signature`. V: rep/request-id-swapped, rep/org-swapped, rep/inputs-hash-swapped

### VR-11 Time rules

`ts` MUST be at most `now + clock_skew_s`, else `ts_in_future`; exactly `now + clock_skew_s` is valid. Verdicts and record promotions carry `expires`: `expires` MUST be after `ts` (else `bad_expiry`), and `expires - ts` MUST be at most `max_validity_s` (else `validity_too_long`). The act is `expired` when `now >= expires`. No act is permanent. The values come from the epoch policy's `freshness`.

`now` is the verifier's clock. An agent that controls the clock defeats expiry and freshness (section 14, L11).

- S1: GIVEN `now == expires` WHEN checked THEN `expired`; GIVEN `now == expires - 1` THEN valid. V: tim/expired-at-now, tim/one-second-left-ok
- S2: GIVEN `ts` exactly `clock_skew_s` ahead of `now` THEN valid; one second more THEN `ts_in_future`. V: tim/ts-future-by-skew-ok, tim/ts-future-by-skew-plus-1
- S3: GIVEN `expires` equal to `ts`, or validity one second over the maximum WHEN checked THEN `bad_expiry`, `validity_too_long`. V: tim/expires-equal-ts, tim/validity-max-plus-1

### VR-12 View rules and fail-closed freshness

`synced_at` is the time the consumer last obtained the act bag from its configured source and folded it successfully. In order:
- `synced_at` more than `clock_skew_s` after `now` is `view_in_future`;
- `now - synced_at` greater than `max_view_age_s` is `stale_view`;
- the act's `head.id` not being a position of the current epoch's accepted chain is `stale_view`. One rule covers a verifier that is behind, another branch, another epoch, and junk.

A head older than the tip is valid; the signing key must be active at the tip regardless of when the act was signed.

These rules run in every witness mode. In mode `relay` the witness rules (WT-05) run after them, and both must pass (WT-07). In mode `none` they are the whole freshness check and `tip_statement` must be null (WT-04). Mode `none` leaves a known gap (section 14, L10).

Why: a non-chain act authorizes something now only if the verifier's view could have seen any revocation.

- S1: GIVEN `now - synced_at == max_view_age_s` THEN valid; one second more THEN `stale_view`. V: frs/age-exactly-max-ok, frs/age-max-plus-1
- S2: GIVEN a head that is a losing candidate of a current resolve, or an unknown id WHEN checked THEN `stale_view`. V: frs/head-other-branch, frs/head-unknown-id
- S3: GIVEN a head older than the tip and a key still active WHEN checked THEN valid; GIVEN the key revoked at the tip THEN `revoked_key`. V: frs/head-older-than-tip-ok, frs/head-older-key-revoked-at-tip

### VR-14 Ingestion contract

A consumer MUST run `check-act` once, when an act first arrives, and record `{receipt_id, tip_id_at_ingestion, valid, reason}` for a valid act. An invalid result is recorded keyed by the hashstr of the full JWS bytes, or not at all; it is never recorded against a receipt id, so a garbage-signature twin cannot make the consumer refuse the valid act later. The consumer MUST NOT re-run `check-act` on stored acts to decide historic validity, and MUST run it for every new act. Consumers verifying chain acts use the fold, not `check-act`.

Why: an approval must not flip after an unrelated later revocation. Vectors assert the pure-function side: a revocation after ingestion changes `check-act` at the new tip, which is why the consumer must not re-run it.

- S1: GIVEN an approve ingested at tip 7 and its signing key removed at 8 WHEN `check-act` is run at tip 8 THEN `revoked_key`; the consumer's recorded decision stands. V: ing/revoked-after-ingestion-recheck-fails
- S2: GIVEN an invalid twin of a valid act WHEN ingested THEN it is not recorded against the receipt id (a consumer implementation test, CF-07).

### VR-15 Duplicate receipt

`seen` holds only receipt ids of acts the consumer previously found valid. A presented act whose receipt id is in `seen` is `duplicate_receipt`.

- S1: GIVEN an invalid twin that was never found valid WHEN the valid act is checked THEN it is not a duplicate. V: rep/invalid-twin-not-in-seen

### VR-16 Verifier-side limits

`check-act` MUST reject a payload segment larger than MAX_PAYLOAD before any other work on it.

- S1: GIVEN a 16385-byte payload WHEN checked THEN `payload_too_large`. V: jcs/oversize

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

Line 1 is at most 80 bytes, is the OS prompt text (RN-11), and MUST carry the decision summary. A free field longer than 12 characters appears as its first 11 characters plus `~`. The free fields are `<class>`, `<person>`, `<member>`, `<role>`, `<request_id>`, `<record_id>` and the genesis `<name>` (`org_name`, up to 24 characters, so it is cut like the others). `kid12`, `hash12` and decimal counts appear as is. Templates:
- `device.add`: `Add device <kid12> (<class>) to <person>`
- `device.remove`: `Remove device <kid12> of <person>`
- `member.add`: `Add device <kid12> as member <member> (<role>)`
- `chain.resolve`: `Resolve fork, keep: ` followed by line 1 of the chosen candidate cut to 59 bytes, plus `~` when cut
- `request.approve`: `APPROVE request <request_id> (<hash12(inputs_hash)>, <N> bytes)`; `request.reject`: `REJECT request ...`; `request.needs-info`: `NEEDS-INFO on request ...`, with the same tail
- `record.promote`: `Promote record <record_id> (<hash12>, <N> bytes)`
- `genesis.sign` over an original: `Sign genesis of <name> (<hash12(doc)>): <M> members, <D> devices`
- `genesis.sign` over a change: `Change <name> (<hash12(doc)>): +<A>/-<R> dev, <C> mem, policy same|NEW`, where A and R are the devices added and removed, C counts member entries added, removed or with a changed role, and `NEW` means some policy byte differs
- `act.endorse`: `Endorse: ` followed by line 1 of the endorsed act cut to 70 bytes, plus `~` when cut

There is one vector per method at maximum field lengths proving the 80-byte bound.

- S1: GIVEN maximum-length fields WHEN rendered THEN line 1 is at most 80 bytes. V: rnd/prompt-line-max-length, rnd/prompt-line-max-device-remove, rnd/prompt-line-max-member-add, rnd/prompt-line-max-resolve, rnd/prompt-line-max-approve, rnd/prompt-line-max-reject, rnd/prompt-line-max-needs-info, rnd/prompt-line-max-promote, rnd/prompt-line-max-genesis-original, rnd/prompt-line-max-genesis-change, rnd/first-line-tilde, rnd/line1-endorse-bounded
- S2: GIVEN each method WHEN rendered THEN line 1 follows its template. V: rnd/line1-approve-size, rnd/line1-device-add-class, rnd/line1-member-add-kid-first, rnd/line1-resolve-keeps-kid12, rnd/line1-genesis-change-summary

### RN-04 Method lines

Every signed value a person decides on is rendered: one line per field, in ACT-09 order, values verbatim. A field line is the field name, a colon, one space and the value (`Person: alice`). A list is a header line, the name and a colon with nothing after it, followed by one indented line per entry. `hash12` and the thumbprint of a key are defined in section 2.1. The lines, in order:
- `device.add`: `Person: <person>`, `New device: <full kid>`, `Agree key: <thumbprint of agree>`, `Class: <class>` (on its own line, so endorsers vouch for it), `Label: <label>`, `Link code: <hash12(link_code_hash)>`.
- `device.remove`: `Person: <person>`, `Remove device: <full kid>`.
- `member.add`: `Member: <member>`, `Role: <role>`, `New device: <full kid>`, `Agree key: <thumbprint of agree>`, `Class: <class>`, `Label: <label>`.
- `chain.resolve`: `Fork parent: <full id>`, `Choose: <full id>`; `Candidates:` and one line per candidate in `candidates` order, `  > <hash12> <line 1>` for the chosen one and `    <hash12> <line 1>` for the others; `Heads:` and one line per head in `heads` order, `  - <hash12> <line 1 of the attached head act>`; then `Overrides: none`, or `Overrides:` and one line per entry in entry order, `  - <hash12 of resolve> (endorsements: <E>)`, E the decimal count.
- `request.*`: `Request: <request_id>`, `Recipient: <recipient>`, `Relay: <relay>`, `Request hash: <hash12(inputs_hash)>`, then the request block (RN-05).
- `record.promote`: `Record: <record_id>`, `Anchors:` and one line `  - <anchor>` per anchor, `Body hash: <hash12(inputs_hash)>`, then the record body block (RN-12).
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
- S2: GIVEN a request over 2048 bytes, or of 33 or 40 block lines WHEN rendered THEN `render_refused`; GIVEN exactly 2048 bytes THEN rendered. V: rnd/request-over-2048-refused, rnd/request-33-lines-refused, rnd/oversize-truncated, rnd/request-32-lines-cap, rnd/request-exactly-2048-ok
- S3: GIVEN a request of zero bytes, or one line of 300 bytes WHEN rendered THEN the block has no content line, or a `| ` line followed by `|+` lines. V: rnd/empty-request, rnd/request-long-line-continuation

### RN-06 Refusal

`render` MUST refuse any payload that is not schema-valid for its method, any method not in the registry, any value outside the alphabets, and any render over 72 lines. A signer MUST NOT sign what its own renderer refuses.

- S1: GIVEN a payload with an extra key WHEN rendered THEN `schema`. V: rnd/refuse-extra-key, rnd/refuse-unknown-method

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
| `genesis.sign` | `document` | hashstr(JCS(document)) = `inputs_hash` |
| `genesis.sign` over a change | `previous` | hashstr(JCS(previous)) = `document.prev` |
| `genesis.sign` over a change | `document` | `head.id` of the payload = `document.head` |
| `act.endorse` | `act` (JWS) | its receipt id = `body.act` = `parent_receipt_hash`; its `performer_id` = `parent_performer_id`; its `parent_receipt_hash` = `head.id`; it is a chain primary or a resolve |
| `act.endorse` of a resolve | `candidates`, `heads` (JWS lists) | bound against the attached resolve exactly as for the resolve itself (next rows) |
| `chain.resolve` | `candidates` (JWS list) | one JWS per id of `body.candidates`; each has `parent_receipt_hash` = the resolve's parent |
| `chain.resolve` | `heads` (JWS list) | one JWS per id of `body.heads`; each is a chain primary |

Every attachment that is an act MUST pass ACT-01 to ACT-14. An attachment that is a genesis document (`document`, `previous`) MUST be valid by itself: GP-15 steps 1 and 3 over the document alone (structure, then policy and devices; the profile and lineage steps belong to the fold). `fixture_key` follows the profile the document itself names: a document naming the production profile that lists a fixture kid is not valid alone, and one naming the fixture profile, or a profile the checker does not implement (step 2 belongs to the fold), is not refused for it. One that binds by hash but is not a valid document is `attachment_mismatch`, the same code as an act attachment that fails ACT-01 to ACT-14. A JWS list bound to a body list holds exactly one JWS per receipt id of that list and nothing else, in any order: a duplicate copy, an extra JWS or a missing id is `attachment_mismatch`. An `act.endorse` of a chain primary that carries `candidates` or `heads` is `attachment_mismatch`. A name that is absent from `attachments` is `attachment_missing`. Every other defect of an attachment is `attachment_mismatch`: a list that is present but is not an array, a value of the wrong type (`request_b64` and `record_body_b64` excepted, CF-03), a list that lacks an id, or an attachment that does not bind. Whether a head lies in a losing subtree is decided by the fold (FO-25), not by the renderer. A signer MUST NOT sign what its renderer refuses.

Why: the words a person sees are a function of signed bytes only; an attachment is never a second, unbound source.

- S1: GIVEN an endorse draft whose attachment is another act WHEN signed THEN exit 2, `attachment_mismatch`, no prompt (a signer implementation test, CF-07). V: rnd/endorse-attachment-mismatch, rnd/endorse-attachment-missing
- S2: GIVEN an endorsement draft of a resolve without `heads`, or with a candidate act outside the resolve's candidates, or a head act whose act `kid` differs from its header kid WHEN rendered THEN `attachment_missing`, `attachment_mismatch`, `attachment_mismatch`. V: rnd/endorse-resolve-nested-attached, rnd/endorse-resolve-heads-missing, rnd/endorse-resolve-candidate-mismatch, rnd/attachment-act-kid-differs, rnd/endorse-primary-extra-attachment
- S3: GIVEN a request, record, document or candidate attachment that does not bind WHEN rendered THEN `attachment_mismatch` or `attachment_missing`. V: rnd/request-attachment-mismatch, rnd/record-attachment-mismatch, rnd/genesis-attachment-hash-mismatch, rnd/genesis-change-previous-mismatch, rnd/resolve-candidate-wrong-parent, rnd/resolve-candidate-missing, rnd/resolve-head-attachment-missing
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

The signer's display channel (`/dev/tty`, `CONOUT$`) and the OS prompt text are both reachable by same-user processes (section 1.2). The full render and line 1 are aids. The signer MUST still put line 1 into the OS prompt; where a platform prompt cannot carry it, that is stated for that class. Chain security comes from FO-22. A tricked touch on a verdict or record promotion signs one decision whose request or record id, hash12 and size are in line 1; a consumer that needs more requires decisions from more than one recipient, which is consumer policy outside this profile. The ceremony's hash12 comparison is an aid (SG-12).

### RN-12 Record body block

`record.promote` renders the record body exactly like a request block (RN-05 escaping, prefixes and limits), delimited by `----- record body (<N> bytes, sha256 <hash12>) -----` and `----- end -----`, from the bound attachment `record_body_b64` (RN-09). Over the limits it is `render_refused`.

- S1: GIVEN a record promotion WHEN rendered THEN the body block appears; GIVEN a body over the limits THEN `render_refused`. V: rnd/record-body-block, rnd/record-body-over-limit-refused

## 9. Conformance and checker CLI

### CF-01 Profile hashes and bundle

- **Core manifest**: `{path: hashstr}` over `spec/profile.md`, `spec/registry.json`, `conformance/CONTRACT.md`, `conformance/fixtures/keys.json` and `conformance/fixtures/fixture-kids.json`.
- **Production profile** = hashstr(JCS({"core": <core manifest>, "kind": "production"})). **Fixture profile** = hashstr(JCS({"core": <core manifest>, "kind": "fixture"})) (GP-18).
- **Bundle hash** = hashstr(JCS(full manifest: the core plus every vector file)), published with each tag for the integrity of the vector set.

Genesis `profile`, pin `spec` and consumer pins hold a profile hash, never the bundle hash. A verifier implements a fixed set of profile hashes; any other is `profile_mismatch`.

Why the split: vectors embed a profile hash in their genesis `profile`. If the profile hash covered the vectors it would have to be its own input, a SHA-256 fixed point that cannot exist. Profile hashes therefore never cover vectors, and vectors may embed them.

- S1: GIVEN a `profile` naming an unimplemented profile hash WHEN folded THEN `profile_mismatch`. V: gen/profile-mismatch, cf/profile-hashes-not-circular

### CF-02 Vector format

Vector files follow the vitni format: one JSON file per vector, `{name, command, input | input_raw, anchor}`. Unlike vitni, `anchor` is REQUIRED on every handsal vector: vitni can run without anchors because two independent verifiers cross-check each other, while handsal starts with one reference. `input_raw` MAY carry bytes that JSON would normalize. Names are `group/case`. Vectors over MAX_INPUT are built by the harness at run time from their row, a valid input padded inside one string to MAX_INPUT + 1 bytes; no 16 MiB file is stored.

- S1: GIVEN a vector without `anchor` WHEN the harness loads it THEN it fails. V: cf/anchor-required

### CF-03 Commands

`handsal-check <command> < input.json` writes exactly one line of JCS JSON and exits 0.

| Command | Input | Output |
|---|---|---|
| `check-act` | VR-01 | `{class, reason, receipt_id, valid}` |
| `fold` | `{acts, at?, lineage, org, pin}` | FO-01 |
| `render` | `{attachments, kid, method, payload}` | `{first_line, text}` or `{"error":code}` (RN-06, RN-09) |
| `subset` | raw bytes | `{canonical, reason}` (ACT-04, grammar only) |
| `kid` | `{x, y}` | `{kid}` (ACT-11) |
| `genesis-check` | `{acts, lineage}`; the last lineage entry is the candidate document with its signatures | `{pin, reason, valid}`; `pin` is the exact content of the pin file (GP-05), the JCS line and its closing LF, when valid, else null |
| `enrolled` | GP-13 | `{enrolled, reason}` |

`pin` and `now` are inputs of the conformance build only. The production build (CF-08) takes neither: it reads the pin through the platform probe and `now` from the system clock, and an input carrying `pin` or `now` is `malformed_input`.

`render` takes exactly the keys `attachments`, `kid`, `method` and `payload`, else `malformed_input`. `payload` is the signed payload as a JSON object (not its bytes and not its base64url text), `kid` is the `kid` of the JWS header and `method` the method string to render, both strings, and `attachments` is an object. The names RN-09 binds are the only ones read: `request_b64` and `record_body_b64` (strings, standard base64 with padding, section 2.2), `document` and `previous` (genesis documents as JSON objects), `act` (a compact JWS string), and `candidates` and `heads` (arrays of compact JWS strings). A `request_b64` or `record_body_b64` that is not a string or not canonical base64 is `malformed_input`; any other attachment of the wrong JSON type is `attachment_mismatch`. Any other name is ignored.

`genesis-check` validates every link of `lineage` in order from the original: GP-03 for the original, GP-19 for each change against the path to its H in the epoch before it, and the GP-15 order per document. It returns the first failure, so `valid:true` means every link is authorized (GP-21). The ceremony and the pin helper use it.

Command inputs follow CF-08: the production build takes no `pin` and no `now`.

`kid` takes exactly `{x, y}`, two strings of base64url characters, and returns the thumbprint of those strings as given. It checks neither length nor curve: whether the key is valid is the concern of the act that introduces it (ACT-11). Any other shape is `malformed_input`.

Input framing: stdin MUST be I-JSON (RFC 7493: UTF-8, no duplicate member names, no lone surrogates) of at most MAX_INPUT bytes. Size is checked first, before parsing. A duplicate member name at any depth, invalid UTF-8, or more than MAX_INPUT bytes is `{"error":"unparseable_input"}`, before any command logic. Exception: `subset` reads its stdin as raw bytes (the value under test; more than MAX_INPUT is `unparseable_input`) and hands them to the recognizer unparsed.

Errors, all with exit 0: an unknown command is `{"error":"unsupported_command"}`; input that is not I-JSON within the bound is `{"error":"unparseable_input"}`; JSON missing or mistyping a required input is `{"error":"malformed_input"}`. A nonzero exit happens only for a crash, which consumers MUST treat as failure. Nothing but the result line goes to stdout. Output is deterministic. There is no checker `build` or `emit` command: emitted bytes are produced by signers (`handsal-sign emit`, SG-01) and anchored by the vector generator.

- S1: GIVEN `{}` and command `x` WHEN run THEN `{"error":"unsupported_command"}`. V: cli/unsupported-command, cli/unparseable-stdin, cli/malformed-input, cli/output-is-jcs
- S2: GIVEN a duplicate key, or more than MAX_INPUT bytes, on stdin WHEN read THEN `{"error":"unparseable_input"}`. V: cli/stdin-duplicate-key-unparseable, cli/stdin-over-max-input-unparseable
- S3: GIVEN a lineage whose original is valid, or whose middle link is forged WHEN `genesis-check` runs THEN `valid:true` with the pin line, or the first failing link's code. V: cli/genesis-check-original-ok, cli/genesis-check-forged-middle-link, cli/genesis-check-change-revoked-signer

### CF-04 Implementations

Every checker implementation MUST produce byte-identical stdout for every vector. The harness (`conformance/run.py`, standard library only, `--impl "<argv>"` given one or more times) reports PASS, DIVERGE or ANCHOR-FAIL per vector, in the manner of vitni's `compare.mjs`.

A signer implementation runs the `render` and `emit` vectors, and only those, through its own conformance executable, `handsal-sign-conformance`. It is built from the same core as the shipped `handsal-sign` (SG-01), is never installed at an administrator path (SG-14, SG-15) and is not part of the signer's distribution. It takes one argument. `render` takes the CF-03 `render` input and writes the CF-03 output, with exit 0 for every result, so the `render` vectors are the ones the checker runs. `emit` is the shipped `emit` (SG-01, SG-04), with the same input, output and exit codes; a vector whose expected exit code is not 0 names it in its `exit` member. Any other argument is `{"error":"unsupported_command"}`, exit 2 (SG-08). The executable holds no key, shows no prompt and reads neither the clock nor a random source: every value its output depends on is in its input.

Why: the shipped `render` takes a draft and fills `performer_id`, `kid` and `ts` from its own key and clock (SG-04, RN-01), so it can never take a `payload` and a `kid` from its caller, and a flag in it would be a way to make the signer show words for bytes it did not derive. As in CF-08, the split is a build, not a flag.

- S1: GIVEN a divergent implementation WHEN the harness runs THEN it reports DIVERGE. V: cf/harness-diverge-selftest
- S2: GIVEN a `render` vector WHEN run through `handsal-sign-conformance` THEN the output the checker gives. V: rnd/approve, rnd/render-73-lines-refused
- S3: GIVEN an approve draft with fixed values WHEN run through `handsal-sign-conformance emit` THEN `{payload_hex}`; GIVEN a draft with a JSON number THEN exit 2, `schema_refused`. V: cli/build-approve, jcs/emit-value-with-number-refused

### CF-05 Reference checker

The reference checker is Python (standard library logic) delegating ES256 to vitni behind a `Verifier` interface. The vitni binary is located only by an absolute administrator-owned path fixed per platform (SG-14): on macOS `/Library/Application Support/handsal/bin/vitni-verify`, checked like the pin (GP-10 `lstat` chain, root-owned, not group or other writable) before each spawn; on Windows `C:\Program Files\handsal\vitni-verify.exe`. There is no PATH lookup and no environment override; tests inject a path through a constructor argument only (the GP-14 pattern). A spawn error, an ownership failure, a timeout, non-JSON output or an `{"error"}` result is `verifier_unavailable`, never a skip, from `check-act`, `fold`, `enrolled` and `genesis-check`, which verify signatures through the same interface: each returns it in its own output form (the reason beside `valid:false`, `{"error"}`, or the `reason` of `enrolled` and `genesis-check`).

- S1: GIVEN the vitni binary absent WHEN `check-act` runs THEN `valid:false`, `verifier_unavailable` (an implementation test, CF-07).

### CF-06 Vector generation

ES256 vectors use the fixed P-256 scalars of `conformance/fixtures/keys.json` (KC-07), RFC 6979 nonces and then low-S normalization, so every run is byte-identical. A rerun followed by `git diff --exit-code` over the vector directory is the regeneration check. The generator calls both vitni implementations (Go and TypeScript) on every positive JWS and aborts unless both say `ok`; negative signature vectors record vitni's verdict. Vectors cover the low-S and high-S forms of one payload; they are the ES256 coverage vitni lacks. Vector anchors are authored by the generator from the expected behaviour, never by running the checker under test. PRODK vectors are not regenerated (CF-08).

- S1: GIVEN the generator run twice WHEN outputs are compared THEN identical. V: cf/generator-reproducible

### CF-07 Coverage rule

Every reason code defined here, except `verifier_unavailable` and `verifier_unexpected` (checker), and `pin_invalid`, `pin_rollback`, `internal`, `user_cancel`, `key_unavailable`, `key_exists` and `no_display` (pin helper and signer), MUST have at least one vector in which it is the only defect. Every adjacent pair of VR-02 steps MUST have an ordering vector, and so must the GP-15 genesis order. Every expectation is a concrete output: a case whose expectation is not observable at a command line is not a vector. A reason code with no vector, other than those excepted, fails the coverage check. The excepted codes need a missing verifier, a held lock, a pin file at a rollback, a biometric prompt, a key backend or a display, and a vector input provides none of them: each is proven by the implementation tests listed below.

Rules whose case no vector input can set up are proven by implementation tests, and each test suite of a checker MUST hold one test per item. The harness gives a vector no way to stub vitni, remove it, set an environment variable or choose a signature:
- VR-03: a vitni reason that is not passed through, a listed one (`alg_not_allowed`) and a string vitni never defined, is `verifier_unexpected`; the test injects a verifier that answers it.
- CF-05: a missing vitni binary, a binary or ancestor that is not administrator-owned or is writable by the user, a spawn error, a timeout and a bad output are `verifier_unavailable` from `check-act`, `fold`, `enrolled` and `genesis-check`; an environment variable naming another binary is ignored; the tests inject a path, an owner and a root through the constructor.
- VR-04: `S` equal to (n-1)/2 is low and `S` equal to (n+1)/2 is `high_s`; no signer can produce a valid signature with a chosen `S`, so the test calls the predicate with both values.
- FO-04 item 3: a chain act whose receipt id equals that of an ancestor is ignored as a cycle; no honest bytes produce it (it needs a SHA-256 fixed point), so the test builds the tree with the id function replaced.

The same holds for components other than the checker: a case that no command input can set up is an implementation test of that component, one test per item.
- Production-only behaviour, `test_builds.py` of the checker: the production build refuses an input carrying `pin` or `now` (`malformed_input`), refuses the fixture profile in every command (`fixture_profile`), reads the pin and the clock in process once per call, and gives the answer the conformance build gives for the same data. The ancestor symlink case of the pin probe (GP-10) is in `test_probe_posix.py`, the WSL2 probe (GP-17) in `test_probe_wsl.py`. Whether the administrator path holds the production build only (SG-15), and whether the Windows-side gate runs isolated Python (GP-17 item 2), are installer tests outside the checker.
- GP-21 pin helper, in the library build of GP-21 Tests: rollback refused (`pin_rollback`, file unchanged), a pin on a sibling change included; an invalid lineage (`pin_invalid`); a first pin and an extension written; the path taken from the org of the returned line only, another org's file untouched; an argument, a third input key or a mistyped `lineage` (`malformed_input`); a malformed file at the derived path (`pin_malformed`); a duplicate input key or more than MAX_INPUT bytes (`unparseable_input`, exit 2); an existing `orgs` the reader would reject (`pin_owner`); the lock held (`internal`); the written file accepted by the platform probe, on macOS and on Windows. The cases `genesis-check` alone decides are vectors: `cli/genesis-check-missing-head-acts-invalid`, `cli/genesis-check-extra-acts-same-result`, `cli/genesis-check-forged-middle-link`.
- SG signer, tests of the signer with a software key backend (KC-07), one per item: an unknown command, none or two arguments are `unsupported_command`, and two trailing LF on stdin are `schema_refused`; `keygen` returns a `kid` that is the thumbprint of `sign` with `agree` different, refuses an existing key (`key_exists`) and an equal pair (`internal`); `keygen` and `pubkey` write the `Key <kid12> for <person>, class <class>` line to the display channel and not to stdout; `pubkey` and `version` show no prompt; `render` and `sign` without a key are `key_unavailable`, and so are a key of another class and one invalidated by a biometric change; a cancelled prompt is `user_cancel` and a missing display channel is `no_display`; two `sign` calls in one process show two prompts; a platform signature with high S comes back low; a failed self-verification and a prehash computed twice are `internal`, with no output; `render` of a payload the renderer refuses, or of a 2049-byte request, is `render_refused` with no prompt; the SG-13 checks of a draft against its attachments (the `act` id, `head`, `parent` id and performer, an attachment that is not a chain act, a missing attachment, a resolve without candidates); the success output is `{jws, receipt_id}` and passes `check-act`; on Windows `pin-read` answers `{bytes_b64, owner_ok, reason}` for a fixture file and a fake `handsal-sign.exe` first on PATH is not used.
- SG-12 ceremony, tests of the ceremony: a production policy whose `relay_kid` is the fixture relay key, a fixture kid, a fixture profile and a two-person organization (`policy_unreachable`) are refused before any write; the head line of a change at a forked previous epoch, the removed-key line and the pin's hash12 are shown; a failed `enrolled` after the write fails the ceremony and leaves the pin unchanged; the macOS write is one `/usr/bin/sudo -k` invocation of the helper and a fake `sudo` first on PATH is not used; on Windows a busy `\\.\pipe\handsal-pin` fails the ceremony before the helper starts, with nothing written.
- SG-15 installer, tests of the installation procedure: an artifact whose hash differs from the published value aborts it before the privileged copy, and neither conformance executable is ever copied to an administrator path.
- VR-14 consumer store: an invalid twin is never recorded against the receipt id of the valid act, and a recorded valid act carries its `tip_id_at_ingestion`.

`enrolled:true` can be shown by a vector only under production keys (PRODK, CF-08), because GP-13 step 7 answers `fixture_profile` under the fixture profile. Until a PRODK vector is committed, `enrolled:true` is proven by implementation tests (`Positive` in `test_enrolled.py` of the checker); every vector of `enrolled` shows a `false` result.

Ordering vectors for VR-02: 1/2 `ord/jws-before-canonical`; 2/3 `ord/canonical-before-schema`; 3/4 `ord/schema-before-method`; 4/5 `ord/method-before-act-object`, `ord/chain-method-before-body`; inside 5 `ord/act-object-before-body`; 5/6 `ord/body-before-fold`; inside 6 `ord/probe-org-before-owner`, `ord/owner-before-pin-parse`, `ord/pin-parse-before-pin-org`, `ord/pin-org-before-fold`; 6/7 `ord/fold-before-org`; 7/8 `ord/org-before-relay`; 8/9 `ord/relay-before-signature`; 9/10 `ord/signature-before-high-s`; 10/11 `ord/high-s-before-identity`; 11/12 `ord/identity-before-inputs`; inside 12 `ord/request-before-inputs`; 12/13 `ord/inputs-before-time`; 13/14 `ord/time-before-view`, `wit/ord-time-before-witness`; inside 14 `wit/ord-view-before-witness`; 14/15 `ord/view-before-dup`, `wit/ord-witness-before-duplicate`; 15/16 `ord/dup-before-class`.

Ordering vectors for GP-15: `gen/order-schema-before-lineage`, `gen/order-profile-before-class`, `gen/order-policy-before-device-class`, `gen/order-lineage-before-render`, `gen/order-lineage-before-unsigned`, `gen/order-unsigned-before-head`, `gen/order-unauthorized-before-carry`.

One adjacent pair of GP-15 has no vector: `role_key_class` before `fixture_key` (step 3). `role_key_class` needs a role holder whose class is not `biometric_only` and is not refused earlier in step 3, and registry version 1 has no such class under a production profile (KC-08 vectors use the fixture-only class, and `fixture_key` is not checked under the fixture profile). The order is fixed by GP-15 and no vector checks it until a registry lists such a class.

The same registry limit leaves the acceptance half of clean(k, H) (FO-26) without an only-defect vector for a role holder: the class of a role holder's device must be `biometric_only` (KC-08), registry version 1 has one such class, and every policy that lists a role holder's device lists it (GP-20), so a role holder's key is always accepted. `chg/unaccepted-signer-not-counted` therefore uses a member who holds no role. A role holder case becomes possible when a registry lists a second `biometric_only` class.

- S1: GIVEN the vector set WHEN the coverage check runs THEN every reason code in section 11 that this requirement does not except has an only-defect vector. V: ord/jws-before-canonical, ord/dup-before-class

### CF-08 Production and conformance checker builds

The checker ships as two builds of one pure core:
- **production** `handsal-check`, the only build installed at the administrator path (SG-14): `check-act`, `enrolled` and `fold` call the platform probe in-process at the fixed pin path and read `now` from the system clock. An input carrying `pin` or `now` is `malformed_input`. A lineage under the fixture profile is `fixture_profile`.
- **conformance** `handsal-check-conformance`: the same commands with `pin` and `now` as input data. It implements both profiles and is never installed at an administrator path. Every vector runs against it (CF-04). No vector runs against the production build: it takes no `pin` and no `now`, so a vector input cannot set it up. Production-only behaviour is proven by implementation tests (CF-07).

Production-profile vectors use PRODK: production keys generated once per tag, used to sign the committed production vectors, with their private scalars destroyed afterwards and not listed in `fixture-kids.json`. Their bytes are committed and covered by the bundle hash; they are not regenerated. Continuous integration injects the vitni path through the conformance build's constructor.

Why: a consumer at the administrator path can never be handed a forged probe, a forged clock or a fixture profile, and every rule stays testable under both profiles. The build split enforces this, not a flag.

- S1: GIVEN the production build and an input with `pin`, or with `now`, or a lineage under the fixture profile WHEN run THEN `{"error":"malformed_input"}` for the first two and `fixture_profile` for the third. These are implementation tests of the production build (CF-07), not vectors.
- S2: GIVEN ORG_PRODK under the production profile WHEN folded, and an approve by alice's production key WHEN checked THEN the state, and valid. V: fix/prodk-fold-ok, fix/prodk-check-act-ok

## 10. Signer CLI

One contract, two implementations: Swift on macOS and Rust on Windows, run against the same vectors. On Windows the signer is a native `.exe` called from WSL2 through interop, with stdin and stdout as byte streams, UTF-8 without BOM, LF only and no newline translation; the authentication prompt appears on the Windows desktop. The signer does not fold: it checks bindings between bytes it holds, never chain state.

### SG-01 Command surface

`handsal-sign <command>`: `version`, `keygen`, `pubkey`, `emit`, `render`, `sign`, and `pin-read` (Windows only, GP-11). Each reads at most one JSON object from stdin through the canonical subset recognizer (ACT-04), with MAX_INPUT in place of MAX_PAYLOAD as the bound on the stdin bytes; MAX_PAYLOAD still bounds the signed values inside, and MAX_DEPTH is unchanged. Every recognizer failure, a duplicate key and an oversize input included, is exit 2 `schema_refused`. One trailing LF of stdin is framing, not part of the object; the MAX_INPUT bound counts it. Each command writes exactly one JCS line to stdout: the JCS bytes then one LF. There is no `info`, `key-create`, `key-list`, `build`, `link-code` or `enroll` command. Any other command, no command, or more than one argument is `{"error":"unsupported_command"}`, exit 2 (SG-08). `emit` writes `{payload_hex}`, the lowercase hex of the emitted payload bytes (ACT-05). These commands are the whole surface of the shipped signer; the executable that runs the vectors is `handsal-sign-conformance` (CF-04).

The largest signer input, the `act.endorse` draft of a resolve at the ACT-09 caps with its 34 act attachments, is at most 766,326 bytes, so MAX_INPUT leaves a wide margin.

- S1: GIVEN a draft padded to MAX_INPUT + 1 bytes WHEN read THEN exit 2, `schema_refused`. V: sgn/signer-stdin-over-max-input-refused
- S2: GIVEN a command that is not listed WHEN run THEN exit 2, `unsupported_command` (a signer implementation test, CF-07).

### SG-02 version

`version` returns `{class, impl, spec}`. `class` is the registry id of the key class the build produces (`apple-se-bio` on macOS), `impl` is `handsal-sign-swift` on macOS and `handsal-sign-rust` on Windows, and `spec` is the production profile hash (CF-01): the shipped signer implements the production profile only (GP-18). It reads no stdin, needs no key and shows no prompt.

- S1: GIVEN `version` WHEN run THEN no authentication prompt (a signer implementation test, CF-07).

### SG-03 keygen and pubkey

`keygen` input `{label, person}` creates a non-exportable hardware key of the build's class plus a separate key-agreement key, binds `person` as the performer for every later signature, and returns `{agree:{x,y}, class, kid, sign:{x,y}}`. It refuses if `agree` equals `sign` (exit 5, `internal`) or if a key already exists for this configuration (exit 2, `key_exists`); it never overwrites. The private key never leaves the hardware. `pubkey` returns the same object with no prompt. Both also write `Key <kid12> for <person>, class <class>` to the display channel, never to stdout, as an aid for linking (SG-09).

- S1: GIVEN a successful keygen WHEN the result is read THEN `kid` is the thumbprint of `sign`; a second keygen is `key_exists` (signer implementation tests, CF-07).
- S2: GIVEN keygen or pubkey WHEN run THEN the kid12 line appears on the display channel, and `pubkey` shows no prompt (signer implementation tests, CF-07).

### SG-04 Draft input and caller powers

`sign`, `render` and `emit` take `draft` plus `attachments`. The draft is a closed object `{body, expires_in_s?, head?, method, org, parent?}`, and a verdict draft also carries `recipient`, `relay` and `request_id` (ACT-09 gives them to the act object of a verdict and to no other method). Each of `expires_in_s`, `head`, `parent`, `recipient`, `relay` and `request_id` is present exactly where its method has it and absent elsewhere; a key outside the set, a missing key or a malformed value is `schema_refused`, and a method outside the registry is `unsupported_method`.
- `parent = {id, performer}` is given for chain acts and endorsements and fills `parent_receipt_hash` and `parent_performer_id`.
- `expires_in_s` is a decimal string from "1" to MAX_EXPIRES_IN_S, present iff the method carries `expires` (verdicts, `record.promote`). "0" is refused, and so are a leading zero, a sign, a fraction and a JSON number: `expires` equal to `ts` is `bad_expiry` at every verifier (VR-11), and a signer MUST NOT sign what every verifier refuses. The policy maximum is checked by verifiers.
- `head` is exactly the ACT-08 object `{id, kind:"chain"}`, present exactly where ACT-08 gives the method one (for `genesis.sign`, iff `prev` of the attached document is non-null, SG-13).
- `recipient`, `relay` and `request_id` go into the act object of the verdict. A verdict draft whose `recipient` is not the person bound to the signer's key at keygen is `identity_mismatch`, exit 2, the code VR-05 gives the same fact, and nothing is signed.

The signer fills `performer_id` (bound at keygen), `kid` in the header and in the act object (ACT-14), `ts` from its own clock, `nonce` from 32 random bytes, `expires = ts + expires_in_s`, every pinned constant, and `inputs_hash` and `outputs_hash` from the attachments. A draft carrying `inputs_hash`, `outputs_hash`, `ts`, `nonce`, display text, prompt text or any authentication handle is refused (`schema_refused`). `emit` alone accepts `fixed = {kid, nonce, performer, ts}` and never signs, so caller-chosen values there are harmless; it applies every rule above with `fixed.performer` as the person bound to the key, so it refuses what `sign` would refuse.

Why: the signer is the single owner of nonce and time, and `render` is the single owner of display text. The caller supplies facts, never derived values or words. Identity has one owner, the key (SG-03): a verdict is addressed to one person (ACT-13), so a key answers only requests addressed to its own person, and the signer says so before the prompt instead of signing what VR-05 rejects.

- S1: GIVEN a draft with `ts` WHEN signed THEN exit 2, `schema_refused`. V: sgn/refuse-ts-input, sgn/refuse-nonce-input, sgn/refuse-display-text, sgn/refuse-auth-handle, sgn/refuse-schema-violation, sgn/refuse-unknown-method, sgn/parent-performer-required
- S2: GIVEN `expires_in_s` on a chain method, "0", or above 30 days WHEN signed THEN `schema_refused`. V: sgn/expires-in-s-refused-for-chain-method, sgn/expires-in-s-zero-refused, sgn/expires-over-30d
- S3: GIVEN an `emit` draft WHEN emitted THEN the act object carries the header kid. V: sgn/emit-act-kid-filled
- S4: GIVEN a verdict draft whose `recipient` is not the key's person WHEN signed or emitted THEN exit 2, `identity_mismatch`; GIVEN a verdict draft without `relay`, or a chain draft carrying `recipient`, THEN `schema_refused`. V: sgn/verdict-recipient-not-performer-refused, sgn/verdict-draft-missing-relay-refused, sgn/chain-draft-recipient-refused

### SG-05 Fresh authentication per signature

Every signature MUST require a fresh user verification from the key's class. A signer MUST NOT accept, cache or reuse an authentication context from a caller or from a previous signature; on macOS this means a new `LAContext` per call. Endorsements and resolves each prompt.

- S1: GIVEN two sign calls in one process WHEN run THEN two prompts (a signer implementation test, CF-07).

### SG-06 Signature form

The signature is ES256 over the ASCII bytes `b64url(header).b64url(payload)`. CryptoKit hashes internally; on Windows, CNG `NCryptSignHash` signs a digest, so the signer computes SHA-256 once itself. The signer returns raw 64-byte R||S, normalizes S to the low half, verifies its own signature with the public key before output, and re-runs the recognizer and schema checks on the emitted payload. Output `{jws, receipt_id}`.

- S1: GIVEN a platform signature with high S WHEN returned THEN S is replaced by n minus S; a failed self-verification, or a prehash computed twice, is exit 5, `internal` (signer implementation tests, CF-07).

### SG-07 Display

The signer writes the full render to its own display channel (`/dev/tty` on macOS, `CONOUT$` on Windows), then `Signing as <performer> with <kid12>`, and puts line 1 into the OS prompt (macOS `localizedReason`; on Windows where the API allows it). The render never goes to stdout. With no display channel the signer exits 4. A refused render (`render_refused`, `attachment_missing`, `attachment_mismatch`) exits 2 with no prompt. The render and line 1 are aids (RN-11).

- S1: GIVEN a payload the renderer refuses WHEN signed THEN `render_refused`, no prompt; with no display channel, exit 4, `no_display` (signer implementation tests, CF-07).

### SG-08 Exit codes

Success is exit 0 with the result. Every failure writes `{"error":code}` and exits:
- 1 `user_cancel` (cancelled, or biometric verification failed);
- 2 input rejected: `schema_refused`, `render_refused`, `attachment_missing`, `attachment_mismatch`, `unsupported_method`, `unsupported_command`, `identity_mismatch`, `key_exists` (keygen only);
- 3 `key_unavailable` (missing, invalidated by a biometric set change, or of the wrong class; missing means that no key is bound (`render` or `sign` before `keygen`));
- 4 `no_display`;
- 5 `internal`, including a failed self-verification.

There is no partial output and no signature without a fresh prompt.

- S1: GIVEN the user cancels WHEN run THEN exit 1, `user_cancel`; a key of another class is exit 3, `key_unavailable` (signer implementation tests, CF-07).

### SG-09 Device linking

The linking tool, outside the signer, generates a one-time code of 32 random bytes and shows it as a QR code. `device.add` and `member.add` bind `link_code_hash`, its hashstr. The new key endorses (FO-07). The fold MUST ignore a `device.add` or `member.add` whose `link_code_hash` equals that of an applied primary on the path from the epoch's root to the act's parent (`link_code_reused`, an internal ignore reason). The scope is the past cone (FO-05): a primary on another branch, or below the parent, never makes a code reused. `link_code_hash` is a one-time uniqueness value; it proves nothing about the QR flow.

The person compares the kid12 shown for the new device (SG-03) with line 1 of the `device.add` OS prompt on each signing device. That comparison is an aid. Linking security is FO-22.

- S1: GIVEN two `device.add` acts with the same code hash WHEN folded THEN only the first applies. V: lnk/reused-code, lnk/code-hash-format, lnk/ok

### SG-10 Rate and surprise

The signer SHOULD limit prompt frequency per process and MUST NOT run while another of its prompts is open. An unexpected prompt is a signal, never routine.

### SG-11 Biometric set change

A key invalidated by a change of the enrolled biometrics is exit 3 `key_unavailable`. Recovery is a `device.add` signed from other devices. The ceremony MUST flag persons holding a single device.

- S1: GIVEN a key invalidated by a biometric change WHEN signing THEN exit 3, `key_unavailable` (a signer implementation test, CF-07).

### SG-12 Enrollment ceremony

The ceremony is a procedure, not a signer command. It MUST:
1. collect the document and every listed device's `genesis.sign`;
2. refuse a document whose `profile` is a fixture profile, and any kid listed in `fixture-kids.json` (a device or the `relay_kid`);
3. run `genesis-check` and stop unless it returns `valid:true`;
4. refuse a policy without a spare person (GP-02 `policy_unreachable`) and a role holder's device whose class is not biometric-only (KC-08);
5. show the render (RN-08 for an original, RN-10 for a change), including the witness lines, and flag persons holding a single device (SG-11);
6. for a change, show from the previous epoch's accepted chain in the ceremony's bag one line about H: when the chain ends at tip T, `H is the tip` or `H is not the tip (tip <full T>)`; when it ends at fork parent P, `Previous epoch forked at <full P>;` followed by `H is P`, `H is below candidate <full c>` or `H is not below P`;
7. for a change, show one line `Key removed in the previous epoch: <full kid>` per kid that the document carries, or whose key signed it, and that a valid `device.remove` in the ceremony's bag removes anywhere in the previous epoch;
8. show hash12 of the `genesis` in the exact pin line and ask the person to compare it with line 1 of the `genesis.sign` prompt they saw;
9. hand `{acts, lineage}` to the pin helper through GP-12 and GP-21;
10. run `enrolled`.

The pin write is the ceremony's last write and is never undone. On a failure after the write the ceremony reports the failure and leaves the pin. The lines of steps 6 to 8 are aids against the cases in section 14 (L4, L5), not boundaries. The ceremony SHOULD run in a terminal with no agent session, because its comparisons happen on a shared channel (RN-11).

- S1: GIVEN `enrolled` false after the pin write WHEN the ceremony finishes THEN it fails and the pin file is unchanged (a ceremony implementation test, CF-07).
- S2: GIVEN a fixture kid, a fixture relay kid, a fixture profile, or a two-person organization WHEN the ceremony runs THEN it refuses before any write (ceremony implementation tests, CF-07).
- S3: GIVEN a change at a forked previous epoch, or one carrying a removed key WHEN the ceremony runs THEN it shows the head line and the removed-key line; and it shows the pin's hash12 (ceremony implementation tests, CF-07).

### SG-13 Signer derives and checks attachments

For `genesis.sign` the signer derives `org` from the attached `document`: hashstr(JCS(document)) for an original (`prev` null, GP-03), `document.org` for a change; a draft whose `org` differs is `attachment_mismatch`. For `act.endorse` the signer MUST derive the expected `body.act`, `parent = {id, performer}` and `head.id` from the attached act (RN-09) and refuse a draft whose values differ (exit 2, `attachment_mismatch`); a missing attachment is `attachment_missing`. For `chain.resolve` the candidate and head acts are required attachments, checked per RN-09. For an endorsement of a resolve the signer requires and checks the nested `candidates` and `heads` attachments. Every refusal is exit 2 with no prompt.

Why: the caller supplies the attachment, never a second copy of facts derivable from it.

- S1: GIVEN an endorse draft whose head, parent id or parent performer differs from the attached act WHEN signed THEN exit 2, `attachment_mismatch` (signer implementation tests, CF-07).
- S2: GIVEN an endorse draft without its attachment, or whose attachment is an approve, or a resolve draft without candidate attachments WHEN signed THEN exit 2, `attachment_missing` (`attachment_mismatch` for the approve) (signer implementation tests, CF-07).
- S3: GIVEN a `genesis.sign` draft of an original whose `org` is not the hash of its attached document WHEN signed or emitted THEN exit 2, `attachment_mismatch`. V: sgn/genesis-org-not-document-hash-refused

### SG-14 Helpers by absolute path

Signer, checker, probe and ceremony locate every helper they execute only by an absolute administrator-owned path fixed per platform. There is no PATH lookup and no environment override outside a test constructor.
- macOS: `/Library/Application Support/handsal/bin/vitni-verify`, `/Library/Application Support/handsal/bin/handsal-pin` (the pin helper, a native binary), `/Library/Application Support/handsal/bin/handsal-check` (the launcher of the production checker, CF-08, in the form GP-17 allows), `/Library/Application Support/handsal/lib/handsal-check.pyz` (its zipapp), `/Library/Application Support/handsal/python/bin/python3` (the pinned interpreter, with its notices in `python/licenses/` beside it), and `/usr/bin/sudo`. The launcher runs the interpreter and the zipapp only by those two paths.
- Windows: `C:\Program Files\handsal\` holding `handsal-sign.exe`, `handsal-check` (in the form GP-17 allows: a native binary, or `lib\handsal-check.pyz` run by the interpreter under `python\` with its notices in `python\licenses\`), `vitni-verify.exe` and `handsal-pin.exe` (native).
- WSL2: the Windows binaries through the drvfs path `/mnt/c/Program Files/handsal/...`, never PATH and never `\\wsl$`. On WSL2 this is not a boundary (GP-17).

The ceremony runs the helper, and the helper runs the checker, only by these paths.

Why: an agent that can set environment variables or prepend to PATH cannot substitute the verifier, the pin reader, the pin helper or sudo.

- S1: GIVEN a fake `sudo` first on PATH WHEN the ceremony runs THEN `/usr/bin/sudo` is used (a ceremony implementation test, CF-07).

### SG-15 Binary installation

Files at administrator paths (`vitni-verify`, both pin helpers, the checker launcher `bin/handsal-check`, `lib/handsal-check.pyz`, the interpreter under `python/` with its `python/licenses/`, `handsal-sign.exe`) are installed only by a person-run procedure that, before the privileged copy, computes the SHA-256 of each artifact (the interpreter as the one pinned archive) and compares it with the value published for the tag, read on a second device. Any mismatch aborts. Artifacts built in a user-writable tree are never copied to an administrator path, and neither conformance executable (`handsal-check-conformance`, `handsal-sign-conformance`) is ever installed.

Why: an administrator path is only as trustworthy as the bytes copied into it.

- S1: GIVEN an artifact whose hash differs from the published value WHEN installing THEN the procedure aborts before the privileged copy (an installer test, CF-07).

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
| `request_mismatch`, `inputs_mismatch`, `outputs_mismatch` | step 12 (VR-02, VR-06, VR-07) |
| `ts_in_future`, `bad_expiry`, `validity_too_long`, `expired` | step 13 (VR-11) |
| `view_in_future`, `stale_view` | step 14 (VR-12), `enrolled` step 6 |
| `witness_unexpected`, `witness_missing`, `witness_malformed`, `witness_key_mismatch`, `witness_bad_signature`, `witness_org_mismatch`, `witness_epoch_mismatch`, `witness_superseded`, `witness_in_future`, `stale_witness`, `behind_witness` | step 14 (WT-04, WT-05, WT-10), `enrolled` step 6 |
| `duplicate_receipt` | step 15 (VR-09, VR-15) |
| `unproven_class` | step 16 (KC-04) |
| `ok` | success of `check-act`, `enrolled`, `genesis-check`, `subset` and the pin helper |
| `local_key_unknown`, `local_key_not_active`, `local_class_not_accepted` | `enrolled` step 5 (GP-13) |
| `attachment_missing`, `attachment_mismatch`, `render_refused` | `render`, signer exit 2 (RN-02, RN-05, RN-09, RN-12) |
| `pin_invalid`, `pin_rollback`, `internal` | pin helper (GP-21) |
| `user_cancel` (1), `schema_refused`, `unsupported_method`, `unsupported_command`, `identity_mismatch`, `key_exists` (2), `key_unavailable` (3), `no_display` (4), `internal` (5) | signer exit codes (SG-08) |

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
| `chk`, `ord`, `vtn`, `sig`, `idn`, `inp`, `rly`, `rep`, `tim`, `frs`, `ing` | VR |
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
- S2: GIVEN a relay policy whose `relay_pub_jwk` equals alice's `sign` key WHEN folded THEN `policy_invalid`. V: wit/pol-relay-key-is-device-key, wit/pol-relay-key-is-agree-key, wit/device-add-relay-key-ignored
- S3: GIVEN `max_tip_age_s` `"59"` or `"86401"` THEN `policy_out_of_bounds`; GIVEN `"60"` or `"86400"` THEN the state. V: wit/pol-tip-age-59, wit/pol-tip-age-86401, wit/pol-tip-age-bounds-ok, wit/pol-tip-age-upper-bound-ok
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
- S3: GIVEN `now - ts == max_tip_age_s` THEN valid; one second more THEN `stale_witness`; GIVEN `ts == now + clock_skew_s + 1` THEN `witness_in_future`. V: wit/tip-age-exactly-max-ok, wit/stale-tip, wit/future-within-skew-ok, wit/future-tip
- S4: GIVEN a statement signed by bob's key with the relay kid in its header WHEN checked THEN `witness_bad_signature`. V: wit/wrong-key-signature, wit/wrong-key-kid, wit/statement-high-s
- S5: GIVEN a statement for another org, or for an epoch the consumer has not pinned WHEN checked THEN `witness_org_mismatch`, `witness_epoch_mismatch`. V: wit/wrong-org, wit/wrong-epoch-newer
- S6: GIVEN two witness defects WHEN checked THEN the earlier step's code. V: wit/ord-key-before-signature, wit/ord-signature-before-content, wit/ord-stale-before-behind, wit/ord-view-before-witness, wit/ord-time-before-witness, wit/ord-witness-before-duplicate
- S7: GIVEN WIT_ORG and TIP_OK WHEN `enrolled` runs THEN false, `fixture_profile` (steps 1 to 6 passed). V: wit/enr-relay-ok

### WT-06 Freshness, never validity

A tip statement can only add a refusal. No rule reads a statement to accept an act, to extend or choose the chain, to supply a key, to lift a fork, or to override any other step: VR-02 steps 1 to 13 and the fold run identically with and without it. A relay tip the consumer lacks is `behind_witness`, never a reason to adopt the relay's chain. Statements inside `acts` are ignored by the fold.

Why: a compromised relay key yields at most forged freshness, the same exposure as mode `none`, never a forged human act.

- S1: GIVEN TIP_OK valid and an approve signed by a key removed at T3 WHEN checked THEN `revoked_key`. V: wit/never-validates-revoked, wit/never-validates-bad-sig, wit/never-validates-unproven
- S2: GIVEN the witness bag plus TIP_OK in `acts` WHEN folded THEN the output equals the output without it. V: wit/statement-in-bag-ignored

### WT-07 Fail closed, no fallback

In mode `relay` every WT-05 failure is a refusal. No code path evaluates mode `relay` with VR-12 alone. VR-12 still runs in mode `relay`: `synced_at` alone never suffices, and the witness never replaces the `head` rule. An unknown or missing mode is a fold error (WT-01), never read as `none`.

Why conjunctive: removing a check per mode would create a mode-dependent hole and a second rule set. Keeping VR-12 makes mode `relay` a strict superset of mode `none`, so turning the witness on can never weaken a consumer. The cost is that a consumer in mode `relay` still supplies a fresh `synced_at`.

- S1: GIVEN WIT_ORG, `tip_statement` null and a fresh `synced_at` WHEN checked THEN `witness_missing`. V: wit/mode-relay-no-statement, wit/synced-at-still-checked

### WT-08 Changing the witness is a policy change

The `witness` value changes only through a genesis change (GP-19): a new document, authority by the previous policy's `rules["genesis.change"]` counting only keys clean at H, proof of possession by every listed device, and a re-pin (GP-12). This covers `none` to `relay`, `relay` to `none`, relay key rotation and any `max_tip_age_s` change. Until the re-pin, the old mode applies on that machine. No act, no flag and no consumer configuration switches the mode. Turning the witness on is a re-pin of one org, not a new profile hash.

The genesis render (RN-04) shows the witness as policy lines: `Witness: none`, or `Witness: relay`, `Relay key: <full kid>`, `Max tip age: <D> s`, so every signer of a change sees a relay key rotation or a downgrade.

Why: a downgrade to `none` needs the same quorum and clean keys as any other authority change; a removed key cannot help install or remove a witness.

- S1: GIVEN ORG (mode `none`) and a change to a relay policy signed by alice and bob at the epoch-0 tip WHEN folded with the new pin THEN the new epoch state has `witness.mode` `relay`. V: wit/change-none-to-relay-quorum, wit/change-relay-key-rotation-ok
- S2: GIVEN a none-to-relay or relay-to-none change signed by alice only, or by alice whose key was removed on the path to H WHEN folded THEN `genesis_change_unauthorized`. V: wit/change-none-to-relay-one-signer, wit/change-relay-to-none-one-signer, wit/change-none-to-relay-revoked-signer
- S3: GIVEN a signed none-to-relay change that is not yet pinned WHEN checked with `tip_statement` null THEN valid; GIVEN the pin at the change THEN `witness_missing`. V: wit/change-before-repin-old-mode, wit/change-after-repin-needs-statement
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
- **L9. Verdicts are one touch, and consumer storage is editable.** Verdicts and record promotions stay single-touch: one decision per touch. `seen` and ingestion records live in consumer storage an agent may edit (VR-09, VR-14).
- **L10. Freshness gaps.** In mode `none`, an actor controlling the act file and the consumer's sync timestamp can withhold a removal from that machine indefinitely (exploiting it also needs a compromised key); `synced_at` proves only that the consumer looked recently. Turn the witness on by a genesis change before a member who is not a maintainer joins, or before a second org exists. In mode `relay` the gap narrows to collusion between relay and agent, or a removal that never reached the relay; for an honest relay a withheld removal is visible after at most `max_tip_age_s`. A compromised relay key yields forged freshness only (WT-06); the recovery is a key rotation by genesis change (WT-08). Every valid successor of an epoch makes the relay set `next` to `"yes"`, so consumers in mode `relay` refuse every non-chain act of that epoch until a person re-pins; this includes backdated changes (L4) and changes from a rival branch (L1). That costs availability only: the pin moves only by a person (GP-12, GP-21). A consumer that already holds a successor in its bag accepts statements issued before the successor until their `max_tip_age_s` expires.
- **L11. The clock.** `now` is the verifier's clock. An agent that controls the clock defeats expiry and freshness. That requires administrator rights on the machine; the profile cannot detect it.
- **L12. Unreachable rules.** Every rule has one spare person (GP-02), so one person losing every device never makes a rule unreachable. Two persons doing so with Q = 2 of 3 does, and the exit is a new organization (FO-27). Recovery is out of scope.
- **L13. The pin's threat scope.** The pin defends against an agent writing files as the person's user. It does not defend against an agent that changes verifier code or its runtime: consumer repositories owned by the user on macOS, and on WSL2 distribution root and `/mnt/c` remounts. A WSL2 consumer receives the Windows-side gate's answer through a path WSL2 root can redirect (GP-17).
- **L14. Installation relies on a person.** SG-15 relies on the person comparing hashes on a second device.
- **L15. Capacity.** MAX_INPUT (16 MiB) bounds the checker's and the pin helper's input. Signer inputs need under 0.8 MB at the caps, but `fold` and `genesis-check` inputs grow with the bag: past about 761 acts of the largest size, or over 7,000 typical chain acts of about 2 KB, an organization can no longer fold or re-pin with these binaries.
- **L16. Windows.** Until the Windows Hello evaluation reports, `win-hello-hw` cannot be listed (KC-02, KC-08). If it reports `biometric_or_pin`, a Windows user cannot be a role holder through that class. Where the Windows prompt cannot carry line 1, that class shows no signer text in the OS prompt (RN-11).

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
