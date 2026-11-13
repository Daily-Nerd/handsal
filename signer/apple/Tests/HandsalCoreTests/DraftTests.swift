import Foundation
import HandsalCore
import Testing

private func hs(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
private let otherKid = "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"
private let ts = "2026-11-08T11:59:00Z"
private let fixed = Fixed(kid: kid, nonce: hs("nonce"), performer: "alice", ts: ts)

private func str(_ s: String) -> JValue { .string(s) }

private func removeDraft() -> [String: JValue] {
    ["body": .object(["kid": str(otherKid), "person": str("carol")]), "method": str("local:handsal.device.remove"),
     "org": str(hs("org")), "parent": .object(["id": str(hs("p")), "performer": str("bob")])]
}

private func promoteDraft() -> [String: JValue] {
    ["body": .object(["anchors": .array([str("a-1")]), "record_id": str("rec-0001")]),
     "expires_in_s": str("3600"), "head": .object(["id": str(hs("h")), "kind": str("chain")]),
     "method": str("local:handsal.record.promote"), "org": str(hs("org"))]
}

private func endorseDraft() -> [String: JValue] {
    ["body": .object(["act": str(hs("a"))]), "head": .object(["id": str(hs("h")), "kind": str("chain")]),
     "method": str("local:handsal.act.endorse"), "org": str(hs("org")),
     "parent": .object(["id": str(hs("a")), "performer": str("bob")])]
}

private func approveDraft() -> [String: JValue] {
    ["body": .object([:]), "expires_in_s": str("3600"), "head": .object(["id": str(hs("h")), "kind": str("chain")]),
     "method": str("local:handsal.request.approve"), "org": str(hs("org")),
     "recipient": str("alice"), "relay": str("r.example"), "request_id": str("req-00000001")]
}

private func refused(_ code: String = "schema_refused", _ body: () throws -> Void) {
    #expect(throws: Refusal(code)) { try body() }
}

@Suite("draft validation (SG-04)")
struct DraftReadTests {
    @Test func readsAValidDraft() throws {
        let draft = try Draft.read(.object(removeDraft()))
        #expect(draft.method == "local:handsal.device.remove")
        #expect(draft.parent == DraftParent(id: hs("p"), performer: "bob"))
        #expect(draft.expiresInS == nil)
        #expect(draft.head == nil)
        let promote = try Draft.read(.object(promoteDraft()))
        #expect(promote.expiresInS == 3600)
    }

    @Test(arguments: ["ts", "nonce", "inputs_hash", "outputs_hash", "display", "prompt", "text", "auth", "auth_handle",
                      "performer_id", "kid", "extra"])
    func refusesAnyKeyTheCallerMayNotSupply(key: String) {
        var draft = removeDraft()
        draft[key] = str("x")
        refused { _ = try Draft.read(.object(draft)) }
    }

    @Test func requiresTheClosedKeySet() {
        for key in ["body", "method", "org"] {
            var draft = removeDraft(); draft[key] = nil
            refused { _ = try Draft.read(.object(draft)) }
        }
        refused { _ = try Draft.read(.string("x")) }
        refused { _ = try Draft.read(.array([])) }
    }

    @Test func orgMustBeAHashstr() {
        var draft = removeDraft(); draft["org"] = str("uEi")
        refused { _ = try Draft.read(.object(draft)) }
    }

    @Test func unknownMethodIsUnsupported() {
        var draft = removeDraft(); draft["method"] = str("local:handsal.request.send")
        refused("unsupported_method") { _ = try Draft.read(.object(draft)) }
        draft["method"] = str("LOCAL:handsal.device.remove")
        refused("unsupported_method") { _ = try Draft.read(.object(draft)) }
    }

    @Test func expiresInSPresentIffTheMethodCarriesExpires() throws {
        var chain = removeDraft(); chain["expires_in_s"] = str("60")
        refused { _ = try Draft.read(.object(chain)) }
        var promote = promoteDraft(); promote["expires_in_s"] = nil
        refused { _ = try Draft.read(.object(promote)) }
        for bad in [str("2592001"), str("01"), str("-1"), str(""), str("1.5"), .number("60"), .null] {
            promote["expires_in_s"] = bad
            refused { _ = try Draft.read(.object(promote)) }
        }
        promote["expires_in_s"] = str("2592000")
        #expect(try Draft.read(.object(promote)).expiresInS == 2_592_000)
    }

    @Test func headRules() throws {
        var endorse = endorseDraft(); endorse["head"] = nil
        refused { _ = try Draft.read(.object(endorse)) }
        var add = removeDraft(); add["head"] = .object(["id": str(hs("h")), "kind": str("chain")])
        refused { _ = try Draft.read(.object(add)) }
        for bad in [JValue.object(["id": str(hs("h")), "kind": str("merkle")]),
                    .object(["id": str(hs("h")), "kind": str("chain"), "n": str("1")]),
                    .object(["id": str("x"), "kind": str("chain")]), .null] {
            var promote = promoteDraft(); promote["head"] = bad
            refused { _ = try Draft.read(.object(promote)) }
        }
        // genesis.sign: the head is due only for a change, which needs the document: the builder decides.
        var genesis = ["body": JValue.object([:]), "method": str("local:handsal.genesis.sign"), "org": str(hs("org"))]
        #expect(try Draft.read(.object(genesis)).head == nil)
        genesis["head"] = .object(["id": str(hs("h")), "kind": str("chain")])
        #expect(try Draft.read(.object(genesis)).head != nil)
    }

    @Test func parentRules() throws {
        var add = removeDraft(); add["parent"] = nil
        refused { _ = try Draft.read(.object(add)) }
        var promote = promoteDraft(); promote["parent"] = .object(["id": str(hs("p")), "performer": .null])
        refused { _ = try Draft.read(.object(promote)) }
        var root = removeDraft(); root["parent"] = .object(["id": str(hs("p")), "performer": .null])
        #expect(try Draft.read(.object(root)).parent == DraftParent(id: hs("p"), performer: nil))
        var endorse = endorseDraft(); endorse["parent"] = .object(["id": str(hs("a")), "performer": .null])
        refused { _ = try Draft.read(.object(endorse)) }
        for bad in [JValue.object(["id": str(hs("p"))]), .object(["id": str("x"), "performer": .null]),
                    .object(["id": str(hs("p")), "performer": str("A")]),
                    .object(["id": str(hs("p")), "performer": .null, "extra": .null]), .string("p")] {
            var draft = removeDraft(); draft["parent"] = bad
            refused { _ = try Draft.read(.object(draft)) }
        }
    }

    @Test func bodyIsValidatedAgainstTheMethodSchema() {
        var extra = removeDraft(); extra["body"] = .object(["kid": str(otherKid), "person": str("carol"), "x": .null])
        refused { _ = try Draft.read(.object(extra)) }
        var form = removeDraft(); form["body"] = .object(["kid": str("short"), "person": str("carol")])
        refused { _ = try Draft.read(.object(form)) }
    }

    @Test(arguments: ["local:handsal.request.approve", "local:handsal.request.reject", "local:handsal.request.needs-info"])
    func verdictDraftsCarryRecipientRelayAndRequestId(method: String) throws {
        var draft = approveDraft(); draft["method"] = str(method)
        let read = try Draft.read(.object(draft))
        #expect(read.verdict == VerdictFields(recipient: "alice", relay: "r.example", requestId: "req-00000001"))
        #expect(read.expiresInS == 3600 && read.parent == nil)
    }

    @Test(arguments: ["recipient", "relay", "request_id"])
    func aVerdictDraftNeedsEachOfTheThree(key: String) {
        var draft = approveDraft(); draft[key] = nil
        refused { _ = try Draft.read(.object(draft)) }
    }

    @Test func theThreeFollowTheirForms() throws {
        for (key, bad) in [("recipient", "Alice"), ("recipient", "a"), ("relay", "Bad Host"), ("relay", ""),
                           ("request_id", "short"), ("request_id", "REQ-00000001")] {
            var draft = approveDraft(); draft[key] = str(bad)
            refused { _ = try Draft.read(.object(draft)) }
        }
        for bad in [JValue.null, .number("1"), .array([])] {
            var draft = approveDraft(); draft["relay"] = bad
            refused { _ = try Draft.read(.object(draft)) }
        }
        var other = approveDraft(); other["recipient"] = str("bob"); other["relay"] = str("relay-2.example.org")
        #expect(try Draft.read(.object(other)).verdict == VerdictFields(recipient: "bob", relay: "relay-2.example.org", requestId: "req-00000001"))
    }

    @Test(arguments: ["recipient", "relay", "request_id"])
    func noMethodButAVerdictTakesThem(key: String) throws {
        for base in [removeDraft(), promoteDraft(), endorseDraft()] {
            var draft = base; draft[key] = str("alice")
            refused { _ = try Draft.read(.object(draft)) }
        }
        #expect(try Draft.read(.object(removeDraft())).verdict == nil)
    }

    @Test func expiresInSIsOneToMaxAndZeroIsRefused() throws {
        var promote = promoteDraft()
        promote["expires_in_s"] = str("0")
        refused { _ = try Draft.read(.object(promote)) }
        var approve = approveDraft()
        approve["expires_in_s"] = str("0")
        refused { _ = try Draft.read(.object(approve)) }
        promote["expires_in_s"] = str("1")
        #expect(try Draft.read(.object(promote)).expiresInS == 1)
        approve["expires_in_s"] = str("2592000")
        #expect(try Draft.read(.object(approve)).expiresInS == 2_592_000)
        approve["expires_in_s"] = str("2592001")
        refused { _ = try Draft.read(.object(approve)) }
    }

    @Test func headIsExactlyTheActEightObject() {
        // ACT-08: `{id, kind:"chain"}` and nothing else, present exactly where the method has one.
        for bad in [JValue.object(["id": str(hs("h"))]), .object(["kind": str("chain")]),
                    .object(["id": str(hs("h")), "kind": str("chain"), "n": str("1")]), .object(["id": str(hs("h")), "kind": str("Chain")])] {
            var approve = approveDraft(); approve["head"] = bad
            refused { _ = try Draft.read(.object(approve)) }
        }
        var approve = approveDraft(); approve["head"] = nil
        refused { _ = try Draft.read(.object(approve)) }
        var remove = removeDraft(); remove["head"] = .object(["id": str(hs("h")), "kind": str("chain")])
        refused { _ = try Draft.read(.object(remove)) }
    }
}

@Suite("payload build (SG-04 caller powers)")
struct PayloadBuildTests {
    private func build(_ draft: [String: JValue], _ attachments: JValue = .object([:]), as who: Fixed = fixed) throws -> [String: JValue] {
        guard case .object(let payload) = try PayloadBuilder.build(draft: Draft.read(.object(draft)), attachments: attachments, fixed: who) else {
            Issue.record("payload is not an object"); return [:]
        }
        return payload
    }

    @Test func fillsEveryPinnedConstantAndTheSignersFields() throws {
        let payload = try build(removeDraft())
        #expect(payload["v"] == str("vitni/0.2") && payload["binding"] == str("local") && payload["status"] == str("OK"))
        #expect(payload["log_policy"] == str("best_effort") && payload["reason"] == .null)
        #expect(payload["action_ref"] == .null && payload["requester_id"] == .null)
        #expect(payload["cost"] == .object(["rail_ref": .null, "tokens": str("0"), "usd_micros": str("0"), "wall_ms": str("0")]))
        #expect(payload["performer_id"] == str("alice") && payload["ts"] == str(ts) && payload["nonce"] == str(hs("nonce")))
        #expect(payload["parent_receipt_hash"] == str(hs("p")) && payload["parent_performer_id"] == str("bob"))
        #expect(payload["inputs_hash"] == str(Encoding.emptyHash) && payload["outputs_hash"] == str(Encoding.emptyHash))
        guard case .object(let ext)? = payload["ext"], case .object(let act)? = ext["dev.handsal/act"] else {
            Issue.record("no act object"); return
        }
        #expect(act["kid"] == str(kid) && act["org"] == str(hs("org")))
        #expect(Set(act.keys) == ["body", "kid", "org"])
        #expect(Set(payload.keys).count == 17)
    }

    @Test func parentFieldsAreNullWhereTheMethodHasNone() throws {
        let payload = try build(promoteDraft(), .object(["record_body_b64": str("YQ==")]))
        #expect(payload["parent_receipt_hash"] == .null && payload["parent_performer_id"] == .null)
    }

    @Test func expiresIsTsPlusExpiresInS() throws {
        let payload = try build(promoteDraft(), .object(["record_body_b64": str("YQ==")]))
        guard case .object(let ext)? = payload["ext"], case .object(let act)? = ext["dev.handsal/act"] else { return }
        #expect(act["expires"] == str("2026-11-08T12:59:00Z"))
        #expect(payload["inputs_hash"] == str(Encoding.hashstr([0x61])))
    }

    @Test func hashesComeFromTheAttachmentsOnly() throws {
        let doc = JValue.object(["prev": .null])
        let docHash = Encoding.hashstr(Array(#"{"prev":null}"#.utf8))
        let genesis: [String: JValue] = ["body": .object([:]), "method": str("local:handsal.genesis.sign"), "org": str(docHash)]
        let payload = try build(genesis, .object(["document": doc]))
        #expect(payload["inputs_hash"] == str(docHash))
        refused("attachment_missing") { _ = try build(genesis) }
        refused("attachment_missing") { _ = try build(promoteDraft()) }
        refused { _ = try build(promoteDraft(), .object(["record_body_b64": str("YQ")])) }
        refused { _ = try build(promoteDraft(), .object(["record_body_b64": .null])) }
    }

    @Test func genesisHeadIsDueExactlyForAChange() throws {
        let original = JValue.object(["prev": .null])
        let originalOrg = Encoding.hashstr(Array(#"{"prev":null}"#.utf8))
        let change = JValue.object(["org": str(hs("org")), "prev": str(hs("p"))])
        var draft: [String: JValue] = ["body": .object([:]), "method": str("local:handsal.genesis.sign"), "org": str(originalOrg)]
        _ = try build(draft, .object(["document": original]))
        draft["org"] = str(hs("org"))
        refused { _ = try build(draft, .object(["document": change])) }
        draft["org"] = str(originalOrg)
        draft["head"] = .object(["id": str(hs("h")), "kind": str("chain")])
        refused { _ = try build(draft, .object(["document": original])) }
        draft["org"] = str(hs("org"))
        _ = try build(draft, .object(["document": change]))
    }

    /// SG-13: the signer derives `org` from the attached document and refuses a draft that differs.
    @Test func genesisOrgIsDerivedFromTheAttachedDocument() throws {
        let original = JValue.object(["prev": .null])
        let originalOrg = Encoding.hashstr(Array(#"{"prev":null}"#.utf8))
        var draft: [String: JValue] = ["body": .object([:]), "method": str("local:handsal.genesis.sign"), "org": str(originalOrg)]
        var payload = try build(draft, .object(["document": original]))
        guard case .object(let ext)? = payload["ext"], case .object(let act)? = ext["dev.handsal/act"] else { Issue.record("no act"); return }
        #expect(act["org"] == str(originalOrg))
        // an original: org is the hash of the document, any other hashstr is a mismatch
        draft["org"] = str(hs("org"))
        refused("attachment_mismatch") { _ = try build(draft, .object(["document": original])) }
        // a change: org is `document.org`
        let change = JValue.object(["org": str(hs("org")), "prev": str(hs("p"))])
        draft["head"] = .object(["id": str(hs("h")), "kind": str("chain")])
        payload = try build(draft, .object(["document": change]))
        #expect(payload["inputs_hash"] != nil)
        draft["org"] = str(hs("other-org"))
        refused("attachment_mismatch") { _ = try build(draft, .object(["document": change])) }
    }

    @Test func verdictFieldsGoIntoTheActObject() throws {
        let request = Array("deploy v2".utf8)
        let payload = try build(approveDraft(), .object(["request_b64": str("ZGVwbG95IHYy")]))
        guard case .object(let ext)? = payload["ext"], case .object(let act)? = ext["dev.handsal/act"] else { Issue.record("no act"); return }
        #expect(act["recipient"] == str("alice") && act["relay"] == str("r.example") && act["request_id"] == str("req-00000001"))
        #expect(Set(act.keys) == ["body", "expires", "head", "kid", "org", "recipient", "relay", "request_id"])
        #expect(payload["inputs_hash"] == str(Encoding.hashstr(request)))
        #expect(payload["parent_receipt_hash"] == .null && payload["performer_id"] == str("alice"))
        var other = approveDraft(); other["recipient"] = str("alice"); other["relay"] = str("other.example"); other["request_id"] = str("req-00000002")
        guard case .object(let ext2)? = try build(other, .object(["request_b64": str("ZGVwbG95IHYy")]))["ext"],
              case .object(let act2)? = ext2["dev.handsal/act"] else { return }
        #expect(act2["relay"] == str("other.example") && act2["request_id"] == str("req-00000002"))
    }

    /// SG-04: a key answers only requests addressed to its own person (the code VR-05 gives the fact).
    @Test func aVerdictForAnotherPersonIsIdentityMismatch() throws {
        var draft = approveDraft(); draft["recipient"] = str("bob")
        refused("identity_mismatch") { _ = try build(draft, .object(["request_b64": str("ZGVwbG95IHYy")])) }
        let asBob = Fixed(kid: kid, nonce: hs("nonce"), performer: "bob", ts: ts)
        _ = try build(draft, .object(["request_b64": str("ZGVwbG95IHYy")]), as: asBob)
        refused("identity_mismatch") { _ = try build(approveDraft(), .object(["request_b64": str("ZGVwbG95IHYy")]), as: asBob) }
    }

    @Test func fixedValuesAreChecked() {
        refused { _ = try build(removeDraft(), as: Fixed(kid: "short", nonce: hs("n"), performer: "alice", ts: ts)) }
        refused { _ = try build(removeDraft(), as: Fixed(kid: kid, nonce: "x", performer: "alice", ts: ts)) }
        refused { _ = try build(removeDraft(), as: Fixed(kid: kid, nonce: hs("n"), performer: "A", ts: ts)) }
        refused { _ = try build(removeDraft(), as: Fixed(kid: kid, nonce: hs("n"), performer: "alice", ts: "now")) }
    }

    @Test func freshNonceIsAHashstrOf32RandomBytes() {
        let a = PayloadBuilder.freshNonce(), b = PayloadBuilder.freshNonce()
        #expect(Encoding.isHashstr(a) && Encoding.isHashstr(b) && a != b)
    }

    /// The vectors are the oracle: take each renderable payload, derive the draft a caller would
    /// send, and the builder must reproduce the very bytes of that payload.
    @Test("builder reproduces vector payloads", arguments: try Vector.load(commands: ["render"]).filter { $0.anchor.hasPrefix(#"{"first_line""#) })
    func reproducesVectorPayloads(row: Vector) throws {
        guard case .json(.object(let input)) = row.input, case .object(let payload)? = input["payload"],
              case .object(let ext)? = payload["ext"], case .object(let act)? = ext["dev.handsal/act"],
              case .string(let method)? = payload["method"], case .string(let ts)? = payload["ts"] else {
            Issue.record("unexpected vector shape"); return
        }
        var draft: [String: JValue] = ["body": act["body"] ?? .null, "method": .string(method), "org": act["org"] ?? .null]
        if let head = act["head"] { draft["head"] = head }
        for key in ["recipient", "relay", "request_id"] { if let value = act[key] { draft[key] = value } }
        if case .string(let parent)? = payload["parent_receipt_hash"] {
            draft["parent"] = .object(["id": .string(parent), "performer": payload["parent_performer_id"] ?? .null])
        }
        if case .string(let expires)? = act["expires"], let e = Forms.epochSeconds(expires), let t = Forms.epochSeconds(ts) {
            draft["expires_in_s"] = .string(String(e - t))
        }
        guard case .string(let performer)? = payload["performer_id"], case .string(let nonce)? = payload["nonce"],
              case .string(let actKid)? = act["kid"] else { return }
        let built = try PayloadBuilder.build(draft: Draft.read(.object(draft)), attachments: input["attachments"] ?? .object([:]),
                                             fixed: Fixed(kid: actKid, nonce: nonce, performer: performer, ts: ts))
        #expect(try Emit.subset(built) == Emit.subset(.object(payload)))
    }
}

@Suite("emit command (SG-01, SG-04)")
struct EmitCommandTests {
    @Test func returnsThePayloadBytesAsHexAndNeverSigns() throws {
        let input = JValue.object(["attachments": .object([:]), "draft": .object(removeDraft()),
                                   "fixed": .object(["kid": str(kid), "nonce": str(hs("nonce")), "performer": str("alice"), "ts": str(ts)])])
        let result = try SignerCommands.emit(input)
        guard case .object(let out) = result, case .string(let hex)? = out["payload_hex"], out.count == 1 else {
            Issue.record("unexpected result \(result)"); return
        }
        let expected = try Emit.subset(PayloadBuilder.build(draft: Draft.read(.object(removeDraft())), attachments: .object([:]),
                                                            fixed: Fixed(kid: kid, nonce: hs("nonce"), performer: "alice", ts: ts)))
        #expect(hex == expected.map { String(format: "%02x", $0) }.joined())
    }

    @Test func fixedIsClosedAndComplete() {
        let base: [String: JValue] = ["kid": str(kid), "nonce": str(hs("nonce")), "performer": str("alice"), "ts": str(ts)]
        func run(_ fixed: JValue) { refused { _ = try SignerCommands.emit(.object(["attachments": .object([:]), "draft": .object(removeDraft()), "fixed": fixed])) } }
        for key in base.keys { var f = base; f[key] = nil; run(.object(f)) }
        var extra = base; extra["x"] = .null; run(.object(extra))
        run(.null)
        refused { _ = try SignerCommands.emit(.object(["attachments": .object([:]), "draft": .object(removeDraft())])) }
        refused { _ = try SignerCommands.emit(.object(["draft": .object(removeDraft()), "fixed": .object(base), "extra": .null])) }
    }
}

/// RN-09 / ACT-09: `inputs_hash` and `outputs_hash` come from a named rule of the registry. A rule
/// the builder does not know must fail loudly; it must never fall through to the empty hash.
@Suite("hash rules of the builder (ACT-09, RN-09)")
struct HashRuleTests {
    private let request = JValue.object(["request_b64": str("ZGVwbG95IHYy")])   // "deploy v2"

    private func verdict() throws -> Draft { try Draft.read(.object(approveDraft())) }

    @Test func aVerdictsInputsHashCoversTheRequestBytes() throws {
        let got = try PayloadBuilder.derive(inputsKind: "raw_request_bytes", outputsKind: "verdict:approve", draft: verdict(), files: ["request_b64": str("ZGVwbG95IHYy")])
        #expect(got.inputs == Encoding.hashstr(Array("deploy v2".utf8)) && got.inputs != Encoding.emptyHash)
        #expect(got.outputs == Encoding.hashstr(Array(#"{"request_id":"req-00000001","verdict":"approve"}"#.utf8)))
        let other = try PayloadBuilder.derive(inputsKind: "raw_request_bytes", outputsKind: "verdict:reject", draft: verdict(), files: ["request_b64": str("YQ==")])
        #expect(other.inputs == Encoding.hashstr([0x61]) && other.outputs != got.outputs)
    }

    @Test func emptyIsNamedNotAssumed() throws {
        let got = try PayloadBuilder.derive(inputsKind: "empty", outputsKind: "empty", draft: Draft.read(.object(removeDraft())), files: [:])
        #expect(got.inputs == Encoding.emptyHash && got.outputs == Encoding.emptyHash)
    }

    @Test(arguments: ["raw_request_body", "", "EMPTY", "jcs_document"])
    func anUnknownInputsRuleFailsLoudly(kind: String) throws {
        #expect(throws: Refusal("internal")) {
            _ = try PayloadBuilder.derive(inputsKind: kind, outputsKind: "empty", draft: try Draft.read(.object(removeDraft())), files: [:])
        }
    }

    @Test(arguments: ["verdict", "verdict:", "verdict:send", "hash_of_nothing", ""])
    func anUnknownOutputsRuleFailsLoudly(kind: String) throws {
        #expect(throws: Refusal("internal")) {
            _ = try PayloadBuilder.derive(inputsKind: "empty", outputsKind: kind, draft: try verdict(), files: [:])
        }
    }

    @Test func aVerdictRuleOnADraftWithoutVerdictFieldsFailsLoudly() throws {
        #expect(throws: Refusal("internal")) {
            _ = try PayloadBuilder.derive(inputsKind: "empty", outputsKind: "verdict:approve", draft: try Draft.read(.object(removeDraft())), files: [:])
        }
    }

    @Test func everyRegistryMethodUsesAKnownRule() throws {
        for (name, spec) in Registry.standard.methods {
            let known: Set = ["empty", "raw_request_bytes", "raw_record_body_bytes", "jcs_genesis_document"]
            #expect(known.contains(spec.inputsHash), "\(name) inputs \(spec.inputsHash)")
            #expect(spec.outputsHash == "empty" || ["approve", "reject", "needs-info"].contains(spec.outputsHash.dropFirst(8)), "\(name) outputs \(spec.outputsHash)")
        }
    }
}
