import Foundation
import HandsalCore
import Testing

/// The decision act (VR-18) in the signer: the three forms of its body, the draft that carries them, the
/// two hashes derived from the attached content and the words, and the render a person confirms.
private func hs(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
private let method = "local:handsal.decision"
private let content = Array("Ruling 0001: keep the retry limit at three.\n".utf8)
private let fixed = Fixed(kid: kid, nonce: hs("nonce"), performer: "alice", ts: "2026-11-08T11:59:00Z")
private let action24 = "ratify ruling and record"

private func str(_ s: String) -> JValue { .string(s) }

private func b64(_ raw: [UInt8]) -> JValue { .string(Data(raw).base64EncodedString()) }

private func draft(action: String = "ratify ruling", consumer: String = "notes", subject: String = "ruling-0001",
                   extra: [String: JValue] = [:]) -> JValue {
    var members: [String: JValue] = [
        "body": .object(["action": str(action), "consumer": str(consumer), "subject": str(subject)]),
        "expires_in_s": str("3600"), "head": .object(["id": str(hs("h")), "kind": str("chain")]),
        "method": str(method), "org": str(hs("org")),
    ]
    for (key, value) in extra { members[key] = value }
    return .object(members)
}

private func payload(_ raw: [UInt8] = content, action: String = "ratify ruling", consumer: String = "notes",
                     subject: String = "ruling-0001") throws -> JValue {
    try PayloadBuilder.build(draft: Draft.read(draft(action: action, consumer: consumer, subject: subject)),
                             attachments: .object(["decision_b64": b64(raw)]), fixed: fixed)
}

private func render(_ raw: [UInt8] = content, attachments: JValue? = nil, action: String = "ratify ruling",
                    consumer: String = "notes", subject: String = "ruling-0001") throws -> Rendered {
    let built = try payload(raw, action: action, consumer: consumer, subject: subject)
    return try Render.render(RenderInput(attachments: attachments ?? .object(["decision_b64": b64(raw)]), kid: kid,
                                         method: method, payload: built))
}

private func refused(_ code: String = "schema_refused", _ body: () throws -> Void) {
    #expect(throws: Refusal(code)) { try body() }
}

@Suite("decision forms (section 2.2, VR-18)")
struct DecisionFormsTests {
    @Test func anActionIsLowercaseWordsWithSingleSpacesUpTo24Characters() {
        for ok in ["ratify ruling", "forget item", "a", String(repeating: "x", count: 24), action24, "a b c"] {
            #expect(Forms.isAction(ok), "\(ok)")
        }
        for bad in ["", "Ratify ruling", "ratify  ruling", " ratify", "ratify ", "ratify2", "re-open", String(repeating: "x", count: 25),
                    "ratify\truling", "ratify\nruling", "caf\u{e9}", "ratify_ruling"] {
            #expect(!Forms.isAction(bad), "\(bad.debugDescription)")
        }
    }

    @Test func aConsumerIdStartsWithALetterAndHas2To32Characters() {
        for ok in ["notes", "ab", String(repeating: "a", count: 32), "a-1"] { #expect(Forms.isConsumerId(ok), "\(ok)") }
        for bad in ["a", String(repeating: "a", count: 33), "1ab", "-ab", "Notes", "", "no tes"] { #expect(!Forms.isConsumerId(bad), "\(bad)") }
    }

    @Test func aSubjectIdHas2To64Characters() {
        for ok in ["ruling-0001", "ab", String(repeating: "a", count: 64), "0a"] { #expect(Forms.isSubjectId(ok), "\(ok)") }
        for bad in ["a", String(repeating: "a", count: 65), "-ab", "Ab", "", "ab cd"] { #expect(!Forms.isSubjectId(bad), "\(bad)") }
    }

    @Test func theRegistryHoldsTheMethodWithItsBodyAndItsTwoHashRules() throws {
        let spec = try #require(Registry.standard.methods[method])
        #expect(spec.actExtraKeys == ["expires"])
        #expect(spec.head == .always)
        #expect(spec.inputsHash == "raw_decision_bytes")
        #expect(spec.outputsHash == "action_subject")
        #expect(Schema.defects(spec.body, .object(["action": str("ratify ruling"), "consumer": str("notes"),
                                                   "subject": str("ruling-0001")]), Registry.standard, code: "body_schema").isEmpty)
    }
}

@Suite("decision draft and payload (SG-04, SG-13, ACT-09)")
struct DecisionDraftTests {
    @Test func readsAValidDraft() throws {
        let read = try Draft.read(draft())
        #expect(read.method == method)
        #expect(read.expiresInS == 3600)
        #expect(read.verdict == nil)
        #expect(read.parent == nil)
    }

    @Test(arguments: ["Ratify ruling", "ratify  ruling", " ratify", "ratify ", "ratify 2", String(repeating: "x", count: 25), ""])
    func refusesAnActionOutsideItsGrammar(action: String) {
        refused { _ = try Draft.read(draft(action: action)) }
    }

    @Test func refusesTheOtherFieldsOutsideTheirForms() {
        refused { _ = try Draft.read(draft(consumer: "Notes")) }
        refused { _ = try Draft.read(draft(subject: "Ruling-0001")) }
    }

    @Test(arguments: ["recipient", "relay", "request_id"])
    func aDecisionDraftHasNoKeyOfAVerdict(key: String) {
        refused { _ = try Draft.read(draft(extra: [key: str("alice")])) }
    }

    @Test func aBodyWithAnExtraOrMissingKeyIsRefused() {
        refused { _ = try Draft.read(draft(extra: ["body": .object(["action": str("a b"), "consumer": str("notes")])])) }
        refused { _ = try Draft.read(draft(extra: ["body": .object(["action": str("a b"), "consumer": str("notes"),
                                                                    "note": str("x"), "subject": str("ab")])])) }
    }

    @Test func expiresInSIsRequired() {
        var members = (draft().dict ?? [:])
        members.removeValue(forKey: "expires_in_s")
        refused { _ = try Draft.read(.object(members)) }
    }

    @Test func theTwoHashesAreDerivedFromTheContentAndTheWords() throws {
        let built = try payload()
        #expect(built["inputs_hash"] == str(Encoding.hashstr(content)))
        let words = try Emit.subset(.object(["action": str("ratify ruling"), "subject": str("ruling-0001")]))
        #expect(built["outputs_hash"] == str(Encoding.hashstr(words)))
        #expect(built["parent_receipt_hash"] == .null)
        #expect(built["performer_id"] == str("alice"))
        let act = try #require(built["ext"]?["dev.handsal/act"]?.dict)
        #expect(Set(act.keys) == ["body", "expires", "head", "kid", "org"])
        #expect(act["expires"] == str("2026-11-08T12:59:00Z"))
    }

    @Test func theConsumerIsSignedInTheBody() throws {
        let built = try payload(consumer: "archive")
        #expect(built["ext"]?["dev.handsal/act"]?["body"]?["consumer"] == str("archive"))
    }

    @Test func aMissingAttachmentIsAttachmentMissingAndNothingIsBuilt() throws {
        refused("attachment_missing") {
            _ = try PayloadBuilder.build(draft: Draft.read(draft()), attachments: .object([:]), fixed: fixed)
        }
        refused("attachment_missing") {
            _ = try PayloadBuilder.build(draft: Draft.read(draft()), attachments: .object(["request_b64": b64(content)]), fixed: fixed)
        }
    }

    @Test func emitGivesThePayloadOfAValidDecision() throws {
        let input: JValue = .object(["attachments": .object(["decision_b64": b64(content)]), "draft": draft(),
                                     "fixed": .object(["kid": str(fixed.kid), "nonce": str(fixed.nonce),
                                                       "performer": str(fixed.performer), "ts": str(fixed.ts)])])
        let out = try SignerCommands.emit(input)
        let want = try Emit.subset(try payload())
        let hex = try #require(out["payload_hex"]?.str)
        #expect(hex == want.map { String(format: "%02x", $0) }.joined())
    }
}

@Suite("decision render (RN-03, RN-04, RN-09, RN-12)")
struct DecisionRenderTests {
    @Test func lineOneAndTheMethodLines() throws {
        let out = try render()
        let h = Render.hash12(Encoding.hashstr(content))
        #expect(out.firstLine == "notes: ratify ruling ruling-0001 (\(h), \(content.count) bytes)")
        let lines = out.text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines[0] == out.firstLine)
        #expect(lines[1] == "Method: local:handsal.decision")
        #expect(Array(lines[4..<8]) == ["Consumer: notes", "Action: ratify ruling", "Subject: ruling-0001", "Decision hash: \(h)"])
        #expect(lines[8] == "----- decision (\(content.count) bytes, sha256 \(h)) -----")
        #expect(lines[9] == "| Ruling 0001: keep the retry limit at three.")
        #expect(lines[10] == "----- end -----")
        #expect(lines.contains("Expires: 2026-11-08T12:59:00Z"))
        #expect(!lines.contains("Sender: not proven"))
        #expect(!lines.contains { $0.hasPrefix("Parent:") })
        #expect(out.text.hasSuffix("\n") && !out.text.hasSuffix("\n\n"))
    }

    @Test func lineOneIsExactly80BytesAtTheLongestFields() throws {
        let full = Array(String(repeating: String(repeating: "x", count: 63) + "\n", count: 32).utf8)   // 2048 bytes in 32 lines
        let out = try render(full, action: action24, consumer: "c" + String(repeating: "c", count: 31),
                             subject: String(repeating: "s", count: 64))
        #expect(out.firstLine.utf8.count == 80)
        #expect(out.firstLine.hasPrefix(String(repeating: "c", count: 11) + "~: " + action24 + " " + String(repeating: "s", count: 11) + "~ ("))
        #expect(out.text.contains("Consumer: " + String(repeating: "c", count: 32)))
        #expect(out.text.contains("Subject: " + String(repeating: "s", count: 64)))
    }

    @Test func theActionIsNeverCut() throws {
        #expect(try render(action: action24).firstLine.contains(": " + action24 + " "))
    }

    @Test func anEmptyContentHasNoContentLine() throws {
        let out = try render([])
        #expect(out.firstLine.contains("0 bytes)"))
        let lines = out.text.split(separator: "\n").map(String.init)
        #expect(lines[8].hasPrefix("----- decision (0 bytes, sha256 "))
        #expect(lines[9] == "----- end -----")
    }

    @Test func aLineLikeTheEndDoesNotEndTheBlock() throws {
        #expect(try render(Array("----- end -----\n".utf8)).text.contains("| ----- end -----"))
    }

    @Test func otherContentIsAMismatchAndNoneIsMissing() throws {
        refused("attachment_mismatch") { _ = try render(attachments: .object(["decision_b64": b64(Array("another".utf8))])) }
        refused("attachment_missing") { _ = try render(attachments: .object([:])) }
        refused("attachment_missing") { _ = try render(attachments: .object(["request_b64": b64(content)])) }
    }

    @Test func theBlockLimitsAreTheRequestLimits() throws {
        _ = try render([UInt8](repeating: 0x61, count: 2048))
        refused("render_refused") { _ = try render([UInt8](repeating: 0x61, count: 2049)) }
        _ = try render(Array(String(repeating: "a\n", count: 32).utf8))
        refused("render_refused") { _ = try render(Array(String(repeating: "a\n", count: 33).utf8)) }
    }

    @Test func aPayloadWhoseActionIsOutsideTheGrammarIsBodySchema() throws {
        let built = try payload()
        guard case .object(var top) = built, case .object(var ext)? = top["ext"], case .object(var act)? = ext["dev.handsal/act"],
              case .object(var body)? = act["body"] else { Issue.record("shape"); return }
        body["action"] = str("Ratify ruling")
        act["body"] = .object(body)
        ext["dev.handsal/act"] = .object(act)
        top["ext"] = .object(ext)
        refused("body_schema") {
            _ = try Render.render(RenderInput(attachments: .object(["decision_b64": b64(content)]), kid: kid, method: method, payload: .object(top)))
        }
    }
}
