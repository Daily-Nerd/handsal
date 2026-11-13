import Foundation
import HandsalCore
import Testing

/// SG-13: the signer derives the facts of an endorsement from the attached act and refuses a draft
/// whose values differ, with exit 2 and no prompt. The acts attached here are signed by the signer
/// itself, so the tests need no hand-built JWS.
@Suite("attachments against the draft (SG-13)")
struct AttachmentSignTests {
    private let parent = hsh("parent")

    /// A chain act signed by `person`, as an attachment would carry it: its JWS and receipt id.
    private func chainAct(by person: String = "alice") throws -> (jws: String, id: String) {
        let rig = Rig(person: person)
        let out = rig.run(["sign"], signInput(chainDraft(parent: parent)))
        #expect(out.exit == 0)
        return (try #require(resultObject(out)["jws"]?.str), try #require(resultObject(out)["receipt_id"]?.str))
    }

    private func endorse(act: String, parentId: String, performer: String, head: String) -> JValue {
        .object(["body": .object(["act": jstr(act)]), "head": .object(["id": jstr(head), "kind": jstr("chain")]),
                 "method": jstr(Methods.endorse), "org": jstr(hsh("org")),
                 "parent": .object(["id": jstr(parentId), "performer": jstr(performer)])])
    }

    private func sign(_ draft: JValue, _ attachments: JValue, as person: String = "bob") -> (Outcome, Rig) {
        let rig = Rig(person: person)
        return (rig.run(["sign"], signInput(draft, attachments)), rig)
    }

    @Test("an endorsement that matches its attached act is signed")
    func aMatchingEndorsementIsSigned() throws {
        let attached = try chainAct()
        let (out, rig) = sign(endorse(act: attached.id, parentId: attached.id, performer: "alice", head: parent), .object(["act": jstr(attached.jws)]))
        #expect(out.exit == 0 && rig.backend.prompts.count == 1)
        #expect(rig.backend.prompts.first?.hasPrefix("Endorse: ") == true)
        #expect(rig.display?.text.hasPrefix("Endorse: ") == true)
    }

    @Test("sgn/endorse-act-id-mismatch: body.act is not the id of the attached act")
    func theActIdMustBeTheAttachedActs() throws {
        let attached = try chainAct()
        let (out, rig) = sign(endorse(act: hsh("other"), parentId: attached.id, performer: "alice", head: parent), .object(["act": jstr(attached.jws)]))
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_mismatch"))
        #expect(rig.backend.prompts.isEmpty && rig.display?.shown.isEmpty == true)
    }

    @Test("sgn/endorse-head-mismatch: head.id is not the parent of the attached act")
    func theHeadMustBeTheAttachedActsParent() throws {
        let attached = try chainAct()
        let (out, rig) = sign(endorse(act: attached.id, parentId: attached.id, performer: "alice", head: hsh("elsewhere")), .object(["act": jstr(attached.jws)]))
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_mismatch") && rig.backend.prompts.isEmpty)
    }

    @Test("sgn/endorse-parent-id-mismatch: parent.id is not the attached act")
    func theParentIdMustBeTheAttachedAct() throws {
        let attached = try chainAct()
        let (out, rig) = sign(endorse(act: attached.id, parentId: hsh("other"), performer: "alice", head: parent), .object(["act": jstr(attached.jws)]))
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_mismatch") && rig.backend.prompts.isEmpty)
    }

    @Test("sgn/endorse-parent-performer-mismatch: parent.performer is not the attached act's performer")
    func theParentPerformerMustBeTheAttachedActsPerformer() throws {
        let attached = try chainAct()
        let (out, rig) = sign(endorse(act: attached.id, parentId: attached.id, performer: "carol", head: parent), .object(["act": jstr(attached.jws)]))
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_mismatch") && rig.backend.prompts.isEmpty)
    }

    @Test("sgn/endorse-attachment-required: no attached act is attachment_missing")
    func anEndorsementNeedsItsAct() throws {
        let attached = try chainAct()
        let (out, rig) = sign(endorse(act: attached.id, parentId: attached.id, performer: "alice", head: parent), .object([:]))
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_missing") && rig.backend.prompts.isEmpty)
    }

    @Test("sgn/endorse-attachment-not-chain: an attached approve is attachment_mismatch")
    func theAttachedActMustBeAChainAct() throws {
        let alice = Rig(person: "alice")
        let approve = alice.run(["sign"], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)])))
        let jws = try #require(resultObject(approve)["jws"]?.str), id = try #require(resultObject(approve)["receipt_id"]?.str)
        let (out, rig) = sign(endorse(act: id, parentId: id, performer: "alice", head: hsh("h")), .object(["act": jstr(jws)]))
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_mismatch") && rig.backend.prompts.isEmpty)
    }

    @Test("sgn/resolve-requires-candidates: a resolve draft without candidate attachments is attachment_missing")
    func aResolveNeedsItsCandidatesAndHeads() throws {
        let a = hsh("c1"), b = hsh("c2")
        let draft = JValue.object(["body": .object(["candidates": .array([jstr(min(a, b)), jstr(max(a, b))]), "choose": jstr(min(a, b)),
                                                    "heads": .array([jstr(hsh("h1"))]), "overrides": .array([])]),
                                   "method": jstr(Methods.resolve), "org": jstr(hsh("org")),
                                   "parent": .object(["id": jstr(hsh("p")), "performer": .null])])
        let (out, rig) = sign(draft, .object([:]), as: "alice")
        #expect(out.exit == 2 && lineText(out) == errorLine("attachment_missing"))
        #expect(rig.backend.prompts.isEmpty && rig.display?.shown.isEmpty == true)
        let (onlyHeads, again) = sign(draft, .object(["heads": .array([])]), as: "alice")
        #expect(onlyHeads.exit == 2 && again.backend.prompts.isEmpty)
    }
}
