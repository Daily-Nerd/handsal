import Foundation
import HandsalCore
import HandsalKeyScan
import Testing

/// SG-03, the invariant "repositories hold key ids, never key material": nothing the signer prints,
/// shows or asks the platform carries the private scalar, in any form a person could paste.
@Suite("key material stays in the key (SG-03)")
struct KeyMaterialTests {
    @Test("the scan finds the scalar in each form, and only the scalar")
    func theScanSeesEveryForm() {
        let scalar = (0..<32).map { UInt8($0 &* 7 &+ 3) }
        for form in KeyScan.forms(of: scalar) {
            #expect(KeyScan.leaks(Array("xx".utf8) + form + Array("yy".utf8), scalar: scalar))
        }
        #expect(!KeyScan.leaks(Array("{\"kid\":\"abc\"}".utf8), scalar: scalar))
        #expect(!KeyScan.leaks([], scalar: scalar))
    }

    @Test func noOutputCarriesKeyMaterial() throws {
        let rig = Rig(person: nil)
        let keygen = rig.run(["keygen"], .object(["label": jstr("laptop"), "person": jstr("alice")]))
        #expect(keygen.exit == 0)
        let scalar = try #require(rig.backend.privateScalar)
        #expect(scalar.count == 32)
        let attached = JValue.object(["request_b64": jstr(requestB64)])
        let kid = try #require(resultObject(keygen)["kid"]?.str)
        let fixed = JValue.object(["kid": jstr(kid), "nonce": jstr(Rig.nonce), "performer": jstr("alice"), "ts": jstr(Rig.ts)])
        let outcomes = [keygen,
                        rig.run(["pubkey"]),
                        rig.run(["emit"], .object(["attachments": attached, "draft": verdictDraft(), "fixed": fixed])),
                        rig.run(["render"], signInput(verdictDraft(), attached)),
                        rig.run(["sign"], signInput(verdictDraft(), attached))]
        #expect(outcomes.allSatisfy { $0.exit == 0 })
        var seen = outcomes.flatMap { $0.line }
        seen += Array((rig.display?.text ?? "").utf8)
        seen += rig.backend.prompts.flatMap { Array($0.utf8) }
        // the scan ran over real output: the kid and the public points are there, the scalar is not
        #expect(KeyScan.contains(seen, Array(kid.utf8)))
        #expect(!KeyScan.leaks(seen, scalar: scalar))
    }
}
