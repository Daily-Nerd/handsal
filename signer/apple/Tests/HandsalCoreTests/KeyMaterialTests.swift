import Foundation
import HandsalCore
import Testing

/// SG-03, the invariant "repositories hold key ids, never key material": nothing the signer prints,
/// shows or asks the platform carries the private scalar, in any form a person could paste.
@Suite("key material stays in the key (SG-03)")
struct KeyMaterialTests {
    /// Every textual and byte form of `scalar` that an output could carry.
    static func forms(of scalar: [UInt8]) -> [[UInt8]] {
        let data = Data(scalar)
        let hex = scalar.map { String(format: "%02x", $0) }.joined()
        let texts = [hex, hex.uppercased(), data.base64EncodedString(), Encoding.base64url(scalar)]
        return [scalar] + texts.map { Array($0.utf8) }
    }

    static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        return (0...(haystack.count - needle.count)).contains { Array(haystack[$0..<($0 + needle.count)]) == needle }
    }

    static func leaks(_ haystack: [UInt8], scalar: [UInt8]) -> Bool {
        forms(of: scalar).contains { contains(haystack, $0) }
    }

    @Test("the scan finds the scalar in each form, and only the scalar")
    func theScanSeesEveryForm() {
        let scalar = (0..<32).map { UInt8($0 &* 7 &+ 3) }
        for form in Self.forms(of: scalar) {
            #expect(Self.leaks(Array("xx".utf8) + form + Array("yy".utf8), scalar: scalar))
        }
        #expect(!Self.leaks(Array("{\"kid\":\"abc\"}".utf8), scalar: scalar))
        #expect(!Self.leaks([], scalar: scalar))
    }

    @Test func noOutputCarriesKeyMaterial() throws {
        let rig = Rig(person: nil)
        let keygen = rig.run(["keygen"], .object(["label": jstr("laptop"), "person": jstr("alice")]))
        #expect(keygen.exit == 0)
        let scalar = try #require(rig.backend.privateScalar)
        #expect(scalar.count == 32)
        let attached = JValue.object(["request_b64": jstr(requestB64)])
        let outcomes = [keygen,
                        rig.run(["pubkey"]),
                        rig.run(["render"], signInput(verdictDraft(), attached)),
                        rig.run(["sign"], signInput(verdictDraft(), attached))]
        #expect(outcomes.allSatisfy { $0.exit == 0 })
        var seen = outcomes.flatMap { $0.line }
        seen += Array((rig.display?.text ?? "").utf8)
        seen += rig.backend.prompts.flatMap { Array($0.utf8) }
        // the scan ran over real output: the kid and the public points are there, the scalar is not
        let kid = try #require(resultObject(keygen)["kid"]?.str)
        #expect(Self.contains(seen, Array(kid.utf8)))
        #expect(!Self.leaks(seen, scalar: scalar))
    }
}
