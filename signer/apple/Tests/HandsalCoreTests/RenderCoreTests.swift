import HandsalCore
import Testing

private let hash = "uEiCwmAdoEBagBdcJhxJqKaPD78wSAoyQmX3fj-_8GlSwRQ"
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"

@Suite("render layout (RN-01, RN-02, RN-03)")
struct RenderCoreTests {
    @Test func shortForms() {
        #expect(Render.hash12(hash) == "CwmA-doEB-agBd")       // characters 3 to 14, skipping the constant uEi
        #expect(Render.kid12(kid) == "E5ua-1p9O-mQf5")
    }

    @Test func cutsFreeFieldsAtTwelve() {
        #expect(Render.cut12("abcdefghijkl") == "abcdefghijkl")
        #expect(Render.cut12("abcdefghijklm") == "abcdefghijk~")
        #expect(Render.cut12("") == "")
        #expect(Render.cut("abc", to: 3) == "abc")
        #expect(Render.cut("abcd", to: 3) == "abc~")
    }

    @Test func wrapsLongLinesIntoNinetyEightByteSegments() {
        let hundred = String(repeating: "a", count: 100)
        #expect(Render.wrap(hundred) == [hundred])
        let hundredOne = String(repeating: "a", count: 101)
        #expect(Render.wrap(hundredOne) == [String(repeating: "a", count: 98), "+ aaa"])
        let long = String(repeating: "b", count: 300)
        let lines = Render.wrap(long)
        #expect(lines.count == 4)
        #expect(lines[0].count == 98 && lines[1] == "+ " + String(repeating: "b", count: 98) && lines[3] == "+ bbbbbb")
        #expect(lines.map { $0.hasPrefix("+ ") ? String($0.dropFirst(2)) : $0 }.joined() == long)   // nothing is hidden
    }

    private func frame(body: [String] = ["Person: alice"], expires: String? = nil, parent: String? = nil, head: String? = nil,
                       sender: Bool = false) throws -> Rendered {
        try Render.frame(first: "FIRST", method: "local:handsal.device.remove", org: hash, performer: "alice", kid: kid, body: body,
                         ts: "2026-11-08T11:59:00Z", expires: expires, parent: parent, head: head, sender: sender)
    }

    @Test func frameOrdersTheLinesAndEndsWithOneLf() throws {
        let out = try frame(expires: "2026-11-08T12:59:00Z", parent: hash, head: hash, sender: true)
        #expect(out.firstLine == "FIRST")
        #expect(out.text == [
            "FIRST", "Method: local:handsal.device.remove", "Org: CwmA-doEB-agBd", "Signer: alice key E5ua-1p9O-mQf5",
            "Person: alice", "Signed at: 2026-11-08T11:59:00Z", "Expires: 2026-11-08T12:59:00Z", "Parent: CwmA-doEB-agBd",
            "Head: CwmA-doEB-agBd", "Sender: not proven", "",
        ].joined(separator: "\n"))
        let bare = try frame()
        #expect(!bare.text.contains("Expires") && !bare.text.contains("Parent") && !bare.text.contains("Head") && !bare.text.contains("Sender"))
        #expect(bare.text.hasSuffix("Signed at: 2026-11-08T11:59:00Z\n") && !bare.text.hasSuffix("\n\n"))
    }

    @Test func frameWrapsLongBodyLinesButNotLineOne() throws {
        let out = try frame(body: ["Relay: " + String(repeating: "r", count: 200)])
        #expect(out.text.contains("\n+ "))
    }

    @Test func frameRefusesMoreThanSeventyTwoLines() throws {
        // 4 header lines + body + Signed at: 67 body lines make 72, 68 make 73
        _ = try frame(body: Array(repeating: "x", count: 67))
        #expect(throws: Refusal("render_refused")) { _ = try frame(body: Array(repeating: "x", count: 68)) }
    }
}
