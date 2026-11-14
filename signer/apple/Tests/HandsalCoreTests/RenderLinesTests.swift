@testable import HandsalCore
import Testing

private func hs(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
private func block(_ raw: String, title: String = "request") throws -> [String] {
    try RenderLines.block(title: title, raw: Array(raw.utf8), inputsHash: Encoding.hashstr(Array(raw.utf8)))
}
private func block(bytes: [UInt8]) throws -> [String] {
    try RenderLines.block(title: "request", raw: bytes, inputsHash: Encoding.hashstr(bytes))
}

@Suite("request and record block (RN-05, RN-12)")
struct BlockTests {
    @Test func framesTheBlockWithSizeAndHash() throws {
        let lines = try block("deploy v2")
        #expect(lines == ["----- request (9 bytes, sha256 CwmA doEB agBd) -----", "| deploy v2", "----- end -----"])
        #expect(try block("x", title: "record body").first?.hasPrefix("----- record body (1 bytes, sha256 ") == true)
    }

    @Test func emptyRequestHasNoContentLine() throws {
        #expect(try block("").count == 2)
    }

    @Test func eachSourceLineIsPrefixedAndAFinalLfStartsNoLine() throws {
        #expect(try block("a\nb").dropFirst().dropLast() == ["| a", "| b"])
        #expect(try block("a\nb\n").dropFirst().dropLast() == ["| a", "| b"])
        #expect(try block("a\n\nb").dropFirst().dropLast() == ["| a", "| ", "| b"])
        #expect(try block("\n").dropFirst().dropLast() == ["| "])
    }

    @Test func everyOtherByteIsEscapedInLowercaseHex() throws {
        #expect(try block(bytes: [0x61, 0x0D, 0x09, 0x00, 0x7F, 0xC3, 0xA9, 0x7E, 0x20]).dropFirst().first == "| a\\x0d\\x09\\x00\\x7f\\xc3\\xa9~ ")
        #expect(try block(bytes: [0xFF, 0xFE]).dropFirst().first == "| \\xff\\xfe")   // invalid UTF-8 is never decoded
    }

    @Test func aDelimiterInTheRequestCannotEndTheBlock() throws {
        #expect(try block("----- end -----\n").dropFirst().first == "| ----- end -----")
    }

    @Test func longLinesContinueWithPlusNeverSplittingAnEscape() throws {
        let lines = Array(try block(String(repeating: "a", count: 300)).dropFirst().dropLast())
        #expect(lines == ["| " + String(repeating: "a", count: 96), "|+" + String(repeating: "a", count: 96),
                          "|+" + String(repeating: "a", count: 96), "|+" + String(repeating: "a", count: 12)])
        let edge = Array(try block(bytes: [UInt8](repeating: 0x61, count: 95) + [0xFF]).dropFirst().dropLast())
        #expect(edge == ["| " + String(repeating: "a", count: 95), "|+\\xff"])
    }

    @Test func limitsAre2048BytesAnd32Lines() throws {
        _ = try block(String(repeating: "a", count: 2048))
        #expect(throws: Refusal("render_refused")) { _ = try block(String(repeating: "a", count: 2049)) }
        _ = try block(String(repeating: "a\n", count: 32))
        #expect(throws: Refusal("render_refused")) { _ = try block(String(repeating: "a\n", count: 33)) }
        // continuation lines count: 16 escaped bytes of 4 characters fill 64 per line
        #expect(throws: Refusal("render_refused")) { _ = try block(bytes: [UInt8](repeating: 0xFF, count: 800)) }
    }
}

@Suite("line 1 templates (RN-03)")
struct FirstLineTests {
    private func act(_ body: JValue, extra: [String: JValue] = [:]) -> [String: JValue] {
        var a: [String: JValue] = ["body": body]
        for (k, v) in extra { a[k] = v }
        return ["ext": .object(["dev.handsal/act": .object(a)]), "inputs_hash": .string(Encoding.hashstr(Array("deploy v2".utf8)))]
    }

    @Test func deviceRemoveAndPromote() throws {
        let remove = act(.object(["kid": .string("NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"), "person": .string("carol")]))
        #expect(try RenderLines.firstLine(method: Methods.deviceRemove, payload: remove, facts: Facts()) == "Remove device NAjt fK8u Px9m of carol")
        let promote = act(.object(["anchors": .array([]), "record_id": .string("rec-0001")]))
        var facts = Facts(); facts.raw = Array("deploy v2".utf8)
        #expect(try RenderLines.firstLine(method: Methods.promote, payload: promote, facts: facts) == "Promote record rec-0001 (CwmA doEB agBd, 9 bytes)")
    }

    @Test func freeFieldsAreCutAtTwelveCharacters() throws {
        let remove = act(.object(["kid": .string("NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"), "person": .string("ppppppppppppp")]))
        #expect(try RenderLines.firstLine(method: Methods.deviceRemove, payload: remove, facts: Facts()) == "Remove device NAjt fK8u Px9m of ppppppppppp~")
    }

    @Test func endorseAndResolveCutTheNestedLineOne() throws {
        var facts = Facts()
        facts.endorsedLine1 = String(repeating: "e", count: 80)
        let endorse = act(.object(["act": .string(hs("a"))]))
        #expect(try RenderLines.firstLine(method: Methods.endorse, payload: endorse, facts: facts) == "Endorse: " + String(repeating: "e", count: 70) + "~")
        let choose = hs("c")
        facts.candidates = [choose: String(repeating: "c", count: 60)]
        let resolve = act(.object(["choose": .string(choose)]))
        #expect(try RenderLines.firstLine(method: Methods.resolve, payload: resolve, facts: facts) == "Resolve fork, keep: " + String(repeating: "c", count: 59) + "~")
    }
}
