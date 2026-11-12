import Foundation
import HandsalCore
import Testing

private func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

@Suite("canonical emitter (ACT-05)")
struct EmitTests {
    @Test func sortsKeysByByteOrderWithNoWhitespace() throws {
        let value = JValue.object(["b": .string("2"), "a": .null, "B": .array([.string("x"), .null])])
        #expect(text(try Emit.subset(value)) == #"{"B":["x",null],"a":null,"b":"2"}"#)
    }

    @Test func writesSlashVerbatimAndKeepsArrayOrder() throws {
        let value = JValue.array([.string("z"), .string("a/b"), .string("a")])
        #expect(text(try Emit.subset(value)) == #"["z","a/b","a"]"#)
    }

    @Test func emptyContainers() throws {
        #expect(text(try Emit.subset(.object([:]))) == "{}")
        #expect(text(try Emit.subset(.array([]))) == "[]")
    }

    @Test(arguments: [
        JValue.number("1"), JValue.bool(true), JValue.string("caf\u{E9}"), JValue.string("a\"b"),
        JValue.string("a\\b"), JValue.string("a\nb"), JValue.string("\u{7F}"),
        JValue.object(["k\u{E9}": .null]), JValue.object(["a": .number("1")]),
    ])
    func refusesWhatTheSubsetCannotExpress(value: JValue) {
        #expect(throws: Refusal.self) { try Emit.subset(value) }
    }

    @Test func refusesNestingPastEightAndSizePastMaxPayload() {
        var deep = JValue.array([])
        for _ in 0..<8 { deep = .array([deep]) }
        #expect(throws: Refusal.self) { try Emit.subset(deep) }
        let big = JValue.string(String(repeating: "a", count: 16_384))
        #expect(throws: Refusal.self) { try Emit.subset(big) }
    }

    @Test func emitThenRecognizeIsTheIdentity() throws {
        let value = JValue.object([
            "z": .array([.object(["y": .string("v"), "x": .null])]),
            "a": .string("a/b c"),
        ])
        let bytes = try Emit.subset(value)
        #expect(Subset.parse(bytes, maxSize: 16_384) == .success(value))
    }

    /// Every `jcs/emit-roundtrip-*` row holds the exact bytes a generator emitted for one method:
    /// the Swift emitter must give the same bytes back (ACT-05, S1).
    @Test("emitter reproduces the generator bytes", arguments: try Vector.load(commands: ["subset"]).filter { $0.name.hasPrefix("jcs/emit-roundtrip-") })
    func reproducesGeneratorBytes(row: Vector) throws {
        guard case .bytes(let bytes) = row.input,
              case .success(let value) = Subset.parse(bytes, maxSize: 16_384) else {
            Issue.record("row does not parse")
            return
        }
        #expect(try Emit.subset(value) == bytes)
    }
}

@Suite("result line writer (CF-03, SG-01)")
struct ResultLineTests {
    @Test func writesSortedKeysAndEscapesLikeJcs() throws {
        let value = JValue.object(["text": .string("a\nb\"c\\d\u{1}"), "first_line": .string("x")])
        #expect(text(try Emit.resultLine(value)) == #"{"first_line":"x","text":"a\nb\"c\\d\u0001"}"#)
    }

    @Test func writesBooleansNullAndNumbers() throws {
        let value = JValue.object(["canonical": .bool(false), "reason": .null, "n": .number("5")])
        #expect(text(try Emit.resultLine(value)) == #"{"canonical":false,"n":5,"reason":null}"#)
    }
}
