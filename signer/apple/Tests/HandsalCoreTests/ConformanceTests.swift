import Foundation
import HandsalConformance
import HandsalCore
import Testing

private func run(_ args: [String], _ stdin: [UInt8] = []) -> Outcome {
    ConformanceCLI.run(arguments: args, readStdin: { stdin })
}

private func line(_ outcome: Outcome) -> String { String(decoding: outcome.line, as: UTF8.self) }

private func bytes(_ text: String) -> [UInt8] { Array(text.utf8) }

private let hs = { (seed: String) in Encoding.hashstr(Array(seed.utf8)) }

@Suite("handsal-sign-conformance (CF-04)")
struct ConformanceCommandTests {
    /// CF-04: one argument, `render` or `emit`; anything else is `unsupported_command`, exit 2.
    @Test(arguments: ["version", "keygen", "pubkey", "sign", "check-act", "fold", "subset", "kid", "pin-read", "RENDER", "", "info"])
    func everyOtherCommandIsUnsupported(command: String) {
        let out = run([command], bytes("{}"))
        #expect(out.exit == 2 && line(out) == #"{"error":"unsupported_command"}"#)
    }

    @Test func noArgumentOrTwoArgumentsIsUnsupported() {
        #expect(line(run([])) == #"{"error":"unsupported_command"}"# && run([]).exit == 2)
        #expect(line(run(["render", "emit"])) == #"{"error":"unsupported_command"}"# && run(["render", "emit"]).exit == 2)
        #expect(run(["emit", "--flag"]).exit == 2)
    }

    /// CF-03: the `render` of the checker, exit 0 for every result, errors as `{"error":code}`.
    @Test func renderTakesTheCheckerFormAndExitsZeroForEveryResult() {
        func code(_ input: String) -> String { line(run(["render"], bytes(input))) }
        func exit(_ input: String) -> Int32 { run(["render"], bytes(input)).exit }
        let cases: [(String, String)] = [
            ("{}", #"{"error":"malformed_input"}"#),
            ("[]", #"{"error":"malformed_input"}"#),
            ("null", #"{"error":"malformed_input"}"#),
            (#"{"attachments":{},"kid":"k","method":"m"}"#, #"{"error":"malformed_input"}"#),
            (#"{"attachments":{},"kid":"k","method":"m","payload":{},"x":1}"#, #"{"error":"malformed_input"}"#),
            (#"{"attachments":[],"kid":"k","method":"m","payload":{}}"#, #"{"error":"malformed_input"}"#),
            (#"{"attachments":{},"kid":1,"method":"m","payload":{}}"#, #"{"error":"malformed_input"}"#),
            (#"{"attachments":{},"kid":"k","method":"m","payload":[]}"#, #"{"error":"malformed_input"}"#),
            (#"{"attachments":{},"kid":"k","method":"m","payload":{}}"#, #"{"error":"schema"}"#),
            (#"{"attachments":{},"kid":"k","method":"m","payload":{"a":1.5e3}}"#, #"{"error":"schema"}"#),
        ]
        for (input, expected) in cases {
            #expect(code(input) == expected, "\(input)")
            #expect(exit(input) == 0, "\(input)")
        }
    }

    @Test func unparseableStdinIsAnErrorLineWithExitZero() {
        let long = [UInt8](repeating: 0x20, count: Limits.maxInput + 1)
        let inputs: [[UInt8]] = [
            bytes(#"{"a":1,"a":2}"#), bytes(#"{"a":{"b":1,"b":2}}"#), [0xFF, 0xFE], bytes("{"), bytes(""), bytes("{} {}"),
            bytes(#"{"a":"\ud800"}"#), bytes(#"{"a":"\udc00"}"#), bytes(#"{"a":"\ud800A"}"#), bytes("{\"a\":\"\u{01}\"}"),
            bytes(#"{"a":01}"#), bytes(#"{"a":+1}"#), bytes(#"{"a":1,}"#), bytes("{'a':1}"), long,
        ]
        for input in inputs {
            let out = run(["render"], input)
            #expect(out.exit == 0 && line(out) == #"{"error":"unparseable_input"}"#, "\(input.prefix(20))")
        }
    }

    @Test func whitespaceAndEscapesAreReadAsJson() {
        // The harness writes ordinary JSON, not the canonical subset: spaces, escapes, any key order.
        let spaced = #" { "payload" : { } , "method" : "m", "kid" : "k" , "attachments" : { } } "# + "\n"
        #expect(line(run(["render"], bytes(spaced))) == #"{"error":"schema"}"#)
        let pair = bytes(#"{"attachments":{},"kid":"k","method":"m","payload":{"a":"😀"}}"#)
        #expect(line(run(["render"], pair)) == #"{"error":"schema"}"#)
    }

    /// `emit` is the shipped emit: same input, same output line, same exit code (CF-04).
    @Test func emitIsTheShippedEmit() throws {
        let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
        let draft = JValue.object(["body": .object(["kid": .string("NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"), "person": .string("carol")]),
                                   "method": .string("local:handsal.device.remove"), "org": .string(hs("org")),
                                   "parent": .object(["id": .string(hs("p")), "performer": .string("bob")])])
        let good = JValue.object(["attachments": .object([:]), "draft": draft,
                                  "fixed": .object(["kid": .string(kid), "nonce": .string(hs("n")), "performer": .string("alice"), "ts": .string("2026-11-08T11:59:00Z")])])
        var bad = good
        if case .object(var members) = good { members["extra"] = .null; bad = .object(members) }
        for input in [good, bad] {
            let stdin = try Emit.subset(input) + [0x0A]
            let shipped = CLI.emit(readStdin: { stdin })
            let conformance = run(["emit"], stdin)
            #expect(conformance == shipped)
        }
        let ok = run(["emit"], try Emit.subset(good))
        #expect(ok.exit == 0 && line(ok).hasPrefix(#"{"payload_hex":""#))
        let refused = run(["emit"], try Emit.subset(bad))
        #expect(refused.exit == 2 && line(refused) == #"{"error":"schema_refused"}"#)
    }

    @Test func emitOverMaxInputIsSchemaRefusedWithExitTwo() {
        let out = run(["emit"], [UInt8](repeating: 0x20, count: Limits.maxInput + 1))
        #expect(out.exit == 2 && line(out) == #"{"error":"schema_refused"}"#)
    }

    @Test func outputIsDeterministic() {
        let input = bytes(#"{"attachments":{},"kid":"k","method":"m","payload":{}}"#)
        #expect(run(["render"], input) == run(["render"], input))
    }
}

@Suite("I-JSON reader of the conformance executable")
struct IJSONTests {
    @Test func readsNestedValuesWithEscapes() {
        let value = IJSON.parse(bytes(#"{"b":[1,true,null,"x\né\"\\\/"],"a":{"c":-0.5e+2}}"#))
        #expect(value == .object(["a": .object(["c": .number("-0.5e+2")]),
                                  "b": .array([.number("1"), .bool(true), .null, .string("x\n\u{E9}\"\\/")])]))
    }

    @Test func refusesWhatIJsonRefuses() {
        for bad in [#"{"a":1,"a":2}"#, #"{"a":"\ud800"}"#, #"{"a":"\udfff"}"#, #"{"a":1"#, #"{"a":.5}"#, #"{"a":-}"#, #"{"a":1e}"#,
                    #"{"a":tru}"#, #"[1,]"#, #"{"a" 1}"#, "{\"a\":\"x\ty\"}", #"{"a":"\x"}"#, "nul"] {
            #expect(IJSON.parse(bytes(bad)) == nil, "\(bad)")
        }
        #expect(IJSON.parse([0x22, 0xC3, 0x28, 0x22]) == nil)
        #expect(IJSON.parse([0x22, 0xED, 0xA0, 0x80, 0x22]) == nil)  // a lone surrogate encoded in UTF-8
        #expect(IJSON.parse(bytes(String(repeating: "[", count: 600) + String(repeating: "]", count: 600))) == nil)
        #expect(IJSON.parse(bytes(String(repeating: "[", count: 20) + String(repeating: "]", count: 20))) != nil)
    }

    @Test func leadingAndTrailingWhitespaceIsAllowed() {
        #expect(IJSON.parse(bytes(" \t\r\n{}\n ")) == .object([:]))
        #expect(IJSON.parse(bytes("{}x")) == nil)
    }
}
