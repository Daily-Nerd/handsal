import Foundation
import HandsalCore
import Testing

/// Section 2.3: the limits have one owner, `spec/registry.json`. `Limits` reads them from
/// `Registry.standard` (which `RegistryGuardTests` compares with the file) and holds no number
/// of its own, so a limit cannot drift from the registry the profile hash covers.
@Suite("limits are the registry's numbers (section 2.3)")
struct LimitsTests {
    private static func fileNumber(_ path: [String]) -> Int? {
        var value: JValue = .object(RegistryGuardTests.doc)
        for key in path {
            guard case .object(let o) = value, let next = o[key] else { return nil }
            value = next
        }
        if case .object(let o) = value, case .string(let text)? = o["value"] { return Int(text) }
        if case .string(let text) = value { return Int(text) }
        return nil
    }

    @Test func everyLimitIsTheNumberInTheFile() {
        let rows: [(String, Int, [String])] = [
            ("maxPayload", Limits.maxPayload, ["constants", "MAX_PAYLOAD"]),
            ("maxDepth", Limits.maxDepth, ["constants", "MAX_DEPTH"]),
            ("maxInput", Limits.maxInput, ["constants", "MAX_INPUT"]),
            ("maxExpiresInS", Limits.maxExpiresInS, ["constants", "MAX_EXPIRES_IN_S"]),
            ("line1Max", Limits.line1Max, ["constants", "render_line_1", "max"]),
            ("lineMax", Limits.lineMax, ["constants", "render_line", "max"]),
            ("wrapSegment", Limits.wrapSegment, ["constants", "render_line", "wrap_segment_max"]),
            ("maxLines", Limits.maxLines, ["constants", "render_length", "max"]),
            ("blockMaxBytes", Limits.blockMaxBytes, ["constants", "request_and_record_block", "max_source_bytes"]),
            ("blockMaxLines", Limits.blockMaxLines, ["constants", "request_and_record_block", "max_block_lines"]),
            ("blockLineBytes", Limits.blockLineBytes, ["constants", "request_and_record_block", "max_escaped_bytes_per_line"]),
        ]
        for (name, value, path) in rows {
            #expect(Self.fileNumber(path) == value, "\(name)")
        }
    }

    /// The tripwire for the way this drifted: a literal typed into `Limits.swift` is a second copy.
    @Test func limitsHoldNoNumberLiteral() throws {
        let source = try String(contentsOf: Vector.root.appendingPathComponent("signer/apple/Sources/HandsalCore/Limits.swift"), encoding: .utf8)
        var code = ""
        var inString = false
        for line in source.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = line.components(separatedBy: "//")[0]
            for c in text {
                if c == "\"" { inString.toggle() } else if !inString { code.append(c) }
            }
            code.append("\n")
        }
        // a number literal: digits that do not belong to an identifier such as `line1Max`
        let literal = try NSRegularExpression(pattern: "(?<![A-Za-z_0-9])[0-9][0-9_]*")
        let whole = NSRange(code.startIndex..., in: code)
        let digits = literal.matches(in: code, range: whole).compactMap { Range($0.range, in: code).map { String(code[$0]) } }
        #expect(digits.isEmpty, "Limits.swift holds the numbers \(digits)")
    }
}
