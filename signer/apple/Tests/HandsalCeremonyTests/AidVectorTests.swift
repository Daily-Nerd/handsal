import Foundation
import HandsalCore
import Testing
@testable import HandsalCeremonyCore

/// The aids reader (SG-12 steps 6 and 7) and the checker's `genesis-aids` (CF-03) describe the same answer in two
/// languages. The conformance vectors hold what the checker answers, so each of them is fed through the reader here:
/// a change to the shape on one side only fails this suite.
@Suite("aids reader over the aid conformance vectors (CF-03)")
struct AidVectorTests {
    private struct Row { let name: String; let answer: JValue }

    private static func rows() throws -> [Row] {
        // <repo>/signer/apple/Tests/HandsalCeremonyTests/AidVectorTests.swift
        let root = (0..<5).reduce(#filePath) { path, _ in (path as NSString).deletingLastPathComponent }
        let directory = root + "/conformance/vectors"
        return try FileManager.default.contentsOfDirectory(atPath: directory).filter { $0.hasPrefix("aid.") && $0.hasSuffix(".json") }.sorted().map { file in
            let data = try Data(contentsOf: URL(fileURLWithPath: directory + "/" + file))
            let document = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            #expect(document["command"] as? String == "genesis-aids")
            let anchor = try #require(document["anchor"] as? String)
            guard case .success(let answer) = Subset.parse(Array(anchor.utf8), maxSize: Limits.maxInput) else { throw Refusal("internal") }
            return Row(name: file, answer: answer)
        }
    }

    @Test func thereAreTwelveAidVectors() throws {
        #expect(try Self.rows().count == 12)
    }

    @Test func everyAnswerThatCarriesAidsReadsAsTheLinesTheyDescribe() throws {
        var shown = 0
        for row in try Self.rows() {
            guard case .object(let members) = row.answer, case .object(let aids)? = members["aids"], case .array(let removed)? = aids["removed"],
                  case .object(let head)? = aids["head"], let place = head["place"]?.str else { continue }
            let lines = try Aids.read(row.answer).lines
            #expect(lines.count == 1 + removed.count, "\(row.name)")
            #expect(lines.dropFirst().elementsEqual(removed.compactMap(\.str).map { "Key removed in the previous epoch: \($0)" }), "\(row.name)")
            let expected: String
            switch place {
            case "tip": expected = "H is the tip"
            case "not_tip": expected = "H is not the tip (tip \(head["tip"]?.str ?? ""))"
            case "parent": expected = "Previous epoch forked at \(head["parent"]?.str ?? ""); H is P"
            case "not_below": expected = "Previous epoch forked at \(head["parent"]?.str ?? ""); H is not below P"
            case "below": expected = "Previous epoch forked at \(head["parent"]?.str ?? ""); H is below candidate \(head["candidate"]?.str ?? "")"
            default: expected = "unknown place \(place)"
            }
            #expect(lines[0] == expected, "\(row.name)")
            shown += 1
        }
        #expect(shown == 10)
    }

    @Test func aRefusedLineageStopsTheCeremonyWithTheCheckersCode() throws {
        let row = try #require(try Self.rows().first { $0.name == "aid.refused-lineage-has-no-aids.json" })
        let stop = try #require(throws: Stop.self) { try Aids.read(row.answer) }
        #expect(stop.result.reason == "genesis_change_unauthorized" && stop.result.written == "no")
    }

    @Test func anOriginalHasNoAidsAndTheCeremonyNeverAsksForThem() throws {
        let row = try #require(try Self.rows().first { $0.name == "aid.original-has-no-aids.json" })
        let stop = try #require(throws: Stop.self) { try Aids.read(row.answer) }
        #expect(stop.result.reason == "internal")
    }
}
