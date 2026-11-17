import Foundation
import HandsalCore
import Testing

/// Runs the conformance vectors that signers answer (CF-04): `render` rows through the renderer
/// and the `subset` rows (`jcs/*`) through the recognizer. `VectorAdapter` turns one vector into
/// the result line the vector's anchor holds.
enum VectorRows {
    static let subset: [Vector] = (try? Vector.load(commands: ["subset"])) ?? []
    static let render: [Vector] = (try? Vector.load(commands: ["render"])) ?? []
}

@Test("vector files load")
func vectorFilesLoad() throws {
    #expect(try Vector.load(commands: ["subset"]).count == 39)
    #expect(try Vector.load(commands: ["render"]).count == 108)   // 102 rnd rows, 2 wit rows, 3 cli rows and 1 prf row
}

@Test("subset rows", arguments: VectorRows.subset)
func subsetRows(row: Vector) throws {
    #expect(VectorAdapter.line(row) == row.anchor)
}

@Test("render rows", arguments: VectorRows.render)
func renderRows(row: Vector) throws {
    #expect(VectorAdapter.line(row) == row.anchor)
}

/// GP-02 and GP-15 steps 1 to 4 for a lone document. The signer has no `fold`, so the harness cannot run the
/// `pol/*` rows; `Genesis.checkAlone` is the same validation the checker's fold runs, and here it is run on the
/// first document of every one-document `pol/*` row and must give the row's own code. The vector files are the
/// oracle, so the three implementations of the policy rules (checker, Rust, Swift) answer one set of rows and
/// none keeps a copy of an expectation. The change rows need a previous document: not run here.
@Test("pol rows through checkAlone")
func polRowsThroughCheckAlone() throws {
    var covered: [String] = []
    for row in try Vector.load(commands: ["fold", "genesis-check"]) where row.name.hasPrefix("pol/") {
        guard case .json(.object(let input)) = row.input, case .array(let lineage)? = input["lineage"],
              lineage.count == 1, case .object(let entry) = lineage[0], let doc = entry["doc"] else { continue }
        let anchor = try TestJSON.parse(Array(row.anchor.utf8))
        var want: String?
        // `fold` answers `{"error":code}`; `genesis-check` (pol/relays-number) answers `{"reason":code,"valid":false}`
        if case .object(let members) = anchor {
            if case .string(let code)? = members["error"] { want = code }
            if case .bool(false)? = members["valid"], case .string(let code)? = members["reason"] { want = code }
        }
        var got: String?
        do { try Genesis.checkAlone(doc) } catch let refusal as Refusal { got = refusal.code }
        #expect(got == want, "\(row.name): \(String(describing: got)) != \(String(describing: want))")
        covered.append(row.name)
    }
    for name in ["pol/relays-missing", "pol/relays-unsorted", "pol/relays-duplicate", "pol/relays-not-hostname",
                 "pol/relays-three", "pol/relays-number"] {
        #expect(covered.contains(name), "\(name) was not run")
    }
    #expect(covered.count >= 28, "only \(covered.count) pol rows run")
}
