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
    #expect(try Vector.load(commands: ["render"]).count == 95)   // 93 rnd rows and the two cli/stdin-nesting rows
}

@Test("subset rows", arguments: VectorRows.subset)
func subsetRows(row: Vector) throws {
    #expect(VectorAdapter.line(row) == row.anchor)
}

@Test("render rows", arguments: VectorRows.render)
func renderRows(row: Vector) throws {
    #expect(VectorAdapter.line(row) == row.anchor)
}
