import Testing
@testable import HandsalCeremonyCore

@Suite("the checker before the pin write")
struct LineageViewTests {
    @Test func aCheckerSeenAsLineageQueriesCannotBeCastBackToMachineQueries() {
        let checker = FakeChecker()
        #expect((checker as any LineageQueries) is any MachineQueries)
        let view: any LineageQueries = LineageView(checker)
        #expect(!(view is any MachineQueries))
    }

    @Test func theViewAsksTheCheckerItWrapsForBothLineageCommands() throws {
        let checker = FakeChecker(["genesis-check": [.null], "genesis-aids": [.null]])
        let view = LineageView(checker)
        _ = try view.genesisCheck(Array("{}".utf8))
        _ = try view.genesisAids(Array("{}".utf8))
        #expect(checker.commands() == ["genesis-check", "genesis-aids"])
    }
}
