import HandsalCore
import Testing
@testable import HandsalCeremonyCore

/// Characterization of the ceremony refusal for profiles (SG-12 step 2), over the set of editions: the fixture locks stay, the unknown-hash locks now also run over a set of two editions,
/// where a lineage of different supported editions is accepted and only a hash of no edition is a mismatch.
@Suite("profile baseline ceremony")
struct ProfileBaselineCeremonyTests {
    private static let unknown = Encoding.hashstr(Array("an edition this build does not implement".utf8))

    /// Every answer the checker could give is queued, so a ceremony that went through would show.
    private func refusal(profiles lineageProfiles: [String], context: GenesisContext = GenesisContext()) -> (result: CeremonyResult, checker: FakeChecker, helper: FakeHelper) {
        var docs = Docs()
        var lineage: [(doc: JValue, sigs: [String])] = []
        var previous: String?
        var org: String?
        for profile in lineageProfiles {
            docs.profile = profile
            let doc = docs.document(prev: previous, org: org, head: previous == nil ? nil : hash("head"))
            lineage.append((doc: doc, sigs: []))
            org = org ?? docHash(doc)
            previous = docHash(doc)
        }
        let last = lineage[lineage.count - 1].doc
        let answers: [String: [JValue]] = ["genesis-check": [checkAnswer(pin: pinLine(genesis: docHash(last), org: org ?? ""))],
                                           "sync": [syncOk], "enrolled": [enrolledYes]]
        let checker = FakeChecker(answers), helper = FakeHelper()
        let result = Ceremony(checker: checker, helper: helper, console: FakeConsole(), context: context)
            .run(arguments: [], stdin: ceremonyInput(lineage: lineage))
        return (result, checker, helper)
    }

    @Test func aFixtureProfileLineageIsRefusedBeforeAnything() {
        let r = refusal(profiles: [Profiles.standard.fixture])
        #expect(r.result == CeremonyResult(reason: "fixture_profile", written: "no", exit: 1))
        #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty)
    }

    @Test func aFixtureDocumentCannotHideBehindAProductionLastLink() {
        let r = refusal(profiles: [Profiles.standard.fixture, Profiles.standard.production])
        #expect(r.result == CeremonyResult(reason: "fixture_profile", written: "no", exit: 1))
        #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty)
    }

    @Test func aLineageNamingAnUnknownHashIsProfileMismatchBeforeAnything() {
        let r = refusal(profiles: [Self.unknown])
        #expect(r.result == CeremonyResult(reason: "profile_mismatch", written: "no", exit: 1))
        #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty)
    }

    @Test func anUnknownHashInTheMiddleOfAProductionLineageIsProfileMismatch() {
        let r = refusal(profiles: [Profiles.standard.production, Self.unknown, Profiles.standard.production])
        #expect(r.result == CeremonyResult(reason: "profile_mismatch", written: "no", exit: 1))
        #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty)
    }

    @Test func aHashOfNoEditionIsProfileMismatchOverASetOfTwoEditions() {
        let set = SyntheticEditions.context()
        for lineage in [[SyntheticEditions.unknown], [SyntheticEditions.oldProduction, SyntheticEditions.unknown],
                        [SyntheticEditions.newProduction, SyntheticEditions.unknown, SyntheticEditions.oldProduction]] {
            let r = refusal(profiles: lineage, context: set)
            #expect(r.result == CeremonyResult(reason: "profile_mismatch", written: "no", exit: 1), "\(lineage.count)")
            #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty)
        }
        // the live production profile is no edition of the synthetic set: the set decides, not the build
        #expect(refusal(profiles: [Profiles.standard.production], context: set).result.reason == "profile_mismatch")
    }

    @Test func aFixtureProfileOfAnOlderEditionIsFixtureProfileBeforeAnything() {
        let r = refusal(profiles: [SyntheticEditions.oldFixture, SyntheticEditions.newProduction], context: SyntheticEditions.context())
        #expect(r.result == CeremonyResult(reason: "fixture_profile", written: "no", exit: 1))
        #expect(r.checker.calls.isEmpty && r.helper.lines.isEmpty)
    }
}
