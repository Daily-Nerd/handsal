@testable import HandsalCore
import Testing

/// What the signer core says about profiles. The unit that decides is `Profiles.resolve`, which answers the edition a hash belongs to
/// and which kind it is; the ceremony half is in `ProfileBaselineCeremonyTests`.
@Suite("profile set")
struct ProfileBaselineTests {
    private static let unknown = Encoding.hashstr(Array("an edition this build does not implement".utf8))

    @Test func resolveAnswersTheEditionAndTheKindOfEveryHash() {
        let set = Editions.two()
        #expect(set.resolve(Editions.oldProduction)?.edition.label == "old")
        #expect(set.resolve(Editions.oldProduction)?.kind == .production)
        #expect(set.resolve(Editions.oldFixture)?.edition.label == "old")
        #expect(set.resolve(Editions.oldFixture)?.kind == .fixture)
        #expect(set.resolve(Editions.newProduction)?.edition.label == "new")
        #expect(set.resolve(Editions.newFixture)?.kind == .fixture)
        #expect(set.resolve(Self.unknown) == nil)
    }

    @Test func theLiveEditionResolvesLikeTheBaselineSaid() {
        let live = Profiles.standard
        #expect(live.resolve(live.production)?.kind == .production)
        #expect(live.resolve(live.fixture)?.kind == .fixture)
        #expect(live.resolve(Self.unknown) == nil)
        #expect(live.production != live.fixture)
    }

    @Test func productionHashesAreInCatalogOrderAndTheCurrentOneIsTheLast() {
        #expect(Editions.two().productionHashes == [Editions.oldProduction, Editions.newProduction])
        #expect(Editions.two().production == Editions.newProduction)
        #expect(Editions.two().isCurrentProduction(Editions.newProduction))
        #expect(!Editions.two().isCurrentProduction(Editions.oldProduction))
        #expect(!Editions.two().isCurrentProduction(Editions.newFixture))
        #expect(Profiles.standard.productionHashes.last == Profiles.standard.production)
    }

    /// The live core is the newest frozen edition, or a new edition after it, and it is listed once (GP-22, C4).
    @Test func theLiveCoreIsTheNewestFrozenEditionOrOneAfterItAndIsListedOnce() {
        let frozen = Profiles.versions.map(\.production)
        let live = Profiles.standard
        #expect(Profiles.versions.map(\.label).first == "edition-1")
        #expect(live.productionHashes == (frozen.last == live.production ? frozen : frozen + [live.production]))
        #expect(live.editions.count == live.productionHashes.count)
        #expect(live.editions[live.editions.count - 1].registry.methods.count == Registry.standard.methods.count)
    }

    @Test func versionReturnsExactlyTheKeysClassImplProfilesAndSpecInThatOrder() throws {
        let environment = Rig(person: nil, keyClass: "apple-se-bio").env
        let out = CLI.run(arguments: ["version"], readStdin: { [] }, environment: environment)
        #expect(out.exit == 0)
        let live = Profiles.standard
        let listed = live.productionHashes.map { "\"\($0)\"" }.joined(separator: ",")
        #expect(lineText(out) == #"{"class":"apple-se-bio","impl":"handsal-sign-swift","profiles":[\#(listed)],"spec":"\#(live.production)"}"#)
        guard case .success(.object(let members)) = Subset.parse(out.line.last == 0x0A ? Array(out.line.dropLast()) : out.line, maxSize: Limits.maxInput) else {
            Issue.record("version did not answer one JSON object"); return
        }
        #expect(Set(members.keys) == ["class", "impl", "profiles", "spec"])
        #expect(members["spec"] == .string(live.production))
    }
}
