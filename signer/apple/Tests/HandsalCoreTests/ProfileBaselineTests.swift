import HandsalCore
import Testing

/// T16.1 characterization of what the signer core says about profiles today. Green on the first run by
/// design; each test pins behavior that a later row (T16.10) restructures, so that row changes the
/// lock knowingly. The ceremony half is in `ProfileBaselineCeremonyTests`.
@Suite("profile baseline (T16.1)")
struct ProfileBaselineTests {
    private static let unknown = Encoding.hashstr(Array("an edition this build does not implement".utf8))

    @Test func kindAnswersProductionFixtureAndNil() {
        #expect(Profiles.standard.kind(Profiles.standard.production) == "production")
        #expect(Profiles.standard.kind(Profiles.standard.fixture) == "fixture")
        #expect(Profiles.standard.kind(Self.unknown) == nil)
        #expect(Profiles.standard.production != Profiles.standard.fixture)
    }

    // T16.10 rewrites this lock to the key set `class, impl, profiles, spec`.
    @Test func versionReturnsExactlyTheKeysClassImplAndSpec() throws {
        let environment = Rig(person: nil, keyClass: "apple-se-bio").env
        let out = CLI.run(arguments: ["version"], readStdin: { [] }, environment: environment)
        #expect(out.exit == 0)
        guard case .success(.object(let members)) = Subset.parse(out.line.last == 0x0A ? Array(out.line.dropLast()) : out.line, maxSize: Limits.maxInput) else {
            Issue.record("version did not answer one JSON object"); return
        }
        #expect(Set(members.keys) == ["class", "impl", "spec"])
        #expect(members["spec"] == .string(Profiles.standard.production))
    }
}
