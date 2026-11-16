@testable import HandsalCore

/// A synthetic two-edition set, injected through `GenesisContext(profiles:)`. The catalog has no row
/// yet, so every test that needs an older edition builds one here and never touches the real tables.
///
/// `old` is the older production edition: it still accepts the class `retired-hw`, which the current
/// edition no longer lists, so a test can tell which edition's tables decided. Neither synthetic edition
/// lists a fixture kid of its own unless a test adds one, so the fixture keys of the conformance
/// documents are valid under both.
enum Editions {
    static let oldProduction = hsh("synthetic old production")
    static let oldFixture = hsh("synthetic old fixture")
    static let newProduction = hsh("synthetic new production")
    static let newFixture = hsh("synthetic new fixture")
    static let retired = ClassSpec(id: "retired-hw", status: "active", userVerification: "biometric_only")

    static func old(fixtureKids: Set<String> = []) -> Edition {
        Edition(label: "old", production: oldProduction, fixture: oldFixture, fixtureKids: fixtureKids,
                registry: Registry.standard.addingClass(retired))
    }

    static func new(fixtureKids: Set<String> = []) -> Edition {
        Edition(label: "new", production: newProduction, fixture: newFixture, fixtureKids: fixtureKids, registry: .standard)
    }

    static func two(oldKids: Set<String> = [], newKids: Set<String> = []) -> Profiles {
        Profiles(editions: [old(fixtureKids: oldKids), new(fixtureKids: newKids)])
    }

    static func context(oldKids: Set<String> = [], newKids: Set<String> = []) -> GenesisContext {
        GenesisContext(profiles: two(oldKids: oldKids, newKids: newKids))
    }

    static let midProduction = hsh("synthetic mid production")
    static let midFixture = hsh("synthetic mid fixture")

    /// Three editions, so a change can name a newer supported edition that is not the current one.
    static func three() -> Profiles {
        let mid = Edition(label: "mid", production: midProduction, fixture: midFixture, fixtureKids: [], registry: .standard)
        return Profiles(editions: [old(), mid, new()])
    }
}
