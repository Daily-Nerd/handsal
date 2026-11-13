import Foundation
import HandsalCore
import Testing

private let x = "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM"
private let y = "KMpi6U7y-MWc6GZvXfhVK1imccl2_0ZhBrP8p1lA0Sw"
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
private let agreeX = "GnEkTo7EpA3CgI-cW-9HF9-PGHDbwkcJ5KebUl3SfGQ"
private let agreeY = "2uUIevgMQObsWEYt2uruvbqcgugPMXmnncoodHcJ9zQ"

private func point(_ x: String, _ y: String) -> JValue { .object(["x": .string(x), "y": .string(y)]) }

@Suite("device keys (ACT-11)")
struct DeviceKeyTests {
    @Test func fixtureKeysAreOnTheCurve() {
        #expect(DeviceKey.pointOk(point(x, y)))
        #expect(DeviceKey.pointOk(point(agreeX, agreeY)))
    }

    @Test func refusesOffCurveAndMalformedPoints() {
        #expect(!DeviceKey.pointOk(point(x, x)))                                   // not on the curve
        #expect(!DeviceKey.pointOk(point(y, x)))
        #expect(!DeviceKey.pointOk(point(String(repeating: "A", count: 43), String(repeating: "A", count: 43))))
        #expect(!DeviceKey.pointOk(point(String(repeating: "_", count: 42) + "w", y)))   // coordinate above p
        #expect(!DeviceKey.pointOk(point(x, "short")))
        #expect(!DeviceKey.pointOk(.object(["x": .string(x)])))
        #expect(!DeviceKey.pointOk(.object(["x": .string(x), "y": .string(y), "z": .null])))
        #expect(!DeviceKey.pointOk(.string("p")))
    }

    @Test func defectNamesTheFirstProblemInOrder() {
        #expect(DeviceKey.defect(kid: kid, sign: point(x, y), agree: point(agreeX, agreeY)) == nil)
        #expect(DeviceKey.defect(kid: kid, sign: point(x, x), agree: point(agreeX, agreeY)) == "sign_point")
        #expect(DeviceKey.defect(kid: kid, sign: point(x, y), agree: point(x, x)) == "agree_point")
        #expect(DeviceKey.defect(kid: String(kid.dropLast()) + "J", sign: point(x, y), agree: point(agreeX, agreeY)) == "kid_not_thumbprint")
        #expect(DeviceKey.defect(kid: kid, sign: point(x, y), agree: point(x, y)) == "agree_equals_sign")
    }
}

@Suite("profiles (CF-01)")
struct ProfileTests {
    /// The embedded core manifest is a copy; the files are the truth. A change to any core file
    /// fails this test until `Profiles.coreManifest` is updated.
    @Test func embeddedManifestMatchesTheCoreFiles() throws {
        #expect(Set(Profiles.coreManifest.keys) == ["conformance/CONTRACT.md", "conformance/fixtures/fixture-kids.json",
                                                    "conformance/fixtures/keys.json", "spec/profile.md", "spec/registry.json"])
        for (path, hash) in Profiles.coreManifest {
            let bytes = [UInt8](try Data(contentsOf: Vector.root.appendingPathComponent(path)))
            #expect(Encoding.hashstr(bytes) == hash, "\(path)")
        }
    }

    @Test func fixtureKidListMatchesTheFile() throws {
        let bytes = [UInt8](try Data(contentsOf: Vector.root.appendingPathComponent("conformance/fixtures/fixture-kids.json")))
        guard case .array(let items) = try TestJSON.parse(bytes) else { Issue.record("not a list"); return }
        #expect(Profiles.standard.fixtureKids == Set(items.compactMap { if case .string(let s) = $0 { return s } else { return nil } }))
        #expect(Profiles.standard.fixtureKids.count == items.count)
    }

    @Test func profileHashesAreTheHashOfTheCanonicalManifest() throws {
        for kind in ["production", "fixture"] {
            let manifest = JValue.object(Profiles.coreManifest.mapValues { .string($0) })
            let want = Encoding.hashstr(try Emit.subset(.object(["core": manifest, "kind": .string(kind)])))
            #expect(Profiles.standard.kind(want) == kind)
        }
        #expect(Profiles.standard.production != Profiles.standard.fixture)
        #expect(Profiles.standard.kind(Encoding.emptyHash) == nil)
    }

    /// The pins are computed with openssl from the files by `tools/repin.py` and live in `conformance/pins.json`
    /// only; the Swift table is a copy and this is where its answer meets the independent one.
    @Test func profileHashesAreThePinsComputedOutsideTheCode() throws {
        let bytes = [UInt8](try Data(contentsOf: Vector.root.appendingPathComponent("conformance/pins.json")))
        guard case .object(let pins) = try TestJSON.parse(bytes) else { Issue.record("not an object"); return }
        #expect(pins["production_profile"] == .string(Profiles.standard.production))
        #expect(pins["fixture_profile"] == .string(Profiles.standard.fixture))
    }

    /// Anchor from the vectors: the fixture-profile genesis document names this profile hash.
    @Test func fixtureProfileHashMatchesTheVectors() throws {
        let row = try Vector.load(commands: ["render"]).first { $0.name == "rnd/genesis-sign-original" }
        guard case .json(.object(let input))? = row?.input, case .object(let attachments)? = input["attachments"],
              case .object(let doc)? = attachments["document"], case .string(let profile)? = doc["profile"] else {
            Issue.record("vector missing"); return
        }
        #expect(Profiles.standard.kind(profile) == "fixture")
    }
}
