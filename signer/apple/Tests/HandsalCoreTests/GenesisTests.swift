@testable import HandsalCore
import Testing

private func str(_ s: String) -> JValue { .string(s) }
private let x = "FlB1fHw5iyiPztQWGC4EItUeI1M2QdzM75XyJLJA5wM"

/// The valid fixture-profile original that `rnd/genesis-sign-original` renders.
private func original() throws -> JValue {
    let row = try Vector.load(commands: ["render"]).first { $0.name == "rnd/genesis-sign-original" }
    guard case .json(.object(let input))? = row?.input, case .object(let attachments)? = input["attachments"],
          let doc = attachments["document"] else { throw Refusal("vector missing") }
    return doc
}

/// `value` with the node at `path` replaced (nil removes a key).
private func setting(_ value: JValue, _ path: [Any], _ new: JValue?) -> JValue {
    guard let head = path.first else { return new ?? .null }
    let rest = Array(path.dropFirst())
    switch value {
    case .object(var members):
        let key = head as! String
        if rest.isEmpty { members[key] = new } else if let child = members[key] { members[key] = setting(child, rest, new) }
        return .object(members)
    case .array(var items):
        let index = head as! Int
        items[index] = setting(items[index], rest, new)
        return .array(items)
    default: return value
    }
}

private func expect(_ code: String, _ doc: JValue, _ ctx: GenesisContext = GenesisContext(), sourceLocation: SourceLocation = #_sourceLocation) {
    #expect(throws: Refusal(code), sourceLocation: sourceLocation) { try Genesis.checkAlone(doc, ctx) }
}

@Suite("genesis document alone (GP-15 steps 1 and 3)")
struct GenesisTests {
    @Test func aValidOriginalPasses() throws {
        try Genesis.checkAlone(original())
    }

    @Test func documentHashIsTheHashOfItsCanonicalBytes() throws {
        let doc = try original()
        #expect(try Genesis.docHash(doc) == Encoding.hashstr(Emit.subset(doc)))
    }

    @Test func structureDefectsAreGenesisSchema() throws {
        let doc = try original()
        for bad in [
            setting(doc, ["v"], str("handsal-genesis/2")), setting(doc, ["name"], str("")),
            setting(doc, ["name"], str(String(repeating: "n", count: 25))), setting(doc, ["profile"], str("x")),
            setting(doc, ["org"], str(Encoding.emptyHash)), setting(doc, ["head"], str(Encoding.emptyHash)),
            setting(doc, ["members"], .array([])), setting(doc, ["devices"], .array([])),
            setting(doc, ["extra"], .null), setting(doc, ["name"], nil), setting(doc, ["prev"], str(Encoding.emptyHash)),
            setting(doc, ["members", 1, "id"], str("alice")),                       // duplicate member
            setting(doc, ["devices", 0, "person"], str("zed")),                     // person not a member
            setting(doc, ["devices", 0, "label"], str("a\"b")),
            setting(doc, ["devices", 0, "class"], .null),
            setting(doc, ["devices", 0, "sign"], .object(["x": str(x)])),
            setting(doc, ["devices", 0, "extra"], .null),
            setting(doc, ["name"], .number("1")),                                    // a number is outside the subset
            setting(doc, ["members", 0, "role"], str("Maintainer")),
            .null, .array([]),
        ] { expect("genesis_schema", bad) }
        // a member without a device
        var members = [JValue]()
        if case .array(let existing)? = (try? original()).flatMap({ if case .object(let o) = $0 { return o["members"] } else { return nil } }) { members = existing }
        expect("genesis_schema", setting(doc, ["members"], .array(members + [.object(["id": str("dave"), "role": str("member")])])))
    }

    @Test func aChangeNeedsOrgAndHead() throws {
        let doc = try original()
        let change = setting(setting(setting(doc, ["prev"], str(Encoding.hashstr([1]))), ["org"], str(Encoding.hashstr([2]))),
                             ["head"], str(Encoding.hashstr([3])))
        try Genesis.checkAlone(change)
        expect("genesis_schema", setting(change, ["head"], nil))
        expect("genesis_schema", setting(change, ["org"], .null))
    }

    @Test func sortOrderIsRequired() throws {
        guard case .object(let o) = try original(), case .array(let devices)? = o["devices"], case .array(let members)? = o["members"],
              case .object(let pol)? = o["policy"], case .array(let roles)? = pol["roles"] else { return }
        let doc = try original()
        expect("doc_not_sorted", setting(doc, ["devices"], .array(devices.reversed())))
        expect("doc_not_sorted", setting(doc, ["members"], .array(members.reversed())))
        expect("doc_not_sorted", setting(doc, ["policy", "roles"], .array(roles.reversed())))
    }

    @Test func deviceKeyDefects() throws {
        let doc = try original()
        expect("genesis_key_invalid", setting(doc, ["devices", 0, "sign", "y"], str(x)))
        expect("genesis_key_invalid", setting(doc, ["devices", 0, "kid"], str("NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY")))
        guard case .object(let o) = doc, case .array(let devices)? = o["devices"] else { return }
        expect("duplicate_key", setting(doc, ["devices"], .array([devices[0]] + devices)))
        // the agreement key of one device is the agreement key of another
        expect("duplicate_key", setting(doc, ["devices", 1, "agree"], { if case .object(let d) = devices[0], let a = d["agree"] { return a } else { return .null } }()))
    }

    @Test func policyDefectsInOrder() throws {
        let doc = try original()
        expect("policy_invalid", setting(doc, ["policy"], nil))
        expect("policy_invalid", setting(doc, ["policy", "v"], str("handsal-policy/2")))
        expect("policy_invalid", setting(doc, ["policy", "rules", "member.add"], nil))
        expect("policy_invalid", setting(doc, ["policy", "rules", "member.add", "persons"], str("two")))
        expect("policy_invalid", setting(doc, ["policy", "rules", "member.add", "roles"], .array([str("ghost")])))
        expect("policy_invalid", setting(doc, ["policy", "witness"], .object(["mode": str("bogus")])))
        expect("policy_invalid", setting(doc, ["policy", "freshness", "clock_skew_s"], str("x")))
        expect("policy_out_of_bounds", setting(doc, ["policy", "freshness", "clock_skew_s"], str("3601")))
        expect("policy_out_of_bounds", setting(doc, ["policy", "freshness", "max_validity_s"], str("59")))
        expect("policy_out_of_bounds", setting(doc, ["policy", "rules", "member.add", "persons"], str("16")))
        expect("policy_unreachable", setting(doc, ["policy", "rules", "member.add", "persons"], str("3")))
        // shape is checked before bounds
        expect("policy_invalid", setting(setting(doc, ["policy", "freshness", "clock_skew_s"], str("3601")), ["policy", "v"], str("x")))
    }

    @Test func classCodes() throws {
        let doc = try original()
        func classes(_ id: String, _ uv: String) -> JValue { .array([.object(["class": str(id), "user_verification": str(uv)])]) }
        expect("class_unknown", setting(doc, ["policy", "classes"], classes("nope", "none")))
        // the first tag is macOS only: the Windows class is not in the registry (T7.7), so it is unknown
        expect("class_unknown", setting(doc, ["policy", "classes"], classes("win-hello-hw", "biometric_only")))
        expect("class_test_only", setting(doc, ["policy", "classes"], classes("test-sw-p256", "none")))
        expect("class_policy_mismatch", setting(doc, ["policy", "classes"], classes("apple-se-bio", "none")))
        // a device of a class the policy does not accept
        expect("genesis_schema", setting(doc, ["devices", 0, "class"], str("fixture-pin")))
    }

    /// KC-02: no tagged registry has a `pending-spike` class, so the rule is proven on a registry built here.
    @Test func aPendingClassIsRefusedOnARegistryThatHasOne() throws {
        let registry = Registry.standard.addingClass(ClassSpec(id: "later-hw", status: "pending-spike", userVerification: nil))
        let doc = try original()
        let classes = JValue.array([.object(["class": str("later-hw"), "user_verification": str("biometric_only")])])
        expect("class_pending", setting(doc, ["policy", "classes"], classes), GenesisContext(registry: registry))
        #expect(Registry.standard.classes["later-hw"] == nil)
    }

    @Test func roleHoldersNeedABiometricOnlyKey() throws {
        let doc = try original()
        let policyClasses = JValue.array([.object(["class": str("apple-se-bio"), "user_verification": str("biometric_only")]),
                                          .object(["class": str("fixture-pin"), "user_verification": str("biometric_or_pin")])])
        let both = setting(doc, ["policy", "classes"], policyClasses)
        try Genesis.checkAlone(both)
        expect("role_key_class", setting(both, ["devices", 0, "class"], str("fixture-pin")))
        // the fixture-only class is not a class under the production profile
        let production = setting(both, ["profile"], str(Profiles.standard.production))
        expect("class_unknown", production)
    }

    @Test func fixtureKidsAreRefusedUnderTheProductionProfileOnly() throws {
        let doc = try original()
        let production = setting(doc, ["profile"], str(Profiles.standard.production))
        expect("fixture_key", production)
        let unknown = setting(doc, ["profile"], str(Encoding.hashstr([9])))
        try Genesis.checkAlone(unknown)        // step 2 belongs to the fold: an unknown profile is no defect here
    }

    @Test func witnessRelayShapeAndBounds() throws {
        let row = try Vector.load(commands: ["render"]).first { $0.name == "wit/render-genesis-witness-relay" }
        guard case .json(.object(let input))? = row?.input, case .object(let attachments)? = input["attachments"],
              let doc = attachments["document"] else { Issue.record("vector missing"); return }
        try Genesis.checkAlone(doc)
        expect("policy_invalid", setting(doc, ["policy", "witness", "relay_kid"], str(x)))
        expect("policy_invalid", setting(doc, ["policy", "witness", "extra"], .null))
        expect("policy_invalid", setting(doc, ["policy", "witness", "relay_pub_jwk", "crv"], str("P-384")))
        expect("policy_invalid", setting(doc, ["policy", "witness", "max_tip_age_s"], str("x")))
        expect("policy_out_of_bounds", setting(doc, ["policy", "witness", "max_tip_age_s"], str("59")))
        expect("policy_out_of_bounds", setting(doc, ["policy", "witness", "max_tip_age_s"], str("86401")))
    }
}

/// `Render.genesisText` is what the enrollment ceremony shows (SG-12 step 5): the same words the
/// signer's render of a `genesis.sign` holds.
@Suite("genesis text for the ceremony (RN-08, RN-10)")
struct GenesisTextTests {
    @Test func anOriginalIsShownInFullWithItsFirstLine() throws {
        let doc = try original()
        let shown = try Render.genesisText(document: doc, previous: nil)
        #expect(shown.firstLine.hasPrefix("Sign genesis of example (") && shown.firstLine.hasSuffix("): 3 members, 3 devices"))
        #expect(shown.lines.contains("Members:") && shown.lines.contains("  - alice maintainer") && shown.lines.contains("Devices:"))
        #expect(shown.lines.contains { $0.hasPrefix("Document hash: ") }, "an original has a document hash line")
        #expect(shown.lines.contains("Policy:") && shown.lines.contains { $0.contains("Witness") || $0.contains("witness") }, "the policy and its witness are shown")
    }

    @Test func theRenderOfTheSignedActHoldsExactlyThoseWords() throws {
        let row = try #require(try Vector.load(commands: ["render"]).first { $0.name == "rnd/genesis-sign-original" })
        guard case .json(.object(let input)) = row.input, let doc = input["attachments"]?["document"] else { Issue.record("no document"); return }
        let shown = try Render.genesisText(document: doc, previous: nil)
        let anchor = try #require(row.anchor)
        for line in [shown.firstLine] + shown.lines { #expect(anchor.contains(line.replacingOccurrences(of: "\"", with: "\\\"")), "\(line)") }
    }

    @Test func aChangeIsShownAsADifference() throws {
        let doc = try original()
        let change = setting(setting(doc, ["prev"], str(try Genesis.docHash(doc))), ["org"], str(try Genesis.docHash(doc)))
        let withHead = setting(change, ["head"], str(Encoding.hashstr(Array("h".utf8))))
        let shown = try Render.genesisText(document: withHead, previous: doc)
        #expect(shown.firstLine.hasPrefix("Change example (") && shown.firstLine.hasSuffix("policy same"))
        #expect(shown.lines.contains { $0.hasPrefix("Previous: ") } && shown.lines.contains { $0.hasPrefix("Head: ") })
        #expect(shown.lines.contains { $0.hasPrefix("Unchanged: 3 devices, 3 members") })
    }

    @Test func aDocumentThatIsNotValidAloneIsRefusedWithItsCode() throws {
        let doc = try original()
        #expect(throws: Refusal("genesis_schema")) { try Render.genesisText(document: setting(doc, ["name"], nil), previous: nil) }
        #expect(throws: Refusal("genesis_schema")) { try Render.genesisText(document: .null, previous: nil) }
    }
}
