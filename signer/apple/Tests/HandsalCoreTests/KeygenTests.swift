import Foundation
import HandsalCore
import Testing

private func keygenInput(label: String = "laptop", person: String = "alice") -> JValue {
    .object(["label": jstr(label), "person": jstr(person)])
}

private func point(_ value: JValue?) -> (String, String)? {
    guard case .object(let m)? = value, case .string(let x)? = m["x"], case .string(let y)? = m["y"], m.count == 2 else { return nil }
    return (x, y)
}

/// SG-03 and the CF-07 signer list: sgn/key-create-kid-thumbprint, sgn/keygen-refuses-existing,
/// sgn/keygen-shows-kid12, sgn/pubkey-no-prompt, sgn/pubkey-shows-kid12.
@Suite("keygen and pubkey (SG-03)")
struct KeygenTests {
    @Test("sgn/key-create-kid-thumbprint: kid is the thumbprint of sign, agree differs")
    func keygenReturnsTheThumbprintAndADistinctAgreementKey() throws {
        let rig = Rig(person: nil)
        let out = rig.run(["keygen"], keygenInput())
        #expect(out.exit == 0)
        let result = resultObject(out)
        #expect(Set(result.keys) == ["agree", "class", "kid", "sign"])
        let sign = try #require(point(result["sign"])), agree = try #require(point(result["agree"]))
        #expect(result["kid"] == jstr(Encoding.thumbprint(x: sign.0, y: sign.1)))
        #expect(sign != agree)
        #expect(result["class"] == jstr("test-sw-p256"))
        #expect(lineText(out).hasPrefix(#"{"agree":{"x":""#) && !lineText(out).contains("\n"))
        // the keys are real: both points are on P-256 and the key set passes the profile's own check
        #expect(DeviceKey.defect(kid: try #require(result["kid"]?.str), sign: try #require(result["sign"]), agree: try #require(result["agree"])) == nil)
        // a second run of the same command with another person and class gives other keys
        let other = Rig(person: nil, keyClass: "apple-se-bio")
        let again = other.run(["keygen"], keygenInput(person: "bob"))
        #expect(resultObject(again)["class"] == jstr("apple-se-bio") && resultObject(again)["kid"] != result["kid"])
    }

    @Test("sgn/keygen-refuses-existing: key_exists, exit 2, the existing key untouched")
    func aSecondKeygenNeverOverwrites() throws {
        let rig = Rig(person: nil)
        let first = resultObject(rig.run(["keygen"], keygenInput()))
        let before = try #require(rig.material)
        let out = rig.run(["keygen"], keygenInput(label: "other", person: "bob"))
        #expect(out.exit == 2 && lineText(out) == errorLine("key_exists"))
        #expect(rig.material == before && rig.backend.creations == 1)
        #expect(resultObject(rig.run(["pubkey"]))["kid"] == first["kid"])
    }

    @Test func anEqualAgreementKeyIsInternalAndLeavesNoKey() {
        let rig = Rig(person: nil)
        rig.backend.makesEqualPair = true
        let out = rig.run(["keygen"], keygenInput())
        #expect(out.exit == 5 && lineText(out) == errorLine("internal"))
        #expect(rig.material == nil && rig.backend.creations == 0)
        // the refusal is the profile's key check, not a one-off: the same rig makes a good key afterwards
        rig.backend.makesEqualPair = false
        #expect(rig.run(["keygen"], keygenInput()).exit == 0 && rig.backend.creations == 1)
    }

    @Test func keygenInputIsAClosedObjectOfLabelAndPerson() {
        let bad: [JValue] = [
            .object([:]), .object(["label": jstr("laptop")]), .object(["person": jstr("alice")]),
            .object(["label": jstr("laptop"), "person": jstr("alice"), "extra": .null]),
            .object(["label": jstr(""), "person": jstr("alice")]), .object(["label": jstr(String(repeating: "a", count: 65)), "person": jstr("alice")]),
            .object(["label": jstr("laptop"), "person": jstr("Alice")]), .object(["label": .null, "person": jstr("alice")]),
            .array([]), jstr("x"),
        ]
        for input in bad {
            let rig = Rig(person: nil)
            let out = rig.run(["keygen"], input)
            #expect(out.exit == 2 && lineText(out) == errorLine("schema_refused"))
            #expect(rig.material == nil)
        }
    }

    @Test("sgn/keygen-shows-kid12: the line goes to the display channel and not to stdout")
    func keygenShowsTheKidLineOnTheDisplayOnly() throws {
        let rig = Rig(person: nil)
        let out = rig.run(["keygen"], keygenInput(person: "alice"))
        let kid = try #require(resultObject(out)["kid"]?.str)
        #expect(rig.display?.text == "Key \(Render.kid12(kid)) for alice, class test-sw-p256\n")
        #expect(!lineText(out).contains("Key ") && !lineText(out).contains(Render.kid12(kid)))
        let other = Rig(person: nil, keyClass: "apple-se-bio")
        let second = other.run(["keygen"], keygenInput(person: "carol"))
        #expect(other.display?.text == "Key \(Render.kid12(try #require(resultObject(second)["kid"]?.str))) for carol, class apple-se-bio\n")
    }

    @Test func keygenWithoutADisplayChannelIsNoDisplayAndCreatesNothing() {
        let rig = Rig(person: nil, display: nil)
        let out = rig.run(["keygen"], keygenInput())
        #expect(out.exit == 4 && lineText(out) == errorLine("no_display"))
        #expect(rig.material == nil && rig.backend.creations == 0)
    }

    @Test("sgn/pubkey-no-prompt and sgn/pubkey-shows-kid12: the same object as keygen")
    func pubkeyReturnsTheKeygenObjectWithoutAPrompt() throws {
        let rig = Rig(person: nil)
        let made = rig.run(["keygen"], keygenInput(person: "alice"))
        let shownByKeygen = rig.display?.shown.count
        let out = rig.run(["pubkey"])
        #expect(out.exit == 0 && out == made)
        #expect(rig.backend.prompts.isEmpty)
        #expect(rig.display?.shown.count == (shownByKeygen ?? 0) + 1)
        #expect(rig.display?.shown.last == "Key \(Render.kid12(try #require(resultObject(out)["kid"]?.str))) for alice, class test-sw-p256\n")
        #expect(!lineText(out).contains("Key "))
    }

    @Test func pubkeyReadsNoStdinAndNeedsAKey() {
        let rig = Rig(person: nil)
        var read = false
        let out = CLI.run(arguments: ["pubkey"], readStdin: { read = true; return [] }, environment: rig.env)
        #expect(!read && out.exit == 3 && lineText(out) == errorLine("key_unavailable"))
        #expect(rig.display?.shown.isEmpty == true)
    }

    @Test("sgn/info-no-prompt: version shows no prompt and needs no key or display")
    func versionShowsNoPrompt() {
        let rig = Rig(person: nil, display: nil)
        let out = rig.run(["version"])
        #expect(out.exit == 0 && rig.backend.prompts.isEmpty && rig.backend.creations == 0)
        #expect(Set(resultObject(out).keys) == ["class", "impl", "spec"])
        let bound = Rig()
        #expect(bound.run(["version"]) == out && bound.backend.prompts.isEmpty)
    }
}
