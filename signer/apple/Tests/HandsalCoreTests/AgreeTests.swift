import CryptoKit
import Foundation
import HandsalCore
import HandsalKeyScan
import Testing

/// One answer of `conformance/fixtures/agree-kat.json`: public fixture keys, written by a pure Python
/// derivation and recomputed by the `cryptography` package (`_gen/tests/test_agree_kat.py`).
private struct Known {
    let id: String
    let context: String
    let key: String
    let scalar: [UInt8]
    let own: Point
    let peer: Point
    let infoHex: String

    static func all() throws -> [Known] {
        let url = Vector.root.appendingPathComponent("conformance/fixtures/agree-kat.json")
        guard case .object(let doc) = try TestJSON.parse([UInt8](try Data(contentsOf: url))), case .array(let rows)? = doc["vectors"] else {
            throw Refusal("internal")
        }
        return try rows.map { row in
            guard let id = row["id"]?.str, let context = row["context"]?.str, let key = row["key"]?.str, let info = row["info_hex"]?.str,
                  let d = row["own"]?["d"]?.str, let ox = row["own"]?["x"]?.str, let oy = row["own"]?["y"]?.str,
                  let px = row["peer"]?["x"]?.str, let py = row["peer"]?["y"]?.str else { throw Refusal("internal") }
            return Known(id: id, context: context, key: key, scalar: Vector.decodeHex(d), own: Point(x: ox, y: oy), peer: Point(x: px, y: py), infoHex: info)
        }
    }

    static func named(_ id: String) throws -> Known {
        try #require(try all().first { $0.id == id })
    }
}

private func peerValue(_ point: Point) -> JValue { .object(["x": jstr(point.x), "y": jstr(point.y)]) }
private func agreeInput(_ context: String, _ peer: Point) -> JValue { .object(["context": jstr(context), "peer": peerValue(peer)]) }
private func keyOf(_ outcome: Outcome) -> String? { resultObject(outcome)["key"]?.str }

private func rigFor(_ known: Known) -> Rig { Rig(agreeScalar: known.scalar) }

/// A peer that holds a software key, as a sender does: its public point, and the derivation done on its side.
private struct Peer {
    let key = P256.KeyAgreement.PrivateKey()
    var point: Point {
        let raw = [UInt8](key.publicKey.x963Representation)
        return Point(x: Encoding.base64url(Array(raw[1..<33])), y: Encoding.base64url(Array(raw[33..<65])))
    }

    /// The raw secret, only to prove what the signer's answer is not.
    func secret(with device: Point) throws -> [UInt8] {
        let x = try #require(Encoding.base64urlDecode(device.x)), y = try #require(Encoding.base64urlDecode(device.y))
        let other = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04] + x + y))
        return try key.sharedSecretFromKeyAgreement(with: other).withUnsafeBytes { [UInt8]($0) }
    }

    func derive(with device: Point, context: String) throws -> [UInt8] {
        let x = try #require(Encoding.base64urlDecode(device.x)), y = try #require(Encoding.base64urlDecode(device.y))
        let other = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04] + x + y))
        let info = try #require(Agreement.info(own: point, peer: device, context: context))
        return Agreement.key(from: try key.sharedSecretFromKeyAgreement(with: other), info: info)
    }
}

/// SG-16 (the `agree` command) and KC-09 (the agreement key): known answers, no prompt, nothing but the derived key
/// leaves, the signing key is not touched.
@Suite("agree (SG-16, KC-09)")
struct AgreeTests {
    @Test("sgn/agree-known-answers: the key is the pinned HKDF output for fixture keys")
    func theKnownAnswersAreDerivedFromFixtureKeys() throws {
        let vectors = try Known.all()
        #expect(vectors.count >= 5)
        for known in vectors {
            let rig = rigFor(known)
            #expect(rig.material?.agree == known.own, "\(known.id): the rig's agreement key is the fixture's")
            let out = rig.run(["agree"], agreeInput(known.context, known.peer))
            #expect(out.exit == 0 && lineText(out) == #"{"key":"\#(known.key)"}"#, "\(known.id)")
        }
    }

    @Test("the info layout: label, a zero byte, the two points in ascending order, the context")
    func theInfoLayoutIsTheOneTheSpecStates() throws {
        for known in try Known.all() {
            let info = try #require(Agreement.info(own: known.own, peer: known.peer, context: known.context))
            #expect(info.map { String(format: "%02x", $0) }.joined() == known.infoHex, "\(known.id)")
            #expect(Array(info.prefix(16)) == Array("handsal-agree/1".utf8) + [0])
            #expect(info.count == 16 + 65 + 65 + known.context.utf8.count)
        }
    }

    @Test("both parties of one pair derive the same key, whichever side asks")
    func theTwoSidesOfOnePairDeriveTheSameKey() throws {
        let basic = try Known.named("basic"), other = try Known.named("other-side")
        let first = rigFor(basic).run(["agree"], agreeInput(basic.context, basic.peer))
        let second = rigFor(other).run(["agree"], agreeInput(other.context, other.peer))
        #expect(keyOf(first) != nil && keyOf(first) == keyOf(second))
        // a sender that is not a handsal signer derives it with the same info and CryptoKit
        let sender = Peer()
        let rig = Rig()
        let device = try #require(rig.material?.agree)
        let out = rig.run(["agree"], agreeInput("mail/v1", sender.point))
        #expect(keyOf(out) == Encoding.base64url(try sender.derive(with: device, context: "mail/v1")))
    }

    @Test func aDifferentContextOrPeerGivesAnotherKey() throws {
        let rig = Rig()
        let a = Peer(), b = Peer()
        let keys = [rig.run(["agree"], agreeInput("one", a.point)), rig.run(["agree"], agreeInput("two", a.point)),
                    rig.run(["agree"], agreeInput("one", b.point))].map(keyOf)
        #expect(keys.allSatisfy { $0 != nil } && Set(keys.compactMap { $0 }).count == 3)
        #expect(rig.run(["agree"], agreeInput("one", a.point)) == rig.run(["agree"], agreeInput("one", a.point)))
        // another device's key gives another answer for the same peer and context
        let elsewhere = Rig()
        #expect(keyOf(elsewhere.run(["agree"], agreeInput("one", a.point))) != keys[0])
    }

    @Test("sgn/agree-no-prompt: no prompt, no display, no sensor, no prompt guard")
    func agreeShowsNoPromptAndNeedsNoDisplayOrSensor() throws {
        let rig = Rig(display: nil)
        rig.backend.mode = .sensorUnavailable
        let out = rig.run(["agree"], agreeInput("mail/v1", Peer().point))
        #expect(out.exit == 0 && keyOf(out) != nil)
        #expect(rig.backend.prompts.isEmpty && rig.backend.agreements == 1)
        #expect(!FileManager.default.fileExists(atPath: rig.lockPath), "the prompt guard was never taken")
        // a prompt that is open elsewhere does not stop an agreement: it is not a prompt
        let busy = Rig(maxPrompts: 0)
        #expect(busy.run(["agree"], agreeInput("mail/v1", Peer().point)).exit == 0)
        #expect(busy.display?.shown.isEmpty == true)
    }

    @Test("the answer is {key} and nothing else: 43 characters, never the shared secret")
    func theOutputIsOnlyTheDerivedKey() throws {
        let rig = Rig()
        let peer = Peer()
        let out = rig.run(["agree"], agreeInput("mail/v1", peer.point))
        let result = resultObject(out)
        #expect(Set(result.keys) == ["key"] && lineText(out).hasSuffix("\"}") && !lineText(out).contains("\n"))
        let key = try #require(result["key"]?.str)
        #expect(key.utf8.count == 43 && Encoding.base64urlDecode(key)?.count == 32)
        let secret = try peer.secret(with: try #require(rig.material?.agree))
        #expect(Encoding.base64urlDecode(key) != secret)
        #expect(!KeyScan.leaks(out.line, scalar: secret))
        // HKDF under the label is not the unlabelled one: the label is in the output's domain
        let unlabelled = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: Data(), info: Data("mail/v1".utf8), outputByteCount: 32)
        #expect(Encoding.base64urlDecode(key) != unlabelled.withUnsafeBytes { [UInt8]($0) })
    }

    @Test("the input is a closed {context, peer}: any other shape is schema_refused")
    func theInputIsAClosedObjectOfContextAndPeer() throws {
        let peer = Peer().point
        let off = Point(x: Encoding.base64url([UInt8](repeating: 1, count: 32)), y: Encoding.base64url([UInt8](repeating: 2, count: 32)))
        let bad: [JValue] = [
            .object([:]), .object(["context": jstr("a")]), .object(["peer": peerValue(peer)]),
            .object(["context": jstr("a"), "peer": peerValue(peer), "extra": .null]),
            .object(["context": jstr("a"), "peer": peerValue(peer), "label": jstr("x")]),
            agreeInput("", peer), agreeInput(String(repeating: "a", count: 129), peer), agreeInput("has space", peer),
            agreeInput("tab\t", peer), agreeInput("caf\u{e9}", peer), agreeInput("new\nline", peer), agreeInput("a\u{7f}", peer),
            agreeInput("quo\"te", peer), agreeInput("back\\slash", peer),
            .object(["context": .null, "peer": peerValue(peer)]), .object(["context": jstr("a"), "peer": .null]),
            .object(["context": jstr("a"), "peer": jstr("x")]),
            .object(["context": jstr("a"), "peer": .object(["x": jstr(peer.x)])]),
            .object(["context": jstr("a"), "peer": .object(["x": jstr(peer.x), "y": jstr(peer.y), "z": jstr("q")])]),
            .object(["context": jstr("a"), "peer": .object(["x": jstr(peer.x + "="), "y": jstr(peer.y)])]),
            agreeInput("a", off), .array([]), jstr("x"),
        ]
        for input in bad {
            let rig = Rig()
            let out = rig.run(["agree"], input)
            #expect(out.exit == 2 && lineText(out) == errorLine("schema_refused"), "\(input)")
            #expect(rig.backend.agreements == 0)
        }
        // the edges of the form are accepted: one character, and 128 printable characters up to the tilde
        for context in ["a", String(repeating: "~", count: 128), "!#$%&'()*+,-./0129:;<=>?@AZ[]^_`az{|}~"] {
            #expect(Rig().run(["agree"], agreeInput(context, peer)).exit == 0, Comment(rawValue: context))
        }
    }

    @Test("SG-08 order: the form is decided before the key, then key_unavailable")
    func withoutAKeyItIsKeyUnavailableAfterTheForm() {
        let peer = Peer().point
        let none = Rig(person: nil)
        let refused = none.run(["agree"], .object(["context": jstr("a")]))
        #expect(refused.exit == 2 && lineText(refused) == errorLine("schema_refused"))
        let missing = none.run(["agree"], agreeInput("a", peer))
        #expect(missing.exit == 3 && lineText(missing) == errorLine("key_unavailable"))
        // a key of another class than the build's is the same refusal as for sign
        let foreign = Rig(person: nil, keyClass: "apple-se-bio")
        foreign.backend.storedClass = "test-sw-p256"
        _ = try? foreign.backend.create(label: "laptop", person: "alice") { _ in }
        let wrong = foreign.run(["agree"], agreeInput("a", peer))
        #expect(wrong.exit == 3 && lineText(wrong) == errorLine("key_unavailable"))
        #expect(none.backend.agreements == 0 && foreign.backend.agreements == 0)
    }

    @Test func agreeReadsOneObjectFromStdinAndIsNotAnotherCommandsInput() {
        let rig = Rig()
        var read = 0
        let out = CLI.run(arguments: ["agree"], readStdin: { read += 1; return Array("{}".utf8) }, environment: rig.env)
        #expect(read == 1 && out.exit == 2 && lineText(out) == errorLine("schema_refused"))
        let extra = rig.run(["agree", "now"])
        #expect(extra.exit == 2 && lineText(extra) == errorLine("unsupported_command"))
        let oversized = rig.run(["agree"], [UInt8](repeating: 0x20, count: Limits.maxInput + 1))
        #expect(oversized.exit == 2 && lineText(oversized) == errorLine("schema_refused"))
    }

    @Test("the signing key is not used: a failure of the signing key does not stop an agreement")
    func aBiometricChangeLeavesTheAgreementKeyUsable() throws {
        let rig = Rig()
        let peer = Peer()
        let before = rig.run(["agree"], agreeInput("mail/v1", peer.point))
        rig.backend.mode = .invalidatedAtSign
        let signed = rig.run(["sign"], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)])))
        #expect(signed.exit == 3 && lineText(signed) == errorLine("key_unavailable"))
        #expect(rig.run(["agree"], agreeInput("mail/v1", peer.point)) == before)
        rig.backend.mode = .cancel
        #expect(rig.run(["agree"], agreeInput("mail/v1", peer.point)) == before)
    }

    @Test("agreement keys never sign: a signature verifies under the sign key and under no other")
    func aSignatureNeverVerifiesUnderTheAgreementKey() throws {
        let rig = Rig()
        let out = rig.run(["sign"], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)])))
        let parts = try jwsParts(of: out)
        let material = try #require(rig.material)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(parts.signature))
        #expect(try publicKey(material).isValidSignature(signature, for: Data(parts.signingInput)))
        let x = try #require(Encoding.base64urlDecode(material.agree.x)), y = try #require(Encoding.base64urlDecode(material.agree.y))
        let agreeKey = try P256.Signing.PublicKey(x963Representation: Data([0x04] + x + y))
        #expect(!agreeKey.isValidSignature(signature, for: Data(parts.signingInput)))
        #expect(material.kid == Encoding.thumbprint(x: material.sign.x, y: material.sign.y) && material.sign != material.agree)
        // and the command that uses the agreement key returns no signature and no jws
        let agreed = rig.run(["agree"], agreeInput("mail/v1", Peer().point))
        #expect(Set(resultObject(agreed).keys) == ["key"] && !lineText(agreed).contains("jws"))
    }

    @Test("the agreement scalar and the shared secret appear in no output (SG-03 for the new command)")
    func theAgreementScalarAndTheSecretAreInNoOutput() throws {
        let rig = Rig()
        let peers = [Peer(), Peer()]
        let outs = peers.map { rig.run(["agree"], agreeInput("mail/v1", $0.point)) }
        let agreeScalar = try #require(rig.backend.agreementScalar), signScalar = try #require(rig.backend.privateScalar)
        var seen = outs.flatMap { $0.line }
        seen += Array((rig.display?.text ?? "").utf8)
        seen += rig.backend.prompts.flatMap { Array($0.utf8) }
        #expect(outs.allSatisfy { $0.exit == 0 } && seen.count > 80)
        #expect(!KeyScan.leaks(seen, scalar: agreeScalar) && !KeyScan.leaks(seen, scalar: signScalar))
        for peer in peers { #expect(!KeyScan.leaks(seen, scalar: try peer.secret(with: try #require(rig.material?.agree)))) }
    }

    // MARK: the port, read as source (the same technique as the LAContext rule of SG-05)

    private func source(_ path: String) throws -> String {
        try String(contentsOf: Vector.root.appendingPathComponent("signer/apple/Sources/" + path), encoding: .utf8)
    }

    private func code(_ text: String) -> [String] {
        text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init).filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
    }

    @Test("no API returns the shared secret: only derived bytes cross the port")
    func noApiReturnsTheSharedSecret() throws {
        let backend = code(try source("HandsalCore/KeyBackend.swift")).joined(separator: "\n")
        #expect(backend.contains("func agree(peer: Point, info: [UInt8]) throws -> [UInt8]"))
        #expect(!backend.contains("SharedSecret") && !backend.contains("sharedSecret"))
        // the one place that makes bytes of a shared secret is the derivation, and it makes the derived key
        var owners: [String: [String]] = [:]
        for file in ["HandsalCore", "HandsalSecureEnclave", "HandsalCeremonyCore", "HandsalPinCore", "HandsalLinkCore"] {
            let directory = Vector.root.appendingPathComponent("signer/apple/Sources/" + file).path
            for name in try FileManager.default.contentsOfDirectory(atPath: directory) where name.hasSuffix(".swift") {
                let text = code(try String(contentsOfFile: directory + "/" + name, encoding: .utf8)).joined(separator: "\n")
                for needle in ["hkdfDerivedSymmetricKey", "x963DerivedSymmetricKey", "sharedSecretFromKeyAgreement", "SharedSecret"]
                where text.contains(needle) {
                    owners[needle, default: []].append(file + "/" + name)
                }
            }
        }
        #expect(owners["hkdfDerivedSymmetricKey"] == ["HandsalCore/Agreement.swift"])
        #expect(owners["x963DerivedSymmetricKey"] == nil)
        #expect(owners["sharedSecretFromKeyAgreement"] == ["HandsalSecureEnclave/SecureEnclaveBackend.swift"])
        #expect(Set(owners["SharedSecret"] ?? []) == ["HandsalCore/Agreement.swift"])
    }

    @Test("the Secure Enclave backend uses the agreement blob only to agree and the signing blob only to sign")
    func eachKeyBlobHasOneUse() throws {
        let text = try source("HandsalSecureEnclave/SecureEnclaveBackend.swift")
        func body(of signature: String) throws -> String {
            let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            let start = try #require(lines.firstIndex { $0.contains(signature) })
            let indent = lines[start].prefix { $0 == " " }.count
            var end = start + 1
            while end < lines.count, !(lines[end].prefix { $0 == " " }.count == indent && lines[end].trimmingCharacters(in: .whitespaces).hasPrefix("}")) { end += 1 }
            return lines[start...end].joined(separator: "\n")
        }
        let sign = try body(of: "public func sign("), agree = try body(of: "public func agree(")
        #expect(sign.contains("signBlob") && !sign.contains("agreeBlob") && !sign.contains("KeyAgreement"))
        #expect(agree.contains("agreeBlob") && !agree.contains("signBlob") && !agree.contains("Signing"))
        // agree builds no authentication context, asks no policy and shows nothing
        #expect(!agree.contains("LAContext") && !agree.contains("authenticationContext") && !agree.contains("policy") && !agree.contains("ready"))
    }

    @Test("access control: the signing key keeps biometryCurrentSet, the agreement key is private-key-usage only")
    func theAgreementKeyIsCreatedWithoutPresence() throws {
        let lines = code(try source("HandsalSecureEnclave/SecureEnclaveBackend.swift"))
        let flagged = lines.filter { $0.contains("biometryCurrentSet") }
        #expect(flagged.count == 1, "the one place that asks for a presence flag")
        let text = lines.joined(separator: "\n")
        #expect(text.contains("SecureEnclave.P256.Signing.PrivateKey(accessControl: signingControl)"))
        #expect(text.contains("SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: agreementControl)"))
        #expect(!text.contains("KeyAgreement.PrivateKey(accessControl: signingControl)"))
        let signingFlags = try #require(lines.first { $0.contains("signingFlags") && $0.contains("[") })
        let agreementFlags = try #require(lines.first { $0.contains("agreementFlags") && $0.contains("[") })
        #expect(signingFlags.contains(".privateKeyUsage") && signingFlags.contains(".biometryCurrentSet"))
        #expect(agreementFlags.contains(".privateKeyUsage"))
        for presence in ["biometry", "userPresence", "devicePasscode", ".or", ".and", "applicationPassword"] {
            #expect(!agreementFlags.contains(presence), Comment(rawValue: presence))
        }
    }
}
