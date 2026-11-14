import CryptoKit
import Foundation
import HandsalCore
import Testing

private let order = SoftwareBackend.order
private let half = Vector.decodeHex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")

private func isLow(_ signature: [UInt8]) -> Bool {
    let s = Array(signature[32..<64])
    return s == half || s.lexicographicallyPrecedes(half)
}

/// SG-04, SG-06, SG-07 and the CF-07 signer list for `sign`.
@Suite("sign sequence (SG-04, SG-06, SG-07)")
struct SignTests {
    private func signed(_ rig: Rig, _ draft: JValue = verdictDraft(), _ attachments: JValue = .object(["request_b64": jstr(requestB64)])) -> Outcome {
        rig.run(["sign"], signInput(draft, attachments))
    }

    @Test("sgn/output-shape: {jws, receipt_id}, the jws verifies and the payload passes the act checks")
    func theSuccessOutputIsAJwsAndItsReceiptId() throws {
        let rig = Rig()
        let out = signed(rig)
        #expect(out.exit == 0 && !lineText(out).contains("\n"))
        let result = resultObject(out)
        #expect(Set(result.keys) == ["jws", "receipt_id"])
        let jws = try #require(result["jws"]?.str)
        let parts = try #require(SplitJWS(jws))
        let material = try #require(rig.material)
        // ES256 over b64url(header).b64url(payload), raw 64 bytes, low S
        #expect(parts.signature.count == 64 && isLow(parts.signature))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(parts.signature))
        #expect(try publicKey(material).isValidSignature(signature, for: Data(parts.signingInput)))
        #expect(String(decoding: parts.header, as: UTF8.self) == #"{"alg":"ES256","kid":"\#(material.kid)"}"#)
        // the payload is the canonical bytes of the payload the signer built, and the id is its hash
        #expect(result["receipt_id"] == jstr(Encoding.hashstr(parts.payload)))
        let parsed = try Acts.parse(jws, registry: .standard, wanted: [Methods.approve], headPresent: false)
        #expect(parsed.id == result["receipt_id"]?.str && parsed.performer == "alice" && parsed.kid == material.kid)
        #expect(parsed.payload["ts"] == jstr(Rig.ts) && parsed.payload["nonce"] == jstr(Rig.nonce))
        guard case .object(let act)? = parsed.payload["ext"]?["dev.handsal/act"] else { Issue.record("no act"); return }
        #expect(act["recipient"] == jstr("alice") && act["expires"] == jstr("2026-11-08T12:59:00Z"))
    }

    /// CF-07: the success output of `sign` passes `check-act`. The key is the fixture key of alice (public test
    /// material, `conformance/fixtures/keys.json`), so the checker finds the signer in the vector's own lineage.
    /// The verifier behind the checker is the stand-in of the checker tests (it accepts any signature that is not
    /// 64 zero bytes), because vitni is another product's binary; the signature itself is verified above, by
    /// CryptoKit, against the key's public half. A missing checker build fails the test, it never skips it.
    @Test("CF-07: the output of sign passes check-act of the reference checker")
    func theSuccessOutputPassesCheckAct() throws {
        let checker = Vector.root.appendingPathComponent("checker/python/.venv/bin/handsal-check-conformance")
        let python = Vector.root.appendingPathComponent("checker/python/.venv/bin/python")
        let stand = Vector.root.appendingPathComponent("checker/python/tests/data/fake_vitni_cli.py")
        for url in [checker, python] {
            #expect(FileManager.default.isExecutableFile(atPath: url.path), "missing \(url.path): run `uv sync --project checker/python` first")
        }
        #expect(FileManager.default.fileExists(atPath: stand.path))
        let vector = try #require(try Vector.load(commands: ["check-act"]).first { $0.name == "ok/approve" })
        guard case .json(.object(var input)) = vector.input else { Issue.record("ok/approve is not a JSON input"); return }
        let keys = try TestJSON.parse([UInt8](try Data(contentsOf: Vector.root.appendingPathComponent("conformance/fixtures/keys.json"))))
        let scalar = Vector.decodeHex(try #require(keys["keys"]?["alice.sign"]?["d"]?.str))

        // the draft is what the vector's payload says alice approved
        let theirJws = try #require(input["jws"]?.str)
        let theirs = try #require(SplitJWS(theirJws))
        let payload = try TestJSON.parse(theirs.payload)
        guard case .object(let act)? = payload["ext"]?["dev.handsal/act"] else { Issue.record("no act"); return }
        var draft: [String: JValue] = ["body": .object([:]), "expires_in_s": jstr("3600"), "method": jstr(Methods.approve)]
        for name in ["head", "org", "recipient", "relay", "request_id"] { draft[name] = act[name] }
        let rig = Rig(keyClass: "apple-se-bio", scalar: scalar)
        let out = signed(rig, .object(draft), .object(["request_b64": try #require(input["request_b64"])]))
        #expect(out.exit == 0)
        let mine = try #require(resultObject(out)["jws"])

        input["jws"] = mine
        let answer = try Self.checkAct(.object(input), checker: checker, python: python, verifier: stand)
        #expect(answer["valid"] == .bool(true) && answer["reason"] == jstr("ok"), "check-act said \(answer)")
        #expect(answer["receipt_id"] == resultObject(out)["receipt_id"])
        #expect(answer["class"] == jstr("apple-se-bio"))
    }

    /// A vector input holds nulls, which the profile's subset (and so `Emit.subset`) refuses: plain JSON for the checker.
    private static func foundation(_ value: JValue) -> Any {
        switch value {
        case .null: return NSNull()
        case .bool(let flag): return flag
        case .number(let text): return NSDecimalNumber(string: text)
        case .string(let text): return text
        case .array(let items): return items.map(foundation)
        case .object(let members): return members.mapValues(foundation)
        }
    }

    private static func checkAct(_ input: JValue, checker: URL, python: URL, verifier: URL) throws -> [String: JValue] {
        let process = Process()
        process.executableURL = checker
        process.arguments = ["--vitni", python.path, "--vitni", verifier.path, "check-act"]
        process.environment = [:]
        let stdin = Pipe(), stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        stdin.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: foundation(input), options: [.fragmentsAllowed]))
        try stdin.fileHandleForWriting.close()
        let bytes = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard case .object(let answer) = try TestJSON.parse([UInt8](bytes.filter { $0 != 0x0a })) else { return [:] }
        return answer
    }

    @Test("SG-08: a refusal that needs no key is decided before key_unavailable, and every exit 2 refusal before no_display")
    func refusalsComeBeforeTheKeyAndTheDisplay() {
        let attached = JValue.object(["request_b64": jstr(requestB64)])
        var noRelay: [String: JValue] = [:]
        if case .object(let members) = verdictDraft() { noRelay = members }
        noRelay["relay"] = nil
        let tooLong = JValue.object(["request_b64": jstr(Data(String(repeating: "x\n", count: 33).utf8).base64EncodedString())])

        // no key: the form of the draft is step 1, so it wins; what needs the key's person is key_unavailable
        let keyless = Rig(person: nil)
        #expect(lineText(keyless.run(["sign"], signInput(.object(noRelay), attached))) == errorLine("schema_refused"))
        let unbound = keyless.run(["sign"], signInput(verdictDraft(), .object([:])))
        #expect(unbound.exit == 3 && lineText(unbound) == errorLine("key_unavailable"))

        // a key and no display: every exit 2 refusal is decided before the display is asked for
        let blind = Rig(display: nil)
        for (draft, attachments, code) in [(verdictDraft(), JValue.object([:]), "attachment_missing"),
                                           (verdictDraft(recipient: "bob"), attached, "identity_mismatch"),
                                           (verdictDraft(), tooLong, "render_refused")] {
            let out = blind.run(["sign"], signInput(draft, attachments))
            #expect(out.exit == 2 && lineText(out) == errorLine(code), "\(code)")
        }
        // a good draft, a key and no display: no_display
        let missingDisplay = blind.run(["sign"], signInput(verdictDraft(), attached))
        #expect(missingDisplay.exit == 4 && lineText(missingDisplay) == errorLine("no_display"))
        #expect(blind.backend.prompts.isEmpty)

        // no key and no display: the key comes first
        let neither = Rig(person: nil, display: nil).run(["sign"], signInput(verdictDraft(), attached))
        #expect(neither.exit == 3 && lineText(neither) == errorLine("key_unavailable"))
    }

    @Test("what is signed is what was shown: the render, then Signing as, and line 1 is the prompt text")
    func theDisplayShowsTheRenderBeforeThePrompt() throws {
        let rig = Rig()
        let out = signed(rig)
        let material = try #require(rig.material)
        let rendered = resultObject(rig.run(["render"], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)]))))
        let renderText = try #require(rendered["text"]?.str), first = try #require(rendered["first_line"]?.str)
        #expect(rig.display?.text == renderText + "Signing as alice with \(Render.kid12(material.kid))\n")
        #expect(rig.backend.prompts == [first])
        // never on stdout
        #expect(!lineText(out).contains("Method:") && !lineText(out).contains(first))
        #expect(first == "APPROVE request req-00000001 (CwmA doEB agBd, 9 bytes)")
    }

    @Test("a different person and draft: the same sequence with other values")
    func theSequenceIsNotTiedToOneInput() throws {
        let rig = Rig(person: "bob", keyClass: "apple-se-bio")
        let out = rig.run(["sign"], signInput(verdictDraft(recipient: "bob", request: "req-00000002"), .object(["request_b64": jstr(requestB64)])))
        #expect(out.exit == 0)
        let parts = try jwsParts(of: out)
        guard case .object(let payload)? = try? Subset.parse(parts.payload, maxSize: 16_384).get() else { Issue.record("payload"); return }
        #expect(payload["performer_id"] == jstr("bob"))
        #expect(rig.display?.text.contains("Signing as bob with ") == true)
        #expect(rig.backend.prompts.first?.hasPrefix("APPROVE request req-00000002") == true)
    }

    @Test("sgn/two-signs-two-prompts: every signature has its own prompt")
    func twoSignsInOneProcessShowTwoPrompts() throws {
        let rig = Rig()
        let a = signed(rig), b = signed(rig, verdictDraft(request: "req-00000003"))
        #expect(a.exit == 0 && b.exit == 0 && a != b)
        #expect(rig.backend.prompts.count == 2)
        #expect(rig.backend.prompts[0] != rig.backend.prompts[1])
        _ = signed(rig)
        #expect(rig.backend.prompts.count == 3)
    }

    @Test("sgn/prompt-open-refused: a second sign while a prompt is open is exit 4, prompt_refused, with no prompt (SG-10)")
    func aSecondSignWhileAPromptIsOpenIsRefused() throws {
        let rig = Rig()
        let rival = PromptGuard(lockPath: rig.lockPath, maxPrompts: 100, perSeconds: 60, clock: { 0 })
        let out: Outcome = try rival.guarded { signed(rig) }
        #expect(out.exit == 4 && lineText(out) == errorLine("prompt_refused"))
        #expect(rig.backend.prompts.isEmpty && rig.display?.shown == [])
        #expect(signed(rig).exit == 0 && rig.backend.prompts.count == 1)
    }

    @Test("SG-10: a refused prompt shows nothing at all: the render and Signing as are written only once the guard is held")
    func aRefusedPromptShowsNothing() throws {
        let rig = Rig()
        let rival = PromptGuard(lockPath: rig.lockPath, maxPrompts: 100, perSeconds: 60, clock: { 0 })
        let out: Outcome = try rival.guarded { signed(rig) }
        #expect(out.exit == 4 && lineText(out) == errorLine("prompt_refused"))
        #expect(rig.display?.shown == [])
        // the same for the rate limit, and the display still works for a prompt that is allowed
        let limited = Rig(maxPrompts: 1)
        #expect(signed(limited).exit == 0)
        let shownBefore = limited.display?.shown.count
        #expect(lineText(signed(limited)) == errorLine("prompt_refused"))
        #expect(limited.display?.shown.count == shownBefore && shownBefore == 2)
    }

    @Test("SG-08: a sensor that cannot verify now is exit 4, biometric_unavailable, with nothing shown and no prompt")
    func aSensorThatCannotVerifyNowIsBiometricUnavailable() {
        let rig = Rig()
        rig.backend.mode = .sensorUnavailable
        let out = signed(rig)
        #expect(out.exit == 4 && lineText(out) == errorLine("biometric_unavailable"))
        #expect(rig.display?.shown == [] && rig.backend.prompts.isEmpty)
        rig.backend.mode = .normal
        #expect(signed(rig).exit == 0 && rig.backend.prompts.count == 1)
    }

    @Test("SG-08 order: no_display, then biometric_unavailable, then prompt_refused")
    func theDisplayThenTheSensorThenTheGuard() throws {
        let noDisplay = Rig(display: nil)
        noDisplay.backend.mode = .sensorUnavailable
        #expect(lineText(signed(noDisplay)) == errorLine("no_display"))
        let both = Rig()
        both.backend.mode = .sensorUnavailable
        let rival = PromptGuard(lockPath: both.lockPath, maxPrompts: 100, perSeconds: 60, clock: { 0 })
        let out: Outcome = try rival.guarded { signed(both) }
        #expect(lineText(out) == errorLine("biometric_unavailable"))
    }

    @Test("sgn/prompt-rate-limit-refused: past the per-process limit the prompt is exit 4, prompt_refused, nothing is signed (SG-10)")
    func thePromptRateLimitIsRefusedAsPromptRefused() {
        let rig = Rig(maxPrompts: 1)
        #expect(signed(rig).exit == 0)
        let out = signed(rig)
        #expect(out.exit == 4 && lineText(out) == errorLine("prompt_refused"))
        #expect(rig.backend.prompts.count == 1)
    }

    @Test("sgn/normalizes-high-s: a platform signature with high S comes back low")
    func aHighSSignatureIsReturnedLow() throws {
        let rig = Rig()
        rig.backend.mode = .highS
        for _ in 0..<3 {
            let out = signed(rig)
            #expect(out.exit == 0)
            let parts = try jwsParts(of: out)
            #expect(isLow(parts.signature))
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(parts.signature))
            #expect(try publicKey(try #require(rig.material)).isValidSignature(signature, for: Data(parts.signingInput)))
        }
    }

    @Test("sgn/self-verify: a signature that does not verify is internal, with no output")
    func aFailedSelfVerificationIsInternal() {
        let rig = Rig()
        rig.backend.mode = .brokenSignature
        let out = signed(rig)
        #expect(out.exit == 5 && lineText(out) == errorLine("internal"))
    }

    @Test("sgn/windows-prehash-once: a message hashed twice does not verify, so it is internal")
    func aPrehashComputedTwiceIsInternal() {
        let rig = Rig()
        rig.backend.mode = .doubleHash
        let out = signed(rig)
        #expect(out.exit == 5 && lineText(out) == errorLine("internal"))
        rig.backend.mode = .normal
        #expect(signed(rig).exit == 0)
    }

    @Test("sgn/cancel: a cancelled prompt is exit 1, user_cancel")
    func aCancelledPromptIsUserCancel() {
        let rig = Rig()
        rig.backend.mode = .cancel
        let out = signed(rig)
        #expect(out.exit == 1 && lineText(out) == errorLine("user_cancel"))
        #expect(rig.backend.prompts.count == 1)
    }

    @Test("sgn/no-display: no display channel is exit 4, no_display, and no prompt")
    func aMissingDisplayIsNoDisplay() {
        let rig = Rig(display: nil)
        let out = signed(rig)
        #expect(out.exit == 4 && lineText(out) == errorLine("no_display"))
        #expect(rig.backend.prompts.isEmpty)
    }

    @Test("render and sign without a key are key_unavailable, exit 3, no prompt")
    func noKeyIsKeyUnavailable() {
        let rig = Rig(person: nil)
        for command in ["render", "sign"] {
            let out = rig.run([command], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)])))
            #expect(out.exit == 3 && lineText(out) == errorLine("key_unavailable"), "\(command)")
        }
        #expect(rig.backend.prompts.isEmpty && rig.display?.shown.isEmpty == true)
    }

    @Test("sgn/class-mismatch: a key of another class is key_unavailable")
    func aKeyOfAnotherClassIsKeyUnavailable() {
        // the bound key says it is of the test class, the build produces apple-se-bio
        let foreign = Rig(person: nil, keyClass: "apple-se-bio")
        foreign.backend.storedClass = "test-sw-p256"
        _ = try? foreign.backend.create(label: "laptop", person: "alice") { _ in }
        #expect(foreign.material?.keyClass == "test-sw-p256")
        for command in ["render", "sign", "pubkey"] {
            let out = foreign.run([command], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)])))
            #expect(out.exit == 3 && lineText(out) == errorLine("key_unavailable"), "\(command)")
        }
        #expect(foreign.backend.prompts.isEmpty)
        // the same build with a key of its own class signs
        #expect(signed(Rig(keyClass: "apple-se-bio")).exit == 0)
    }

    @Test("sgn/key-invalidated: a key a biometric change invalidated is exit 3, key_unavailable")
    func aKeyTheBiometricsInvalidatedIsKeyUnavailable() {
        let atSign = Rig()
        atSign.backend.mode = .invalidatedAtSign
        let out = signed(atSign)
        #expect(out.exit == 3 && lineText(out) == errorLine("key_unavailable"))
        let known = Rig()
        known.backend.mode = .invalidated
        for command in ["render", "sign"] {
            let result = known.run([command], signInput(verdictDraft(), .object(["request_b64": jstr(requestB64)])))
            #expect(result.exit == 3 && lineText(result) == errorLine("key_unavailable"), "\(command)")
        }
        #expect(known.backend.prompts.isEmpty)
    }

    @Test("sgn/render-refused: a render the renderer refuses is exit 2 with no prompt")
    func aRefusedRenderShowsNoPrompt() {
        let rig = Rig()
        let wide = JValue.object(["body": .object(["anchors": .array([jstr("a")]), "record_id": jstr("rec-0001")]), "expires_in_s": jstr("60"),
                                  "head": .object(["id": jstr(hsh("h")), "kind": jstr("chain")]), "method": jstr(Methods.promote), "org": jstr(hsh("org"))])
        let out = rig.run(["sign"], signInput(wide, .object(["record_body_b64": jstr(b64(Array(repeating: 0x61, count: 2049)))])))
        #expect(out.exit == 2 && lineText(out) == errorLine("render_refused"))
        #expect(rig.backend.prompts.isEmpty && rig.display?.shown.isEmpty == true)
    }

    @Test("sgn/request-too-long-refused: a 2049-byte request is render_refused, 2048 is signed")
    func aRequestOverTheBlockLimitIsRefusedWithNoPrompt() {
        let rig = Rig()
        let over = rig.run(["sign"], signInput(verdictDraft(), .object(["request_b64": jstr(b64(Array(repeating: 0x61, count: 2049)))])))
        #expect(over.exit == 2 && lineText(over) == errorLine("render_refused"))
        #expect(rig.backend.prompts.isEmpty)
        let fits = rig.run(["sign"], signInput(verdictDraft(), .object(["request_b64": jstr(b64(Array(repeating: 0x61, count: 2048)))])))
        #expect(fits.exit == 0 && rig.backend.prompts.count == 1)
    }

    @Test func aVerdictForAnotherPersonIsRefusedBeforeAnyPrompt() {
        let rig = Rig()
        let out = signed(rig, verdictDraft(recipient: "bob"))
        #expect(out.exit == 2 && lineText(out) == errorLine("identity_mismatch"))
        #expect(rig.backend.prompts.isEmpty && rig.display?.shown.isEmpty == true)
    }

    @Test func aBadDraftIsRefusedBeforeAnyPrompt() {
        let rig = Rig()
        var members: [String: JValue] = [:]
        if case .object(let m) = verdictDraft() { members = m }
        members["ts"] = jstr(Rig.ts)
        let out = signed(rig, .object(members))
        #expect(out.exit == 2 && lineText(out) == errorLine("schema_refused"))
        members["ts"] = nil; members["expires_in_s"] = jstr("0")
        #expect(signed(rig, .object(members)).exit == 2 && rig.backend.prompts.isEmpty)
    }
}

func b64(_ bytes: [UInt8]) -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    var out: [UInt8] = []
    var i = 0
    while i < bytes.count {
        let n = min(3, bytes.count - i)
        var chunk = UInt32(bytes[i]) << 16
        if n > 1 { chunk |= UInt32(bytes[i + 1]) << 8 }
        if n > 2 { chunk |= UInt32(bytes[i + 2]) }
        for k in 0...n { out.append(alphabet[Int((chunk >> UInt32(18 - 6 * k)) & 63)]) }
        out.append(contentsOf: [UInt8](repeating: UInt8(ascii: "="), count: 3 - n))
        i += 3
    }
    return String(decoding: out, as: UTF8.self)
}
