import HandsalCore
import Testing

private func hs(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
private let otherKid = "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"
private let ts = "2026-11-08T11:59:00Z"
private let defaultRig = Rig(person: "alice", keyClass: "apple-se-bio")
private let env = defaultRig.env
private let bare = Rig(person: nil, keyClass: "apple-se-bio").env

private func str(_ s: String) -> JValue { .string(s) }
private func line(_ outcome: Outcome) -> String { String(decoding: outcome.line, as: UTF8.self) }

private func run(_ args: [String], stdin: [UInt8] = [], environment: Environment = env) -> Outcome {
    CLI.run(arguments: args, readStdin: { stdin }, environment: environment)
}

private func removeDraft(parent: String = hs("p")) -> JValue {
    .object(["body": .object(["kid": str(otherKid), "person": str("carol")]), "method": str("local:handsal.device.remove"),
             "org": str(hs("org")), "parent": .object(["id": str(parent), "performer": str("bob")])])
}

private func encode(_ value: JValue) -> [UInt8] { (try? Emit.subset(value)) ?? [] }

@Suite("command line plumbing (SG-01, SG-02, SG-08)")
struct CLITests {
    @Test func versionAnswersWithoutReadingStdinOrAKey() {
        var read = false
        let out = CLI.run(arguments: ["version"], readStdin: { read = true; return [] }, environment: bare)
        #expect(out.exit == 0 && !read)
        #expect(line(out) == #"{"class":"apple-se-bio","impl":"handsal-sign-swift","spec":"\#(Profiles.standard.production)"}"#)
    }

    @Test(arguments: ["info", "key-create", "key-list", "build", "link-code", "enroll", "pin-read", "", "VERSION", "check-act"])
    func unknownCommandsAreRefused(command: String) {
        let out = run([command])
        #expect(out.exit == 2 && line(out) == #"{"error":"unsupported_command"}"#)
    }

    @Test func missingOrExtraArgumentsAreRefused() {
        #expect(run([]).exit == 2)
        #expect(run(["version", "extra"]).exit == 2)
        #expect(run(["emit", "--flag"]).exit == 2)
    }

    private func emitInput(draft: JValue = removeDraft()) -> JValue {
        .object(["attachments": .object([:]), "draft": draft,
                 "fixed": .object(["kid": str(kid), "nonce": str(hs("nonce")), "performer": str("alice"), "ts": str(ts)])])
    }

    @Test func emitWritesOneJcsLineAndExitsZero() throws {
        let out = run(["emit"], stdin: encode(emitInput()))
        #expect(out.exit == 0 && !out.line.contains(0x0A))
        let expected = try Emit.resultLine(SignerCommands.emit(emitInput()))
        #expect(out.line == expected)
    }

    @Test func oneTrailingLfOnStdinIsFramingNotInput() {
        #expect(run(["emit"], stdin: encode(emitInput()) + [0x0A]).exit == 0)
        #expect(run(["emit"], stdin: encode(emitInput()) + [0x0A, 0x0A]).exit == 2)
    }

    @Test func stdinMustBeInTheCanonicalSubset() {
        let canonical = encode(emitInput())
        let spaced = Array(String(decoding: canonical, as: UTF8.self).replacingOccurrences(of: ",", with: ", ").utf8)
        for bad in [spaced, Array(#"{"a":"1","a":"2"}"#.utf8), Array(#"{"draft":1}"#.utf8), [0xFF], [], Array("[]".utf8), Array("null".utf8)] {
            let out = run(["emit"], stdin: bad)
            #expect(out.exit == 2 && line(out) == #"{"error":"schema_refused"}"#)
        }
    }

    @Test func stdinPastMaxInputIsRefused() {
        let big = [UInt8](repeating: 0x20, count: Limits.maxInput + 1)
        let out = run(["emit"], stdin: big)
        #expect(out.exit == 2 && line(out) == #"{"error":"schema_refused"}"#)
    }

    @Test func emitRefusesABadDraftWithExitTwo() {
        var input = emitInput()
        if case .object(var o) = input, case .object(var d)? = o["draft"] { d["ts"] = str(ts); o["draft"] = .object(d); input = .object(o) }
        let out = run(["emit"], stdin: encode(input))
        #expect(out.exit == 2 && line(out) == #"{"error":"schema_refused"}"#)
        let verdict = emitInput(draft: .object(["body": .object([:]), "method": str(Methods.approve), "org": str(hs("org"))]))
        #expect(line(run(["emit"], stdin: encode(verdict))) == #"{"error":"schema_refused"}"#)
        let unknown = emitInput(draft: .object(["body": .object([:]), "method": str("local:handsal.request.send"), "org": str(hs("org"))]))
        #expect(line(run(["emit"], stdin: encode(unknown))) == #"{"error":"unsupported_method"}"#)
    }

    private func renderInput(parent: String = hs("p")) -> JValue {
        .object(["attachments": .object([:]), "draft": removeDraft(parent: parent)])
    }

    @Test func renderNeedsAKeyForThePerformerAndKid() {
        let out = run(["render"], stdin: encode(renderInput()), environment: bare)
        #expect(out.exit == 3 && line(out) == #"{"error":"key_unavailable"}"#)
    }

    @Test func renderShowsTheTextTheSignerWouldSign() throws {
        let out = run(["render"], stdin: encode(renderInput()))
        #expect(out.exit == 0)
        let draft = try Draft.read(removeDraft())
        let boundKid = try #require(defaultRig.material).kid
        let payload = try PayloadBuilder.build(draft: draft, attachments: .object([:]), fixed: Fixed(kid: boundKid, nonce: hs("nonce"), performer: "alice", ts: ts))
        let rendered = try Render.render(RenderInput(attachments: .object([:]), kid: boundKid, method: Methods.deviceRemove, payload: payload))
        #expect(line(out) == String(decoding: try Emit.resultLine(.object(["first_line": str(rendered.firstLine), "text": str(rendered.text)])), as: UTF8.self))
        #expect(rendered.firstLine == "Remove device NAjt fK8u Px9m of carol")
    }

    @Test func renderRefusalsExitTwoWithTheSgEightCodes() {
        func code(_ attachments: JValue, _ draft: JValue) -> (Int32, String) {
            let out = run(["render"], stdin: encode(.object(["attachments": attachments, "draft": draft])))
            return (out.exit, line(out))
        }
        let decision = JValue.object(["body": .object(["action": str("promote"), "consumer": str("acme"), "subject": str("0005-1a2b3c4d5e6f7a8b")]),
                                      "expires_in_s": str("60"), "head": .object(["id": str(hs("h")), "kind": str("chain")]),
                                      "method": str(Methods.decision), "org": str(hs("org"))])
        #expect(code(.object([:]), decision) == (2, #"{"error":"attachment_missing"}"#))
        #expect(code(.object(["decision_b64": str("YQ")]), decision) == (2, #"{"error":"schema_refused"}"#))
        // decided content over the block limit cannot be shown, so it cannot be signed
        let over = base64(Array(repeating: 0x61, count: 2049))
        #expect(code(.object(["decision_b64": str(over)]), decision) == (2, #"{"error":"render_refused"}"#))
    }

    @Test func exitCodeTable() {
        #expect(ExitCodes.outcome(for: Refusal("schema_refused")) == Outcome(exit: 2, line: Array(#"{"error":"schema_refused"}"#.utf8)))
        for code in ["render_refused", "attachment_missing", "attachment_mismatch", "unsupported_method", "unsupported_command", "identity_mismatch", "key_exists"] {
            #expect(ExitCodes.outcome(for: Refusal(code)).exit == 2, "\(code)")
        }
        // codes the checker-form renderer uses are the signer's schema_refused
        for code in ["schema", "body_schema", "malformed_input", "genesis_schema", "payload_not_canonical_subset"] {
            #expect(ExitCodes.outcome(for: Refusal(code)) == ExitCodes.outcome(for: Refusal("schema_refused")), "\(code)")
        }
        #expect(ExitCodes.outcome(for: Refusal("method_unknown")) == ExitCodes.outcome(for: Refusal("unsupported_method")))
        #expect(ExitCodes.outcome(for: Refusal("user_cancel")).exit == 1)
        #expect(ExitCodes.outcome(for: Refusal("key_unavailable")).exit == 3)
        #expect(ExitCodes.outcome(for: Refusal("no_display")).exit == 4)
        #expect(ExitCodes.outcome(for: Refusal("prompt_refused")) == Outcome(exit: 4, line: Array(#"{"error":"prompt_refused"}"#.utf8)))
        #expect(ExitCodes.outcome(for: Refusal("biometric_unavailable")) == Outcome(exit: 4, line: Array(#"{"error":"biometric_unavailable"}"#.utf8)))
        #expect(ExitCodes.outcome(for: Refusal("internal")).exit == 5)
        // a code nobody listed is an internal error, loudly, never exit 0 or a made-up code
        #expect(ExitCodes.outcome(for: Refusal("something_new")) == ExitCodes.outcome(for: Refusal("internal")))
    }
}

private func base64(_ bytes: [UInt8]) -> String {
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
