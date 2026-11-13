import CryptoKit

/// `render`, `sign` and `version` (SG-01, SG-02, SG-04 to SG-07).
///
/// `render` and `sign` start from one function, `prepare`, so the words a person reads and the bytes
/// the key signs are derived the same way from the same draft: the signer cannot show one thing and
/// sign another. `sign` then adds the display, the prompt and the signature checks.
///
/// The sequence of `sign`, each step before the next and every refusal before any prompt:
///   1. read the closed `{attachments, draft}` object and the draft (`schema_refused`)
///   2. the bound key, of this build's class (`key_unavailable`)
///   3. build the payload from draft, attachments and the signer's own values; check the draft
///      against its attachments (`identity_mismatch`, `attachment_mismatch`, `attachment_missing`)
///   4. render it (`render_refused`)
///   5. open the display channel (`no_display`), then ask the backend whether the person can be
///      asked now (`biometric_unavailable`)
///   6. take the prompt guard (`prompt_refused`, SG-10); only then write the render and
///      `Signing as ...`, and open one prompt with line 1 as its text, over `b64url(header).b64url(payload)`
///   7. low-S, then verify the signature with the public key, then read the payload back through
///      the recognizer and the schema checks. A failure of 7 is `internal` and nothing is output.
extension SignerCommands {
    struct Prepared {
        let draft: Draft
        let key: KeyMaterial
        let payload: [UInt8]
        let rendered: Rendered
    }

    static func boundKey(_ environment: Environment) throws -> KeyMaterial {
        guard let key = try environment.backend.bound(), key.keyClass == environment.backend.keyClass else {
            throw Refusal("key_unavailable")
        }
        return key
    }

    static func prepare(_ input: JValue, environment: Environment) throws -> Prepared {
        guard case .object(let top) = input, Set(top.keys) == ["attachments", "draft"],
              let attachments = top["attachments"], let draftValue = top["draft"] else { throw Refusal("schema_refused") }
        let draft = try Draft.read(draftValue)
        let key = try boundKey(environment)
        let payload = try PayloadBuilder.build(draft: draft, attachments: attachments,
                                               fixed: Fixed(kid: key.kid, nonce: environment.nonce(), performer: key.person,
                                                            ts: Forms.time(epochSeconds: environment.now())))
        let rendered = try Render.render(RenderInput(attachments: attachments, kid: key.kid, method: draft.method, payload: payload))
        return Prepared(draft: draft, key: key, payload: try Emit.subset(payload), rendered: rendered)
    }

    /// `version` (SG-02): the class this build produces, the implementation and the production
    /// profile. No stdin, no key, no prompt.
    public static func version(environment: Environment) -> JValue {
        .object(["class": .string(environment.backend.keyClass), "impl": .string("handsal-sign-swift"),
                 "spec": .string(Profiles.standard.production)])
    }

    /// `render` (SG-01, SG-04): `{attachments, draft}` in, `{first_line, text}` out: the text of the
    /// payload the signer would sign. It needs the key for the performer and kid, and shows no prompt.
    public static func render(_ input: JValue, environment: Environment) throws -> JValue {
        let prepared = try prepare(input, environment: environment)
        return .object(["first_line": .string(prepared.rendered.firstLine), "text": .string(prepared.rendered.text)])
    }

    /// `sign` (SG-04 to SG-07): `{jws, receipt_id}`.
    public static func sign(_ input: JValue, environment: Environment) throws -> JValue {
        let prepared = try prepare(input, environment: environment)
        let key = prepared.key

        let display = try environment.display()
        try environment.backend.ready()

        let header = Array(#"{"alg":"ES256","kid":"\#(key.kid)"}"#.utf8)
        let signingInput = Encoding.base64url(header) + "." + Encoding.base64url(prepared.payload)
        let message = Array(signingInput.utf8)
        // the guard first: a refused prompt shows nothing (SG-10)
        let platform = try environment.prompts.guarded {
            try display.show(prepared.rendered.text)
            try display.show("Signing as \(key.person) with \(Render.kid12(key.kid))\n")
            return try environment.backend.sign(message, reason: prepared.rendered.firstLine)
        }

        let signature = try Signature.lowS(platform)
        guard verifies(signature, over: message, key: key) else { throw Refusal("internal") }
        let jws = signingInput + "." + Encoding.base64url(signature)
        // The emitted act must pass the recognizer and the schema checks a verifier will run.
        let parsed: ParsedAct
        do {
            parsed = try Acts.parse(jws, registry: .standard, wanted: [prepared.draft.method], headPresent: prepared.draft.head != nil)
        } catch {
            throw Refusal("internal")
        }
        return .object(["jws": .string(jws), "receipt_id": .string(parsed.id)])
    }

    /// SG-06: the signer verifies its own signature with the public key before it returns it.
    private static func verifies(_ signature: [UInt8], over message: [UInt8], key: KeyMaterial) -> Bool {
        guard let x = Encoding.base64urlDecode(key.sign.x), let y = Encoding.base64urlDecode(key.sign.y),
              let publicKey = try? P256.Signing.PublicKey(x963Representation: [0x04] + x + y),
              let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return publicKey.isValidSignature(parsed, for: message)
    }
}
