/// The draft a caller hands the signer (SG-04): facts only, never derived values or words.
///
/// Invariants: the draft is a closed object, `{body, expires_in_s?, head?, method, org, parent?}`.
/// `expires_in_s` is present exactly where the method carries `expires`. `parent` exists exactly
/// where ACT-13 gives the method a parent. The body satisfies the method's closed schema.
/// The signer owns `performer_id`, `kid`, `ts`, `nonce`, `expires`, every pinned constant and both
/// hashes; a draft key outside the closed set (`ts`, `nonce`, `inputs_hash`, display text, an
/// authentication handle, anything else) is `schema_refused`.
/// Failure modes: `schema_refused`, `unsupported_method`, `attachment_missing`; all exit 2.
public struct DraftParent: Equatable, Sendable {
    public let id: String
    public let performer: String?
    public init(id: String, performer: String?) { self.id = id; self.performer = performer }
}

public struct Draft: Sendable {
    public let method: String
    public let org: String
    public let body: JValue
    public let head: JValue?
    public let parent: DraftParent?
    public let expiresInS: Int?

    private static let headNode = SchemaNode.keys(["id": .leaf(.hashstr), "kind": .const("chain")])

    /// Verdict drafts cannot be built yet: SG-04 lists no draft field for `recipient`, `relay` and
    /// `request_id`, which the act object of a verdict needs (ACT-09). Refusing is the only
    /// answer that does not invent a field; see the apply report.
    private static let awaitingSpec = Methods.verdicts

    private static func refused() -> Refusal { Refusal("schema_refused") }

    public static func read(_ value: JValue, registry: Registry = .standard) throws -> Draft {
        guard case .object(let members) = value else { throw refused() }
        let allowed: Set = ["body", "expires_in_s", "head", "method", "org", "parent"]
        guard Set(members.keys).isSubset(of: allowed),
              case .string(let method)? = members["method"],
              let body = members["body"],
              case .string(let org)? = members["org"] else { throw refused() }
        guard let spec = registry.methods[method], !awaitingSpec.contains(method) else { throw Refusal("unsupported_method") }
        guard Forms.isHashstr(org) else { throw refused() }

        var expiresInS: Int?
        if spec.actExtraKeys.contains("expires") {
            guard case .string(let text)? = members["expires_in_s"], Forms.isDecimal(text),
                  let n = Int(text), n <= registry.number("MAX_EXPIRES_IN_S") else { throw refused() }
            expiresInS = n
        } else if members["expires_in_s"] != nil {
            throw refused()
        }

        var head: JValue?
        switch spec.head {
        case .always: guard members["head"] != nil else { throw refused() }
        case .never: guard members["head"] == nil else { throw refused() }
        case .conditional: break
        }
        if let given = members["head"] {
            guard Schema.defects(headNode, given, registry, code: "schema").isEmpty else { throw refused() }
            head = given
        }

        var parent: DraftParent?
        let rule = Methods.parentRule(method)
        if rule == .none {
            guard members["parent"] == nil else { throw refused() }
        } else {
            guard case .object(let p)? = members["parent"], Set(p.keys) == ["id", "performer"],
                  case .string(let id)? = p["id"], Forms.isHashstr(id) else { throw refused() }
            switch p["performer"] {
            case .string(let who)?: guard Forms.isMemberId(who) else { throw refused() }; parent = DraftParent(id: id, performer: who)
            case .null?: guard rule == .primary else { throw refused() }; parent = DraftParent(id: id, performer: nil)
            default: throw refused()
            }
        }

        guard Schema.defects(spec.body, body, registry, code: "body_schema").isEmpty else { throw refused() }
        return Draft(method: method, org: org, body: body, head: head, parent: parent, expiresInS: expiresInS)
    }
}

/// The values `emit` takes from the caller, and the values `sign` takes from the signer itself.
public struct Fixed: Sendable {
    public let kid: String
    public let nonce: String
    public let performer: String
    public let ts: String
    public init(kid: String, nonce: String, performer: String, ts: String) {
        self.kid = kid; self.nonce = nonce; self.performer = performer; self.ts = ts
    }
}

public enum PayloadBuilder {
    private static func refused() -> Refusal { Refusal("schema_refused") }

    /// The `nonce` of a fresh payload: the hashstr of 32 bytes from the system CSPRNG (ACT-07).
    public static func freshNonce() -> String {
        var generator = SystemRandomNumberGenerator()
        return Encoding.hashstr((0..<32).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    private static func rawBytes(_ attachments: [String: JValue], _ name: String) throws -> [UInt8] {
        guard let value = attachments[name] else { throw Refusal("attachment_missing") }
        guard case .string(let text) = value, let raw = Encoding.base64Decode(text) else { throw refused() }
        return raw
    }

    /// The payload the signer would sign for `draft`. `attachments` supply the bytes both hashes
    /// derive from; nothing here trusts a hash the caller wrote.
    public static func build(draft: Draft, attachments: JValue, fixed: Fixed, registry: Registry = .standard) throws -> JValue {
        guard case .object(let files) = attachments else { throw refused() }
        guard Forms.isB64u32(fixed.kid), Forms.isHashstr(fixed.nonce), Forms.isMemberId(fixed.performer),
              let start = Forms.epochSeconds(fixed.ts) else { throw refused() }
        guard let spec = registry.methods[draft.method] else { throw Refusal("unsupported_method") }

        var inputs = Encoding.emptyHash
        var headDue = spec.head == .always
        switch spec.inputsHash {
        case "raw_record_body_bytes":
            inputs = Encoding.hashstr(try rawBytes(files, "record_body_b64"))
        case "jcs_genesis_document":
            guard let document = files["document"] else { throw Refusal("attachment_missing") }
            guard case .object(let members) = document, let prev = members["prev"],
                  let bytes = try? Emit.subset(document) else { throw Refusal("attachment_mismatch") }
            inputs = Encoding.hashstr(bytes)
            headDue = prev != .null
        default: break
        }
        guard (draft.head != nil) == headDue else { throw refused() }

        var act: [String: JValue] = ["body": draft.body, "kid": .string(fixed.kid), "org": .string(draft.org)]
        if let head = draft.head { act["head"] = head }
        if let seconds = draft.expiresInS { act["expires"] = .string(Forms.time(epochSeconds: start + seconds)) }

        return .object([
            "action_ref": .null, "binding": .string("local"),
            "cost": .object(["rail_ref": .null, "tokens": .string("0"), "usd_micros": .string("0"), "wall_ms": .string("0")]),
            "ext": .object(["dev.handsal/act": .object(act)]),
            "inputs_hash": .string(inputs), "log_policy": .string("best_effort"), "method": .string(draft.method),
            "nonce": .string(fixed.nonce), "outputs_hash": .string(Encoding.emptyHash),
            "parent_performer_id": draft.parent?.performer.map { .string($0) } ?? .null,
            "parent_receipt_hash": draft.parent.map { .string($0.id) } ?? .null,
            "performer_id": .string(fixed.performer), "reason": .null, "requester_id": .null,
            "status": .string("OK"), "ts": .string(fixed.ts), "v": .string("vitni/0.2"),
        ])
    }
}

public enum SignerCommands {
    private static let hex = Array("0123456789abcdef".utf8)

    /// `emit` (SG-01): `{attachments, draft, fixed}` in, `{payload_hex}` out. It never signs, so the
    /// caller may choose `fixed = {kid, nonce, performer, ts}` here and nowhere else.
    public static func emit(_ input: JValue) throws -> JValue {
        guard case .object(let top) = input, Set(top.keys) == ["attachments", "draft", "fixed"],
              let attachments = top["attachments"], let draftValue = top["draft"],
              case .object(let f)? = top["fixed"], Set(f.keys) == ["kid", "nonce", "performer", "ts"],
              case .string(let kid)? = f["kid"], case .string(let nonce)? = f["nonce"],
              case .string(let performer)? = f["performer"], case .string(let ts)? = f["ts"] else {
            throw Refusal("schema_refused")
        }
        let payload = try PayloadBuilder.build(draft: Draft.read(draftValue), attachments: attachments,
                                               fixed: Fixed(kid: kid, nonce: nonce, performer: performer, ts: ts))
        var digits: [UInt8] = []
        for byte in try Emit.subset(payload) { digits.append(hex[Int(byte >> 4)]); digits.append(hex[Int(byte & 15)]) }
        return .object(["payload_hex": .string(String(decoding: digits, as: UTF8.self))])
    }

    /// `render` (SG-01, SG-04): `{attachments, draft}` in, `{first_line, text}` out: the text of the
    /// payload the signer would sign. The signer fills performer, kid, ts and nonce itself, so a
    /// key must be bound first.
    public static func render(_ input: JValue, environment: Environment) throws -> JValue {
        guard case .object(let top) = input, Set(top.keys) == ["attachments", "draft"],
              let attachments = top["attachments"], let draftValue = top["draft"] else { throw Refusal("schema_refused") }
        let draft = try Draft.read(draftValue)
        guard let identity = environment.identity else { throw Refusal("key_unavailable") }
        let payload = try PayloadBuilder.build(draft: draft, attachments: attachments,
                                               fixed: Fixed(kid: identity.kid, nonce: environment.nonce(),
                                                            performer: identity.performer,
                                                            ts: Forms.time(epochSeconds: environment.now())))
        let rendered = try Render.render(RenderInput(attachments: attachments, kid: identity.kid, method: draft.method, payload: payload))
        return .object(["first_line": .string(rendered.firstLine), "text": .string(rendered.text)])
    }
}
