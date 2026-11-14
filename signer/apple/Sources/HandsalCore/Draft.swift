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

/// The three keys a verdict draft adds (SG-04, ACT-09): they go into the act object of a verdict and
/// of no other method.
public struct VerdictFields: Equatable, Sendable {
    public let recipient: String
    public let relay: String
    public let requestId: String
    public init(recipient: String, relay: String, requestId: String) {
        self.recipient = recipient; self.relay = relay; self.requestId = requestId
    }
}

public struct Draft: Sendable {
    public let method: String
    public let org: String
    public let body: JValue
    public let head: JValue?
    public let parent: DraftParent?
    public let expiresInS: Int?
    public let verdict: VerdictFields?

    private static let headNode = SchemaNode.keys(["id": .leaf(.hashstr), "kind": .const("chain")])

    private static func refused() -> Refusal { Refusal("schema_refused") }

    public static func read(_ value: JValue, registry: Registry = .standard) throws -> Draft {
        guard case .object(let members) = value else { throw refused() }
        let allowed: Set = ["body", "expires_in_s", "head", "method", "org", "parent", "recipient", "relay", "request_id"]
        guard Set(members.keys).isSubset(of: allowed),
              case .string(let method)? = members["method"],
              let body = members["body"],
              case .string(let org)? = members["org"] else { throw refused() }
        guard let spec = registry.methods[method] else { throw Refusal("unsupported_method") }
        guard Forms.isHashstr(org) else { throw refused() }

        var expiresInS: Int?
        if spec.actExtraKeys.contains("expires") {
            guard case .string(let text)? = members["expires_in_s"], Forms.isDecimal(text),
                  let n = Int(text), n >= 1, n <= registry.number("MAX_EXPIRES_IN_S") else { throw refused() }
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

        // recipient, relay and request_id: present exactly for the methods whose act object has them (ACT-09).
        var verdict: VerdictFields?
        if spec.actExtraKeys.contains("recipient") {
            func field(_ key: String) throws -> String {
                guard case .string(let text)? = members[key], let form = registry.actExtraKeyTypes[key], form.accepts(text) else { throw refused() }
                return text
            }
            verdict = VerdictFields(recipient: try field("recipient"), relay: try field("relay"), requestId: try field("request_id"))
        } else if ["recipient", "relay", "request_id"].contains(where: { members[$0] != nil }) {
            throw refused()
        }

        guard Schema.defects(spec.body, body, registry, code: "body_schema").isEmpty else { throw refused() }
        return Draft(method: method, org: org, body: body, head: head, parent: parent, expiresInS: expiresInS, verdict: verdict)
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

    /// The two hashes of a payload from the registry's named rules (ACT-09, RN-09), and for a
    /// `genesis.sign` whether a head is due and which `org` the document gives. Every rule is named: `empty` is a rule like the others,
    /// and a name this function does not know is `internal`, never a silent empty hash.
    public static func derive(inputsKind: String, outputsKind: String, draft: Draft,
                              files: [String: JValue]) throws -> (inputs: String, outputs: String, headDue: Bool?, org: String?) {
        var inputs = Encoding.emptyHash
        var headDue: Bool?
        var derivedOrg: String?
        switch inputsKind {
        case "empty": break
        case "raw_request_bytes": inputs = Encoding.hashstr(try rawBytes(files, "request_b64"))
        case "raw_record_body_bytes": inputs = Encoding.hashstr(try rawBytes(files, "record_body_b64"))
        case "raw_decision_bytes": inputs = Encoding.hashstr(try rawBytes(files, "decision_b64"))
        case "jcs_genesis_document":
            guard let document = files["document"] else { throw Refusal("attachment_missing") }
            guard case .object(let members) = document, let prev = members["prev"],
                  let bytes = try? Emit.subset(document) else { throw Refusal("attachment_mismatch") }
            inputs = Encoding.hashstr(bytes)
            headDue = prev != .null
            // SG-13: `org` is derived from the document, never taken from the caller. The comparison with
            // the draft is the caller's (SG-08: the head, which is draft shape, is checked first).
            if prev == .null {
                derivedOrg = inputs
            } else {
                guard let org = members["org"]?.str else { throw Refusal("attachment_mismatch") }   // a document the signer cannot read
                derivedOrg = org
            }
        default: throw Refusal("internal")
        }
        var outputs = Encoding.emptyHash
        if outputsKind.hasPrefix("verdict:") {
            let name = String(outputsKind.dropFirst(8))
            guard ["approve", "reject", "needs-info"].contains(name), let verdict = draft.verdict else { throw Refusal("internal") }
            outputs = Encoding.hashstr(try Emit.subset(.object(["request_id": .string(verdict.requestId), "verdict": .string(name)])))
        } else if outputsKind == "action_subject" {
            // VR-18: the words of the decision, from the draft's own body (the grammar was checked with the body)
            guard case .object(let body) = draft.body, let action = body["action"], let subject = body["subject"] else { throw Refusal("internal") }
            outputs = Encoding.hashstr(try Emit.subset(.object(["action": action, "subject": subject])))
        } else if outputsKind != "empty" {
            throw Refusal("internal")
        }
        return (inputs, outputs, headDue, derivedOrg)
    }

    /// The payload the signer would sign for `draft`. `attachments` supply the bytes both hashes
    /// derive from; nothing here trusts a hash the caller wrote.
    public static func build(draft: Draft, attachments: JValue, fixed: Fixed, registry: Registry = .standard) throws -> JValue {
        guard case .object(let files) = attachments else { throw refused() }
        guard Forms.isB64u32(fixed.kid), Forms.isHashstr(fixed.nonce), Forms.isMemberId(fixed.performer),
              let start = Forms.epochSeconds(fixed.ts) else { throw refused() }
        guard let spec = registry.methods[draft.method] else { throw Refusal("unsupported_method") }
        // Identity has one owner, the key: a verdict is addressed to one person (SG-04, ACT-13).
        if let verdict = draft.verdict, verdict.recipient != fixed.performer { throw Refusal("identity_mismatch") }

        let derived = try derive(inputsKind: spec.inputsHash, outputsKind: spec.outputsHash, draft: draft, files: files)
        let inputs = derived.inputs, outputs = derived.outputs
        let headDue = derived.headDue ?? (spec.head == .always)
        guard (draft.head != nil) == headDue else { throw refused() }
        // SG-08 step 3: the values derived from the attachments come after the shape of the draft, and
        // the order of the checks among attachments is RN-09's ("Order of checks").
        if let derivedOrg = derived.org, draft.org != derivedOrg { throw Refusal("attachment_mismatch") }

        var act: [String: JValue] = ["body": draft.body, "kid": .string(fixed.kid), "org": .string(draft.org)]
        if let head = draft.head { act["head"] = head }
        if let seconds = draft.expiresInS { act["expires"] = .string(Forms.time(epochSeconds: start + seconds)) }
        if let verdict = draft.verdict {
            act["recipient"] = .string(verdict.recipient)
            act["relay"] = .string(verdict.relay)
            act["request_id"] = .string(verdict.requestId)
        }

        return .object([
            "action_ref": .null, "binding": .string("local"),
            "cost": .object(["rail_ref": .null, "tokens": .string("0"), "usd_micros": .string("0"), "wall_ms": .string("0")]),
            "ext": .object(["dev.handsal/act": .object(act)]),
            "inputs_hash": .string(inputs), "log_policy": .string("best_effort"), "method": .string(draft.method),
            "nonce": .string(fixed.nonce), "outputs_hash": .string(outputs),
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

}
