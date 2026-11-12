/// The act envelope (ACT-01, ACT-06, ACT-08, ACT-13, ACT-14): `check-act` steps 3 and 5.
///
/// Step 3 checks the envelope alone: the 17 keys, the constants, the forms of the envelope fields
/// and the shape of `ext`. Step 5 checks the act object once the method is known: its closed key
/// set, `head`, the extra keys of the method, the per-method parent fields (ACT-13), the signer
/// kid (ACT-14), then the body. Every defect is `schema` except a body structure defect, which is
/// `body_schema`; `schema` is reported first.
public enum Envelope {
    public static let extKey = "dev.handsal/act"
    private static let keys: Set<String> = [
        "action_ref", "binding", "cost", "ext", "inputs_hash", "log_policy", "method", "nonce", "outputs_hash",
        "parent_performer_id", "parent_receipt_hash", "performer_id", "reason", "requester_id", "status", "ts", "v",
    ]
    private static let constants = ["v": "vitni/0.2", "binding": "local", "status": "OK", "log_policy": "best_effort"]
    private static let cost = JValue.object(["rail_ref": .null, "tokens": .string("0"), "usd_micros": .string("0"), "wall_ms": .string("0")])
    private static let headNode = SchemaNode.keys(["id": .leaf(.hashstr), "kind": .const("chain")])

    private static func refuse() -> Refusal { Refusal("schema") }

    /// Step 3: ACT-01 constants and key set, ACT-07 forms of envelope fields, shape of `ext`.
    public static func checkEnvelope(_ value: JValue) throws {
        guard case .object(let p) = value, Set(p.keys) == keys else { throw refuse() }
        for (key, want) in constants where p[key] != .string(want) { throw refuse() }
        for key in ["reason", "action_ref", "requester_id"] where p[key] != .null { throw refuse() }
        guard p["cost"] == cost, case .string? = p["method"] else { throw refuse() }
        for key in ["inputs_hash", "outputs_hash", "nonce"] {
            guard case .string(let s)? = p[key], Forms.isHashstr(s) else { throw refuse() }
        }
        switch p["parent_receipt_hash"] {
        case .null?: break
        case .string(let s)?: guard Forms.isHashstr(s) else { throw refuse() }
        default: throw refuse()
        }
        switch p["parent_performer_id"] {
        case .null?: break
        case .string(let s)?: guard Forms.isMemberId(s) else { throw refuse() }
        default: throw refuse()
        }
        guard case .string(let performer)? = p["performer_id"], Forms.isMemberId(performer),
              case .string(let ts)? = p["ts"], Forms.isTime(ts) else { throw refuse() }
        guard case .object(let ext)? = p["ext"], Set(ext.keys) == [extKey], case .object? = ext[extKey] else { throw refuse() }
    }

    private static func parentsOk(_ method: String, _ p: [String: JValue]) -> Bool {
        let parent = p["parent_receipt_hash"] ?? .null
        let performer = p["parent_performer_id"] ?? .null
        switch Methods.parentRule(method) {
        case .none: return parent == .null && performer == .null
        case .primary: return parent != .null
        case .endorse: return parent != .null && performer != .null
        }
    }

    /// Step 5 for a payload whose envelope passed step 3 and whose method is in the registry.
    /// `headPresent` says whether a conditional `head` (genesis.sign) is due, and must be given for it.
    public static func checkActObject(_ payload: [String: JValue], headerKid: String, registry: Registry,
                                      headPresent: Bool?) throws {
        guard case .string(let name)? = payload["method"], let spec = registry.methods[name],
              case .object(let ext)? = payload["ext"], case .object(let act)? = ext[extKey] else { throw refuse() }
        var members: [String: SchemaNode] = [
            "body": .scoped(code: "body_schema", spec.body), "kid": .leaf(.kid), "org": .leaf(.hashstr),
        ]
        switch spec.head {
        case .always: members["head"] = headNode
        case .never: break
        case .conditional:
            guard let due = headPresent else { preconditionFailure("a conditional head needs the caller to say if it is due") }
            if due { members["head"] = headNode }
        }
        for key in spec.actExtraKeys {
            guard let form = registry.actExtraKeyTypes[key] else { preconditionFailure("registry has no form for \(key)") }
            members[key] = .leaf(form)
        }
        var found = Schema.defects(.keys(members), .object(act), registry, code: "schema")
        if !parentsOk(name, payload) { found.append("schema") }
        if act["kid"] != .string(headerKid) { found.append("schema") }
        try Schema.refuse(found)
    }
}

/// An act read once: the JWS shape and header (ACT-02, ACT-03), the canonical payload, the
/// envelope, the method, the act object with its closed body, and the hashes a method fixes to
/// the empty hash. Nothing here reads a key, a state or a clock. The receipt id is the identity
/// (ACT-12): two texts of one payload differ only by their signature.
public struct ParsedAct: Sendable {
    public let jws: String
    public let kid: String
    public let signature: [UInt8]
    public let payload: [String: JValue]
    public let method: String
    public let id: String
    public let performer: String
    public let parent: String?
    public let parentPerformer: String?
    public let act: [String: JValue]
    public let body: JValue
    public let head: JValue?
}

public enum Acts {
    private static func shape() -> Refusal { Refusal("jws_shape") }

    private static func jwsParts(_ text: String) throws -> (kid: String, payload: [UInt8], signature: [UInt8]) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw shape() }
        var decoded: [[UInt8]] = []
        for part in parts {
            guard let bytes = Encoding.base64urlDecode(String(part)) else { throw shape() }
            decoded.append(bytes)
        }
        let prefix = Array(#"{"alg":"ES256","kid":""#.utf8)
        let header = decoded[0]
        guard header.count == prefix.count + 43 + 2, header.starts(with: prefix),
              Array(header.suffix(2)) == Array(#""}"#.utf8) else { throw shape() }
        let kid = String(decoding: header[prefix.count..<prefix.count + 43], as: UTF8.self)
        guard Forms.isB64u32(kid), decoded[2].count == 64 else { throw shape() }
        return (kid, decoded[1], decoded[2])
    }

    /// The `ParsedAct` of `text`, whose method must be in `wanted`, else a `Refusal`.
    public static func parse(_ text: String, registry: Registry, wanted: Set<String>, headPresent: Bool? = nil) throws -> ParsedAct {
        let parts = try jwsParts(text)
        let value: JValue
        switch Subset.parse(parts.payload, maxSize: Limits.maxPayload) {
        case .success(let v): value = v
        case .failure(.tooLarge): throw Refusal("payload_too_large")
        case .failure(.notCanonical): throw Refusal("payload_not_canonical_subset")
        }
        guard case .object(let payload) = value else { throw Refusal("payload_not_canonical_subset") }
        try Envelope.checkEnvelope(value)
        guard case .string(let method)? = payload["method"], let spec = registry.methods[method], wanted.contains(method) else {
            throw Refusal("method_unknown")
        }
        try Envelope.checkActObject(payload, headerKid: parts.kid, registry: registry, headPresent: headPresent)
        if spec.inputsHash == "empty", payload["inputs_hash"] != .string(Encoding.emptyHash) { throw Refusal("schema") }
        if spec.outputsHash == "empty", payload["outputs_hash"] != .string(Encoding.emptyHash) { throw Refusal("schema") }
        guard case .object(let ext)? = payload["ext"], case .object(let act)? = ext[Envelope.extKey],
              case .string(let performer)? = payload["performer_id"] else { throw Refusal("schema") }
        func field(_ key: String) -> String? { if case .string(let s)? = payload[key] { return s } else { return nil } }
        return ParsedAct(jws: text, kid: parts.kid, signature: parts.signature, payload: payload, method: method,
                         id: Encoding.hashstr(parts.payload), performer: performer, parent: field("parent_receipt_hash"),
                         parentPerformer: field("parent_performer_id"), act: act, body: act["body"] ?? .null, head: act["head"])
    }
}
