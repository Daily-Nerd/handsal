/// RN-09: attachments are bound to the payload, then the whole render.
///
/// Every renderer verifies every attachment against the signed payload before it shows a word, so
/// the words a person sees are a function of signed bytes only. An attachment is bound by hash or
/// by id:
///   verdicts          `request_b64`      hashstr(bytes) = `inputs_hash`
///   decision          `decision_b64`     hashstr(bytes) = `inputs_hash`
///   genesis.sign      `document`         hashstr(JCS(document)) = `inputs_hash`
///                     `previous`         (a change) hashstr(JCS(previous)) = `document.prev`
///                     `head.id` of the payload = `document.head` (a change)
///                     both are valid alone (GP-15 steps 1 and 3), else `attachment_mismatch`
///   act.endorse       `act`              receipt id = `body.act` = `parent_receipt_hash`; `performer_id` =
///                                        `parent_performer_id`; its `parent_receipt_hash` = `head.id`;
///                                        a chain primary or a resolve
///   chain.resolve     `candidates`       one JWS per id of `body.candidates`, each with the resolve's parent
///                     `heads`            one JWS per id of `body.heads`, each a chain primary
///   act.endorse of a resolve: `candidates` and `heads` bound against the attached resolve, the same way
/// A list holds exactly one JWS per id and nothing else, in any order. Every attached act passes
/// ACT-01 to ACT-14 (`Acts.parse`), whatever its defect: that is `attachment_mismatch`. An absent
/// attachment or list is `attachment_missing`. Attachments the method does not bind (a `sender`,
/// say) are never read. Whether a head lies in a losing subtree is the fold's to decide (FO-25).
///
/// Order (RN-09, "Order of checks"): envelope and method (`schema`, `method_unknown`), for `genesis.sign`
/// its document (which fixes whether a head is due), the act object and body (`schema`, `body_schema`),
/// then the other attachments in the order above, each read and bound completely before the next; the
/// first defect wins. A `request_b64` or `decision_b64` that is not canonical base64 is
/// `malformed_input` (CF-03).
extension Render {
    private static func missing() -> Refusal { Refusal("attachment_missing") }
    private static func mismatch() -> Refusal { Refusal("attachment_mismatch") }

    private static func bytes(_ attachments: [String: JValue], _ name: String, bound inputs: String) throws -> [UInt8] {
        guard let value = attachments[name] else { throw missing() }
        guard case .string(let text) = value, let raw = Encoding.base64Decode(text) else { throw Refusal("malformed_input") }
        guard Encoding.hashstr(raw) == inputs else { throw mismatch() }
        return raw
    }

    private static func document(_ attachments: [String: JValue], _ name: String, bound hash: String,
                                 _ ctx: GenesisContext) throws -> RenderGenesis.Doc {
        guard let value = attachments[name] else { throw missing() }
        guard (try? Genesis.docHash(value)) == hash else { throw mismatch() }
        do { try Genesis.checkAlone(value, ctx) } catch is Refusal { throw mismatch() }
        do { return try RenderGenesis.read(value) } catch is Refusal { throw mismatch() }
    }

    private static func act(_ value: JValue?, _ registry: Registry, wanted: Set<String>) throws -> ParsedAct {
        guard let text = value?.str else { throw mismatch() }
        do { return try Acts.parse(text, registry: registry, wanted: wanted) } catch is Refusal { throw mismatch() }
    }

    /// `{receipt id: line 1}` of the JWS list `name`: exactly one per id in `ids`, each passing `accept`.
    private static func actList(_ attachments: [String: JValue], _ name: String, ids: [String], _ registry: Registry,
                                accept: (ParsedAct) -> Bool) throws -> [String: String] {
        guard let value = attachments[name] else { throw missing() }
        guard let items = value.list else { throw mismatch() }
        let parsed = try items.map { try act($0, registry, wanted: Methods.primaries) }
        guard parsed.map(\.id).sorted() == ids.sorted(), parsed.allSatisfy(accept) else { throw mismatch() }
        var lines: [String: String] = [:]
        for item in parsed { lines[item.id] = try RenderLines.firstLine(method: item.method, payload: item.payload, facts: Facts()) }
        return lines
    }

    private static func resolveFacts(_ payload: [String: JValue], _ attachments: [String: JValue], _ registry: Registry) throws -> Facts {
        guard let body = payload["ext"]?[Envelope.extKey]?["body"], let parent = payload["parent_receipt_hash"]?.str,
              let candidates = body["candidates"]?.list?.compactMap(\.str),
              let heads = body["heads"]?.list?.compactMap(\.str) else { throw Refusal("schema") }
        var facts = Facts()
        facts.candidates = try actList(attachments, "candidates", ids: candidates, registry) { $0.parent == parent }
        facts.heads = try actList(attachments, "heads", ids: heads, registry) { _ in true }
        return facts
    }

    private static func endorseFacts(_ payload: [String: JValue], _ attachments: [String: JValue], _ registry: Registry) throws -> Facts {
        guard let actObject = payload["ext"]?[Envelope.extKey]?.dict else { throw Refusal("schema") }
        guard let attached = attachments["act"] else { throw missing() }
        let endorsed = try act(attached, registry, wanted: Methods.chainActs)
        guard endorsed.id == actObject["body"]?["act"]?.str, payload["parent_receipt_hash"]?.str == endorsed.id,
              payload["parent_performer_id"]?.str == endorsed.performer,
              endorsed.parent == actObject["head"]?["id"]?.str else { throw mismatch() }
        var inner = Facts()
        if endorsed.method == Methods.resolve {
            inner = try resolveFacts(endorsed.payload, attachments, registry)
        } else if attachments["candidates"] != nil || attachments["heads"] != nil {
            throw mismatch()
        }
        var facts = Facts()
        facts.endorsedLine1 = try RenderLines.firstLine(method: endorsed.method, payload: endorsed.payload, facts: inner)
        facts.endorsedLines = try RenderLines.methodLines(method: endorsed.method, payload: endorsed.payload, facts: inner)
        return facts
    }

    private static func checkAct(_ payload: [String: JValue], kid: String, _ registry: Registry, headPresent: Bool? = nil) throws {
        try Envelope.checkActObject(payload, headerKid: kid, registry: registry, headPresent: headPresent)
        if payload["method"]?.str == Methods.resolve {
            guard let body = payload["ext"]?[Envelope.extKey]?["body"], let choose = body["choose"]?.str,
                  body["candidates"]?.list?.contains(.string(choose)) == true else { throw Refusal("body_schema") }
        }
    }

    private static func frame(_ payload: [String: JValue], first: String, body: [String]) throws -> Rendered {
        guard let act = payload["ext"]?[Envelope.extKey]?.dict, let method = payload["method"]?.str,
              let org = act["org"]?.str, let performer = payload["performer_id"]?.str, let kid = act["kid"]?.str,
              let ts = payload["ts"]?.str else { throw Refusal("schema") }
        return try frame(first: first, method: method, org: org, performer: performer, kid: kid, body: body, ts: ts,
                         expires: act["expires"]?.str, parent: payload["parent_receipt_hash"]?.str,
                         head: act["head"]?["id"]?.str, sender: Methods.verdicts.contains(method))
    }

    /// The `Rendered` of an input (RN-01), or a `Refusal` with the code of section 11.
    public static func render(_ input: RenderInput, registry: Registry = .standard,
                              genesis ctx: GenesisContext = GenesisContext()) throws -> Rendered {
        let method = input.method
        try Envelope.checkEnvelope(input.payload)
        guard let payload = input.payload.dict, payload["method"]?.str == method else { throw Refusal("schema") }
        guard registry.methods[method] != nil else { throw Refusal("method_unknown") }
        guard let attachments = input.attachments.dict, let inputs = payload["inputs_hash"]?.str else { throw Refusal("schema") }

        if method == Methods.genesisSign {
            let doc = try document(attachments, "document", bound: inputs, ctx)
            // RN-09 Order of checks: the document fixes whether a head is due, and the act object's form
            // (head presence included) is decided before `previous` is read.
            try checkAct(payload, kid: input.kid, registry, headPresent: doc.prev != nil)
            var previous: RenderGenesis.Doc?
            if let prev = doc.prev { previous = try document(attachments, "previous", bound: prev, ctx) }
            if let head = payload["ext"]?[Envelope.extKey]?["head"]?["id"]?.str, head != doc.head { throw mismatch() }
            return try frame(payload, first: try RenderGenesis.summary(doc, previous), body: try RenderGenesis.lines(doc, previous))
        }
        try checkAct(payload, kid: input.kid, registry)
        var facts = Facts()
        if Methods.verdicts.contains(method) {
            facts.raw = try bytes(attachments, "request_b64", bound: inputs)
        } else if method == Methods.decision {
            facts.raw = try bytes(attachments, "decision_b64", bound: inputs)
        } else if method == Methods.resolve {
            facts = try resolveFacts(payload, attachments, registry)
        } else if method == Methods.endorse {
            facts = try endorseFacts(payload, attachments, registry)
        }
        return try frame(payload, first: try RenderLines.firstLine(method: method, payload: payload, facts: facts),
                         body: try RenderLines.methodLines(method: method, payload: payload, facts: facts))
    }
}
