import HandsalCore
import Testing

private func hs(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
private let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
private let otherKid = "NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"
private let ts = "2026-11-08T11:59:00Z"
private func str(_ s: String) -> JValue { .string(s) }

/// A valid device.remove payload, built the way the signer builds one.
private func removePayload() throws -> [String: JValue] {
    let draft = try Draft.read(.object([
        "body": .object(["kid": str(otherKid), "person": str("carol")]), "method": str("local:handsal.device.remove"),
        "org": str(hs("org")), "parent": .object(["id": str(hs("p")), "performer": str("bob")]),
    ]))
    guard case .object(let p) = try PayloadBuilder.build(draft: draft, attachments: .object([:]),
                                                         fixed: Fixed(kid: kid, nonce: hs("n"), performer: "alice", ts: ts)) else { return [:] }
    return p
}

private func promotePayload() throws -> [String: JValue] {
    let draft = try Draft.read(.object([
        "body": .object(["anchors": .array([str("a-1")]), "record_id": str("rec-0001")]), "expires_in_s": str("60"),
        "head": .object(["id": str(hs("h")), "kind": str("chain")]), "method": str("local:handsal.record.promote"),
        "org": str(hs("org")),
    ]))
    guard case .object(let p) = try PayloadBuilder.build(draft: draft, attachments: .object(["record_body_b64": str("YQ==")]),
                                                         fixed: Fixed(kid: kid, nonce: hs("n"), performer: "alice", ts: ts)) else { return [:] }
    return p
}

private func act(_ payload: [String: JValue]) -> [String: JValue] {
    guard case .object(let ext)? = payload["ext"], case .object(let a)? = ext["dev.handsal/act"] else { return [:] }
    return a
}

private func with(_ payload: [String: JValue], act edit: ([String: JValue]) -> [String: JValue]) -> [String: JValue] {
    var out = payload
    out["ext"] = .object(["dev.handsal/act": .object(edit(act(payload)))])
    return out
}

private func expect(_ code: String, _ body: () throws -> Void) {
    #expect(throws: Refusal(code)) { try body() }
}

@Suite("act envelope and act object (ACT-01, ACT-06, ACT-13, ACT-14)")
struct EnvelopeTests {
    @Test func aBuiltPayloadPasses() throws {
        let p = try removePayload()
        try Envelope.checkEnvelope(.object(p))
        try Envelope.checkActObject(p, headerKid: kid, registry: .standard, headPresent: nil)
        let q = try promotePayload()
        try Envelope.checkEnvelope(.object(q))
        try Envelope.checkActObject(q, headerKid: kid, registry: .standard, headPresent: nil)
    }

    @Test(arguments: [
        ("v", JValue.string("vitni/0.1")), ("binding", .string("mcp")), ("status", .string("FAILED")),
        ("log_policy", .string("x")), ("reason", .string("r")), ("action_ref", .string("a")), ("requester_id", .string("r")),
        ("cost", .object(["rail_ref": .null, "tokens": .string("1"), "usd_micros": .string("0"), "wall_ms": .string("0")])),
        ("nonce", .string("x")), ("inputs_hash", .string("uEi")), ("outputs_hash", .null), ("parent_receipt_hash", .string("x")),
        ("parent_performer_id", .string("A")), ("performer_id", .string("A")), ("ts", .string("2026-13-01T00:00:00Z")),
        ("method", .null), ("ext", .object([:])), ("ext", .object(["dev.handsal/act": .object([:]), "x.other": .null])),
        ("ext", .object(["dev.handsal/act": .string("x")])),
    ])
    func envelopeDefectsAreSchema(pair: (String, JValue)) throws {
        var p = try removePayload(); p[pair.0] = pair.1
        expect("schema") { try Envelope.checkEnvelope(.object(p)) }
    }

    @Test func keySetIsClosed() throws {
        var extra = try removePayload(); extra["x"] = .null
        expect("schema") { try Envelope.checkEnvelope(.object(extra)) }
        var missing = try removePayload(); missing["ts"] = nil
        expect("schema") { try Envelope.checkEnvelope(.object(missing)) }
        expect("schema") { try Envelope.checkEnvelope(.array([])) }
    }

    @Test func parentFieldsFollowTheMethod() throws {
        var chainNull = try removePayload(); chainNull["parent_receipt_hash"] = .null
        expect("schema") { try Envelope.checkActObject(chainNull, headerKid: kid, registry: .standard, headPresent: nil) }
        var promoteParent = try promotePayload(); promoteParent["parent_receipt_hash"] = str(hs("p"))
        expect("schema") { try Envelope.checkActObject(promoteParent, headerKid: kid, registry: .standard, headPresent: nil) }
        // a primary under the root has a null parent performer
        var root = try removePayload(); root["parent_performer_id"] = .null
        try Envelope.checkActObject(root, headerKid: kid, registry: .standard, headPresent: nil)
    }

    @Test func actObjectDefects() throws {
        let p = try removePayload()
        expect("schema") { try Envelope.checkActObject(p, headerKid: otherKid, registry: .standard, headPresent: nil) }
        expect("schema") { try Envelope.checkActObject(with(p) { var a = $0; a["x"] = .null; return a }, headerKid: kid, registry: .standard, headPresent: nil) }
        expect("schema") { try Envelope.checkActObject(with(p) { var a = $0; a["head"] = .object(["id": str(hs("h")), "kind": str("chain")]); return a }, headerKid: kid, registry: .standard, headPresent: nil) }
        expect("schema") { try Envelope.checkActObject(with(p) { var a = $0; a["kid"] = nil; return a }, headerKid: kid, registry: .standard, headPresent: nil) }
        let q = try promotePayload()
        expect("schema") { try Envelope.checkActObject(with(q) { var a = $0; a["head"] = nil; return a }, headerKid: kid, registry: .standard, headPresent: nil) }
        expect("schema") { try Envelope.checkActObject(with(q) { var a = $0; a["expires"] = str("tomorrow"); return a }, headerKid: kid, registry: .standard, headPresent: nil) }
        expect("body_schema") { try Envelope.checkActObject(with(p) { var a = $0; a["body"] = .object(["kid": str(otherKid)]); return a }, headerKid: kid, registry: .standard, headPresent: nil) }
        // one defect in the act object and one in the body: schema is ordered first
        expect("schema") { try Envelope.checkActObject(with(p) { var a = $0; a["kid"] = str(otherKid); a["body"] = .object([:]); return a }, headerKid: kid, registry: .standard, headPresent: nil) }
    }
}

private func segment(_ bytes: [UInt8]) -> String { Encoding.base64url(bytes) }
private func jws(payload: [UInt8], header: String? = nil, signature: [UInt8] = [UInt8](repeating: 7, count: 64)) -> String {
    let h = header ?? #"{"alg":"ES256","kid":"\#(kid)"}"#
    return [segment(Array(h.utf8)), segment(payload), segment(signature)].joined(separator: ".")
}

@Suite("one act, read once (ACT-02, ACT-03, ACT-12)")
struct ActParseTests {
    private func parse(_ text: String, wanted: Set<String> = [Methods.deviceRemove]) throws -> ParsedAct {
        try Acts.parse(text, registry: .standard, wanted: wanted)
    }

    @Test func readsAValidAct() throws {
        let bytes = try Emit.subset(.object(removePayload()))
        let parsed = try parse(jws(payload: bytes))
        #expect(parsed.id == Encoding.hashstr(bytes) && parsed.kid == kid && parsed.method == Methods.deviceRemove)
        #expect(parsed.performer == "alice" && parsed.parent == hs("p") && parsed.parentPerformer == "bob")
        #expect(parsed.signature.count == 64)
    }

    @Test func receiptIdIsOfThePayloadNotTheSignature() throws {
        let bytes = try Emit.subset(.object(removePayload()))
        let a = try parse(jws(payload: bytes, signature: [UInt8](repeating: 1, count: 64)))
        let b = try parse(jws(payload: bytes, signature: [UInt8](repeating: 2, count: 64)))
        #expect(a.id == b.id)
    }

    @Test func jwsShapeDefects() throws {
        let bytes = try Emit.subset(.object(removePayload()))
        let good = jws(payload: bytes)
        for bad in [good + ".x", String(good.split(separator: ".").prefix(2).joined(separator: ".")), "a.b.c", "", "..",
                    jws(payload: bytes, header: #"{"alg":"ES256","kid":"\#(kid)","typ":"JWT"}"#),
                    jws(payload: bytes, header: #"{"kid":"\#(kid)","alg":"ES256"}"#),
                    jws(payload: bytes, header: #"{"alg":"ES256", "kid":"\#(kid)"}"#),
                    jws(payload: bytes, header: #"{"alg":"ES384","kid":"\#(kid)"}"#),
                    jws(payload: bytes, signature: [UInt8](repeating: 7, count: 63)),
                    jws(payload: bytes, signature: [UInt8](repeating: 7, count: 65)),
                    good.replacingOccurrences(of: ".", with: "=.", options: [], range: good.startIndex..<good.endIndex)] {
            expect("jws_shape") { _ = try parse(bad) }
        }
    }

    @Test func payloadMustBeACanonicalObject() throws {
        expect("payload_not_canonical_subset") { _ = try parse(jws(payload: Array("[]".utf8))) }
        expect("payload_not_canonical_subset") { _ = try parse(jws(payload: Array("null".utf8))) }
        expect("payload_not_canonical_subset") { _ = try parse(jws(payload: Array(#"{"a": "b"}"#.utf8))) }
    }

    @Test func methodMustBeOneTheCallerReads() throws {
        let bytes = try Emit.subset(.object(removePayload()))
        expect("method_unknown") { _ = try parse(jws(payload: bytes), wanted: [Methods.deviceAdd]) }
    }

    @Test func fixedHashesAreChecked() throws {
        var p = try removePayload(); p["inputs_hash"] = str(hs("x"))
        expect("schema") { _ = try parse(jws(payload: try Emit.subset(.object(p)))) }
        var q = try removePayload(); q["outputs_hash"] = str(hs("x"))
        expect("schema") { _ = try parse(jws(payload: try Emit.subset(.object(q)))) }
    }

    @Test func headerKidMustEqualTheActObjectKid() throws {
        let bytes = try Emit.subset(.object(removePayload()))
        let other = [segment(Array(#"{"alg":"ES256","kid":"\#(otherKid)"}"#.utf8)), segment(bytes), segment([UInt8](repeating: 7, count: 64))].joined(separator: ".")
        expect("schema") { _ = try parse(other) }
    }
}
