import HandsalConformance
import HandsalCore
import Testing

/// The `emit` expectations the catalog gives (SG-01, SG-04, SG-13, CF-04), written as tests through
/// `handsal-sign-conformance` so they hold before the vector files exist and after: each case is
/// one catalog id, one input, one exit code and one output.
@Suite("emit expectations of the catalog (CF-04)")
struct EmitCatalogTests {
    private static let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"

    private func fixed(performer: String = "alice") -> JValue {
        .object(["kid": jstr(Self.kid), "nonce": jstr(hsh("nonce")), "performer": jstr(performer), "ts": jstr("2026-11-08T11:59:00Z")])
    }

    private func emit(_ draft: JValue, attachments: JValue = .object(["request_b64": jstr(requestB64)]), performer: String = "alice") -> Outcome {
        let input = JValue.object(["attachments": attachments, "draft": draft, "fixed": fixed(performer: performer)])
        return ConformanceCLI.run(arguments: ["emit"], readStdin: { ((try? Emit.subset(input)) ?? []) + [0x0A] })
    }

    private func with(_ draft: JValue, _ edit: (inout [String: JValue]) -> Void) -> JValue {
        guard case .object(var members) = draft else { return draft }
        edit(&members)
        return .object(members)
    }

    private func refused(_ outcome: Outcome, _ code: String, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(outcome.exit == 2 && lineText(outcome) == errorLine(code), sourceLocation: sourceLocation)
    }

    private func payload(_ outcome: Outcome) -> JValue? {
        guard outcome.exit == 0, case .string(let hex)? = resultObject(outcome)["payload_hex"],
              case .success(let value) = Subset.parse(Vector.decodeHex(hex), maxSize: Limits.maxPayload) else { return nil }
        return value
    }

    @Test("cli/build-approve and sgn/emit-act-kid-filled: the act object carries the header kid")
    func anApproveDraftEmitsAPayloadWithTheFixedKid() throws {
        let out = emit(verdictDraft())
        #expect(out.exit == 0)
        let value = try #require(payload(out))
        #expect(value["performer_id"] == jstr("alice") && value["nonce"] == jstr(hsh("nonce")) && value["ts"] == jstr("2026-11-08T11:59:00Z"))
        #expect(value["ext"]?["dev.handsal/act"]?["kid"] == jstr(Self.kid))
        #expect(value["ext"]?["dev.handsal/act"]?["recipient"] == jstr("alice"))
        #expect(value["outputs_hash"] == jstr(Encoding.hashstr(Array(#"{"request_id":"req-00000001","verdict":"approve"}"#.utf8))))
        let reject = try #require(payload(emit(with(verdictDraft()) { $0["method"] = jstr(Methods.reject) })))
        #expect(reject["outputs_hash"] == jstr(Encoding.hashstr(Array(#"{"request_id":"req-00000001","verdict":"reject"}"#.utf8))))
    }

    @Test("cli/build-bad-nonce: a nonce that is no hashstr is refused")
    func aBadFixedNonceIsRefused() {
        let input = JValue.object(["attachments": .object(["request_b64": jstr(requestB64)]), "draft": verdictDraft(),
                                   "fixed": .object(["kid": jstr(Self.kid), "nonce": jstr("not-a-hashstr"), "performer": jstr("alice"), "ts": jstr("2026-11-08T11:59:00Z")])])
        refused(ConformanceCLI.run(arguments: ["emit"], readStdin: { (try? Emit.subset(input)) ?? [] }), "schema_refused")
    }

    @Test("sgn/refuse-ts-input, refuse-nonce-input, refuse-display-text, refuse-auth-handle, refuse-schema-violation")
    func theCallerMayNotSupplyWhatTheSignerOwns() {
        for (key, value) in [("ts", "2026-11-08T11:59:00Z"), ("nonce", hsh("n")), ("prompt", "Approve this"), ("auth_context", "handle"),
                             ("inputs_hash", hsh("i")), ("outputs_hash", hsh("o")), ("performer_id", "alice")] {
            refused(emit(with(verdictDraft()) { $0[key] = jstr(value) }), "schema_refused")
        }
        refused(emit(with(chainDraft()) { $0["body"] = .object(["kid": jstr(Self.kid), "person": jstr("carol"), "extra": .null]) }), "schema_refused")
    }

    @Test("sgn/refuse-unknown-method: a method outside the registry is unsupported_method")
    func anUnknownMethodIsUnsupported() {
        refused(emit(with(verdictDraft()) { $0["method"] = jstr("local:handsal.request.send") }), "unsupported_method")
    }

    @Test("sgn/expires-in-s-refused-for-chain-method, sgn/expires-over-30d, sgn/expires-in-s-zero-refused")
    func expiresInSRules() throws {
        refused(emit(with(chainDraft()) { $0["expires_in_s"] = jstr("60") }), "schema_refused")
        refused(emit(with(verdictDraft()) { $0["expires_in_s"] = jstr("2592001") }), "schema_refused")
        refused(emit(with(verdictDraft()) { $0["expires_in_s"] = jstr("0") }), "schema_refused")
        let top = try #require(payload(emit(with(verdictDraft()) { $0["expires_in_s"] = jstr("2592000") })))
        #expect(top["ext"]?["dev.handsal/act"]?["expires"] == jstr("2026-12-08T11:59:00Z"))
        let one = try #require(payload(emit(with(verdictDraft()) { $0["expires_in_s"] = jstr("1") })))
        #expect(one["ext"]?["dev.handsal/act"]?["expires"] == jstr("2026-11-08T11:59:01Z"))
    }

    @Test("sgn/parent-performer-required: a chain draft whose parent has no performer key")
    func theParentNeedsItsPerformerKey() {
        refused(emit(with(chainDraft()) { $0["parent"] = .object(["id": jstr(hsh("p"))]) }), "schema_refused")
    }

    @Test("sgn/verdict-recipient-not-performer-refused, verdict-draft-missing-relay-refused, chain-draft-recipient-refused")
    func verdictDraftRules() {
        refused(emit(with(verdictDraft()) { $0["recipient"] = jstr("bob") }), "identity_mismatch")
        refused(emit(with(verdictDraft()) { $0["relay"] = nil }), "schema_refused")
        refused(emit(with(chainDraft()) { $0["recipient"] = jstr("alice") }), "schema_refused")
        #expect(emit(with(verdictDraft()) { $0["recipient"] = jstr("bob") }, performer: "bob").exit == 0)
    }

    @Test("sgn/genesis-org-not-document-hash-refused")
    func theGenesisOrgIsTheDocumentHash() {
        let document = JValue.object(["prev": .null])
        let right = Encoding.hashstr(Array(#"{"prev":null}"#.utf8))
        let draft = JValue.object(["body": .object([:]), "method": jstr(Methods.genesisSign), "org": jstr(right)])
        #expect(emit(draft, attachments: .object(["document": document])).exit == 0)
        refused(emit(with(draft) { $0["org"] = jstr(hsh("org")) }, attachments: .object(["document": document])), "attachment_mismatch")
    }

    @Test("jcs/emit-sorted, jcs/emit-slash-raw, jcs/emit-value-with-number-refused")
    func theEmittedBytesAreCanonical() throws {
        let draft = JValue.object(["body": .object(["anchors": .array([jstr("a/b")]), "record_id": jstr("rec-0001")]), "expires_in_s": jstr("60"),
                                   "head": .object(["id": jstr(hsh("h")), "kind": jstr("chain")]), "method": jstr(Methods.promote), "org": jstr(hsh("org"))])
        let out = emit(draft, attachments: .object(["record_body_b64": jstr("YQ==")]))
        guard case .string(let hex)? = resultObject(out)["payload_hex"] else { Issue.record("no payload"); return }
        let bytes = Vector.decodeHex(hex)
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(text.contains(#""anchors":["a/b"]"#))                 // slash written raw
        #expect(text.hasPrefix(#"{"action_ref":null,"binding":"local","cost":"#))   // keys in byte order
        #expect(text.contains(#""tokens":"0""#) && !text.contains(" "))
        // a number anywhere in the input is refused, never coerced
        let withNumber = Array(#"{"attachments":{},"draft":{"body":{"n":1}},"fixed":{}}"#.utf8)
        let refusedOutcome = ConformanceCLI.run(arguments: ["emit"], readStdin: { withNumber })
        refused(refusedOutcome, "schema_refused")
    }
}
