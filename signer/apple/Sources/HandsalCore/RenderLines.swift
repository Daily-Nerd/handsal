/// Line 1 (RN-03), the method lines (RN-04) and the request, record and decision blocks (RN-05, RN-12).
///
/// `facts` carries what a bound attachment tells line 1 and the method lines: the raw bytes of a
/// request or a record body, the line 1 of each attached candidate and head act, the endorsed act,
/// the genesis summary. Nothing here reads an attachment; `RenderAttach` binds them first.
///
/// `block` renders untrusted bytes. They are never decoded as UTF-8: each source line is `| `
/// plus its escaped bytes, 0x20 to 0x7E as is and every other byte as `\xHH`, so no Unicode table
/// is needed, a line `----- end -----` in the request cannot end the block, and control and
/// bidirectional bytes are visible. A block over 2048 source bytes or 32 lines is `render_refused`:
/// nothing is truncated.
struct Facts {
    var raw: [UInt8]?
    var summary: String?
    var candidates: [String: String] = [:]
    var heads: [String: String] = [:]
    var endorsedLine1: String?
    var endorsedLines: [String] = []
}

enum RenderLines {
    private static let verdictTitles = [
        Methods.approve: "APPROVE request", Methods.reject: "REJECT request", Methods.needsInfo: "NEEDS-INFO on request",
    ]

    private static func schema() -> Refusal { Refusal("schema") }

    private static func act(_ payload: [String: JValue]) throws -> [String: JValue] {
        guard let a = payload["ext"]?[Envelope.extKey]?.dict else { throw schema() }
        return a
    }

    private static func field(_ object: [String: JValue]?, _ key: String) throws -> String {
        guard let s = object?[key]?.str else { throw schema() }
        return s
    }

    private static func body(_ act: [String: JValue]) throws -> [String: JValue] {
        guard let b = act["body"]?.dict else { throw schema() }
        return b
    }

    static func firstLine(method: String, payload: [String: JValue], facts: Facts) throws -> String {
        let a = try act(payload)
        let b = try body(a)
        switch method {
        case Methods.deviceAdd:
            return "Add device \(Render.kid12(try field(b, "kid"))) (\(Render.cut12(try field(b, "class")))) to \(Render.cut12(try field(b, "person")))"
        case Methods.deviceRemove:
            return "Remove device \(Render.kid12(try field(b, "kid"))) of \(Render.cut12(try field(b, "person")))"
        case Methods.memberAdd:
            let device = b["device"]?.dict
            return "Add device \(Render.kid12(try field(device, "kid"))) as member \(Render.cut12(try field(b, "member"))) (\(Render.cut12(try field(b, "role"))))"
        case Methods.promote:
            guard let raw = facts.raw else { throw Refusal("attachment_missing") }
            return "Promote record \(Render.cut12(try field(b, "record_id"))) (\(Render.hash12(try field(payload, "inputs_hash"))), \(raw.count) bytes)"
        case Methods.decision:
            // `<consumer>: <action> <subject> (<hash12>, <N> bytes)`: consumer and subject are cut like any free
            // field, the action is whole (its grammar bounds it at 24 so the line stays at 80 bytes, RN-03)
            guard let raw = facts.raw else { throw Refusal("attachment_missing") }
            return "\(Render.cut12(try field(b, "consumer"))): \(try field(b, "action")) \(Render.cut12(try field(b, "subject"))) (\(Render.hash12(try field(payload, "inputs_hash"))), \(raw.count) bytes)"
        case Methods.resolve:
            guard let line = facts.candidates[try field(b, "choose")] else { throw Refusal("attachment_missing") }
            return "Resolve fork, keep: " + Render.cut(line, to: 59)
        case Methods.endorse:
            guard let line = facts.endorsedLine1 else { throw Refusal("attachment_missing") }
            return "Endorse: " + Render.cut(line, to: 70)
        case Methods.genesisSign:
            guard let summary = facts.summary else { throw Refusal("attachment_missing") }
            return summary
        default:
            guard let title = verdictTitles[method], let raw = facts.raw else { throw Refusal("method_unknown") }
            return "\(title) \(Render.cut12(try field(a, "request_id"))) (\(Render.hash12(try field(payload, "inputs_hash"))), \(raw.count) bytes)"
        }
    }

    // MARK: block

    private static func escape(_ raw: ArraySlice<UInt8>) -> [String] {
        let hex = Array("0123456789abcdef".utf8)
        return raw.map { byte in
            if byte >= 0x20 && byte <= 0x7E { return String(UnicodeScalar(byte)) }
            return "\\x" + String(UnicodeScalar(hex[Int(byte >> 4)])) + String(UnicodeScalar(hex[Int(byte & 15)]))
        }
    }

    /// The content of one source line in segments of at most 96 characters, never splitting an escape.
    private static func segments(_ tokens: [String]) -> [String] {
        var out: [String] = []
        var current = ""
        var size = 0
        for token in tokens {
            if size + token.utf8.count > Limits.blockLineBytes {
                out.append(current)
                current = ""
                size = 0
            }
            current += token
            size += token.utf8.count
        }
        out.append(current)
        return out
    }

    static func block(title: String, raw: [UInt8], inputsHash: String) throws -> [String] {
        guard raw.count <= Limits.blockMaxBytes else { throw Refusal("render_refused") }
        var sources = raw.split(separator: 0x0A, omittingEmptySubsequences: false)
        if sources.last?.isEmpty == true { sources.removeLast() }   // a final LF ends the last line
        var content: [String] = []
        for source in sources {
            let parts = segments(escape(source))
            content.append("| " + parts[0])
            content.append(contentsOf: parts.dropFirst().map { "|+" + $0 })
        }
        guard content.count <= Limits.blockMaxLines else { throw Refusal("render_refused") }
        let header = "----- \(title) (\(raw.count) bytes, sha256 \(Render.hash12(inputsHash))) -----"
        return [header] + content + ["----- end -----"]
    }

    // MARK: method lines

    private static func agree(_ device: [String: JValue]?) throws -> String {
        guard let point = device?["agree"]?.dict else { throw schema() }
        return "Agree key: " + Encoding.thumbprint(x: try field(point, "x"), y: try field(point, "y"))
    }

    private static func listed(_ title: String, _ ids: [String], _ lineOf: [String: String], marker: String? = nil) throws -> [String] {
        var out = [title]
        for id in ids {
            guard let line = lineOf[id] else { throw Refusal("attachment_missing") }
            let lead = marker == nil ? "  - " : (id == marker ? "  > " : "    ")
            out.append("\(lead)\(Render.hash12(id)) \(line)")
        }
        return out
    }

    private static func strings(_ value: JValue?) throws -> [String] {
        guard let items = value?.list else { throw schema() }
        return try items.map { guard let s = $0.str else { throw schema() }; return s }
    }

    static func methodLines(method: String, payload: [String: JValue], facts: Facts) throws -> [String] {
        let a = try act(payload)
        let b = try body(a)
        let inputs = try field(payload, "inputs_hash")
        switch method {
        case Methods.deviceAdd:
            return ["Person: " + (try field(b, "person")), "New device: " + (try field(b, "kid")), try agree(b),
                    "Class: " + (try field(b, "class")), "Label: " + (try field(b, "label")),
                    "Link code: " + Render.hash12(try field(b, "link_code_hash"))]
        case Methods.deviceRemove:
            return ["Person: " + (try field(b, "person")), "Remove device: " + (try field(b, "kid"))]
        case Methods.memberAdd:
            let device = b["device"]?.dict
            return ["Member: " + (try field(b, "member")), "Role: " + (try field(b, "role")),
                    "New device: " + (try field(device, "kid")), try agree(device),
                    "Class: " + (try field(device, "class")), "Label: " + (try field(device, "label"))]
        case Methods.promote:
            guard let raw = facts.raw else { throw Refusal("attachment_missing") }
            var out = ["Record: " + (try field(b, "record_id")), "Anchors:"]
            out += try strings(b["anchors"]).map { "  - " + $0 }
            out.append("Body hash: " + Render.hash12(inputs))
            return out + (try block(title: "record body", raw: raw, inputsHash: inputs))
        case Methods.decision:
            guard let raw = facts.raw else { throw Refusal("attachment_missing") }
            let out = ["Consumer: " + (try field(b, "consumer")), "Action: " + (try field(b, "action")),
                       "Subject: " + (try field(b, "subject")), "Decision hash: " + Render.hash12(inputs)]
            return out + (try block(title: "decision", raw: raw, inputsHash: inputs))
        case Methods.resolve:
            let choose = try field(b, "choose")
            var out = ["Fork parent: " + (try field(payload, "parent_receipt_hash")), "Choose: " + choose]
            out += try listed("Candidates:", try strings(b["candidates"]), facts.candidates, marker: choose)
            out += try listed("Heads:", try strings(b["heads"]), facts.heads)
            guard let overrides = b["overrides"]?.list else { throw schema() }
            if overrides.isEmpty { return out + ["Overrides: none"] }
            out.append("Overrides:")
            for entry in overrides {
                guard let e = entry.dict, let count = e["endorsements"]?.list?.count else { throw schema() }
                out.append("  - \(Render.hash12(try field(e, "resolve"))) (endorsements: \(count))")
            }
            return out
        case Methods.endorse:
            return ["Endorsed act: " + (try field(b, "act"))] + facts.endorsedLines
        default:
            guard verdictTitles[method] != nil, let raw = facts.raw else { throw Refusal("method_unknown") }
            let out = ["Request: " + (try field(a, "request_id")), "Recipient: " + (try field(a, "recipient")),
                       "Relay: " + (try field(a, "relay")), "Request hash: " + Render.hash12(inputs)]
            return out + (try block(title: "request", raw: raw, inputsHash: inputs))
        }
    }
}
