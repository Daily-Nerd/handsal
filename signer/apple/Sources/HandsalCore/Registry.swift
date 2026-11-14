/// The registry (KC-01, ACT-09): key classes, the method table and the section 2 constants.
///
/// `spec/registry.json` is the file the profile hash covers. These tables are written out in Swift
/// because the signer has no Foundation JSON, so `RegistryGuardTests` compares them with the file
/// and fails the moment they differ. A table that is not the registry never ships green.

public enum Form: String, Sendable {
    case hashstr, b64u32, kid, memberId = "member_id", roleId = "role_id", classId = "class_id"
    case requestId = "request_id", recordId = "record_id", label, orgName = "org_name", anchor
    case hostname, time, decimal

    func accepts(_ value: String) -> Bool {
        switch self {
        case .hashstr: return Forms.isHashstr(value)
        case .b64u32, .kid: return Forms.isB64u32(value)
        case .memberId: return Forms.isMemberId(value)
        case .roleId: return Forms.isRoleId(value)
        case .classId: return Forms.isClassId(value)
        case .requestId: return Forms.isRequestId(value)
        case .recordId: return Forms.isRecordId(value)
        case .label: return Forms.isLabel(value)
        case .orgName: return Forms.isOrgName(value)
        case .anchor: return Forms.isAnchor(value)
        case .hostname: return Forms.isHostname(value)
        case .time: return Forms.isTime(value)
        case .decimal: return Forms.isDecimal(value)
        }
    }

    /// The forms ACT-07 names: their defect is `schema` wherever they sit.
    var isAct07: Bool { self == .hashstr || self == .time || self == .memberId || self == .decimal }
}

public indirect enum SchemaNode: Sendable {
    case leaf(Form)
    case const(String)
    case keys([String: SchemaNode])
    /// The subtree reports its defects under another container code (a body inside the act object).
    case scoped(code: String, SchemaNode)
    case list(of: SchemaNode, cap: String, sorted: Bool, distinct: Bool, sortedBy: String?, distinctBy: String?)

    static func hashList(cap: String) -> SchemaNode {
        .list(of: .leaf(.hashstr), cap: cap, sorted: true, distinct: true, sortedBy: nil, distinctBy: nil)
    }

    /// The node in the vocabulary `spec/registry.json` uses.
    public var registryJSON: JValue {
        switch self {
        case .leaf(let form): return .object(["type": .string(form.rawValue)])
        case .const(let text): return .object(["const": .string(text)])
        case .keys(let members): return .object(["keys": .object(members.mapValues { $0.registryJSON })])
        case .scoped(_, let node): return node.registryJSON
        case .list(let of, let cap, let sorted, let distinct, let sortedBy, let distinctBy):
            var out: [String: JValue] = ["type": .string("list"), "cap": .string(cap)]
            if case .leaf(let form) = of { out["of"] = .string(form.rawValue) } else { out["of"] = of.registryJSON }
            if sorted { out["sorted"] = .bool(true) }
            if distinct { out["distinct"] = .bool(true) }
            if let sortedBy { out["sorted_by"] = .string(sortedBy) }
            if let distinctBy { out["distinct_by"] = .string(distinctBy) }
            return .object(out)
        }
    }
}

public enum HeadRule: String, Sendable { case always, conditional, never }

public struct MethodSpec: Sendable {
    public let name: String
    public let actExtraKeys: [String]
    public let head: HeadRule
    public let body: SchemaNode
    public let inputsHash: String
    public let outputsHash: String
}

public struct ClassSpec: Sendable {
    public let id: String
    public let status: String
    public let userVerification: String?
}

public struct Registry: Sendable {
    public let methods: [String: MethodSpec]
    public let classes: [String: ClassSpec]
    public let fixtureOnly: [String: ClassSpec]
    public let actExtraKeyTypes: [String: Form]
    private let constants: [String: Int]

    /// The value of a registry constant by path, for example `persons.min`. A name that is not in
    /// the table is a bug in the caller and stops the process, never a default.
    public func number(_ path: String) -> Int {
        guard let value = constants[path] else { fatalError("registry has no constant \(path)") }
        return value
    }

    public var constantPaths: [String] { Array(constants.keys) }

    /// A copy with one more class. Not public: only a test of a rule that reads a class the shipped
    /// registry has none of (a `pending-spike` class, KC-02: the first tag has none) builds one.
    func addingClass(_ spec: ClassSpec) -> Registry {
        Registry(methods: methods, classes: classes.merging([spec.id: spec]) { _, new in new },
                 fixtureOnly: fixtureOnly, actExtraKeyTypes: actExtraKeyTypes, constants: constants)
    }

    /// The class `id` under the profile kind, or nil (`class_unknown`).
    public func lookupClass(_ id: String, fixture: Bool) -> ClassSpec? {
        classes[id] ?? (fixture ? fixtureOnly[id] : nil)
    }

    private static func keys(_ members: [String: SchemaNode]) -> SchemaNode { .keys(members) }
    private static let pointNode = SchemaNode.keys(["x": .leaf(.b64u32), "y": .leaf(.b64u32)])

    private static func method(_ name: String, extra: [String] = [], head: HeadRule, body: SchemaNode,
                               inputs: String, outputs: String) -> (String, MethodSpec) {
        let full = "local:handsal." + name
        return (full, MethodSpec(name: full, actExtraKeys: extra, head: head, body: body, inputsHash: inputs, outputsHash: outputs))
    }

    private static let deviceKeys: [String: SchemaNode] = [
        "agree": pointNode, "class": .leaf(.classId), "kid": .leaf(.kid), "label": .leaf(.label), "sign": pointNode,
    ]

    public static let standard: Registry = {
        var device = deviceKeys
        device["link_code_hash"] = .leaf(.hashstr)
        device["person"] = .leaf(.memberId)
        let overrideEntry = SchemaNode.keys([
            "endorsements": .hashList(cap: "chain_resolve_caps.endorsements_per_override"),
            "resolve": .leaf(.hashstr),
        ])
        let verdictExtra = ["expires", "recipient", "relay", "request_id"]
        let table = [
            method("genesis.sign", head: .conditional, body: .keys([:]), inputs: "jcs_genesis_document", outputs: "empty"),
            method("device.add", head: .never, body: .keys(device), inputs: "empty", outputs: "empty"),
            method("device.remove", head: .never, body: .keys(["kid": .leaf(.kid), "person": .leaf(.memberId)]),
                   inputs: "empty", outputs: "empty"),
            method("member.add", head: .never, body: .keys([
                "device": .keys(deviceKeys), "link_code_hash": .leaf(.hashstr), "member": .leaf(.memberId),
                "role": .leaf(.roleId),
            ]), inputs: "empty", outputs: "empty"),
            method("chain.resolve", head: .never, body: .keys([
                "candidates": .hashList(cap: "chain_resolve_caps.candidates"),
                "choose": .leaf(.hashstr),
                "heads": .hashList(cap: "chain_resolve_caps.heads"),
                "overrides": .list(of: overrideEntry, cap: "chain_resolve_caps.overrides", sorted: false,
                                   distinct: false, sortedBy: "resolve", distinctBy: "resolve"),
            ]), inputs: "empty", outputs: "empty"),
            method("act.endorse", head: .always, body: .keys(["act": .leaf(.hashstr)]), inputs: "empty", outputs: "empty"),
            method("request.approve", extra: verdictExtra, head: .always, body: .keys([:]),
                   inputs: "raw_request_bytes", outputs: "verdict:approve"),
            method("request.reject", extra: verdictExtra, head: .always, body: .keys([:]),
                   inputs: "raw_request_bytes", outputs: "verdict:reject"),
            method("request.needs-info", extra: verdictExtra, head: .always, body: .keys([:]),
                   inputs: "raw_request_bytes", outputs: "verdict:needs-info"),
            method("record.promote", extra: ["expires"], head: .always, body: .keys([
                "anchors": .list(of: .leaf(.anchor), cap: "record_promote_anchors", sorted: false, distinct: false,
                                 sortedBy: nil, distinctBy: nil),
                "record_id": .leaf(.recordId),
            ]), inputs: "raw_record_body_bytes", outputs: "empty"),
        ]
        func cls(_ id: String, _ status: String, _ uv: String?) -> (String, ClassSpec) {
            (id, ClassSpec(id: id, status: status, userVerification: uv))
        }
        return Registry(
            methods: Dictionary(uniqueKeysWithValues: table),
            classes: Dictionary(uniqueKeysWithValues: [
                cls("apple-se-bio", "active", "biometric_only"),
                cls("test-sw-p256", "test-only", "none"),
            ]),
            fixtureOnly: Dictionary(uniqueKeysWithValues: [cls("fixture-pin", "active", "biometric_or_pin")]),
            actExtraKeyTypes: ["expires": .time, "recipient": .memberId, "relay": .hostname, "request_id": .requestId],
            constants: [
                "MAX_PAYLOAD": 16384, "MAX_DEPTH": 8, "MAX_INPUT": 16_777_216, "MAX_NESTING": 64, "MAX_EXPIRES_IN_S": 2_592_000,
                "pin_file_size.max": 512,
                "persons.min": 2, "persons.max": 15,
                "clock_skew_s.min": 0, "clock_skew_s.max": 3600,
                "max_validity_s.min": 60, "max_validity_s.max": 2_592_000,
                "max_view_age_s.min": 60, "max_view_age_s.max": 2_592_000,
                "max_tip_age_s.min": 60, "max_tip_age_s.max": 86_400,
                "record_promote_anchors.min": 1, "record_promote_anchors.max": 16,
                "chain_resolve_caps.candidates.min": 2, "chain_resolve_caps.candidates.max": 17,
                "chain_resolve_caps.heads.min": 1, "chain_resolve_caps.heads.max": 16,
                "chain_resolve_caps.overrides.min": 0, "chain_resolve_caps.overrides.max": 16,
                "chain_resolve_caps.endorsements_per_override.min": 1,
                "chain_resolve_caps.endorsements_per_override.max": 15,
                "render_line_1.max": 80,
                "render_line.max": 100, "render_line.wrap_segment_max": 98,
                "render_length.max": 72,
                "request_and_record_block.max_source_bytes": 2048, "request_and_record_block.max_block_lines": 32,
                "request_and_record_block.max_escaped_bytes_per_line": 96,
            ])
    }()
}

/// The closed-object engine (ACT-07, ACT-09, ACT-10). Which reason code a defect gets:
/// the ACT-07 forms are `schema` wherever they sit; any other defect takes the code of the
/// container being checked (`schema` for the act object, `body_schema` for a body).
public enum Schema {
    public static func defects(_ node: SchemaNode, _ value: JValue, _ registry: Registry, code: String) -> [String] {
        var found: [String] = []
        walk(node, value, registry, code, &found)
        return found
    }

    /// Throws the code ordered first in `found`: `schema` before the rest.
    public static func refuse(_ found: [String]) throws {
        if found.contains("schema") { throw Refusal("schema") }
        if let first = found.first { throw Refusal(first) }
    }

    public static func check(_ node: SchemaNode, _ value: JValue, _ registry: Registry, code: String) throws {
        try refuse(defects(node, value, registry, code: code))
    }

    private static func orderDefect(sorted: Bool, distinct: Bool, by: String?, items: [JValue]) -> Bool {
        var keys: [[UInt8]] = []
        for item in items {
            if let by {
                guard case .object(let members) = item, case .string(let s)? = members[by] else { return false }
                keys.append(Array(s.utf8))
            } else {
                guard case .string(let s) = item else { return false }
                keys.append(Array(s.utf8))
            }
        }
        if sorted, zip(keys, keys.dropFirst()).contains(where: { $1.lexicographicallyPrecedes($0) }) { return true }
        return distinct && Set(keys).count != keys.count
    }

    private static func walk(_ node: SchemaNode, _ value: JValue, _ registry: Registry, _ code: String, _ found: inout [String]) {
        switch node {
        case .const(let text):
            if case .string(let s) = value, s == text { return }
            found.append(code)
        case .scoped(let scope, let inner):
            walk(inner, value, registry, scope, &found)
        case .keys(let expected):
            guard case .object(let members) = value else { found.append(code); return }
            if Set(members.keys) != Set(expected.keys) { found.append(code) }
            for name in expected.keys.sorted() {
                if let child = members[name], let childNode = expected[name] { walk(childNode, child, registry, code, &found) }
            }
        case .list(let of, let cap, let sorted, let distinct, let sortedBy, let distinctBy):
            guard case .array(let items) = value else { found.append(code); return }
            if items.count < registry.number(cap + ".min") || items.count > registry.number(cap + ".max") { found.append(code) }
            for item in items { walk(of, item, registry, code, &found) }
            if orderDefect(sorted: sorted || sortedBy != nil, distinct: distinct || distinctBy != nil,
                           by: sortedBy ?? distinctBy, items: items) { found.append(code) }
        case .leaf(let form):
            if case .string(let s) = value, form.accepts(s) { return }
            found.append(form.isAct07 ? "schema" : code)
        }
    }
}
