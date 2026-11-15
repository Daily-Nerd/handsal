/// Policy validation (GP-02, KC-02, KC-03, KC-07, WT-01): GP-15 step 3 up to the class codes.
///
/// One entry point, `validate`, running the checks in the order GP-15 fixes, each pass over the
/// whole policy before the next begins:
///   1. shape                        `policy_invalid` (witness shape included)
///   2. bounds                       `policy_out_of_bounds`
///   3. a spare person per rule      `policy_unreachable`
///   4. classes, one code per pass   `class_unknown`, `class_pending`, `class_test_only`,
///                                   `class_policy_mismatch`
/// Bounds are the registry's constants; this file names none. The policy is data: nothing here
/// names a class, a role or a threshold.
enum Policy {
    private static let topKeys: Set<String> = ["classes", "freshness", "relays", "roles", "rules", "v", "witness"]
    private static let freshnessKeys = ["clock_skew_s", "max_validity_s", "max_view_age_s"]
    private static let ruleNames: Set<String> = ["chain.resolve", "device.remove", "genesis.change", "member.add"]
    private static let version = "handsal-policy/1"
    private static let jwkKeys: Set<String> = ["crv", "kty", "x", "y"]
    private static let relayKeys: Set<String> = ["max_tip_age_s", "mode", "relay_kid", "relay_pub_jwk"]

    private static func invalid() -> Refusal { Refusal("policy_invalid") }

    private static func roleList(_ value: JValue?, listed: [String]? = nil) throws -> [String] {
        guard case .array(let items)? = value, !items.isEmpty else { throw invalid() }
        var out: [String] = []
        for item in items {
            guard case .string(let s) = item, Forms.isRoleId(s) else { throw invalid() }
            out.append(s)
        }
        guard Set(out).count == out.count else { throw invalid() }
        if let listed, !Set(out).isSubset(of: listed) { throw invalid() }
        return out
    }

    private static func decimal(_ value: JValue?) -> Int? {
        guard case .string(let s)? = value, Forms.isDecimal(s) else { return nil }
        return Int(s)
    }

    private struct Parsed {
        var rules: [[String: JValue]] = []
        var classes: [(name: String, uv: String)] = []
        var witness: [String: JValue] = [:]
        var freshness: [String: Int] = [:]
        var relays: [String] = []
        var persons: [Int] = []
        var ruleRoles: [[String]] = []
    }

    private static func shape(_ policy: JValue?, members: [JValue]) throws -> Parsed {
        guard case .object(let p)? = policy, Set(p.keys) == topKeys, p["v"] == .string(version) else { throw invalid() }
        var out = Parsed()
        let roles = try roleList(p["roles"])
        guard case .array(let classes)? = p["classes"], !classes.isEmpty else { throw invalid() }
        for entry in classes {
            guard case .object(let c) = entry, Set(c.keys) == ["class", "user_verification"],
                  case .string(let name)? = c["class"], case .string(let uv)? = c["user_verification"] else { throw invalid() }
            out.classes.append((name, uv))
        }
        guard Set(out.classes.map { $0.name }).count == out.classes.count else { throw invalid() }
        guard case .object(let fresh)? = p["freshness"], Set(fresh.keys) == Set(freshnessKeys) else { throw invalid() }
        for key in freshnessKeys {
            guard let n = decimal(fresh[key]) else { throw invalid() }
            out.freshness[key] = n
        }
        guard case .array(let hosts)? = p["relays"] else { throw invalid() }
        for host in hosts {
            guard case .string(let name) = host, Forms.isHostname(name) else { throw invalid() }
            out.relays.append(name)
        }
        guard Set(out.relays).count == out.relays.count else { throw invalid() }
        guard case .object(let rules)? = p["rules"], Set(rules.keys) == ruleNames else { throw invalid() }
        for rule in rules.values {
            guard case .object(let r) = rule, Set(r.keys) == ["persons", "roles"], let n = decimal(r["persons"]) else { throw invalid() }
            out.persons.append(n)
            out.ruleRoles.append(try roleList(r["roles"], listed: roles))
        }
        for member in members {
            guard case .object(let m) = member, case .string(let role)? = m["role"], roles.contains(role) else { throw invalid() }
        }
        guard case .object(let witness)? = p["witness"] else { throw invalid() }
        out.witness = witness
        return out
    }

    private static func witnessShape(_ witness: [String: JValue], devices: [JValue]) throws {
        guard case .string(let mode)? = witness["mode"] else { throw invalid() }
        if mode == "none" {
            guard Set(witness.keys) == ["mode"] else { throw invalid() }
            return
        }
        guard mode == "relay", Set(witness.keys) == relayKeys, decimal(witness["max_tip_age_s"]) != nil,
              case .object(let jwk)? = witness["relay_pub_jwk"], Set(jwk.keys) == jwkKeys,
              jwk["crv"] == .string("P-256"), jwk["kty"] == .string("EC"),
              case .string(let x)? = jwk["x"], case .string(let y)? = jwk["y"],
              DeviceKey.pointOk(.object(["x": .string(x), "y": .string(y)])),
              case .string(let kid)? = witness["relay_kid"], kid == Encoding.thumbprint(x: x, y: y) else { throw invalid() }
        for device in devices {
            guard case .object(let d) = device else { continue }
            if d["kid"] == .string(kid) { throw invalid() }
            for key in ["sign", "agree"] {
                if case .object(let point)? = d[key], point["x"] == .string(x), point["y"] == .string(y) { throw invalid() }
            }
        }
    }

    static func validate(_ policy: JValue?, members: [JValue], devices: [JValue], registry: Registry, fixture: Bool) throws {
        let parsed = try shape(policy, members: members)
        try witnessShape(parsed.witness, devices: devices)
        for key in freshnessKeys {
            let n = parsed.freshness[key] ?? -1
            guard n >= registry.number(key + ".min"), n <= registry.number(key + ".max") else { throw Refusal("policy_out_of_bounds") }
        }
        if parsed.relays.count < registry.number("relays.min") || parsed.relays.count > registry.number("relays.max") {
            throw Refusal("policy_out_of_bounds")
        }
        for n in parsed.persons where n < registry.number("persons.min") || n > registry.number("persons.max") {
            throw Refusal("policy_out_of_bounds")
        }
        if parsed.witness["mode"] == .string("relay"), let age = decimal(parsed.witness["max_tip_age_s"]),
           age < registry.number("max_tip_age_s.min") || age > registry.number("max_tip_age_s.max") {
            throw Refusal("policy_out_of_bounds")
        }
        for (index, roles) in parsed.ruleRoles.enumerated() {
            let holders = members.filter { member in
                if case .object(let m) = member, case .string(let role)? = m["role"] { return roles.contains(role) }
                return false
            }.count
            if parsed.persons[index] >= holders { throw Refusal("policy_unreachable") }
        }
        let known = parsed.classes.map { ($0, registry.lookupClass($0.name, fixture: fixture)) }
        if known.contains(where: { $0.1 == nil }) { throw Refusal("class_unknown") }
        if known.contains(where: { $0.1?.status == "pending-spike" }) { throw Refusal("class_pending") }
        if known.contains(where: { $0.1?.status == "test-only" }) { throw Refusal("class_test_only") }
        if known.contains(where: { $0.0.uv != $0.1?.userVerification }) { throw Refusal("class_policy_mismatch") }
    }
}
