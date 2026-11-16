/// Genesis document validation (GP-01, GP-15 steps 1 and 3, GP-18, KC-05, KC-08), for a renderer
/// that holds a document and no lineage (RN-09).
///
/// `checkAlone` checks one document by itself in the order GP-15 fixes and refuses with the
/// reason code of the first failing check:
///   step 1, structure   `genesis_schema`, `doc_not_sorted`, `genesis_key_invalid`, `duplicate_key`;
///                       each pass covers the whole document before the next begins
///   step 3, policy      `Policy.validate` (its codes), then a listed device of a class the policy
///                       does not accept (`genesis_schema`), `role_key_class`, `fixture_key`
/// Step 2 (profile) and the lineage steps belong to the fold, so an unimplemented profile is no
/// defect here. Step 3 runs under the edition the document names (its registry tables and its fixture
/// kids) and under the kind it names: strict (fixture keys refused) unless it names a fixture profile
/// or none this build implements. A hash no edition owns is read under the current edition, so a class
/// later retired still renders on a `previous` document of the edition that had it (RN-09).
public struct GenesisContext: Sendable {
    public var profiles: Profiles
    public init(profiles: Profiles = .standard) { self.profiles = profiles }
}

public enum Genesis {
    static let version = "handsal-genesis/1"
    private static let baseKeys: Set<String> = ["devices", "members", "name", "org", "prev", "profile", "v"]
    private static let deviceKeys: Set<String> = ["agree", "class", "kid", "label", "person", "sign"]

    private static func schema() -> Refusal { Refusal("genesis_schema") }

    /// hashstr(JCS(doc)): the document hash, the org id of an original, and a change's `prev`.
    public static func docHash(_ doc: JValue) throws -> String {
        Encoding.hashstr(try Emit.subset(doc))
    }

    static func string(_ value: JValue?) -> String? {
        if case .string(let s)? = value { return s }
        return nil
    }

    static func isHashstr(_ value: JValue?) -> Bool {
        string(value).map(Forms.isHashstr) ?? false
    }

    private static func isPointShape(_ value: JValue?) -> Bool {
        guard case .object(let m)? = value, Set(m.keys) == ["x", "y"], string(m["x"]) != nil, string(m["y"]) != nil else { return false }
        return true
    }

    private static func checkShape(_ value: JValue) throws -> [String: JValue] {
        guard case .object(let doc) = value, (try? Emit.subset(value)) != nil else { throw schema() }
        guard Set(doc.keys).subtracting(["policy", "head"]) == baseKeys, doc["v"] == .string(version),
              let name = string(doc["name"]), Forms.isOrgName(name),
              let profile = string(doc["profile"]), Forms.isHashstr(profile) else { throw schema() }
        if doc["prev"] == .null {
            guard doc["org"] == .null, doc["head"] == nil else { throw schema() }
        } else {
            guard isHashstr(doc["prev"]), isHashstr(doc["org"]), isHashstr(doc["head"]) else { throw schema() }
        }
        guard case .array(let members)? = doc["members"], !members.isEmpty,
              case .array(let devices)? = doc["devices"], !devices.isEmpty else { throw schema() }
        var ids: [String] = []
        for member in members {
            guard case .object(let m) = member, Set(m.keys) == ["id", "role"],
                  let id = string(m["id"]), Forms.isMemberId(id), let role = string(m["role"]), Forms.isRoleId(role) else { throw schema() }
            ids.append(id)
        }
        guard Set(ids).count == ids.count else { throw schema() }
        var persons = Set<String>()
        for device in devices {
            guard case .object(let d) = device, Set(d.keys) == deviceKeys, string(d["class"]) != nil, string(d["kid"]) != nil,
                  let label = string(d["label"]), Forms.isLabel(label), let person = string(d["person"]), ids.contains(person),
                  isPointShape(d["sign"]), isPointShape(d["agree"]) else { throw schema() }
            persons.insert(person)
        }
        guard persons == Set(ids) else { throw schema() }
        return doc
    }

    private static func ascending(_ values: [String]) -> Bool {
        let bytes = values.map { Array($0.utf8) }
        return !zip(bytes, bytes.dropFirst()).contains { $1.lexicographicallyPrecedes($0) }
    }

    private static func strings(_ value: JValue?) -> [String]? {
        guard case .array(let items)? = value else { return nil }
        var out: [String] = []
        for item in items { guard case .string(let s) = item else { return nil }; out.append(s) }
        return out
    }

    /// Every list of the policy that one byte form depends on, when it is well formed enough to be
    /// ordered. A malformed policy is `policy_invalid` later, never `doc_not_sorted`.
    private static func policyLists(_ policy: JValue?) -> [[String]] {
        guard case .object(let p)? = policy else { return [] }
        var out: [[String]] = []
        if case .array(let classes)? = p["classes"] {
            let names = classes.compactMap { item -> String? in
                if case .object(let c) = item { return string(c["class"]) } else { return nil }
            }
            if names.count == classes.count { out.append(names) }
        }
        if let relays = strings(p["relays"]) { out.append(relays) }
        if let roles = strings(p["roles"]) { out.append(roles) }
        if case .object(let rules)? = p["rules"] {
            for rule in rules.values {
                if case .object(let r) = rule, let roles = strings(r["roles"]) { out.append(roles) }
            }
        }
        return out
    }

    private static func checkSorted(_ doc: [String: JValue]) throws {
        guard case .array(let members)? = doc["members"], case .array(let devices)? = doc["devices"] else { throw schema() }
        var lists: [[String]] = [
            members.compactMap { if case .object(let m) = $0 { return string(m["id"]) } else { return nil } },
            devices.compactMap { if case .object(let d) = $0 { return string(d["kid"]) } else { return nil } },
        ]
        lists.append(contentsOf: policyLists(doc["policy"]))
        if !lists.allSatisfy(ascending) { throw Refusal("doc_not_sorted") }
    }

    private static func checkKeys(_ doc: [String: JValue]) throws {
        guard case .array(let devices)? = doc["devices"] else { throw schema() }
        var kids: [String] = []
        var agrees: [JValue] = []
        for device in devices {
            guard case .object(let d) = device, let kid = string(d["kid"]), let sign = d["sign"], let agree = d["agree"] else { throw schema() }
            if DeviceKey.defect(kid: kid, sign: sign, agree: agree) != nil { throw Refusal("genesis_key_invalid") }
            kids.append(kid)
            agrees.append(agree)
        }
        let uniqueAgrees = agrees.reduce(into: [JValue]()) { if !$0.contains($1) { $0.append($1) } }
        if Set(kids).count != kids.count || uniqueAgrees.count != agrees.count { throw Refusal("duplicate_key") }
    }

    private static func checkDevicesAgainstPolicy(_ doc: [String: JValue], _ edition: Edition, fixture: Bool) throws {
        guard case .object(let policy)? = doc["policy"], case .array(let classes)? = policy["classes"],
              case .object(let rules)? = policy["rules"],
              case .array(let members)? = doc["members"], case .array(let devices)? = doc["devices"] else { throw schema() }
        let accepted = Set(classes.compactMap { item -> String? in if case .object(let c) = item { return string(c["class"]) } else { return nil } })
        var holderRoles = Set<String>()
        for rule in rules.values { if case .object(let r) = rule, let roles = strings(r["roles"]) { holderRoles.formUnion(roles) } }
        var holders = Set<String>()
        for member in members {
            if case .object(let m) = member, let id = string(m["id"]), let role = string(m["role"]), holderRoles.contains(role) { holders.insert(id) }
        }
        for device in devices {
            guard case .object(let d) = device, let cls = string(d["class"]), let person = string(d["person"]) else { throw schema() }
            if !accepted.contains(cls) { throw schema() }
            if holders.contains(person), edition.registry.lookupClass(cls, fixture: fixture)?.userVerification != "biometric_only" {
                throw Refusal("role_key_class")
            }
        }
    }

    private static func checkFixtureKeys(_ doc: [String: JValue], _ edition: Edition) throws {
        guard case .array(let devices)? = doc["devices"], case .object(let policy)? = doc["policy"],
              case .object(let witness)? = policy["witness"] else { throw schema() }
        var kids = devices.compactMap { item -> String? in if case .object(let d) = item { return string(d["kid"]) } else { return nil } }
        if witness["mode"] == .string("relay"), let relay = string(witness["relay_kid"]) { kids.append(relay) }
        if kids.contains(where: edition.fixtureKids.contains) { throw Refusal("fixture_key") }
    }

    public static func checkAlone(_ value: JValue, _ ctx: GenesisContext = GenesisContext()) throws {
        let doc = try checkShape(value)
        try checkSorted(doc)
        try checkKeys(doc)
        let match = string(doc["profile"]).flatMap(ctx.profiles.resolve)
        let edition = match?.edition ?? ctx.profiles.current
        let fixture = match?.kind != .production
        guard case .array(let members)? = doc["members"], case .array(let devices)? = doc["devices"] else { throw schema() }
        try Policy.validate(doc["policy"], members: members, devices: devices, registry: edition.registry, fixture: fixture)
        try checkDevicesAgainstPolicy(doc, edition, fixture: fixture)
        if !fixture { try checkFixtureKeys(doc, edition) }
    }
}
