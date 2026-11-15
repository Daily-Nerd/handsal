/// Genesis rendering (RN-04, RN-08, RN-10) and the size bound of GP-15 step 5.
///
/// An original renders in full: every member, every device (full kid, class on its own line,
/// label, agree thumbprint) and the whole policy, the witness included. A change renders as a
/// difference from the document it replaces: `Org name` and `Profile`, `Previous`, the full `Head`,
/// the members and devices added or removed, the roles changed, the full policy, and what stayed.
/// Carried devices are byte-identical (GP-20), so there is no "devices changed" section; a section
/// with no entry is not written.
/// It reads a document that passed `Genesis.checkAlone`; a shape that is not there is
/// `genesis_schema`, never a default.
enum RenderGenesis {
    struct Device {
        let kid: String, person: String, cls: String, label: String, agree: String
    }

    struct Doc {
        let value: JValue
        let name: String, profile: String
        let prev: String?, head: String?
        let members: [(id: String, role: String)]
        let devices: [Device]
        let policy: [String: JValue]
    }

    private static func bad() -> Refusal { Refusal("genesis_schema") }

    static func read(_ value: JValue) throws -> Doc {
        guard let d = value.dict, let name = d["name"]?.str, let profile = d["profile"]?.str,
              let memberList = d["members"]?.list, let deviceList = d["devices"]?.list,
              let policy = d["policy"]?.dict else { throw bad() }
        let members = try memberList.map { m -> (id: String, role: String) in
            guard let id = m["id"]?.str, let role = m["role"]?.str else { throw bad() }
            return (id, role)
        }
        let devices = try deviceList.map { v -> Device in
            guard let kid = v["kid"]?.str, let person = v["person"]?.str, let cls = v["class"]?.str,
                  let label = v["label"]?.str, let x = v["agree"]?["x"]?.str, let y = v["agree"]?["y"]?.str else { throw bad() }
            return Device(kid: kid, person: person, cls: cls, label: label, agree: Encoding.thumbprint(x: x, y: y))
        }
        return Doc(value: value, name: name, profile: profile, prev: d["prev"]?.str, head: d["head"]?.str,
                   members: members, devices: devices, policy: policy)
    }

    private static func deviceLines(_ d: Device) -> [String] {
        ["  - \(d.kid) of \(d.person)", "    Class: " + d.cls, "    Label: " + d.label, "    Agree: " + d.agree]
    }

    private static func policyLines(_ policy: [String: JValue]) throws -> [String] {
        guard let roles = policy["roles"]?.list?.compactMap(\.str), let rules = policy["rules"]?.dict,
              let classes = policy["classes"]?.list, let fresh = policy["freshness"]?.dict,
              let relays = policy["relays"]?.list?.compactMap(\.str), let witness = policy["witness"]?.dict else { throw bad() }
        var out = ["Policy:", "  Roles: " + roles.joined(separator: ",")]
        for name in rules.keys.sorted(by: { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }) {
            guard let persons = rules[name]?["persons"]?.str, let rr = rules[name]?["roles"]?.list?.compactMap(\.str) else { throw bad() }
            out.append("  Rule \(name): \(persons) of \(rr.joined(separator: ","))")
        }
        for entry in classes {
            guard let cls = entry["class"]?.str, let uv = entry["user_verification"]?.str else { throw bad() }
            out.append("  Class \(cls): \(uv)")
        }
        guard let skew = fresh["clock_skew_s"]?.str, let validity = fresh["max_validity_s"]?.str,
              let view = fresh["max_view_age_s"]?.str else { throw bad() }
        out += ["  Clock skew: \(skew) s", "  Max validity: \(validity) s", "  Max view age: \(view) s",
                "  Relays: " + (relays.isEmpty ? "none" : relays.joined(separator: ","))]
        if witness["mode"]?.str == "none" {
            out.append("  Witness: none")
        } else {
            guard let kid = witness["relay_kid"]?.str, let age = witness["max_tip_age_s"]?.str else { throw bad() }
            out += ["  Witness: relay", "  Relay key: " + kid, "  Max tip age: \(age) s"]
        }
        return out
    }

    private struct Difference {
        var added: [(id: String, role: String)] = []
        var removed: [(id: String, role: String)] = []
        var changed: [(id: String, old: String, new: String)] = []
        var devicesAdded: [Device] = []
        var devicesRemoved: [Device] = []
        var carried = 0
    }

    private static func difference(_ doc: Doc, _ previous: Doc) -> Difference {
        var out = Difference()
        let before = Dictionary(uniqueKeysWithValues: previous.members.map { ($0.id, $0.role) })
        let after = Dictionary(uniqueKeysWithValues: doc.members.map { ($0.id, $0.role) })
        out.added = doc.members.filter { before[$0.id] == nil }
        out.removed = previous.members.filter { after[$0.id] == nil }
        out.changed = doc.members.compactMap { m in before[m.id].flatMap { $0 != m.role ? (m.id, $0, m.role) : nil } }
        let old = Set(previous.devices.map(\.kid)), new = Set(doc.devices.map(\.kid))
        out.devicesAdded = doc.devices.filter { !old.contains($0.kid) }
        out.devicesRemoved = previous.devices.filter { !new.contains($0.kid) }
        out.carried = doc.devices.filter { old.contains($0.kid) }.count
        return out
    }

    /// Line 1 of the `genesis.sign` over `doc` (RN-03): an original, or a change against `previous`.
    static func summary(_ doc: Doc, _ previous: Doc?) throws -> String {
        let name = Render.cut12(doc.name), digest = Render.hash12(try Genesis.docHash(doc.value))
        guard let previous else {
            return "Sign genesis of \(name) (\(digest)): \(doc.members.count) members, \(doc.devices.count) devices"
        }
        let diff = difference(doc, previous)
        let policyNew = (try? Emit.subset(.object(doc.policy))) != (try? Emit.subset(.object(previous.policy)))
        return "Change \(name) (\(digest)): +\(diff.devicesAdded.count)/-\(diff.devicesRemoved.count) dev, "
            + "\(diff.added.count + diff.removed.count + diff.changed.count) mem, policy \(policyNew ? "NEW" : "same")"
    }

    private static func section(_ title: String, _ entries: [String]) -> [String] {
        entries.isEmpty ? [] : [title] + entries
    }

    /// The method lines of the `genesis.sign` over `doc` (RN-04, RN-10).
    static func lines(_ doc: Doc, _ previous: Doc?) throws -> [String] {
        guard let previous, let prev = doc.prev, let head = doc.head else {
            var out = ["Org name: " + doc.name, "Profile: " + doc.profile, "Members:"]
            out += doc.members.map { "  - \($0.id) \($0.role)" }
            out.append("Devices:")
            out += doc.devices.flatMap(deviceLines)
            return out + (try policyLines(doc.policy)) + ["Document hash: " + Render.hash12(try Genesis.docHash(doc.value))]
        }
        let diff = difference(doc, previous)
        var out = ["Org name: " + doc.name, "Profile: " + doc.profile, "Previous: " + Render.hash12(prev), "Head: " + head]
        out += section("Members added:", diff.added.map { "  - \($0.id) \($0.role)" })
        out += section("Members removed:", diff.removed.map { "  - \($0.id) \($0.role)" })
        out += section("Role changed:", diff.changed.map { "  - \($0.id) \($0.old) -> \($0.new)" })
        out += section("Devices added:", diff.devicesAdded.flatMap(deviceLines))
        out += section("Devices removed:", diff.devicesRemoved.map { "  - \($0.kid) of \($0.person)" })
        out += try policyLines(doc.policy)
        let unchanged = doc.members.count - diff.added.count - diff.changed.count
        return out + ["Unchanged: \(diff.carried) devices, \(unchanged) members"]
    }
}
