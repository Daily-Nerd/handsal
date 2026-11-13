import HandsalCore

/// What the person collected (SG-12 step 1): one line, one JSON object
/// `{acts, device_kid, lineage, synced_at, tip_statement}`, then one LF. `lineage` is the
/// `genesis-check` lineage, the last entry the candidate document with the `genesis.sign` receipts
/// of every listed device; `acts` is the bag of every epoch; `device_kid`, `synced_at` and
/// `tip_statement` are what `enrolled` needs beyond them (GP-13).
///
/// The grammar is the canonical subset recognizer with MAX_INPUT, like the helper's input: a
/// recognizer failure is `unparseable_input`, a missing, extra or mistyped key is `malformed_input`.
/// The ceremony takes no argument. `org` is not an input: it is the hash of the first document
/// (GP-04), so there is one source for it.
struct CeremonyInput {
    struct Entry {
        let doc: JValue
        let sigs: [String]
        var value: JValue { .object(["doc": doc, "sigs": .array(sigs.map { .string($0) })]) }
    }

    let acts: [String]
    let lineage: [Entry]
    let deviceKid: String
    let syncedAt: String
    let tipStatement: JValue
    /// The org id: the hash of the first document (GP-04). Read validates that every document hashes,
    /// so it is computed once there and is never a default.
    let org: String

    static func read(arguments: [String], stdin: [UInt8]) throws -> CeremonyInput {
        guard arguments.isEmpty else { throw Stop.input("malformed_input") }
        guard stdin.count <= Limits.maxInput, stdin.last == 0x0A,
              case .success(let value) = Subset.parse(Array(stdin.dropLast()), maxSize: Limits.maxInput) else { throw Stop.input("unparseable_input") }
        guard case .object(let members) = value, Set(members.keys) == ["acts", "device_kid", "lineage", "synced_at", "tip_statement"],
              case .array(let acts)? = members["acts"], case .array(let entries)? = members["lineage"], !entries.isEmpty,
              case .string(let kid)? = members["device_kid"], Forms.isB64u32(kid),
              case .string(let syncedAt)? = members["synced_at"], Forms.isTime(syncedAt),
              let tip = members["tip_statement"], tip == .null || tip.str != nil else { throw Stop.input("malformed_input") }
        var org: String?
        let lineage = try entries.map { entry -> Entry in
            guard case .object(let parts) = entry, Set(parts.keys) == ["doc", "sigs"], case .object? = parts["doc"],
                  case .array(let sigs)? = parts["sigs"], sigs.allSatisfy({ $0.str != nil }),
                  let doc = parts["doc"], let hash = try? Genesis.docHash(doc) else { throw Stop.input("malformed_input") }
            org = org ?? hash
            return Entry(doc: doc, sigs: sigs.compactMap(\.str))
        }
        guard acts.allSatisfy({ $0.str != nil }), let org else { throw Stop.input("malformed_input") }
        return CeremonyInput(acts: acts.compactMap(\.str), lineage: lineage, deviceKid: kid, syncedAt: syncedAt,
                             tipStatement: tip, org: org)
    }

    /// The `genesis-check` and pin helper input `{acts, lineage}`.
    func lineageInput() throws -> [UInt8] {
        try Emit.subset(.object(["acts": .array(acts.map { .string($0) }), "lineage": .array(lineage.map(\.value))]), maxSize: Limits.maxInput)
    }

    /// The `enrolled` input (GP-13) of the production build: no `pin`, no `now`.
    func enrolledInput() throws -> [UInt8] {
        try Emit.subset(.object(["acts": .array(acts.map { .string($0) }), "device_kid": .string(deviceKid),
                                 "lineage": .array(lineage.map(\.value)), "org": .string(org), "synced_at": .string(syncedAt),
                                 "tip_statement": tipStatement]), maxSize: Limits.maxInput)
    }
}
