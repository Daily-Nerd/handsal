import HandsalCore

/// The aids of SG-12 steps 6 and 7: what the person should know about the previous epoch before
/// they pin a change. They are aids against the cases of section 14 (L4, L5), never boundaries, so
/// they read structure (receipt ids and parents) and the checker's own `fold`, and decide nothing.
///
/// Step 6, for H the `head` of the candidate document, from the previous epoch's accepted chain:
///   the chain ends at tip T:   `H is the tip`  or  `H is not the tip (tip <full T>)`
///   it ends at a fork at P:    `Previous epoch forked at <full P>;` then `H is P`,
///                              `H is below candidate <full c>` or `H is not below P`
/// A candidate counts as below itself: H equal to a candidate is the top of that branch (the spec
/// is silent on the case; this is the reading that never leaves H unplaced).
/// Step 7: one `Key removed in the previous epoch: <full kid>` per kid the candidate carries, or
/// whose key signed it, that a valid `device.remove` removes anywhere in the previous epoch. The
/// validity is the checker's: a kid whose device the fold of a branch shows `removed`. For a forked
/// epoch every branch is folded alone (its own acts and the acts above the fork), so a removal on
/// either side shows, and none is lost to the fork error.
/// Failure mode: a previous epoch the checker cannot fold stops the ceremony with its code: an aid
/// that cannot be shown is not skipped.
struct Aids {
    let lines: [String]

    private static let counted: Set<String> = Methods.chainActs.union([Methods.endorse])

    static func gather(input: CeremonyInput, candidate: JValue, checker: any CeremonyChecker) throws -> Aids {
        let previous = Array(input.lineage.dropLast())
        guard let head = candidate["head"]?.str else { throw Stop.refused("genesis_schema") }
        let org = input.org

        func fold(acts: [String]) throws -> JValue {
            let bytes = try Emit.subset(.object(["acts": .array(acts.map { .string($0) }), "lineage": .array(previous.map(\.value)), "org": .string(org)]),
                                        maxSize: Limits.maxInput)
            return try checker.run("fold", input: bytes)
        }

        // id -> parent, from the acts of the bag that parse as chain acts or endorsements
        var parents: [String: String] = [:]
        var parsed: [String: String?] = [:]
        for act in input.acts {
            // an aid for the person, after `genesis-check` judged the bag: an act that does not parse is left out of the picture
            if let read = try? Acts.parse(act, registry: .standard, wanted: counted) {
                parents[read.id] = read.parent
                parsed[act] = read.id
            }
        }

        var lines: [String] = []
        var removed = Set<String>()
        let whole = try fold(acts: input.acts)
        if let error = whole["error"]?.str {
            guard error == "fork", let candidates = whole["fork"]?["candidates"]?.list?.compactMap(\.str), !candidates.isEmpty,
                  let fork = whole["fork"]?["parent"]?.str else { throw Stop.refused(error == "fork" ? "internal" : error) }
            lines.append("Previous epoch forked at \(fork); " + forkSentence(head: head, fork: fork, candidates: candidates, parents: parents))
            for branch in candidates {
                let bag = input.acts.filter { act in
                    guard let id = parsed[act] ?? nil else { return true }   // not an act of the chain: every branch keeps it
                    return owner(of: id, candidates: candidates, parents: parents).map { $0 == branch } ?? true
                }
                removed.formUnion(try removedKids(fold(acts: bag)))
            }
        } else {
            guard let tip = whole["tip"]?["id"]?.str else { throw Stop.refused("internal") }
            lines.append(head == tip ? "H is the tip" : "H is not the tip (tip \(tip))")
            removed = try removedKids(whole)
        }

        let carried = Set((candidate["devices"]?.list ?? []).compactMap { $0["kid"]?.str })
        let signers = Set((input.lineage.last?.sigs ?? []).compactMap(signerKid))
        for kid in removed.intersection(carried.union(signers)).sorted() { lines.append("Key removed in the previous epoch: \(kid)") }
        return Aids(lines: lines)
    }

    private static func forkSentence(head: String, fork: String, candidates: [String], parents: [String: String]) -> String {
        if head == fork { return "H is P" }
        if let candidate = candidates.sorted().first(where: { below(head, candidate: $0, parents: parents) }) {
            return "H is below candidate \(candidate)"
        }
        return "H is not below P"
    }

    /// Whether `id` is `candidate` or lies under it, following parents.
    private static func below(_ id: String, candidate: String, parents: [String: String]) -> Bool {
        owner(of: id, candidates: [candidate], parents: parents) != nil
    }

    /// The first candidate on the way from `id` up through its parents, or nil. A visited set keeps a
    /// cycle in hostile input from looping.
    private static func owner(of id: String, candidates: [String], parents: [String: String]) -> String? {
        var current: String? = id
        var seen = Set<String>()
        while let at = current, seen.insert(at).inserted {
            if candidates.contains(at) { return at }
            current = parents[at]
        }
        return nil
    }

    /// The kids a fold's `devices` shows `removed`.
    private static func removedKids(_ answer: JValue) throws -> Set<String> {
        if let error = answer["error"]?.str { throw Stop.refused(error) }
        guard let devices = answer["devices"]?.dict else { throw Stop.refused("internal") }
        var out = Set<String>()
        for person in devices.values {
            for (kid, device) in person.dict ?? [:] where device["status"]?.str == "removed" { out.insert(kid) }
        }
        return out
    }

    /// The header kid of a `genesis.sign` receipt; a string that is not a receipt has none.
    private static func signerKid(_ jws: String) -> String? {
        guard let first = jws.split(separator: ".", omittingEmptySubsequences: false).first,
              let header = Encoding.base64urlDecode(String(first)),
              case .success(let value) = Subset.parse(header, maxSize: 256), let kid = value["kid"]?.str, Forms.isB64u32(kid) else { return nil }
        return kid
    }
}
