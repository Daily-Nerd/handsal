import HandsalCore

/// The aids of SG-12 steps 6 and 7, as lines: what the person should know about the previous epoch before they
/// pin a change. They are aids against the cases of section 14 (L4, L5), never boundaries.
///
/// The facts are the checker's. `genesis-aids` folds the lineage as `genesis-check` does and answers where H
/// lies in the previous epoch and which kids a valid `device.remove` removed there, from its input alone (no pin,
/// no store, no clock), so this file reads no act, keeps no parent map and runs no fold: it checks the shape of
/// the answer and writes the lines.
///
/// Step 6, for H the `head` of the candidate document:
///   the accepted chain ends at tip T:  `H is the tip`  or  `H is not the tip (tip <full T>)`
///   it ends at a fork at P:            `Previous epoch forked at <full P>;` then `H is P`,
///                                      `H is below candidate <full c>` or `H is not below P`
/// A candidate counts as below itself: H equal to a candidate is the top of that branch.
/// Step 7: one `Key removed in the previous epoch: <full kid>` per kid in the answer's `removed`.
/// Failure mode: an answer that is a refusal stops the ceremony with its code, and an answer of another shape is
/// `internal`: an aid that cannot be shown is not skipped.
struct Aids {
    let lines: [String]

    /// The aids of the change that is the last entry of `input`'s lineage.
    static func gather(input: CeremonyInput, checker: any LineageQueries) throws -> Aids {
        try read(checker.genesisAids(input.lineageInput()))
    }

    static func read(_ answer: JValue) throws -> Aids {
        if let error = answer["error"]?.str { throw Stop.refused(error) }
        guard case .object(let members) = answer, Set(members.keys) == ["aids", "reason"], let reason = members["reason"]?.str else {
            throw Stop.refused("internal")
        }
        guard reason == "ok" else {
            guard members["aids"] == .null else { throw Stop.refused("internal") }
            throw Stop.refused(reason)
        }
        guard case .object(let aids)? = members["aids"], Set(aids.keys) == ["head", "removed"], let head = aids["head"],
              case .array(let removed)? = aids["removed"] else { throw Stop.refused("internal") }
        let kids = try removed.map { item -> String in
            guard let kid = item.str, Forms.isB64u32(kid) else { throw Stop.refused("internal") }
            return kid
        }
        guard kids == kids.sorted(by: { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }), Set(kids).count == kids.count else {
            throw Stop.refused("internal")
        }
        return Aids(lines: [try headLine(head)] + kids.map { "Key removed in the previous epoch: \($0)" })
    }

    private static func headLine(_ head: JValue) throws -> String {
        guard case .object(let members) = head, let at = members["at"]?.str, let place = members["place"]?.str else { throw Stop.refused("internal") }
        switch at {
        case "tip":
            guard Set(members.keys) == ["at", "place", "tip"], let tip = members["tip"]?.str, Forms.isHashstr(tip) else { throw Stop.refused("internal") }
            switch place {
            case "tip": return "H is the tip"
            case "not_tip": return "H is not the tip (tip \(tip))"
            default: throw Stop.refused("internal")
            }
        case "fork":
            guard Set(members.keys) == ["at", "candidate", "candidates", "parent", "place"], let parent = members["parent"]?.str, Forms.isHashstr(parent),
                  case .array(let list)? = members["candidates"], !list.isEmpty else { throw Stop.refused("internal") }
            let candidates = list.compactMap(\.str)
            guard candidates.count == list.count, candidates.allSatisfy(Forms.isHashstr) else { throw Stop.refused("internal") }
            let prefix = "Previous epoch forked at \(parent); "
            switch (place, members["candidate"]) {
            case ("parent", .null?): return prefix + "H is P"
            case ("not_below", .null?): return prefix + "H is not below P"
            case ("below", .string(let candidate)?) where candidates.contains(candidate): return prefix + "H is below candidate \(candidate)"
            default: throw Stop.refused("internal")
            }
        default:
            throw Stop.refused("internal")
        }
    }
}
