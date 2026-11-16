import HandsalCore

/// What the ceremony refuses before it runs anything (SG-12 step 2), and the policy checks of
/// step 4. Each is a refusal with the reason code the fold gives the same fact.
///
/// Step 2: a document whose `profile` is a fixture profile (`fixture_profile`), a profile of no
/// edition of the supported set (`profile_mismatch`), and any kid listed in the `fixture-kids.json`
/// of the edition that document names, a device's or the relay's (`fixture_key`). It reads every
/// document of the lineage, so a fixture document cannot hide behind a production last link, and it
/// accepts documents of different supported editions: the age of an edition is not its question
/// (`profile_downgrade` comes from `genesis-check`, step 3). A document that is not even shaped like
/// one is left to `genesis-check`, which owns the structure rules.
/// Step 4 is `Genesis.checkAlone` on the candidate under the edition it names: a policy without a
/// spare person (`policy_unreachable`), a role holder's device whose class is not biometric-only
/// (`role_key_class`, KC-08), and the rest of GP-15 steps 1 and 3, by an implementation of its own
/// beside the checker's.
enum Refusals {
    static func beforeAnything(_ lineage: [CeremonyInput.Entry], profiles: Profiles = .standard) throws {
        for entry in lineage {
            let match = entry.doc["profile"]?.str.flatMap(profiles.resolve)
            if match?.kind == .fixture { throw Stop.refused("fixture_profile") }
            if match == nil, entry.doc["profile"]?.str != nil { throw Stop.refused("profile_mismatch") }
            var kids = (entry.doc["devices"]?.list ?? []).compactMap { $0["kid"]?.str }
            if let relay = entry.doc["policy"]?["witness"]?["relay_kid"]?.str { kids.append(relay) }
            let own = match?.edition ?? profiles.current
            if kids.contains(where: own.fixtureKids.contains) { throw Stop.refused("fixture_key") }
        }
    }

    static func policy(of candidate: JValue, context: GenesisContext = GenesisContext()) throws {
        do {
            try Genesis.checkAlone(candidate, context)
        } catch let refusal as Refusal {
            throw Stop.refused(refusal.code)
        }
    }
}
