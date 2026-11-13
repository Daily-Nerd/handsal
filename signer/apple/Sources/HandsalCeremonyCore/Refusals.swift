import HandsalCore

/// What the ceremony refuses before it runs anything (SG-12 step 2), and the policy checks of
/// step 4. Each is a refusal with the reason code the fold gives the same fact.
///
/// Step 2: a document whose `profile` is a fixture profile (`fixture_profile`), a profile this
/// build does not implement (`profile_mismatch`), and any kid listed in `fixture-kids.json`, a
/// device's or the relay's (`fixture_key`). It reads every document of the lineage, so a fixture
/// document cannot hide behind a production last link. A document that is not even shaped like one
/// is left to `genesis-check`, which owns the structure rules.
/// Step 4 is `Genesis.checkAlone` on the candidate under the production profile: a policy without a
/// spare person (`policy_unreachable`), a role holder's device whose class is not biometric-only
/// (`role_key_class`, KC-08), and the rest of GP-15 steps 1 and 3, by an implementation of its own
/// beside the checker's.
enum Refusals {
    static func beforeAnything(_ lineage: [CeremonyInput.Entry], profiles: Profiles = .standard) throws {
        for entry in lineage {
            switch entry.doc["profile"]?.str.flatMap(profiles.kind) {
            case "fixture"?: throw Stop.refused("fixture_profile")
            case nil where entry.doc["profile"]?.str != nil: throw Stop.refused("profile_mismatch")
            default: break
            }
            var kids = (entry.doc["devices"]?.list ?? []).compactMap { $0["kid"]?.str }
            if let relay = entry.doc["policy"]?["witness"]?["relay_kid"]?.str { kids.append(relay) }
            if kids.contains(where: profiles.isFixtureKid) { throw Stop.refused("fixture_key") }
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
