@testable import HandsalCore

/// Genesis documents for the signer tests: the conformance original with its profile set, a change of
/// a document, and the `genesis.sign` input over them. The documents carry the fixture keys of the
/// vectors, which the synthetic editions of `Editions` do not list, so they are valid alone under them.
enum GenesisDocs {
    static let head = hsh("the head of the previous epoch")

    static func original(profile: String, retired: Bool = false) throws -> JValue {
        let row = try Vector.load(commands: ["render"]).first { $0.name == "rnd/genesis-sign-original" }
        guard case .json(.object(let input))? = row?.input, case .object(let attachments)? = input["attachments"],
              case .object(var doc)? = attachments["document"] else { throw Refusal("vector missing") }
        doc["profile"] = .string(profile)
        if retired {
            // a class the older edition accepts and the current one retired
            if case .object(var policy)? = doc["policy"] {
                policy["classes"] = .array([.object(["class": .string("retired-hw"), "user_verification": .string("biometric_only")])])
                doc["policy"] = .object(policy)
            }
            if case .array(let devices)? = doc["devices"] {
                doc["devices"] = .array(devices.map { device in
                    guard case .object(var d) = device else { return device }
                    d["class"] = .string("retired-hw")
                    return .object(d)
                })
            }
        }
        return .object(doc)
    }

    /// A change of `previous` (an original) that names `profile`: `prev`, `org` and `head` are what GP-15 gives a change.
    static func change(of previous: JValue, profile: String) throws -> JValue {
        guard case .object(var doc) = try original(profile: profile) else { throw Refusal("vector missing") }
        let id = try Genesis.docHash(previous)
        doc["prev"] = .string(id)
        doc["org"] = .string(id)
        doc["head"] = .string(head)
        return .object(doc)
    }

    /// The `{attachments, draft}` of a `genesis.sign` over `document`, with `previous` attached for a change.
    static func input(_ document: JValue, previous: JValue? = nil) throws -> JValue {
        let org: String
        if case .string(let given)? = document["org"] { org = given } else { org = try Genesis.docHash(document) }
        var draft: [String: JValue] = ["body": .object([:]), "method": .string(Methods.genesisSign), "org": .string(org)]
        var attachments: [String: JValue] = ["document": document]
        if let previous {
            draft["head"] = .object(["id": .string(head), "kind": .string("chain")])
            attachments["previous"] = previous
        }
        return signInput(.object(draft), .object(attachments))
    }
}
