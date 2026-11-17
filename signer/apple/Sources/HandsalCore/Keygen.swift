/// `keygen` and `pubkey` (SG-03).
///
/// `keygen` creates the signing key and a separate agreement key through the backend, binds
/// `person` as the performer for every later signature, and returns `{agree, class, kid, sign}`.
/// `pubkey` returns the same object and shows nothing: it is a pure read of the public key and needs no
/// display channel. Only `keygen` writes `Key <kid12> for <person>, class <class>` to the display channel, never
/// to stdout, as an aid for linking devices (SG-09).
///
/// Invariants: the pair is checked by the profile's own key rule (`DeviceKey.defect`: on the curve,
/// `kid` is the thumbprint, `agree` differs from `sign`) before the backend stores anything, so a
/// refused pair leaves no key; an existing key is never overwritten (`key_exists`).
/// Failure modes: `keygen` has `schema_refused` (input), `no_display` (before any key exists), `key_exists` and
/// `internal` (a pair the profile refuses); `pubkey` has only `key_unavailable` (no usable key).
extension SignerCommands {
    private static func keyLine(_ key: KeyMaterial) -> String {
        "Key \(Render.kid12(key.kid)) for \(key.person), class \(key.keyClass)\n"
    }

    public static func keygen(_ input: JValue, environment: Environment) throws -> JValue {
        guard case .object(let members) = input, Set(members.keys) == ["label", "person"],
              case .string(let label)? = members["label"], Forms.isLabel(label),
              case .string(let person)? = members["person"], Forms.isMemberId(person) else { throw Refusal("schema_refused") }
        let display = try environment.display()
        let key = try environment.backend.create(label: label, person: person) { made in
            guard DeviceKey.defect(kid: made.kid, sign: made.sign.value, agree: made.agree.value) == nil else { throw Refusal("internal") }
        }
        try display.show(keyLine(key))
        return key.result
    }

    public static func pubkey(environment: Environment) throws -> JValue {
        try boundKey(environment).result
    }
}
