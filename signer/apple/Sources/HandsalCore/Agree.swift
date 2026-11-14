/// `agree` (SG-16): `{context, peer}` in, `{key}` out.
///
/// The signer does a key agreement with the device's own agreement key and `peer`, and returns the HKDF output
/// of `Agreement` under the handsal label and the caller's `context`; the raw shared secret never leaves the
/// backend. The command needs no prompt, no display, no sensor check and no prompt guard: the agreement key is
/// created without presence (KC-09). It never reads the signing key.
///
/// Sequence (SG-08 order): the form of the input (`schema_refused`), the bound key of this build's class
/// (`key_unavailable`), the `info`, the backend's agreement. A backend answer that is not 32 bytes is `internal`.
extension SignerCommands {
    public static func agree(_ input: JValue, environment: Environment) throws -> JValue {
        guard case .object(let members) = input, Set(members.keys) == ["context", "peer"],
              case .string(let context)? = members["context"], Forms.isAgreeContext(context),
              let value = members["peer"], DeviceKey.pointOk(value),
              let x = value["x"]?.str, let y = value["y"]?.str else { throw Refusal("schema_refused") }
        let key = try boundKey(environment)
        let peer = Point(x: x, y: y)
        guard let info = Agreement.info(own: key.agree, peer: peer, context: context) else { throw Refusal("internal") }
        let derived = try environment.backend.agree(peer: peer, info: info)
        guard derived.count == Agreement.keyLength else { throw Refusal("internal") }
        return .object(["key": .string(Encoding.base64url(derived))])
    }
}
