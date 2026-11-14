/// A P-256 public point `{x, y}`: 32 big-endian bytes per coordinate, canonical base64url.
public struct Point: Equatable, Sendable {
    public let x: String
    public let y: String
    public init(x: String, y: String) { self.x = x; self.y = y }

    var value: JValue { .object(["x": .string(x), "y": .string(y)]) }
}

/// What a backend holds for the one key of this configuration: the person it signs as (bound at
/// keygen, SG-03), the class, and the two public keys. The `kid` is derived, never stored, so it
/// cannot disagree with the signing key (ACT-11).
public struct KeyMaterial: Equatable, Sendable {
    public let keyClass: String
    public let person: String
    public let sign: Point
    public let agree: Point

    public init(keyClass: String, person: String, sign: Point, agree: Point) {
        self.keyClass = keyClass; self.person = person; self.sign = sign; self.agree = agree
    }

    public var kid: String { Encoding.thumbprint(x: sign.x, y: sign.y) }

    /// The `{agree, class, kid, sign}` result of `keygen` and `pubkey` (SG-03).
    var result: JValue {
        .object(["agree": agree.value, "class": .string(keyClass), "kid": .string(kid), "sign": sign.value])
    }
}

/// The key store and signer behind the signer's commands (KC-07, SG-03, SG-05, SG-16).
///
/// Owner of: the private keys, which never leave it, and the user verification that guards the signing key.
/// The agreement key has no per-use verification (KC-09): `agree` asks nothing of a person.
/// The signer core owns everything else: the draft, the payload, the render, the hash rules, the
/// low-S rule and the self-verification. A backend only creates a key, says which key it holds,
/// and signs the exact bytes it is given after a fresh user verification of its own.
///
/// Invariants:
/// - One key per configuration. `create` never overwrites; a second call is `key_exists`.
/// - `create` hands the new public keys to `accept` before anything is stored, so a refused pair
///   leaves no key behind.
/// - `sign` needs a fresh user verification every call and keeps no authentication context.
/// - `agree` needs none, never uses the signing key and never returns the shared secret: only the 32 derived bytes.
/// Failure modes, each a `Refusal` with the code of SG-08: `key_exists`, `key_unavailable` (no key,
/// or one the platform will not use), `user_cancel`, `biometric_unavailable`, `internal`.
public protocol KeyBackend: Sendable {
    /// The class of key this build produces (`apple-se-bio` on macOS).
    var keyClass: String { get }

    /// The key bound to this configuration, nil when there is none.
    func bound() throws -> KeyMaterial?

    func create(label: String, person: String, accept: (KeyMaterial) throws -> Void) throws -> KeyMaterial

    /// ES256 over `message`, raw 64-byte R||S, after a fresh verification whose prompt text is
    /// `reason`. The signature may have a high S; the signer normalizes and verifies it.
    func sign(_ message: [UInt8], reason: String) throws -> [UInt8]

    /// ECDH between the agreement key and `peer` (a point already checked to be on P-256), then HKDF-SHA-256 with an
    /// empty salt and `info` (`Agreement.info`), 32 bytes out. The shared secret stays inside: the backend passes it to
    /// `Agreement.key(from:info:)` and returns the result. No prompt, no authentication context, no signing key.
    /// `key_unavailable` when no key is held; `internal` for a failure the platform does not name.
    func agree(peer: Point, info: [UInt8]) throws -> [UInt8]

    /// Called before anything is shown or asked: throws `biometric_unavailable` when the platform
    /// cannot verify a person right now (SG-08). A backend with no such condition does nothing.
    func ready() throws
}

extension KeyBackend {
    public func ready() throws {}
}
