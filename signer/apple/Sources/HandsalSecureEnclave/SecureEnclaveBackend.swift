import CryptoKit
import Foundation
import HandsalCore
import LocalAuthentication
import Security

/// The Secure Enclave key backend of the shipped macOS signer (KC-01, SG-03, SG-05).
///
/// Keys are `SecureEnclave.P256` keys through CryptoKit. The private key never leaves the chip.
/// What is stored is the `dataRepresentation` blob in a private file (`KeyFile`), never a keychain
/// item, so the binary needs no keychain entitlement and ad-hoc signing is enough. The signing key's access
/// control is `.biometryCurrentSet` with private key usage: a change of the enrolled fingerprints
/// invalidates it (SG-11), and every signature needs a fresh verification of the current set. The agreement
/// key is created with private key usage only (KC-09): `agree` asks no one, a change of the fingerprints
/// leaves it usable, and it is never used to sign.
///
/// SG-05, fresh authentication per signature: `sign` creates a new authentication context as a
/// local, hands it to the one key it was made for, and lets it go out of scope. No property, no
/// parameter and no result holds one, so a caller cannot supply a context and a previous
/// signature's context cannot be reused. `SecureEnclaveTests` reads this file to keep it so.
/// `agree` (SG-16) does the key agreement inside the Secure Enclave and hands the opaque result to `Agreement`,
/// so the shared secret never leaves as bytes.
/// Failure modes: `key_unavailable` (no hardware, no key, a key the platform will not use),
/// `key_exists`, `user_cancel`, `biometric_unavailable`, `internal`; see `SecureEnclaveErrors`.
public struct SecureEnclaveBackend: KeyBackend {
    public let keyClass = "apple-se-bio"
    private let directory: String
    private let policy: BiometricPolicy

    public init(directory: String, policy: BiometricPolicy = .live) { self.directory = directory; self.policy = policy }

    /// Where the signer keeps its key for the current user.
    public static var defaultDirectory: String { NSHomeDirectory() + "/Library/Application Support/handsal-sign" }

    public static func standard() -> SecureEnclaveBackend { SecureEnclaveBackend(directory: defaultDirectory) }

    public var lockPath: String { directory + "/prompt.lock" }
    private var keyPath: String { directory + "/key.json" }

    private func stored() throws -> StoredKey? {
        guard let bytes = try KeyFile.read(path: keyPath) else { return nil }
        return try KeyFile.decode(bytes)
    }

    public func bound() throws -> KeyMaterial? {
        guard let key = try stored() else { return nil }
        return KeyMaterial(keyClass: key.keyClass, person: key.person, sign: key.sign, agree: key.agree)
    }

    private static func point(_ raw: [UInt8]) -> Point {
        Point(x: Encoding.base64url(Array(raw[1..<33])), y: Encoding.base64url(Array(raw[33..<65])))
    }

    private static func accessControl(_ flags: SecAccessControlCreateFlags) throws -> SecAccessControl {
        var failure: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                            flags, &failure) else {
            throw SecureEnclaveErrors.refusal(for: failure?.takeRetainedValue() ?? Refusal("internal"))
        }
        return control
    }

    public func create(label: String, person: String, accept: (KeyMaterial) throws -> Void) throws -> KeyMaterial {
        guard try stored() == nil else { throw Refusal("key_exists") }
        guard SecureEnclave.isAvailable else { throw Refusal("key_unavailable") }
        let signing: SecureEnclave.P256.Signing.PrivateKey
        let agreement: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            // The two keys have two access rules (KC-09). The signing key needs a fresh verification of the current
            // fingerprint set for every signature. The agreement key needs none: private key use only, fixed at creation.
            let signingFlags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryCurrentSet]
            let agreementFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
            let signingControl = try Self.accessControl(signingFlags)
            let agreementControl = try Self.accessControl(agreementFlags)
            signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: signingControl)
            agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: agreementControl)
        } catch let refusal as Refusal {
            throw refusal
        } catch {
            throw Refusal("key_unavailable")
        }
        let material = KeyMaterial(keyClass: keyClass, person: person,
                                   sign: Self.point([UInt8](signing.publicKey.x963Representation)),
                                   agree: Self.point([UInt8](agreement.publicKey.x963Representation)))
        // The profile's key rule runs before anything is written: a refused pair leaves nothing.
        try accept(material)
        let record = StoredKey(label: label, person: person, keyClass: keyClass, sign: material.sign, agree: material.agree,
                               signBlob: [UInt8](signing.dataRepresentation), agreeBlob: [UInt8](agreement.dataRepresentation))
        try KeyFile.createExclusive(path: keyPath, bytes: try KeyFile.encode(record))
        return material
    }

    /// The precheck before a prompt (SG-08): a sensor that cannot verify now is refused before
    /// anything is shown, with the code the platform's own error maps to.
    public func ready() throws {
        if let failure = policy.unavailability() { throw SecureEnclaveErrors.refusal(for: failure) }
    }

    public func sign(_ message: [UInt8], reason: String) throws -> [UInt8] {
        guard let record = try stored() else { throw Refusal("key_unavailable") }
        let context = LAContext()
        context.localizedReason = reason
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(record.signBlob), authenticationContext: context)
            return [UInt8](try key.signature(for: Data(message)).rawRepresentation)
        } catch {
            throw SecureEnclaveErrors.refusal(for: error)
        }
    }

    public func agree(peer: Point, info: [UInt8]) throws -> [UInt8] {
        guard let record = try stored() else { throw Refusal("key_unavailable") }
        guard let x = Encoding.base64urlDecode(peer.x), let y = Encoding.base64urlDecode(peer.y) else { throw Refusal("internal") }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(record.agreeBlob))
            let other = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04] + x + y))
            return Agreement.key(from: try key.sharedSecretFromKeyAgreement(with: other), info: info)
        } catch {
            throw SecureEnclaveErrors.refusal(for: error)
        }
    }
}
