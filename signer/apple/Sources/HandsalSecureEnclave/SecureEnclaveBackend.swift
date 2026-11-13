import CryptoKit
import Foundation
import HandsalCore
import LocalAuthentication
import Security

/// The Secure Enclave key backend of the shipped macOS signer (KC-01, SG-03, SG-05).
///
/// Keys are `SecureEnclave.P256` keys through CryptoKit. The private key never leaves the chip.
/// What is stored is the `dataRepresentation` blob in a private file (`KeyFile`), never a keychain
/// item, so the binary needs no keychain entitlement and ad-hoc signing is enough. The access
/// control is `.biometryCurrentSet` with private key usage: a change of the enrolled fingerprints
/// invalidates the key (SG-11), and every signature needs a fresh verification of the current set.
///
/// SG-05, fresh authentication per signature: `sign` creates a new authentication context as a
/// local, hands it to the one key it was made for, and lets it go out of scope. No property, no
/// parameter and no result holds one, so a caller cannot supply a context and a previous
/// signature's context cannot be reused. `SecureEnclaveTests` reads this file to keep it so.
/// Failure modes: `key_unavailable` (no hardware, no key, a key the platform will not use),
/// `key_exists`, `user_cancel`, `internal`; see `SecureEnclaveErrors`.
public struct SecureEnclaveBackend: KeyBackend {
    public let keyClass = "apple-se-bio"
    private let directory: String

    public init(directory: String) { self.directory = directory }

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

    private static func accessControl() throws -> SecAccessControl {
        var failure: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                            [.privateKeyUsage, .biometryCurrentSet], &failure) else {
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
            let control = try Self.accessControl()
            signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control)
            agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control)
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
}
