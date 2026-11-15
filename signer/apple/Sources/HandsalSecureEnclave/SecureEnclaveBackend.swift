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
    /// The key folder, asked for where a key is read or written and nowhere else (SH12): `version` and `emit` never
    /// ask, so a uid with no home still answers them.
    private let resolve: @Sendable () throws -> String
    private let policy: BiometricPolicy

    public init(directory: String, policy: BiometricPolicy = .live) { self.resolve = { directory }; self.policy = policy }

    /// A backend whose folder is under `home()` (the lookup of the directory service in the shipped signer). No home is
    /// `internal` at the first use of the key.
    public init(home: @escaping @Sendable () -> String?, policy: BiometricPolicy = .live) {
        self.resolve = { try Self.directory(home: home) }; self.policy = policy
    }

    /// Where the signer keeps its key for the current user (SH12). The home is the one the directory service holds
    /// for the real uid. No environment variable is read: `HOME` and `CFFIXED_USER_HOME` belong to whoever started
    /// the process, and `NSHomeDirectory()` follows them. A uid with no home is the signer faulty: `internal`, never a
    /// substitute folder.
    public static func defaultDirectory() throws -> String { try directory(home: directoryServiceHome) }

    /// The one rule that turns a home into the key folder; `home` is the lookup, so a test can say what it finds.
    public static func directory(home: () -> String?) throws -> String {
        guard let home = home(), !home.isEmpty else { throw Refusal("internal") }
        return home + "/Library/Application Support/handsal-sign"
    }

    private static func directoryServiceHome() -> String? {
        var record = passwd()
        var found: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 16384)
        guard getpwuid_r(getuid(), &record, &buffer, buffer.count, &found) == 0, found != nil, let dir = record.pw_dir else { return nil }
        return String(cString: dir)
    }

    public static func standard() -> SecureEnclaveBackend { SecureEnclaveBackend(home: directoryServiceHome) }

    /// The prompt lock beside the key: as fallible as the folder (`internal` with no home).
    public func lockPath() throws -> String { try resolve() + "/prompt.lock" }
    private func keyPath() throws -> String { try resolve() + "/key.json" }

    private func stored() throws -> StoredKey? {
        guard let bytes = try KeyFile.read(path: try keyPath()) else { return nil }
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
        try KeyFile.createExclusive(path: try keyPath(), bytes: try KeyFile.encode(record))
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
