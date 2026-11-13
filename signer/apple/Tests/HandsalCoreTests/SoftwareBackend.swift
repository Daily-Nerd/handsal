import CryptoKit
import Foundation
import HandsalCore

/// The software key backend of KC-07 for tests: class `test-sw-p256`, no hardware, no prompt UI.
/// It lives in the test target only. The shipped `handsal-sign` is built from targets that do not
/// contain it, and `BackendLinkTests` checks the binary.
///
/// It records every prompt (`prompts`) so a test can say how many a command showed and with what
/// words, and it can misbehave on purpose (`Mode`) so the signer's guards are exercised against
/// the faults they exist for: a cancel, a key the platform invalidated, a high-S or wrong
/// signature, a signature over a digest instead of the message.
final class SoftwareBackend: KeyBackend, @unchecked Sendable {
    enum Mode { case normal, highS, cancel, invalidatedAtSign, invalidated, doubleHash, brokenSignature }

    let keyClass: String
    private let lock = NSLock()
    private var signing: P256.Signing.PrivateKey?
    private var material: KeyMaterial?
    private var behavior: Mode = .normal
    private var asked: [String] = []
    private var created = 0
    /// `keygen` makes the agreement key equal to the signing key: a fault the signer must refuse.
    var makesEqualPair = false
    /// The class written into the key a later `create` stores, when it is not the build's own.
    var storedClass: String?

    /// A fixed signing scalar (the public fixture keys of KC-07) instead of a fresh random key.
    private let scalar: [UInt8]?

    init(keyClass: String = "test-sw-p256", scalar: [UInt8]? = nil) { self.keyClass = keyClass; self.scalar = scalar }

    var mode: Mode {
        get { lock.withLock { behavior } }
        set { lock.withLock { behavior = newValue } }
    }

    var prompts: [String] { lock.withLock { asked } }
    var creations: Int { lock.withLock { created } }

    private static func point(_ key: P256.Signing.PublicKey) -> Point {
        let raw = [UInt8](key.x963Representation)
        return Point(x: Encoding.base64url(Array(raw[1..<33])), y: Encoding.base64url(Array(raw[33..<65])))
    }

    func bound() throws -> KeyMaterial? {
        try lock.withLock {
            if behavior == .invalidated, material != nil { throw Refusal("key_unavailable") }
            return material
        }
    }

    func create(label: String, person: String, accept: (KeyMaterial) throws -> Void) throws -> KeyMaterial {
        try lock.withLock {
            guard material == nil else { throw Refusal("key_exists") }
            let key = try scalar.map { try P256.Signing.PrivateKey(rawRepresentation: Data($0)) } ?? P256.Signing.PrivateKey()
            let agreement = makesEqualPair ? key.publicKey : P256.Signing.PrivateKey().publicKey
            let made = KeyMaterial(keyClass: storedClass ?? keyClass, person: person, sign: Self.point(key.publicKey), agree: Self.point(agreement))
            try accept(made)
            signing = key
            material = made
            created += 1
            return made
        }
    }

    func sign(_ message: [UInt8], reason: String) throws -> [UInt8] {
        try lock.withLock {
            asked.append(reason)
            guard let signing else { throw Refusal("key_unavailable") }
            switch behavior {
            case .cancel: throw Refusal("user_cancel")
            case .invalidatedAtSign, .invalidated: throw Refusal("key_unavailable")
            case .normal: return [UInt8](try signing.signature(for: Data(message)).rawRepresentation)
            case .highS: return Self.highS([UInt8](try signing.signature(for: Data(message)).rawRepresentation))
            case .doubleHash: return [UInt8](try signing.signature(for: Data(SHA256.hash(data: message))).rawRepresentation)
            case .brokenSignature:
                var raw = [UInt8](try signing.signature(for: Data(message)).rawRepresentation)
                raw[10] ^= 0x01
                return raw
            }
        }
    }

    // MARK: high-S, written out here and not shared with the signer under test

    static let order: [UInt8] = Vector.decodeHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

    /// `n - s` for the S half of a raw signature, whichever half S was in; the result is high.
    static func highS(_ raw: [UInt8]) -> [UInt8] {
        let r = Array(raw[0..<32]), s = Array(raw[32..<64])
        let half = Vector.decodeHex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
        if half.lexicographicallyPrecedes(s) { return raw }   // already above n/2
        return r + subtract(order, s)
    }

    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(a[index]) - Int(b[index]) - borrow
            if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
            out[index] = UInt8(value)
        }
        return out
    }
}

/// A display channel that records what it is shown, or none at all.
final class RecordingDisplay: Display, @unchecked Sendable {
    private let lock = NSLock()
    private var written: [String] = []
    var shown: [String] { lock.withLock { written } }
    var text: String { shown.joined() }
    func show(_ text: String) throws { lock.withLock { written.append(text) } }
}
