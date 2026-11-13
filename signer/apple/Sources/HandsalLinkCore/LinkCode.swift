import HandsalCore

/// The one-time code of device linking (SG-09): 32 random bytes.
///
/// Invariants: exactly 32 bytes from the system CSPRNG, never all zero; `hash` is the canonical
/// hashstr of those bytes (the `link_code_hash` of `device.add` and `member.add`, ACT-09), and
/// `text` is what the QR code carries: the base64url of the bytes, 43 characters.
/// Failure mode: a source that gives another length, or only zeros, is `internal`: a short or
/// empty code is never shown and never hashed, so no weak `link_code_hash` can exist.
public struct LinkCode: Equatable, Sendable {
    public static let size = 32

    public let bytes: [UInt8]

    public var hash: String { Encoding.hashstr(bytes) }
    public var text: String { Encoding.base64url(bytes) }

    public static func make(random: () -> [UInt8] = systemRandom) throws -> LinkCode {
        let bytes = random()
        guard bytes.count == size, bytes.contains(where: { $0 != 0 }) else { throw Refusal("internal") }
        return LinkCode(bytes: bytes)
    }

    public static func systemRandom() -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<size).map { _ in UInt8.random(in: 0...255, using: &generator) }
    }
}
