/// The low-S rule (SG-06, VR-04): a signature's S is in the lower half of the group order.
///
/// A platform may return either half. The signer returns the low one, so every signature has one
/// form and a verifier that refuses `high_s` never sees one from an honest signer.
public enum Signature {
    // The P-256 group order n, and n - 1 halved: S is low when S <= (n - 1) / 2 (VR-04).
    private static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]
    private static let half: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
    ]

    private static func isZero(_ value: [UInt8]) -> Bool { !value.contains { $0 != 0 } }

    /// `raw` (R||S, 64 bytes) with S replaced by n - S when S is high. A signature that is not 64
    /// bytes, or whose S is 0 or not below n, is no signature: `internal`.
    public static func lowS(_ raw: [UInt8]) throws -> [UInt8] {
        guard raw.count == 64 else { throw Refusal("internal") }
        let r = Array(raw[0..<32]), s = Array(raw[32..<64])
        guard !isZero(s), s.lexicographicallyPrecedes(order) else { throw Refusal("internal") }
        guard half.lexicographicallyPrecedes(s) else { return raw }
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(order[index]) - Int(s[index]) - borrow
            if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
            out[index] = UInt8(value)
        }
        return r + out
    }
}
