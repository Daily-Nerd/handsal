import CryptoKit

/// Encodings shared by every command (ACT-03, ACT-07, ACT-11). Pure functions; a function that
/// cannot decode answers nil, and the caller picks the reason code.
public enum Encoding {
    private static let urlAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)
    private static let stdAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    private static func encode(_ bytes: [UInt8], alphabet: [UInt8], pad: Bool) -> String {
        var out: [UInt8] = []
        var i = 0
        while i < bytes.count {
            let n = min(3, bytes.count - i)
            var chunk = UInt32(bytes[i]) << 16
            if n > 1 { chunk |= UInt32(bytes[i + 1]) << 8 }
            if n > 2 { chunk |= UInt32(bytes[i + 2]) }
            for k in 0...n { out.append(alphabet[Int((chunk >> UInt32(18 - 6 * k)) & 63)]) }
            if pad { out.append(contentsOf: [UInt8](repeating: UInt8(ascii: "="), count: 3 - n)) }
            i += 3
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes `symbols` (no padding) and requires that encoding gives the input back (canonical).
    private static func decode(_ symbols: [UInt8], alphabet: [UInt8]) -> [UInt8]? {
        var lookup = [Int](repeating: -1, count: 256)
        for (index, byte) in alphabet.enumerated() { lookup[Int(byte)] = index }
        if symbols.count % 4 == 1 { return nil }
        var out: [UInt8] = []
        var i = 0
        while i < symbols.count {
            let n = min(4, symbols.count - i)
            var chunk: UInt32 = 0
            for k in 0..<n {
                let v = lookup[Int(symbols[i + k])]
                if v < 0 { return nil }
                chunk |= UInt32(v) << UInt32(18 - 6 * k)
            }
            out.append(UInt8((chunk >> 16) & 255))
            if n > 2 { out.append(UInt8((chunk >> 8) & 255)) }
            if n > 3 { out.append(UInt8(chunk & 255)) }
            i += 4
        }
        let again = encode(out, alphabet: alphabet, pad: false)
        return Array(again.utf8) == symbols ? out : nil
    }

    public static func base64url(_ bytes: [UInt8]) -> String {
        encode(bytes, alphabet: urlAlphabet, pad: false)
    }

    /// Canonical base64url without padding (ACT-03): no other alphabet, no spare bits set.
    public static func base64urlDecode(_ text: String) -> [UInt8]? {
        decode(Array(text.utf8), alphabet: urlAlphabet)
    }

    /// Standard base64 with padding, canonical (section 2.2 `_b64` inputs).
    public static func base64Decode(_ text: String) -> [UInt8]? {
        var symbols = Array(text.utf8)
        guard symbols.count % 4 == 0 else { return nil }
        var pad = 0
        while symbols.last == UInt8(ascii: "="), pad < 3 { symbols.removeLast(); pad += 1 }
        guard pad <= 2, !symbols.contains(UInt8(ascii: "=")) else { return nil }
        guard let out = decode(symbols, alphabet: stdAlphabet) else { return nil }
        let want = encode(out, alphabet: stdAlphabet, pad: true)
        return want == text ? out : nil
    }

    public static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: bytes))
    }

    /// `"u" + base64url(0x12 0x20 || sha256(bytes))`, 47 characters (section 2.1).
    public static func hashstr(_ bytes: [UInt8]) -> String {
        "u" + base64url([0x12, 0x20] + sha256(bytes))
    }

    public static let emptyHash = hashstr([])

    public static func isHashstr(_ text: String) -> Bool {
        guard text.utf8.count == 47, text.hasPrefix("uEi") else { return false }
        guard let raw = base64urlDecode(String(text.dropFirst())) else { return false }
        return raw.count == 34 && raw[0] == 0x12 && raw[1] == 0x20
    }

    /// RFC 7638 thumbprint of a P-256 key, over the members crv, kty, x, y in that order (ACT-11).
    public static func thumbprint(x: String, y: String) -> String {
        let json = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return base64url(sha256(Array(json.utf8)))
    }
}
