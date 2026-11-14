import CryptoKit
import Foundation

/// The derivation behind `agree` (SG-16): the one owner of the label, the layout of `info` and the HKDF.
///
/// The shared secret of a key agreement is never returned by any API. A key backend does the agreement
/// inside its key store and hands the `SharedSecret` (an opaque CryptoKit value) to `key(from:info:)`, the
/// only function that makes bytes of it, and what leaves is the 32-byte HKDF-SHA-256 output:
///
///     info = "handsal-agree/1" || 0x00 || lo || hi || context
///
/// `lo` and `hi` are the two public points of the agreement (the device's own `agree` point and the peer's),
/// each 65 bytes `0x04 || x || y`, the smaller in byte order first. They are ordered by value and not by role,
/// so both parties of one agreement build the same `info`. Everything before `context` has a fixed length, so
/// two inputs never share an `info`. The salt is empty (HashLen zero bytes, RFC 5869) and the length is 32.
/// Failure mode: a point that is not 32-byte coordinates has no encoding, so `info` is nil and the caller
/// reports `internal` (a point of the input was validated before; one of the key's own is the key store's).
public enum Agreement {
    /// The label that confines the output to handsal's agreement domain.
    public static let label: [UInt8] = Array("handsal-agree/1".utf8)
    /// The length of the derived key, in bytes.
    public static let keyLength = 32

    /// `0x04 || x || y`, or nil for a point whose coordinates are not 32 bytes of canonical base64url.
    static func uncompressed(_ point: Point) -> [UInt8]? {
        guard point.x.utf8.count == 43, point.y.utf8.count == 43, let x = Encoding.base64urlDecode(point.x),
              let y = Encoding.base64urlDecode(point.y), x.count == 32, y.count == 32 else { return nil }
        return [0x04] + x + y
    }

    public static func info(own: Point, peer: Point, context: String) -> [UInt8]? {
        guard let a = uncompressed(own), let b = uncompressed(peer) else { return nil }
        let (low, high) = a.lexicographicallyPrecedes(b) ? (a, b) : (b, a)
        return label + [0x00] + low + high + Array(context.utf8)
    }

    /// The derived key. This is the one place that turns a shared secret into bytes, and the bytes are the HKDF output.
    public static func key(from secret: SharedSecret, info: [UInt8]) -> [UInt8] {
        let derived = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(info), outputByteCount: keyLength)
        return derived.withUnsafeBytes { [UInt8]($0) }
    }
}
