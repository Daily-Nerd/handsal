import CryptoKit

/// Device key validity (ACT-11, KC-05): one definition of a device's keys.
///
/// A device has a signing key and an agreement key, both P-256 points `{x, y}` of 32 big-endian
/// bytes in canonical base64url, and a `kid` that is the thumbprint of the signing key. The
/// agreement key differs from the signing key.
/// The curve check is CryptoKit's: it refuses a point that is off the curve or whose coordinate is
/// not below the field prime, and the cofactor is 1.
public enum DeviceKey {
    public static func isOnCurve(x: [UInt8], y: [UInt8]) -> Bool {
        guard x.count == 32, y.count == 32 else { return false }
        return (try? P256.Signing.PublicKey(x963Representation: [0x04] + x + y)) != nil
    }

    /// True iff `point` is exactly `{x, y}`, canonical 32-byte coordinates, on P-256.
    public static func pointOk(_ point: JValue) -> Bool {
        guard case .object(let members) = point, Set(members.keys) == ["x", "y"],
              case .string(let xs)? = members["x"], case .string(let ys)? = members["y"],
              let x = Encoding.base64urlDecode(xs), let y = Encoding.base64urlDecode(ys),
              xs.utf8.count == 43, ys.utf8.count == 43 else { return false }
        return isOnCurve(x: x, y: y)
    }

    private static func coordinates(_ point: JValue) -> (String, String)? {
        guard case .object(let m) = point, case .string(let x)? = m["x"], case .string(let y)? = m["y"] else { return nil }
        return (x, y)
    }

    /// nil for a valid key set, else the first defect: `sign_point`, `agree_point`,
    /// `kid_not_thumbprint`, `agree_equals_sign`.
    public static func defect(kid: String, sign: JValue, agree: JValue) -> String? {
        guard pointOk(sign), let s = coordinates(sign) else { return "sign_point" }
        guard pointOk(agree) else { return "agree_point" }
        if kid != Encoding.thumbprint(x: s.0, y: s.1) { return "kid_not_thumbprint" }
        if sign == agree { return "agree_equals_sign" }
        return nil
    }
}
