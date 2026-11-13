import Foundation
import HandsalCore

/// SG-03, the invariant "repositories hold key ids, never key material". One scan, used by the test of
/// every tool that writes or shows something (signer, linking tool, ceremony, pin helper): it looks for a
/// private scalar in the bytes of an output, in each form a person could paste.
public enum KeyScan {
    /// Every textual and byte form of `scalar` that an output could carry.
    public static func forms(of scalar: [UInt8]) -> [[UInt8]] {
        let data = Data(scalar)
        let hex = scalar.map { String(format: "%02x", $0) }.joined()
        let texts = [hex, hex.uppercased(), data.base64EncodedString(), Encoding.base64url(scalar)]
        return [scalar] + texts.map { Array($0.utf8) }
    }

    public static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        return (0...(haystack.count - needle.count)).contains { Array(haystack[$0..<($0 + needle.count)]) == needle }
    }

    public static func leaks(_ haystack: [UInt8], scalar: [UInt8]) -> Bool {
        forms(of: scalar).contains { contains(haystack, $0) }
    }
}
