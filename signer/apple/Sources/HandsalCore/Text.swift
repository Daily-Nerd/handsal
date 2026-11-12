/// Byte classes of the signed alphabet (ACT-04, ACT-10). One owner.
public enum Text {
    /// One byte of a signed string: 0x20 to 0x7E except `"` and `\`.
    public static func isPlain(_ byte: UInt8) -> Bool {
        byte >= 0x20 && byte <= 0x7E && byte != 0x22 && byte != 0x5C
    }

    public static func isPlain(_ text: String) -> Bool {
        text.utf8.allSatisfy(isPlain)
    }
}
