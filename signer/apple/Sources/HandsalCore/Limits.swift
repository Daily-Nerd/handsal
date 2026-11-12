/// The constants of section 2.3. One owner, so no number is repeated.
public enum Limits {
    /// Every signed or hashed value: payload, header, genesis document.
    public static let maxPayload = 16_384
    public static let maxDepth = 8
    /// The bytes a signer reads from its input channel.
    public static let maxInput = 16_777_216
    public static let maxExpiresInS = 2_592_000
    public static let line1Max = 80
    public static let lineMax = 100
    public static let wrapSegment = 98
    public static let maxLines = 72
    public static let blockMaxBytes = 2048
    public static let blockMaxLines = 32
    public static let blockLineBytes = 96
}
