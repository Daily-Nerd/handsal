/// A parsed JSON value.
///
/// Owner of: the shape of every value the signer reads or writes.
/// Invariant: `object` keys are unique (a dictionary cannot hold a duplicate), and emission
/// order is decided by the emitter alone, never by this type.
/// `bool` and `number` exist because result lines and the checker-form test input carry them.
/// The canonical subset recognizer never produces either, and the subset emitter refuses both.
public enum JValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case number(String)
    case string(String)
    case array([JValue])
    case object([String: JValue])
}

/// A rule of the profile said no. `code` is the reason code the spec names.
public struct Refusal: Error, Equatable, Sendable {
    public let code: String
    public init(_ code: String) { self.code = code }
}
