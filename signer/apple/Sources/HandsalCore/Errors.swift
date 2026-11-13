/// The outcome of one run and the exit-code table of SG-08.
///
/// Invariants: exactly one JCS line per run, exit codes 0 to 5 only. Every failure is
/// `{"error":code}` with the exit code of its group:
///   1 `user_cancel` (cancelled, or biometric verification failed)
///   2 input rejected: `schema_refused`, `render_refused`, `attachment_missing`, `attachment_mismatch`,
///     `unsupported_method`, `unsupported_command`, `identity_mismatch`, `key_exists`
///   3 `key_unavailable` (no key, a key the platform invalidated, or a key of another class)
///   4 `no_display`
///   5 `internal`, including a failed self-verification
/// Failure mode: a code nobody listed is `internal`, exit 5, never a made-up code and never exit 0.
/// Codes the checker-form renderer and the validators use (`schema`, `body_schema`, ...) are the
/// signer's `schema_refused`. There is no partial output on any failure.
public struct Outcome: Equatable, Sendable {
    public let exit: Int32
    public let line: [UInt8]
    public init(exit: Int32, line: [UInt8]) { self.exit = exit; self.line = line }
}

public enum ExitCodes {
    private static let refusedInput: Set = ["schema_refused", "render_refused", "attachment_missing", "attachment_mismatch",
                                            "unsupported_method", "unsupported_command", "identity_mismatch", "key_exists"]
    /// Codes the checker-form renderer and the validators use; the signer says `schema_refused`.
    private static let schemaLike: Set = ["schema", "body_schema", "malformed_input", "genesis_schema",
                                          "payload_not_canonical_subset", "payload_too_large", "jws_shape"]
    private static let other: [String: Int32] = ["user_cancel": 1, "key_unavailable": 3, "no_display": 4, "prompt_refused": 4, "internal": 5]

    static func error(_ code: String, exit: Int32) -> Outcome {
        Outcome(exit: exit, line: Array(#"{"error":"\#(code)"}"#.utf8))
    }

    public static func outcome(for refusal: Refusal) -> Outcome {
        let code = refusal.code
        if refusedInput.contains(code) { return error(code, exit: 2) }
        if schemaLike.contains(code) { return error("schema_refused", exit: 2) }
        if code == "method_unknown" { return error("unsupported_method", exit: 2) }
        if let exit = other[code] { return error(code, exit: exit) }
        return error("internal", exit: 5)
    }
}
