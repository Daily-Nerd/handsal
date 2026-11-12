import Darwin

/// The signer's command line (SG-01, SG-02, SG-08), as a function from arguments and stdin bytes to
/// one output line and an exit code, so everything it does is testable without a process.
///
/// Invariants: exactly one JCS line per run, exit codes 0 to 5 only, stdout never carries a render.
/// `version` shows no prompt and reads no stdin. Every other command reads at most one object from
/// stdin through the canonical subset recognizer, bounded by MAX_INPUT (SG-01).
/// Failure modes: every failure is `{"error":code}` with the exit code of SG-08; an error nobody
/// listed is `internal`, exit 5, never a made-up code and never exit 0.
public struct Identity: Equatable, Sendable {
    public let performer: String
    public let kid: String
    public init(performer: String, kid: String) { self.performer = performer; self.kid = kid }
}

/// What the signer owns and a caller never supplies: who it signs as, its clock, its randomness.
public struct Environment: Sendable {
    /// Bound at keygen. Nil until a key exists, and then `render` and `sign` answer `key_unavailable`.
    public var identity: Identity?
    public var now: @Sendable () -> Int
    public var nonce: @Sendable () -> String
    public init(identity: Identity?, now: @escaping @Sendable () -> Int, nonce: @escaping @Sendable () -> String) {
        self.identity = identity; self.now = now; self.nonce = nonce
    }

    public static let live = Environment(identity: nil, now: { Int(time(nil)) }, nonce: PayloadBuilder.freshNonce)
}

public struct Outcome: Equatable, Sendable {
    public let exit: Int32
    public let line: [UInt8]
    public init(exit: Int32, line: [UInt8]) { self.exit = exit; self.line = line }
}

public enum ExitCodes {
    private static let refusedInput: Set = ["schema_refused", "render_refused", "attachment_missing", "attachment_mismatch",
                                            "unsupported_method", "key_exists"]
    /// Codes the checker-form renderer and the validators use; the signer says `schema_refused`.
    private static let schemaLike: Set = ["schema", "body_schema", "malformed_input", "genesis_schema",
                                          "payload_not_canonical_subset", "payload_too_large", "jws_shape"]
    private static let other: [String: Int32] = ["user_cancel": 1, "key_unavailable": 3, "no_display": 4, "internal": 5]

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

public enum CLI {
    private static func succeed(_ value: JValue) -> Outcome {
        guard let line = try? Emit.resultLine(value) else { return ExitCodes.outcome(for: Refusal("internal")) }
        return Outcome(exit: 0, line: line)
    }

    /// One object from stdin: at most MAX_INPUT bytes, one trailing LF of framing removed, read
    /// through the canonical subset recognizer.
    static func readObject(_ bytes: [UInt8]) throws -> JValue {
        guard bytes.count <= Limits.maxInput else { throw Refusal("schema_refused") }
        let body = bytes.last == 0x0A ? Array(bytes.dropLast()) : bytes
        guard case .success(let value) = Subset.parse(body, maxSize: Limits.maxInput) else { throw Refusal("schema_refused") }
        return value
    }

    public static func run(arguments: [String], readStdin: () -> [UInt8], environment: Environment = .live) -> Outcome {
        guard arguments.count == 1 else { return ExitCodes.outcome(for: Refusal("unsupported_method")) }
        do {
            switch arguments[0] {
            case "version":
                return succeed(.object(["class": .string("apple-se-bio"), "impl": .string("handsal-sign-swift"),
                                        "spec": .string(Profiles.standard.production)]))
            case "emit":
                return succeed(try SignerCommands.emit(readObject(readStdin())))
            case "render":
                return succeed(try SignerCommands.render(readObject(readStdin()), environment: environment))
            case "keygen", "pubkey", "sign":
                // The key backend is a later task; until it exists these cannot do their work.
                throw Refusal("internal")
            default:
                throw Refusal("unsupported_method")
            }
        } catch let refusal as Refusal {
            return ExitCodes.outcome(for: refusal)
        } catch {
            return ExitCodes.outcome(for: Refusal("internal"))
        }
    }
}
