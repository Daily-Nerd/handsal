/// The signer's command line (SG-01, SG-02, SG-08), as a function from arguments and stdin bytes to
/// one output line and an exit code, so everything it does is testable without a process.
///
/// Invariants: exactly one JCS line per run, exit codes 0 to 5 only, stdout never carries a render.
/// `version` and `pubkey` read no stdin and show no prompt; `agree` reads one object and shows no prompt either. Every other command reads at most one
/// object from stdin through the canonical subset recognizer, bounded by MAX_INPUT (SG-01).
/// Failure modes: every failure is `{"error":code}` with the exit code of SG-08 (see `ExitCodes`);
/// an unknown, missing or extra command is `unsupported_command`.
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

    private static func answer(_ command: () throws -> JValue) -> Outcome {
        do {
            return succeed(try command())
        } catch let refusal as Refusal {
            return ExitCodes.outcome(for: refusal)
        } catch {
            return ExitCodes.outcome(for: Refusal("internal"))
        }
    }

    /// `emit` alone: the shipped signer and `handsal-sign-conformance` both answer it through here, so
    /// there is one implementation of its input, output and exit codes (CF-04).
    public static func emit(readStdin: () -> [UInt8]) -> Outcome {
        answer { try SignerCommands.emit(readObject(readStdin())) }
    }

    public static func run(arguments: [String], readStdin: () -> [UInt8], environment: Environment) -> Outcome {
        guard arguments.count == 1 else { return ExitCodes.outcome(for: Refusal("unsupported_command")) }
        switch arguments[0] {
        case "version": return answer { SignerCommands.version(environment: environment) }
        case "pubkey": return answer { try SignerCommands.pubkey(environment: environment) }
        case "emit": return emit(readStdin: readStdin)
        case "keygen": return answer { try SignerCommands.keygen(readObject(readStdin()), environment: environment) }
        case "render": return answer { try SignerCommands.render(readObject(readStdin()), environment: environment) }
        case "sign": return answer { try SignerCommands.sign(readObject(readStdin()), environment: environment) }
        case "agree": return answer { try SignerCommands.agree(readObject(readStdin()), environment: environment) }
        default: return ExitCodes.outcome(for: Refusal("unsupported_command"))
        }
    }
}
