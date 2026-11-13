import HandsalCore
import HandsalIJSON

/// The command line of `handsal-sign-conformance` (CF-04), as a function from arguments and stdin
/// bytes to one output line and an exit code.
///
/// It is the signer's half of the vector contract: `render` takes the CF-03 form and gives the
/// CF-03 output, exit 0 for every result, so the `render` vectors are the very ones the checker
/// runs; `emit` is the shipped `emit`, same input, output and exit codes. Any other argument is
/// `unsupported_command`, exit 2 (SG-08).
///
/// Invariants: no key, no prompt, no display, no clock, no randomness. Every value the output
/// depends on is in the input, which is why the function takes no `Environment`.
/// Why a separate executable and not a flag on the shipped signer: the shipped `render` fills
/// `performer_id`, `kid` and `ts` from its key and clock, so a flag would be a way to make the
/// signer show words for bytes it did not derive. The split is a build, not a flag (CF-08).
public enum ConformanceCLI {
    public static func run(arguments: [String], readStdin: () -> [UInt8]) -> Outcome {
        guard arguments.count == 1 else { return ExitCodes.outcome(for: Refusal("unsupported_command")) }
        switch arguments[0] {
        case "render": return render(readStdin())
        case "emit": return CLI.emit(readStdin: readStdin)
        default: return ExitCodes.outcome(for: Refusal("unsupported_command"))
        }
    }

    private static func result(_ value: JValue) -> Outcome {
        guard let line = try? Emit.resultLine(value) else { return ExitCodes.outcome(for: Refusal("internal")) }
        return Outcome(exit: 0, line: line)
    }

    private static func error(_ code: String) -> Outcome { result(.object(["error": .string(code)])) }

    /// CF-03: size first, then I-JSON, then exactly `{attachments, kid, method, payload}` with the
    /// right types, then the pure render. Every outcome is exit 0.
    static func render(_ bytes: [UInt8]) -> Outcome {
        guard bytes.count <= Limits.maxInput, let value = IJSON.parse(bytes) else { return error("unparseable_input") }
        guard case .object(let input) = value, Set(input.keys) == ["attachments", "kid", "method", "payload"],
              case .object? = input["attachments"], case .string(let kid)? = input["kid"],
              case .string(let method)? = input["method"], case .object? = input["payload"],
              let attachments = input["attachments"], let payload = input["payload"] else { return error("malformed_input") }
        do {
            let rendered = try Render.render(RenderInput(attachments: attachments, kid: kid, method: method, payload: payload))
            return result(.object(["first_line": .string(rendered.firstLine), "text": .string(rendered.text)]))
        } catch let refusal as Refusal {
            return error(refusal.code)
        } catch {
            return ExitCodes.outcome(for: Refusal("internal"))
        }
    }
}
