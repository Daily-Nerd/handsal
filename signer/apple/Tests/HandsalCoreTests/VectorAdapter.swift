import HandsalConformance
import HandsalCore

/// Turns one vector into the output line its anchor holds, the way the harness does: it writes the
/// vector's input as the process would read it on stdin and runs the command of
/// `handsal-sign-conformance` (CF-04) on it. The `subset` rows go to the recognizer, which the
/// signer shares with that executable.
enum VectorAdapter {
    static func line(_ row: Vector) -> String {
        switch row.command {
        case "subset": return subset(row)
        case "render", "emit": return conformance(row)
        default: return "unsupported command \(row.command)"
        }
    }

    static func subset(_ row: Vector) -> String {
        guard case .bytes(let bytes) = row.input else { return "subset needs raw bytes" }
        switch Subset.parse(bytes, maxSize: 16384) {
        case .success: return #"{"canonical":true,"reason":"ok"}"#
        case .failure(.tooLarge): return #"{"canonical":false,"reason":"payload_too_large"}"#
        case .failure(.notCanonical): return #"{"canonical":false,"reason":"payload_not_canonical_subset"}"#
        }
    }

    /// What the harness writes to stdin for a vector: the input, one LF after it (run.py `build_stdin`).
    static func stdin(_ row: Vector) -> [UInt8] {
        switch row.input {
        case .bytes(let raw): return raw
        case .json(let value): return ((try? Emit.resultLine(value)) ?? []) + [0x0A]
        }
    }

    /// The exit code and the output line of the conformance executable for the vector.
    static func outcome(_ row: Vector) -> Outcome {
        ConformanceCLI.run(arguments: [row.command], readStdin: { stdin(row) })
    }

    static func conformance(_ row: Vector) -> String {
        let out = outcome(row)
        guard out.exit == Int32(row.exit) else { return "exit \(out.exit), expected \(row.exit)" }
        return String(decoding: out.line, as: UTF8.self)
    }
}
