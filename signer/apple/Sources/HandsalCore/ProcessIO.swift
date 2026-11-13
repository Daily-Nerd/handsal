import Darwin

/// The process plumbing both executables share: stdin in, one line on stdout, the exit code out.
/// Every decision is in the `Outcome` a command function returns, so tests never need a process.
public enum ProcessIO {
    /// At most MAX_INPUT + 1 bytes of stdin: one byte past the bound is enough for the core to
    /// refuse, and nothing more is ever buffered.
    public static func readStdinBounded() -> [UInt8] {
        var data: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while data.count <= Limits.maxInput {
            let n = read(STDIN_FILENO, &chunk, chunk.count)
            if n <= 0 { break }
            data.append(contentsOf: chunk[0..<n])
        }
        return data
    }

    /// Writes the result line and one LF, flushes and exits with the code. Never returns.
    public static func finish(_ outcome: Outcome) -> Never {
        let line = outcome.line + [0x0A]
        line.withUnsafeBufferPointer { _ = fwrite($0.baseAddress, 1, $0.count, stdout) }
        fflush(stdout)
        exit(outcome.exit)
    }

    public static var arguments: [String] { Array(CommandLine.arguments.dropFirst()) }
}
