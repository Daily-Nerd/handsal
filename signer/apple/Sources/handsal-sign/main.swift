import Darwin
import HandsalCore

// Plumbing only: arguments and stdin in, one line on stdout, the exit code out. Every decision is
// in `CLI.run`, which tests call without a process.

func readStdinBounded() -> [UInt8] {
    var data: [UInt8] = []
    var chunk = [UInt8](repeating: 0, count: 65_536)
    // One byte past MAX_INPUT is enough for the core to refuse; never buffer more than that.
    while data.count <= Limits.maxInput {
        let n = read(STDIN_FILENO, &chunk, chunk.count)
        if n <= 0 { break }
        data.append(contentsOf: chunk[0..<n])
    }
    return data
}

let outcome = CLI.run(arguments: Array(CommandLine.arguments.dropFirst()), readStdin: readStdinBounded)
let line = outcome.line + [0x0A]
line.withUnsafeBufferPointer { _ = fwrite($0.baseAddress, 1, $0.count, stdout) }
fflush(stdout)
exit(outcome.exit)
