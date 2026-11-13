import Darwin
import Foundation
import HandsalCore
import HandsalIJSON

/// Running a program the ceremony depends on, by absolute path, with an empty environment, one
/// stdin and one bounded stdout. Nothing is looked up on PATH and nothing the caller exported
/// reaches the child (SG-14): an agent that sets variables or prepends to PATH cannot substitute
/// the checker, `sudo` or the helper.
enum Run {
    struct Result { let status: Int32; let output: [UInt8] }

    /// Starts `process`, feeds it `input`, and reads at most `limit` bytes of stdout; more is a failure
    /// (`internal`), as is a launch that fails or a child that did not exit normally. stderr is the
    /// terminal's, so a prompt of `sudo` stays visible.
    static func feed(_ process: Process, input: [UInt8], limit: Int) throws -> Result {
        signal(SIGPIPE, SIG_IGN)
        let stdin = Pipe(), stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        do { try process.run() } catch { throw Refusal("internal") }
        let descriptor = stdin.fileHandleForWriting.fileDescriptor
        let writer = Thread {
            input.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let n = write(descriptor, buffer.baseAddress! + offset, buffer.count - offset)
                    if n <= 0 { break }
                    offset += n
                }
            }
            try? stdin.fileHandleForWriting.close()
        }
        writer.start()
        var output: [UInt8] = []
        var tooMuch = false
        while true {
            guard let chunk = try? stdout.fileHandleForReading.read(upToCount: 65_536), !chunk.isEmpty else { break }
            output.append(contentsOf: chunk)
            if output.count > limit { tooMuch = true; process.terminate(); break }
        }
        process.waitUntilExit()
        guard !tooMuch, process.terminationReason == .exit else { throw Refusal("internal") }
        return Result(status: process.terminationStatus, output: output)
    }
}

/// The production checker at its SG-14 path (CF-08): `handsal-check <command>`, one JSON object in,
/// one JCS result line out. An answer that is not exactly one line of I-JSON, a nonzero exit (a
/// crash, CF-03) and a checker that cannot be started are `internal`: the ceremony never guesses
/// what a broken checker meant.
public struct ProductionChecker: CeremonyChecker {
    let executable: String

    public static let installed = ProductionChecker(executable: "/Library/Application Support/handsal/bin/handsal-check")

    #if DEBUG
    /// The test constructor: a stub in place of the SG-14 path. A release build, the installed one, has none.
    init(executable: String) { self.executable = executable }
    #else
    private init(executable: String) { self.executable = executable }
    #endif

    public func run(_ command: String, input: [UInt8]) throws -> JValue {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = [command]
        process.environment = [:]
        process.standardError = FileHandle.nullDevice
        let result = try Run.feed(process, input: input, limit: Limits.maxInput)
        let line = result.output
        guard result.status == 0, line.last == 0x0A, !line.dropLast().contains(0x0A), let value = IJSON.parse(Array(line.dropLast())) else {
            throw Refusal("internal")
        }
        return value
    }
}

/// The macOS channel to the pin helper (GP-12): exactly one `/usr/bin/sudo -k <helper>` run, with
/// no argument to the helper, the GP-21 input line on its stdin and its report on stdout. `-k` with
/// a command neither uses a cached credential nor leaves one. Both paths are fixed (SG-14); a fake
/// `sudo` first on PATH is never started because nothing here consults PATH.
public struct SudoChannel: HelperChannel {
    let sudo: String
    let helper: String

    public static let installed = SudoChannel(sudo: "/usr/bin/sudo", helper: "/Library/Application Support/handsal/bin/handsal-pin")

    #if DEBUG
    /// The test constructor: a stand-in for `sudo` and for the helper. A release build has none.
    init(sudo: String, helper: String) { self.sudo = sudo; self.helper = helper }
    #else
    private init(sudo: String, helper: String) { self.sudo = sudo; self.helper = helper }
    #endif

    func makeProcess() -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: sudo)
        process.arguments = ["-k", helper]
        process.environment = [:]
        return process
    }

    public func submit(_ line: [UInt8]) throws -> HelperReply {
        let result = try Run.feed(makeProcess(), input: line, limit: 4096)
        return HelperReply(exit: result.status, output: result.output)
    }
}
