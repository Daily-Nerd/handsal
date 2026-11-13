import Darwin
import Foundation
import HandsalCore
import HandsalIJSON

/// Running a program the ceremony depends on, by absolute path, with an empty environment, one
/// stdin and one bounded stdout. Nothing is looked up on PATH and nothing the caller exported
/// reaches the child (SG-14): an agent that sets variables or prepends to PATH cannot substitute
/// the checker, `sudo` or the helper.
///
/// This is the one place a child is started, and it is started with `posix_spawn` and no process
/// group of its own: the child stays in the ceremony's group, which is the terminal's foreground
/// group when a person ran the ceremony from a shell. Foundation's `Process` puts every child in a
/// new group, a background group on the terminal, and `sudo` there cannot turn echo off and cannot
/// read the password from `/dev/tty`: the password is typed in the clear. Starting a child cannot
/// leave the group by construction, so no caller has to remember it.
enum Run {
    struct Result { let status: Int32; let output: [UInt8] }

    /// Where the child's stderr goes: the terminal's (a prompt of `sudo` stays visible) or nowhere.
    enum Stderr { case inherited, discarded }

    /// Starts `path` with `arguments`, feeds it `input`, and reads at most `limit` bytes of stdout;
    /// more is a failure (`internal`), as is a launch that fails or a child that did not exit normally.
    static func feed(path: String, arguments: [String], input: [UInt8], limit: Int, stderr: Stderr) throws -> Result {
        signal(SIGPIPE, SIG_IGN)
        var toChild: [Int32] = [0, 0], fromChild: [Int32] = [0, 0]
        guard pipe(&toChild) == 0 else { throw Refusal("internal") }
        guard pipe(&fromChild) == 0 else { close(toChild[0]); close(toChild[1]); throw Refusal("internal") }
        guard let pid = spawn(path: path, arguments: arguments, stdin: toChild[0], stdout: fromChild[1], stderr: stderr) else {
            for descriptor in toChild + fromChild { close(descriptor) }
            throw Refusal("internal")
        }
        close(toChild[0]); close(fromChild[1])
        let writeEnd = toChild[1]
        let writer = Thread {
            input.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let n = write(writeEnd, buffer.baseAddress! + offset, buffer.count - offset)
                    if n <= 0 { break }
                    offset += n
                }
            }
            close(writeEnd)
        }
        writer.start()
        var output: [UInt8] = []
        var tooMuch = false
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while true {
            let n = read(fromChild[0], &chunk, chunk.count)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            output.append(contentsOf: chunk[0..<n])
            if output.count > limit { tooMuch = true; kill(pid, SIGTERM); break }
        }
        close(fromChild[0])
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 { if errno != EINTR { throw Refusal("internal") } }
        // Mask of the wait status, as <sys/wait.h> defines it: exited normally when the low 7 bits are zero.
        guard !tooMuch, (status & 0x7f) == 0 else { throw Refusal("internal") }
        return Result(status: (status >> 8) & 0xff, output: output)
    }

    /// `posix_spawn` with no `POSIX_SPAWN_SETPGROUP` (the child keeps the ceremony's group), every
    /// other descriptor closed, default signal handlers and an empty mask, and an empty environment.
    private static func spawn(path: String, arguments: [String], stdin: Int32, stdout: Int32, stderr: Stderr) -> pid_t? {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_adddup2(&actions, stdin, 0)
        posix_spawn_file_actions_adddup2(&actions, stdout, 1)
        switch stderr {
        case .inherited: posix_spawn_file_actions_addinherit_np(&actions, 2)
        case .discarded: posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0)
        }
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        var everySignal = sigset_t(), noSignal = sigset_t()
        sigfillset(&everySignal); sigemptyset(&noSignal)
        posix_spawnattr_setsigdefault(&attributes, &everySignal)
        posix_spawnattr_setsigmask(&attributes, &noSignal)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))
        var argv: [UnsafeMutablePointer<CChar>?] = ([path] + arguments).map { strdup($0) } + [nil]
        defer { for pointer in argv { free(pointer) } }
        var envp: [UnsafeMutablePointer<CChar>?] = [nil]
        var pid: pid_t = 0
        guard posix_spawn(&pid, path, &actions, &attributes, &argv, &envp) == 0 else { return nil }
        return pid
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
        let result = try Run.feed(path: executable, arguments: [command], input: input, limit: Limits.maxInput, stderr: .discarded)
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

    /// The one invocation: `sudo -k <helper>`, and no other argument.
    var arguments: [String] { ["-k", helper] }

    public func submit(_ line: [UInt8]) throws -> HelperReply {
        let result = try Run.feed(path: sudo, arguments: arguments, input: line, limit: 4096, stderr: .inherited)
        return HelperReply(exit: result.status, output: result.output)
    }
}
