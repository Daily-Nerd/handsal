import Darwin

/// SG-10: the signer limits prompt frequency per process and never runs while another of its
/// prompts is open.
///
/// Owner of both rules. "Another prompt is open" spans processes (two `handsal-sign` runs), so it
/// is one advisory `flock` on a private file: held while the prompt is open, released by the OS
/// when the process ends however it ends. The frequency limit is a count of prompts in a window.
/// Failure mode: the prompt is not shown and the call is `internal`, exit 5: SG-08 lists no code
/// for a refused prompt, so the spec's own catch-all is used rather than a made-up code.
/// A refused call does not count against the limit.
public final class PromptGuard: @unchecked Sendable {
    public let lockPath: String
    private let maxPrompts: Int
    private let perSeconds: Int
    private let clock: @Sendable () -> Int
    private var recent: [Int] = []
    private var open = false

    public init(lockPath: String, maxPrompts: Int = 5, perSeconds: Int = 60, clock: @escaping @Sendable () -> Int) {
        self.lockPath = lockPath; self.maxPrompts = maxPrompts; self.perSeconds = perSeconds; self.clock = clock
    }

    /// Runs `prompt` as the one open prompt, or throws without running it.
    public func guarded<T>(_ prompt: () throws -> T) throws -> T {
        guard !open else { throw Refusal("internal") }
        let now = clock()
        let window = recent.filter { now - $0 < perSeconds }
        guard window.count < maxPrompts else { throw Refusal("internal") }

        let fd = Darwin.open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Refusal("internal") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw Refusal("internal") }
        defer { flock(fd, LOCK_UN) }

        open = true
        defer { open = false }
        recent = window + [now]
        return try prompt()
    }
}
