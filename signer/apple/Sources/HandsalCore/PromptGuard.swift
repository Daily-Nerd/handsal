import Darwin

/// SG-10: the signer limits prompt frequency per process and never runs while another of its
/// prompts is open.
///
/// Owner of both rules. "Another prompt is open" spans processes (two `handsal-sign` runs), so it
/// is one advisory `flock` on a private file: held while the prompt is open, released by the OS
/// when the process ends however it ends. The frequency limit is a count of prompts in a window.
/// Failure mode: a prompt that is open elsewhere or a limit that is reached is `prompt_refused`, exit 4
/// (SG-08, SG-10): nothing is shown and nothing is signed. A lock file that cannot be opened is
/// `internal`: that is the signer faulty, not a refusal.
/// A refused call does not count against the limit.
public final class PromptGuard: @unchecked Sendable {
    /// Where the lock file is, asked for when a prompt is about to run. It may fail (`internal`): a lock that cannot be
    /// named is a lock that cannot be taken, and the prompt does not run.
    private let lockPath: @Sendable () throws -> String
    private let maxPrompts: Int
    private let perSeconds: Int
    private let clock: @Sendable () -> Int
    private var recent: [Int] = []
    private var open = false

    public init(lockPath: @escaping @Sendable () throws -> String, maxPrompts: Int = 5, perSeconds: Int = 60,
                clock: @escaping @Sendable () -> Int) {
        self.lockPath = lockPath; self.maxPrompts = maxPrompts; self.perSeconds = perSeconds; self.clock = clock
    }

    public convenience init(lockPath: String, maxPrompts: Int = 5, perSeconds: Int = 60, clock: @escaping @Sendable () -> Int) {
        self.init(lockPath: { lockPath }, maxPrompts: maxPrompts, perSeconds: perSeconds, clock: clock)
    }

    /// Runs `prompt` as the one open prompt, or throws without running it.
    public func guarded<T>(_ prompt: () throws -> T) throws -> T {
        guard !open else { throw Refusal("prompt_refused") }
        let now = clock()
        let window = recent.filter { now - $0 < perSeconds }
        guard window.count < maxPrompts else { throw Refusal("prompt_refused") }

        let fd = Darwin.open(try lockPath(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Refusal("internal") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw Refusal("prompt_refused") }
        defer { flock(fd, LOCK_UN) }

        open = true
        defer { open = false }
        recent = window + [now]
        return try prompt()
    }
}
