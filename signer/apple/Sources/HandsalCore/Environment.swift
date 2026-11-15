import Darwin

/// What the signer owns and a caller never supplies: its key, its display, its clock, its
/// randomness and its prompt guard (SG-04, SG-05, SG-07, SG-10).
///
/// One value, built once at the entry point. Tests build theirs with a software backend and a
/// recording display; the shipped binary builds `live`. Nothing else decides who the signer signs
/// as: the person is the one bound to the key at keygen.
public struct Environment: Sendable {
    public var backend: any KeyBackend
    /// Opens the display channel, or throws `no_display`.
    public var display: @Sendable () throws -> any Display
    public var now: @Sendable () -> Int
    public var nonce: @Sendable () -> String
    public var prompts: PromptGuard

    public init(backend: any KeyBackend, display: @escaping @Sendable () throws -> any Display,
                now: @escaping @Sendable () -> Int, nonce: @escaping @Sendable () -> String, prompts: PromptGuard) {
        self.backend = backend; self.display = display; self.now = now; self.nonce = nonce; self.prompts = prompts
    }

    /// The shipped signer: the controlling terminal, the system clock, 32 bytes from the system
    /// CSPRNG, and a prompt lock at `lockPath`.
    public static func live(backend: any KeyBackend, lockPath: @escaping @Sendable () throws -> String) -> Environment {
        let clock: @Sendable () -> Int = { Int(time(nil)) }
        return Environment(backend: backend, display: { try TTYDisplay.open(path: TTYDisplay.standardPath) },
                           now: clock, nonce: PayloadBuilder.freshNonce,
                           prompts: PromptGuard(lockPath: lockPath, clock: clock))
    }
}
