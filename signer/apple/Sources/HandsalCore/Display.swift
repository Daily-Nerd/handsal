import Darwin

/// The display channel (SG-07): where the signer writes the full render and the `Signing as` line
/// before it prompts. On macOS it is the controlling terminal, never stdout, so the render cannot
/// be mixed into a result or piped away by the caller.
public protocol Display: Sendable {
    func show(_ text: String) throws
}

/// A display channel opened on a path. Failure to open it is `no_display` (exit 4): without a
/// channel the person cannot read what they are about to sign.
public final class TTYDisplay: Display, @unchecked Sendable {
    public static let standardPath = "/dev/tty"
    private let descriptor: Int32

    private init(descriptor: Int32) { self.descriptor = descriptor }

    deinit { close(descriptor) }

    public static func open(path: String) throws -> TTYDisplay {
        let fd = Darwin.open(path, O_WRONLY | O_NOCTTY | O_CLOEXEC)
        guard fd >= 0 else { throw Refusal("no_display") }
        var info = stat()
        // a directory or a missing node is no place to write a render
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) != S_IFDIR else { close(fd); throw Refusal("no_display") }
        return TTYDisplay(descriptor: fd)
    }

    public func show(_ text: String) throws {
        var bytes = Array(text.utf8)[...]
        while !bytes.isEmpty {
            let written = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
            guard written > 0 else { throw Refusal("no_display") }
            bytes = bytes.dropFirst(written)
        }
    }
}
