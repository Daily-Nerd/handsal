import Darwin
import HandsalCore

/// The controlling terminal as the ceremony's console (SG-07 for this tool): output and the one
/// question go to `/dev/tty`, never to stdout or stdin, so a pipe cannot answer for the person and
/// stdout stays one result line. No terminal is `no_display`. Only a line `y` or `yes` (any case)
/// is a yes: end of file, an empty line and anything else are no.
public final class TTYConsole: Console, @unchecked Sendable {
    private let path: String

    public init(path: String = TTYDisplay.standardPath) { self.path = path }

    public func show(_ text: String) throws {
        try TTYDisplay.open(path: path).show(text)
    }

    public func confirm(_ question: String) throws -> Bool {
        try show(question + " [y/N] ")
        let fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC)
        guard fd >= 0 else { throw Refusal("no_display") }
        defer { close(fd) }
        var line: [UInt8] = []
        var byte: UInt8 = 0
        while line.count < 16, read(fd, &byte, 1) == 1, byte != 0x0A { line.append(byte) }
        return Self.isYes(String(decoding: line, as: UTF8.self))
    }

    /// The terminal's foreground group is this process's group. Anything else is refused, including a
    /// terminal that cannot be opened or is not this process's controlling terminal (`tcgetpgrp` fails).
    public func requireForeground() throws {
        let fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC)
        guard fd >= 0 else { throw Refusal("no_display") }
        defer { close(fd) }
        guard tcgetpgrp(fd) == getpgrp() else { throw Refusal("no_display") }
    }

    /// `y` or `yes`, any case, and nothing else: an empty answer is no.
    static func isYes(_ answer: String) -> Bool {
        let lowered = answer.lowercased()
        return lowered == "y" || lowered == "yes"
    }
}
