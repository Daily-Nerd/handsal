import Darwin
import HandsalCore

/// The pin, read and written (GP-21 steps 2 and 3, Write).
///
/// Read: a file that exists at the derived path, whatever its contents, must be a well-formed pin
/// line for that org: a non-regular entry, a symlink, a file the recognizer refuses or one for
/// another org is `pin_malformed`. A read that fails is `internal`.
///
/// Write: the content is exactly the pin the checker returned. A temporary file is created
/// exclusively in `orgs` (`O_CREAT|O_EXCL|O_NOFOLLOW`) and given the reader's attributes before
/// the rename (owner and group by `fchown`, mode 0644 by `fchmod`, one link), is flushed, then
/// renamed over the path and `orgs` is synced. The path therefore holds the old pin or the new
/// one, never a partial one. A failure before the rename removes the helper's own temporary file
/// and writes nothing. Nothing after the rename can change the outcome: the rename is the write,
/// and a failed sync of the directory afterwards does not undo it, so it is not reported as a
/// failure of a write that completed.
/// The helper never deletes, truncates or restores a pin; the only file it ever removes is its own
/// temporary file, which is not a pin.
struct PinStore {
    let directories: PinDirectories
    let owner: Owner

    func existing(org: String) throws -> PinLine? {
        guard let name = PinLine.fileName(org: org) else { throw PinFailure(.internal) }
        let path = directories.orgs + "/" + name
        guard let info = try lstatOrNil(path) else { return nil }
        guard ReaderChecks.isRegularFile(info) else { throw PinFailure(.pinMalformed) }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw PinFailure(errno == ELOOP ? .pinMalformed : .internal) }
        defer { close(fd) }
        var bytes = [UInt8](repeating: 0, count: PinLine.maxBytes + 1)
        let n = read(fd, &bytes, bytes.count)
        guard n >= 0 else { throw PinFailure(.internal) }
        guard let line = PinLine.parse(Array(bytes.prefix(n))), line.org == org else { throw PinFailure(.pinMalformed) }
        return line
    }

    func write(_ pin: [UInt8], org: String) throws {
        guard let name = PinLine.fileName(org: org) else { throw PinFailure(.internal) }
        let final = directories.orgs + "/" + name
        let temporary = final + "." + Self.suffix() + ".tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PinFailure(.internal) }
        var renamed = false
        defer { if !renamed { unlink(temporary) } }
        do {
            defer { close(fd) }
            guard fchown(fd, owner.uid, owner.gid) == 0, fchmod(fd, 0o644) == 0 else { throw PinFailure(.internal) }
            var offset = 0
            try pin.withUnsafeBytes { buffer in
                while offset < buffer.count {
                    let n = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                    guard n > 0 else { throw PinFailure(.internal) }
                    offset += n
                }
            }
            guard fcntl(fd, F_FULLFSYNC) == 0 || fsync(fd) == 0 else { throw PinFailure(.internal) }
        }
        guard rename(temporary, final) == 0 else { throw PinFailure(.internal) }
        renamed = true
        let directory = open(directories.orgs, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if directory >= 0 { fsync(directory); close(directory) }
    }

    private static func suffix() -> String {
        var generator = SystemRandomNumberGenerator()
        let digits = Array("0123456789abcdef")
        return String((0..<8).map { _ in digits[Int.random(in: 0..<16, using: &generator)] })
    }
}
