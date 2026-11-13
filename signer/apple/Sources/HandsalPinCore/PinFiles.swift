import Darwin
import HandsalCore

/// Who the helper makes the pin's directories and files belong to: root and wheel when installed.
/// The test constructor passes the current user, the stand-in for root that a test can be
/// (the reader takes the same stand-in as its `owner_uid`, GP-14).
struct Owner: Equatable {
    let uid: uid_t
    let gid: gid_t
    static let administrator = Owner(uid: 0, gid: 0)
}

/// The reader's own checks (GP-10), written once for the helper: the directories it finds and the
/// files it creates must be what the reader accepts.
///
/// A directory is a real directory, not a symlink, owned by the administrator, and writable by
/// neither group nor others. A file is a regular file with the same ownership and one link.
enum ReaderChecks {
    static let notWritable: mode_t = 0o022

    static func isAdministered(_ info: stat, _ owner: Owner) -> Bool {
        info.st_uid == owner.uid && info.st_mode & notWritable == 0
    }

    static func isDirectory(_ info: stat) -> Bool { info.st_mode & S_IFMT == S_IFDIR }
    static func isRegularFile(_ info: stat) -> Bool { info.st_mode & S_IFMT == S_IFREG }
}

/// `lstat` of a path: nil when nothing is there, `internal` for any other failure.
func lstatOrNil(_ path: String) throws -> stat? {
    var info = stat()
    if lstat(path, &info) == 0 { return info }
    guard errno == ENOENT else { throw PinFailure(.internal) }
    return nil
}

/// The directories of the pin (GP-21 Directories): `<root>/Library/Application Support/handsal` and
/// its `orgs`. The installer creates `handsal` (the helper lives under it); the helper is the only
/// creator of `orgs` and `pin.lock`, and creates `handsal` itself only when it finds it absent. What
/// it creates gets `fchown` and `fchmod`, which do not depend on umask. When present it checks them, and every
/// directory above them down from the root, with the reader's checks and refuses a mismatch with
/// `pin_owner`, writing nothing. It never repairs, because a repair would be a privileged change
/// to an object the agent may have prepared.
/// `Library` and `Application Support` are the system's: absent, they are an I/O failure (`internal`).
struct PinDirectories {
    let root: String
    let owner: Owner

    private static let chain = ["Library", "Application Support", "handsal", "orgs"]
    private static let created: Set = ["handsal", "orgs"]

    /// `root` is a virtual `/`: joining under it never doubles the slash of the real one.
    private var base: String { root == "/" ? "" : root }
    var handsal: String { base + "/Library/Application Support/handsal" }
    var orgs: String { handsal + "/orgs" }
    var lock: String { handsal + "/pin.lock" }

    /// Checks (and where it is the helper's to do so, creates) the whole chain, root first.
    func ensure() throws {
        try check(root)
        var path = base
        for name in Self.chain {
            path += "/" + name
            if try lstatOrNil(path) == nil {
                guard Self.created.contains(name) else { throw PinFailure(.internal) }
                try create(path)
            }
            try check(path)
        }
    }

    private func check(_ path: String) throws {
        guard let info = try lstatOrNil(path) else { throw PinFailure(.internal) }
        guard ReaderChecks.isDirectory(info), ReaderChecks.isAdministered(info, owner) else { throw PinFailure(.pinOwner) }
    }

    private func create(_ path: String) throws {
        guard mkdir(path, 0o700) == 0 else { throw PinFailure(.internal) }
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw PinFailure(.internal) }
        defer { close(fd) }
        guard fchown(fd, owner.uid, owner.gid) == 0, fchmod(fd, 0o755) == 0 else { throw PinFailure(.internal) }
    }
}

/// `pin.lock` (GP-21 Lock): after the directory check and before the checker runs, the helper
/// opens `handsal/pin.lock`, created like a pin file when absent, and takes an exclusive
/// non-blocking `flock` held until after the rename. A lock held by another run is `internal` and
/// nothing is written; the OS drops the lock when the process ends however it ends.
/// The lock file is held to the file half of the reader's checks too, so a file that is not the
/// helper's own is `pin_owner`, like any other object the helper finds and will not trust.
final class PinLock {
    private let fd: Int32

    private init(fd: Int32) { self.fd = fd }

    static func take(at path: String, owner: Owner) throws -> PinLock {
        var fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0, errno == ENOENT {
            fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if fd >= 0 {
                guard fchown(fd, owner.uid, owner.gid) == 0, fchmod(fd, 0o644) == 0 else { close(fd); throw PinFailure(.internal) }
            } else if errno == EEXIST {
                fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)   // another run created it between the two calls
            }
        }
        guard fd >= 0 else { throw PinFailure(.internal) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { close(fd); throw PinFailure(.internal) }
        guard ReaderChecks.isRegularFile(info), ReaderChecks.isAdministered(info, owner), info.st_nlink == 1 else {
            close(fd)
            throw PinFailure(.pinOwner)
        }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); throw PinFailure(.internal) }
        return PinLock(fd: fd)
    }

    func release() {
        flock(fd, LOCK_UN)
        close(fd)
    }
}
