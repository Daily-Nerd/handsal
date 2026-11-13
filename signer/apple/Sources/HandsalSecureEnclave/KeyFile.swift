import Darwin
import HandsalCore

/// The key a Secure Enclave backend remembers: not the private key, which never leaves the
/// hardware, but the opaque `dataRepresentation` blobs the hardware hands back (they are of no use
/// without the device and the enrolled biometrics), the public points, and the person bound at
/// keygen.
public struct StoredKey: Equatable, Sendable {
    public let label: String
    public let person: String
    public let keyClass: String
    public let sign: Point
    public let agree: Point
    public let signBlob: [UInt8]
    public let agreeBlob: [UInt8]

    public init(label: String, person: String, keyClass: String, sign: Point, agree: Point, signBlob: [UInt8], agreeBlob: [UInt8]) {
        self.label = label; self.person = person; self.keyClass = keyClass
        self.sign = sign; self.agree = agree; self.signBlob = signBlob; self.agreeBlob = agreeBlob
    }
}

/// The key file: one canonical-subset JSON object in a private directory.
///
/// Invariants: created exclusively, so a second keygen can never overwrite the first (`key_exists`);
/// mode 0600 in a 0700 directory; a symbolic link at the path is never followed. The file is never
/// a keychain item. Reading anything that is not exactly the format written here is
/// `key_unavailable`: a damaged key is a key the signer will not use, not a crash and not a repair.
public enum KeyFile {
    private static let version = "1"

    private static func fail() -> Refusal { Refusal("key_unavailable") }

    public static func encode(_ key: StoredKey) throws -> [UInt8] {
        func point(_ p: Point) -> JValue { .object(["x": .string(p.x), "y": .string(p.y)]) }
        return try Emit.subset(.object([
            "agree": point(key.agree), "agree_blob": .string(Encoding.base64url(key.agreeBlob)), "class": .string(key.keyClass),
            "label": .string(key.label), "person": .string(key.person), "sign": point(key.sign),
            "sign_blob": .string(Encoding.base64url(key.signBlob)), "v": .string(version),
        ]))
    }

    public static func decode(_ bytes: [UInt8]) throws -> StoredKey {
        guard case .success(let value) = Subset.parse(bytes, maxSize: Limits.maxPayload), case .object(let m) = value,
              Set(m.keys) == ["agree", "agree_blob", "class", "label", "person", "sign", "sign_blob", "v"],
              m["v"]?.str == version,
              let keyClass = m["class"]?.str, Forms.isClassId(keyClass),
              let label = m["label"]?.str, Forms.isLabel(label), let person = m["person"]?.str, Forms.isMemberId(person),
              let sign = point(m["sign"]), let agree = point(m["agree"]),
              let signBlob = m["sign_blob"]?.str.flatMap(Encoding.base64urlDecode), !signBlob.isEmpty,
              let agreeBlob = m["agree_blob"]?.str.flatMap(Encoding.base64urlDecode), !agreeBlob.isEmpty else { throw fail() }
        return StoredKey(label: label, person: person, keyClass: keyClass, sign: sign, agree: agree, signBlob: signBlob, agreeBlob: agreeBlob)
    }

    private static func point(_ value: JValue?) -> Point? {
        guard case .object(let m)? = value, Set(m.keys) == ["x", "y"], let x = m["x"]?.str, let y = m["y"]?.str,
              Forms.isB64u32(x), Forms.isB64u32(y) else { return nil }
        return Point(x: x, y: y)
    }

    /// The bytes at `path`, nil when nothing is there. A symbolic link, a directory or an
    /// unreadable file is `key_unavailable`.
    public static func read(path: String) throws -> [UInt8]? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw fail() }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= Int64(Limits.maxPayload) else { throw fail() }
        var data: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n < 0 { throw fail() }
            if n == 0 { break }
            data.append(contentsOf: chunk[0..<n])
        }
        return data
    }

    /// Writes `bytes` to `path` only if nothing is there: `O_EXCL`, `O_NOFOLLOW`, mode 0600, in a
    /// directory made 0700 when absent. Anything already there, a link included, is `key_exists`.
    public static func createExclusive(path: String, bytes: [UInt8]) throws {
        let directory = String(path[..<(path.lastIndex(of: "/") ?? path.startIndex)])
        if !directory.isEmpty {
            // intermediate directories 0700 as well; an existing directory is used as it is
            var current = ""
            for part in directory.split(separator: "/", omittingEmptySubsequences: true) {
                current += "/" + part
                if mkdir(current, 0o700) != 0 && errno != EEXIST { throw Refusal("internal") }
            }
        }
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Refusal(errno == EEXIST ? "key_exists" : "internal") }
        defer { close(fd) }
        var offset = 0
        while offset < bytes.count {
            let n = bytes[offset...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { unlink(path); throw Refusal("internal") }
            offset += n
        }
        guard fsync(fd) == 0 else { unlink(path); throw Refusal("internal") }
    }
}
