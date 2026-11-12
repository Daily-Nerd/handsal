import Foundation
import HandsalCore
import Testing

/// One conformance vector file (conformance/vector_schema.py is the contract).
struct Vector: Sendable, CustomTestStringConvertible {
    enum Input: Sendable {
        case json(JValue)
        case bytes([UInt8])
    }

    let name: String
    let command: String
    let anchor: String
    let input: Input
    let exit: Int

    var testDescription: String { name }

    /// The repository root: this file lives at <root>/signer/apple/Tests/HandsalCoreTests.
    static let root: URL = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return url
    }()

    /// Every vector file is read once per test process.
    private static let cache = Cache()

    private final class Cache: @unchecked Sendable {
        private let lock = NSLock()
        private var all: [Vector]?
        func get(_ build: () throws -> [Vector]) throws -> [Vector] {
            lock.lock(); defer { lock.unlock() }
            if let all { return all }
            let loaded = try build()
            all = loaded
            return loaded
        }
    }

    static func load(commands: Set<String>) throws -> [Vector] {
        try cache.get { try loadAll() }.filter { commands.contains($0.command) }
    }

    private static func loadAll() throws -> [Vector] {
        let dir = root.appendingPathComponent("conformance/vectors")
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { $0.hasSuffix(".json") }
            .sorted()
        var out: [Vector] = []
        for file in files {
            let bytes = [UInt8](try Data(contentsOf: dir.appendingPathComponent(file)))
            guard case .object(let doc) = try TestJSON.parse(bytes),
                  case .string(let command)? = doc["command"],
                  case .string(let name)? = doc["name"],
                  case .string(let anchor)? = doc["anchor"] else { continue }
            let input: Input
            if let value = doc["input"] {
                input = .json(value)
            } else if case .string(let raw)? = doc["input_raw"] {
                input = .bytes(Array(raw.utf8))
            } else if case .string(let hex)? = doc["input_hex"] {
                input = .bytes(Vector.decodeHex(hex))
            } else {
                throw TestJSON.ParseError(offset: -1)
            }
            var code = 0
            if case .number(let text)? = doc["exit"], let parsed = Int(text) { code = parsed }
            out.append(Vector(name: name, command: command, anchor: anchor, input: input, exit: code))
        }
        return out
    }

    static func decodeHex(_ text: String) -> [UInt8] {
        let digits = Array(text.utf8)
        var out: [UInt8] = []
        var i = 0
        while i + 1 < digits.count {
            out.append(UInt8(String(decoding: digits[i...i + 1], as: UTF8.self), radix: 16) ?? 0)
            i += 2
        }
        return out
    }
}
