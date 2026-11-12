/// The canonical subset recognizer (ACT-04), grammar only.
///
/// Invariants: a value is accepted only if every byte is part of the grammar. The recognizer works
/// on bytes, so invalid UTF-8 and a byte order mark fail as bytes outside the string alphabet, with
/// no decoding step to disagree about. Object keys are unique, ASCII and strictly ascending by byte.
/// Nesting is bounded at `Limits.maxDepth` before recursion goes deeper, so hostile input cannot
/// exhaust the stack.
/// Owner of state: none; the parser state lives in one local value.
/// Failure modes: `.tooLarge` when the input exceeds the caller's bound (checked first), otherwise
/// `.notCanonical`. Both fail closed; there is no partial result.
public enum SubsetFailure: Error, Equatable, Sendable {
    case notCanonical
    case tooLarge
}

public enum Subset {
    /// `maxSize` is the byte bound of the caller: `Limits.maxPayload` for a signed value,
    /// `Limits.maxInput` for stdin (SG-01).
    public static func parse(_ bytes: [UInt8], maxSize: Int) -> Result<JValue, SubsetFailure> {
        if bytes.count > maxSize { return .failure(.tooLarge) }
        var reader = Reader(bytes: bytes)
        do {
            let value = try reader.value(depth: 0)
            guard reader.i == bytes.count else { return .failure(.notCanonical) }
            return .success(value)
        } catch {
            return .failure(.notCanonical)
        }
    }

    private struct Bad: Error {}

    private struct Reader {
        let bytes: [UInt8]
        var i = 0

        init(bytes: [UInt8]) { self.bytes = bytes }

        func peek() -> UInt8? { i < bytes.count ? bytes[i] : nil }

        mutating func take(_ byte: UInt8) throws {
            guard peek() == byte else { throw Bad() }
            i += 1
        }

        mutating func string() throws -> [UInt8] {
            try take(0x22)
            let start = i
            while true {
                guard let b = peek() else { throw Bad() }
                if b == 0x22 { break }
                guard Text.isPlain(b) else { throw Bad() }
                i += 1
            }
            let out = Array(bytes[start..<i])
            i += 1
            return out
        }

        mutating func value(depth: Int) throws -> JValue {
            switch peek() {
            case 0x22:
                return .string(String(decoding: try string(), as: UTF8.self))
            case UInt8(ascii: "n"):
                guard i + 4 <= bytes.count, Array(bytes[i..<i + 4]) == Array("null".utf8) else { throw Bad() }
                i += 4
                return .null
            case UInt8(ascii: "{"): return try object(depth: depth + 1)
            case UInt8(ascii: "["): return try array(depth: depth + 1)
            default: throw Bad()
            }
        }

        mutating func object(depth: Int) throws -> JValue {
            guard depth <= Limits.maxDepth else { throw Bad() }
            try take(UInt8(ascii: "{"))
            var out: [String: JValue] = [:]
            if peek() == UInt8(ascii: "}") { i += 1; return .object(out) }
            var previous: [UInt8]?
            while true {
                let key = try string()
                if let previous, !previous.lexicographicallyPrecedes(key) { throw Bad() }
                previous = key
                try take(UInt8(ascii: ":"))
                out[String(decoding: key, as: UTF8.self)] = try value(depth: depth)
                if peek() == UInt8(ascii: ",") { i += 1; continue }
                try take(UInt8(ascii: "}"))
                return .object(out)
            }
        }

        mutating func array(depth: Int) throws -> JValue {
            guard depth <= Limits.maxDepth else { throw Bad() }
            try take(UInt8(ascii: "["))
            var out: [JValue] = []
            if peek() == UInt8(ascii: "]") { i += 1; return .array(out) }
            while true {
                out.append(try value(depth: depth))
                if peek() == UInt8(ascii: ",") { i += 1; continue }
                try take(UInt8(ascii: "]"))
                return .array(out)
            }
        }
    }
}
