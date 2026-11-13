import HandsalCore

/// The I-JSON reader (RFC 7493) as CF-03 frames it, for input that is ordinary JSON and not the
/// canonical subset: the input of a `render` vector (written by the harness with spaces, escapes
/// and any key order) and the answers of the checker (booleans, nested objects). The signer's
/// canonical subset recognizer rightly refuses both, so this reader is its own target and the
/// shipped signer and the pin helper never link it.
///
/// Invariants: UTF-8 only, no duplicate member name at any depth, no lone surrogate (as an escape
/// or as UTF-8 bytes), strict RFC 8259 grammar, one value and nothing after it but whitespace.
/// Failure mode: nil. The caller says `unparseable_input`; there is no partial value.
/// Nesting is bounded at MAX_NESTING (CF-03) so a hostile input cannot exhaust the stack: arrays and
/// objects count together, the root counts as 1, exactly MAX_NESTING levels pass, one more fails.
/// The bound is the registry constant, read here and written nowhere else.
public enum IJSON {
    private static let maxNesting = Registry.standard.number("MAX_NESTING")

    public static func parse(_ bytes: [UInt8]) -> JValue? {
        var reader = Reader(bytes: bytes)
        reader.skipSpace()
        guard let value = reader.value(depth: 0) else { return nil }
        reader.skipSpace()
        return reader.i == bytes.count ? value : nil
    }

    private struct Reader {
        let bytes: [UInt8]
        var i = 0

        init(bytes: [UInt8]) { self.bytes = bytes }

        mutating func skipSpace() {
            while i < bytes.count, bytes[i] == 0x20 || bytes[i] == 0x09 || bytes[i] == 0x0A || bytes[i] == 0x0D { i += 1 }
        }

        mutating func take(_ text: String) -> Bool {
            for byte in text.utf8 {
                guard i < bytes.count, bytes[i] == byte else { return false }
                i += 1
            }
            return true
        }

        /// `depth` is the number of containers already open; entering one makes it `depth + 1` levels.
        mutating func value(depth: Int) -> JValue? {
            guard i < bytes.count else { return nil }
            switch bytes[i] {
            case UInt8(ascii: "{"): return object(depth: depth)
            case UInt8(ascii: "["): return array(depth: depth)
            case UInt8(ascii: "\""): return string().map { .string($0) }
            case UInt8(ascii: "t"): return take("true") ? .bool(true) : nil
            case UInt8(ascii: "f"): return take("false") ? .bool(false) : nil
            case UInt8(ascii: "n"): return take("null") ? .null : nil
            default: return number()
            }
        }

        private func isDigit(_ index: Int) -> Bool { index < bytes.count && bytes[index] >= 0x30 && bytes[index] <= 0x39 }

        /// -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
        mutating func number() -> JValue? {
            let start = i
            if i < bytes.count, bytes[i] == UInt8(ascii: "-") { i += 1 }
            guard isDigit(i) else { return nil }
            if bytes[i] == 0x30 { i += 1 } else { while isDigit(i) { i += 1 } }
            if i < bytes.count, bytes[i] == UInt8(ascii: ".") {
                i += 1
                guard isDigit(i) else { return nil }
                while isDigit(i) { i += 1 }
            }
            if i < bytes.count, bytes[i] == UInt8(ascii: "e") || bytes[i] == UInt8(ascii: "E") {
                i += 1
                if i < bytes.count, bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "-") { i += 1 }
                guard isDigit(i) else { return nil }
                while isDigit(i) { i += 1 }
            }
            return .number(String(decoding: bytes[start..<i], as: UTF8.self))
        }

        mutating func object(depth: Int) -> JValue? {
            guard depth + 1 <= IJSON.maxNesting else { return nil }
            i += 1
            var members: [String: JValue] = [:]
            skipSpace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "}") { i += 1; return .object(members) }
            while true {
                skipSpace()
                guard i < bytes.count, bytes[i] == UInt8(ascii: "\""), let key = string() else { return nil }
                skipSpace()
                guard take(":") else { return nil }
                skipSpace()
                guard let member = value(depth: depth + 1), members.updateValue(member, forKey: key) == nil else { return nil }
                skipSpace()
                guard i < bytes.count else { return nil }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(members) }
                return nil
            }
        }

        mutating func array(depth: Int) -> JValue? {
            guard depth + 1 <= IJSON.maxNesting else { return nil }
            i += 1
            var items: [JValue] = []
            skipSpace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
            while true {
                skipSpace()
                guard let item = value(depth: depth + 1) else { return nil }
                items.append(item)
                skipSpace()
                guard i < bytes.count else { return nil }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
                return nil
            }
        }

        mutating func hex4() -> UInt32? {
            var out: UInt32 = 0
            for _ in 0..<4 {
                guard i < bytes.count else { return nil }
                let b = bytes[i]
                let digit: UInt32
                switch b {
                case 0x30...0x39: digit = UInt32(b - 0x30)
                case 0x41...0x46: digit = UInt32(b - 0x41 + 10)
                case 0x61...0x66: digit = UInt32(b - 0x61 + 10)
                default: return nil
                }
                out = out * 16 + digit
                i += 1
            }
            return out
        }

        mutating func string() -> String? {
            guard take("\"") else { return nil }
            var raw: [UInt8] = []
            while true {
                guard i < bytes.count else { return nil }
                let b = bytes[i]
                i += 1
                if b == UInt8(ascii: "\"") { break }
                if b < 0x20 { return nil }
                if b != UInt8(ascii: "\\") { raw.append(b); continue }
                guard i < bytes.count else { return nil }
                let e = bytes[i]
                i += 1
                switch e {
                case UInt8(ascii: "\""): raw.append(0x22)
                case UInt8(ascii: "\\"): raw.append(0x5C)
                case UInt8(ascii: "/"): raw.append(0x2F)
                case UInt8(ascii: "b"): raw.append(0x08)
                case UInt8(ascii: "f"): raw.append(0x0C)
                case UInt8(ascii: "n"): raw.append(0x0A)
                case UInt8(ascii: "r"): raw.append(0x0D)
                case UInt8(ascii: "t"): raw.append(0x09)
                case UInt8(ascii: "u"):
                    guard var code = hex4() else { return nil }
                    if (0xD800..<0xDC00).contains(code) {
                        guard take("\\u"), let low = hex4(), (0xDC00..<0xE000).contains(low) else { return nil }
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    }
                    guard let scalar = Unicode.Scalar(code) else { return nil }  // a lone low surrogate has none
                    raw.append(contentsOf: Array(String(Character(scalar)).utf8))
                default: return nil
                }
            }
            // Strict UTF-8: Swift refuses overlongs, surrogates and anything past U+10FFFF.
            var decoder = UTF8()
            var iterator = raw.makeIterator()
            var scalars = String.UnicodeScalarView()
            while true {
                switch decoder.decode(&iterator) {
                case .scalarValue(let scalar): scalars.append(scalar)
                case .emptyInput: return String(scalars)
                case .error: return nil
                }
            }
        }
    }
}
