import HandsalCore

/// A small general JSON reader for the test target only: vector files are plain JSON, with escapes
/// and numbers, so the signer's subset recognizer cannot read them. Not shipped.
enum TestJSON {
    struct ParseError: Error { let offset: Int }

    static func parse(_ bytes: [UInt8]) throws -> JValue {
        var parser = Parser(bytes: bytes)
        parser.skipSpace()
        let value = try parser.value()
        parser.skipSpace()
        if parser.i != bytes.count { throw ParseError(offset: parser.i) }
        return value
    }

    private struct Parser {
        let bytes: [UInt8]
        var i = 0

        init(bytes: [UInt8]) { self.bytes = bytes }

        mutating func skipSpace() {
            while i < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[i]) { i += 1 }
        }

        func fail() -> ParseError { ParseError(offset: i) }

        mutating func expect(_ text: String) throws {
            for b in text.utf8 {
                guard i < bytes.count, bytes[i] == b else { throw fail() }
                i += 1
            }
        }

        mutating func value() throws -> JValue {
            guard i < bytes.count else { throw fail() }
            switch bytes[i] {
            case UInt8(ascii: "{"): return try object()
            case UInt8(ascii: "["): return try array()
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try expect("true"); return .bool(true)
            case UInt8(ascii: "f"): try expect("false"); return .bool(false)
            case UInt8(ascii: "n"): try expect("null"); return .null
            default: return try number()
            }
        }

        mutating func number() throws -> JValue {
            let start = i
            while i < bytes.count, "+-0123456789.eE".utf8.contains(bytes[i]) { i += 1 }
            if start == i { throw fail() }
            return .number(String(decoding: bytes[start..<i], as: UTF8.self))
        }

        mutating func object() throws -> JValue {
            i += 1
            var out: [String: JValue] = [:]
            skipSpace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
            while true {
                skipSpace()
                let key = try string()
                skipSpace()
                try expect(":")
                skipSpace()
                out[key] = try value()
                skipSpace()
                guard i < bytes.count else { throw fail() }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
                throw fail()
            }
        }

        mutating func array() throws -> JValue {
            i += 1
            var out: [JValue] = []
            skipSpace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
            while true {
                skipSpace()
                out.append(try value())
                skipSpace()
                guard i < bytes.count else { throw fail() }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
                throw fail()
            }
        }

        mutating func hex4() throws -> UInt32 {
            var out: UInt32 = 0
            for _ in 0..<4 {
                guard i < bytes.count, let digit = Character(UnicodeScalar(bytes[i])).hexDigitValue else { throw fail() }
                out = out * 16 + UInt32(digit)
                i += 1
            }
            return out
        }

        mutating func string() throws -> String {
            try expect("\"")
            var raw: [UInt8] = []
            while true {
                guard i < bytes.count else { throw fail() }
                let b = bytes[i]
                i += 1
                if b == UInt8(ascii: "\"") { break }
                if b != UInt8(ascii: "\\") { raw.append(b); continue }
                guard i < bytes.count else { throw fail() }
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
                    var code = try hex4()
                    if (0xD800..<0xDC00).contains(code) {
                        try expect("\\u")
                        let low = try hex4()
                        guard (0xDC00..<0xE000).contains(low) else { throw fail() }
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    }
                    guard let scalar = UnicodeScalar(code) else { throw fail() }
                    raw.append(contentsOf: Array(String(Character(scalar)).utf8))
                default: throw fail()
                }
            }
            guard let text = String(validatingUTF8: raw.map { CChar(bitPattern: $0) } + [0]) , text.utf8.count == raw.count else { throw fail() }
            return text
        }
    }
}
