/// Emitters (ACT-05, SG-01).
///
/// `subset` writes a value of the canonical subset: keys sorted by byte order, no whitespace,
/// strings verbatim (`/` unescaped), arrays in the given order. It refuses everything the subset
/// cannot express instead of coercing it, so bytes that are signed or hashed come from here only.
/// `resultLine` writes a command result (RFC 8785 style): result objects are not signed values, so
/// they may carry booleans and numbers.
/// Failure mode: `Refusal("schema_refused")`, loudly, never a repaired value.
public enum Emit {
    private static func refuse() -> Refusal { Refusal("schema_refused") }

    public static func subset(_ value: JValue) throws -> [UInt8] {
        var out: [UInt8] = []
        try write(value, depth: 0, into: &out)
        guard out.count <= Limits.maxPayload else { throw refuse() }
        return out
    }

    private static func write(_ value: JValue, depth: Int, into out: inout [UInt8]) throws {
        switch value {
        case .null:
            out.append(contentsOf: "null".utf8)
        case .bool, .number:
            throw refuse()
        case .string(let text):
            guard Text.isPlain(text) else { throw refuse() }
            out.append(0x22)
            out.append(contentsOf: text.utf8)
            out.append(0x22)
        case .object(let members):
            guard depth + 1 <= Limits.maxDepth else { throw refuse() }
            out.append(UInt8(ascii: "{"))
            let keys = members.keys.map { Array($0.utf8) }.sorted { $0.lexicographicallyPrecedes($1) }
            for (index, key) in keys.enumerated() {
                if index > 0 { out.append(UInt8(ascii: ",")) }
                let name = String(decoding: key, as: UTF8.self)
                try write(.string(name), depth: depth + 1, into: &out)
                out.append(UInt8(ascii: ":"))
                try write(members[name] ?? .null, depth: depth + 1, into: &out)
            }
            out.append(UInt8(ascii: "}"))
        case .array(let items):
            guard depth + 1 <= Limits.maxDepth else { throw refuse() }
            out.append(UInt8(ascii: "["))
            for (index, item) in items.enumerated() {
                if index > 0 { out.append(UInt8(ascii: ",")) }
                try write(item, depth: depth + 1, into: &out)
            }
            out.append(UInt8(ascii: "]"))
        }
    }

    public static func resultLine(_ value: JValue) throws -> [UInt8] {
        var out: [UInt8] = []
        result(value, into: &out)
        return out
    }

    private static let hex = Array("0123456789abcdef".utf8)

    private static func resultString(_ text: String, into out: inout [UInt8]) {
        out.append(0x22)
        for byte in text.utf8 {
            switch byte {
            case 0x22: out.append(contentsOf: [0x5C, 0x22])
            case 0x5C: out.append(contentsOf: [0x5C, 0x5C])
            case 0x08: out.append(contentsOf: [0x5C, UInt8(ascii: "b")])
            case 0x0C: out.append(contentsOf: [0x5C, UInt8(ascii: "f")])
            case 0x0A: out.append(contentsOf: [0x5C, UInt8(ascii: "n")])
            case 0x0D: out.append(contentsOf: [0x5C, UInt8(ascii: "r")])
            case 0x09: out.append(contentsOf: [0x5C, UInt8(ascii: "t")])
            case 0..<0x20:
                out.append(contentsOf: [0x5C, UInt8(ascii: "u"), 0x30, 0x30, hex[Int(byte >> 4)], hex[Int(byte & 15)]])
            default: out.append(byte)
            }
        }
        out.append(0x22)
    }

    private static func result(_ value: JValue, into out: inout [UInt8]) {
        switch value {
        case .null: out.append(contentsOf: "null".utf8)
        case .bool(let flag): out.append(contentsOf: (flag ? "true" : "false").utf8)
        case .number(let raw): out.append(contentsOf: raw.utf8)
        case .string(let text): resultString(text, into: &out)
        case .array(let items):
            out.append(UInt8(ascii: "["))
            for (index, item) in items.enumerated() {
                if index > 0 { out.append(UInt8(ascii: ",")) }
                result(item, into: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .object(let members):
            out.append(UInt8(ascii: "{"))
            let keys = members.keys.sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
            for (index, key) in keys.enumerated() {
                if index > 0 { out.append(UInt8(ascii: ",")) }
                resultString(key, into: &out)
                out.append(UInt8(ascii: ":"))
                result(members[key] ?? .null, into: &out)
            }
            out.append(UInt8(ascii: "}"))
        }
    }
}
