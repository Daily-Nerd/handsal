import HandsalCore

/// The pin file (GP-05): exactly one line of canonical-subset JSON, one LF, at most 512 bytes.
///
/// `{"genesis":H,"org":O,"spec":S,"v":"handsal-pin/1"}` + LF. The recognizer owns the grammar
/// (sorted keys, no whitespace, ASCII, no repeated name), so what this type adds is the member set
/// and the forms of the values. The helper reads an existing file and the checker's answer with the
/// same function, so the two cannot disagree about what a pin is.
/// Failure mode: nil. The caller says `pin_malformed` or `internal` according to who produced the bytes.
struct PinLine: Equatable {
    static let maxBytes = 512
    static let version = "handsal-pin/1"

    let genesis: String
    let org: String
    let spec: String

    static func parse(_ bytes: [UInt8]) -> PinLine? {
        guard bytes.count <= maxBytes, bytes.last == 0x0A,
              case .success(.object(let members)) = Subset.parse(Array(bytes.dropLast()), maxSize: maxBytes),
              Set(members.keys) == ["genesis", "org", "spec", "v"],
              members["v"] == .string(version),
              let genesis = members["genesis"]?.str, Forms.isHashstr(genesis),
              let org = members["org"]?.str, Forms.isHashstr(org),
              let spec = members["spec"]?.str, Forms.isHashstr(spec) else { return nil }
        return PinLine(genesis: genesis, org: org, spec: spec)
    }

    /// `<hex64>.pin`: the lowercase hex of the digest inside the org id (GP-05). Hex, so that
    /// case-folding cannot merge two names.
    static func fileName(org: String) -> String? {
        guard Forms.isHashstr(org), let raw = Encoding.base64urlDecode(String(org.dropFirst())), raw.count == 34 else { return nil }
        let digits = Array("0123456789abcdef")
        return String(raw.dropFirst(2).flatMap { [digits[Int($0 >> 4)], digits[Int($0 & 15)]] }) + ".pin"
    }
}
