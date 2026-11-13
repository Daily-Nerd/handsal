import Darwin
import Foundation
import HandsalCore

/// How the helper runs the production checker (GP-21 step 1, SG-14).
///
/// The installed helper runs `/Library/Application Support/handsal/bin/handsal-check genesis-check`
/// and nothing else: a fixed absolute path, no PATH lookup, and an empty environment, so nothing
/// the caller exported reaches the checker. The test constructor of `PinHelper` replaces the
/// command; the installed binary has no way to do that.
struct CheckerCommand: Equatable {
    let executable: String
    let arguments: [String]

    static let installed = CheckerCommand(executable: "/Library/Application Support/handsal/bin/handsal-check",
                                          arguments: ["genesis-check"])
}

/// What `genesis-check` answered (CF-03): `{pin, reason, valid}`, a JCS line.
///
/// Invariants of the answer, checked here so the caller never sees a half-believed one: `valid` true
/// means `reason` is `ok` and `pin` is a well-formed pin line (GP-05); anything else means `pin` is
/// null. An `{"error":code}` answer (the checker refused the input before judging it) is not
/// `valid:true`, so it is `pin_invalid` with that code as the inner reason.
/// Failure mode: `internal` for output that is not one JCS line of this shape, a nonzero exit, a
/// launch that failed, or more output than any answer needs: the helper never guesses what a
/// broken checker meant.
struct CheckerAnswer: Equatable {
    let valid: Bool
    let reason: String
    let pin: [UInt8]?

    static let maxOutput = 4096

    static func run(_ command: CheckerCommand, input: [UInt8]) throws -> CheckerAnswer {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: command.executable)
        process.arguments = command.arguments
        process.environment = [:]
        let stdin = Pipe(), stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { throw PinFailure(.internal) }

        // The input goes in from another thread so a checker that answers before it has read
        // everything cannot deadlock against a full pipe.
        let writer = stdin.fileHandleForWriting.fileDescriptor
        let feed = Thread {
            input.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let n = write(writer, buffer.baseAddress! + offset, buffer.count - offset)
                    if n <= 0 { break }
                    offset += n
                }
            }
            try? stdin.fileHandleForWriting.close()
        }
        feed.start()

        var output: [UInt8] = []
        var tooMuch = false
        while true {
            guard let chunk = try? stdout.fileHandleForReading.read(upToCount: 1024), !chunk.isEmpty else { break }
            output.append(contentsOf: chunk)
            if output.count > maxOutput { tooMuch = true; process.terminate(); break }
        }
        process.waitUntilExit()
        guard !tooMuch, process.terminationReason == .exit, process.terminationStatus == 0 else { throw PinFailure(.internal) }
        return try parse(output)
    }

    static func parse(_ bytes: [UInt8]) throws -> CheckerAnswer {
        var reader = JCSLine(bytes: bytes)
        guard let members = reader.object() else { throw PinFailure(.internal) }
        if Set(members.keys) == ["error"], case .string(let code)? = members["error"], isCode(code) {
            return CheckerAnswer(valid: false, reason: code, pin: nil)
        }
        guard Set(members.keys) == ["pin", "reason", "valid"], case .string(let reason)? = members["reason"], isCode(reason),
              case .bool(let valid)? = members["valid"] else { throw PinFailure(.internal) }
        switch (valid, members["pin"]) {
        case (true, .string(let text)?):
            let pin = Array(text.utf8)
            guard reason == "ok", PinLine.parse(pin) != nil else { throw PinFailure(.internal) }
            return CheckerAnswer(valid: true, reason: reason, pin: pin)
        case (false, .null?):
            guard reason != "ok" else { throw PinFailure(.internal) }
            return CheckerAnswer(valid: false, reason: reason, pin: nil)
        default:
            throw PinFailure(.internal)
        }
    }

    /// A reason code of section 11: lowercase snake_case.
    private static func isCode(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.count <= 64 && text.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || $0 == UInt8(ascii: "_") }
    }
}

/// A reader for one JCS result line (the checker's, the helper's): a flat object of strings, booleans and null,
/// keys in ascending order, no whitespace, followed by exactly one LF. A result line is not in the
/// canonical subset (it carries booleans), so the recognizer cannot read it, and nothing wider
/// than this shape is needed: anything else is nil.
struct JCSLine {
    let bytes: [UInt8]
    var i = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    private mutating func take(_ text: String) -> Bool {
        for byte in text.utf8 {
            guard i < bytes.count, bytes[i] == byte else { return false }
            i += 1
        }
        return true
    }

    mutating func object() -> [String: JValue]? {
        guard take("{") else { return nil }
        var members: [String: JValue] = [:]
        var previous: [UInt8]?
        while true {
            guard let key = string(), let keyBytes = Optional(Array(key.utf8)) else { return nil }
            if let previous, !previous.lexicographicallyPrecedes(keyBytes) { return nil }
            previous = keyBytes
            guard take(":"), let value = value() else { return nil }
            members[key] = value
            if take(",") { continue }
            guard take("}"), take("\n"), i == bytes.count else { return nil }
            return members
        }
    }

    private mutating func value() -> JValue? {
        if take("null") { return .null }
        if take("true") { return .bool(true) }
        if take("false") { return .bool(false) }
        return string().map { .string($0) }
    }

    private mutating func hex4() -> UInt32? {
        var out: UInt32 = 0
        for _ in 0..<4 {
            guard i < bytes.count, let digit = Self.digit(bytes[i]) else { return nil }
            out = out * 16 + digit
            i += 1
        }
        return out
    }

    private static func digit(_ byte: UInt8) -> UInt32? {
        switch byte {
        case 0x30...0x39: return UInt32(byte - 0x30)
        case 0x61...0x66: return UInt32(byte - 0x61 + 10)   // JCS writes lowercase hex only
        default: return nil
        }
    }

    private mutating func string() -> String? {
        guard take("\"") else { return nil }
        var raw: [UInt8] = []
        while i < bytes.count {
            let byte = bytes[i]
            i += 1
            if byte == UInt8(ascii: "\"") { return String(bytes: raw, encoding: .utf8) }
            if byte < 0x20 { return nil }
            guard byte == UInt8(ascii: "\\") else { raw.append(byte); continue }
            guard i < bytes.count else { return nil }
            let escape = bytes[i]
            i += 1
            switch escape {
            case UInt8(ascii: "\""): raw.append(0x22)
            case UInt8(ascii: "\\"): raw.append(0x5C)
            case UInt8(ascii: "b"): raw.append(0x08)
            case UInt8(ascii: "f"): raw.append(0x0C)
            case UInt8(ascii: "n"): raw.append(0x0A)
            case UInt8(ascii: "r"): raw.append(0x0D)
            case UInt8(ascii: "t"): raw.append(0x09)
            case UInt8(ascii: "u"):
                // JCS writes \u00xx for the other control bytes and nothing else escaped.
                guard let code = hex4(), code < 0x20 else { return nil }
                raw.append(UInt8(code))
            default: return nil
            }
        }
        return nil
    }
}
